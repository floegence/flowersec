package sessionv4

import (
	"context"
	"errors"
	"math"
	"sync"
	"time"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

var ErrDuplexAborted = errors.New("sessionv4: duplex bridge aborted")
var ErrDuplexCleanupIncomplete = errors.New("sessionv4: duplex bridge cleanup incomplete")

// DuplexOptions fixes both chunks and the complete lifetime before ownership
// transfer. This internal Stream composition requires one Environment, budget
// root and clock. Native adapters have their own explicit ownership contract.
// RuntimeBytes covers channels, allocation overhead and all four task stacks.
type DuplexOptions struct {
	ChunkBytes, TimeoutMS, CleanupTimeoutMS, RuntimeBytes uint64
	HardDeadline                                          *timev4.Deadline
}

// DuplexBridgeCharge excludes the two explicit CopyCharge reservations (each
// already includes its pump/lifecycle worker) and the two ownership charges.
// Only the supervisor and one bounded result waiter are added here.
func DuplexBridgeCharge(options DuplexOptions) (resourcev4.Vector, error) {
	fixed := uint64(unsafe.Sizeof(DuplexBridge{})) + uint64(unsafe.Sizeof(duplexResultOwner{})) + uint64(unsafe.Sizeof(duplexContext{})) + uint64(unsafe.Sizeof(timev4.Deadline{})) + uint64(unsafe.Sizeof(timev4.Window{}))
	if _, err := CopyCharge(options.ChunkBytes); err != nil {
		return resourcev4.Vector{}, err
	}
	if options.TimeoutMS == 0 || options.CleanupTimeoutMS == 0 || options.RuntimeBytes == 0 || options.RuntimeBytes > math.MaxUint64-fixed {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	return resourcev4.Vector{resourcev4.SDKBytes: fixed + options.RuntimeBytes, resourcev4.Items: 1, resourcev4.Tasks: 2, resourcev4.WorkSlots: 2, resourcev4.Timers: 1}, nil
}

// DuplexProgress contains no payload aliases. Outcome is absent until the
// exchange has ended; an in-progress snapshot never defaults to normal.
type DuplexProgress struct {
	AToB, BToA     CopyProgress
	Started, Final bool
	Outcome        protocolv4.V4DuplexOutcome
	CleanupStatus  protocolv4.V4CleanupStatus
}

// DuplexObservation carries partial metadata even when a Wait is canceled.
// Result is present only after both copy gates are sealed. Repeated Wait calls
// return the same result owner and tail allocations. Its metadata is immutable;
// the application owns its payload after handoff. CleanupStatus on the bridge
// continues to expose actual late cleanup after this fixed result is published.
type DuplexObservation struct {
	DuplexProgress
	Result *protocolv4.V4DuplexResult
}

type duplexEvent struct{ phase uint8 }

// Variant pointers point into this compact owner, never back into the bridge.
type duplexResultOwner struct {
	value   protocolv4.V4DuplexResult
	drained [2]bool
}

// The existing supervisor owns parent cancellation observation. WithCancel on
// an arbitrary parent can spawn an additional, unadmitted propagation worker.
// Gates still check the original context even before the supervisor runs.
type duplexContext struct {
	context.Context
	operation context.Context
}

func (c *duplexContext) Err() error {
	if err := c.operation.Err(); err != nil {
		return err
	}
	return c.Context.Err()
}

// DuplexBridge uses two precharged SDK workers for Copy, half-close, concurrent
// Finish and independent endpoint cleanup. It never submits ordinary work to
// ApplicationExecutor. The constructor owns expiration even before Start.
type DuplexBridge struct {
	mu                             sync.Mutex
	owners                         [2]*StreamOwnership
	natives                        [2]*nativeTCPOwnership
	nativeEndpoint, nativeFinished [2]bool
	copies                         [2]*copyState
	endpointResults                [2]protocolv4.V4CloseResult
	workerDone                     [2]chan struct{}
	pumpExited                     [2]chan struct{}
	reservation                    resourcev4.Reference
	deadline                       *timev4.Deadline
	clock                          *timev4.Clock
	cleanup                        *timev4.Window
	cleanupMS                      uint64
	operationContext               context.Context
	cancel                         context.CancelFunc
	first                          error
	outcome                        protocolv4.V4DuplexOutcome
	started, published             bool
	complete, incomplete           bool
	doneClosed                     bool
	delivered, waiting             bool
	cleanupPinned                  bool
	stopRequested, faultClosed     bool
	result                         *duplexResultOwner
	start, abort, fault            chan struct{}
	finishStart, cleanupStart      chan struct{}
	ready, done                    chan struct{}
	incompleteReady                chan struct{}
	events                         chan duplexEvent
}

// NewDuplexBridge takes only canonical accepted Stream handles. Every supplied
// reservation is a distinct, pre-admitted full-vector owner. Failed acquisition
// releases unused claims without resetting or consuming either endpoint.
func NewDuplexBridge(ctx context.Context, a, b OpenHandle, options DuplexOptions, reservation resourcev4.Reference, ownership, chunks [2]resourcev4.Reference) (*DuplexBridge, error) {
	return newDuplexBridge(ctx, a, b, nil, options, reservation, ownership, chunks)
}

// NewNativeDuplexBridge uses the same operation and two workers with a sealed
// native TCP endpoint. The native endpoint has its own canonical ownership
// reservation; arbitrary net.Conn or external socket aliases are not accepted.
func NewNativeDuplexBridge(ctx context.Context, stream OpenHandle, native *NativeTCP, options DuplexOptions, reservation resourcev4.Reference, ownership, chunks [2]resourcev4.Reference) (*DuplexBridge, error) {
	if native == nil || native.nativeTCPCore == nil {
		return nil, cryptov4.ErrConfiguration
	}
	return newDuplexBridge(ctx, stream, OpenHandle{}, native, options, reservation, ownership, chunks)
}

type duplexTasks struct {
	context    context.Context
	workers    [2]resourcev4.Reference
	supervisor resourcev4.Reference
}

func newDuplexBridge(ctx context.Context, a, b OpenHandle, native *NativeTCP, options DuplexOptions, reservation resourcev4.Reference, ownership, chunks [2]resourcev4.Reference) (*DuplexBridge, error) {
	d, tasks, err := prepareDuplexBridge(ctx, a, b, native, options, reservation, ownership, chunks)
	if err != nil {
		return nil, err
	}
	for i := range 2 {
		go d.worker(i, tasks.context, tasks.workers[i])
	}
	go d.supervise(ctx, d.clock, d.cleanupMS, tasks.supervisor)
	return d, nil
}

// Separate admission from launching the three fixed SDK tasks. No production
// callback or substitute endpoint can be installed through this private seam.
func prepareDuplexBridge(ctx context.Context, a, b OpenHandle, native *NativeTCP, options DuplexOptions, reservation resourcev4.Reference, ownership, chunks [2]resourcev4.Reference) (_ *DuplexBridge, tasks duplexTasks, err error) {
	charge, err := DuplexBridgeCharge(options)
	if err != nil || ctx == nil || a.owner == nil || native == nil && (b.owner == nil || a.owner.engine == b.owner.engine && a.scope == b.scope) {
		return nil, tasks, cryptov4.ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return nil, tasks, err
	}
	clock := a.owner.engine.Clock()
	if !options.HardDeadline.BelongsTo(clock) || native == nil && clock != b.owner.engine.Clock() {
		return nil, tasks, timev4.ErrOwner
	}
	if native != nil {
		native.mu.Lock()
		matches := native.clock == clock
		native.mu.Unlock()
		if !matches {
			return nil, tasks, timev4.ErrOwner
		}
	}
	refs := [5]resourcev4.Reference{reservation, ownership[0], ownership[1], chunks[0], chunks[1]}
	for i, ref := range refs {
		for j := range i {
			if ref == refs[j] {
				return nil, tasks, resourcev4.ErrOwner
			}
		}
		if err := ref.CheckSameEnvironment(reservation); err != nil {
			return nil, tasks, err
		}
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		return nil, tasks, err
	}
	d := &DuplexBridge{reservation: owned, clock: clock, cleanupMS: options.CleanupTimeoutMS, operationContext: ctx, start: make(chan struct{}), abort: make(chan struct{}), fault: make(chan struct{}), finishStart: make(chan struct{}), cleanupStart: make(chan struct{}), ready: make(chan struct{}), incompleteReady: make(chan struct{}), done: make(chan struct{}), events: make(chan duplexEvent, 4)}
	pumpBase, cancel := context.WithCancel(context.Background())
	pumpCtx := &duplexContext{Context: pumpBase, operation: ctx}
	d.cancel = cancel
	d.result = &duplexResultOwner{}
	var workerRefs [2]resourcev4.Reference
	var supervisorRef resourcev4.Reference
	defer func() {
		if err == nil {
			return
		}
		cancel()
		supervisorRef.Release()
		for i := range 2 {
			workerRefs[i].Release()
			if d.copies[i] != nil {
				d.copies[i].release()
			}
			if d.owners[i] != nil {
				_ = d.owners[i].Release()
			}
			if d.natives[i] != nil {
				_ = d.natives[i].release()
			}
		}
		owned.Release()
	}()
	supervisorRef, err = owned.Borrow()
	if err != nil {
		return nil, tasks, err
	}
	start, err := clock.Sample()
	if err != nil {
		return nil, tasks, err
	}
	d.deadline, err = options.HardDeadline.ForkAgeAt(start, options.TimeoutMS)
	if err != nil {
		return nil, tasks, err
	}
	for i, h := range [2]OpenHandle{a, b} {
		var ownerRef resourcev4.Reference
		if i == 1 && native != nil {
			d.natives[i], err = native.own(ownership[i], d.deadline, pumpCtx)
			d.nativeEndpoint[i] = true
			if err == nil {
				ownerRef = d.natives[i].reservation
			}
		} else {
			d.owners[i], err = h.owner.ownStreamContext(h, ownership[i], d.deadline, pumpCtx)
			if err == nil {
				ownerRef = d.owners[i].reservation
			}
		}
		if err != nil {
			return nil, tasks, err
		}
		if err = chunks[i].CheckSameEnvironment(ownerRef); err != nil {
			return nil, tasks, err
		}
		d.copies[i], err = prepareCopy(options.ChunkBytes, chunks[i])
		if err != nil {
			return nil, tasks, err
		}
		workerRefs[i], err = d.copies[i].reservation.Borrow()
		if err != nil {
			return nil, tasks, err
		}
		d.workerDone[i] = make(chan struct{})
		d.pumpExited[i] = make(chan struct{})
	}
	return d, duplexTasks{context: pumpCtx, workers: workerRefs, supervisor: supervisorRef}, nil
}

func (d *DuplexBridge) Start() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.first != nil || d.started || d.complete {
		return d.first
	}
	for i := range 2 {
		if err := d.enterEndpoint(i); err != nil {
			d.failLocked(err, protocolv4.V4DuplexOutcomeFailed)
			return d.first
		}
	}
	d.started = true
	close(d.start)
	return nil
}

func (d *DuplexBridge) failLocked(err error, outcome protocolv4.V4DuplexOutcome) {
	if err == nil || d.complete {
		return
	}
	if err != ErrDuplexAborted && err != ErrDuplexCleanupIncomplete {
		err = boundedReadCause(err)
	}
	if (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) && d.operationContext.Err() != nil {
		outcome = protocolv4.V4DuplexOutcomeAborted
	}
	if d.first == nil && !d.published {
		d.first, d.outcome = err, outcome
	}
	// This original context is checked inside both read/acceptance gates.
	// The supervisor may be delayed, but explicit Abort cannot admit more I/O.
	d.cancel()
	if !d.cleanupPinned {
		d.cleanupPinned = true
		d.cleanup, _ = timev4.NewWindow(d.clock, d.cleanupMS)
	}
	d.stopRequested = true
	if !d.faultClosed {
		d.faultClosed = true
		close(d.fault)
	}
}

func (d *DuplexBridge) fail(err error, outcome protocolv4.V4DuplexOutcome) {
	d.mu.Lock()
	d.failLocked(err, outcome)
	d.mu.Unlock()
}

// Abort is the short logical gate. The pre-admitted supervisor performs the
// original endpoint revocation/Reset; no callback or additional worker starts.
func (d *DuplexBridge) Abort() { d.fail(ErrDuplexAborted, protocolv4.V4DuplexOutcomeAborted) }

func (d *DuplexBridge) worker(i int, ctx context.Context, reference resourcev4.Reference) {
	defer func() { reference.Release(); close(d.workerDone[i]) }()
	state := d.copies[i]
	var result CopyResult
	var err error
	select {
	case <-d.start:
		result, err = d.runCopy(i, ctx)
		if err != nil {
			d.fail(err, protocolv4.V4DuplexOutcomeFailed)
		}
	case <-d.abort:
		result = state.result(protocolv4.V4ReadTerminalUnknown)
		state.mu.Lock()
		state.complete = true
		state.mu.Unlock()
	}
	close(d.pumpExited[i])
	if err == nil && result.SourceTerminal == protocolv4.V4ReadTerminalEof {
		err = d.closeWrite(1-i, ctx)
		if err != nil {
			d.fail(err, protocolv4.V4DuplexOutcomeFailed)
		} else {
			d.events <- duplexEvent{phase: 1}
			select {
			case <-d.finishStart:
				if err = d.finishSend(1-i, ctx); err != nil {
					d.fail(err, protocolv4.V4DuplexOutcomeFailed)
				}
				d.events <- duplexEvent{phase: 2}
			case <-d.abort:
			}
		}
	}
	<-d.cleanupStart
	d.cleanupEndpoint(i)
}

func (d *DuplexBridge) supervise(ctx context.Context, clock *timev4.Clock, cleanupMS uint64, reference resourcev4.Reference) {
	engines := [2]*cryptov4.Engine{d.owners[0].admission.engine, d.owners[0].admission.engine}
	if d.owners[1] != nil {
		engines[1] = d.owners[1].admission.engine
	}
	defer func() { reference.Release(); d.finish(engines) }()
	sessionDone := [2]<-chan struct{}{engines[0].Done(), engines[1].Done()}
	workerDone := [2]<-chan struct{}{d.workerDone[0], d.workerDone[1]}
	pumpDone := [2]<-chan struct{}{d.pumpExited[0], d.pumpExited[1]}
	pumps := 0
	var nativeTargetDone <-chan struct{}
	if d.natives[1] != nil {
		nativeTargetDone = d.owners[0].queue.writeDone
	}
	fault := (<-chan struct{})(d.fault)
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	defer timer.Stop()
	var cleanup *timev4.Window
	closing, aborted := false, false
	closed, finished, workers := 0, 0, 0
	startCleanup := func() {
		if !closing {
			closing = true
			d.mu.Lock()
			if !d.cleanupPinned {
				d.cleanupPinned = true
				d.cleanup, _ = timev4.NewWindow(clock, cleanupMS)
			}
			cleanup = d.cleanup
			d.mu.Unlock()
			close(d.cleanupStart)
		}
	}
	abort := func() {
		if !aborted {
			aborted = true
			for i := range 2 {
				d.revokeEndpoint(i)
			}
			d.cancel()
			close(d.abort)
			for i := range 2 {
				d.cancelEndpoint(i)
			}
		}
		startCleanup()
	}
	for {
		remaining, err := d.deadline.RemainingMS()
		if err != nil {
			d.fail(err, protocolv4.V4DuplexOutcomeFailed)
		}
		d.mu.Lock()
		failed, incomplete := d.stopRequested, d.incomplete
		d.mu.Unlock()
		if failed {
			abort()
		}
		// Actual pump exits and cleanup time are independent facts. No timeout
		// path waits on a provider or scheduler while holding the observer hostage.
		for i := range 2 {
			if pumpDone[i] != nil {
				select {
				case <-pumpDone[i]:
					pumpDone[i] = nil
					pumps++
				default:
				}
			}
		}
		if incomplete && pumps == 2 {
			d.mu.Lock()
			d.publishLocked(engines, false)
			d.mu.Unlock()
		}
		if workers == 2 {
			if cleanup != nil && cleanup.Check() != nil {
				d.mu.Lock()
				d.incomplete = true
				d.mu.Unlock()
			}
			return
		}
		if closing && !incomplete {
			left, cleanupErr := uint64(0), ErrDuplexCleanupIncomplete
			if cleanup != nil {
				left, cleanupErr = cleanup.RemainingMS()
			}
			if cleanupErr != nil {
				d.mu.Lock()
				d.incomplete = true
				// A still-live native call can own mutable chunk bytes. Return only
				// counters until both actual pumps have frozen their original tails.
				if pumps == 2 {
					d.publishLocked(engines, false)
				}
				close(d.incompleteReady)
				d.mu.Unlock()
				// Keep observing the original lifetime and explicit Abort while
				// actual endpoint cleanup remains outstanding. Publication neither
				// extends that lifetime nor creates another timer/worker.
				continue
			} else if failed {
				remaining = left
			} else {
				remaining = min(remaining, left)
			}
		}
		var tick <-chan time.Time
		if !incomplete || !aborted {
			timer.Reset(idleTimerChunk(remaining))
			tick = timer.C
		}
		select {
		case <-ctx.Done():
			d.fail(ctx.Err(), protocolv4.V4DuplexOutcomeAborted)
			ctx = context.Background()
		case <-sessionDone[0]:
			d.fail(cryptov4.ErrClosed, protocolv4.V4DuplexOutcomeFailed)
			sessionDone[0] = nil
		case <-sessionDone[1]:
			d.fail(cryptov4.ErrClosed, protocolv4.V4DuplexOutcomeFailed)
			sessionDone[1] = nil
		case <-fault:
			fault = nil
		case e := <-d.events:
			if e.phase == 1 {
				closed++
				if closed == 2 {
					close(d.finishStart)
				}
			} else {
				finished++
				if finished == 2 {
					d.mu.Lock()
					if d.first == nil {
						d.outcome = protocolv4.V4DuplexOutcomeNormal
					}
					d.mu.Unlock()
					startCleanup()
				}
			}
		case <-nativeTargetDone:
			nativeTargetDone = nil
			owner := d.owners[0]
			owner.mu.Lock()
			queue := owner.queue
			if queue != nil {
				queue.mu.Lock()
				cause := queue.failure
				if cause == nil && (queue.closed || !d.copies[1].progress().Complete) {
					cause = ErrFlowClosed
				}
				queue.mu.Unlock()
				owner.mu.Unlock()
				if cause != nil {
					d.fail(cause, protocolv4.V4DuplexOutcomeFailed)
				}
			} else {
				owner.mu.Unlock()
			}
		case <-pumpDone[0]:
			pumpDone[0] = nil
			pumps++
		case <-pumpDone[1]:
			pumpDone[1] = nil
			pumps++
		case <-workerDone[0]:
			workerDone[0] = nil
			workers++
		case <-workerDone[1]:
			workerDone[1] = nil
			workers++
		case <-tick:
		}
		timer.Stop()
	}
}

func (d *DuplexBridge) cleanupLocked() protocolv4.V4CleanupStatus {
	c := protocolv4.V4CleanupStatus{Status: protocolv4.V4CleanupStatePending, CoreCleanup: protocolv4.V4CoreCleanupPending}
	if d.incomplete || d.cleanup != nil && d.cleanup.Check() != nil {
		c.Status = protocolv4.V4CleanupStateCleanupIncomplete
	}
	if d.complete && !d.waiting {
		c.Status, c.CoreCleanup = protocolv4.V4CleanupStateComplete, protocolv4.V4CoreCleanupComplete
	}
	return c
}

func (d *DuplexBridge) progressLocked() DuplexProgress {
	return DuplexProgress{AToB: d.copies[0].progress(), BToA: d.copies[1].progress(), Started: d.started, Final: d.published, Outcome: d.outcome, CleanupStatus: d.cleanupLocked()}
}

func (d *DuplexBridge) Progress() DuplexProgress {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.progressLocked()
}

func (d *DuplexBridge) CleanupStatus() protocolv4.V4CleanupStatus {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.cleanupLocked()
}

func duplexSourceStatus(terminal protocolv4.V4ReadTerminal) protocolv4.V4StreamStatus {
	switch terminal {
	case protocolv4.V4ReadTerminalEof:
		return protocolv4.V4StreamStatusEof
	case protocolv4.V4ReadTerminalAbandoned:
		return protocolv4.V4StreamStatusAborted
	case protocolv4.V4ReadTerminalOpen:
		return protocolv4.V4StreamStatusOpen
	default:
		return protocolv4.V4StreamStatusError
	}
}

func (d *DuplexBridge) publishLocked(engines [2]*cryptov4.Engine, complete bool) {
	if d.published {
		d.complete = complete
		return
	}
	var endpoints [2]protocolv4.V4CloseResult
	for i := range 2 {
		endpoints[i] = d.endpointResults[i]
		if d.owners[i] != nil {
			if current, err := d.owners[i].CloseResult(); err == nil {
				endpoints[i] = current
			}
		}
		d.result.drained[i] = endpoints[i].SendDrained
		if d.natives[i] != nil {
			endpoints[i], d.result.drained[i] = d.natives[i].closeResult()
		} else if d.nativeEndpoint[i] {
			d.result.drained[i] = d.nativeFinished[i]
		}
	}
	// Endpoint snapshots can wait for original transport gates. Recheck the
	// operation lifetime after those waits, inside the final result gate.
	if !d.stopRequested {
		err := d.operationContext.Err()
		for _, engine := range engines {
			if err == nil {
				err = engine.CheckApplicationAuthorization()
			}
		}
		if err == nil {
			err = d.deadline.Check()
		}
		if err != nil {
			d.failLocked(err, protocolv4.V4DuplexOutcomeFailed)
		}
	}
	if d.incomplete && d.first == nil {
		d.first = ErrDuplexCleanupIncomplete
	}
	d.complete = complete
	var directions [2]protocolv4.V4DuplexDirectionResult
	for i := range 2 {
		state := d.copies[i]
		state.mu.Lock()
		transfer := state.final.Progress
		state.mu.Unlock()
		send := protocolv4.V4DuplexSendResult{EndpointKind: protocolv4.V4DuplexEndpointKindFlowersecStream, SendDrained: &d.result.drained[1-i]}
		if d.nativeEndpoint[1-i] {
			send = protocolv4.V4DuplexSendResult{EndpointKind: protocolv4.V4DuplexEndpointKindNativeDuplex, NativeSendFinished: &d.result.drained[1-i]}
		}
		directions[i] = protocolv4.V4DuplexDirectionResult{Progress: transfer, SourceStatus: duplexSourceStatus(endpoints[i].ReadTerminal), SendResult: send}
	}
	d.result.value = protocolv4.V4DuplexResult{AToB: directions[0], BToA: directions[1], Outcome: d.outcome, CleanupStatus: d.cleanupLocked()}
	d.published = true
	close(d.ready)
}

func (d *DuplexBridge) finish(engines [2]*cryptov4.Engine) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.publishLocked(engines, true)
	d.cancel()
	d.cancel, d.owners[0], d.owners[1] = nil, nil, nil
	d.natives = [2]*nativeTCPOwnership{}
	d.deadline, d.operationContext, d.clock = nil, nil, nil
	if d.delivered {
		d.reservation.Release()
		d.reservation = resourcev4.Reference{}
	}
	d.closeDoneLocked()
}

func (d *DuplexBridge) observationLocked(handoff bool) DuplexObservation {
	r := DuplexObservation{DuplexProgress: d.progressLocked()}
	if d.published && handoff {
		if !d.delivered {
			// No final pointer has escaped yet. An admitted observer releases its
			// own tail at this same gate before the first application handoff.
			d.result.value.CleanupStatus = d.cleanupLocked()
			d.delivered = true
			for _, state := range d.copies {
				state.release()
			}
			if d.complete {
				d.reservation.Release()
				d.reservation = resourcev4.Reference{}
			}
		}
		r.Result = &d.result.value
	}
	return r
}

// Wait cancellation only ends observation. Before final handoff it returns
// current counters without an alias to the mutable chunk. A single admitted
// waiter pins its original charge through cancellation or the final handoff gate.
func (d *DuplexBridge) Wait(ctx context.Context) (DuplexObservation, error) {
	if ctx == nil {
		return DuplexObservation{}, cryptov4.ErrConfiguration
	}
	d.mu.Lock()
	if d.waiting && !d.delivered {
		r := d.observationLocked(false)
		d.mu.Unlock()
		return r, ErrStreamOwnershipBusy
	}
	if d.published {
		r, err := d.observationLocked(true), d.first
		d.mu.Unlock()
		return r, err
	}
	if d.waiting {
		r := d.observationLocked(false)
		d.mu.Unlock()
		return r, ErrStreamOwnershipBusy
	}
	tail, err := d.reservation.Borrow()
	if err != nil {
		r := d.observationLocked(false)
		d.mu.Unlock()
		return r, err
	}
	d.waiting = true
	d.mu.Unlock()
	releaseWait := func() {
		if tail != (resourcev4.Reference{}) {
			// Expiry publication belongs to the supervisor. An observer may
			// report the original window's status, but cannot consume its wake.
			d.waiting = false
			tail.Release()
			tail = resourcev4.Reference{}
			d.closeDoneLocked()
		}
	}
	defer func() { d.mu.Lock(); releaseWait(); d.mu.Unlock() }()
	select {
	case <-d.incompleteReady:
		d.mu.Lock()
		defer d.mu.Unlock()
		releaseWait()
		err := d.first
		if err == nil {
			err = ErrDuplexCleanupIncomplete
		}
		return d.observationLocked(true), err
	case <-d.ready:
		d.mu.Lock()
		defer d.mu.Unlock()
		releaseWait()
		return d.observationLocked(true), d.first
	case <-ctx.Done():
		d.mu.Lock()
		defer d.mu.Unlock()
		return d.observationLocked(false), ctx.Err()
	}
}

func (d *DuplexBridge) closeDoneLocked() {
	if d.complete && !d.waiting && !d.doneClosed {
		d.doneClosed = true
		d.cleanup = nil
		close(d.done)
	}
}

func (d *DuplexBridge) Done() <-chan struct{} { return d.done }
