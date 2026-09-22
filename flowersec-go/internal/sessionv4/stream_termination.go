package sessionv4

import (
	"context"
	"errors"
	"math"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

var (
	ErrTerminationDeadline = errors.New("sessionv4: stream terminal proof deadline exceeded")
	ErrQuarantineCapacity  = errors.New("sessionv4: stream quarantine capacity exhausted")
)

// StreamTerminationPolicy is fixed before OPEN. NormalMS includes the entire
// original normal termination; quarantine cannot restart or extend its cap.
type StreamTerminationPolicy struct {
	NormalMS, QuarantineMS uint64
	QuarantineDirections   uint32
}

// Each original direction owns its first termination clock and first failure.
// Its gate is never held while taking a flow or admission gate.
type directionTermination struct {
	mu               sync.Mutex
	service          *StreamTerminationService
	normal, until    *timev4.Window
	quarantine, done bool
	cause, failure   error
}

func (d *directionTermination) start(failed bool, cause error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.cause == nil && cause != nil {
		d.cause = cause
	}
	p := d.service
	if p == nil || d.done {
		return
	}
	if d.until != nil && (!failed || d.quarantine) {
		return
	}
	defer p.notify()
	if d.until == nil && d.failure == nil {
		now, err := p.admission.engine.Clock().Monotonic()
		if err != nil {
			d.failure = err
			return
		}
		duration := p.policy.QuarantineMS
		if !failed {
			duration += p.policy.NormalMS
			d.normal, err = timev4.NewWindowAt(p.admission.engine.Clock(), now, p.policy.NormalMS)
		}
		if err == nil {
			d.until, err = timev4.NewWindowAt(p.admission.engine.Clock(), now, duration)
		}
		d.failure = err
	}
	if failed && !d.quarantine && d.failure == nil {
		// Failure during normal drainage starts immediate isolation, bounded
		// both by ten seconds from this event and by the original total cap.
		remaining, err := d.until.RemainingMS()
		if err == nil && remaining > p.policy.QuarantineMS {
			d.until, err = timev4.NewWindow(p.admission.engine.Clock(), p.policy.QuarantineMS)
		}
		if err != nil {
			d.failure = err
			return
		}
		d.enterQuarantine()
	}
}

func (d *directionTermination) enterQuarantine() {
	if d.quarantine {
		return
	}
	p := d.service
	for {
		used := p.quarantined.Load()
		if used >= p.policy.QuarantineDirections {
			d.failure = ErrQuarantineCapacity
			return
		}
		if p.quarantined.CompareAndSwap(used, used+1) {
			d.quarantine = true
			return
		}
	}
}

// poll never resets a window. A delayed scheduler uses the original normal +
// quarantine cap, not a fresh quarantine period beginning when it woke up.
func (d *directionTermination) poll() (remaining uint64, fence bool, err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.done || d.service == nil {
		return 0, false, nil
	}
	if d.failure != nil {
		return 0, false, d.failure
	}
	if d.until == nil {
		return 0, false, nil
	}
	remaining, err = d.until.RemainingMS()
	if errors.Is(err, timev4.ErrExpired) {
		err = ErrTerminationDeadline
	}
	if err != nil {
		d.failure = err
		return 0, false, err
	}
	if !d.quarantine && d.normal != nil {
		normal, e := d.normal.RemainingMS()
		if errors.Is(e, timev4.ErrExpired) {
			d.enterQuarantine()
		} else if e != nil {
			d.failure = e
		} else {
			remaining = min(remaining, normal)
		}
	}
	return remaining, d.quarantine, d.failure
}

func (d *directionTermination) finish() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.finishLocked()
}

// A late proof cannot erase an expired original deadline before the Session
// coordinator gets CPU time. Retirement may still finish cleanup separately.
func (d *directionTermination) complete() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.done && d.service != nil {
		if d.failure != nil {
			return d.failure
		}
		if d.until != nil {
			if _, err := d.until.RemainingMS(); err != nil {
				if errors.Is(err, timev4.ErrExpired) {
					err = ErrTerminationDeadline
				}
				d.failure = err
				return err
			}
		}
	}
	d.finishLocked()
	return nil
}

func (d *directionTermination) finishLocked() {
	if d.done {
		return
	}
	d.done = true
	d.normal, d.until = nil, nil
	if d.service != nil {
		if d.quarantine {
			d.service.quarantined.Add(^uint32(0))
			d.quarantine = false
		}
		d.service.notify()
	}
}

func (d *directionTermination) retire() {
	d.finish()
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.service != nil {
		d.service.references.Add(-1)
		d.service = nil
	}
	d.normal, d.until = nil, nil
}

func (d *directionTermination) firstCause() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.cause
}

// StreamTerminationService rotates over original bounded OPEN/proof slots.
// It publishes through the same scope-zero writer as rekey/ordinary maintenance;
// no per-Stream queue, replacement writer or per-message task is created.
type StreamTerminationService struct {
	admission            *OpenAdmission
	writer               *RecordWriter
	policy               StreamTerminationPolicy
	reservation          resourcev4.Reference
	publication          *timev4.Window
	rejectionPublication *timev4.Deadline
	rekeyTiming          *rekeyTiming
	rekeyRound           *cryptov4.RekeyRound
	wake, stop, done     chan struct{}
	quarantined          atomic.Uint32
	references           atomic.Int64
	sealed               atomic.Bool
	// The original admission gate protects these service lifecycle fields.
	cursor                                                int
	active, started, closed, coordinator, worker, cleaned bool
}

func StreamTerminationServiceCharge(streams uint32) (resourcev4.Vector, error) {
	// Direction structs are part of SendFlow/ReceivePool charges. Up to three
	// clock objects per direction include an immediate quarantine contraction.
	bytes := uint64(unsafe.Sizeof(StreamTerminationService{})) + (uint64(streams)*6+1)*uint64(unsafe.Sizeof(timev4.Window{}))
	return resourcev4.Vector{resourcev4.Timers: 1, resourcev4.SDKBytes: bytes, resourcev4.Items: uint64(streams)*6 + 2, resourcev4.Tasks: 2, resourcev4.WorkSlots: 2}, nil
}

func NewStreamTerminationService(a *OpenAdmission, writer *RecordWriter, policy StreamTerminationPolicy, reservation resourcev4.Reference) (*StreamTerminationService, error) {
	if a == nil || writer == nil || writer.engine != a.engine || writer.scope != 0 || policy.NormalMS == 0 || policy.QuarantineMS == 0 || policy.NormalMS > math.MaxUint64-policy.QuarantineMS || policy.QuarantineDirections == 0 || policy.QuarantineDirections > 32 || policy.QuarantineMS > 10000 {
		return nil, cryptov4.ErrConfiguration
	}
	if _, err := timev4.NewWindow(a.engine.Clock(), policy.NormalMS); err != nil {
		return nil, err
	}
	if _, err := timev4.NewWindow(a.engine.Clock(), policy.QuarantineMS); err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed || a.runtime != nil || a.termination != nil || a.active != 0 || a.pending != 0 || a.positiveProofs != 0 || a.rejectionProofs != 0 || a.bootstrap != nil || a.exchange != nil {
		return nil, cryptov4.ErrConfiguration
	}
	charge, err := StreamTerminationServiceCharge(a.limits.Active)
	if err != nil {
		return nil, err
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		return nil, err
	}
	p := &StreamTerminationService{admission: a, writer: writer, policy: policy, reservation: owned, wake: make(chan struct{}, 1), stop: make(chan struct{}), done: make(chan struct{})}
	a.termination = p
	return p, nil
}

func (p *StreamTerminationService) notify() {
	select {
	case p.wake <- struct{}{}:
	default:
	}
}

// checkLocked checks all original deadlines even while a provider publication
// is blocked. Receipt/proof and real cleanup remain independent facts.
func (p *StreamTerminationService) checkLocked() (remaining uint64, err error) {
	a := p.admission
	if p.closed || a.closed {
		return 0, cryptov4.ErrClosed
	}
	if err := p.reservation.Check(); err != nil {
		return 0, err
	}
	remaining, err = a.engine.AuthorizationRemainingMS()
	if err != nil {
		return 0, err
	}
	if p.publication != nil {
		r, err := p.publication.RemainingMS()
		if errors.Is(err, timev4.ErrExpired) {
			err = ErrTerminationDeadline
		}
		if err != nil {
			return 0, err
		}
		remaining = min(remaining, r)
	}
	if p.rejectionPublication != nil {
		r, err := p.rejectionPublication.RemainingMS()
		if err != nil {
			return 0, rekeyTimeError(err)
		}
		remaining = min(remaining, r)
	}
	if p.rekeyTiming != nil {
		r, active, err := p.rekeyTiming.protocolRemainingMS()
		if err != nil {
			return 0, err
		}
		if active {
			cap, err := p.rekeyRound.DeadlineRemainingMS()
			if err != nil {
				return 0, err
			}
			remaining = min(remaining, r, cap)
		}
	}
	for i := range a.slots {
		s := &a.slots[i]
		if s.phase == openOpening || s.phase == openPending || s.pendingRejection() || s.rejectionToken && s.deciding {
			r, err := s.deadline.RemainingMS()
			if err != nil {
				return 0, rekeyTimeError(err)
			}
			remaining = min(remaining, r)
		}
		if !s.accepted || s.flow == nil {
			continue
		}
		for _, d := range []*directionTermination{&s.flow.send.termination, &s.flow.receive.termination} {
			r, fence, err := d.poll()
			if err != nil {
				return 0, err
			}
			if r != 0 {
				remaining = min(remaining, r)
			}
			if fence {
				if d == &s.flow.receive.termination {
					s.flow.receive.pool.mu.Lock()
					reached := s.flow.receive.hasTerminal && s.flow.receive.observed == s.flow.receive.terminal
					s.flow.receive.pool.mu.Unlock()
					// A delayed maintenance handoff cannot discard a FIN's
					// already authenticated unread application bytes.
					if !reached {
						s.flow.receive.Fence()
						if s.flow.nativeReceive != nil {
							s.flow.nativeReceive.Close()
						}
					}
				} else {
					s.flow.send.Stop()
					if !s.stoppedSubmitted {
						s.stoppedDirty = true
					}
				}
			}
		}
	}
	return remaining, nil
}

type terminalMessage uint8

const (
	terminalStop terminalMessage = iota
	terminalStopped
	terminalDrained
	terminalReject
	terminalCredit
)

func (p *StreamTerminationService) nextLocked() (chosen *openSlot, kind terminalMessage, next int) {
	a := p.admission
	for scanned := range len(a.slots) {
		i := (p.cursor + scanned) % len(a.slots)
		s := &a.slots[i]
		if s.pendingRejection() && !s.deciding {
			return s, terminalReject, (i + 1) % len(a.slots)
		}
		if !s.accepted || s.flow == nil || s.phase != openLive && s.phase != openRecent || s.terminalPublishing || s.cleanupBusy {
			continue
		}
		f := s.flow
		if _, ok := f.receive.DrainProof(); ok && !s.drainSubmitted {
			return s, terminalDrained, (i + 1) % len(a.slots)
		}
		f.send.mu.Lock()
		stopped := f.send.hasTerminal && (!f.send.finTerminal && !s.stoppedSubmitted || s.stoppedDirty)
		f.send.mu.Unlock()
		if stopped {
			return s, terminalStopped, (i + 1) % len(a.slots)
		}
		f.receive.pool.mu.Lock()
		stop := f.receive.abandoned && !f.receive.hasTerminal && !s.stopSubmitted
		f.receive.pool.mu.Unlock()
		if stop {
			return s, terminalStop, (i + 1) % len(a.slots)
		}
	}
	// Credit uses this same finite maintenance worker after terminal work.
	// Each Stream retains only its latest absolute frontier, never an ACK queue.
	for scanned := range len(a.slots) {
		i := (p.cursor + scanned) % len(a.slots)
		s := &a.slots[i]
		if !s.accepted || s.flow == nil || s.phase != openLive || s.terminalPublishing || s.cleanupBusy {
			continue
		}
		f := s.flow.receive
		f.pool.mu.Lock()
		ready := f.creditReadyLocked()
		f.pool.mu.Unlock()
		if ready {
			return s, terminalCredit, (i + 1) % len(a.slots)
		}
	}
	return nil, terminalStop, p.cursor
}

// Progress publishes at most one message. Before-ticket contention retains
// the original intent; once ticketed, any publication failure closes Session.
func (p *StreamTerminationService) Progress(ctx context.Context) (result RecordWriteResult, ready bool, err error) {
	if ctx == nil {
		return result, false, cryptov4.ErrConfiguration
	}
	a := p.admission
	a.mu.Lock()
	if _, err = p.checkLocked(); err != nil {
		a.mu.Unlock()
		a.closeWithCause(err)
		return result, false, err
	}
	if p.active {
		a.mu.Unlock()
		return result, false, nil
	}
	chosen, kind, next := p.nextLocked()
	if chosen == nil {
		a.mu.Unlock()
		return result, false, nil
	}
	if kind == terminalReject {
		p.rejectionPublication = chosen.deadline
	} else {
		d := &chosen.flow.receive.termination
		if kind == terminalStopped {
			d = &chosen.flow.send.termination
		}
		d.mu.Lock()
		p.publication = d.until
		d.mu.Unlock()
	}
	if p.publication == nil && p.rejectionPublication == nil {
		// A duplicate STOP can request an existing completed proof. Its real
		// publication still owns finite original maintenance work.
		p.publication, err = timev4.NewWindow(a.engine.Clock(), p.policy.NormalMS)
		if err != nil {
			a.mu.Unlock()
			a.closeWithCause(err)
			return result, false, err
		}
	}
	p.active = true
	p.cursor = next
	chosen.retirementReferences++
	h := OpenHandle{a, chosen.scope}
	a.mu.Unlock()
	if kind == terminalReject {
		result, err = a.PublishRejection(ctx, h, p.writer)
	} else {
		result, err = a.publishTerminalMessage(ctx, h, p.writer, kind)
	}
	a.mu.Lock()
	if kind == terminalReject && !result.Submitted && errors.Is(err, ErrOpenAssociation) && chosen.rejectionToken && (chosen.phase == openRecent || chosen.phase == openHeld) {
		// Another publisher may win between selection and claim. Its one
		// outcome already owns the proof; never publish a second one or close
		// a healthy Session solely because this scheduling hint was stale.
		err = a.checkDeadline(p.rejectionPublication)
	}
	if err == nil && p.publication != nil {
		if e := p.publication.Check(); e != nil {
			err = e
			if errors.Is(e, timev4.ErrExpired) {
				err = ErrTerminationDeadline
			}
		}
	}
	p.publication = nil
	p.rejectionPublication = nil
	p.active = false
	chosen.retirementReferences--
	a.collect(chosen)
	p.cleanupLocked()
	a.mu.Unlock()
	if !result.Submitted && (errors.Is(err, cryptov4.ErrCapacity) || errors.Is(err, cryptov4.ErrTransition) || errors.Is(err, cryptov4.ErrNotReady) || errors.Is(err, ErrOpenPending)) {
		return result, false, nil
	}
	if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		a.closeWithCause(err)
	}
	return result, true, err
}

// Run uses two pre-admitted tasks: one finite publication worker and an
// independent deadline coordinator. A stuck provider never stalls expiry.
func (p *StreamTerminationService) Run(ctx context.Context) (err error) {
	if ctx == nil {
		return cryptov4.ErrConfiguration
	}
	a := p.admission
	a.mu.Lock()
	if p.started || p.closed {
		a.mu.Unlock()
		return cryptov4.ErrClosed
	}
	p.started, p.coordinator, p.worker = true, true, true
	a.mu.Unlock()
	defer func() { a.closeWithCause(err); a.mu.Lock(); p.coordinator = false; p.cleanupLocked(); a.mu.Unlock() }()
	type completion struct {
		ready bool
		err   error
	}
	jobs, completed := make(chan struct{}), make(chan completion, 1)
	go func() {
		defer func() { a.mu.Lock(); p.worker = false; p.cleanupLocked(); a.mu.Unlock() }()
		for range jobs {
			_, ready, err := p.Progress(ctx)
			completed <- completion{ready, err}
		}
	}()
	defer close(jobs)
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	defer timer.Stop()
	busy, retry := false, false
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		a.mu.Lock()
		remaining, err := p.checkLocked()
		var submit chan<- struct{}
		if err == nil && !busy {
			if chosen, _, _ := p.nextLocked(); chosen != nil {
				if retry {
					remaining = min(remaining, uint64(10))
				} else {
					submit = jobs
				}
			}
		}
		a.mu.Unlock()
		if err != nil {
			return err
		}
		// Only actual before-ticket contention uses a finite retry quantum.
		// Idle services sleep until an owner event or original security cap;
		// successful publications immediately make the next direction eligible.
		timer.Reset(idleTimerChunk(remaining))
		select {
		case submit <- struct{}{}:
			busy = true
		case <-ctx.Done():
			return ctx.Err()
		case <-p.stop:
			return cryptov4.ErrClosed
		case <-a.engine.Done():
			return cryptov4.ErrClosed
		case result := <-completed:
			busy = false
			retry = !result.ready
			if result.err != nil {
				return result.err
			}
		case <-p.wake:
			retry = false
		case <-timer.C:
			retry = false
		}
		timer.Stop()
	}
}

func (p *StreamTerminationService) Close() {
	a := p.admission
	a.mu.Lock()
	defer a.mu.Unlock()
	if !p.closed {
		p.sealed.Store(true)
		p.closed = true
		close(p.stop)
	}
	p.cleanupLocked()
}

func (p *StreamTerminationService) cleanupLocked() {
	if p.closed && !p.cleaned && !p.active && !p.coordinator && !p.worker {
		p.cleaned = true
		close(p.done)
	}
}

func (p *StreamTerminationService) WaitCleanup(ctx context.Context) error {
	if ctx == nil {
		return cryptov4.ErrConfiguration
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-p.done:
		return nil
	}
}

func (p *StreamTerminationService) retire() error {
	a := p.admission
	a.mu.Lock()
	defer a.mu.Unlock()
	if !p.cleaned || p.references.Load() != 0 {
		return cryptov4.ErrCapacity
	}
	p.reservation.Release()
	return nil
}
