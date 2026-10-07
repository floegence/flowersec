package sessionv4

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

type managementCall struct {
	token                                 uint64
	serial                                uint64
	done                                  chan struct{}
	response                              rpcv4.ManagementResponse
	err                                   error
	diagnosticOperation                   *DiagnosticOperation
	used, complete, abandoned, publishing bool
}

type earlyManagementResponse struct {
	used       bool
	ownerToken uint64
	serial     uint64
	response   rpcv4.ManagementResponse
	err        error
}

// ManagementChannel owns the actual M Stream: one reader, two finite SDK
// service workers, and two original outbound wait/result positions. It never
// borrows an application executor slot or starts a per-request goroutine.
type ManagementChannel struct {
	mu                                 sync.Mutex
	owner                              *StreamOwnership
	writer                             *RPCBatchWriter
	engine                             *rpcv4.ExecutionManagementWire
	parser                             *protocolv4.ManagementParser
	clock                              *timev4.Clock
	resolver                           rpcv4.ExecutionManagementResolver
	reservation, parserReservation     resourcev4.Reference
	buffer                             [16384]byte
	executor                           *ApplicationExecutor
	executorBorrow                     resourcev4.Reference
	managementTasks                    [2]*managementTask
	managementWake                     chan struct{}
	tasks                              sync.WaitGroup
	workers                            sync.WaitGroup
	calls                              [2]managementCall
	earlyResponses                     [2]earlyManagementResponse
	callToken                          uint64
	waiters                            int
	waitersDone                        chan struct{}
	done, closeDone                    chan struct{}
	cancel                             context.CancelFunc
	started, closed, cleaned, cleaning bool
}

func ManagementChannelCharge(runtimeBytes uint64) (resourcev4.Vector, error) {
	if runtimeBytes == 0 {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	return (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(ManagementChannel{})) + 2*(uint64(unsafe.Sizeof(managementTask{}))+256) + 3*uint64(unsafe.Sizeof(timev4.Deadline{})), resourcev4.Items: 8, resourcev4.Tasks: 2, resourcev4.WorkSlots: 2, resourcev4.Timers: 4}).Add(resourcev4.Vector{resourcev4.SDKBytes: runtimeBytes})
}
func ManagementParserCharge(runtimeBytes uint64) (resourcev4.Vector, error) {
	if runtimeBytes == 0 {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	n, err := protocolv4.ManagementParserBackingBytes()
	if err != nil {
		return resourcev4.Vector{}, err
	}
	return (resourcev4.Vector{resourcev4.SDKBytes: n, resourcev4.Items: 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: runtimeBytes})
}
func NewManagementChannel(owner *StreamOwnership, clock *timev4.Clock, executor *ApplicationExecutor, resolver rpcv4.ExecutionManagementResolver, refs [4]resourcev4.Reference, runtimeBytes uint64) (_ *ManagementChannel, err error) {
	if owner == nil || clock == nil || executor == nil {
		return nil, cryptov4.ErrConfiguration
	}
	for _, ref := range refs[1:] {
		if err := refs[0].CheckSameEnvironment(ref); err != nil {
			return nil, err
		}
	}
	charge, err := ManagementChannelCharge(runtimeBytes)
	if err != nil {
		return nil, err
	}
	owned, err := refs[0].Take(charge)
	if err != nil {
		return nil, err
	}
	c := &ManagementChannel{owner: owner, clock: clock, executor: executor, resolver: resolver, reservation: owned, managementWake: make(chan struct{}, 1), done: make(chan struct{}), closeDone: make(chan struct{}), waitersDone: make(chan struct{})}
	if c.resolver == nil {
		c.resolver = rpcv4.ExecutionManagementResolverFunc(nil)
	}
	defer func() {
		if err != nil {
			if c.engine != nil {
				c.engine.Close()
			}
			if c.writer != nil {
				c.writer.Close()
				_ = c.writer.Retire()
			}
			c.parserReservation.Release()
			c.executorBorrow.Release()
			owned.Release()
		}
	}()
	executor.mu.Lock()
	if err = executor.reservation.CheckSameRoot(owned); err == nil {
		c.executorBorrow, err = executor.reservation.Borrow()
	}
	executor.mu.Unlock()
	if err != nil {
		return nil, err
	}
	c.writer, err = newManagementBatchWriter(owner, refs[1], runtimeBytes)
	if err != nil {
		return nil, err
	}
	c.engine, err = rpcv4.NewExecutionManagementWire(rpcv4.ExecutionManagementWireConfig{Clock: clock, Sink: c.writer, RuntimeBytes: runtimeBytes,
		DrainDeadline: owner.admission.managementDeadline.Load,
		AdmissionOpen: func() bool { return !owner.admission.managementSealed.Load() },
	}, refs[2])
	if err != nil {
		return nil, err
	}
	charge, err = ManagementParserCharge(runtimeBytes)
	if err != nil {
		return nil, err
	}
	c.parserReservation, err = refs[3].Take(charge)
	if err != nil {
		return nil, err
	}
	c.parser, err = protocolv4.NewManagementParser()
	if err != nil {
		return nil, err
	}
	if err = owner.protectReceiveCredit(16384); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *ManagementChannel) remainingManagementMS(deadline *timev4.Deadline) (uint64, error) {
	if c.owner.admission.managementSealed.Load() {
		return 0, rpcv4.ErrManagementClosed
	}
	if original := c.owner.admission.managementDeadline.Load(); original != nil {
		if err := deadline.TightenFrom(original); err != nil {
			return 0, err
		}
	}
	return deadline.RemainingMS()
}

// Request keeps the original deadline, target and authorization until the
// complete response or generation cleanup. Local cancellation only abandons
// the wait; an unresolved late response still occupies its original cell.
func (c *ManagementChannel) Request(ctx context.Context, cancel bool, target rpcv4.ExecutionTarget, deadline *timev4.Deadline, access rpcv4.ExecutionAccess) (rpcv4.ManagementResponse, error) {
	return c.requestWithDiagnostic(ctx, cancel, target, deadline, access, nil)
}

func (c *ManagementChannel) requestWithDiagnostic(ctx context.Context, cancel bool, target rpcv4.ExecutionTarget, deadline *timev4.Deadline, access rpcv4.ExecutionAccess, diagnosticOperation *DiagnosticOperation) (response rpcv4.ManagementResponse, returnErr error) {
	transferred := false
	defer func() {
		if !transferred {
			finishApplicationDiagnosticError(diagnosticOperation, returnErr)
		}
	}()
	if c == nil || ctx == nil || deadline == nil || access == nil {
		return rpcv4.ManagementResponse{}, cryptov4.ErrConfiguration
	}
	c.mu.Lock()
	if c.closed || c.owner != nil && c.owner.admission.managementSealed.Load() {
		c.mu.Unlock()
		return rpcv4.ManagementResponse{}, rpcv4.ErrManagementClosed
	}
	index := -1
	for i := range c.calls {
		if !c.calls[i].used {
			index = i
			break
		}
	}
	if index < 0 {
		c.mu.Unlock()
		return rpcv4.ManagementResponse{}, rpcv4.ErrCapacity
	}
	c.mu.Unlock()
	if err := deadline.Check(); err != nil {
		return rpcv4.ManagementResponse{}, err
	}
	c.mu.Lock()
	if c.closed || c.owner != nil && c.owner.admission.managementSealed.Load() {
		c.mu.Unlock()
		return rpcv4.ManagementResponse{}, rpcv4.ErrManagementClosed
	}
	if c.calls[index].used {
		index = -1
		for i := range c.calls {
			if !c.calls[i].used {
				index = i
				break
			}
		}
		if index < 0 {
			c.mu.Unlock()
			return rpcv4.ManagementResponse{}, rpcv4.ErrCapacity
		}
	}
	// Claim the original result position after the caller deadline check. No
	// request serial is consumed while publication is pending. The token gives
	// an early response a stable owner even while its serial is still zero.
	c.callToken++
	if c.callToken == 0 {
		c.mu.Unlock()
		return rpcv4.ManagementResponse{}, cryptov4.ErrCapacity
	}
	cell := &c.calls[index]
	*cell = managementCall{token: c.callToken, used: true, done: make(chan struct{}), diagnosticOperation: diagnosticOperation}
	transferred = true
	c.waiters++
	done := cell.done
	c.mu.Unlock()
	// The original waiter owns its engine tail until Abandon and diagnostic
	// transfer have returned; physical cleanup must not overtake that tail.
	defer func() {
		c.mu.Lock()
		c.leaveWaiterLocked()
		c.mu.Unlock()
	}()
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	defer timer.Stop()
	for {
		remaining, err := c.remainingManagementMS(deadline)
		if err == nil {
			err = ctx.Err()
		}
		wake := c.writer.ManagementWake()
		c.mu.Lock()
		closed := c.closed
		engine := c.engine
		if !closed && err == nil {
			cell.publishing = true
		}
		c.mu.Unlock()
		if closed {
			err = rpcv4.ErrManagementClosed
		}
		var serial uint64
		if err == nil {
			serial, err = engine.TryRequestDeadlineOwned(ctx, cancel, target, deadline, access, cell.token)
		}
		abandonSerial := uint64(0)
		c.mu.Lock()
		cell.publishing = false
		if err == nil {
			closed = c.closed
			if !closed {
				cell.serial = serial
				for i := range c.earlyResponses {
					early := &c.earlyResponses[i]
					if !early.used || early.ownerToken != cell.token || early.serial != serial {
						continue
					}
					if !cell.complete {
						cell.response, cell.err, cell.complete = early.response, early.err, true
						close(cell.done)
					}
					*early = earlyManagementResponse{}
				}
				c.mu.Unlock()
				break
			}
			// Close may race the finite engine publication. Retire the serial
			// after releasing c.mu if the engine still owns it.
			abandonSerial = serial
			err = rpcv4.ErrManagementClosed
		}
		if err == nil {
			c.mu.Unlock()
			break
		}
		if !errors.Is(err, cryptov4.ErrCapacity) {
			c.clearEarlyResponseLocked(cell.token)
			operation := c.retireCallLocked(cell, err)
			c.mu.Unlock()
			if abandonSerial != 0 {
				_ = engine.Abandon(abandonSerial)
			}
			finishApplicationDiagnosticError(operation, err)
			return rpcv4.ManagementResponse{}, err
		}
		c.mu.Unlock()
		timer.Reset(time.Duration(min(remaining, uint64((1<<63-1)/time.Millisecond))) * time.Millisecond)
		select {
		case <-ctx.Done():
		case <-done:
		case <-wake:
		case <-timer.C:
		}
		timer.Stop()
	}
	var waitErr error
	for waitErr == nil {
		remaining, err := c.remainingManagementMS(deadline)
		if err != nil {
			waitErr = err
			break
		}
		timer.Reset(time.Duration(min(remaining, uint64((1<<63-1)/time.Millisecond))) * time.Millisecond)
		select {
		case <-done:
			c.mu.Lock()
			response, err := cell.response, cell.err
			c.mu.Unlock()
			if err == nil {
				err = ctx.Err()
			}
			if err == nil && response.Status != "unavailable" {
				err = access.WithExecutionAccess(target, func(authority resourcev4.Reference) error {
					return c.reservation.CheckSameEnvironment(authority)
				})
			}
			if err == nil {
				err = deadline.Check()
			}
			if err != nil {
				response = rpcv4.ManagementResponse{}
			}
			c.mu.Lock()
			operation := c.retireCallLocked(cell, err)
			c.mu.Unlock()
			finishApplicationDiagnosticError(operation, err)
			return response, err
		case <-ctx.Done():
			waitErr = ctx.Err()
		case <-timer.C:
		}
		timer.Stop()
	}
	c.mu.Lock()
	// Even an already completed result must pass this caller's original wait
	// deadline. A simultaneous response is retired once, without redelivery.
	engine := c.engine
	abandonSerial := uint64(0)
	var operation *DiagnosticOperation
	if cell.complete || c.closed {
		c.clearEarlyResponseLocked(cell.token)
		operation = c.retireCallLocked(cell, waitErr)
	} else {
		cell.abandoned = true
		recordApplicationDiagnosticFailure(cell.diagnosticOperation, waitErr)
		abandonSerial = cell.serial
	}
	c.mu.Unlock()
	if abandonSerial != 0 {
		_ = engine.Abandon(abandonSerial)
	}
	finishApplicationDiagnosticError(operation, waitErr)
	return rpcv4.ManagementResponse{}, waitErr
}

// retireCallLocked withdraws only this observer. Once Close begins, the
// original diagnostic reference stays in its cell until engine, writer and
// native stream cleanup have all completed in WaitCleanup.
func (c *ManagementChannel) retireCallLocked(cell *managementCall, cause error) *DiagnosticOperation {
	if c.closed {
		cell.abandoned = true
		recordApplicationDiagnosticFailure(cell.diagnosticOperation, cause)
		// The caller has taken its result. Only the original diagnostic
		// responsibility remains; retain no returned error graph in this cell.
		cell.err, cell.response = nil, rpcv4.ManagementResponse{}
		return nil
	}
	operation := cell.diagnosticOperation
	*cell = managementCall{}
	return operation
}

func (c *ManagementChannel) clearEarlyResponseLocked(ownerToken uint64) {
	if ownerToken == 0 {
		return
	}
	for i := range c.earlyResponses {
		if c.earlyResponses[i].used && c.earlyResponses[i].ownerToken == ownerToken {
			c.earlyResponses[i] = earlyManagementResponse{}
		}
	}
}

func (c *ManagementChannel) leaveWaiterLocked() {
	c.waiters--
	if c.closed && c.waiters == 0 {
		close(c.waitersDone)
	}
}
func (c *ManagementChannel) acceptResponse(wire []byte) error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return rpcv4.ErrManagementClosed
	}
	engine := c.engine
	c.mu.Unlock()
	// Engine decoding and association validation own their own finite gate and
	// must not be nested under the channel mutex.
	response, serial, ownerToken, disposition, err := engine.AcceptResponseWithOwner(wire)
	if err != nil && disposition != rpcv4.ManagementResponseRejected {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return rpcv4.ErrManagementClosed
	}
	for i := range c.calls {
		cell := &c.calls[i]
		if !cell.used || cell.serial != serial || cell.complete {
			continue
		}
		if cell.abandoned {
			operation := cell.diagnosticOperation
			*cell = managementCall{}
			finishApplicationDiagnostic(operation)
			return nil
		}
		if disposition == rpcv4.ManagementResponseDiscarded {
			// A response may leave the wire while the channel still holds the
			// publication gate. Route it by the real owner token below; using
			// the not-yet-installed serial would discard a valid result.
			if ownerToken == 0 {
				return nil
			}
		}
		if disposition != rpcv4.ManagementResponseDiscarded {
			cell.response, cell.err, cell.complete = response, err, true
			close(cell.done)
			return nil
		}
		// A discarded disposition can still carry the authenticated early
		// response from the wire publication window. Preserve that fact in the
		// real owner cell; processing/duplicate dispositions carry a zero
		// response and must leave the waiter pending rather than waking it with
		// an empty value. The done channel is closed exactly once.
		if ownerToken == cell.token && response.Serial == serial {
			cell.response, cell.err, cell.complete = response, err, true
			close(cell.done)
		}
		return nil
	}
	if disposition == rpcv4.ManagementResponseDiscarded && ownerToken == 0 {
		return nil
	}
	if ownerToken == 0 {
		return nil
	}
	for i := range c.calls {
		if !c.calls[i].used || c.calls[i].token != ownerToken || !c.calls[i].publishing {
			continue
		}
		for j := range c.earlyResponses {
			early := &c.earlyResponses[j]
			if early.used {
				continue
			}
			*early = earlyManagementResponse{used: true, ownerToken: ownerToken, serial: serial, response: response, err: err}
			return nil
		}
		return nil
	}
	return nil
}
func (c *ManagementChannel) Run(ctx context.Context) (err error) {
	if c == nil || ctx == nil {
		return cryptov4.ErrConfiguration
	}
	c.mu.Lock()
	if c.started || c.closed {
		c.mu.Unlock()
		return cryptov4.ErrTransition
	}
	runCtx, cancel := context.WithCancel(ctx)
	c.cancel, c.started = cancel, true
	c.workers.Add(1)
	c.mu.Unlock()
	go c.serve(runCtx)
	defer func() {
		c.Close()
		c.workers.Wait()
		c.tasks.Wait()
		close(c.done)
	}()
	var job rpcv4.ManagementJob
	var response bool
	var partial *timev4.Deadline
	onHeader := func(h protocolv4.ApplicationHeader) error {
		response = h.IsResponse()
		if response {
			return nil
		}
		var err error
		job, err = c.engine.BeginRequestHeader(h)
		return err
	}
	for {
		readCtx := runCtx
		var stopRead context.CancelFunc
		if partial != nil {
			remaining, err := partial.RemainingMS()
			if err != nil {
				return err
			}
			if !response && job != (rpcv4.ManagementJob{}) {
				original, err := job.RemainingMS()
				if err != nil {
					return err
				}
				remaining = min(remaining, original)
			}
			readCtx, stopRead = context.WithTimeout(runCtx, time.Duration(remaining)*time.Millisecond)
		}
		read, readErr := c.owner.ReadInto(readCtx, c.buffer[:])
		if stopRead != nil {
			stopRead()
		}
		input := c.buffer[:read.Progress.Filled]
		for len(input) > 0 {
			if partial == nil {
				partial, err = timev4.NewAge(c.clock, 30000, ^uint64(0))
				if err != nil {
					return err
				}
			}
			if err := partial.Check(); err != nil {
				return err
			}
			n, wire, err := c.parser.NextWithHeader(input, onHeader)
			if err != nil {
				return err
			}
			input = input[n:]
			if wire == nil {
				continue
			}
			partial = nil
			if response {
				err = c.acceptResponse(wire)
			} else {
				if err = job.Admit(wire); err == nil {
					err = c.queueManagement(runCtx, job)
				}
			}
			if err != nil {
				return err
			}
			job = rpcv4.ManagementJob{}
			response = false
		}
		clear(c.buffer[:read.Progress.Filled])
		if readErr != nil {
			return readErr
		}
		if read.ReadTerminal != protocolv4.V4ReadTerminalOpen {
			if err := c.parser.End(); err != nil {
				return err
			}
			return io.EOF
		}
	}
}
func (c *ManagementChannel) queueManagement(ctx context.Context, job rpcv4.ManagementJob) error {
	c.owner.admission.managementGate.Lock()
	defer c.owner.admission.managementGate.Unlock()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.owner.admission.managementSealed.Load() {
		return rpcv4.ErrManagementClosed
	}
	for i, current := range c.managementTasks {
		if current != nil {
			continue
		}
		callCtx, cancel := context.WithCancel(ctx)
		task := &managementTask{channel: c, job: job, ctx: callCtx, cancel: cancel, resolver: c.resolver, done: make(chan struct{})}
		c.managementTasks[i] = task
		c.tasks.Add(1)
		if err := c.executor.submitManagement(task); err != nil {
			task.err = err
			close(task.done)
			c.tasks.Done()
			c.managementTasks[i] = nil
			cancel()
			return err
		}
		notifyOpenWait(c.managementWake)
		return nil
	}
	return rpcv4.ErrCapacity
}

func (c *ManagementChannel) serve(ctx context.Context) {
	defer c.workers.Done()
	defer func() { _ = recover(); c.Close() }()
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	defer timer.Stop()
	for {
		wake := c.writer.ManagementWake()
		active := false
		for i := range c.managementTasks {
			c.mu.Lock()
			task := c.managementTasks[i]
			c.mu.Unlock()
			if task == nil {
				continue
			}
			active = true
			done := false
			select {
			case <-task.done:
				done = true
			default:
			}
			if !task.published {
				var err error
				_, deadlineErr := task.job.RemainingMS()
				if deadlineErr != nil || done && task.err != nil {
					// Check every unpublished reply, including one selected before
					// ring backpressure. Conversion retains the original slot/serial
					// and any still-running provider tail until actual return.
					task.cancel()
					task.response, err = task.job.Unavailable()
				} else if task.response == (rpcv4.ManagementReply{}) && done {
					task.response = task.reply
				}
				if err != nil {
					return
				}
				if task.response != (rpcv4.ManagementReply{}) {
					err = task.response.Publish(ctx)
					if err == nil {
						task.published = true
					} else if !errors.Is(err, cryptov4.ErrCapacity) {
						return
					}
				}
			}
			if task.published && done {
				task.cancel()
				c.mu.Lock()
				c.managementTasks[i] = nil
				c.mu.Unlock()
			}
		}
		var tick <-chan time.Time
		if active {
			timer.Reset(10 * time.Millisecond)
			tick = timer.C
		}
		select {
		case <-ctx.Done():
			return
		case <-c.managementWake:
		case <-wake:
		case <-tick:
		}
		timer.Stop()
	}
}
func (c *ManagementChannel) Close() {
	if c == nil {
		return
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	cancel := c.cancel
	if !c.started {
		close(c.done)
	}
	for i := range c.calls {
		p := &c.calls[i]
		if !p.used {
			continue
		}
		// All cells retain their diagnostic reference through physical cleanup,
		// including abandoned observers and publication turns still in flight.
		if !p.abandoned && !p.complete {
			p.complete, p.err = true, rpcv4.ErrManagementClosed
			close(p.done)
		}
	}
	if c.waiters == 0 {
		close(c.waitersDone)
	}
	clear(c.earlyResponses[:])
	c.mu.Unlock()
	defer close(c.closeDone)
	if cancel != nil {
		cancel()
	}
	c.engine.Close()
	c.writer.Close()
	_ = c.owner.Cancel()
}
func (c *ManagementChannel) WaitCleanup(ctx context.Context) error {
	if c == nil {
		return nil
	}
	if ctx == nil {
		return cryptov4.ErrConfiguration
	}
	c.mu.Lock()
	if c.cleaned {
		c.mu.Unlock()
		return nil
	}
	if !c.closed || c.cleaning {
		c.mu.Unlock()
		return cryptov4.ErrCapacity
	}
	c.cleaning = true
	c.mu.Unlock()
	defer func() { c.mu.Lock(); c.cleaning = false; c.mu.Unlock() }()
	for _, done := range []<-chan struct{}{c.closeDone, c.done, c.waitersDone} {
		select {
		case <-done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if !c.engine.CleanupComplete() {
		return cryptov4.ErrCapacity
	}
	for {
		err := c.writer.Retire()
		if err == nil {
			break
		}
		if !errors.Is(err, cryptov4.ErrCapacity) {
			return err
		}
		select {
		case <-c.writer.Wake():
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if err := c.owner.Cleanup(ctx); err != nil {
		return err
	}
	if err := c.owner.Release(); err != nil {
		return err
	}
	c.mu.Lock()
	var operations [2]*DiagnosticOperation
	for i := range c.calls {
		if c.calls[i].used {
			operations[i] = c.calls[i].diagnosticOperation
		}
		c.calls[i] = managementCall{}
	}
	clear(c.buffer[:])
	// All reader, service, waiter and provider aliases have physically exited.
	c.parser, c.engine, c.writer, c.owner, c.resolver = nil, nil, nil, nil, nil
	clear(c.managementTasks[:])
	c.executor = nil
	c.executorBorrow.Release()
	c.executorBorrow = resourcev4.Reference{}
	c.clock = nil
	c.parserReservation.Release()
	c.parserReservation = resourcev4.Reference{}
	c.reservation.Release()
	c.reservation = resourcev4.Reference{}
	c.cleaned = true
	c.mu.Unlock()
	// waitersDone guarantees the original finite outcome was recorded. A
	// successful response racing Close has no failure to add at cleanup.
	for _, operation := range operations {
		finishApplicationDiagnostic(operation)
	}
	return nil
}
