package sessionv4

import (
	"context"
	"math"
	"sync/atomic"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

// This fixed diagnostic service is a separate part of the original root
// executor. It cannot consume ordinary, Completion, management or query slots.
const diagnosticRunning = 2
const diagnosticReady = 4

type diagnosticLane struct {
	closing        chan struct{}
	slots          [diagnosticRunning + diagnosticReady]diagnosticTaskSlot
	running, ready uint32
	sequence       uint64
}

type diagnosticTaskSlot struct {
	handle   *diagnosticTask
	ctx      context.Context
	cancel   context.CancelCauseFunc
	work     func(context.Context)
	backing  resourcev4.Reference
	sequence uint64
	started  bool
	wake     chan<- struct{}
}

// A retained completed handle contains no callback, context, sink or executor.
// Slot reuse cannot let an old handle cancel a later callback.
type diagnosticTask struct {
	executor atomic.Pointer[ApplicationExecutor]
	index    int
	done     chan struct{}
}

func diagnosticLaneCharge(c ApplicationExecutorConfig) (resourcev4.Vector, error) {
	if !c.Diagnostics {
		return resourcev4.Vector{}, nil
	}
	if c.RuntimeBytesPerTask > math.MaxUint64/diagnosticRunning {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	charge := resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(diagnosticLane{})) + uint64(unsafe.Sizeof(diagnosticTask{}))*(diagnosticRunning+diagnosticReady), resourcev4.Items: diagnosticRunning + diagnosticReady, resourcev4.Tasks: diagnosticRunning, resourcev4.WorkSlots: diagnosticRunning}
	charge, err := charge.Add(resourcev4.Vector{resourcev4.SDKBytes: c.RuntimeBytesPerTask * diagnosticRunning})
	if err != nil {
		return resourcev4.Vector{}, err
	}
	return charge.Add(resourcev4.Vector{resourcev4.SDKBytes: c.RuntimeBytes})
}

// enqueueDiagnostic is used only by the diagnostic pump. It atomically moves
// the original event's admitted backing borrow into the diagnostic service.
// Capacity refusal leaves that borrow with the caller, which drops the event.
// parent is the sink's SDK-created cancellation context, never application code.
func (e *ApplicationExecutor) enqueueDiagnostic(parent context.Context, backingBorrow resourcev4.Reference, work func(context.Context), wake chan<- struct{}) (*diagnosticTask, error) {
	if e == nil || parent == nil || work == nil {
		return nil, cryptov4.ErrConfiguration
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || e.diagnostics == nil {
		return nil, resourcev4.ErrClosed
	}
	d := e.diagnostics
	if d.ready == diagnosticReady || d.sequence == math.MaxUint64 {
		return nil, cryptov4.ErrCapacity
	}
	if err := parent.Err(); err != nil {
		return nil, err
	}
	if err := e.reservation.CheckSameRoot(backingBorrow); err != nil {
		return nil, err
	}
	backing, err := backingBorrow.TakeBorrow()
	if err != nil {
		return nil, err
	}
	index := 0
	for d.slots[index].handle != nil {
		index++
	}
	d.sequence++
	ctx, cancel := context.WithCancelCause(parent)
	h := &diagnosticTask{index: index, done: make(chan struct{})}
	h.executor.Store(e)
	d.slots[index] = diagnosticTaskSlot{handle: h, ctx: ctx, cancel: cancel, work: work, backing: backing, sequence: d.sequence, wake: wake}
	d.ready++
	e.dispatchDiagnosticsLocked()
	return h, nil
}

func (e *ApplicationExecutor) dispatchDiagnosticsLocked() {
	d := e.diagnostics
	for !e.closed && d.running < diagnosticRunning && d.ready > 0 {
		index := -1
		for i := range d.slots {
			slot := &d.slots[i]
			if slot.handle != nil && !slot.started && (index < 0 || slot.sequence < d.slots[index].sequence) {
				index = i
			}
		}
		if index < 0 {
			return
		}
		s := &d.slots[index]
		if s.ctx.Err() != nil || s.backing.Check() != nil {
			e.releaseDiagnosticLocked(index)
			continue
		}
		s.started = true
		d.ready--
		d.running++
		go e.runDiagnostic(index, s.handle)
	}
}

func (e *ApplicationExecutor) runDiagnostic(index int, owner *diagnosticTask) {
	defer func() {
		// Includes every application defer, panic and Goexit before any charge
		// or actual running position can be reused.
		_ = recover()
		e.mu.Lock()
		e.releaseDiagnosticLocked(index)
		e.dispatchDiagnosticsLocked()
		e.cleanupLocked()
		e.mu.Unlock()
	}()
	e.mu.Lock()
	s := &e.diagnostics.slots[index]
	ctx, work := s.ctx, s.work
	allowed := s.handle == owner && !e.closed && ctx.Err() == nil && s.backing.Check() == nil
	e.mu.Unlock()
	if allowed {
		work(ctx)
	}
}

func (e *ApplicationExecutor) releaseDiagnosticLocked(index int) {
	d := e.diagnostics
	s := &d.slots[index]
	if s.handle == nil {
		return
	}
	s.handle.executor.Store(nil)
	s.cancel(context.Canceled)
	s.backing.Release()
	close(s.handle.done)
	select {
	case s.wake <- struct{}{}:
	default:
	}
	if s.started {
		d.running--
	} else {
		d.ready--
	}
	*s = diagnosticTaskSlot{}
}

func (h *diagnosticTask) cancel(reason error) {
	if h == nil {
		return
	}
	e := h.executor.Load()
	if e == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.diagnostics == nil || h.executor.Load() != e || e.diagnostics.slots[h.index].handle != h {
		return
	}
	s := &e.diagnostics.slots[h.index]
	if reason == nil {
		reason = context.Canceled
	}
	s.cancel(reason)
	if !s.started {
		e.releaseDiagnosticLocked(h.index)
		e.dispatchDiagnosticsLocked()
		e.cleanupLocked()
	}
}

func (e *ApplicationExecutor) closeDiagnosticsLocked() {
	if e.diagnostics == nil {
		return
	}
	select {
	case <-e.diagnostics.closing:
	default:
		close(e.diagnostics.closing)
	}
	for i := range e.diagnostics.slots {
		s := &e.diagnostics.slots[i]
		if s.handle == nil {
			continue
		}
		s.cancel(context.Canceled)
		if !s.started {
			e.releaseDiagnosticLocked(i)
		}
	}
}

// The sink is a borrower of the root's existing service. It cannot create a
// private executor or enable a lane after the root was admitted.
func (e *ApplicationExecutor) diagnosticService(backing resourcev4.Reference) (<-chan struct{}, error) {
	if e == nil {
		return nil, cryptov4.ErrConfiguration
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || e.diagnostics == nil {
		return nil, resourcev4.ErrClosed
	}
	if err := e.reservation.CheckSameRoot(backing); err != nil {
		return nil, err
	}
	return e.diagnostics.closing, nil
}
