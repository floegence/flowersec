package rpcv4

import (
	"context"
	"errors"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

type DurableExecutionWork struct{ *durableExecutionWork }
type durableExecutionWork struct {
	admission                                                                                  *DurableExecutionAdmission
	mu                                                                                         sync.Mutex
	history                                                                                    *DurableExecutions
	index                                                                                      int
	routes                                                                                     *ContractRoutes
	entry                                                                                      *contractRouteEntry
	input                                                                                      InputBorrow
	header                                                                                     protocolv4.ApplicationHeader
	policy                                                                                     protocolv4.ServiceContractPolicy
	target                                                                                     ExecutionTarget
	access                                                                                     ExecutionAccess
	database                                                                                   *ledgerv4.SQLiteExecutionWork
	reservation, task, storeReservation, authority                                             resourcev4.Reference
	deadline                                                                                   *timev4.Deadline
	output                                                                                     []byte
	outputBytes, outputCode                                                                    uint32
	resultReaders                                                                              uint32
	final                                                                                      ExecutionObservation
	writeFailed                                                                                bool
	contextCancel                                                                              context.CancelFunc
	taskDone                                                                                   <-chan struct{}
	io, admitted, taskIssued, entered, reported, resultCommitted, published, cancelled, exited bool
}

func durableExecutionWorkCharge(response uint32, runtimeBytes uint64) (resourcev4.Vector, error) {
	if response > 1048576 || runtimeBytes == 0 {
		return resourcev4.Vector{}, ErrConfiguration
	}
	n := uint64(unsafe.Sizeof(DurableExecutionWork{})) + uint64(unsafe.Sizeof(durableExecutionWork{})) + uint64(unsafe.Sizeof(timev4.Deadline{})) + uint64(response) + 128
	return (resourcev4.Vector{resourcev4.SDKBytes: n, resourcev4.Items: 2}).Add(resourcev4.Vector{resourcev4.SDKBytes: runtimeBytes})
}

func (w *DurableExecutionWork) beginIO() error {
	if w == nil || w.durableExecutionWork == nil {
		return ErrOwner
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.exited {
		return ErrOwner
	}
	if w.io {
		return ErrCapacity
	}
	w.io = true
	return nil
}
func (w *DurableExecutionWork) endIO() {
	w.mu.Lock()
	w.io = false
	admission := w.releaseResultLocked()
	w.mu.Unlock()
	if admission != nil {
		admission.releaseTail()
	}
}

func (w *DurableExecutionWork) entryGuard() error {
	w.mu.Lock()
	cancelled := w.cancelled
	w.mu.Unlock()
	if cancelled {
		return timev4.ErrCancelled
	}
	if err := w.deadline.Check(); err != nil {
		return err
	}
	return w.history.checkVerified(w.target, w.access, w.routes, w.input.owner, w.header, w.policy, w)
}

// SubmitTask starts only the original preacquired executor permit. The callback
// is finite SDK work that returns its genuine post-application exit channel.
// Holding this short gate makes immediate executor entry observe taskIssued;
// no database operation or application callback runs under it.
func (w *DurableExecutionWork) SubmitTask(submit func() (<-chan struct{}, error)) error {
	if w == nil || w.durableExecutionWork == nil || submit == nil {
		return ErrOwner
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.io || w.exited || !w.admitted || w.taskIssued || w.cancelled {
		return ErrOwner
	}
	done, err := submit()
	if err != nil {
		return err
	}
	w.taskIssued, w.taskDone = true, done
	w.task = resourcev4.Reference{}
	if done == nil {
		return ErrConfiguration
	}
	return nil
}

func (w *DurableExecutionWork) Context(parent context.Context) (context.Context, error) {
	if w == nil || w.durableExecutionWork == nil || parent == nil {
		return nil, ErrOwner
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.io || w.exited || !w.admitted || w.contextCancel != nil {
		return nil, ErrOwner
	}
	ctx, cancel := context.WithCancel(parent)
	w.contextCancel = cancel
	if w.cancelled {
		cancel()
	}
	return ctx, nil
}

func (w *DurableExecutionWork) Enter(ctx context.Context) (InputBorrow, error) {
	if err := w.beginIO(); err != nil {
		return InputBorrow{}, err
	}
	defer w.endIO()
	if !w.admitted || !w.taskIssued || w.entered {
		return InputBorrow{}, ErrOwner
	}
	if err := w.database.Enter(ctx, w.entryGuard); err != nil {
		return InputBorrow{}, err
	}
	// Recheck the original input owner's earlier monotonic projection and
	// current permission after the actual provider call, before input delivery.
	if err := w.entryGuard(); err != nil {
		return InputBorrow{}, err
	}
	w.entered = true
	w.final.State, w.final.Dispatched = ExecutionExecuting, true
	return w.input, nil
}

func (w *DurableExecutionWork) CheckContinuation(ctx context.Context) error {
	if err := w.beginIO(); err != nil {
		return err
	}
	defer w.endIO()
	if !w.entered || w.reported {
		return ErrOwner
	}
	return w.database.CheckRunning(ctx, w.entryGuard)
}

// Finish copies application-owned bytes into the original admitted SDK output
// before the provider sees them. Application buffers are never cleared. Only a
// definite original result commit permits the response callback below.
func (w *DurableExecutionWork) Finish(ctx context.Context, code uint32, payload []byte) error {
	if err := w.beginIO(); err != nil {
		return err
	}
	defer w.endIO()
	if !w.entered || w.reported || w.writeFailed || w.outputBytes != 0 {
		return ErrOwner
	}
	w.reported = true
	if len(payload) > len(w.output) {
		return ErrResponseLimit
	}
	w.outputBytes, w.outputCode = uint32(copy(w.output, payload)), code
	err := w.database.Finish(ctx, code, w.output[:w.outputBytes], w.resultGuard)
	w.resultCommitted = err == nil
	if err == nil {
		facts, factErr := w.database.FinishedResult()
		if factErr != nil {
			w.resultCommitted = false
			return factErr
		}
		w.final = durableObservation(facts)
	}
	return durableExecutionError(err)
}

// Actual completion belongs to the already dispatched business work. Closing
// its Session or output interest does not erase the outcome. Publication still
// uses current access separately, and this guard creates no continuation right.
func (w *DurableExecutionWork) resultGuard() error {
	if err := w.reservation.Check(); err != nil {
		return err
	}
	return w.authority.CheckRetained()
}

// PublishResult lends only the original immutable SDK result to the bounded
// response owner on this same task. It performs no application encoding.
func (w *DurableExecutionWork) PublishResult(publish func(uint32, []byte) error) error {
	if publish == nil {
		return ErrConfiguration
	}
	if err := w.beginIO(); err != nil {
		return err
	}
	defer w.endIO()
	if !w.resultCommitted || w.published || w.policy.Shape == 1 {
		return ErrOwner
	}
	if err := w.history.checkAccess(w.target, w.access); err != nil {
		return err
	}
	w.published = true
	return publish(w.outputCode, w.output[:w.outputBytes:w.outputBytes])
}

func (w *DurableExecutionWork) cancel() {
	if w == nil || w.durableExecutionWork == nil {
		return
	}
	w.mu.Lock()
	if !w.exited {
		w.cancelled = true
		if w.contextCancel != nil {
			w.contextCancel()
		}
	}
	w.mu.Unlock()
}

func (w *DurableExecutionWork) cancelTarget(target ExecutionTarget) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.exited && w.target == target {
		w.cancelled = true
		if w.contextCancel != nil {
			w.contextCancel()
		}
	}
}

// Exit waits for proof of actual callback return, then settles the same original
// durable responsibility. An unavailable store leaves this owner in the finite
// service table; the original coordinator may retry cleanup through Collect.
func (w *DurableExecutionWork) Exit(ctx context.Context) error {
	if w == nil || w.durableExecutionWork == nil {
		return nil
	}
	w.mu.Lock()
	if w.exited {
		w.mu.Unlock()
		return nil
	}
	w.mu.Unlock()
	if err := w.beginIO(); err != nil {
		return err
	}
	defer w.endIO()
	if w.taskIssued {
		select {
		case <-w.taskDone:
		default:
			return ErrCapacity
		}
	}
	if w.database != nil {
		if err := w.database.Exit(ctx); err != nil {
			return err
		}
	}
	w.releaseLocal()
	return nil
}

func (w *DurableExecutionWork) releaseLocal() {
	// The I/O claim excludes task/entry/result operations. Close may cancel
	// concurrently, so detach the context and mark exit under its short gate.
	w.mu.Lock()
	w.exited = true
	cancel := w.contextCancel
	w.contextCancel = nil
	w.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	routes := w.routes
	routes.mu.Lock()
	routes.captures--
	routes.cleanupLocked()
	routes.mu.Unlock()
	input := w.input.owner
	w.input.Release()
	input.Close()
	w.mu.Lock()
	w.final.WorkActive = false
	if !w.resultCommitted {
		w.final.State, w.final.Reason = ExecutionFailed, "dispatch_unavailable"
		if w.final.Dispatched {
			w.final.State, w.final.Reason = ExecutionUnknown, "work_outcome_unknown"
		}
	}
	w.mu.Unlock()
	w.task.Release()
	w.storeReservation.Release()
	if w.admission == nil {
		w.authority.Release()
	}
	s := w.history
	s.mu.Lock()
	s.works[w.index] = nil
	s.active--
	s.cleanupLocked()
	s.mu.Unlock()
	w.history = nil
	w.routes = nil
	w.entry = nil
	w.input = InputBorrow{}
	w.header = protocolv4.ApplicationHeader{}
	w.policy = protocolv4.ServiceContractPolicy{}
	w.access = nil
	w.target = ExecutionTarget{}
	w.deadline = nil
	w.database = nil
	w.authority = resourcev4.Reference{}
	w.task = resourcev4.Reference{}
	w.storeReservation = resourcev4.Reference{}
	// Result metadata stays owned until the last original response join exits.
}

func (w *DurableExecutionWork) CleanupComplete() bool {
	if w == nil || w.durableExecutionWork == nil {
		return true
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.exited && !w.io
}

// Collect performs bounded continuation/actual-tail checks outside all service
// gates. It creates no task, timer, per-operation waiter or retry goroutine.
func (s *DurableExecutions) Collect(ctx context.Context) error {
	if s == nil || s.durableExecutions == nil || ctx == nil {
		return ErrConfiguration
	}
	s.mu.Lock()
	cleaned := s.cleaned
	s.mu.Unlock()
	if cleaned {
		return nil
	}
	if err := s.beginCall(true); err != nil {
		return err
	}
	defer s.endCall()
	s.mu.Lock()
	turns := min(16, len(s.works))
	s.mu.Unlock()
	var first error
	for range turns {
		s.mu.Lock()
		if s.cleaned || len(s.works) == 0 {
			s.mu.Unlock()
			return first
		}
		i := s.cursor
		s.cursor = (s.cursor + 1) % len(s.works)
		w := s.works[i]
		s.mu.Unlock()
		if w == nil {
			continue
		}
		w.mu.Lock()
		eligible := !w.exited && (w.taskIssued || !w.admitted || w.cancelled)
		w.mu.Unlock()
		if !eligible {
			continue
		}
		if err := w.beginIO(); err != nil {
			continue
		}
		exited := !w.taskIssued
		if w.taskIssued {
			select {
			case <-w.taskDone:
				exited = true
			default:
			}
		}
		var err error
		if exited {
			if w.database != nil {
				err = w.database.Exit(ctx)
			}
			if err == nil {
				w.releaseLocal()
			}
		} else if w.entered && !w.reported {
			err = w.database.CheckRunning(ctx, w.entryGuard)
			if err != nil && !errors.Is(err, ledgerv4.ErrCapacity) && !errors.Is(err, timev4.ErrUnavailable) && !errors.Is(err, timev4.ErrPending) {
				w.cancel()
			}
		}
		w.endIO()
		if err != nil && !errors.Is(err, ledgerv4.ErrCapacity) && first == nil {
			first = err
		}
	}
	s.mu.Lock()
	closed := s.closed || s.reservation.Check() != nil
	s.mu.Unlock()
	if !closed {
		if err := s.config.Store.Collect(ctx); first == nil {
			first = err
		}
	}
	return first
}

func (*DurableExecutionWork) String() string               { return "Flowersec.DurableExecutionWork" }
func (*DurableExecutionWork) GoString() string             { return "Flowersec.DurableExecutionWork" }
func (*DurableExecutionWork) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

// Write holds only the original finite output gate. The actual continuation
// check happens before the copy and may perform provider I/O outside SDK locks.
func (w *DurableExecutionWork) Write(ctx context.Context, payload []byte) (int, error) {
	if err := w.beginIO(); err != nil {
		return 0, err
	}
	defer w.endIO()
	if !w.entered || w.reported || w.writeFailed {
		return 0, ErrOwner
	}
	if err := w.database.CheckRunning(ctx, w.entryGuard); err != nil {
		return 0, durableExecutionError(err)
	}
	if uint64(len(payload)) > uint64(len(w.output))-uint64(w.outputBytes) {
		w.writeFailed = true
		return 0, ErrResponseLimit
	}
	n := copy(w.output[w.outputBytes:], payload)
	w.outputBytes += uint32(n)
	return n, nil
}

func (w *DurableExecutionWork) FinishWritten(ctx context.Context, code uint32) error {
	if err := w.beginIO(); err != nil {
		return err
	}
	defer w.endIO()
	if !w.entered || w.reported || w.writeFailed {
		return ErrOwner
	}
	w.reported, w.outputCode = true, code
	err := w.database.Finish(ctx, code, w.output[:w.outputBytes], w.resultGuard)
	if err == nil {
		facts, factErr := w.database.FinishedResult()
		err = factErr
		if err == nil {
			w.final = durableObservation(facts)
			w.resultCommitted = true
		}
	}
	return durableExecutionError(err)
}

func (w *DurableExecutionWork) releaseResultLocked() *DurableExecutionAdmission {
	if !w.exited || w.io || w.resultReaders != 0 {
		return nil
	}
	clear(w.output)
	w.output = nil
	w.reservation.Release()
	w.reservation = resourcev4.Reference{}
	admission := w.admission
	w.admission = nil
	return admission
}
