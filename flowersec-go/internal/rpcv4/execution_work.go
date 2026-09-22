package rpcv4

import (
	"context"
	"crypto/sha256"
	"math"
	"strings"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

// ExecutionWork is the unique original dispatch responsibility, not a public
// operation or a query result. Only the first successful registration receives
// it. The Session adapter transfers its task to the original executor and calls
// Exit only after that real task and its owned external work have exited.
// A response, deadline, cancellation or Session close never calls Exit early.
type ExecutionWork struct {
	mu                                    sync.Mutex
	history                               *VolatileExecutions
	admission                             *ExecutionAdmission
	index                                 int
	generation                            uint64
	input                                 InputBorrow
	routes                                *ContractRoutes
	entry                                 *contractRouteEntry
	access                                ExecutionAccess
	target                                ExecutionTarget
	deadline, run                         *timev4.Deadline
	runMS                                 uint64
	reservation, task, authority          resourcev4.Reference
	cancelled                             chan struct{}
	cancelContext                         context.CancelFunc
	taskDone                              <-chan struct{}
	final                                 ExecutionObservation
	taskIssued, entered, reported, exited bool
}

func (*ExecutionWork) String() string                  { return "Flowersec.ExecutionWork" }
func (*ExecutionWork) GoString() string                { return "Flowersec.ExecutionWork" }
func (*ExecutionWork) MarshalJSON() ([]byte, error)    { return []byte("{}"), nil }
func (w *ExecutionWork) Cancellation() <-chan struct{} { return w.cancelled }

// Context attaches cancellation to the original admitted invocation without
// creating a watcher task. Store cancellation, owner close and trusted-clock
// collection cancel this same context while noncooperative work stays charged.
func (w *ExecutionWork) Context(parent context.Context) (context.Context, error) {
	if w == nil || parent == nil {
		return nil, ErrOwner
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.exited || w.cancelContext != nil {
		return nil, ErrOwner
	}
	s := w.history
	s.mu.Lock()
	defer s.mu.Unlock()
	record, err := w.recordLocked()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(parent)
	w.cancelContext = cancel
	if record.signaled || s.closed {
		cancel()
	}
	return ctx, nil
}

func (w *ExecutionWork) recordLocked() (*executionRecord, error) {
	if w.exited || w.history == nil || w.index < 0 || w.index >= len(w.history.records) {
		return nil, ErrOwner
	}
	r := &w.history.records[w.index]
	if !r.used || r.generation != w.generation || r.work != w {
		return nil, ErrOwner
	}
	return r, nil
}

// TakeTask transfers the preadmitted task to an executor adapter. Callers that
// use SubmitTask may transfer it together with the invocation reservation in a
// single callback; this lower-level form is retained for adapters that need to
// perform their own finite two-reference handoff.
func (w *ExecutionWork) TakeTask() (resourcev4.Reference, error) {
	if w == nil {
		return resourcev4.Reference{}, ErrOwner
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.exited || w.taskIssued {
		return resourcev4.Reference{}, ErrOwner
	}
	s := w.history
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return resourcev4.Reference{}, ErrClosed
	}
	ref, err := w.task.Take(s.taskCharge)
	if err == nil {
		w.task = resourcev4.Reference{}
		w.taskIssued = true
	}
	return ref, err
}

// SubmitTask hands the preadmitted responsibility to the original executor.
// The finite SDK callback must either return its genuine task-exit channel or
// reject without starting work. Exit cannot refund a submitted live task.
func (w *ExecutionWork) SubmitTask(submit func(resourcev4.Reference, resourcev4.Reference) (<-chan struct{}, error)) error {
	if w == nil || submit == nil {
		return ErrOwner
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.exited || w.taskIssued {
		return ErrOwner
	}
	s := w.history
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if closed {
		return ErrClosed
	}
	done, err := submit(w.task, w.reservation)
	if err != nil {
		return err
	}
	// Executor adapters are trusted SDK components; a missing exit channel is
	// a contract violation. Retain the occupied work rather than refunding it.
	w.taskIssued, w.taskDone = true, done
	w.task = resourcev4.Reference{}
	if done == nil {
		return ErrConfiguration
	}
	return nil
}

// Enter is the one finite SDK input handoff before application decoding or
// handler entry. Current registration/authority, cancel and original deadlines
// share this decision. Returning the borrowed bytes is actual application input
// delivery; a later caller cannot undo that fact or obtain a second dispatch.
func (w *ExecutionWork) Enter() (input InputBorrow, err error) {
	if w == nil {
		return input, ErrOwner
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.exited || w.entered || !w.taskIssued {
		return input, ErrOwner
	}
	err = w.access.WithExecutionAccess(w.target, func(resourcev4.Reference) error {
		routes := w.routes
		routes.mu.Lock()
		defer routes.mu.Unlock()
		if routes.closed || !w.entry.registered {
			return ErrMethod
		}
		s := w.history
		s.mu.Lock()
		defer s.mu.Unlock()
		r, err := w.recordLocked()
		if err != nil {
			return err
		}
		if s.closed || r.cancelRequested || r.state != ExecutionAccepted {
			return ErrClosed
		}
		now, err := w.deadline.Sample()
		if err != nil {
			return err
		}
		run, err := w.deadline.ForkAgeAt(now, w.runMS)
		if err != nil {
			return err
		}
		w.run = run
		w.entered = true
		r.dispatched = true
		r.state = ExecutionExecuting
		input = w.input
		return nil
	})
	return input, err
}

// CheckContinuation precedes another application entry such as the handler
// after its decoder. It never resets the original run start or wire deadline.
func (w *ExecutionWork) CheckContinuation() error {
	if w == nil {
		return ErrOwner
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.exited || !w.entered || w.reported {
		return ErrClosed
	}
	return w.access.WithExecutionAccess(w.target, func(resourcev4.Reference) error {
		s := w.history
		s.mu.Lock()
		defer s.mu.Unlock()
		r, err := w.recordLocked()
		if err != nil {
			return err
		}
		if s.closed || r.cancelRequested || r.state != ExecutionExecuting {
			return ErrClosed
		}
		if err = w.deadline.Check(); err != nil {
			return err
		}
		return w.run.Check()
	})
}

// Write copies encoded output into the execution's original result backing.
// It does not depend on a live Session or ReplySlot. Current execution access
// and the original continuation deadline still precede each application write.
func (w *ExecutionWork) Write(payload []byte) (n int, err error) {
	if w == nil {
		return 0, ErrOwner
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.exited || !w.entered || w.reported {
		return 0, ErrClosed
	}
	err = w.access.WithExecutionAccess(w.target, func(resourcev4.Reference) error {
		s := w.history
		s.mu.Lock()
		defer s.mu.Unlock()
		r, err := w.recordLocked()
		if err != nil {
			return err
		}
		if s.closed || r.cancelRequested || r.state != ExecutionExecuting {
			return ErrClosed
		}
		if err := w.deadline.Check(); err != nil {
			return err
		}
		if err := w.run.Check(); err != nil {
			return err
		}
		b := r.result
		if b == nil || b.formed || b.writeFailed {
			return ErrResponseLimit
		}
		if uint64(len(payload)) > uint64(len(b.payload))-uint64(b.written) {
			b.writeFailed = true
			return ErrResponseLimit
		}
		n = copy(b.payload[b.written:], payload)
		b.written += uint32(n)
		return nil
	})
	return n, err
}

// FinishWritten records the output after the actual handler has returned. A
// closed response or canceled Session cannot erase those execution facts.
func (w *ExecutionWork) FinishWritten(errorCode uint32) error {
	return w.finish(errorCode, nil, false)
}

// Finish records the actual original handler's result once. It cannot reopen
// a ReplySlot or dispatch a callback. A late return may resolve prior unknown
// execution facts while the original response has already completed elsewhere.
// Result retention starts at this actual formation, independent of history GC.
func (w *ExecutionWork) Finish(errorCode uint32, payload []byte) error {
	return w.finish(errorCode, payload, true)
}
func (w *ExecutionWork) finish(errorCode uint32, payload []byte, replace bool) error {
	if w == nil {
		return ErrOwner
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.exited || !w.entered || w.reported {
		return ErrOwner
	}
	if uint64(len(payload)) > 1048576 {
		return ErrResponseLimit
	}
	s := w.history
	s.mu.Lock()
	defer s.mu.Unlock()
	r, err := w.recordLocked()
	if err != nil {
		return err
	}
	if s.closed {
		return ErrClosed
	}
	length := uint32(len(payload))
	if r.result != nil && !replace {
		length = r.result.written
	}
	if r.result == nil {
		if r.streamMetadataOnly {
			if err := w.entry.contract.CheckResponsePayload(errorCode, 0); err != nil {
				return err
			}
			r.resultCode = errorCode
		}
		if length != 0 || errorCode != 0 && !r.streamMetadataOnly {
			return ErrResponseLimit
		}
	} else {
		if err := w.entry.contract.CheckResponsePayload(errorCode, length); err != nil {
			return err
		}
		b := r.result
		if length > uint32(len(b.payload)) || b.formed || b.writeFailed || replace && b.written != 0 {
			return ErrResponseLimit
		}
		now, err := s.clock.Sample()
		if err != nil {
			return err
		}
		if b.retentionMS > math.MaxUint64-now.UpperMS {
			return ErrConfiguration
		}
		if replace {
			copy(b.payload, payload)
		}
		b.length, b.written, b.code = length, length, errorCode
		b.digest = sha256.Sum256(b.payload[:length])
		if b.retentionMS != 0 {
			b.expires = now.UpperMS + b.retentionMS
		}
		b.formed = true
		r.resultFormed = true
		r.resultBytes, r.resultCode, r.resultDigest, r.resultExpires = b.length, b.code, b.digest, b.expires
	}
	w.reported = true
	r.reason = ""
	r.state = ExecutionCompleted
	if errorCode != 0 {
		r.state = ExecutionFailed
	}
	return nil
}

// Exit joins actual work. Unreported entered work becomes unknown, never an
// assertion that no external effect happened. It relinquishes only physical
// work/input/authorization; history and any promised result remain in the store.
// The compact work handle remains charged until its internal owner Release.
func (w *ExecutionWork) Exit() error {
	if w == nil {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.exited {
		return nil
	}
	if w.taskIssued {
		select {
		case <-w.taskDone:
		default:
			return ErrCapacity
		}
	}
	s := w.history
	s.mu.Lock()
	r, err := w.recordLocked()
	if err != nil {
		s.mu.Unlock()
		return err
	}
	if !w.reported && (r.state == ExecutionAccepted || r.state == ExecutionExecuting) {
		if r.dispatched {
			r.state = ExecutionUnknown
			r.reason = "work_outcome_unknown"
		} else {
			r.state = ExecutionFailed
			r.reason = "dispatch_unavailable"
		}
	}
	s.signalLocked(r)
	r.work = nil
	s.active--
	if r.result != nil && (!r.result.formed || s.closed || r.result.retentionMS == 0) {
		r.result.expired = true
		s.cleanupResultLocked(r)
	}
	w.final = s.snapshotLocked(r)
	if s.closed && r.result == nil && r.joins == 0 {
		s.removeLocked(w.index)
	}
	s.cleanupLocked()
	s.mu.Unlock()
	// No store gate is held while other original owners release their locks.
	w.routes.mu.Lock()
	w.routes.captures--
	w.routes.cleanupLocked()
	w.routes.mu.Unlock()
	owner := w.input.owner
	w.input.Release()
	owner.Close()
	w.task.Release()
	if w.admission != nil {
		w.admission.releaseTail()
		w.admission = nil
	} else {
		w.authority.Release()
	}
	w.history = nil
	w.routes = nil
	w.entry = nil
	w.access = nil
	w.target = ExecutionTarget{}
	w.input = InputBorrow{}
	w.task = resourcev4.Reference{}
	w.authority = resourcev4.Reference{}
	w.deadline = nil
	w.run = nil
	w.taskDone = nil
	w.cancelContext = nil
	w.exited = true
	return nil
}
func (w *ExecutionWork) Status() ExecutionObservation {
	if w == nil {
		return ExecutionObservation{Reason: "owner_unavailable"}
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.exited {
		return w.final
	}
	s := w.history
	s.mu.Lock()
	defer s.mu.Unlock()
	r, err := w.recordLocked()
	if err != nil {
		return ExecutionObservation{Reason: "owner_unavailable"}
	}
	return s.snapshotLocked(r)
}
func (w *ExecutionWork) Release() error {
	if w == nil {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.exited {
		return ErrCapacity
	}
	w.reservation.Release()
	w.reservation = resourcev4.Reference{}
	return nil
}

// ExecutionResultRead is a charged immutable encoded-result capture. It owns
// no dispatch right. Every bounded copy repeats current target authorization;
// expiration closes reads but keeps real backing until all captures release.
type ExecutionResultRead struct {
	durable                  *DurableExecutions
	clock                    *timev4.Clock
	mu                       sync.Mutex
	history                  *VolatileExecutions
	index                    int
	generation               uint64
	result                   *executionResult
	target                   ExecutionTarget
	access                   ExecutionAccess
	reservation, authority   resourcev4.Reference
	closed, publicationOwned bool
}

func ExecutionResultReadCharge(runtimeBytes uint64) (resourcev4.Vector, error) {
	if runtimeBytes == 0 {
		return resourcev4.Vector{}, ErrConfiguration
	}
	return (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(ExecutionResultRead{})) + uint64(unsafe.Sizeof(Publication{})) + uint64(unsafe.Sizeof(timev4.Deadline{})) + 128, resourcev4.Items: 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: runtimeBytes})
}
func (s *VolatileExecutions) CaptureResult(target ExecutionTarget, access ExecutionAccess, metadata resourcev4.Reference, runtimeBytes uint64) (read *ExecutionResultRead, err error) {
	if s == nil || access == nil {
		return nil, ErrConfiguration
	}
	charge, err := ExecutionResultReadCharge(runtimeBytes)
	if err != nil {
		return nil, err
	}
	err = access.WithExecutionAccess(target, func(authority resourcev4.Reference) error {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.closed {
			return ErrClosed
		}
		if err := metadata.CheckSameEnvironment(s.reservation); err != nil {
			return err
		}
		if err := metadata.CheckSameEnvironment(authority); err != nil {
			return err
		}
		k, err := s.keyLocked(target)
		if err != nil {
			return err
		}
		i, _ := s.findLocked(k)
		if i < 0 {
			// A result reference carries no proof of continuous RAM coverage.
			return ErrHistoryUnknown
		}
		r := &s.records[i]
		if r.request != target.RequestDigest || r.contract != target.ContractDigest {
			return ErrExecutionConflict
		}
		b := r.result
		if r.resultDeleted || b != nil && b.formed && (b.expired || b.retentionMS == 0) {
			return ErrResultExpired
		}
		if b == nil || !b.formed {
			return ErrResultUnavailable
		}
		if b.readers == math.MaxUint32 {
			return ErrCapacity
		}
		now, err := s.clock.Sample()
		if err != nil {
			return err
		}
		if !now.ValidBefore(b.expires) {
			return ErrResultExpired
		}
		owned, err := metadata.Take(charge)
		if err != nil {
			return err
		}
		borrow, err := authority.Borrow()
		if err != nil {
			owned.Release()
			return err
		}
		b.readers++
		target.Service = s.service
		target.Caller.Subject = strings.Clone(target.Caller.Subject)
		read = &ExecutionResultRead{history: s, clock: s.clock, index: i, generation: r.generation, result: b, target: target, access: access, reservation: owned, authority: borrow}
		return nil
	})
	return
}

// withAccess takes current authorization before the Network or result lock.
// Closure can race this snapshot, so withResult repeats the live-owner check.
func (r *ExecutionResultRead) withAccess(action func(resourcev4.Reference) error) error {
	if r == nil {
		return ErrOwner
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return ErrClosed
	}
	access, target := r.access, r.target
	r.mu.Unlock()
	return access.WithExecutionAccess(target, action)
}

// withResult protects the actual immutable bytes through a finite SDK copy
// or publication. The caller already holds the current authorization gate.
func (r *ExecutionResultRead) withResult(authority resourcev4.Reference, action func(*executionResult) error) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return ErrClosed
	}
	if r.durable != nil {
		s := r.durable
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.closed {
			return ErrClosed
		}
		if err := r.authority.CheckSameEnvironment(authority); err != nil {
			return err
		}
		now, err := r.clock.Sample()
		if err != nil {
			return err
		}
		if r.result.expires == 0 || !now.ValidBefore(r.result.expires) {
			return ErrResultExpired
		}
		return action(r.result)
	}
	s := r.history
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	if err := r.authority.CheckSameEnvironment(authority); err != nil {
		return err
	}
	if r.result.expired {
		return ErrResultExpired
	}
	now, err := s.clock.Sample()
	if err != nil {
		return err
	}
	if !now.ValidBefore(r.result.expires) {
		return ErrResultExpired
	}
	return action(r.result)
}

func (r *ExecutionResultRead) CopyChunk(dst []byte, offset uint32) (n int, err error) {
	if r == nil || len(dst) > 4096 {
		return 0, ErrConfiguration
	}
	err = r.withAccess(func(authority resourcev4.Reference) error {
		return r.withResult(authority, func(result *executionResult) error {
			if r.publicationOwned {
				return ErrOwner
			}
			if offset > result.length {
				return ErrResponseLimit
			}
			n = copy(dst, result.payload[offset:result.length])
			return nil
		})
	})
	return
}

// Length returns retained result metadata through the same current
// authorization and expiry gate used by CopyChunk.
func (r *ExecutionResultRead) Length() (length uint32, err error) {
	err = r.withAccess(func(authority resourcev4.Reference) error {
		return r.withResult(authority, func(result *executionResult) error {
			length = result.length
			return nil
		})
	})
	return
}

func (r *ExecutionResultRead) Close() { r.close(false) }
func (r *ExecutionResultRead) close(publication bool) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.publicationOwned != publication {
		return
	}
	if r.durable != nil {
		s := r.durable
		clear(r.result.payload)
		s.mu.Lock()
		s.joins--
		s.cleanupLocked()
		s.mu.Unlock()
	} else {
		s := r.history
		s.mu.Lock()
		entry := &s.records[r.index]
		if entry.generation == r.generation && entry.result == r.result {
			r.result.readers--
			s.cleanupResultLocked(entry)
			if s.closed && entry.work == nil && entry.result == nil && entry.joins == 0 {
				s.removeLocked(r.index)
			}
		}
		s.cleanupLocked()
		s.mu.Unlock()
	}
	r.authority.Release()
	r.reservation.Release()
	r.authority = resourcev4.Reference{}
	r.reservation = resourcev4.Reference{}
	r.history = nil
	r.durable = nil
	r.clock = nil
	r.result = nil
	r.access = nil
	r.target = ExecutionTarget{}
	r.closed = true
}
