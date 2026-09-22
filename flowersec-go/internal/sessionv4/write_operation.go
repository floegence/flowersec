package sessionv4

import (
	"context"
	"errors"
	"math"
	"sync"
	"sync/atomic"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

var ErrWriteOperationInput = errors.New("sessionv4: write operation input exceeds capacity")
var ErrWriteOperationFailed = errors.New("sessionv4: write operation failed")

// WriteOptions fixes a finite lifetime at PrepareWrite. HardDeadline is the
// original Stream's earlier bound, not a deadline borrowed from a Wait call.
// The public facade supplies its documented preset when no timeout is given.
type WriteOptions struct {
	TimeoutMS    uint64
	HardDeadline *timev4.Deadline
}

// writeRequest is shared by synchronous Write and stable operations. Accepted
// bytes belong to this input alone and are advanced only at the queue copy gate.
type writeRequest struct {
	typed               *typedMessageSend
	messages            *StreamMessages
	input               []byte
	requested, accepted uint64
	operation           *WriteOperation
	deadline            *timev4.Deadline
	transfer            *copyState
	owner               *StreamOwnership
}

// WriteOperation extends the observation lifetime of the original request.
// Terminal handles contain only copied metadata, a fixed local error and a
// closed signal. They do not retain the queue, Stream, Session or clock graph.
// The caller owns that compact result after its original slab slot is returned.
type WriteOperation struct {
	mu       sync.Mutex
	queue    atomic.Pointer[SendQueue]
	slot     int
	progress protocolv4.V4WriteProgress
	failure  error
	done     chan struct{}
}

// MaxWriteOperationBytes is the admitted per-request staging cap. Ordinary
// Write/WriteAll keep their existing segmented behavior for larger inputs.
func (q *SendQueue) MaxWriteOperationBytes() uint64 { return uint64(q.maxOperationBytes) }

// PrepareWrite takes a slot and its already reserved immutable backing before
// copying input. It accepts no bytes. The original running send coordinator
// owns expiration, including for objects whose Start and Wait are never called.
func (q *SendQueue) PrepareWrite(input []byte, options WriteOptions) (*WriteOperation, error) {
	return q.prepareWriteOwned(input, options, nil)
}

func (q *SendQueue) prepareWriteOwned(input []byte, options WriteOptions, owner *StreamOwnership) (*WriteOperation, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(input) > q.maxOperationBytes {
		return nil, ErrWriteOperationInput
	}
	if options.TimeoutMS == 0 || q.service == nil || !q.service.running.Load() {
		return nil, cryptov4.ErrConfiguration
	}
	if err := q.requestErrorLocked(owner); err != nil {
		return nil, err
	}
	clock := q.flow.writer.engine.Clock()
	if !options.HardDeadline.BelongsTo(clock) {
		return nil, timev4.ErrOwner
	}
	index := q.reserveWaitLocked()
	if index < 0 {
		return nil, cryptov4.ErrCapacity
	}
	// All time objects and the result metadata fit this original charged slot.
	start, err := clock.Sample()
	var deadline *timev4.Deadline
	if err == nil {
		deadline, err = options.HardDeadline.ForkAgeAt(start, options.TimeoutMS)
	}
	if err != nil {
		q.removeWaitLocked(index)
		return nil, err
	}
	storage := q.operationStorage[index*q.maxOperationBytes : index*q.maxOperationBytes+len(input)]
	copy(storage, input)
	op := &WriteOperation{slot: index, done: make(chan struct{}), progress: protocolv4.V4WriteProgress{
		RequestedBytes: uint64(len(input)), Phase: protocolv4.V4WritePhasePrepared,
		TerminalReason: protocolv4.V4WriteTerminalReasonNone,
		CleanupStatus:  protocolv4.V4CleanupStatus{Status: protocolv4.V4CleanupStatePending, CoreCleanup: protocolv4.V4CoreCleanupPending},
	}}
	op.queue.Store(q)
	q.slots[index].request = &writeRequest{input: storage, requested: uint64(len(input)), operation: op, deadline: deadline, owner: owner}
	q.notifyOperationsLocked()
	return op, nil
}

func (q *SendQueue) notifyOperationsLocked() {
	if q.service != nil {
		select {
		case q.service.operationWake <- struct{}{}:
		default:
		}
	}
}

// requestLocked rejects stale method entries after a slot was returned and
// reused. A caller may have loaded the old queue before terminal detachment.
func (op *WriteOperation) requestLocked(q *SendQueue) *writeRequest {
	if op.queue.Load() != q || op.slot >= len(q.slots) {
		return nil
	}
	r := q.slots[op.slot].request
	if r == nil || r.operation != op {
		return nil
	}
	return r
}

// Start is a single local FIFO submission. Repetition only reads the original
// result; it cannot requeue a canceled, failed or completed input.
func (op *WriteOperation) Start() error {
	if q := op.queue.Load(); q != nil {
		q.mu.Lock()
		if r := op.requestLocked(q); r != nil {
			if err := r.deadline.Check(); err != nil {
				if !cursorTimePaused(err) {
					q.finishOperationLocked(op.slot, writeTimeReason(err))
				}
				q.mu.Unlock()
				return err
			}
			if err := q.requestErrorLocked(r.owner); err != nil {
				if !cursorTimePaused(err) {
					q.finishOperationLocked(op.slot, protocolv4.V4WriteTerminalReasonStreamTerminated)
				}
				q.mu.Unlock()
				return err
			}
			if !q.slots[op.slot].linked {
				q.linkWaitLocked(op.slot)
				op.mu.Lock()
				op.progress.Phase = protocolv4.V4WritePhaseRunning
				op.mu.Unlock()
				q.notifyOperationsLocked()
			}
		}
		q.mu.Unlock()
	}
	_, err := op.snapshot()
	return err
}

// Cancel ends only this request's unaccepted suffix at the original copy gate.
// Every previously accepted byte remains in the queue for its original sender.
func (op *WriteOperation) Cancel() {
	if q := op.queue.Load(); q != nil {
		q.mu.Lock()
		if op.requestLocked(q) != nil {
			q.finishOperationLocked(op.slot, protocolv4.V4WriteTerminalReasonCanceled)
			q.cleanupLocked()
		}
		q.mu.Unlock()
	}
}

func (op *WriteOperation) snapshot() (protocolv4.V4WriteProgress, error) {
	op.mu.Lock()
	defer op.mu.Unlock()
	return op.progress, op.failure
}

func (op *WriteOperation) Progress() protocolv4.V4WriteProgress { p, _ := op.snapshot(); return p }
func (op *WriteOperation) CleanupStatus() protocolv4.V4CleanupStatus {
	return op.Progress().CleanupStatus
}

// Wait cancellation detaches just this bounded observer. The request keeps its
// original operation deadline and does not inherit the observer's context.
func (op *WriteOperation) Wait(ctx context.Context) (protocolv4.V4WriteProgress, error) {
	if ctx == nil {
		return op.Progress(), cryptov4.ErrConfiguration
	}
	q := op.queue.Load()
	if q == nil {
		return op.snapshot()
	}
	q.mu.Lock()
	if op.requestLocked(q) == nil {
		q.mu.Unlock()
		return op.snapshot()
	}
	if err := ctx.Err(); err != nil {
		q.mu.Unlock()
		return op.Progress(), err
	}
	if q.usedMethodsLocked() >= len(q.slots) {
		q.mu.Unlock()
		return op.Progress(), cryptov4.ErrCapacity
	}
	if err := q.reservation.Check(); err != nil {
		q.mu.Unlock()
		return op.Progress(), err
	}
	q.observers++
	op.mu.Lock()
	op.progress.CleanupStatus.PendingCallbacks++
	op.mu.Unlock()
	q.mu.Unlock()
	select {
	case <-op.done:
	case <-ctx.Done():
	}
	q.mu.Lock()
	q.observers--
	q.writeOwner.notify()
	op.mu.Lock()
	op.progress.CleanupStatus.PendingCallbacks--
	op.cleanupLocked()
	p, err := op.progress, op.failure
	op.mu.Unlock()
	q.cleanupLocked()
	q.mu.Unlock()
	if p.Phase != protocolv4.V4WritePhaseTerminal {
		err = ctx.Err()
	}
	return p, err
}

func (op *WriteOperation) cleanupLocked() {
	if op.progress.Phase == protocolv4.V4WritePhaseTerminal {
		op.progress.CleanupStatus.CoreCleanup = protocolv4.V4CoreCleanupComplete
		if op.progress.CleanupStatus.PendingCallbacks == 0 {
			op.progress.CleanupStatus.Status = protocolv4.V4CleanupStateComplete
		}
	}
}

func writeTimeReason(err error) protocolv4.V4WriteTerminalReason {
	if errors.Is(err, timev4.ErrExpired) {
		return protocolv4.V4WriteTerminalReasonDeadlineExceeded
	}
	return protocolv4.V4WriteTerminalReasonFailed
}

func (q *SendQueue) finishOperationLocked(index int, reason protocolv4.V4WriteTerminalReason) {
	r := q.slots[index].request
	op := r.operation
	clear(r.input)
	r.input, r.deadline, r.operation = nil, nil, nil
	op.mu.Lock()
	op.progress.AcceptedBytes = r.accepted
	op.progress.Phase, op.progress.TerminalReason = protocolv4.V4WritePhaseTerminal, reason
	switch reason {
	case protocolv4.V4WriteTerminalReasonComplete:
		op.failure = nil
	case protocolv4.V4WriteTerminalReasonCanceled:
		op.failure = context.Canceled
	case protocolv4.V4WriteTerminalReasonDeadlineExceeded:
		op.failure = context.DeadlineExceeded
	case protocolv4.V4WriteTerminalReasonQueueFull:
		op.failure = cryptov4.ErrCapacity
	case protocolv4.V4WriteTerminalReasonStreamTerminated:
		op.failure = ErrFlowClosed
	default:
		op.failure = ErrWriteOperationFailed
	}
	op.queue.Store(nil)
	op.cleanupLocked()
	close(op.done)
	op.mu.Unlock()
	q.removeWaitLocked(index)
}

func (q *SendQueue) stopOperationsLocked() {
	for i := range q.slots {
		if r := q.slots[i].request; r != nil && r.operation != nil {
			q.finishOperationLocked(i, protocolv4.V4WriteTerminalReasonStreamTerminated)
		}
	}
}

func (q *SendQueue) acceptanceErrorLocked() error {
	if q.closed {
		return q.failure
	}
	if q.sealed {
		return ErrFlowClosed
	}
	if err := q.reservation.Check(); err != nil {
		return err
	}
	if err := q.flow.writer.engine.CheckApplicationAuthorization(); err != nil {
		return err
	}
	q.flow.mu.Lock()
	defer q.flow.mu.Unlock()
	if q.flow.stopping {
		return ErrFlowClosed
	}
	return q.flow.reservation.Check()
}

func (q *SendQueue) requestErrorLocked(owner *StreamOwnership) error {
	if err := q.writeOwnershipLocked(owner); err != nil {
		return err
	}
	return q.acceptanceErrorLocked()
}

// acceptLocked performs one bounded synchronous copy. Queue responsibility and
// this exact request's acceptance count advance together; no stream offset
// subtraction or asynchronous completion can credit another request's bytes.
func (q *SendQueue) acceptLocked(r *writeRequest) (int, error) {
	if err := q.writeOwnershipLocked(r.owner); err != nil {
		return 0, err
	}
	n := min(int(r.requested-r.accepted), len(q.storage)-q.size, sendAcceptancePiece)
	if uint64(n) > math.MaxUint64-q.accepted {
		return 0, ErrStreamData
	}
	if r.owner != nil && uint64(n) > math.MaxUint64-r.owner.accepted.Load() {
		return 0, ErrStreamData
	}
	if r.transfer != nil {
		if err := r.transfer.checkAcceptance(n); err != nil {
			return 0, err
		}
	}
	accept := func() error {
		input := r.input[int(r.accepted) : int(r.accepted)+n]
		tail := (q.head + q.size) % len(q.storage)
		first := copy(q.storage[tail:], input)
		copy(q.storage[:n-first], input[first:])
		q.size += n
		q.accepted += uint64(n)
		r.accepted += uint64(n)
		if r.owner != nil {
			r.owner.accepted.Add(uint64(n))
		}
		if r.transfer != nil {
			r.transfer.accept(n)
		}
		if op := r.operation; op != nil {
			op.mu.Lock()
			op.progress.AcceptedBytes = r.accepted
			op.mu.Unlock()
		}
		q.completion.accepted(q.accepted)
		q.Notify()
		return nil
	}
	if r.messages != nil {
		if err := r.messages.acceptOutput(accept); err != nil {
			return 0, err
		}
	} else if r.typed != nil {
		if err := r.typed.acceptBytes(n, accept); err != nil {
			return 0, err
		}
	} else {
		_ = accept()
	}
	return n, nil
}

// serviceOperationsLocked is run by the original send coordinator, never a
// provider worker. One pass copies at most one piece and scans a finite slab.
// It returns the next original deadline wake and whether a live owner remains.
func (q *SendQueue) serviceOperationsLocked() (uint64, bool) {
	next, active := uint64(math.MaxUint64), false
	for i := range q.slots {
		r := q.slots[i].request
		if r == nil || r.operation == nil {
			continue
		}
		remaining, err := r.deadline.RemainingMS()
		if err != nil && !cursorTimePaused(err) {
			q.finishOperationLocked(i, writeTimeReason(err))
			continue
		}
		if err != nil {
			remaining = 10
		}
		if gateErr := q.requestErrorLocked(r.owner); gateErr != nil {
			if !cursorTimePaused(gateErr) {
				q.finishOperationLocked(i, protocolv4.V4WriteTerminalReasonStreamTerminated)
				continue
			}
			remaining = min(remaining, 10)
		}
		next, active = min(next, remaining), true
	}
	if q.first >= 0 {
		index := q.first
		r := q.slots[index].request
		if r != nil && r.operation != nil {
			// Authority can change after the slab scan. Every final copy gate
			// refusal must settle or schedule the same owner, never silently
			// park it until the older timer expires.
			if err := q.requestErrorLocked(r.owner); err != nil {
				if cursorTimePaused(err) {
					return min(next, 10), true
				}
				q.finishOperationLocked(index, protocolv4.V4WriteTerminalReasonStreamTerminated)
				return next, active
			}
			if err := r.deadline.Check(); err != nil {
				if cursorTimePaused(err) {
					return min(next, 10), true
				}
				q.finishOperationLocked(index, writeTimeReason(err))
				return next, active
			}
			if q.size < len(q.storage) || r.requested == 0 {
				_, err := q.acceptLocked(r)
				if err != nil {
					q.finishOperationLocked(index, protocolv4.V4WriteTerminalReasonFailed)
				} else if r.accepted == r.requested {
					q.finishOperationLocked(index, protocolv4.V4WriteTerminalReasonComplete)
				}
				if q.first >= 0 && q.size < len(q.storage) {
					q.notifyOperationsLocked()
				}
			}
		}
	}
	return next, active
}
