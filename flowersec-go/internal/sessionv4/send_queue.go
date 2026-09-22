package sessionv4

import (
	"context"
	"errors"
	"io"
	"math"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

type sendWaitSlot struct {
	used       bool
	linked     bool
	helper     bool
	request    *writeRequest
	prev, next int
	wake       chan struct{}
}

const sendAcceptancePiece = 4096

// SendQueue is the application's acceptance owner in front of the original
// SendFlow/record publisher. Its fixed ring holds every accepted byte until
// actual publication or explicit direction failure. A cancelled Write wait
// never removes previously accepted data and never controls the publisher.
// The Session's already admitted scheduler calls Pump; no goroutine or retry
// loop is created here and maintenance retains its independent service share.
type SendQueue struct {
	mu                    sync.Mutex
	flow                  *SendFlow
	completion            *sendCompletion
	service               *SendService
	serviceSignal         atomic.Pointer[sendServiceSignal]
	serviceNotify         sendServiceSignal
	reservation           resourcev4.Reference
	writeOwner            *StreamOwnership
	rawUsed               bool
	rpcBatch              *RPCBatchWriter
	methodTails           int
	methodWaiters         int
	storage               []byte
	operationStorage      []byte
	maxOperationBytes     int
	head, size            int
	chunk                 int
	accepted, published   uint64
	slots                 []sendWaitSlot
	first, last, waiters  int
	observers             int
	sealed, closed        bool
	finComplete, pumping  bool
	failure               error
	wake, writeDone, done chan struct{}
	cleaned               bool
}

// SendQueueCharge includes the application ring, all fixed FIFO/wait slots,
// immutable operation staging for each slot, deadline/result metadata, and
// one original pump task. Stable requests share these slots with ordinary
// writers and observers; terminal compact metadata transfers to the caller. Runtime channels/stacks/allocator overhead and
// the separate SendFlow/record/crypto/provider copy remain profile costs.
func SendQueueCharge(capacity uint64, waiters uint32) (resourcev4.Vector, error) {
	if capacity == 0 || capacity > uint64(math.MaxInt) || waiters == 0 || uint64(waiters) > uint64(math.MaxInt) {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	perSlot := uint64(unsafe.Sizeof(sendWaitSlot{})) + uint64(unsafe.Sizeof(writeRequest{})) + uint64(unsafe.Sizeof(WriteOperation{})) + uint64(unsafe.Sizeof(timev4.Deadline{}))
	if capacity > (math.MaxUint64-uint64(unsafe.Sizeof(SendQueue{})))/uint64(waiters)-perSlot {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	metadata := uint64(unsafe.Sizeof(SendQueue{})) + uint64(waiters)*(perSlot+capacity)
	if capacity > math.MaxUint64-metadata || uint64(waiters) > uint64(math.MaxInt)/capacity {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	return resourcev4.Vector{resourcev4.SDKBytes: capacity + metadata, resourcev4.Items: uint64(waiters) + 1, resourcev4.Tasks: uint64(waiters) + 1, resourcev4.WorkSlots: uint64(waiters) + 1, resourcev4.Timers: uint64(waiters)}, nil
}

func NewSendQueue(flow *SendFlow, capacity uint64, waiters uint32, chunk int, reservation resourcev4.Reference) (*SendQueue, error) {
	charge, err := SendQueueCharge(capacity, waiters)
	if err != nil || flow == nil || chunk <= 0 {
		return nil, cryptov4.ErrConfiguration
	}
	flow.mu.Lock()
	defer flow.mu.Unlock()
	if flow.queue != nil || flow.active || flow.stopping || chunk > len(flow.storage) {
		return nil, cryptov4.ErrConfiguration
	}
	if err := reservation.CheckSameEnvironment(flow.reservation); err != nil {
		return nil, err
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		return nil, err
	}
	q := &SendQueue{flow: flow, completion: flow.completion, reservation: owned, storage: make([]byte, int(capacity)), operationStorage: make([]byte, int(capacity)*int(waiters)), maxOperationBytes: int(capacity), chunk: chunk, accepted: flow.frontier.Offset, published: flow.frontier.Offset, slots: make([]sendWaitSlot, int(waiters)), first: -1, last: -1, wake: make(chan struct{}, 1), writeDone: make(chan struct{}), done: make(chan struct{})}
	for i := range q.slots {
		q.slots[i].wake = make(chan struct{}, 1)
	}
	flow.queue = q
	flow.queueOwner = q
	return q, nil
}

// Notify is a coalesced hint for the sole Session scheduler, never an authority
// or a per-record job. Credit, rekey completion and newly accepted bytes can
// all make the same original queue eligible. Global crypto-slot availability
// is handled by that scheduler, not a private polling loop here.
func (q *SendQueue) Notify() {
	if signal := q.serviceSignal.Load(); signal != nil {
		signal.notify()
	}
	select {
	case q.wake <- struct{}{}:
	default:
	}
}
func (q *SendQueue) Wake() <-chan struct{} { return q.wake }

// Write returns the stable contiguous prefix accepted into the SDK ring. It
// may return a short count; WriteAll advances only that input's known suffix.
// Input is borrowed only until return. FIFO waiters are admitted from a fixed
// slab, and cancellation while waiting returns zero without consuming input.
func (q *SendQueue) Write(ctx context.Context, input []byte) (int, error) {
	return q.write(ctx, input, nil)
}

func (q *SendQueue) write(ctx context.Context, input []byte, transfer *copyState) (int, error) {
	return q.writeOwned(ctx, input, transfer, nil)
}

func (q *SendQueue) writeOwned(ctx context.Context, input []byte, transfer *copyState, owner *StreamOwnership) (int, error) {
	return q.writeMethodOwned(ctx, input, transfer, owner, false)
}

func (q *SendQueue) writeMethodOwned(ctx context.Context, input []byte, transfer *copyState, owner *StreamOwnership, helper bool) (int, error) {
	return q.writeMessageOwned(ctx, input, transfer, owner, helper, nil)
}

func (q *SendQueue) writeMessageOwned(ctx context.Context, input []byte, transfer *copyState, owner *StreamOwnership, helper bool, messages *StreamMessages) (int, error) {
	return q.writeAdapterOwned(ctx, input, transfer, owner, helper, messages, nil)
}
func (q *SendQueue) writeTypedMessageOwned(ctx context.Context, input []byte, owner *StreamOwnership, message *typedMessageSend) (int, error) {
	return q.writeAdapterOwned(ctx, input, nil, owner, true, nil, message)
}
func (q *SendQueue) writeAdapterOwned(ctx context.Context, input []byte, transfer *copyState, owner *StreamOwnership, helper bool, messages *StreamMessages, typed *typedMessageSend) (int, error) {
	if ctx == nil {
		return 0, cryptov4.ErrConfiguration
	}
	q.mu.Lock()
	request := writeRequest{input: input, requested: uint64(len(input)), transfer: transfer, owner: owner, messages: messages, typed: typed}
	slot := -1
	defer func() {
		if slot >= 0 {
			q.removeWaitLocked(slot)
		}
		q.cleanupLocked()
		q.mu.Unlock()
	}()
	for {
		if err := q.writeOwnershipLocked(owner); err != nil {
			return 0, err
		}
		if err := transfer.checkOwners(); err != nil {
			return 0, err
		}
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		if err := q.acceptanceErrorLocked(); err != nil {
			return 0, err
		}
		if len(input) == 0 {
			return 0, nil
		}
		if slot < 0 {
			slot = q.addMethodWaitLocked(helper)
			if slot < 0 {
				return 0, cryptov4.ErrCapacity
			}
			q.slots[slot].request = &request
		}
		if q.first == slot && q.size < len(q.storage) {
			return q.acceptLocked(&request)
		}
		wake, closed := q.slots[slot].wake, q.flow.writer.engine.Done()
		q.mu.Unlock()
		select {
		case <-ctx.Done():
		case <-ownershipWake(owner):
		case <-transfer.sourceWake():
		case <-q.writeDone:
		case <-closed:
		case <-wake:
		}
		q.mu.Lock()
	}
}

// WriteAll advances only the known, not-yet-accepted suffix of this input.
// An error returns the cumulative stable acceptance count. It neither FINs nor
// resets the Stream and never resends a prefix accepted by an earlier Write.
func (q *SendQueue) WriteAll(ctx context.Context, input []byte) (int, error) {
	return q.writeAllOwned(ctx, input, nil)
}

func (q *SendQueue) writeAllOwned(ctx context.Context, input []byte, owner *StreamOwnership) (int, error) {
	if err := q.beginWriteMethod(owner); err != nil {
		return 0, err
	}
	defer q.endWriteMethod()
	accepted := 0
	for {
		n, err := q.writeMethodOwned(ctx, input[accepted:], nil, owner, true)
		accepted += n
		if err != nil || accepted == len(input) {
			return accepted, err
		}
		if n == 0 {
			return accepted, io.ErrNoProgress
		}
	}
}

// Composite helpers retain a finite method claim between their child writes,
// including while waiting on a different source. A full-Stream handoff cannot
// overtake these original writers or refund their actual destination aliases.
func (q *SendQueue) beginWriteMethod(owner *StreamOwnership) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if err := q.writeOwnershipLocked(owner); err != nil {
		return err
	}
	if q.usedMethodsLocked() >= len(q.slots) {
		return cryptov4.ErrCapacity
	}
	q.methodTails++
	return nil
}

// A helper and its currently linked child write share one original method
// position. Between child writes the helper keeps that capacity reserved;
// ordinary writers, prepared operations and observers cannot borrow it.
func (q *SendQueue) usedMethodsLocked() int {
	return q.waiters + q.observers + q.methodTails - q.methodWaiters
}

func (q *SendQueue) endWriteMethod() {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.methodTails--
	q.cleanupLocked()
}

// Prepared operations reserve from this same slab before Start links them.
func (q *SendQueue) reserveWaitLocked() int {
	return q.reserveMethodWaitLocked(false)
}

func (q *SendQueue) reserveMethodWaitLocked(helper bool) int {
	if !helper && q.usedMethodsLocked() >= len(q.slots) || helper && q.methodWaiters >= q.methodTails {
		return -1
	}
	for i := range q.slots {
		s := &q.slots[i]
		if !s.used {
			s.used, s.linked, s.prev, s.next = true, false, -1, -1
			s.helper = helper
			q.waiters++
			if helper {
				q.methodWaiters++
			}
			return i
		}
	}
	return -1
}
func (q *SendQueue) linkWaitLocked(index int) {
	s := &q.slots[index]
	s.linked, s.prev, s.next = true, q.last, -1
	if q.last >= 0 {
		q.slots[q.last].next = index
	} else {
		q.first = index
	}
	q.last = index
}
func (q *SendQueue) addMethodWaitLocked(helper bool) int {
	index := q.reserveMethodWaitLocked(helper)
	if index >= 0 {
		q.linkWaitLocked(index)
	}
	return index
}
func (q *SendQueue) removeWaitLocked(index int) {
	s := &q.slots[index]
	if s.linked {
		if s.prev >= 0 {
			q.slots[s.prev].next = s.next
		} else {
			q.first = s.next
		}
		if s.next >= 0 {
			q.slots[s.next].prev = s.prev
		} else {
			q.last = s.prev
		}
	}
	if s.helper {
		q.methodWaiters--
	}
	s.used, s.linked, s.helper, s.request = false, false, false, nil
	q.waiters--
	q.wakeWriterLocked()
}

func (q *SendQueue) wakeWriterLocked() {
	if q.first >= 0 && q.size < len(q.storage) {
		q.notifyOperationsLocked()
		select {
		case q.slots[q.first].wake <- struct{}{}:
		default:
		}
	}
}

// Seal requests the original ordered FIN after all accepted bytes. This local
// method does not claim that FIN has a ticket or that the peer has drained it;
// the public CloseWrite/Finish facade must observe those separate facts.
func (q *SendQueue) Seal() error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if err := q.writeOwnershipLocked(nil); err != nil {
		return err
	}
	q.sealLocked()
	return nil
}

// CloseWrite seals new acceptance immediately, then waits for the one ordered
// FIN's irrevocable crypto ticket. Cancelling this wait never reopens the gate
// or cancels the original publication task.
func (q *SendQueue) CloseWrite(ctx context.Context) error { return q.waitClose(ctx, false) }

// Finish requests the same FIN and waits for authenticated DRAINED(drained).
// A complete local provider write cannot satisfy this wait. The receive
// direction remains owned by its original reader throughout.
func (q *SendQueue) Finish(ctx context.Context) error { return q.waitClose(ctx, true) }

func (q *SendQueue) waitClose(ctx context.Context, drain bool) error {
	return q.waitCloseOwned(ctx, drain, nil)
}

func (q *SendQueue) waitCloseOwned(ctx context.Context, drain bool, owner *StreamOwnership) error {
	if ctx == nil {
		return cryptov4.ErrConfiguration
	}
	q.mu.Lock()
	checkOwner := q.writeOwnershipLocked
	wake := ownershipWake(owner)
	if drain {
		checkOwner = q.finishOwnershipLocked
		if owner != nil {
			wake = owner.revokeDone
		}
	}
	if err := checkOwner(owner); err != nil {
		q.mu.Unlock()
		return err
	}
	q.sealLocked()
	if settled, err := q.completion.result(drain); settled {
		q.mu.Unlock()
		return err
	}
	if err := ctx.Err(); err != nil {
		q.mu.Unlock()
		return err
	}
	if q.usedMethodsLocked() >= len(q.slots) {
		q.mu.Unlock()
		return cryptov4.ErrCapacity
	}
	q.observers++
	done := q.completion.finDone
	if drain {
		done = q.completion.drainDone
	}
	q.mu.Unlock()
	select {
	case <-done:
	case <-ctx.Done():
	case <-wake:
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	q.observers--
	q.cleanupLocked()
	if settled, err := q.completion.result(drain); settled {
		if err == nil {
			err = checkOwner(owner)
		}
		return err
	}
	if err := checkOwner(owner); err != nil {
		return err
	}
	return ctx.Err()
}

func (q *SendQueue) SendStatus() SendStatus { return q.completion.snapshot() }

func (q *SendQueue) sealLocked() {
	if !q.sealed {
		q.sealed = true
		q.stopOperationsLocked()
		close(q.writeDone)
		q.Notify()
	}
}

// Pump makes at most one bounded record publication using the original
// publisher. Its context belongs to the Session's service task, never a Write
// waiter. No-ticket backpressure leaves the same queue prefix for a later
// eligible turn. Any ticketed failure permanently closes this direction.
func (q *SendQueue) Pump(ctx context.Context) (RecordWriteResult, int, error) {
	return q.pump(ctx, nil)
}

func (q *SendQueue) pump(ctx context.Context, service *SendService) (RecordWriteResult, int, error) {
	if ctx == nil {
		return RecordWriteResult{}, 0, cryptov4.ErrConfiguration
	}
	q.mu.Lock()
	if q.service != service {
		q.mu.Unlock()
		return RecordWriteResult{}, 0, cryptov4.ErrConfiguration
	}
	if q.closed {
		err := q.failure
		q.mu.Unlock()
		return RecordWriteResult{}, 0, err
	}
	if q.finComplete {
		q.mu.Unlock()
		return RecordWriteResult{}, 0, nil
	}
	if q.pumping {
		q.mu.Unlock()
		return RecordWriteResult{}, 0, cryptov4.ErrCapacity
	}
	if err := q.reservation.Check(); err != nil {
		q.mu.Unlock()
		return RecordWriteResult{}, 0, err
	}
	flow := q.flow
	flow.mu.Lock()
	stopped := flow.stopping
	credit := flow.limit - flow.frontier.Offset
	flow.mu.Unlock()
	if stopped {
		q.mu.Unlock()
		return RecordWriteResult{}, 0, ErrFlowClosed
	}
	n := min(q.size, len(q.storage)-q.head, q.chunk, int(min(credit, uint64(math.MaxInt))))
	fin := q.sealed && n == q.size
	if n == 0 && !fin {
		pending := q.size != 0
		q.mu.Unlock()
		if pending {
			return RecordWriteResult{}, 0, ErrCredit
		}
		return RecordWriteResult{}, 0, nil
	}
	q.pumping = true
	input := q.storage[q.head : q.head+n]
	q.mu.Unlock()
	result, err := flow.write(ctx, input, fin, q)
	q.mu.Lock()
	if q.closed {
		err = q.failure
	}
	fatal := err != nil && (result.Submitted || !sendQueueBackpressure(err))
	published := 0
	if result.Complete {
		clear(q.storage[q.head : q.head+n])
		q.head = (q.head + n) % len(q.storage)
		q.size -= n
		q.published += uint64(n)
		published = n
		q.finComplete = fin && err == nil
		q.wakeWriterLocked()
	}
	if fatal {
		q.completion.fail(err)
		q.closeLocked(err)
	}
	q.mu.Unlock()
	if fatal {
		flow.Stop()
	}
	q.mu.Lock()
	q.pumping = false
	if q.rpcBatch != nil {
		q.rpcBatch.notifyLocked()
	}
	q.cleanupLocked()
	q.mu.Unlock()
	return result, published, err
}

func sendQueueBackpressure(err error) bool {
	return errors.Is(err, ErrCredit) || errors.Is(err, cryptov4.ErrCapacity) || errors.Is(err, cryptov4.ErrTransition) || errors.Is(err, cryptov4.ErrNotReady) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || cursorTimePaused(err)
}

func (q *SendQueue) Stop(cause error) {
	q.mu.Lock()
	flow := q.flow
	q.closeLocked(cause)
	service := q.service
	q.mu.Unlock()
	if flow != nil {
		flow.Stop()
	}
	if service != nil {
		service.detachStopped(q)
	}
}

func (q *SendQueue) stopFromFlow(cause error) {
	q.mu.Lock()
	q.closeLocked(cause)
	service := q.service
	q.mu.Unlock()
	if service != nil {
		service.detachStopped(q)
	}
}

func (q *SendQueue) closeLocked(cause error) {
	q.completion.stop(cause)
	if q.finComplete {
		// A later cleanup/Stop cannot turn an already completed FIN and its
		// application prefix into a failed local publication.
		q.cleanupLocked()
		return
	}
	if !q.closed {
		if cause == nil {
			cause = ErrAbandoned
		}
		q.failure = cause
		q.closed = true
		q.sealLocked()
	}
	if q.rpcBatch != nil {
		q.rpcBatch.notifyLocked()
	}
	q.cleanupLocked()
}

func (q *SendQueue) cleanupLocked() {
	if q.cleaned || q.pumping || q.rpcBatch != nil || q.waiters != 0 || q.observers != 0 || q.methodTails != 0 || !q.closed && !q.finComplete {
		return
	}
	flow := q.flow
	if flow != nil {
		flow.mu.Lock()
		// Keep the original attachment until the underlying direction is
		// sealed too. Otherwise a concurrent raw writer or constructor could
		// acquire it between this queue's Close and the original flow Stop.
		if !flow.stopping {
			flow.mu.Unlock()
			return
		}
	}
	clear(q.storage)
	q.storage = nil
	clear(q.operationStorage)
	q.operationStorage = nil
	q.size = 0
	q.cleaned = true
	close(q.done)
	if flow != nil {
		// Publish detachment only after the original queue cleanup is real.
		// Stream CloseResult and admission retirement use this same flow gate.
		q.flow = nil
		flow.queue = nil
		flow.mu.Unlock()
	}
}

// retire returns the original observation/wait slab only after its enclosing
// Stream owner has settled Finish and all actual waiter tails have exited.
// DATA cleanup alone does not refund still-usable close/finish wait capacity.
func (q *SendQueue) retire() error {
	q.mu.Lock()
	defer q.mu.Unlock()
	settled, _ := q.completion.result(true)
	if !q.cleaned || q.waiters != 0 || q.observers != 0 || q.methodTails != 0 || !settled || q.service != nil {
		return cryptov4.ErrCapacity
	}
	q.slots = nil
	q.reservation.Release()
	return nil
}

func (q *SendQueue) WaitCleanup(ctx context.Context) error {
	if ctx == nil {
		return cryptov4.ErrConfiguration
	}
	select {
	case <-q.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Snapshot keeps local accepted and actually published application frontiers
// separate. Neither proves peer drain, delivery or application processing.
func (q *SendQueue) Snapshot() (accepted, published uint64, pending int, sealed, finComplete, cleanupComplete bool, failure error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.accepted, q.published, q.size, q.sealed, q.finComplete, q.cleaned, q.failure
}
