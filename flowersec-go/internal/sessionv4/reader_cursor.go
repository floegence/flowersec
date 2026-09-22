package sessionv4

import (
	"context"
	"errors"
	"math"
	"runtime"
	"sync"
	"time"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

var (
	ErrCursorTarget     = errors.New("sessionv4: invalid reader cursor target")
	ErrCursorFrozen     = errors.New("sessionv4: reader cursor prefix frozen")
	ErrCursorClosed     = errors.New("sessionv4: reader cursor closed")
	ErrAlreadyDelivered = errors.New("sessionv4: reader cursor already delivered")
)

// This is a local scheduling quantum, not a wire limit. The core gate is
// released between pieces, even when the authenticated queue is already full.
const cursorScanPiece = 4096

type cursorTarget struct {
	limit     uint64
	delimiter [32]byte
	prefix    [32]uint8
	length    uint8 // Zero selects exact, including exact(0).
}

func exactCursorTarget(k, capacity uint64) (cursorTarget, error) {
	if k > capacity || k > uint64(math.MaxInt) {
		return cursorTarget{}, ErrCursorTarget
	}
	return cursorTarget{limit: k}, nil
}

func untilCursorTarget(delimiter []byte, maximum, capacity uint64) (cursorTarget, error) {
	if len(delimiter) == 0 || len(delimiter) > 32 || maximum < uint64(len(delimiter)) {
		return cursorTarget{}, ErrCursorTarget
	}
	target, err := exactCursorTarget(maximum, capacity)
	if err != nil {
		return cursorTarget{}, err
	}
	target.length = uint8(len(delimiter))
	copy(target.delimiter[:], delimiter)
	for i, matched := 1, uint8(0); i < len(delimiter); i++ {
		for matched > 0 && delimiter[i] != delimiter[matched] {
			matched = target.prefix[matched-1]
		}
		if delimiter[i] == delimiter[matched] {
			matched++
		}
		target.prefix[i] = matched
	}
	return target, nil
}

// ReaderCursor is the sole advancement owner until its original boundary is
// fixed. Wait cancellation preserves that owner, its private prefix and KMP
// state. A completed candidate detaches from the Stream/crypto graph and keeps
// only the independently admitted delivery authorization and private backing.
// All source copies are synchronous; there is no read task or adapter queue.
type ReaderCursor struct {
	mu              sync.Mutex
	flow            *ReceiveFlow
	owner           *StreamOwnership
	target          cursorTarget
	start, filled   uint64
	matched         uint8
	storage         []byte
	reservation     resourcev4.Reference
	authorization   protocolv4.AuthorizationGuard
	scopeDeadline   *timev4.Deadline
	scopeContext    context.Context
	changed         chan struct{} // One lifetime broadcast when filling stops.
	timer           *time.Timer   // Only the sole read waiter uses this timer.
	status          protocolv4.V4StreamStatus
	cause           protocolv4.V4ReadCause
	failure         error
	closeReason     protocolv4.V4ReadMethodFailureReason
	closeIdentities uint64
	complete        bool
	frozen          bool
	delivered       bool
	closed          bool
	waiting         bool
	signaled        bool
}

// ReaderCursorCharge covers storage, fixed matching metadata, one waiter and
// one timer. The profile additionally admits allocator/channel/timer/stack
// overhead and a separate CredentialSubscriptionsCharge before consumption.
// This minimum alone is not a provider or runtime memory qualification.
func ReaderCursorCharge(storageBytes uint64) (resourcev4.Vector, error) {
	metadata := uint64(unsafe.Sizeof(ReaderCursor{})) + uint64(unsafe.Sizeof(ReadMethodError{})) + uint64(unsafe.Sizeof(protocolv4.V4ReaderCursorSnapshot{}))
	if storageBytes > uint64(math.MaxInt) || storageBytes > math.MaxUint64-metadata {
		return resourcev4.Vector{}, ErrCursorTarget
	}
	return resourcev4.Vector{resourcev4.SDKBytes: storageBytes + metadata, resourcev4.Items: 2, resourcev4.WorkSlots: 1, resourcev4.Tasks: 1, resourcev4.Timers: 1}, nil
}

func NewExactReaderCursor(f *ReceiveFlow, k, capacity uint64, reservation resourcev4.Reference, authorization *protocolv4.DeliveryAuthorization) (*ReaderCursor, error) {
	target, err := exactCursorTarget(k, capacity)
	if err != nil {
		return nil, cursorConstructionError(err)
	}
	return admitReaderCursor(f, target, reservation, authorization)
}

func NewUntilReaderCursor(f *ReceiveFlow, delimiter []byte, maximum, capacity uint64, reservation resourcev4.Reference, authorization *protocolv4.DeliveryAuthorization) (*ReaderCursor, error) {
	target, err := untilCursorTarget(delimiter, maximum, capacity)
	if err != nil {
		return nil, cursorConstructionError(err)
	}
	return admitReaderCursor(f, target, reservation, authorization)
}

func admitReaderCursor(f *ReceiveFlow, target cursorTarget, reservation resourcev4.Reference, authorization *protocolv4.DeliveryAuthorization) (*ReaderCursor, error) {
	return admitOwnedReaderCursor(f, target, reservation, authorization, nil)
}

func admitOwnedReaderCursor(f *ReceiveFlow, target cursorTarget, reservation resourcev4.Reference, authorization *protocolv4.DeliveryAuthorization, owner *StreamOwnership) (*ReaderCursor, error) {
	if f == nil || authorization == nil {
		return nil, cursorConstructionError(ErrCursorTarget)
	}
	f.pool.mu.Lock()
	defer f.pool.mu.Unlock()
	if err := f.readOwnershipLocked(owner); err != nil {
		return nil, cursorConstructionError(err)
	}
	if f.readPending {
		return nil, cursorConstructionError(ErrReadInProgress)
	}
	if target.limit > math.MaxUint64-f.delivered {
		return nil, cursorConstructionError(ErrCursorTarget)
	}
	if err := reservation.CheckSameEnvironment(f.reservation); err != nil {
		return nil, cursorConstructionError(err)
	}
	charge, err := ReaderCursorCharge(target.limit)
	if err != nil {
		return nil, cursorConstructionError(err)
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		return nil, cursorConstructionError(err)
	}
	guard, err := authorization.TakeFor(owned)
	if err != nil {
		owned.Release()
		return nil, cursorConstructionError(err)
	}
	c := newReaderCursorLocked(f, target, owned, guard)
	c.owner = owner
	if owner != nil {
		c.scopeDeadline = owner.deadline
		c.scopeContext = owner.operationContext
	}
	return c, nil
}

// The caller has already admitted the actual backing and delivery reference,
// and holds the pool gate. Isolated mechanics tests use a synthetic guard here;
// production constructors accept only the original DeliveryAuthorization.
func newReaderCursorLocked(f *ReceiveFlow, target cursorTarget, owned resourcev4.Reference, guard protocolv4.AuthorizationGuard) *ReaderCursor {
	c := &ReaderCursor{flow: f, target: target, start: f.delivered, storage: make([]byte, int(target.limit)), reservation: owned, authorization: guard, changed: make(chan struct{}), timer: time.NewTimer(time.Hour), status: protocolv4.V4StreamStatusOpen}
	c.timer.Stop()
	f.readPending = true
	return c
}

// Progress returns a generated bounded metadata snapshot with no data alias.
func (c *ReaderCursor) Progress() protocolv4.V4ReaderCursorSnapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.snapshotLocked()
}

func (c *ReaderCursor) resultLocked(wait protocolv4.V4WaitStatus) protocolv4.V4ReadResult {
	target := c.target.limit
	r := protocolv4.V4ReadResult{Progress: protocolv4.V4ReadProgress{Offset: c.start + c.filled, Target: &target}, WaitStatus: wait, StreamStatus: c.status}
	if c.cause != "" && wait == protocolv4.V4WaitStatusReady {
		cause := c.cause
		r.Cause = &cause
	}
	return r
}

func (c *ReaderCursor) ReadExactly(ctx context.Context) (protocolv4.V4ReadResult, error) {
	return c.read(ctx, false, false)
}
func (c *ReaderCursor) ReadUntil(ctx context.Context) (protocolv4.V4ReadResult, error) {
	return c.read(ctx, true, false)
}
func (c *ReaderCursor) ReadLine(ctx context.Context) (protocolv4.V4ReadResult, error) {
	return c.read(ctx, true, true)
}

// Local method failures return a zero value plus ReadMethodError metadata.
// Only actual payload/wait/Stream outcomes produce a ReadResult.
func (c *ReaderCursor) read(ctx context.Context, until, line bool) (protocolv4.V4ReadResult, error) {
	c.mu.Lock()
	if ctx == nil || (c.target.length != 0) != until || line && (c.target.length != 1 || c.target.delimiter[0] != '\n') {
		reason := protocolv4.V4ReadMethodFailureReasonTargetMismatch
		if ctx == nil {
			reason = protocolv4.V4ReadMethodFailureReasonInvalidArgument
		}
		r, err := c.methodFailureLocked(reason, ErrCursorTarget)
		c.mu.Unlock()
		return r, err
	}
	if c.delivered {
		r, err := c.methodFailureLocked(protocolv4.V4ReadMethodFailureReasonAlreadyDelivered, ErrAlreadyDelivered)
		c.mu.Unlock()
		return r, err
	}
	if c.waiting {
		r, err := c.methodFailureLocked(protocolv4.V4ReadMethodFailureReasonReadInProgress, ErrReadInProgress)
		c.mu.Unlock()
		return r, err
	}
	// A completed/frozen cursor may return advancement ownership while this
	// original waiter still holds the source's notification channels. Keep
	// that exact flow's physical slot/charge until this call actually exits;
	// otherwise Cleanup could reuse a supposedly free slot under a late wait.
	tail := c.flow
	tailOwner := c.owner
	if tail != nil {
		tail.pool.mu.Lock()
		if tail.readTails == math.MaxUint32 {
			tail.pool.mu.Unlock()
			r, err := c.methodFailureLocked(protocolv4.V4ReadMethodFailureReasonOwnerUnavailable, ErrReadInProgress)
			c.mu.Unlock()
			return r, err
		}
		tail.readTails++
		tail.pool.mu.Unlock()
	}
	c.waiting = true
	defer func() {
		if tail != nil {
			tail.pool.mu.Lock()
			tail.readTails--
			tail.notifyCleanupLocked()
			tail.pool.mu.Unlock()
		}
		tailOwner.notify()
		c.waiting = false
		c.timer.Stop()
		c.releaseLocked()
		c.mu.Unlock()
	}()
	for {
		if c.delivered {
			return c.methodFailureLocked(protocolv4.V4ReadMethodFailureReasonAlreadyDelivered, ErrAlreadyDelivered)
		}
		if c.closed {
			return c.methodFailureLocked(c.closeReason, nil)
		}
		if c.frozen {
			return c.methodFailureLocked(protocolv4.V4ReadMethodFailureReasonPrefixFrozen, ErrCursorFrozen)
		}
		remaining, err := c.authorizedLocked()
		if err != nil {
			return c.methodFailureLocked(methodFailureReason(err), err)
		}
		if c.complete {
			return c.deliverLocked(ctx)
		}
		// Observe terminal facts before cancellation, but never consume another
		// byte after this wait has already been cancelled.
		moved, err := c.advanceLocked(ctx.Err() == nil)
		if err != nil {
			if !cursorTimePaused(err) {
				c.closeLocked(err)
			}
			return c.methodFailureLocked(methodFailureReason(err), err)
		}
		if c.complete {
			continue // Recheck current delivery authority after the source copy.
		}
		if err := ctx.Err(); err != nil {
			return c.resultLocked(protocolv4.V4WaitStatusWaitCanceled), err
		}
		if moved {
			c.mu.Unlock()
			runtime.Gosched()
			c.mu.Lock()
			continue
		}
		readWake, poolClosed := c.flow.readWake, c.flow.pool.done
		ownerWake := ownershipWake(c.owner)
		authorizationWake := c.authorization.Wake()
		c.timer.Reset(idleTimerChunk(remaining))
		c.mu.Unlock()
		select {
		case <-ctx.Done():
		case <-readWake:
		case <-ownerWake:
		case <-poolClosed:
		case <-authorizationWake:
		case <-c.changed:
		case <-c.timer.C:
		}
		c.mu.Lock()
		c.timer.Stop()
	}
}

func cursorTimePaused(err error) bool {
	return errors.Is(err, timev4.ErrPending) || errors.Is(err, timev4.ErrUnavailable)
}

func (c *ReaderCursor) authorizedLocked() (uint64, error) {
	err := c.reservation.Check()
	if err == nil && c.scopeContext != nil {
		err = c.scopeContext.Err()
	}
	var remaining uint64
	if err == nil {
		remaining, err = c.authorization.RemainingMS()
	}
	if err == nil && c.scopeDeadline != nil {
		var left uint64
		left, err = c.scopeDeadline.RemainingMS()
		remaining = min(remaining, left)
	}
	if err != nil && !cursorTimePaused(err) {
		c.closeLocked(err)
	}
	return remaining, err
}

// advanceLocked holds both cursor and original queue gates through scanning,
// copy and frontier accounting. The suffix after the first delimiter stays in
// the source ring, including when that suffix shares the same received frame.
func (c *ReaderCursor) advanceLocked(consume bool) (bool, error) {
	f := c.flow
	f.pool.mu.Lock()
	defer f.pool.mu.Unlock()
	if err := f.readOwnershipLocked(c.owner); err != nil {
		return false, err
	}
	terminal, err := f.readStatusLocked()
	if err != nil && terminal != protocolv4.V4ReadTerminalAbandoned {
		// A local authorization/resource/read-owner failure is not evidence
		// of a Stream protocol error and cannot erase an established EOF.
		return false, err
	}
	c.setStatusLocked(terminal, err)
	if terminal != protocolv4.V4ReadTerminalOpen || err != nil || c.target.limit == 0 {
		c.finishSourceLocked(f, err)
		return false, nil
	}
	if !consume {
		return false, nil
	}
	n := min(f.size, cursorScanPiece, int(c.target.limit-c.filled))
	matched := c.matched
	found := false
	if c.target.length != 0 {
		for i := 0; i < n; i++ {
			b := f.storage[(f.head+i)%len(f.storage)]
			for matched > 0 && b != c.target.delimiter[matched] {
				matched = c.target.prefix[matched-1]
			}
			if b == c.target.delimiter[matched] {
				matched++
			}
			if matched == c.target.length {
				n, found = i+1, true
				break
			}
		}
	}
	count, terminal, err := f.readCopyLocked(c.storage[int(c.filled) : int(c.filled)+n])
	c.filled += uint64(count)
	c.matched = matched
	c.setStatusLocked(terminal, err)
	if found || c.filled == c.target.limit || terminal != protocolv4.V4ReadTerminalOpen || err != nil {
		if c.target.length != 0 && !found && c.filled == c.target.limit {
			c.cause = protocolv4.V4ReadCauseDelimiterNotFound
		}
		c.finishSourceLocked(f, err)
	}
	return count != 0, nil
}

func (c *ReaderCursor) setStatusLocked(terminal protocolv4.V4ReadTerminal, err error) {
	switch terminal {
	case protocolv4.V4ReadTerminalEof:
		c.status = protocolv4.V4StreamStatusEof
	case protocolv4.V4ReadTerminalAbandoned:
		c.status = protocolv4.V4StreamStatusAborted
	default:
		c.status = protocolv4.V4StreamStatusOpen
		if err != nil {
			c.status = protocolv4.V4StreamStatusError
		}
	}
}

func (c *ReaderCursor) finishSourceLocked(f *ReceiveFlow, err error) {
	if c.status == protocolv4.V4StreamStatusEof && c.cause == "" && c.filled < c.target.limit && (c.target.length == 0 || c.matched != c.target.length) {
		c.cause = protocolv4.V4ReadCauseUnexpectedEof
	}
	c.complete, c.failure = true, boundedReadCause(err)
	f.readPending = false
	f.notifyCleanupLocked()
	c.flow = nil
	c.owner.notify()
	c.owner = nil
	c.signalLocked()
}

func (c *ReaderCursor) signalLocked() {
	if !c.signaled {
		c.signaled = true
		close(c.changed)
	}
}

func (c *ReaderCursor) detachLocked() {
	if f := c.flow; f != nil {
		f.pool.mu.Lock()
		f.readPending = false
		f.notifyCleanupLocked()
		c.flow = nil
		f.pool.mu.Unlock()
	}
	c.owner.notify()
	c.owner = nil
	c.signalLocked()
}

// TakePrefix permanently ends filling even if this wait is already cancelled.
// An in-flight source copy uses this same mutex, so all genuinely consumed
// bytes are included before another reader can acquire the source direction.
func (c *ReaderCursor) TakePrefix(ctx context.Context) (protocolv4.V4ReadResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ctx == nil {
		return c.methodFailureLocked(protocolv4.V4ReadMethodFailureReasonInvalidArgument, ErrCursorTarget)
	}
	if c.delivered {
		return c.methodFailureLocked(protocolv4.V4ReadMethodFailureReasonAlreadyDelivered, ErrAlreadyDelivered)
	}
	if c.closed {
		return c.methodFailureLocked(c.closeReason, nil)
	}
	c.frozen = true
	if c.flow != nil {
		// Preserve already observable EOF/error facts without advancing the
		// source. Freezing an open partial target is not unexpected EOF.
		if _, err := c.advanceLocked(false); err != nil {
			if !cursorTimePaused(err) {
				c.closeLocked(err)
			}
			c.detachLocked()
			return c.methodFailureLocked(methodFailureReason(err), err)
		}
	}
	c.detachLocked()
	if _, err := c.authorizedLocked(); err != nil {
		return c.methodFailureLocked(methodFailureReason(err), err)
	}
	return c.deliverLocked(ctx)
}

func (c *ReaderCursor) deliverLocked(ctx context.Context) (protocolv4.V4ReadResult, error) {
	if err := ctx.Err(); err != nil && c.status == protocolv4.V4StreamStatusOpen {
		return c.resultLocked(protocolv4.V4WaitStatusWaitCanceled), err
	}
	// This synchronous Go ownership handoff is irrevocable under the same
	// cursor gate as Close/cancellation. No task can discard or republish it.
	r := c.resultLocked(protocolv4.V4WaitStatusReady)
	r.Data = c.storage[:c.filled:c.filled]
	r.Progress.Filled = c.filled
	c.storage = nil
	c.delivered = true
	c.detachLocked()
	c.releaseLocked()
	return r, c.failure
}

func (c *ReaderCursor) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed && !c.delivered {
		c.closeLocked(ErrCursorClosed)
	}
}

func (c *ReaderCursor) closeLocked(err error) {
	c.closed = true
	c.closeReason = methodFailureReason(err)
	c.closeIdentities = methodIdentities(err)
	clear(c.storage)
	c.storage = nil
	c.detachLocked()
	c.releaseLocked()
}

func (c *ReaderCursor) releaseLocked() {
	if c.waiting || !c.closed && !c.delivered {
		return
	}
	c.timer.Stop()
	if c.authorization != nil {
		cause := c.failure
		if c.closed && c.closeIdentities != 0 {
			cause = sourceReadError(c.closeIdentities)
		}
		c.authorization.Close(cause)
		c.authorization = nil
	}
	c.reservation.Release()
	c.reservation = resourcev4.Reference{}
	c.scopeDeadline = nil
	c.scopeContext = nil
}
