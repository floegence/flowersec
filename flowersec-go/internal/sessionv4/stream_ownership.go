package sessionv4

import (
	"context"
	"errors"
	"math"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

var ErrStreamOwned = errors.New("sessionv4: stream has another or revoked owner")
var ErrStreamOwnershipBusy = errors.New("sessionv4: stream owner has live method or buffer tails")

// StreamOwnership is the internal full-Stream capability used by lifecycle
// compositions. The original admission slot is canonical; callers cannot
// acquire authority by wrapping the same engine/scope in another StreamFlow.
// Revocation and physical release are separate. This object creates no worker,
// executor, timer, or alternate I/O queue.
type StreamOwnership struct {
	mu                         sync.Mutex
	admission                  *OpenAdmission
	handle                     OpenHandle
	flow                       *StreamFlow
	queue                      *SendQueue
	reservation                resourcev4.Reference
	users, cap                 uint64
	cleaning                   bool
	handoffClean               bool
	revoked                    atomic.Bool
	sealed                     atomic.Bool
	accepted                   atomic.Uint64
	deadline                   *timev4.Deadline
	operationContext           context.Context
	done                       chan struct{}
	revokeDone                 chan struct{}
	changed                    chan struct{}
	messages                   *StreamMessages
	typed                      *TypedMessageStream
	resume                     *resumeTarget
	recoveryProgress           *streamRecoveryProgress
	rawUsed                    bool
	allocationRoot             *resourcev4.Root
	allocationOwner            resourcev4.OwnerKey
	allocationScopes           [resourcev4.MaxAccountsPerCharge]resourcev4.Account
	allocationCount            int
	allocationExecutor         *ApplicationExecutor
	allocationGroup            *applicationGroup
	allocationExecutionBacking resourcev4.Reference
}

// StreamOwnershipCharge covers its original metadata and one capability. I/O
// calls share the already reserved queue slots and receive advancement owner;
// the complete profile also admits channel and allocator overhead.
func StreamOwnershipCharge() resourcev4.Vector {
	return resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(StreamOwnership{})), resourcev4.Items: 1}
}

func (a *OpenAdmission) OwnStream(h OpenHandle, reservation resourcev4.Reference) (*StreamOwnership, error) {
	return a.ownStream(h, reservation, nil)
}

// A composition fixes its original deadline before publishing either I/O
// capability. Every subsequent acceptance/delivery checks this same owner.
func (a *OpenAdmission) ownStream(h OpenHandle, reservation resourcev4.Reference, deadline *timev4.Deadline) (*StreamOwnership, error) {
	return a.ownStreamContext(h, reservation, deadline, nil)
}

func (a *OpenAdmission) ownStreamContext(h OpenHandle, reservation resourcev4.Reference, deadline *timev4.Deadline, operationContext context.Context) (*StreamOwnership, error) {
	return a.bindStreamOwnership(h, reservation, deadline, operationContext, nil)
}

// A Session factory constructs the private facade and its notifications before
// accepted publication. It has no I/O authority until the original slot binds it.
func prepareStreamOwnership(reservation resourcev4.Reference) (*StreamOwnership, error) {
	owned, err := reservation.Take(StreamOwnershipCharge())
	if err != nil {
		return nil, err
	}
	return &StreamOwnership{reservation: owned, done: make(chan struct{}), revokeDone: make(chan struct{}), changed: make(chan struct{}, 1)}, nil
}

func (a *OpenAdmission) bindStreamOwnership(h OpenHandle, reservation resourcev4.Reference, deadline *timev4.Deadline, operationContext context.Context, candidate *StreamOwnership) (*StreamOwnership, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	s, err := a.slot(h)
	if err != nil {
		return nil, err
	}
	if a.closed {
		return nil, cryptov4.ErrClosed
	}
	if operationContext != nil {
		if err := operationContext.Err(); err != nil {
			return nil, err
		}
	}
	if deadline != nil {
		if !deadline.BelongsTo(a.engine.Clock()) {
			return nil, timev4.ErrOwner
		}
		if err := deadline.Check(); err != nil {
			return nil, err
		}
	}
	if !s.accepted || s.flow == nil || s.cancelled || s.coreCleaned || s.phase != openLive && s.phase != openRecent && s.phase != openHeld {
		return nil, ErrOpenPending
	}
	if s.bootstrap && (!a.bootstrap.complete || !a.bootstrap.materialized || s.carrier == nil || s.deciding) {
		return nil, ErrOpenPending
	}
	if s.owner != nil || s.cleanupBusy || s.retirementReferences == math.MaxUint32 {
		return nil, ErrStreamOwned
	}
	f := s.flow
	f.send.mu.Lock()
	q := f.send.queueOwner
	f.send.mu.Unlock()
	if q == nil || f.send.writer.engine != a.engine || f.send.writer.scope != h.scope || f.receive.engine != a.engine || f.receive.scope != h.scope {
		return nil, cryptov4.ErrConfiguration
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	f.receive.pool.mu.Lock()
	defer f.receive.pool.mu.Unlock()
	if q.writeOwner != nil || f.receive.readOwner != nil || q.waiters != 0 || q.observers != 0 || q.methodTails != 0 || f.receive.readPending || f.receive.readTails != 0 {
		return nil, ErrStreamOwnershipBusy
	}
	if len(q.slots) == 0 || f.receive.cleaned {
		return nil, ErrFlowClosed
	}
	if err := reservation.CheckSameEnvironment(q.reservation); err != nil {
		return nil, err
	}
	if err := reservation.CheckSameEnvironment(f.receive.reservation); err != nil {
		return nil, err
	}
	o := candidate
	if o == nil {
		o, err = prepareStreamOwnership(reservation)
		if err != nil {
			return nil, err
		}
	} else if o.admission != nil || o.reservation != reservation {
		return nil, cryptov4.ErrConfiguration
	} else if err := o.reservation.Check(); err != nil {
		return nil, err
	}
	o.admission, o.handle, o.flow, o.queue = a, h, f, q
	o.cap, o.deadline, o.operationContext = uint64(len(q.slots))+1, deadline, operationContext
	s.owner, q.writeOwner, f.receive.readOwner = o, o, o
	s.retirementReferences++
	return o, nil
}

func ownershipWake(o *StreamOwnership) <-chan struct{} {
	if o == nil {
		return nil
	}
	return o.done
}

func (q *SendQueue) writeOwnershipLocked(o *StreamOwnership) error {
	if q.rpcBatch != nil {
		return ErrStreamOwned
	}
	if o != nil && o.sealed.Load() {
		return ErrStreamOwned
	}
	if o == nil && q.writeOwner == nil {
		q.rawUsed = true
	}
	return q.finishOwnershipLocked(o)
}

// Lifecycle completion retains the original identity and hard deadline after
// callback I/O is sealed. It never restores application acceptance authority.
func (q *SendQueue) finishOwnershipLocked(o *StreamOwnership) error {
	if q.writeOwner != o || o != nil && o.revoked.Load() {
		return ErrStreamOwned
	}
	if o != nil {
		return o.checkLifetime()
	}
	return nil
}

func (f *ReceiveFlow) readOwnershipLocked(o *StreamOwnership) error {
	if f.readOwner != o {
		if o == nil {
			return ErrReadInProgress
		}
		return ErrStreamOwned
	}
	if o != nil {
		if o.revoked.Load() || o.sealed.Load() {
			return ErrStreamOwned
		}
		return o.checkLifetime()
	}
	f.rawUsed = true
	return nil
}

func (o *StreamOwnership) checkLifetime() error {
	if o.operationContext != nil {
		if err := o.operationContext.Err(); err != nil {
			return err
		}
	}
	if o.deadline != nil {
		if err := o.deadline.Check(); err != nil {
			return err
		}
	}
	return o.reservation.Check()
}

// The callback's actual invocation claim is ordered with the original Session
// and Stream close gates. Application code runs only after these locks leave.
func (o *StreamOwnership) enterCallback() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.admission == nil || o.sealed.Load() || o.revoked.Load() {
		return ErrStreamOwned
	}
	a := o.admission
	a.mu.Lock()
	defer a.mu.Unlock()
	s, err := a.slot(o.handle)
	if err != nil {
		return err
	}
	if a.closed || s.cancelled || s.owner != o {
		return cryptov4.ErrClosed
	}
	if err := o.checkLifetime(); err != nil {
		return err
	}
	return a.engine.CheckApplicationAuthorization()
}

// notify is a merged edge, safe under original transport gates. No owner lock,
// callback, allocation or polling task is needed to wake late cleanup.
func (o *StreamOwnership) notify() {
	if o != nil {
		select {
		case o.changed <- struct{}{}:
		default:
		}
	}
}

// begin bounds even callers parked before an underlying I/O gate. Release
// cannot detach a transport while any admitted method still holds its alias.
func (o *StreamOwnership) begin() (*OpenAdmission, OpenHandle, *StreamFlow, *SendQueue, error) {
	return o.beginMethod(false)
}

func (o *StreamOwnership) beginMethod(ending bool) (*OpenAdmission, OpenHandle, *StreamFlow, *SendQueue, error) {
	return o.beginMessagesMethod(nil, ending)
}

func (o *StreamOwnership) beginMessagesMethod(messages *StreamMessages, ending bool) (*OpenAdmission, OpenHandle, *StreamFlow, *SendQueue, error) {
	return o.beginCapabilityMethod(messages, ending, messages == nil)
}

func (o *StreamOwnership) beginCapabilityMethod(messages *StreamMessages, ending, raw bool) (*OpenAdmission, OpenHandle, *StreamFlow, *SendQueue, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if !ending && (o.messages != messages || o.typed != nil || o.resume != nil && messages == nil) {
		return nil, OpenHandle{}, nil, nil, ErrStreamOwned
	}
	if o.admission == nil || !ending && o.revoked.Load() {
		return nil, OpenHandle{}, nil, nil, ErrStreamOwned
	}
	if ending {
		if o.cleaning {
			return nil, OpenHandle{}, nil, nil, ErrStreamOwnershipBusy
		}
		o.cleaning = true
	} else {
		if o.users == o.cap {
			return nil, OpenHandle{}, nil, nil, ErrStreamOwnershipBusy
		}
		o.users++
		if raw {
			o.rawUsed = true
		}
	}
	return o.admission, o.handle, o.flow, o.queue, nil
}

func (o *StreamOwnership) end() { o.mu.Lock(); o.users--; o.notify(); o.mu.Unlock() }

// AcceptedBytes counts only this owner's actual synchronous acceptance gates,
// including prepared writes. It never borrows other writers' Stream offsets.
func (o *StreamOwnership) AcceptedBytes() uint64 { return o.accepted.Load() }

func (o *StreamOwnership) ReadInto(ctx context.Context, dst []byte) (ReadTransfer, error) {
	_, _, f, _, err := o.begin()
	if err != nil {
		return ReadTransfer{}, err
	}
	defer o.end()
	return f.receive.readIntoOwned(ctx, dst, o)
}

func (o *StreamOwnership) TryRead(dst []byte) (int, protocolv4.V4ReadTerminal, error) {
	_, _, f, _, err := o.begin()
	if err != nil {
		return 0, protocolv4.V4ReadTerminalUnknown, err
	}
	defer o.end()
	return f.receive.tryReadOwned(dst, o)
}

func (o *StreamOwnership) Write(ctx context.Context, input []byte) (int, error) {
	_, _, _, q, err := o.begin()
	if err != nil {
		return 0, err
	}
	defer o.end()
	return q.writeOwned(ctx, input, nil, o)
}

func (o *StreamOwnership) WriteAll(ctx context.Context, input []byte) (int, error) {
	_, _, _, q, err := o.begin()
	if err != nil {
		return 0, err
	}
	defer o.end()
	return q.writeAllOwned(ctx, input, o)
}

// CopyTo preserves both original claims; a destination release cannot detach
// while this pump still has its alias. The bridge checks distinct canonical
// endpoints before acquiring either claim.
func (o *StreamOwnership) CopyTo(ctx context.Context, destination *StreamOwnership, chunkBytes uint64, reservation resourcev4.Reference) (CopyResult, error) {
	if destination == nil || destination == o {
		return CopyResult{}, cryptov4.ErrConfiguration
	}
	_, _, source, _, err := o.begin()
	if err != nil {
		return CopyResult{}, err
	}
	defer o.end()
	_, _, target, queue, err := destination.begin()
	if err != nil {
		return CopyResult{}, err
	}
	defer destination.end()
	if source.send.writer.engine == target.send.writer.engine && source.receive.scope == target.receive.scope {
		return CopyResult{}, cryptov4.ErrConfiguration
	}
	return copyOwned(ctx, queue, source.receive, chunkBytes, reservation, o, destination)
}

func (o *StreamOwnership) PrepareWrite(input []byte, options WriteOptions) (*WriteOperation, error) {
	_, _, _, q, err := o.begin()
	if err != nil {
		return nil, err
	}
	defer o.end()
	return q.prepareWriteOwned(input, options, o)
}

func (o *StreamOwnership) CloseWrite(ctx context.Context) error { return o.waitClose(ctx, false) }
func (o *StreamOwnership) Finish(ctx context.Context) error     { return o.waitClose(ctx, true) }
func (o *StreamOwnership) waitClose(ctx context.Context, drain bool) error {
	_, _, _, q, err := o.begin()
	if err != nil {
		return err
	}
	defer o.end()
	return q.waitCloseOwned(ctx, drain, o)
}

func (o *StreamOwnership) ExactReaderCursor(k, capacity uint64, reservation resourcev4.Reference, authorization *protocolv4.DeliveryAuthorization) (*ReaderCursor, error) {
	_, _, f, _, err := o.begin()
	if err != nil {
		return nil, cursorConstructionError(err)
	}
	defer o.end()
	target, err := exactCursorTarget(k, capacity)
	if err != nil {
		return nil, cursorConstructionError(err)
	}
	return admitOwnedReaderCursor(f.receive, target, reservation, authorization, o)
}

func (o *StreamOwnership) UntilReaderCursor(delimiter []byte, maximum, capacity uint64, reservation resourcev4.Reference, authorization *protocolv4.DeliveryAuthorization) (*ReaderCursor, error) {
	_, _, f, _, err := o.begin()
	if err != nil {
		return nil, cursorConstructionError(err)
	}
	defer o.end()
	target, err := untilCursorTarget(delimiter, maximum, capacity)
	if err != nil {
		return nil, cursorConstructionError(err)
	}
	return admitOwnedReaderCursor(f.receive, target, reservation, authorization, o)
}

func (o *StreamOwnership) Cancel() error {
	// This bounded local transition must remain available when all admitted
	// I/O methods are parked. Holding the capability gate pins its aliases.
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.admission == nil {
		return ErrStreamOwned
	}
	return o.admission.cancelOwned(o.handle, o)
}

func (o *StreamOwnership) Cleanup(ctx context.Context) error {
	a, h, _, _, err := o.beginMethod(true)
	if err != nil {
		return err
	}
	defer func() { o.mu.Lock(); o.cleaning = false; o.notify(); o.mu.Unlock() }()
	return a.cleanupStreamOwned(ctx, h, o)
}

func (o *StreamOwnership) CloseResult() (protocolv4.V4CloseResult, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.admission == nil {
		return protocolv4.V4CloseResult{}, ErrStreamOwned
	}
	return o.flow.CloseResult(), nil
}

// Revoke fences owned calls at both original direction gates and wakes existing
// waits. It does not Reset, FIN, discard accepted bytes, or refund live tails.
func (o *StreamOwnership) Revoke() {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.admission == nil || o.revoked.Load() {
		return
	}
	o.admission.mu.Lock()
	o.queue.mu.Lock()
	o.flow.receive.pool.mu.Lock()
	o.revokeLocked()
	o.flow.receive.pool.mu.Unlock()
	o.queue.mu.Unlock()
	o.admission.mu.Unlock()
}

// sealApplication is the private callback handoff. It stops application I/O
// and prepared writes at their original gates, while preserving only the
// scope's Finish/Cancel/Cleanup authority. It sends neither FIN nor Reset.
func (o *StreamOwnership) sealApplication() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.admission == nil {
		return false
	}
	o.queue.mu.Lock()
	o.flow.receive.pool.mu.Lock()
	o.sealApplicationLocked()
	o.flow.receive.pool.mu.Unlock()
	o.queue.mu.Unlock()
	return o.handoffClean
}

func (o *StreamOwnership) sealApplicationLocked() {
	if !o.sealed.Swap(true) {
		o.handoffClean = o.queue.usedMethodsLocked() == 0
		close(o.done)
	}
	o.queue.stopOperationsLocked()
	o.queue.Notify()
	o.flow.receive.signalReadLocked()
	o.notify()
}

func (o *StreamOwnership) revokeLocked() {
	if o.revoked.Swap(true) {
		return
	}
	close(o.revokeDone)
	o.sealApplicationLocked()
}

// Release relinquishes authority only when all admitted calls and original
// read/write owners have actually exited. A busy refusal keeps the same owner;
// no hidden cleanup worker or new quota is created. Detached handles retain only
// their finite accepted counter and closed notification.
func (o *StreamOwnership) Release() error {
	var tail *OpenAdmission
	defer func() {
		if tail != nil {
			tail.endTail()
		}
	}()
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.admission == nil {
		return nil
	}
	if o.users != 0 || o.cleaning || o.messages != nil || o.typed != nil || o.resume != nil {
		return ErrStreamOwnershipBusy
	}
	a, q, f := o.admission, o.queue, o.flow
	a.mu.Lock()
	s, err := a.slot(o.handle)
	if err != nil {
		a.mu.Unlock()
		return err
	}
	q.mu.Lock()
	f.receive.pool.mu.Lock()
	if q.waiters != 0 || q.observers != 0 || q.methodTails != 0 || f.receive.readPending || f.receive.readTails != 0 {
		f.receive.pool.mu.Unlock()
		q.mu.Unlock()
		a.mu.Unlock()
		return ErrStreamOwnershipBusy
	}
	o.revokeLocked()
	a.beginTailLocked()
	tail = a
	s.owner, q.writeOwner, f.receive.readOwner = nil, nil, nil
	s.retirementReferences--
	a.notifyCleanup()
	f.receive.pool.mu.Unlock()
	q.mu.Unlock()
	a.collect(s)
	a.mu.Unlock()
	o.admission, o.flow, o.queue = nil, nil, nil
	o.deadline = nil
	o.operationContext = nil
	o.allocationRoot = nil
	o.allocationOwner = resourcev4.OwnerKey{}
	clear(o.allocationScopes[:])
	o.allocationCount = 0
	o.allocationExecutor, o.allocationGroup = nil, nil
	o.allocationExecutionBacking.Release()
	o.allocationExecutionBacking = resourcev4.Reference{}
	if o.recoveryProgress != nil {
		o.recoveryProgress.reservation.Release()
		o.recoveryProgress = nil
	}
	o.handle = OpenHandle{}
	o.reservation.Release()
	o.reservation = resourcev4.Reference{}
	return nil
}
