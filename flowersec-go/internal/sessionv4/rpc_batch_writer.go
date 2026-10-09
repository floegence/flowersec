package sessionv4

import (
	"context"
	"math"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
)

// RPCBatchWriter is the one ordinary RPC publisher's attachment to the real
// Stream acceptance ring. It neither queues a second candidate nor owns a
// second sender. The existing SendService publishes records and wakes this
// attachment as its actual application frontier advances.
type RPCBatchWriter struct {
	mu                sync.Mutex
	wakeMu            sync.Mutex
	managementWake    chan struct{}
	owner             *StreamOwnership
	queue             *SendQueue
	reservation       resourcev4.Reference
	wake              chan struct{}
	tail              uint64
	framing           channelFraming
	closed, retired   bool
	publicationActive bool
}

var _ rpcv4.BatchPublicationSink = (*RPCBatchWriter)(nil)

// WithBatchPublication enters authorization before the Publisher's Network
// gate. The same original writer stays pinned until this finite copy returns;
// no provider call or application callback runs in the publication action.
func (w *RPCBatchWriter) WithBatchPublication(ctx context.Context, action func() error) error {
	if w == nil || ctx == nil || action == nil || w.framing != channelRPC {
		return cryptov4.ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	w.mu.Lock()
	if w.closed || w.retired || w.queue == nil || w.owner == nil || w.owner.admission == nil || w.owner.admission.engine == nil {
		w.mu.Unlock()
		return ErrFlowClosed
	}
	if w.publicationActive {
		w.mu.Unlock()
		return cryptov4.ErrCapacity
	}
	w.publicationActive = true
	engine := w.owner.admission.engine
	w.mu.Unlock()
	defer func() { w.mu.Lock(); w.publicationActive = false; w.mu.Unlock() }()
	acceptance, err := engine.PrepareApplicationAcceptance()
	if err != nil {
		return err
	}
	return acceptance.WithPublication(func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if _, err := acceptance.Check(); err != nil {
			return err
		}
		return action()
	})
}

func RPCBatchWriterCharge(runtimeBytes uint64) (resourcev4.Vector, error) {
	if runtimeBytes == 0 {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	return (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(RPCBatchWriter{})), resourcev4.Items: 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: runtimeBytes})
}

// NewRPCBatchWriter pins the original full-Stream owner until Retire. It must
// be installed before another write/helper/operation begins. Reader capacity
// and this writer's runtime backing are admitted separately before channel OPEN.
func NewRPCBatchWriter(owner *StreamOwnership, reservation resourcev4.Reference, runtimeBytes uint64) (*RPCBatchWriter, error) {
	return newChannelBatchWriter(owner, reservation, runtimeBytes, channelRPC)
}

// A notification attachment uses the same original ring and sender, with its
// framing selected once by the authenticated channel kind. It cannot accept
// RPC fragments; the notification publisher owns its serial message boundary.
func newNotifyBatchWriter(owner *StreamOwnership, reservation resourcev4.Reference, runtimeBytes uint64) (*RPCBatchWriter, error) {
	return newChannelBatchWriter(owner, reservation, runtimeBytes, channelNotify)
}

type channelFraming uint8

const (
	channelRPC channelFraming = iota
	channelNotify
	channelManagement
)

func newManagementBatchWriter(owner *StreamOwnership, reservation resourcev4.Reference, runtimeBytes uint64) (*RPCBatchWriter, error) {
	return newChannelBatchWriter(owner, reservation, runtimeBytes, channelManagement)
}
func (w *RPCBatchWriter) TryAcceptManagement(ctx context.Context, wire []byte, gate rpcv4.ManagementPublicationGate) (uint64, error) {
	if w == nil || w.framing != channelManagement || ctx == nil || len(wire) < 3 || len(wire) > 1538 {
		return 0, cryptov4.ErrConfiguration
	}
	if err := w.managementAcceptancePreflight(ctx); err != nil {
		return 0, err
	}
	return w.acceptManagementBytes(ctx, wire, gate, false)
}

// TryAcceptAuthorizedManagement is used while the original management
// endpoint/lease authorization gate is held. It performs only the bounded
// writer/queue/capacity/ring transfer and skips recursive Engine auth.
func (w *RPCBatchWriter) TryAcceptAuthorizedManagement(ctx context.Context, wire []byte, gate rpcv4.ManagementPublicationGate) (uint64, error) {
	if w == nil || w.framing != channelManagement || ctx == nil || len(wire) < 3 || len(wire) > 1538 {
		return 0, cryptov4.ErrConfiguration
	}
	return w.acceptManagementBytes(ctx, wire, gate, true)
}

// managementAcceptancePreflight performs the engine and flow authorization
// checks without holding either the writer or send-queue mutex. The final
// lifetime and ring checks are repeated by acceptManagementBytes.
func (w *RPCBatchWriter) managementAcceptancePreflight(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	w.mu.Lock()
	if w.closed || w.retired || w.queue == nil {
		w.mu.Unlock()
		return ErrFlowClosed
	}
	q, owner := w.queue, w.owner
	if err := w.reservation.Check(); err != nil {
		w.mu.Unlock()
		return err
	}
	w.mu.Unlock()
	q.mu.Lock()
	if q.rpcBatch != w || owner.sealed.Load() || q.closed || q.sealed || q.flow == nil || q.flow.reset.Load() {
		q.mu.Unlock()
		return ErrFlowClosed
	}
	if err := q.reservation.Check(); err != nil {
		q.mu.Unlock()
		return err
	}
	flow := q.flow
	engine := flow.writer.engine
	q.mu.Unlock()
	if err := engine.CheckApplicationAuthorization(); err != nil {
		return err
	}
	flow.mu.Lock()
	defer flow.mu.Unlock()
	if flow.stopping {
		return ErrFlowClosed
	}
	return flow.reservation.Check()
}

func (w *RPCBatchWriter) acceptManagementBytes(ctx context.Context, wire []byte, gate rpcv4.ManagementPublicationGate, authorized bool) (uint64, error) {
	var tail uint64
	transfer := func() error {
		admission := w.owner.admission
		admission.managementGate.Lock()
		defer admission.managementGate.Unlock()
		if admission.managementSealed.Load() {
			return rpcv4.ErrManagementClosed
		}
		w.mu.Lock()
		defer w.mu.Unlock()
		if w.closed || w.retired || w.queue == nil {
			return ErrFlowClosed
		}
		q := w.queue
		// Ordinary callers completed engine authorization in the preflight
		// before entering the final publication gate. Authorized callers already
		// hold that decision. The transfer phase therefore only rechecks the
		// writer, queue, reservation, and ring state; repeating engine auth here
		// would recurse when the final gate itself holds that provider lock.
		_ = authorized
		q.mu.Lock()
		defer q.mu.Unlock()
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := w.reservation.Check(); err != nil {
			return err
		}
		if q.rpcBatch != w || w.owner.sealed.Load() {
			return ErrStreamOwned
		}
		if err := q.finishOwnershipLocked(w.owner); err != nil {
			return err
		}
		// Engine authorization was completed before entering the final gate;
		// this phase only rechecks the local lifetime and backing state.
		if err := q.authorizedRequestAcceptanceErrorLocked(); err != nil {
			return err
		}
		if q.published < w.tail || q.first != -1 || len(wire) > len(q.storage)-q.size {
			return cryptov4.ErrCapacity
		}
		if uint64(len(wire)) > math.MaxUint64-q.accepted || uint64(len(wire)) > math.MaxUint64-w.owner.accepted.Load() {
			return ErrStreamData
		}
		ringTail := (q.head + q.size) % len(q.storage)
		first := copy(q.storage[ringTail:], wire)
		copy(q.storage[:len(wire)-first], wire[first:])
		q.size += len(wire)
		q.accepted += uint64(len(wire))
		w.owner.accepted.Add(uint64(len(wire)))
		w.tail = q.accepted
		tail = w.tail
		q.completion.accepted(q.accepted)
		q.Notify()
		return nil
	}
	if gate != nil {
		if err := gate(transfer); err != nil {
			return 0, err
		}
	} else if err := transfer(); err != nil {
		return 0, err
	}
	return tail, nil
}

func newChannelBatchWriter(owner *StreamOwnership, reservation resourcev4.Reference, runtimeBytes uint64, framing channelFraming) (*RPCBatchWriter, error) {
	if owner == nil {
		return nil, cryptov4.ErrConfiguration
	}
	charge, err := RPCBatchWriterCharge(runtimeBytes)
	if err != nil {
		return nil, err
	}
	_, _, _, q, err := owner.begin()
	if err != nil {
		return nil, err
	}
	keep := false
	defer func() {
		if !keep {
			owner.end()
		}
	}()
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.rpcBatch != nil || q.service == nil || q.usedMethodsLocked() != 0 || q.observers != 0 || q.size != 0 || q.pumping || len(q.storage) < 16384 {
		return nil, cryptov4.ErrCapacity
	}
	if err := q.requestErrorLocked(owner); err != nil {
		return nil, err
	}
	if err := reservation.CheckSameEnvironment(q.reservation); err != nil {
		return nil, err
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		return nil, err
	}
	w := &RPCBatchWriter{owner: owner, queue: q, reservation: owned, wake: make(chan struct{}, 1), tail: q.accepted, framing: framing}
	if framing == channelManagement {
		w.managementWake = make(chan struct{})
	}
	q.rpcBatch = w
	keep = true
	return w, nil
}

func (w *RPCBatchWriter) Wake() <-chan struct{} { return w.wake }

// ManagementWake broadcasts a generation of real ring progress to the two
// service publishers and two bounded callers. Each snapshots it before trying
// the acceptance gate, so another waiter cannot steal its only progress hint.
func (w *RPCBatchWriter) ManagementWake() <-chan struct{} {
	w.wakeMu.Lock()
	defer w.wakeMu.Unlock()
	return w.managementWake
}

// Queue progress calls notifyLocked under the original queue gate. Close may
// also wake the owner. The immutable coalesced channel needs no writer mutex.
func (w *RPCBatchWriter) notifyLocked() {
	if w.framing == channelManagement {
		w.wakeMu.Lock()
		close(w.managementWake)
		w.managementWake = make(chan struct{})
		w.wakeMu.Unlock()
	}
	select {
	case w.wake <- struct{}{}:
	default:
	}
}

// CheckRequestAcceptance performs the writer-only preflight used while the
// caller still owns the request authorization gate. It deliberately checks no
// endpoint or application authorization; WithRequestPublication owns that
// ordering. The complete geometry and ring checks are repeated by
// TryAcceptAuthorizedRequest after the caller gate is entered.
func (w *RPCBatchWriter) CheckRequestAcceptance(ctx context.Context) error {
	if w == nil || (w.framing != channelRPC && w.framing != channelNotify) || ctx == nil {
		return cryptov4.ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed || w.retired || w.queue == nil {
		return ErrFlowClosed
	}
	if err := w.reservation.Check(); err != nil {
		return err
	}
	q := w.queue
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.rpcBatch != w || w.owner.sealed.Load() {
		return ErrStreamOwned
	}
	if err := q.finishOwnershipLocked(w.owner); err != nil {
		return err
	}
	return q.authorizedRequestAcceptanceErrorLocked()
}

// TryAcceptAuthorizedRequest is the narrow request path. The caller has
// already entered its original WithRequestPublication gate, so this method
// performs only the writer/queue acceptance and bounded ring copy. In
// particular, it must not acquire or revalidate the caller's authorization.
func (w *RPCBatchWriter) TryAcceptAuthorizedRequest(ctx context.Context, fragments [][]byte) (uint64, error) {
	return w.tryAcceptRequest(ctx, fragments, true)
}

// TryAccept atomically copies a complete fair-selected batch into the SAME
// admitted ring, or accepts nothing. The publisher holds its message gate
// across this call and its per-message serial/offset/terminal updates. Markers
// are singleton batches. Source bytes remain immutable through this call and
// are no longer borrowed on return. No provider or peer completion is inferred.
func (w *RPCBatchWriter) TryAccept(ctx context.Context, fragments [][]byte) (uint64, error) {
	return w.tryAcceptRequest(ctx, fragments, false)
}

func (w *RPCBatchWriter) tryAcceptRequest(ctx context.Context, fragments [][]byte, authorized bool) (uint64, error) {
	if w == nil || w.framing != channelRPC || ctx == nil || len(fragments) == 0 || len(fragments) > 4 {
		return 0, cryptov4.ErrConfiguration
	}
	// Validate finite geometry before entering the acceptance gate. The
	// caller's single publisher already owns canonical headers and serials.
	total := 0
	for _, wire := range fragments {
		fragment, err := protocolv4.DecodeRPCFragment(wire)
		if err != nil {
			return 0, err
		}
		if (fragment.Kind == protocolv4.RPCAbort || fragment.Kind == protocolv4.RPCStopOutput) && len(fragments) != 1 {
			return 0, cryptov4.ErrConfiguration
		}
		total += len(wire)
	}
	if total > 65536 {
		return 0, cryptov4.ErrConfiguration
	}
	if authorized {
		return w.acceptBytesAuthorizedRequest(ctx, fragments, total)
	}
	return w.acceptBytesGuarded(ctx, fragments, total, nil)
}

func (w *RPCBatchWriter) TryAcceptResponse(ctx context.Context, fragments [][]byte, publication *rpcv4.Publication) (uint64, error) {
	if publication == nil {
		return 0, cryptov4.ErrConfiguration
	}
	return w.tryAcceptResponse(ctx, fragments, publication, false)
}

// TryAcceptAuthorizedResponse is used by result-read publication while its
// original result authorization gate is held. A nil publication is valid for
// intermediate response fragments; a non-nil one attaches the final frontier.
func (w *RPCBatchWriter) TryAcceptAuthorizedResponse(ctx context.Context, fragments [][]byte, publication *rpcv4.Publication) (uint64, error) {
	return w.tryAcceptResponse(ctx, fragments, publication, true)
}

func (w *RPCBatchWriter) tryAcceptResponse(ctx context.Context, fragments [][]byte, publication *rpcv4.Publication, authorized bool) (uint64, error) {
	if w == nil || w.framing != channelRPC || ctx == nil || len(fragments) == 0 || len(fragments) > 4 {
		return 0, cryptov4.ErrConfiguration
	}
	// Validate finite geometry before entering the acceptance gate. The
	// caller's single publisher already owns canonical headers and serials.
	total := 0
	for _, wire := range fragments {
		fragment, err := protocolv4.DecodeRPCFragment(wire)
		if err != nil {
			return 0, err
		}
		if (fragment.Kind == protocolv4.RPCAbort || fragment.Kind == protocolv4.RPCStopOutput) && len(fragments) != 1 {
			return 0, cryptov4.ErrConfiguration
		}
		total += len(wire)
	}
	if total > 65536 {
		return 0, cryptov4.ErrConfiguration
	}
	if authorized {
		return w.acceptBytesGuardedMode(ctx, fragments, total, nil, true, publication)
	}
	return w.acceptBytesGuarded(ctx, fragments, total, nil, publication)
}

func (w *RPCBatchWriter) TryAcceptNotify(ctx context.Context, chunk []byte) (uint64, error) {
	if w == nil || w.framing != channelNotify || ctx == nil || len(chunk) == 0 || len(chunk) > 16384 {
		return 0, cryptov4.ErrConfiguration
	}
	return w.acceptBytes(ctx, [][]byte{chunk}, len(chunk))
}

// TryAcceptAuthorizedNotify copies notification bytes while the original
// notify publication guard is held. It skips the recursive Engine check used
// by ordinary TryAcceptNotify.
func (w *RPCBatchWriter) TryAcceptAuthorizedNotify(ctx context.Context, chunk []byte) (uint64, error) {
	if w == nil || w.framing != channelNotify || ctx == nil || len(chunk) == 0 || len(chunk) > 16384 {
		return 0, cryptov4.ErrConfiguration
	}
	return w.acceptBytesGuardedMode(ctx, [][]byte{chunk}, len(chunk), nil, true)
}

func (w *RPCBatchWriter) acceptBytes(ctx context.Context, fragments [][]byte, total int) (uint64, error) {
	return w.acceptBytesGuarded(ctx, fragments, total, nil)
}

func (w *RPCBatchWriter) acceptBytesAuthorizedRequest(ctx context.Context, fragments [][]byte, total int) (uint64, error) {
	return w.acceptBytesGuardedMode(ctx, fragments, total, nil, true)
}

func (w *RPCBatchWriter) acceptBytesGuarded(ctx context.Context, fragments [][]byte, total int, gate rpcv4.ManagementPublicationGate, publication ...*rpcv4.Publication) (uint64, error) {
	return w.acceptBytesGuardedMode(ctx, fragments, total, gate, false, publication...)
}

func (w *RPCBatchWriter) acceptBytesGuardedMode(ctx context.Context, fragments [][]byte, total int, gate rpcv4.ManagementPublicationGate, authorized bool, publication ...*rpcv4.Publication) (uint64, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed || w.retired || w.queue == nil {
		return 0, ErrFlowClosed
	}
	q := w.queue
	if !authorized {
		if w.owner == nil || w.owner.admission == nil || w.owner.admission.engine == nil {
			return 0, ErrFlowClosed
		}
		if err := w.owner.admission.engine.CheckApplicationAuthorization(); err != nil {
			return 0, err
		}
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if err := w.reservation.Check(); err != nil {
		return 0, err
	}
	if q.rpcBatch != w || w.owner.sealed.Load() {
		return 0, ErrStreamOwned
	}
	if err := q.finishOwnershipLocked(w.owner); err != nil {
		return 0, err
	}
	var acceptanceErr error
	if authorized {
		acceptanceErr = q.authorizedRequestAcceptanceErrorLocked()
	} else {
		acceptanceErr = q.acceptanceErrorLocked()
	}
	if acceptanceErr != nil {
		return 0, acceptanceErr
	}
	if q.published < w.tail || q.first != -1 || total > len(q.storage)-q.size {
		return 0, cryptov4.ErrCapacity
	}
	if uint64(total) > math.MaxUint64-q.accepted || uint64(total) > math.MaxUint64-w.owner.accepted.Load() {
		return 0, ErrStreamData
	}
	// There are no callbacks, awaits, allocations or fallible steps between
	// this original final guard and the complete bounded ring copy.
	transfer := func() error {
		for _, wire := range fragments {
			tail := (q.head + q.size) % len(q.storage)
			first := copy(q.storage[tail:], wire)
			copy(q.storage[:len(wire)-first], wire[first:])
			q.size += len(wire)
		}
		q.accepted += uint64(total)
		w.owner.accepted.Add(uint64(total))
		w.tail = q.accepted
		if len(publication) != 0 && publication[0] != nil {
			q.responsePublication, q.responseTail = publication[0], w.tail
		}
		q.completion.accepted(q.accepted)
		q.Notify() // Current SendService does not coalesce or wait for another write.
		return nil
	}
	if gate != nil {
		if err := gate(transfer); err != nil {
			return 0, err
		}
	} else {
		_ = transfer()
	}
	return w.tail, nil
}

// NotifyTailReleased distinguishes logical failure from the last provider's
// real ring borrow. A stopped notification source cannot retire before this
// physical frontier, even when publication can no longer succeed.
func (w *RPCBatchWriter) NotifyTailReleased(tail uint64) bool {
	if w == nil {
		return false
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.retired {
		return true
	}
	if w.framing != channelNotify || w.queue == nil || tail != w.tail {
		return false
	}
	q := w.queue
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.published >= tail || q.closed && !q.pumping
}

// Published checks the batch's own original application frontier. The next
// batch cannot start until its last record has actually completed publication.
// Cancellation of an observer does not revoke the accepted batch.
func (w *RPCBatchWriter) Published(tail uint64) (bool, error) {
	if w == nil {
		return false, ErrStreamOwned
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.retired || w.queue == nil || tail == 0 || tail != w.tail {
		return false, ErrStreamOwned
	}
	q := w.queue
	q.mu.Lock()
	defer q.mu.Unlock()
	// Pump advances the published frontier before it drops its physical
	// borrow of the queue. Retire requires that borrow to be gone as well;
	// reporting publication during that interval lets a caller race into
	// ErrCapacity even though the requested records are already written.
	if q.published >= tail && !q.pumping {
		return true, nil
	}
	if q.closed {
		return false, q.failure
	}
	return false, nil
}

func (w *RPCBatchWriter) Close() {
	if w == nil {
		return
	}
	w.mu.Lock()
	w.closed = true
	w.notifyLocked()
	w.mu.Unlock()
}

func (w *RPCBatchWriter) drainIdle() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed || w.retired || w.queue == nil {
		return false
	}
	q := w.queue
	q.mu.Lock()
	defer q.mu.Unlock()
	if !q.pumping && q.published >= w.tail {
		// Seal only this send direction. Its ordinary sender publishes FIN;
		// the peer's independent output and our reader remain alive.
		q.sealLocked()
		return true
	}
	return false
}

// Retire joins this attachment's last accepted ring/publication use. Logical
// Close alone cannot refund it or detach the original Stream. A failed Stream
// may release only after the actual queue pump stops borrowing its ring.
func (w *RPCBatchWriter) Retire() error {
	if w == nil {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.retired {
		return nil
	}
	if !w.closed || w.publicationActive {
		return cryptov4.ErrCapacity
	}
	q := w.queue
	q.mu.Lock()
	if q.pumping || q.published < w.tail && !q.closed {
		q.mu.Unlock()
		return cryptov4.ErrCapacity
	}
	if q.rpcBatch != w {
		q.mu.Unlock()
		return ErrStreamOwned
	}
	q.rpcBatch = nil
	q.cleanupLocked()
	q.mu.Unlock()
	w.owner.end()
	w.owner = nil
	w.queue = nil
	w.reservation.Release()
	w.reservation = resourcev4.Reference{}
	w.retired = true
	return nil
}
