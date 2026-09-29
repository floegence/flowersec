package sessionv4

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

const serviceStreamQuantum = uint64(16 * 1024)
const maxPreacceptedStreams = 8
const maxPreacceptedStreamsPerService = 2
const preacceptedIdleMS = uint64(30000)

// Each entry is one actual business Stream in this same Session, never a free
// channel, alternate admission policy or replacement for a retired generation.
// Its original Stream factory task stays charged until transfer or real cleanup.
type preacceptedStream struct {
	mu                                   sync.Mutex
	plan                                 *SessionCorePlan
	allocation                           *sessionStreamAllocation
	admission                            *OpenAdmission
	owner                                *StreamOwnership
	route                                rpcv4.ContractRoute
	reservation, claimHold, claimReserve resourcev4.Reference
	deadline                             *timev4.Deadline
	idle                                 *timev4.Window
	context                              context.Context
	cancel                               context.CancelFunc
	changed                              chan struct{}
	binding                              [32]byte
	kind                                 string
	metadata                             [4096]byte
	namespace                            [128]byte
	namespaceBytes                       int
	metadataBytes, index                 int
	claimed, closed, transferred         bool
}

func preacceptedBinding(kind string, metadata []byte, contract [32]byte) [32]byte {
	hash := sha256.New()
	_, _ = hash.Write([]byte("flowersec/local/preaccepted-stream/v4\x00"))
	_, _ = hash.Write(contract[:])
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(kind)))
	_, _ = hash.Write(length[:])
	_, _ = hash.Write([]byte(kind))
	binary.BigEndian.PutUint32(length[:], uint32(len(metadata)))
	_, _ = hash.Write(length[:])
	_, _ = hash.Write(metadata)
	var result [32]byte
	copy(result[:], hash.Sum(result[:0]))
	return result
}

// PreacceptServiceStream is explicit trusted setup, outside any application
// invocation. It creates at most one pending entry in the Session's fixed slab.
// A try_now miss never calls it and never adds replenishment demand. The exact
// route, kind and metadata are fixed before OPEN; the lifetime is not renewed.
func (c *SessionCore) PreacceptServiceStream(ctx context.Context, kind string, metadata []byte, contract [32]byte, deadline *timev4.Deadline) (err error) {
	return c.preacceptServiceStream(ctx, kind, metadata, contract, deadline, false)
}

// Required declarations share the existing pool's pending or empty entry.
// The original pool gate performs the final check, so concurrent registrations
// cannot open duplicate Streams for the same target. Checkout never calls this.
func (c *SessionCore) preacceptServiceStream(ctx context.Context, kind string, metadata []byte, contract [32]byte, deadline *timev4.Deadline, required bool, workloads ...*unaryWorkload) (err error) {
	if len(workloads) > 1 {
		return cryptov4.ErrConfiguration
	}
	var workload *unaryWorkload
	if len(workloads) == 1 {
		workload = workloads[0]
	}
	if c == nil || c.plan == nil || ctx == nil || deadline == nil || !canonicalStreamHandlerKind(kind) || len(metadata) > 4096 {
		return cryptov4.ErrConfiguration
	}
	application, err := checkApplicationContext(ctx)
	if err != nil {
		return err
	}
	if application {
		return ErrApplicationDependency
	}
	p := c.plan
	binding := preacceptedBinding(kind, metadata, contract)
	if required {
		p.mu.Lock()
		existing := p.hasPreacceptedTargetLocked(binding, workload)
		p.mu.Unlock()
		if existing {
			return nil
		}
	}
	finishCapacity, err := p.preacceptedCapacityGate(binding, contract, required, workload)
	if err != nil {
		return err
	}
	defer finishCapacity()
	allocation, admission, err := p.preparePreacceptedStream(ctx, kind, metadata, contract, workload)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			p.finishStream(allocation)
		}
	}()
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.rpc == nil || !deadline.BelongsTo(p.engine.Clock()) || !serviceStreamGeometry(p.config.Streams) {
		return cryptov4.ErrConfiguration
	}
	if required && p.hasPreacceptedTargetLocked(binding, workload) {
		return nil
	}
	index := -1
	for j, entry := range p.preaccepted {
		if entry == nil {
			index = j
			break
		}
	}
	if index < 0 {
		return cryptov4.ErrCapacity
	}
	p.rpc.mu.Lock()
	parent, routes := p.rpc.runtimeContext, p.rpc.routes
	live := p.rpc.runtimeStarted && !p.rpc.closed && !p.rpc.retired && parent != nil
	p.rpc.mu.Unlock()
	if !live {
		return cryptov4.ErrNotReady
	}
	charges, err := preacceptedStreamCharges(p.config.Streams.RuntimeBytes, len(kind))
	if err != nil {
		return err
	}
	var requests [2]resourcev4.Request
	var refs [2]resourcev4.Reference
	for j, charge := range charges {
		owner := p.resourceOwner
		var seed [49]byte
		copy(seed[:32], "flowersec/preaccepted/owner/v4/")
		copy(seed[32:48], allocation.identity[:])
		seed[48] = byte(j)
		digest := sha256.Sum256(seed[:])
		copy(owner.Instance[:], digest[:16])
		copy(owner.Backing[:], digest[16:])
		requests[j] = resourcev4.Request{Owner: owner, Charge: charge, Accounts: p.accounts[:p.accountCount]}
	}
	if f := allocation.callerFloor; f != nil {
		if err := resourcev4.CheckoutProtectedBatch(f.owners[streamCallerPreaccepted:], refs[:]); err != nil {
			return err
		}
	} else if err := p.root.ReserveBatch(requests[:], refs[:]); err != nil {
		return err
	}
	defer func() {
		if !committed {
			for _, ref := range refs {
				ref.Release()
			}
		}
	}()
	route, err := routes.Capture(contract, refs[1], p.config.Streams.RuntimeBytes)
	if err != nil {
		return err
	}
	defer func() {
		if !committed {
			route.Release()
		}
	}()
	_, policy, err := route.Policy()
	if err != nil || policy.Shape != 1 {
		return rpcv4.ErrMethod
	}
	if err := p.preacceptedServiceCapacityLocked(policy.Namespace); err != nil {
		return err
	}
	fixed, err := deadline.Fork(deadline.Cap())
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	work, cancel := context.WithCancel(parent)
	entry := &preacceptedStream{plan: p, allocation: allocation, admission: admission, route: route, reservation: refs[0], deadline: fixed, context: work, cancel: cancel, changed: make(chan struct{}, 1), index: index, kind: strings.Clone(kind), binding: binding}
	entry.claimReserve, err = entry.reservation.Borrow()
	if err != nil {
		cancel()
		return err
	}
	entry.metadataBytes = copy(entry.metadata[:], metadata)
	entry.namespaceBytes = copy(entry.namespace[:], policy.Namespace)
	p.preaccepted[index] = entry
	if f := allocation.callerFloor; f != nil {
		f.preaccepted = entry
	}
	committed = true
	go entry.run()
	return nil
}

func (p *SessionCorePlan) hasPreacceptedTargetLocked(binding [32]byte, workloads ...*unaryWorkload) bool {
	for _, entry := range p.preaccepted {
		if entry == nil {
			continue
		}
		entry.mu.Lock()
		existing := entry.matchesWorkload(workloads) && entry.binding == binding && !entry.closed && !entry.claimed && !entry.transferred
		entry.mu.Unlock()
		if existing {
			return true
		}
	}
	return false
}

func serviceStreamGeometry(c SessionStreamConfig) bool {
	return c.ReceiveBytes >= serviceStreamQuantum && c.InitialReceiveLimit >= serviceStreamQuantum && c.QueueBytes >= serviceStreamQuantum
}

// Pending and closing entries retain their service share until the original
// factory has actually cleaned them. Different methods of one service share
// the same two positions; a different digest does not create another pool.
func (p *SessionCorePlan) preacceptedServiceCapacityLocked(namespace string) error {
	count := 0
	for _, entry := range p.preaccepted {
		if entry != nil && string(entry.namespace[:entry.namespaceBytes]) == namespace {
			count++
		}
	}
	if count >= maxPreacceptedStreamsPerService {
		return cryptov4.ErrCapacity
	}
	return nil
}

func (e *preacceptedStream) signalLocked() {
	select {
	case e.changed <- struct{}{}:
	default:
	}
}
func (e *preacceptedStream) close() {
	if e == nil {
		return
	}
	e.mu.Lock()
	e.closed = true
	e.cancel()
	e.signalLocked()
	e.mu.Unlock()
}

func (e *preacceptedStream) run() {
	defer func() {
		e.cancel()
		e.route.Release()
		clear(e.metadata[:])
		e.kind = ""
		e.mu.Lock()
		e.claimReserve.Release()
		e.claimReserve = resourcev4.Reference{}
		e.reservation.Release()
		e.mu.Unlock()
		p := e.plan
		p.mu.Lock()
		if f := e.allocation.callerFloor; f != nil && f.preaccepted == e {
			f.preaccepted = nil
		}
		if p.preaccepted[e.index] == e {
			p.preaccepted[e.index] = nil
			p.notifyLocked()
		}
		p.mu.Unlock()
		p.finishStream(e.allocation)
	}()
	a, allocation := e.admission, e.allocation
	h, _, err := e.plan.openBusinessStream(e.context, allocation, e.kind, e.metadata[:e.metadataBytes], e.deadline)
	if err == nil {
		err = a.WaitOutcome(e.context, h)
	}
	if err == nil {
		err = a.checkServiceStreamCredit(h)
	}
	var owner *StreamOwnership
	if err == nil {
		o := allocation.candidate
		owner, err = a.bindStreamOwnership(h, o.reservation, e.deadline, nil, o)
		if err == nil {
			allocation.candidate = nil
			err = owner.protectReceiveCredit(serviceStreamQuantum)
		}
	}
	if err != nil {
		_ = a.Cancel(h)
	}
	var idle *timev4.Window
	if err == nil {
		idle, err = timev4.NewWindow(e.plan.engine.Clock(), preacceptedIdleMS)
	}
	e.mu.Lock()
	e.owner = owner
	e.idle = idle
	if err != nil {
		e.closed = true
	}
	e.signalLocked()
	e.mu.Unlock()
	e.plan.mu.Lock()
	e.plan.notifyLocked()
	e.plan.mu.Unlock()
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	defer timer.Stop()
	for {
		// Sample outside the entry gate. An idle window is never transferred
		// into the business deadline and cannot be renewed by observations.
		now, sampleErr := e.plan.engine.Clock().Sample()
		remaining, lifetimeErr := e.deadline.RemainingMS()
		if lifetimeErr == nil && idle != nil {
			idleRemaining, idleErr := idle.RemainingMS()
			remaining, lifetimeErr = min(remaining, idleRemaining), idleErr
		}
		e.mu.Lock()
		if e.transferred && !e.claimed {
			e.mu.Unlock()
			return
		}
		if lifetimeErr == nil {
			lifetimeErr = sampleErr
		}
		if lifetimeErr == nil && e.idle != nil {
			lifetimeErr = e.idle.CheckAt(now.Mark)
		}
		if lifetimeErr != nil && !cursorTimePaused(lifetimeErr) || e.context.Err() != nil {
			e.closed = true
		}
		closed, claimed, current := e.closed, e.claimed, e.owner
		var ownerChanged <-chan struct{}
		if current != nil {
			ownerChanged = current.changed
		}
		e.mu.Unlock()
		if closed && !claimed {
			if current == nil {
				return
			}
			current.Revoke()
			_ = current.Cancel()
			err := current.Cleanup(context.Background())
			if err == nil {
				if err = current.Release(); err == nil {
					return
				}
			}
			// The original task and entry remain occupied through physical
			// termination, including a provider or cleanup tail that is late.
			remaining = 10
		}
		if remaining == 0 || cursorTimePaused(lifetimeErr) {
			remaining = 10
		}
		remaining = min(remaining, preacceptedIdleMS)
		timer.Reset(idleTimerChunk(remaining))
		select {
		case <-e.changed:
		case <-ownerChanged:
		case <-timer.C:
		}
		timer.Stop()
	}
}

// A private checkout excludes competing constructors but publishes no bytes.
// A failed vector acquisition releases it only after all temporary aliases end.
func (p *SessionCorePlan) claimPreaccepted(ctx context.Context, kind string, metadata []byte, contract [32]byte, floor *streamCallerFloor) (*preacceptedStream, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	binding := preacceptedBinding(kind, metadata, contract)
	now, err := p.engine.Clock().Sample()
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil, cryptov4.ErrClosed
	}
	for _, entry := range p.preaccepted {
		if entry == nil || entry.allocation.callerFloor != floor {
			continue
		}
		entry.mu.Lock()
		available := entry.availableAt(binding, now, false)
		if available {
			hold, err := entry.claimReserve.TakeBorrow()
			if err != nil {
				entry.mu.Unlock()
				return nil, err
			}
			entry.claimHold, entry.claimReserve, entry.claimed = hold, resourcev4.Reference{}, true
			entry.mu.Unlock()
			return entry, nil
		}
		entry.mu.Unlock()
	}
	return nil, cryptov4.ErrNotReady
}

// availableAt is called under the original entry gate. It only inspects the
// same owner that checkout will transfer; it creates no speculative demand.
func (e *preacceptedStream) availableAt(binding [32]byte, now timev4.Sample, claimed bool) bool {
	if e.closed || e.claimed != claimed || e.transferred || e.owner == nil || e.binding != binding || e.idle == nil || e.idle.CheckAt(now.Mark) != nil || e.deadline.CheckAt(now) != nil || e.context.Err() != nil || e.reservation.Check() != nil {
		return false
	}
	o := e.owner
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.admission == nil || o.revoked.Load() || o.sealed.Load() || o.closeRequested.Load() || o.rawUsed || o.messages != nil || o.typed != nil || o.conn != nil || o.resume != nil || o.users != 0 || o.cleaning || o.accepted.Load() != 0 {
		return false
	}
	a := o.admission
	a.mu.Lock()
	defer a.mu.Unlock()
	s, err := a.slot(o.handle)
	if err != nil || a.closed || a.draining || a.peerGoAway.set || s.owner != o || !s.accepted || s.cancelled || s.coreCleaned || s.phase != openLive || s.carrier == nil {
		return false
	}
	q, f := o.queue, o.flow.receive
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed || q.sealed || q.cleaned || q.size != 0 || q.accepted != 0 || q.writeOwner != o || q.reservation.Check() != nil {
		return false
	}
	q.flow.mu.Lock()
	stopped := q.flow.reset.Load() || q.flow.stopping || q.flow.cleaned
	q.flow.mu.Unlock()
	if stopped {
		return false
	}
	f.pool.mu.Lock()
	defer f.pool.mu.Unlock()
	return !f.pool.closed && !f.cleaned && !f.abandoned && !f.hasTerminal && f.size == 0 && f.delivered == 0 && f.readOwner == o && f.reservation.Check() == nil
}

func (p *SessionCorePlan) checkPreaccepted(ctx context.Context, kind string, metadata []byte, contract [32]byte, workloads ...*unaryWorkload) error {
	if p == nil || p.engine == nil {
		return cryptov4.ErrNotReady
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	now, err := p.engine.Clock().Sample()
	if err != nil {
		return err
	}
	binding := preacceptedBinding(kind, metadata, contract)
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return cryptov4.ErrClosed
	}
	for _, entry := range p.preaccepted {
		if entry != nil && entry.matchesWorkload(workloads) {
			entry.mu.Lock()
			available := entry.availableAt(binding, now, false)
			entry.mu.Unlock()
			if available {
				return nil
			}
		}
	}
	return cryptov4.ErrNotReady
}

func (e *preacceptedStream) releaseClaim() {
	e.mu.Lock()
	e.claimed = false
	if !e.closed && !e.transferred {
		if ref, err := e.claimHold.TakeBorrow(); err == nil {
			e.claimReserve = ref
		} else {
			// Exhaustion or a closed original scope cannot create a fresh
			// checkout alias. Retire the same entry without replacement.
			e.closed = true
			e.claimHold.Release()
		}
	} else {
		e.claimHold.Release()
	}
	e.claimHold = resourcev4.Reference{}
	e.signalLocked()
	e.mu.Unlock()
}

func (e *preacceptedStream) transfer(ctx context.Context, m *StreamMessages, now timev4.Sample) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.availableAt(e.binding, now, true) {
		return cryptov4.ErrNotReady
	}
	owner := e.owner
	f := owner.flow.receive
	f.pool.mu.Lock()
	terminal, err := f.readStatusLocked()
	unused := f.size == 0 && f.delivered == 0 && terminal == protocolv4.V4ReadTerminalOpen
	f.pool.mu.Unlock()
	if err != nil || !unused || owner.accepted.Load() != 0 {
		e.closed = true
		e.signalLocked()
		return ErrStreamOwned
	}
	if err := m.bindMessageOwner(ctx, owner, true, false); err != nil {
		return err
	}
	e.owner, e.transferred = nil, true
	e.signalLocked()
	return nil
}

// ErrStreamOwned and expiry retire an unusable old entry; a pure capacity miss
// leaves it private and reusable. Neither outcome opens a replacement Stream.
func preacceptedStartMiss(err error) bool {
	return errors.Is(err, cryptov4.ErrNotReady) || errors.Is(err, ErrStreamOwned) || errors.Is(err, timev4.ErrExpired)
}

// Checkout is synchronous and never starts an OPEN. The private claim permits
// construction of the complete operation vector without consuming the entry.
// Only the final ownership transfer commits Start and starts its original task.
func (p *SessionCorePlan) beginPreacceptedMessages(ctx context.Context, kind string, metadata, payload []byte, contract *protocolv4.ServiceContract, config StreamMessagesConfig, reservation resourcev4.Reference, authorization *protocolv4.DeliveryAuthorization) (_ *StreamMessages, err error) {
	digest, err := contract.Digest()
	if err != nil {
		return nil, err
	}
	entry, err := p.claimPreaccepted(ctx, kind, metadata, digest, config.transportFloor)
	if err != nil {
		return nil, err
	}
	defer entry.releaseClaim()
	m, err := p.prepareMessages(contract, config, reservation, authorization, entry.allocation.identity)
	if err != nil {
		return nil, err
	}
	defer m.finishEnvironmentPreparation()
	committed := false
	defer func() {
		if !committed {
			m.mu.Lock()
			m.releasePositionLocked()
			m.closeLocked()
			m.mu.Unlock()
		}
	}()
	if err := m.prepareRequestLocked(payload); err != nil {
		return nil, err
	}
	if err := m.prepareStartDependencies(ctx, config.dependencies); err != nil {
		return nil, err
	}
	now, err := p.engine.Clock().Sample()
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	if p.closed || p.rpc == nil {
		p.mu.Unlock()
		return nil, cryptov4.ErrClosed
	}
	p.rpc.mu.Lock()
	parent := p.rpc.runtimeContext
	live := p.rpc.runtimeStarted && !p.rpc.closed && !p.rpc.retired && parent != nil
	p.rpc.mu.Unlock()
	if !live {
		p.mu.Unlock()
		return nil, cryptov4.ErrNotReady
	}
	work, cancel := context.WithCancel(parent)
	m.openingCancel = cancel
	err = entry.transfer(ctx, m, now)
	p.mu.Unlock()
	if err != nil {
		return nil, err
	}
	committed = true
	go m.runAcceptedPublication(work)
	return m, nil
}

func preacceptedStreamCharges(runtimeBytes uint64, kindBytes int) (charges [2]resourcev4.Vector, err error) {
	if runtimeBytes == 0 || kindBytes < 0 {
		return charges, cryptov4.ErrConfiguration
	}
	charges[0], err = (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(preacceptedStream{})) + uint64(unsafe.Sizeof(timev4.Deadline{})) + uint64(unsafe.Sizeof(timev4.Window{})) + uint64(unsafe.Sizeof(time.Timer{})) + uint64(kindBytes) + 512, resourcev4.Items: 4, resourcev4.Timers: 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: runtimeBytes})
	if err == nil {
		charges[1], err = rpcv4.ContractRouteCharge(runtimeBytes)
	}
	return
}

// Explicit/required preparation consumes a matching method's original floor.
// It does not multiply that method's transport target or borrow another method's
// reservation. A busy declared target reports capacity instead of adding one.
func (p *SessionCorePlan) preparePreacceptedStream(ctx context.Context, kind string, metadata []byte, contract [32]byte, workload *unaryWorkload) (*sessionStreamAllocation, *OpenAdmission, error) {
	if workload == nil {
		return p.prepareStream(ctx, len(kind)+len(metadata))
	}
	p.mu.Lock()
	if p.closed || p.rpc == nil {
		p.mu.Unlock()
		return nil, nil, cryptov4.ErrClosed
	}
	r := p.rpc
	r.mu.Lock()
	var floor *streamCallerFloor
	declared := false
	for _, slot := range r.workloadSlots {
		if slot == nil || slot.closed || slot.closing || slot.workload.closed || slot.workload.cleaned {
			continue
		}
		w := slot.workload
		if w != workload || w.stream == nil || w.stream.core != &p.core || w.admissionContract != contract || w.stream.kind != kind || !bytes.Equal(w.stream.metadata, metadata) {
			continue
		}
		declared = true
		if slot.transport.checkAvailableLocked() == nil {
			floor = slot.transport
			break
		}
	}
	r.mu.Unlock()
	p.mu.Unlock()
	if !declared || floor == nil {
		return nil, nil, cryptov4.ErrCapacity
	}
	return p.prepareStreamInvocation(ctx, len(kind)+len(metadata), nil, false, floor)
}

// Empty selector slices are read-only pool inspection. An explicit nil target
// denotes ordinary capacity; a workload can see only its own original floors.
func (e *preacceptedStream) matchesWorkload(workloads []*unaryWorkload) bool {
	if len(workloads) == 0 {
		return true
	}
	if len(workloads) != 1 {
		return false
	}
	if e.allocation.callerFloor == nil {
		return workloads[0] == nil
	}
	return e.allocation.callerFloor.workload == workloads[0]
}
