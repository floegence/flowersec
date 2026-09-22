package sessionv4

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

const serviceStreamQuantum = uint64(16 * 1024)
const maxPreacceptedStreams = 8

// Each entry is one actual business Stream in this same Session, never a free
// channel, alternate admission policy or replacement for a retired generation.
// Its original Stream factory task stays charged until transfer or real cleanup.
type preacceptedStream struct {
	mu                           sync.Mutex
	plan                         *SessionCorePlan
	allocation                   *sessionStreamAllocation
	admission                    *OpenAdmission
	owner                        *StreamOwnership
	route                        rpcv4.ContractRoute
	reservation, claimHold       resourcev4.Reference
	deadline                     *timev4.Deadline
	context                      context.Context
	cancel                       context.CancelFunc
	changed                      chan struct{}
	binding                      [32]byte
	kind                         string
	metadata                     [4096]byte
	metadataBytes, index         int
	claimed, closed, transferred bool
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
	allocation, admission, err := p.prepareStream(ctx, len(kind)+len(metadata))
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
	var charges [2]resourcev4.Vector
	charges[0], err = (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(preacceptedStream{})) + uint64(unsafe.Sizeof(timev4.Deadline{})) + uint64(unsafe.Sizeof(time.Timer{})) + uint64(len(kind)) + 512, resourcev4.Items: 3, resourcev4.Timers: 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: p.config.Streams.RuntimeBytes})
	if err == nil {
		charges[1], err = rpcv4.ContractRouteCharge(p.config.Streams.RuntimeBytes)
	}
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
	if err := p.root.ReserveBatch(requests[:], refs[:]); err != nil {
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
	fixed, err := deadline.Fork(deadline.Cap())
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	work, cancel := context.WithCancel(parent)
	entry := &preacceptedStream{plan: p, allocation: allocation, admission: admission, route: route, reservation: refs[0], deadline: fixed, context: work, cancel: cancel, changed: make(chan struct{}, 1), index: index, kind: strings.Clone(kind), binding: preacceptedBinding(kind, metadata, contract)}
	entry.metadataBytes = copy(entry.metadata[:], metadata)
	p.preaccepted[index] = entry
	committed = true
	go entry.run()
	return nil
}

func serviceStreamGeometry(c SessionStreamConfig) bool {
	return c.ReceiveBytes >= serviceStreamQuantum && c.InitialReceiveLimit >= serviceStreamQuantum && c.QueueBytes >= serviceStreamQuantum
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
		e.reservation.Release()
		p := e.plan
		p.mu.Lock()
		if p.preaccepted[e.index] == e {
			p.preaccepted[e.index] = nil
			p.notifyLocked()
		}
		p.mu.Unlock()
		p.finishStream(e.allocation)
	}()
	a, allocation := e.admission, e.allocation
	h, _, err := a.OpenLocal(e.context, BusinessStream, e.kind, e.metadata[:e.metadataBytes], &CarrierAssociation{shared: a.sharedIngress}, allocation.reservation, e.deadline)
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
	e.mu.Lock()
	e.owner = owner
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
		e.mu.Lock()
		if e.transferred && !e.claimed {
			e.mu.Unlock()
			return
		}
		remaining, lifetimeErr := e.deadline.RemainingMS()
		if lifetimeErr == nil && e.owner != nil {
			lifetimeErr = e.owner.checkLifetime()
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
func (p *SessionCorePlan) claimPreaccepted(ctx context.Context, kind string, metadata []byte, contract [32]byte) (*preacceptedStream, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	binding := preacceptedBinding(kind, metadata, contract)
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil, cryptov4.ErrClosed
	}
	for _, entry := range p.preaccepted {
		if entry == nil {
			continue
		}
		entry.mu.Lock()
		available := !entry.closed && !entry.claimed && !entry.transferred && entry.owner != nil && entry.binding == binding
		if available {
			if err := entry.owner.checkLifetime(); err == nil {
				hold, err := entry.reservation.Borrow()
				if err != nil {
					entry.mu.Unlock()
					return nil, err
				}
				entry.claimHold, entry.claimed = hold, true
				entry.mu.Unlock()
				return entry, nil
			}
		}
		entry.mu.Unlock()
	}
	return nil, cryptov4.ErrNotReady
}

func (e *preacceptedStream) releaseClaim() {
	e.mu.Lock()
	e.claimed = false
	e.claimHold.Release()
	e.claimHold = resourcev4.Reference{}
	e.signalLocked()
	e.mu.Unlock()
}

func (e *preacceptedStream) transfer(ctx context.Context, m *StreamMessages) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || !e.claimed || e.transferred || e.owner == nil {
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
	entry, err := p.claimPreaccepted(ctx, kind, metadata, digest)
	if err != nil {
		return nil, err
	}
	defer entry.releaseClaim()
	m, err := p.prepareMessages(contract, config, reservation, authorization, entry.allocation.identity)
	if err != nil {
		return nil, err
	}
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
	err = entry.transfer(ctx, m)
	p.mu.Unlock()
	if err != nil {
		return nil, err
	}
	committed = true
	go m.runAcceptedPublication(work)
	return m, nil
}
