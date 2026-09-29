package sessionv4

import (
	"context"
	"crypto/sha256"
	"sync"
	"time"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// RelayMessagePairConfig reserves both opaque forwarding lanes before either
// hop claim. Native routes additionally reserve the complete mapping graph.
type RelayMessagePairConfig struct {
	MaxPendingNativeMappings, MaxResidentNativeMappings uint32
	MaxTotalNativeMappings                              uint64
	MaxDatagramBytes                                    uint32
	Clock                                               *timev4.Clock
	PreparationDeadline                                 *timev4.Deadline
	MaxEnvelopeBytes                                    uint32
	RuntimeBytes                                        uint64
}

type relayPairBinding struct {
	parent, route, identities, relay, contract [32]byte
	attempt, pairing                           [16]byte
	tenant, service, audience, source          string
}

// RelayMessagePair has exactly two original registration positions. A failed
// or retired registration never reopens either slot. It owns all forwarding
// work and charged buffers until both real provider tails have returned.
type RelayMessagePair struct {
	native                                               *relayNativePair
	mu                                                   sync.Mutex
	c                                                    RelayMessagePairConfig
	reservation, shared                                  resourcev4.Reference
	binding                                              relayPairBinding
	hops                                                 [2]*RelayHop
	registered                                           [2]bool
	references                                           uint8
	buffers                                              [2][]byte
	wake                                                 chan struct{}
	results                                              chan error
	cancel                                               context.CancelFunc
	started, running, closed, closing, cleaning, cleaned bool
}

func RelayMessagePairCharge(c RelayMessagePairConfig) (resourcev4.Vector, error) {
	if c.Clock == nil || !c.PreparationDeadline.BelongsTo(c.Clock) || c.MaxEnvelopeBytes < 9 || c.MaxEnvelopeBytes > protocolv4.MaxPayloadLength+protocolv4.EnvelopePrefixSize || c.RuntimeBytes == 0 {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	nativeCharge, err := relayNativeCharge(c)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	charge, err := (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(RelayMessagePair{})) + 2*uint64(c.MaxEnvelopeBytes) + 1024, resourcev4.Items: 3, resourcev4.WorkSlots: 3, resourcev4.Tasks: 3, resourcev4.Timers: 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: c.RuntimeBytes})
	if err != nil {
		return resourcev4.Vector{}, err
	}
	return charge.Add(nativeCharge)
}

func NewRelayMessagePair(c RelayMessagePairConfig, reservation, dependencies resourcev4.Reference) (*RelayMessagePair, error) {
	charge, err := RelayMessagePairCharge(c)
	if err != nil {
		return nil, err
	}
	if err = reservation.CheckSameEnvironment(dependencies); err != nil {
		return nil, err
	}
	if err = c.PreparationDeadline.Check(); err != nil {
		return nil, err
	}
	shared, err := dependencies.Borrow()
	if err != nil {
		return nil, err
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		shared.Release()
		return nil, err
	}
	p := &RelayMessagePair{c: c, reservation: owned, shared: shared, buffers: [2][]byte{make([]byte, c.MaxEnvelopeBytes), make([]byte, c.MaxEnvelopeBytes)}, wake: make(chan struct{}, 1), results: make(chan error, 2)}
	p.native = newRelayNativePair(p)
	return p, nil
}

func (p *RelayMessagePair) register(r *RelayHop) error {
	if p == nil || r == nil || r.c.Clock != p.c.Clock {
		return cryptov4.ErrConfiguration
	}
	if err := r.reservation.CheckSameEnvironment(p.reservation); err != nil {
		return err
	}
	if err := r.c.Initial.Deadline.TightenFrom(p.c.PreparationDeadline); err != nil {
		return err
	}
	grant := r.maps[0]
	limits := grant.Field("limits")
	envelope, _ := limits.Named("GrantLimits", "max_envelope_bytes").Uint()
	queue, _ := limits.Named("GrantLimits", "max_queue_bytes").Uint()
	items, _ := limits.Named("GrantLimits", "max_queue_items").Uint()
	if envelope != uint64(p.c.MaxEnvelopeBytes) || queue < 2*envelope || items < 2 {
		return cryptov4.ErrCapacity
	}
	if err := p.validateCarriers(r); err != nil {
		return err
	}
	read32 := func(name string) [32]byte { b, _ := grant.Field(name).ByteString(); return [32]byte(b) }
	read16 := func(name string) [16]byte { b, _ := grant.Field(name).ByteString(); return [16]byte(b) }
	tenant, _ := grant.Field("tenant_id").Text()
	service, _ := grant.Field("service").Text()
	audience, _ := grant.Field("audience").Text()
	binding := relayPairBinding{parent: sha256.Sum256(grant.Field("parent_ref").Encoded()), route: read32("route_digest"), identities: sha256.Sum256(grant.Field("identity_digests").Encoded()), relay: read32("relay_identity_digest"), contract: read32("session_contract_digest"), attempt: read16("attempt_id"), pairing: read16("pairing_id"), tenant: tenant, service: service, audience: audience, source: r.c.Initial.ActivationSourceProfile}
	side := int(r.prepared.binding.Role)
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.registered[side] || p.references != 0 && p.binding != binding {
		return resourcev4.ErrOwner
	}
	ref, err := p.reservation.Borrow()
	if err != nil {
		return err
	}
	if p.native != nil {
		if err = p.native.bind(r); err != nil {
			ref.Release()
			return err
		}
	}
	p.registered[side], p.hops[side], p.binding = true, r, binding
	p.references++
	r.pairRef, r.pairRegistered = ref, true
	p.notifyLocked()
	return nil
}

func (p *RelayMessagePair) notifyLocked() {
	select {
	case p.wake <- struct{}{}:
	default:
	}
}
func (p *RelayMessagePair) notify() {
	if p != nil {
		p.mu.Lock()
		p.notifyLocked()
		p.mu.Unlock()
	}
}

func (p *RelayMessagePair) release(r *RelayHop) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i, hop := range p.hops {
		if hop == r {
			p.hops[i] = nil
			p.references--
			break
		}
	}
	r.pairRef.Release()
	r.pairRef, r.pairRegistered = resourcev4.Reference{}, false
	p.cleanupLocked()
	p.notifyLocked()
}

func (p *RelayMessagePair) check() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return cryptov4.ErrClosed
	}
	if err := p.reservation.Check(); err != nil {
		return err
	}
	return p.shared.Check()
}

// Run has one original caller. It waits only for its two pre-registered HOP
// owners and never fetches an Artifact, starts a Session, or retries a claim.
func (p *RelayMessagePair) Run(ctx context.Context) (err error) {
	if p == nil || ctx == nil {
		return cryptov4.ErrConfiguration
	}
	p.mu.Lock()
	if p.started || p.closed {
		p.mu.Unlock()
		return cryptov4.ErrTransition
	}
	p.started, p.running = true, true
	local, cancel := context.WithCancel(context.Background())
	p.cancel = cancel
	p.mu.Unlock()
	returned := false
	defer func() {
		if recover() != nil || !returned {
			err = ErrEnvironmentTaskExit
		}
		p.Close()
		p.mu.Lock()
		p.running = false
		p.notifyLocked()
		p.cleanupLocked()
		p.mu.Unlock()
	}()
	err = p.run(ctx, local)
	returned = true
	return err
}

func (p *RelayMessagePair) run(parent, ctx context.Context) error {
	timer := time.NewTimer(time.Millisecond)
	defer timer.Stop()
	var hops [2]*RelayHop
	for {
		if err := parent.Err(); err != nil {
			return err
		}
		if err := p.check(); err != nil {
			return err
		}
		remaining, err := p.c.PreparationDeadline.RemainingMS()
		if err != nil {
			return err
		}
		p.mu.Lock()
		hops = p.hops
		p.mu.Unlock()
		ready := true
		for _, hop := range hops {
			if hop == nil {
				ready = false
				continue
			}
			hop.mu.Lock()
			authenticated, closed := hop.authenticated, hop.closed
			hop.mu.Unlock()
			if closed {
				return cryptov4.ErrClosed
			}
			ready = ready && authenticated
		}
		if ready {
			break
		}
		timer.Reset(idleTimerChunk(remaining))
		select {
		case <-p.wake:
		case <-parent.Done():
		case <-ctx.Done():
		case <-timer.C:
		}
		timer.Stop()
	}
	// Keep both hop owners out of retirement before touching either Initial.
	acquired := 0
	defer func() {
		for _, hop := range hops[:acquired] {
			hop.mu.Lock()
			hop.forwarding = false
			hop.mu.Unlock()
		}
	}()
	for _, hop := range hops {
		hop.mu.Lock()
		if hop.closed || hop.running || hop.forwarding || hop.building {
			hop.mu.Unlock()
			return cryptov4.ErrTransition
		}
		hop.forwarding = true
		acquired++
		hop.mu.Unlock()
	}
	if err := hops[0].ledger.MatchPeer(hops[1].ledger); err != nil {
		return err
	}
	for _, hop := range hops {
		if err := hop.guard.Check(); err != nil {
			return err
		}
		x := hop.initial
		x.mu.Lock()
		err := x.checkLocked()
		if err == nil && (x.hopPhase != 4 || x.authenticating || x.sending || x.receiving) {
			err = protocolv4.ErrHopAuthStage
		}
		if err == nil {
			x.transferred = true
		}
		x.mu.Unlock()
		if err != nil {
			return err
		}
		hop.guard.Notify()
		if err = x.WaitCleanup(parent); err != nil {
			return err
		}
	}
	// The original two work positions retain their buffers until both actual
	// forwarding loops exit, even if cancellation cannot promptly stop a host.
	active := 2
	if p.native != nil {
		active = 1
		go func() {
			var err error
			returned := false
			defer func() {
				if recover() != nil || !returned {
					err = ErrEnvironmentTaskExit
				}
				p.results <- err
			}()
			err = p.native.run(ctx, hops)
			returned = true
		}()
	} else {
		for direction := 0; direction < 2; direction++ {
			go p.forward(ctx, hops[direction], hops[1-direction], p.buffers[direction])
		}
	}
	defer func() {
		p.Close()
		for active > 0 {
			<-p.results
			active--
		}
	}()
	for {
		if err := p.check(); err != nil {
			return err
		}
		remaining := ^uint64(0)
		for _, hop := range hops {
			ms, err := hop.guard.RemainingMS()
			if err != nil {
				return err
			}
			remaining = min(remaining, ms)
		}
		timer.Reset(idleTimerChunk(remaining))
		select {
		case err := <-p.results:
			active--
			if err == nil {
				err = cryptov4.ErrClosed
			}
			return err
		case <-parent.Done():
			return parent.Err()
		case <-ctx.Done():
			return ctx.Err()
		case <-hops[0].guard.Wake():
		case <-hops[1].guard.Wake():
		case <-timer.C:
		}
		timer.Stop()
	}
}

func (p *RelayMessagePair) forward(ctx context.Context, from, to *RelayHop, buffer []byte) {
	err := error(nil)
	returned := false
	defer func() {
		if recover() != nil || !returned {
			err = ErrEnvironmentTaskExit
		}
		p.results <- err
	}()
	err = func() error {
		for {
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := from.guard.Check(); err != nil {
				return err
			}
			n, err := from.prepared.messageAdapter.ReadMessage(ctx, buffer)
			if err != nil {
				return err
			}
			if n < 0 || n > len(buffer) {
				return cryptov4.ErrConfiguration
			}
			if _, err = relayEnvelopeType(buffer[:n]); err != nil {
				return err
			}
			if err = to.guard.Check(); err != nil {
				return err
			}
			// The original envelope is forwarded byte-for-byte. The relay has
			// no key, does not inspect encrypted metadata and creates no ACK.
			if err = to.prepared.messageAdapter.WriteMessage(ctx, buffer[:n:n]); err != nil {
				return err
			}
		}
	}()
	returned = true
}

func (p *RelayMessagePair) Close() {
	if p == nil {
		return
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.closed, p.closing = true, true
	if p.cancel != nil {
		p.cancel()
	}
	hops := p.hops
	p.notifyLocked()
	p.mu.Unlock()
	if p.native != nil {
		p.native.close()
	}
	for _, hop := range hops {
		if hop != nil {
			hop.Close()
			hop.mu.Lock()
			carrier := hop.prepared
			hop.mu.Unlock()
			if carrier != nil {
				_ = carrier.closeProvider()
			}
		}
	}
	p.mu.Lock()
	p.closing = false
	p.notifyLocked()
	p.cleanupLocked()
	p.mu.Unlock()
}

func (p *RelayMessagePair) WaitCleanup(ctx context.Context) error {
	if p == nil || ctx == nil {
		return cryptov4.ErrConfiguration
	}
	p.mu.Lock()
	if p.cleaned {
		p.mu.Unlock()
		return nil
	}
	if !p.closed || p.running || p.closing || p.cleaning {
		p.mu.Unlock()
		return cryptov4.ErrCapacity
	}
	p.cleaning = true
	hops := p.hops
	p.mu.Unlock()
	defer func() { p.mu.Lock(); p.cleaning = false; p.cleanupLocked(); p.mu.Unlock() }()
	if err := p.native.waitCleanup(ctx); err != nil {
		return err
	}
	for _, hop := range hops {
		if hop == nil {
			continue
		}
		if err := hop.WaitCleanup(ctx); err != nil {
			return err
		}
		if err := hop.Retire(); err != nil {
			return err
		}
	}
	return nil
}

func (p *RelayMessagePair) cleanupLocked() {
	if !p.closed || p.running || p.closing || p.cleaning || p.references != 0 || p.cleaned {
		return
	}
	if p.native != nil {
		p.native.destroy()
	}
	for _, buffer := range p.buffers {
		clear(buffer)
	}
	p.buffers, p.binding = [2][]byte{}, relayPairBinding{}
	p.shared.Release()
	p.reservation.Release()
	p.cleaned = true
}
