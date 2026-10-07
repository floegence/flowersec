package controlv4

import (
	"bytes"
	"context"
	"math"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// PoolOwnerProofIssuerConfig supplies a signer for the key already fixed by the
// original source journal. The request never chooses a key, source or clock.
// RuntimeBytes covers the actual signer provider's bounded working backing.
type PoolOwnerProofIssuerConfig struct {
	Deployment               *PoolTunnelDeployment
	Signer                   protocolv4.MapSigner
	ValidityMS, RuntimeBytes uint64
}

// PoolOwnerProofIssuer has one admitted signing position. Closing it cancels
// authority for new work; its backing remains until the actual signer returns.
// It neither reconstructs journal history nor grants publication rights.
type PoolOwnerProofIssuer struct {
	mu                              sync.Mutex
	config                          PoolOwnerProofIssuerConfig
	source                          *PoolSourceAuthority
	service                         *PoolService
	clock                           *timev4.Clock
	key                             protocolv4.TopUpFenceAuthority
	codec                           *protocolv4.SignedMapCodec
	reservation, shared, deployment resourcev4.Reference
	done                            chan struct{}
	busy, closed, cleaned           bool
}

func PoolOwnerProofIssuerCharge(c PoolOwnerProofIssuerConfig) (resourcev4.Vector, error) {
	if c.Deployment == nil || c.Signer == nil || c.ValidityMS == 0 || c.ValidityMS > 60000 || c.RuntimeBytes == 0 {
		return resourcev4.Vector{}, resourcev4.ErrConfiguration
	}
	backing, err := protocolv4.SignedMapBackingBytes("OwnerFenceProof", 512, 64)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	return (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(PoolOwnerProofIssuer{})) + backing + 16384, resourcev4.Items: 1, resourcev4.WorkSlots: 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: c.RuntimeBytes})
}

func NewPoolOwnerProofIssuer(c PoolOwnerProofIssuerConfig, reservation, dependencies resourcev4.Reference) (_ *PoolOwnerProofIssuer, err error) {
	charge, err := PoolOwnerProofIssuerCharge(c)
	if err != nil {
		return nil, err
	}
	if err = reservation.CheckSameEnvironment(dependencies); err != nil {
		return nil, err
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		return nil, err
	}
	p := &PoolOwnerProofIssuer{config: c, reservation: owned, done: make(chan struct{})}
	success := false
	defer func() {
		if !success {
			p.Close()
		}
	}()
	p.shared, err = dependencies.Borrow()
	if err != nil {
		return nil, err
	}
	d := c.Deployment
	d.mu.Lock()
	if d.closed || d.source == nil || d.journal == nil || d.clock == nil {
		d.mu.Unlock()
		return nil, resourcev4.ErrClosed
	}
	if err = d.reservation.CheckSameEnvironment(dependencies); err != nil {
		d.mu.Unlock()
		return nil, err
	}
	p.deployment, err = d.reservation.Borrow()
	p.source, p.clock, p.key = d.source, d.clock, d.fenceKey
	if err == nil {
		p.service, err = d.authority.Service()
	}
	d.mu.Unlock()
	if err != nil {
		return nil, err
	}
	public := c.Signer.PublicKey()
	if len(public) != 32 || !bytes.Equal(public, p.key.PublicKey[:]) || p.key.KeyID == ([16]byte{}) {
		return nil, resourcev4.ErrOwner
	}
	p.codec, err = protocolv4.NewSignedMapCodec("OwnerFenceProof", 512, 64)
	if err != nil {
		return nil, err
	}
	success = true
	return p, nil
}

func (p *PoolOwnerProofIssuer) controlReferenceFor(tenant string, source [16]byte, clock *timev4.Clock, service *PoolService, environment resourcev4.Reference) (resourcev4.Reference, error) {
	if p == nil {
		return resourcev4.Reference{}, resourcev4.ErrConfiguration
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.source == nil || p.clock != clock || p.service != service {
		return resourcev4.Reference{}, resourcev4.ErrOwner
	}
	p.source.mu.Lock()
	matched := p.source.tenant == tenant && p.source.source == source
	p.source.mu.Unlock()
	if !matched {
		return resourcev4.Reference{}, resourcev4.ErrOwner
	}
	if err := p.reservation.CheckSameEnvironment(environment); err != nil {
		return resourcev4.Reference{}, err
	}
	return p.reservation.Borrow()
}

// Issue verifies the full canonical immutable intent, authenticates the original
// source access and holds the independent current fence through actual signing.
// Releasing that permit before HTTP delivery permits immediate TopUp without
// an artificial overlap. A subsequent owner change makes the proof stale; the
// journal still pins its own current permit at the real durable transaction.
// Proof lifetime does not inherit the immutable append deadline: current-owner
// response recovery and ACK remain possible after that deadline has passed.
func (p *PoolOwnerProofIssuer) Issue(ctx context.Context, access ledgerv4.TopUpAccess, request protocolv4.TopUpRequestFacts, dst []byte) (int, error) {
	if p == nil || ctx == nil || access == nil || len(dst) < 512 {
		return 0, resourcev4.ErrConfiguration
	}
	if !p.mu.TryLock() {
		return 0, ErrBusy
	}
	if p.closed || p.busy {
		p.mu.Unlock()
		return 0, ErrBusy
	}
	p.busy = true
	c, source, clock, key, codec := p.config, p.source, p.clock, p.key, p.codec
	p.mu.Unlock()
	defer func() { p.mu.Lock(); defer p.mu.Unlock(); p.busy = false; p.cleanupLocked() }()
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if err := access.CheckTopUpAccess(request.Tenant, request.Source); err != nil {
		return 0, err
	}
	permit, fence, err := source.acquireOwnerProof(request)
	if err != nil {
		return 0, err
	}
	defer permit.Release()
	now, err := clock.Sample()
	if err != nil {
		return 0, err
	}
	if now.LowerMS > math.MaxUint64-c.ValidityMS {
		return 0, timev4.ErrExpired
	}
	expires := min(now.LowerMS+c.ValidityMS, fence.LeaseUntilMS)
	if !now.ValidBefore(expires) {
		return 0, timev4.ErrExpired
	}
	guard := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			return resourcev4.ErrClosed
		}
		refs := [3]resourcev4.Reference{p.reservation, p.shared, p.deployment}
		p.mu.Unlock()
		for _, ref := range refs {
			if err := ref.Check(); err != nil {
				return err
			}
		}
		if err := access.CheckTopUpAccess(request.Tenant, request.Source); err != nil {
			return err
		}
		if err := permit.Check(); err != nil {
			return err
		}
		sample, err := clock.Sample()
		if err != nil {
			return err
		}
		if !sample.BelongsTo(clock) || !sample.Mark.SameEra(now.Mark) || sample.LowerMS < now.LowerMS || !sample.ValidBefore(expires) {
			return timev4.ErrExpired
		}
		return nil
	}
	fields := [8]protocolv4.Field{
		{Name: "tenant_id", Kind: protocolv4.TextString, Text: request.Tenant},
		{Name: "source_incarnation", Kind: protocolv4.ByteString, Bytes: request.Source[:]},
		{Name: "operation_id", Kind: protocolv4.ByteString, Bytes: request.Operation[:]},
		{Name: "request_digest", Kind: protocolv4.ByteString, Bytes: request.Digest[:]},
		{Name: "current_generation", Number: request.Generation},
		{Name: "issued_at_ms", Number: now.LowerMS},
		{Name: "expires_at_ms", Number: expires},
		{Name: "authority_key_id", Kind: protocolv4.ByteString, Bytes: key.KeyID[:]},
	}
	signed, err := codec.SignWith(fields[:], key.PublicKey, c.Signer, protocolv4.DecodeContext{}, guard)
	if err != nil {
		return 0, err
	}
	defer signed.Release()
	wire, err := signed.Bytes()
	if err != nil {
		return 0, err
	}
	if len(wire) == 0 || len(wire) > 512 {
		return 0, resourcev4.ErrCapacity
	}
	if err = guard(); err != nil {
		return 0, err
	}
	return copy(dst, wire), nil
}

func (p *PoolOwnerProofIssuer) Close() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	p.cleanupLocked()
}
func (p *PoolOwnerProofIssuer) cleanupLocked() {
	if !p.closed || p.busy || p.cleaned {
		return
	}
	p.config = PoolOwnerProofIssuerConfig{}
	p.source, p.clock, p.codec = nil, nil, nil
	p.service = nil
	p.key = protocolv4.TopUpFenceAuthority{}
	p.deployment.Release()
	p.shared.Release()
	p.reservation.Release()
	p.deployment, p.shared, p.reservation = resourcev4.Reference{}, resourcev4.Reference{}, resourcev4.Reference{}
	p.cleaned = true
	close(p.done)
}
func (p *PoolOwnerProofIssuer) WaitCleanup(ctx context.Context) error {
	if p == nil || ctx == nil {
		return resourcev4.ErrConfiguration
	}
	select {
	case <-p.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (*PoolOwnerProofIssuer) String() string   { return "Flowersec.PoolOwnerProofIssuer" }
func (*PoolOwnerProofIssuer) GoString() string { return "Flowersec.PoolOwnerProofIssuer" }
func (*PoolOwnerProofIssuer) MarshalJSON() ([]byte, error) {
	return []byte(`"Flowersec.PoolOwnerProofIssuer"`), nil
}
