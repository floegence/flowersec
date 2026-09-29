package controlv4

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"math"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// PoolIssuancePolicy checks the authenticated original source operation and
// current independent authorization. It is bounded local host work; it cannot
// authorize publication, overwrite an outbox or restore a consumer dispatch.
type PoolIssuancePolicy interface {
	CheckPoolIssuance(context.Context, ledgerv4.TopUpServerSnapshot) error
}

type PoolTunnelIssueConfig struct {
	Grants           [2]LiveArtifactGrantConfig
	RelayCertificate []byte
	RelayTrust       *protocolv4.NamespaceTrustStore
}

// The Artifact issuer has its own durable issuance obligation authority. Its
// trusted authentication is installed here, never taken from TopUp input.
// Issued material remains private until PoolService commits the whole outbox.
type PoolBatchSigningConfig struct {
	Clock                                                   *timev4.Clock
	ArtifactIssuer                                          *protocolv4.ArtifactIssuer
	ArtifactAuthentication                                  []byte
	Policy                                                  PoolIssuancePolicy
	Tenant, Audience, CryptoProfile, ActivationSigningKeyID string
	Source, ArtifactIssuerID                                [16]byte
	Pool                                                    [32]byte
	Trust                                                   [3]*protocolv4.NamespaceTrustStore
	ClientCertificate, ServerCertificate                    []byte
	Signer                                                  protocolv4.MapSigner
	Indices                                                 []uint64
	Budget                                                  protocolv4.PoolAttemptLimits
	Tunnels                                                 [16]*PoolTunnelIssueConfig
	Root                                                    *resourcev4.Root
	Owner                                                   resourcev4.OwnerKey
	Accounts                                                []resourcev4.Account
	WorkMS, RuntimeBytes                                    uint64
}

type PoolBatchSigningIssuer struct {
	mu                             sync.Mutex
	config                         PoolBatchSigningConfig
	reservation, shared, issuerRef resourcev4.Reference
	trust                          [19]resourcev4.Reference
	grantRefs                      [16][2]resourcev4.Reference
	endpoints                      [2]*protocolv4.SignedMap
	credentials                    [2]*protocolv4.Credential
	relays                         [16]*protocolv4.SignedMap
	indices                        [16]uint64
	accounts                       [8]resourcev4.Account
	planCharge                     resourcev4.Vector
	codec                          *protocolv4.TopUpCodec
	artifactCodec                  *protocolv4.SignedMapCodec
	artifact, proof                []byte
	grants                         [16][2][]byte
	materials                      [4][]byte
	delegation, once               [8192]byte
	serial                         uint64
	cancel                         context.CancelFunc
	done                           chan struct{}
	busy, closed, cleaned          bool
}

func PoolBatchSigningIssuerCharge(c PoolBatchSigningConfig) (resourcev4.Vector, error) {
	if c.Clock == nil || c.ArtifactIssuer == nil || c.Policy == nil || c.Signer == nil || c.Root == nil || len(c.Accounts) > 8 || c.Source == ([16]byte{}) || c.ArtifactIssuerID == ([16]byte{}) || c.Pool == ([32]byte{}) || c.WorkMS == 0 || c.WorkMS > 90000 || c.RuntimeBytes == 0 || len(c.ArtifactAuthentication) == 0 || len(c.ArtifactAuthentication) > 16384 || len(c.Indices) == 0 || len(c.Indices) > 16 {
		return resourcev4.Vector{}, resourcev4.ErrConfiguration
	}
	for _, s := range []string{c.Tenant, c.Audience, c.CryptoProfile, c.ActivationSigningKeyID} {
		if len(s) == 0 || len(s) > 128 {
			return resourcev4.Vector{}, resourcev4.ErrConfiguration
		}
	}
	for _, t := range c.Trust {
		if t == nil {
			return resourcev4.Vector{}, resourcev4.ErrConfiguration
		}
	}
	for _, cert := range [][]byte{c.ClientCertificate, c.ServerCertificate} {
		if len(cert) == 0 || len(cert) > 8192 {
			return resourcev4.Vector{}, resourcev4.ErrConfiguration
		}
	}
	for i, index := range c.Indices {
		if index >= 16 || i > 0 && c.Indices[i-1] >= index {
			return resourcev4.Vector{}, resourcev4.ErrConfiguration
		}
	}
	artifact, err := protocolv4.SignedMapBackingBytes("Artifact", 65536, 16384)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	cert, err := protocolv4.SignedMapBackingBytes("IdentityCertificate", 8192, 4096)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	credential, err := protocolv4.CredentialBackingBytes("IdentityCertificate")
	if err != nil {
		return resourcev4.Vector{}, err
	}
	codec, err := protocolv4.TopUpCodecBackingBytes()
	if err != nil {
		return resourcev4.Vector{}, err
	}
	grantLimit, err := protocolv4.SchemaByteLimit("Grant")
	if err != nil {
		return resourcev4.Vector{}, err
	}
	n := uint64(unsafe.Sizeof(PoolBatchSigningIssuer{})) + artifact + 2*(cert+credential) + codec + 5*65536 + 4096 + 16384 + 4096
	for i, t := range c.Tunnels {
		if t == nil {
			continue
		}
		found := false
		for _, index := range c.Indices {
			found = found || index == uint64(i)
		}
		if !found || t.RelayTrust == nil || len(t.RelayCertificate) == 0 || len(t.RelayCertificate) > 8192 {
			return resourcev4.Vector{}, resourcev4.ErrConfiguration
		}
		for _, g := range t.Grants {
			if g.Signer == nil || g.Validation.Namespace == nil || g.Validation.Policy == nil || g.Validation.Issuer.Schema != "Grant" || len(g.Service) == 0 || len(g.Service) > 128 || len(g.Audience) == 0 || len(g.Audience) > 128 {
				return resourcev4.Vector{}, resourcev4.ErrConfiguration
			}
		}
		n += cert + credential + 2*uint64(grantLimit) + uint64(unsafe.Sizeof(PoolTunnelIssueConfig{})) + 4096
	}
	return (resourcev4.Vector{resourcev4.SDKBytes: n, resourcev4.Items: 1, resourcev4.WorkSlots: 1, resourcev4.Tasks: 1, resourcev4.Timers: 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: c.RuntimeBytes})
}

func NewPoolBatchSigningIssuer(c PoolBatchSigningConfig, reservation, dependencies resourcev4.Reference) (_ *PoolBatchSigningIssuer, err error) {
	cost, err := PoolBatchSigningIssuerCharge(c)
	if err != nil {
		return nil, err
	}
	if err = reservation.CheckAllocationScope(c.Root, c.Owner, c.Accounts); err != nil {
		return nil, err
	}
	if err = reservation.CheckSameEnvironment(dependencies); err != nil {
		return nil, err
	}
	owned, err := reservation.Take(cost)
	if err != nil {
		return nil, err
	}
	p := &PoolBatchSigningIssuer{config: c, reservation: owned, done: make(chan struct{})}
	defer func() {
		if err != nil {
			p.Close()
		}
	}()
	p.shared, err = dependencies.Borrow()
	if err != nil {
		return nil, err
	}
	p.issuerRef, err = c.ArtifactIssuer.ReferenceFor(c.Clock, dependencies)
	if err != nil {
		return nil, err
	}
	p.config.ArtifactAuthentication = bytes.Clone(c.ArtifactAuthentication)
	p.config.Tenant = strings.Clone(c.Tenant)
	p.config.Audience = strings.Clone(c.Audience)
	p.config.CryptoProfile = strings.Clone(c.CryptoProfile)
	p.config.ActivationSigningKeyID = strings.Clone(c.ActivationSigningKeyID)
	p.config.ClientCertificate, p.config.ServerCertificate = nil, nil
	p.config.Tunnels = [16]*PoolTunnelIssueConfig{}
	n := copy(p.indices[:], c.Indices)
	p.config.Indices = p.indices[:n:n]
	n = copy(p.accounts[:], c.Accounts)
	p.config.Accounts = p.accounts[:n:n]
	for i, t := range c.Trust {
		p.trust[i], err = t.ReferenceFor(c.Clock, dependencies)
		if err != nil {
			return nil, err
		}
	}
	for i, wire := range [][]byte{c.ClientCertificate, c.ServerCertificate} {
		p.endpoints[i], err = liveArtifactCertificate(wire, c.Trust[i+1])
		if err != nil {
			return nil, err
		}
		p.credentials[i], err = p.endpoints[i].DetachCredential()
		if err != nil {
			return nil, err
		}
		scope := p.credentials[i].Scope()
		if scope.Tenant != c.Tenant || scope.Audience != c.Audience || scope.Profile != c.CryptoProfile || scope.Role != uint64(i) {
			return nil, resourcev4.ErrConfiguration
		}
	}
	if p.credentials[0].Facts().Digest == p.credentials[1].Facts().Digest {
		return nil, resourcev4.ErrConfiguration
	}
	grantLimit, _ := protocolv4.SchemaByteLimit("Grant")
	count := uint8(0)
	for i, t := range c.Tunnels {
		if t == nil {
			continue
		}
		count++
		cloned := *t
		cloned.RelayCertificate = nil
		p.config.Tunnels[i] = &cloned
		p.trust[3+i], err = t.RelayTrust.ReferenceFor(c.Clock, dependencies)
		if err != nil {
			return nil, err
		}
		p.relays[i], err = liveArtifactCertificate(t.RelayCertificate, t.RelayTrust)
		if err != nil {
			return nil, err
		}
		for side := range cloned.Grants {
			g := &cloned.Grants[side]
			g.Service = strings.Clone(g.Service)
			g.Audience = strings.Clone(g.Audience)
			g.Validation.Issuer.Schema = strings.Clone(g.Validation.Issuer.Schema)
			if !bytes.Equal(g.Signer.PublicKey(), g.Validation.Issuer.Key[:]) {
				return nil, resourcev4.ErrConfiguration
			}
			p.grantRefs[i][side], err = g.Validation.Namespace.PreparationReferenceFor(c.Clock, dependencies)
			if err != nil {
				return nil, err
			}
			p.grants[i][side] = make([]byte, grantLimit)
		}
	}
	p.planCharge, err = protocolv4.PoolActivationPlanCapacity(count)
	if err != nil {
		return nil, err
	}
	p.codec, err = protocolv4.NewTopUpCodec()
	if err != nil {
		return nil, err
	}
	p.artifactCodec, err = protocolv4.NewSignedMapCodec("Artifact", 65536, 16384)
	if err != nil {
		return nil, err
	}
	p.artifact = make([]byte, 65536)
	p.proof = make([]byte, 4096)
	for i := range p.materials {
		p.materials[i] = make([]byte, 65536)
	}
	return p, nil
}

func (p *PoolBatchSigningIssuer) check(ctx context.Context, window *timev4.Window, original ledgerv4.TopUpServerSnapshot) error {
	p.mu.Lock()
	closed := p.closed
	p.mu.Unlock()
	if closed {
		return resourcev4.ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, r := range []resourcev4.Reference{p.reservation, p.shared, p.issuerRef} {
		if err := r.Check(); err != nil {
			return err
		}
	}
	for _, r := range p.trust {
		if r != (resourcev4.Reference{}) {
			if err := r.Check(); err != nil {
				return err
			}
		}
	}
	for _, pair := range p.grantRefs {
		for _, r := range pair {
			if r != (resourcev4.Reference{}) {
				if err := r.Check(); err != nil {
					return err
				}
			}
		}
	}
	if err := window.Check(); err != nil {
		return err
	}
	now, err := p.config.Clock.Sample()
	if err != nil {
		return err
	}
	if !now.ValidBefore(original.Request.DeadlineMS) {
		return timev4.ErrExpired
	}
	return p.config.Policy.CheckPoolIssuance(ctx, original)
}

func (p *PoolBatchSigningIssuer) IssuePoolBatch(ctx context.Context, original ledgerv4.TopUpServerSnapshot, dst []byte) (result PoolIssueResult, err error) {
	if p == nil || ctx == nil || len(dst) < 524288 {
		return result, resourcev4.ErrConfiguration
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return result, resourcev4.ErrClosed
	}
	if p.busy {
		p.mu.Unlock()
		return result, ErrBusy
	}
	c := p.config
	q := original.Request
	if original.State != ledgerv4.TopUpServerPending || original.Permanent || q.Tenant != c.Tenant || q.Source != c.Source || q.Pool != c.Pool || q.Identity != p.credentials[0].Facts().Digest || q.DesiredCount < 1 || q.DesiredCount > 4 || original.HighestArtifact > math.MaxUint64-uint64(q.DesiredCount) || p.serial > math.MaxUint64-uint64(q.DesiredCount) {
		p.mu.Unlock()
		return result, ledgerv4.ErrOwner
	}
	call, cancel := context.WithTimeout(ctx, time.Duration(c.WorkMS)*time.Millisecond)
	p.cancel = cancel
	p.busy = true
	p.mu.Unlock()
	success := false
	defer func() {
		cancel()
		if !success {
			clear(dst[:524288])
			result = PoolIssueResult{}
		}
		p.mu.Lock()
		p.clearScratch()
		p.cancel = nil
		p.busy = false
		p.cleanupLocked()
		p.mu.Unlock()
	}()
	window, err := timev4.NewWindow(c.Clock, c.WorkMS)
	if err != nil {
		return result, err
	}
	guard := func() error { return p.check(call, window, original) }
	if err = guard(); err != nil {
		return result, err
	}
	// All plan positions are admitted before the first Artifact is signed.
	var refs [4]resourcev4.Reference
	defer func() {
		for _, r := range refs {
			r.Release()
		}
	}()
	for i := uint32(0); i < q.DesiredCount; i++ {
		p.serial++
		var seed [56]byte
		copy(seed[:16], "pool-signing-1")
		copy(seed[16:32], c.Owner.Instance[:])
		copy(seed[32:48], c.Owner.Backing[:])
		binary.BigEndian.PutUint64(seed[48:], p.serial)
		h := sha256.Sum256(seed[:])
		owner := c.Owner
		copy(owner.Instance[:], h[:16])
		copy(owner.Backing[:], h[16:])
		refs[i], err = c.Root.Reserve(owner, p.planCharge, c.Accounts...)
		if err != nil {
			return result, err
		}
	}
	var items [4]protocolv4.TopUpIssueEntry
	for i := uint32(0); i < q.DesiredCount; i++ {
		if err = guard(); err != nil {
			return result, err
		}
		var request [104]byte
		copy(request[:24], "flowersec/pool-issue/v1")
		copy(request[24:56], q.Digest[:])
		copy(request[56:72], q.Source[:])
		copy(request[72:88], q.Operation[:])
		binary.BigEndian.PutUint64(request[88:96], original.HighestArtifact+1+uint64(i))
		binary.BigEndian.PutUint64(request[96:], q.Generation)
		id := sha256.Sum256(request[:])
		n, e := c.ArtifactIssuer.IssueArtifactBytes(call, protocolv4.ArtifactIssueRequest{RequestID: id, Authentication: c.ArtifactAuthentication}, p.artifact)
		if e != nil {
			return result, e
		}
		items[i], err = p.issueMaterial(p.artifact[:n], p.materials[i], refs[i], q, guard)
		clear(p.artifact)
		if err != nil {
			return result, err
		}
	}
	if err = guard(); err != nil {
		return result, err
	}
	result.ResponseBytes, err = p.codec.EncodeResponse(dst, q, original.HighestArtifact+1, false, 0, items[:q.DesiredCount])
	if err != nil {
		return result, err
	}
	if err = guard(); err != nil {
		return result, err
	}
	success = true
	return result, nil
}

func (p *PoolBatchSigningIssuer) clearScratch() {
	clear(p.artifact)
	clear(p.proof)
	for _, pair := range p.grants {
		for _, b := range pair {
			clear(b)
		}
	}
	for _, b := range p.materials {
		clear(b)
	}
	clear(p.delegation[:])
	clear(p.once[:])
}
func (p *PoolBatchSigningIssuer) Close() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	if p.cancel != nil {
		p.cancel()
	}
	p.cleanupLocked()
}
func (p *PoolBatchSigningIssuer) cleanupLocked() {
	if !p.closed || p.busy || p.cleaned {
		return
	}
	p.clearScratch()
	clear(p.config.ArtifactAuthentication)
	for _, m := range p.endpoints {
		if m != nil {
			m.Release()
		}
	}
	for _, m := range p.relays {
		if m != nil {
			m.Release()
		}
	}
	for _, r := range p.trust {
		r.Release()
	}
	for _, pair := range p.grantRefs {
		for _, r := range pair {
			r.Release()
		}
	}
	p.trust = [19]resourcev4.Reference{}
	p.grantRefs = [16][2]resourcev4.Reference{}
	p.endpoints = [2]*protocolv4.SignedMap{}
	p.credentials = [2]*protocolv4.Credential{}
	p.relays = [16]*protocolv4.SignedMap{}
	p.codec = nil
	p.artifactCodec = nil
	p.artifact = nil
	p.proof = nil
	p.grants = [16][2][]byte{}
	p.materials = [4][]byte{}
	clear(p.indices[:])
	clear(p.accounts[:])
	p.config = PoolBatchSigningConfig{}
	p.issuerRef.Release()
	p.shared.Release()
	p.reservation.Release()
	p.issuerRef, p.shared, p.reservation = resourcev4.Reference{}, resourcev4.Reference{}, resourcev4.Reference{}
	p.cleaned = true
	close(p.done)
}
func (p *PoolBatchSigningIssuer) WaitCleanup(ctx context.Context) error {
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
func (*PoolBatchSigningIssuer) String() string   { return "Flowersec.PoolBatchSigningIssuer" }
func (*PoolBatchSigningIssuer) GoString() string { return "Flowersec.PoolBatchSigningIssuer" }
func (*PoolBatchSigningIssuer) MarshalJSON() ([]byte, error) {
	return []byte(`"Flowersec.PoolBatchSigningIssuer"`), nil
}

var _ PoolBatchIssuer = (*PoolBatchSigningIssuer)(nil)
