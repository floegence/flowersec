package controlv4

import (
	"context"
	"strings"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// PoolBatchVerificationConfig fixes the complete credential and route trust
// graph independently of a source journal or publication destination.
// Construction retains these original owners before either store is opened.
type PoolBatchVerificationConfig struct {
	Clock                                *timev4.Clock
	Tenant, Audience, CryptoProfile      string
	SourceIncarnation, ArtifactIssuer    [16]byte
	Pool, ClientIdentity, ServerIdentity [32]byte
	ActivationSigningKeyID               string
	Trust                                [3]*protocolv4.NamespaceTrustStore
	Routes                               [16]*PoolRelayRouteConfig
	Root                                 *resourcev4.Root
	Owner                                resourcev4.OwnerKey
	Accounts                             []resourcev4.Account
	RuntimeBytes                         uint64
}

type poolBatchVerifier struct {
	mu                                sync.Mutex
	config                            PoolBatchVerificationConfig
	reservation, shared, dependencies resourcev4.Reference
	trust                             [51]resourcev4.Reference
	accounts                          [8]resourcev4.Account
	codec                             *protocolv4.TopUpCodec
	material                          *protocolv4.Decoder
	maps                              [7]*protocolv4.SignedMapCodec
	selection                         *protocolv4.PoolSelectionWorkspace
	parents                           [64]ledgerv4.SQLitePoolRelayParent
	delegation, once                  [8192]byte
	serial                            uint64
	done                              chan struct{}
	busy, closed, cleaned             bool
}

var poolRelayMapSchemas = [7]string{"Artifact", "ActivationAuthorization", "IdentityCertificate", "IdentityCertificate", "Grant", "Grant", "IdentityCertificate"}

func poolBatchVerifierCharge(c PoolBatchVerificationConfig) (resourcev4.Vector, error) {
	if c.Clock == nil || c.Root == nil || len(c.Accounts) > 8 || c.RuntimeBytes == 0 || c.SourceIncarnation == ([16]byte{}) || c.ArtifactIssuer == ([16]byte{}) || c.Pool == ([32]byte{}) || c.ClientIdentity == ([32]byte{}) || c.ServerIdentity == ([32]byte{}) || c.ClientIdentity == c.ServerIdentity {
		return resourcev4.Vector{}, resourcev4.ErrConfiguration
	}
	for _, s := range []string{c.Tenant, c.Audience, c.CryptoProfile, c.ActivationSigningKeyID} {
		if len(s) == 0 || len(s) > 128 {
			return resourcev4.Vector{}, resourcev4.ErrConfiguration
		}
	}
	for _, trust := range c.Trust {
		if trust == nil {
			return resourcev4.Vector{}, resourcev4.ErrConfiguration
		}
	}
	for _, r := range c.Routes {
		if r == nil {
			continue
		}
		if r.Grants[0] == nil || r.Grants[1] == nil || r.RelayTrust == nil || r.Mapping.Parent.Tenant != c.Tenant || r.Mapping.ParentIssuer != c.ArtifactIssuer || r.Mapping.EndpointAudience != c.Audience || r.Mapping.Profile != c.CryptoProfile || r.Mapping.Activation.SigningKeyID != c.ActivationSigningKeyID {
			return resourcev4.Vector{}, resourcev4.ErrConfiguration
		}
		for _, s := range poolRelayMappingStrings(&r.Mapping) {
			if len(*s) == 0 || len(*s) > 128 {
				return resourcev4.Vector{}, resourcev4.ErrConfiguration
			}
		}
	}
	n, err := protocolv4.TopUpCodecBackingBytes()
	if err != nil {
		return resourcev4.Vector{}, err
	}
	d, err := protocolv4.DecoderBackingBytes(65536, poolMaterialNodes)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	n += d
	s, err := protocolv4.PoolSelectionBackingBytes(65536, 4096)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	n += s
	for _, schema := range poolRelayMapSchemas {
		limit, e := protocolv4.SchemaByteLimit(schema)
		if e != nil {
			return resourcev4.Vector{}, e
		}
		cost, e := protocolv4.SignedMapBackingBytes(schema, limit, limit)
		if e != nil {
			return resourcev4.Vector{}, e
		}
		n += cost
	}
	p, err := protocolv4.RelayParentProjectionBackingBytes()
	if err != nil {
		return resourcev4.Vector{}, err
	}
	// One scratch pair of closures/activation bindings is covered by the extra
	// projection. The 64 retained projections coexist until publication copies.
	n += 65*p + uint64(unsafe.Sizeof(poolBatchVerifier{})) + 16*(uint64(unsafe.Sizeof(PoolRelayRouteConfig{}))+4096) + 4096
	return (resourcev4.Vector{resourcev4.SDKBytes: n, resourcev4.Items: 1, resourcev4.WorkSlots: 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: c.RuntimeBytes})
}

func newPoolBatchVerifier(c PoolBatchVerificationConfig, cost resourcev4.Vector, reservation, dependencies resourcev4.Reference) (_ *poolBatchVerifier, err error) {
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
	f := &poolBatchVerifier{config: c, reservation: owned, dependencies: dependencies, done: make(chan struct{})}
	defer func() {
		if err != nil {
			f.Close()
		}
	}()
	f.shared, err = dependencies.Borrow()
	if err != nil {
		return nil, err
	}
	f.config.Tenant = strings.Clone(c.Tenant)
	f.config.Audience = strings.Clone(c.Audience)
	f.config.CryptoProfile = strings.Clone(c.CryptoProfile)
	f.config.ActivationSigningKeyID = strings.Clone(c.ActivationSigningKeyID)
	n := copy(f.accounts[:], c.Accounts)
	f.config.Accounts = f.accounts[:n:n]
	f.config.Routes = [16]*PoolRelayRouteConfig{}
	for i, t := range c.Trust {
		f.trust[i], err = t.ReferenceFor(c.Clock, dependencies)
		if err != nil {
			return nil, err
		}
	}
	for i, r := range c.Routes {
		if r == nil {
			continue
		}
		cloned := *r
		f.config.Routes[i] = &cloned
		for _, s := range poolRelayMappingStrings(&cloned.Mapping) {
			*s = strings.Clone(*s)
		}
		for side, t := range [3]*protocolv4.NamespaceTrustStore{r.Grants[0], r.Grants[1], r.RelayTrust} {
			f.trust[3+i*3+side], err = t.ReferenceFor(c.Clock, dependencies)
			if err != nil {
				return nil, err
			}
		}
	}
	f.codec, err = protocolv4.NewTopUpCodec()
	if err != nil {
		return nil, err
	}
	f.material, err = protocolv4.NewDecoder(65536, poolMaterialNodes)
	if err != nil {
		return nil, err
	}
	f.selection, err = protocolv4.NewPoolSelectionWorkspace(65536, 4096)
	if err != nil {
		return nil, err
	}
	for i, schema := range poolRelayMapSchemas {
		limit, _ := protocolv4.SchemaByteLimit(schema)
		f.maps[i], err = protocolv4.NewSignedMapCodec(schema, limit, limit)
		if err != nil {
			return nil, err
		}
	}
	return f, nil
}

func (f *poolBatchVerifier) checkLocked(ctx context.Context) error {
	if f.closed {
		return resourcev4.ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, r := range []resourcev4.Reference{f.reservation, f.shared} {
		if err := r.Check(); err != nil {
			return err
		}
	}
	for _, r := range f.trust {
		if r != (resourcev4.Reference{}) {
			if err := r.Check(); err != nil {
				return err
			}
		}
	}
	return nil
}
func (f *poolBatchVerifier) check(ctx context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.checkLocked(ctx)
}

func (f *poolBatchVerifier) Close() {
	if f == nil {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	f.cleanupLocked()
}

func (f *poolBatchVerifier) cleanupLocked() {
	if !f.closed || f.busy || f.cleaned {
		return
	}
	for _, r := range f.trust {
		r.Release()
	}
	clear(f.trust[:])
	clear(f.parents[:])
	clear(f.accounts[:])
	clear(f.delegation[:])
	clear(f.once[:])
	f.maps = [7]*protocolv4.SignedMapCodec{}
	f.codec = nil
	f.material = nil
	f.selection = nil
	f.config = PoolBatchVerificationConfig{}
	f.dependencies = resourcev4.Reference{}
	f.shared.Release()
	f.reservation.Release()
	f.shared, f.reservation = resourcev4.Reference{}, resourcev4.Reference{}
	f.cleaned = true
	close(f.done)
}
func (f *poolBatchVerifier) WaitCleanup(ctx context.Context) error {
	if f == nil || ctx == nil {
		return resourcev4.ErrConfiguration
	}
	select {
	case <-f.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// verifyBatch holds exactly one finite scratch position until all signed
// material is checked and cleared. Original parsed outbox facts remain owned
// by the caller; public relay projections exist only during this invocation.
func (f *poolBatchVerifier) verifyBatch(request protocolv4.TopUpRequestFacts, batch *protocolv4.TopUpBatch) (err error) {
	if f == nil || batch == nil {
		return resourcev4.ErrConfiguration
	}
	ctx := context.Background()
	f.mu.Lock()
	if err = f.checkLocked(ctx); err != nil {
		f.mu.Unlock()
		return err
	}
	if f.busy {
		f.mu.Unlock()
		return ErrBusy
	}
	f.busy = true
	c := f.config
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		if err == nil {
			err = f.checkLocked(ctx)
		}
		clear(f.parents[:])
		clear(f.delegation[:])
		clear(f.once[:])
		f.busy = false
		f.cleanupLocked()
		f.mu.Unlock()
	}()
	if request.Tenant != c.Tenant || request.Source != c.SourceIncarnation || request.Pool != c.Pool || request.Identity != c.ClientIdentity || !batch.MatchesRequest(request) {
		return ledgerv4.ErrOwner
	}
	facts, err := batch.Facts()
	if err != nil {
		return err
	}
	if facts.Count == 0 || facts.Count > 4 || facts.Count != request.DesiredCount || facts.Generation != request.Generation {
		return ErrResponse
	}
	for i, entry := range facts.Entries[:facts.Count] {
		if entry.Identity != c.ClientIdentity || entry.Generation != request.Generation {
			return ledgerv4.ErrOwner
		}
		wire, e := batch.Material(uint32(i))
		if e != nil {
			return e
		}
		if _, e = f.verifyMaterial(ctx, request, entry, wire, f.parents[:16]); e != nil {
			return e
		}
		clear(f.parents[:])
	}
	return f.check(ctx)
}
