package controlv4

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"math"
	"strings"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// Each route has an independent original parent/activation/Grant issuer
// mapping. Neither the material nor a replay request selects trust roots.
type PoolRelayRouteConfig struct {
	Mapping    protocolv4.RelayIssuerMapping
	Grants     [2]*protocolv4.NamespaceTrustStore
	RelayTrust *protocolv4.NamespaceTrustStore
}

type PoolRelayFactoryConfig struct {
	Clock                                *timev4.Clock
	Source                               *ledgerv4.SQLiteTopUpServer
	Table                                *ledgerv4.SQLiteRelayAuthorityTable
	SourceIdentity                       ledgerv4.SQLiteIdentity
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

// PoolRelayFactory verifies complete paired issuer outboxes and admits their
// public distribution. It never signs, prepares a carrier or sends server allow.
// One method owns all scratch through actual return; no queue is allocated.
// Dependencies must retain the entire shared namespace/trust graph, as they do
// for the destination relay table. Returned publications borrow that graph
// independently and own their own reservations.
type PoolRelayFactory struct {
	mu                                sync.Mutex
	config                            PoolRelayFactoryConfig
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

func PoolRelayFactoryCharge(c PoolRelayFactoryConfig) (resourcev4.Vector, error) {
	if c.Clock == nil || c.Source == nil || c.Table == nil || c.Root == nil || len(c.Accounts) > 8 || c.RuntimeBytes == 0 || c.SourceIncarnation == ([16]byte{}) || c.ArtifactIssuer == ([16]byte{}) || c.Pool == ([32]byte{}) || c.ClientIdentity == ([32]byte{}) || c.ServerIdentity == ([32]byte{}) || c.ClientIdentity == c.ServerIdentity {
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
	// Validate the fixed publication destination independently of any batch.
	if _, err := ledgerv4.SQLitePoolRelayPublicationCharge(ledgerv4.SQLitePoolRelayPublicationConfig{Table: c.Table, SourceIdentity: c.SourceIdentity, Parents: []ledgerv4.SQLitePoolRelayParent{{}}}); err != nil {
		return resourcev4.Vector{}, err
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
	n += 65*p + uint64(unsafe.Sizeof(PoolRelayFactory{})) + 16*(uint64(unsafe.Sizeof(PoolRelayRouteConfig{}))+4096) + 4096
	return (resourcev4.Vector{resourcev4.SDKBytes: n, resourcev4.Items: 1, resourcev4.WorkSlots: 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: c.RuntimeBytes})
}

func NewPoolRelayFactory(c PoolRelayFactoryConfig, reservation, dependencies resourcev4.Reference) (_ *PoolRelayFactory, err error) {
	cost, err := PoolRelayFactoryCharge(c)
	if err != nil {
		return nil, err
	}
	if err = c.Source.CheckSourceBinding(c.Tenant, c.SourceIncarnation); err != nil {
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
	f := &PoolRelayFactory{config: c, reservation: owned, dependencies: dependencies, done: make(chan struct{})}
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
	f.config.SourceIdentity.Authority = strings.Clone(c.SourceIdentity.Authority)
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

func poolRelayMappingStrings(m *protocolv4.RelayIssuerMapping) []*string {
	return []*string{&m.Parent.Tenant, &m.Parent.Authority, &m.Activation.Tenant, &m.Activation.AuthorityNamespace, &m.Activation.SigningKeyID, &m.Activation.SpendAuthority, &m.Activation.WinnerAuthority, &m.Service, &m.RelayAudience, &m.EndpointAudience, &m.Profile, &m.Grants[0].Namespace.Tenant, &m.Grants[0].Namespace.Authority, &m.Grants[1].Namespace.Tenant, &m.Grants[1].Namespace.Authority}
}

func (f *PoolRelayFactory) checkLocked(ctx context.Context) error {
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
func (f *PoolRelayFactory) check(ctx context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.checkLocked(ctx)
}

func (f *PoolRelayFactory) PreparePoolRelayPublication(ctx context.Context, original ledgerv4.TopUpServerSnapshot, response []byte) (publication *ledgerv4.SQLitePoolRelayPublication, err error) {
	if f == nil || ctx == nil || len(response) == 0 || len(response) > 524288 {
		return nil, resourcev4.ErrConfiguration
	}
	f.mu.Lock()
	if err = f.checkLocked(ctx); err != nil {
		f.mu.Unlock()
		return nil, err
	}
	if f.busy {
		f.mu.Unlock()
		return nil, ErrBusy
	}
	if f.serial == math.MaxUint64 {
		f.mu.Unlock()
		return nil, resourcev4.ErrCapacity
	}
	f.busy = true
	f.serial++
	c := f.config
	var seed [56]byte
	copy(seed[:16], "pool-relay-1")
	copy(seed[16:32], c.Owner.Instance[:])
	copy(seed[32:48], c.Owner.Backing[:])
	binary.BigEndian.PutUint64(seed[48:], f.serial)
	digest := sha256.Sum256(seed[:])
	owner := c.Owner
	copy(owner.Instance[:], digest[:16])
	copy(owner.Backing[:], digest[16:])
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		if err == nil {
			err = f.checkLocked(ctx)
		}
		f.mu.Unlock()
		if err != nil && publication != nil {
			_ = publication.Close()
			publication = nil
		}
		f.mu.Lock()
		clear(f.parents[:])
		clear(f.delegation[:])
		clear(f.once[:])
		f.busy = false
		f.cleanupLocked()
		f.mu.Unlock()
	}()
	q := original.Request
	if original.Permanent || original.State != ledgerv4.TopUpServerPending && original.State != ledgerv4.TopUpServerCommitted || q.Tenant != c.Tenant || q.Source != c.SourceIncarnation || q.Pool != c.Pool || q.Identity != c.ClientIdentity {
		return nil, ledgerv4.ErrOwner
	}
	batch, err := f.codec.ParseResponse(response, q)
	if err != nil {
		return nil, err
	}
	defer batch.Release()
	facts, err := batch.Facts()
	if err != nil {
		return nil, err
	}
	if original.State == ledgerv4.TopUpServerCommitted && original.Response != facts {
		return nil, ledgerv4.ErrConflict
	}
	count := 0
	for i, entry := range facts.Entries[:facts.Count] {
		if err = f.check(ctx); err != nil {
			return nil, err
		}
		wire, e := batch.Material(uint32(i))
		if e != nil {
			return nil, e
		}
		n, e := f.verifyMaterial(ctx, q, entry, wire, f.parents[count:])
		if e != nil {
			return nil, e
		}
		count += n
	}
	if count == 0 {
		return nil, nil
	}
	config := ledgerv4.SQLitePoolRelayPublicationConfig{Table: c.Table, SourceIdentity: c.SourceIdentity, Parents: f.parents[:count]}
	cost, err := ledgerv4.SQLitePoolRelayPublicationCharge(config)
	if err != nil {
		return nil, err
	}
	ref, err := c.Root.Reserve(owner, cost, c.Accounts...)
	if err != nil {
		return nil, err
	}
	defer ref.Release()
	if err = f.check(ctx); err != nil {
		return nil, err
	}
	return ledgerv4.NewSQLitePoolRelayPublication(ctx, c.Source, original, response, config, ref, f.dependencies)
}

func (f *PoolRelayFactory) Close() {
	if f == nil {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	f.cleanupLocked()
}
func (f *PoolRelayFactory) cleanupLocked() {
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
	f.config = PoolRelayFactoryConfig{}
	f.dependencies = resourcev4.Reference{}
	f.shared.Release()
	f.reservation.Release()
	f.shared, f.reservation = resourcev4.Reference{}, resourcev4.Reference{}
	f.cleaned = true
	close(f.done)
}
func (f *PoolRelayFactory) WaitCleanup(ctx context.Context) error {
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
func (*PoolRelayFactory) String() string   { return "Flowersec.PoolRelayFactory" }
func (*PoolRelayFactory) GoString() string { return "Flowersec.PoolRelayFactory" }
func (*PoolRelayFactory) MarshalJSON() ([]byte, error) {
	return []byte(`"Flowersec.PoolRelayFactory"`), nil
}

var _ PoolRelayPublicationFactory = (*PoolRelayFactory)(nil)
