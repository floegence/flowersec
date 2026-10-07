package controlv4

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"math"
	"strings"
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
	*poolBatchVerifier
	config PoolRelayFactoryConfig
}

func (c PoolRelayFactoryConfig) verification() PoolBatchVerificationConfig {
	return PoolBatchVerificationConfig{
		Clock: c.Clock, Tenant: c.Tenant, Audience: c.Audience, CryptoProfile: c.CryptoProfile,
		SourceIncarnation: c.SourceIncarnation, ArtifactIssuer: c.ArtifactIssuer,
		Pool: c.Pool, ClientIdentity: c.ClientIdentity, ServerIdentity: c.ServerIdentity,
		ActivationSigningKeyID: c.ActivationSigningKeyID, Trust: c.Trust, Routes: c.Routes,
		Root: c.Root, Owner: c.Owner, Accounts: c.Accounts, RuntimeBytes: c.RuntimeBytes,
	}
}

func PoolRelayFactoryCharge(c PoolRelayFactoryConfig) (resourcev4.Vector, error) {
	if c.Source == nil || c.Table == nil {
		return resourcev4.Vector{}, resourcev4.ErrConfiguration
	}
	if _, err := ledgerv4.SQLitePoolRelayPublicationCharge(ledgerv4.SQLitePoolRelayPublicationConfig{Table: c.Table, SourceIdentity: c.SourceIdentity, Parents: []ledgerv4.SQLitePoolRelayParent{{}}}); err != nil {
		return resourcev4.Vector{}, err
	}
	cost, err := poolBatchVerifierCharge(c.verification())
	if err != nil {
		return resourcev4.Vector{}, err
	}
	return cost.Add(resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(PoolRelayFactory{})) + 128})
}

func NewPoolRelayFactory(c PoolRelayFactoryConfig, reservation, dependencies resourcev4.Reference) (*PoolRelayFactory, error) {
	cost, err := PoolRelayFactoryCharge(c)
	if err != nil {
		return nil, err
	}
	if err = c.Source.CheckSourceBinding(c.Tenant, c.SourceIncarnation); err != nil {
		return nil, err
	}
	verifier, err := newPoolBatchVerifier(c.verification(), cost, reservation, dependencies)
	if err != nil {
		return nil, err
	}
	c.SourceIdentity.Authority = strings.Clone(c.SourceIdentity.Authority)
	c.Tenant, c.Audience, c.CryptoProfile = verifier.config.Tenant, verifier.config.Audience, verifier.config.CryptoProfile
	c.ActivationSigningKeyID = verifier.config.ActivationSigningKeyID
	c.Accounts, c.Routes = verifier.config.Accounts, verifier.config.Routes
	return &PoolRelayFactory{poolBatchVerifier: verifier, config: c}, nil
}

func poolRelayMappingStrings(m *protocolv4.RelayIssuerMapping) []*string {
	return []*string{&m.Parent.Tenant, &m.Parent.Authority, &m.Activation.Tenant, &m.Activation.AuthorityNamespace, &m.Activation.SigningKeyID, &m.Activation.SpendAuthority, &m.Activation.WinnerAuthority, &m.Service, &m.RelayAudience, &m.EndpointAudience, &m.Profile, &m.Grants[0].Namespace.Tenant, &m.Grants[0].Namespace.Authority, &m.Grants[1].Namespace.Tenant, &m.Grants[1].Namespace.Authority}
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
	f.poolBatchVerifier.cleanupLocked()
	if f.cleaned {
		f.config = PoolRelayFactoryConfig{}
	}
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
