package controlv4

import (
	"bytes"
	"context"
	"crypto/rand"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

// PoolTunnelAuthorityConfig composes original trusted deployment owners. The
// Artifact authority and retention are independently installed; Store remains
// the original complete-outbox owner and Publication.Table the public relay
// destination. None of these identities or signing keys comes from a request.
// Batch.ArtifactIssuer, Service.Issuer and Service.RelayPublications must be nil:
// this constructor fixes their exact original call chain before it is exposed.
type PoolTunnelAuthorityConfig struct {
	Artifact     protocolv4.ArtifactIssuerConfig
	Batch        PoolBatchSigningConfig
	Publication  PoolRelayFactoryConfig
	Service      PoolServiceConfig
	Root         *resourcev4.Root
	Owner        resourcev4.OwnerKey
	Accounts     []resourcev4.Account
	RuntimeBytes uint64
}

// PoolTunnelAuthority owns signing, Grant construction and committed public
// distribution as one deployment lifecycle. PoolService preserves the complete
// pending -> signed -> publication-admitted -> outbox-committed -> published
// order. Closing never removes durable issuance, outbox or relay registrations.
type PoolTunnelAuthority struct {
	mu                       sync.Mutex
	artifact                 *protocolv4.ArtifactIssuer
	batch                    *PoolBatchSigningIssuer
	publication              *PoolRelayFactory
	service                  *PoolService
	reservation, shared      resourcev4.Reference
	refs                     [4]resourcev4.Reference
	closed, waiting, cleaned bool
}

func PoolTunnelAuthorityCharge(c PoolTunnelAuthorityConfig) (resourcev4.Vector, error) {
	if c.Root == nil || c.RuntimeBytes == 0 || len(c.Accounts) > resourcev4.MaxAccountsPerCharge || c.Artifact.Authority == nil || c.Batch.ArtifactIssuer != nil || c.Service.Issuer != nil || c.Service.RelayPublications != nil || c.Service.Store == nil || c.Publication.Source != c.Service.Store || c.Publication.Table == nil || c.Batch.Root != c.Root || c.Publication.Root != c.Root {
		return resourcev4.Vector{}, resourcev4.ErrConfiguration
	}
	base, batch, pub, service := c.Artifact.Base, c.Batch, c.Publication, c.Service
	if base.Clock != batch.Clock || base.Clock != pub.Clock || base.Tenant != batch.Tenant || base.Tenant != pub.Tenant || base.Tenant != service.Tenant || base.Audience != batch.Audience || base.Audience != pub.Audience || base.CryptoProfile != batch.CryptoProfile || base.CryptoProfile != pub.CryptoProfile || base.IssuerKeyID != batch.ArtifactIssuerID || base.IssuerKeyID != pub.ArtifactIssuer || batch.Source != pub.SourceIncarnation || batch.Source != service.Source || batch.Pool != pub.Pool || batch.ActivationSigningKeyID != pub.ActivationSigningKeyID || batch.Trust != base.Trust || pub.Trust != base.Trust || !bytes.Equal(batch.ClientCertificate, base.ClientCertificate) || !bytes.Equal(batch.ServerCertificate, base.ServerCertificate) {
		return resourcev4.Vector{}, resourcev4.ErrOwner
	}
	tunnels := 0
	for index, original := range c.Artifact.Tunnels {
		signed, route := batch.Tunnels[index], pub.Routes[index]
		if (original == nil) != (signed == nil) || (original == nil) != (route == nil) {
			return resourcev4.Vector{}, resourcev4.ErrConfiguration
		}
		if original == nil {
			continue
		}
		tunnels++
		selected := false
		for _, candidate := range batch.Indices {
			if candidate == uint64(index) {
				selected = true
				break
			}
		}
		if !selected {
			return resourcev4.Vector{}, resourcev4.ErrOwner
		}
		for side, leg := range original.Legs {
			// Original and batch issuance share one independent Grant policy, while
			// publication additionally checks its complete immutable issuer mapping.
			if leg.Grant != signed.Grants[side].Validation || leg.Service != signed.Grants[side].Service || leg.RelayAudience != signed.Grants[side].Audience || leg.Service != route.Mapping.Service || leg.RelayAudience != route.Mapping.RelayAudience || leg.RelayTrust != signed.RelayTrust || leg.RelayTrust != route.RelayTrust || !bytes.Equal(leg.RelayCertificate, signed.RelayCertificate) {
				return resourcev4.Vector{}, resourcev4.ErrOwner
			}
		}
	}
	if tunnels == 0 {
		return resourcev4.Vector{}, resourcev4.ErrConfiguration
	}
	for _, accounts := range [][]resourcev4.Account{batch.Accounts, pub.Accounts} {
		if len(accounts) != len(c.Accounts) {
			return resourcev4.Vector{}, resourcev4.ErrOwner
		}
		for _, account := range accounts {
			found := false
			for _, expected := range c.Accounts {
				if account == expected {
					found = true
					break
				}
			}
			if !found {
				return resourcev4.Vector{}, resourcev4.ErrOwner
			}
		}
	}
	return (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(PoolTunnelAuthority{})) + 1024, resourcev4.Items: 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: c.RuntimeBytes})
}

// Construction admits every child before any issuance/provider call. Required
// signing, namespace, authentication, durable-store and continuity inputs have
// no default, fallback, self-signed substitute or synthetic committed receipt.
func NewPoolTunnelAuthority(c PoolTunnelAuthorityConfig, reservation, dependencies resourcev4.Reference) (_ *PoolTunnelAuthority, err error) {
	charge, err := PoolTunnelAuthorityCharge(c)
	if err != nil {
		return nil, err
	}
	if err = reservation.CheckSameEnvironment(dependencies); err != nil {
		return nil, err
	}
	if err = reservation.CheckAllocationScope(c.Root, c.Owner, c.Accounts); err != nil {
		return nil, err
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		return nil, err
	}
	a := &PoolTunnelAuthority{reservation: owned}
	success := false
	defer func() {
		if !success {
			a.Close()
			_ = a.WaitCleanup(context.Background())
		}
	}()
	a.shared, err = dependencies.Borrow()
	if err != nil {
		return nil, err
	}
	var owners [4]resourcev4.OwnerKey
	reserve := func(index int, cost resourcev4.Vector) error {
		owner := c.Owner
		if _, e := rand.Read(owner.Instance[:]); e != nil {
			return e
		}
		if _, e := rand.Read(owner.Backing[:]); e != nil {
			return e
		}
		owners[index] = owner
		a.refs[index], err = c.Root.Reserve(owner, cost, c.Accounts...)
		return err
	}
	cost, err := protocolv4.ArtifactIssuerCharge(c.Artifact)
	if err != nil {
		return nil, err
	}
	if err = reserve(0, cost); err != nil {
		return nil, err
	}
	a.artifact, err = protocolv4.NewArtifactIssuer(c.Artifact, a.refs[0], dependencies)
	if err != nil {
		return nil, err
	}
	batch := c.Batch
	batch.ArtifactIssuer = a.artifact
	cost, err = PoolBatchSigningIssuerCharge(batch)
	if err != nil {
		return nil, err
	}
	if err = reserve(1, cost); err != nil {
		return nil, err
	}
	batch.Owner = owners[1]
	a.batch, err = NewPoolBatchSigningIssuer(batch, a.refs[1], dependencies)
	if err != nil {
		return nil, err
	}
	cost, err = PoolRelayFactoryCharge(c.Publication)
	if err != nil {
		return nil, err
	}
	if err = reserve(2, cost); err != nil {
		return nil, err
	}
	publication := c.Publication
	publication.Owner = owners[2]
	a.publication, err = NewPoolRelayFactory(publication, a.refs[2], dependencies)
	if err != nil {
		return nil, err
	}
	service := c.Service
	service.Issuer, service.RelayPublications = a.batch, a.publication
	cost, err = PoolServiceCharge(service)
	if err != nil {
		return nil, err
	}
	if err = reserve(3, cost); err != nil {
		return nil, err
	}
	a.service, err = NewPoolService(service, a.refs[3], dependencies)
	if err != nil {
		return nil, err
	}
	success = true
	return a, nil
}

// Service returns the original bounded endpoint for HTTPS or control RPC.
// It performs the complete durable outbox/publication chain on every new
// operation and authenticates explicit replays against the retained outbox.
func (a *PoolTunnelAuthority) Service() (*PoolService, error) {
	if a == nil {
		return nil, resourcev4.ErrConfiguration
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed || a.service == nil {
		return nil, resourcev4.ErrClosed
	}
	if err := a.reservation.Check(); err != nil {
		return nil, err
	}
	return a.service, nil
}
func (a *PoolTunnelAuthority) Close() {
	if a == nil {
		return
	}
	a.mu.Lock()
	a.closed = true
	service, batch, pub, artifact := a.service, a.batch, a.publication, a.artifact
	a.mu.Unlock()
	if service != nil {
		service.Close()
	}
	if batch != nil {
		batch.Close()
	}
	if pub != nil {
		pub.Close()
	}
	if artifact != nil {
		artifact.Close()
	}
}
func (a *PoolTunnelAuthority) WaitCleanup(ctx context.Context) error {
	if a == nil || ctx == nil {
		return resourcev4.ErrConfiguration
	}
	a.mu.Lock()
	if a.cleaned {
		a.mu.Unlock()
		return nil
	}
	if !a.closed || a.waiting {
		a.mu.Unlock()
		return resourcev4.ErrCapacity
	}
	a.waiting = true
	service, batch, pub, artifact := a.service, a.batch, a.publication, a.artifact
	a.mu.Unlock()
	defer func() { a.mu.Lock(); a.waiting = false; a.mu.Unlock() }()
	if service != nil {
		if err := service.WaitCleanup(ctx); err != nil {
			return err
		}
	}
	if batch != nil {
		if err := batch.WaitCleanup(ctx); err != nil {
			return err
		}
	}
	if pub != nil {
		if err := pub.WaitCleanup(ctx); err != nil {
			return err
		}
	}
	if artifact != nil {
		if err := artifact.WaitCleanup(ctx); err != nil {
			return err
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, ref := range a.refs {
		ref.Release()
	}
	a.shared.Release()
	a.reservation.Release()
	a.refs = [4]resourcev4.Reference{}
	a.shared, a.reservation = resourcev4.Reference{}, resourcev4.Reference{}
	a.service, a.batch, a.publication, a.artifact = nil, nil, nil, nil
	a.cleaned = true
	return nil
}
func (*PoolTunnelAuthority) String() string   { return "Flowersec.PoolTunnelAuthority" }
func (*PoolTunnelAuthority) GoString() string { return "Flowersec.PoolTunnelAuthority" }
func (*PoolTunnelAuthority) MarshalJSON() ([]byte, error) {
	return []byte(`"Flowersec.PoolTunnelAuthority"`), nil
}
