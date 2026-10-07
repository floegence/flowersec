package controlv4

import (
	"context"
	"crypto/rand"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// PoolTunnelDeploymentConfig is the original host composition. Each physical
// store and its identity/continuity gate must already be independently admitted.
// ProvisionSource is an explicit provisioning decision; an absent or rejected
// history never falls through to Create. Relay.Parents can restore only public
// committed registrations, without recreating issuance or endpoint dispatch.
// Fields owned by this constructor (Host, Authority, Policy, Source, Table and
// issuer pointers) must be empty in the input rather than placeholder owners.
type PoolTunnelDeploymentConfig struct {
	IssueStore, RelayStore *ledgerv4.SQLiteStore
	IssueIdentity          ledgerv4.SQLiteIdentity
	SourceBacking          *ledgerv4.SQLiteBacking
	SourceContinuity       ledgerv4.SQLiteContinuity
	ProvisionSource        bool
	Host                   ArtifactIssueHostConfig
	Issue                  ledgerv4.SQLiteDirectIssueConfig
	Source                 PoolSourceAuthorityConfig
	Journal                ledgerv4.SQLiteTopUpServerConfig
	Relay                  ledgerv4.SQLiteRelayAuthorityConfig
	Authority              PoolTunnelAuthorityConfig
	Root                   *resourcev4.Root
	Owner                  resourcev4.OwnerKey
	Accounts               []resourcev4.Account
	RuntimeBytes           uint64
}

// PoolTunnelDeployment fixes the original finite namespace share, durable
// Artifact issuer, independently fenced source journal and committed relay
// table before exposing PoolService. No request can select any of these owners.
// IssueStore, RelayStore and SourceBacking remain with their physical host; this
// aggregate owns the source connection and borrows every external dependency.
type PoolTunnelDeployment struct {
	mu                                      sync.Mutex
	host                                    *ArtifactIssueHost
	issue                                   *ledgerv4.SQLiteDirectIssueAuthority
	source                                  *PoolSourceAuthority
	journal                                 *ledgerv4.SQLiteTopUpServer
	relay                                   *ledgerv4.SQLiteRelayAuthorityTable
	authority                               *PoolTunnelAuthority
	reservation, shared, issueStore, policy resourcev4.Reference
	policyBacking                           *poolTunnelPolicyBacking
	fenceKey                                protocolv4.TopUpFenceAuthority
	clock                                   *timev4.Clock
	refs                                    [6]resourcev4.Reference
	closed, waiting, cleaned                bool
}

func PoolTunnelDeploymentCharge(c PoolTunnelDeploymentConfig) (resourcev4.Vector, error) {
	if c.Root == nil || c.RuntimeBytes == 0 || len(c.Accounts) == 0 || len(c.Accounts) > resourcev4.MaxAccountsPerCharge || c.IssueStore == nil || c.RelayStore == nil || c.SourceBacking == nil || c.SourceContinuity == nil || c.IssueStore == c.RelayStore || c.Issue.Host != nil || c.Journal.Authority != nil || c.Authority.Artifact.Authority != nil || c.Authority.Artifact.Base.Authority != nil || c.Authority.Batch.Policy != nil || c.Authority.Batch.ArtifactIssuer != nil || c.Authority.Publication.Source != nil || c.Authority.Publication.Table != nil || c.Authority.Service.Store != nil || c.Authority.Service.Issuer != nil || c.Authority.Service.RelayPublications != nil {
		return resourcev4.Vector{}, resourcev4.ErrConfiguration
	}
	base, verify := c.Authority.Artifact.Base, c.Source.Verification
	if c.Host.Policy.Trust != base.Trust[0] || c.Issue.Policy.Trust != base.Trust[0] || c.Host.Policy.Clock != base.Clock || c.Issue.Policy.Clock != base.Clock || c.Journal.Clock != base.Clock || verify.Clock != base.Clock || c.Journal.Tenant != verify.Tenant || c.Journal.Source != verify.SourceIncarnation || c.Authority.Service.Tenant != verify.Tenant || c.Authority.Service.Source != verify.SourceIncarnation || c.Source.Identity != c.Authority.Publication.SourceIdentity || c.Source.Identity == c.IssueIdentity || c.Source.Identity == c.Relay.Identity || c.IssueIdentity == c.Relay.Identity {
		return resourcev4.Vector{}, resourcev4.ErrOwner
	}
	// The journal verifier and publication verifier share an independently fixed
	// complete mapping. Neither can take issuer or identity facts from the batch.
	publication := c.Authority.Publication.verification()
	if verify.Tenant != publication.Tenant || verify.SourceIncarnation != publication.SourceIncarnation || verify.Pool != publication.Pool || verify.ArtifactIssuer != publication.ArtifactIssuer || verify.ClientIdentity != publication.ClientIdentity || verify.ServerIdentity != publication.ServerIdentity || verify.Audience != publication.Audience || verify.CryptoProfile != publication.CryptoProfile || verify.ActivationSigningKeyID != publication.ActivationSigningKeyID || verify.Trust != publication.Trust {
		return resourcev4.Vector{}, resourcev4.ErrOwner
	}
	for i, route := range verify.Routes {
		other := publication.Routes[i]
		if (route == nil) != (other == nil) {
			return resourcev4.Vector{}, resourcev4.ErrOwner
		}
		if route != nil && (route.Mapping != other.Mapping || route.Grants != other.Grants || route.RelayTrust != other.RelayTrust) {
			return resourcev4.Vector{}, resourcev4.ErrOwner
		}
	}
	found := false
	for _, share := range c.Host.Shares {
		if share.Identity != c.IssueIdentity {
			continue
		}
		if share.MaxOutstanding != c.Issue.MaxOutstanding || share.StateBytes != c.Issue.StateBytes || share.ClientIdentity != verify.ClientIdentity || share.ServerIdentity != verify.ServerIdentity {
			return resourcev4.Vector{}, resourcev4.ErrOwner
		}
		found = true
	}
	if !found {
		return resourcev4.Vector{}, resourcev4.ErrOwner
	}
	return (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(PoolTunnelDeployment{})) + 2048, resourcev4.Items: 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: c.RuntimeBytes})
}

func NewPoolTunnelDeployment(ctx context.Context, c PoolTunnelDeploymentConfig, reservation, dependencies resourcev4.Reference) (_ *PoolTunnelDeployment, err error) {
	if ctx == nil {
		return nil, resourcev4.ErrConfiguration
	}
	charge, err := PoolTunnelDeploymentCharge(c)
	if err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if err = reservation.CheckAllocationScope(c.Root, c.Owner, c.Accounts); err != nil {
		return nil, err
	}
	if err = reservation.CheckSameEnvironment(dependencies); err != nil {
		return nil, err
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		return nil, err
	}
	d := &PoolTunnelDeployment{reservation: owned, fenceKey: c.Journal.FenceKey, clock: c.Journal.Clock}
	success := false
	defer func() {
		if !success {
			d.Close()
			_ = d.WaitCleanup(context.Background())
		}
	}()
	d.shared, err = dependencies.Borrow()
	if err != nil {
		return nil, err
	}
	var identity ledgerv4.SQLiteIdentity
	d.issueStore, identity, _, err = c.IssueStore.RelayReference(dependencies)
	if err != nil {
		return nil, err
	}
	if identity != c.IssueIdentity {
		return nil, ledgerv4.ErrOwner
	}
	var owners [6]resourcev4.OwnerKey
	reserve := func(index int, cost resourcev4.Vector) error {
		owner := c.Owner
		if _, e := rand.Read(owner.Instance[:]); e != nil {
			return e
		}
		if _, e := rand.Read(owner.Backing[:]); e != nil {
			return e
		}
		owners[index] = owner
		d.refs[index], err = c.Root.Reserve(owner, cost, c.Accounts...)
		return err
	}
	host := c.Host
	host.Root = c.Root
	host.Accounts = c.Accounts
	cost, err := ArtifactIssueHostCharge(host)
	if err != nil {
		return nil, err
	}
	if err = reserve(0, cost); err != nil {
		return nil, err
	}
	host.Owner = owners[0]
	d.host, err = NewArtifactIssueHost(host, d.refs[0], dependencies)
	if err != nil {
		return nil, err
	}
	issue := c.Issue
	issue.Host = d.host
	cost, err = ledgerv4.SQLiteDirectIssueCharge(issue)
	if err != nil {
		return nil, err
	}
	if err = reserve(1, cost); err != nil {
		return nil, err
	}
	d.issue, err = ledgerv4.NewSQLiteDirectIssueAuthority(ctx, c.IssueStore, issue, d.refs[1], dependencies)
	if err != nil {
		return nil, err
	}
	source := c.Source
	source.Verification.Root = c.Root
	source.Verification.Accounts = c.Accounts
	cost, err = PoolSourceAuthorityCharge(source)
	if err != nil {
		return nil, err
	}
	if err = reserve(2, cost); err != nil {
		return nil, err
	}
	source.Verification.Owner = owners[2]
	d.source, err = NewPoolSourceAuthority(source, d.refs[2], dependencies)
	if err != nil {
		return nil, err
	}
	journal := c.Journal
	journal.Authority = d.source
	cost, err = ledgerv4.SQLiteTopUpServerCharge(c.SourceBacking.Limits(), journal)
	if err != nil {
		return nil, err
	}
	if err = reserve(3, cost); err != nil {
		return nil, err
	}
	if c.ProvisionSource {
		d.journal, err = ledgerv4.CreateSQLiteTopUpServer(ctx, c.SourceBacking, c.Source.Identity, c.SourceContinuity, journal, d.refs[3], dependencies)
	} else {
		d.journal, err = ledgerv4.OpenSQLiteTopUpServer(ctx, c.SourceBacking, c.Source.Identity, c.SourceContinuity, journal, d.refs[3], dependencies)
	}
	if err != nil {
		return nil, err
	}
	cost, err = ledgerv4.SQLiteRelayAuthorityCharge(c.Relay)
	if err != nil {
		return nil, err
	}
	if err = reserve(4, cost); err != nil {
		return nil, err
	}
	d.relay, err = ledgerv4.NewSQLiteRelayAuthorityTableContext(ctx, c.RelayStore, c.Relay, d.refs[4], dependencies)
	if err != nil {
		return nil, err
	}
	authority := c.Authority
	authority.Artifact.Authority = d.issue
	authority.Batch.Policy = d.source
	authority.Publication.Source, authority.Publication.Table = d.journal, d.relay
	authority.Service.Store = d.journal
	authority.Root = c.Root
	authority.Accounts = c.Accounts
	authority.Batch.Root = c.Root
	authority.Batch.Accounts = c.Accounts
	authority.Publication.Root = c.Root
	authority.Publication.Accounts = c.Accounts
	cost, err = PoolTunnelAuthorityCharge(authority)
	if err != nil {
		return nil, err
	}
	if err = reserve(5, cost); err != nil {
		return nil, err
	}
	authority.Owner = owners[5]
	d.authority, err = NewPoolTunnelAuthority(authority, d.refs[5], dependencies)
	if err != nil {
		return nil, err
	}
	success = true
	return d, nil
}

// Service returns only the original authenticated control endpoint. It never
// bypasses the pending journal, durable issuance permit or publication gate.
func (d *PoolTunnelDeployment) Service() (*PoolService, error) {
	if d == nil {
		return nil, resourcev4.ErrConfiguration
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed || d.authority == nil {
		return nil, resourcev4.ErrClosed
	}
	return d.authority.Service()
}

// SourceJournal returns the original complete-outbox owner for authenticated
// observation and CaptureRelayLeg. A captured leg proves only already committed
// original public history; it cannot restore a signing/consumer/allow dispatch.
func (d *PoolTunnelDeployment) SourceJournal() (*ledgerv4.SQLiteTopUpServer, error) {
	if d == nil {
		return nil, resourcev4.ErrConfiguration
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed || d.journal == nil {
		return nil, resourcev4.ErrClosed
	}
	if err := d.reservation.Check(); err != nil {
		return nil, err
	}
	return d.journal, nil
}

// RelayTable exposes the same original public table for physical relay routes.
// Restored rows retain lookup authority only; no activation or allow is replayed.
func (d *PoolTunnelDeployment) RelayTable() (*ledgerv4.SQLiteRelayAuthorityTable, error) {
	if d == nil {
		return nil, resourcev4.ErrConfiguration
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed || d.relay == nil {
		return nil, resourcev4.ErrClosed
	}
	if err := d.reservation.Check(); err != nil {
		return nil, err
	}
	return d.relay, nil
}

func (d *PoolTunnelDeployment) Close() {
	if d == nil {
		return
	}
	d.mu.Lock()
	d.closed = true
	authority, issue, journal, source, relay, host := d.authority, d.issue, d.journal, d.source, d.relay, d.host
	d.mu.Unlock()
	if authority != nil {
		authority.Close()
	}
	if issue != nil {
		issue.Close()
	}
	if journal != nil {
		journal.Close()
	}
	if source != nil {
		source.Close()
	}
	if relay != nil {
		relay.Close()
	}
	if host != nil {
		host.Close()
	}
}

func (d *PoolTunnelDeployment) WaitCleanup(ctx context.Context) error {
	if d == nil || ctx == nil {
		return resourcev4.ErrConfiguration
	}
	d.mu.Lock()
	if d.cleaned {
		d.mu.Unlock()
		return nil
	}
	if !d.closed || d.waiting {
		d.mu.Unlock()
		return resourcev4.ErrCapacity
	}
	d.waiting = true
	authority, issue, journal, source, relay, host := d.authority, d.issue, d.journal, d.source, d.relay, d.host
	d.mu.Unlock()
	defer func() { d.mu.Lock(); d.waiting = false; d.mu.Unlock() }()
	if authority != nil {
		if err := authority.WaitCleanup(ctx); err != nil {
			return err
		}
	}
	if issue != nil {
		if err := issue.WaitCleanup(ctx); err != nil {
			return err
		}
	}
	if journal != nil {
		if err := journal.WaitCleanup(ctx); err != nil {
			return err
		}
		if err := journal.Retire(); err != nil {
			return err
		}
	}
	if source != nil {
		if err := source.WaitCleanup(ctx); err != nil {
			return err
		}
	}
	if relay != nil {
		if err := relay.WaitCleanup(ctx); err != nil {
			return err
		}
	}
	if host != nil {
		if err := host.WaitCleanup(ctx); err != nil {
			return err
		}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, ref := range d.refs {
		ref.Release()
	}
	d.issueStore.Release()
	d.shared.Release()
	d.reservation.Release()
	d.policy.Release()
	d.refs = [6]resourcev4.Reference{}
	d.issueStore, d.shared, d.reservation = resourcev4.Reference{}, resourcev4.Reference{}, resourcev4.Reference{}
	d.authority, d.issue, d.journal, d.source, d.relay, d.host = nil, nil, nil, nil, nil, nil
	d.policy = resourcev4.Reference{}
	d.policyBacking = nil
	d.fenceKey = protocolv4.TopUpFenceAuthority{}
	d.clock = nil
	d.cleaned = true
	return nil
}

func (*PoolTunnelDeployment) String() string   { return "Flowersec.PoolTunnelDeployment" }
func (*PoolTunnelDeployment) GoString() string { return "Flowersec.PoolTunnelDeployment" }
func (*PoolTunnelDeployment) MarshalJSON() ([]byte, error) {
	return []byte(`"Flowersec.PoolTunnelDeployment"`), nil
}
