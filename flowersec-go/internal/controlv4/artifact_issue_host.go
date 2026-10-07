package controlv4

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"math"
	"strings"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

type ArtifactIssueAuthenticationKind uint8

const (
	// The control certificate must have been authenticated by the original
	// DirectIssueHTTPSService; a matching caller-supplied envelope is insufficient.
	ArtifactIssueMutualTLS ArtifactIssueAuthenticationKind = 1
	// A private deployment credential held by the original local batch issuer.
	// This digest is configured independently, never learned from a request.
	ArtifactIssueLocalCredential ArtifactIssueAuthenticationKind = 2
)

// ArtifactIssueShareConfig is a preallocated deployment share, not an allocation
// request. Reopening the same exact SQLite identity reuses the same fixed share;
// no different store identity can inherit it or grow it by recreating an adapter.
// Both endpoint identities must have independently installed complete-State read
// permission for every namespace in ReadNamespaces, including relay/Grant owners.
type ArtifactIssueShareConfig struct {
	Identity                                             ledgerv4.SQLiteIdentity
	MaxOutstanding                                       uint32
	StateBytes                                           uint64
	ClientIdentity, ServerIdentity                       [32]byte
	AuthenticationKind                                   ArtifactIssueAuthenticationKind
	ControlClientCertificateDigest, AuthenticationDigest [32]byte
	ReadNamespaces                                       []protocolv4.NamespaceReference
}

type ArtifactIssueHostConfig struct {
	Policy       protocolv4.DirectIssuePolicyConfig
	Shares       []ArtifactIssueShareConfig
	Root         *resourcev4.Root
	Owner        resourcev4.OwnerKey
	Accounts     []resourcev4.Account
	RuntimeBytes uint64
}

// ArtifactIssueHost binds one original signed issuer/namespace authorization to
// a complete finite deployment share manifest and immutable authentication ACLs.
// SQLiteDirectIssueAuthority remains the original durable obligation owner; this
// host does not sign, allocate leases, fabricate state or publish credentials.
type ArtifactIssueHost struct {
	mu                         sync.Mutex
	reservation, shared, trust resourcev4.Reference
	policy                     *protocolv4.DirectIssuePolicy
	limits                     protocolv4.DirectIssuePolicyLimits
	shares                     []artifactIssueShare
	done                       chan struct{}
	closed, cleaned            bool
}
type artifactIssueShare struct {
	identity                      ledgerv4.SQLiteIdentity
	outstanding                   uint32
	stateBytes                    uint64
	client, server                [32]byte
	kind                          ArtifactIssueAuthenticationKind
	controlClient, authentication [32]byte
	reads                         [protocolv4.MaxArtifactIssueNamespaces]protocolv4.NamespaceReference
	readCount                     uint8
	serial                        uint64
	active                        bool
}
type artifactIssueHostAccess struct {
	host   *ArtifactIssueHost
	index  int
	serial uint64
}

func ArtifactIssueHostCharge(c ArtifactIssueHostConfig) (resourcev4.Vector, error) {
	if c.Policy.Trust == nil || c.Policy.Clock == nil || c.Root == nil || len(c.Accounts) > 8 || c.RuntimeBytes == 0 || len(c.Shares) == 0 || len(c.Shares) > 16 {
		return resourcev4.Vector{}, resourcev4.ErrConfiguration
	}
	for i, s := range c.Shares {
		if len(s.Identity.Authority) == 0 || len(s.Identity.Authority) > 128 || s.Identity.StoreID == ([32]byte{}) || s.Identity.Generation == 0 || s.MaxOutstanding == 0 || s.MaxOutstanding > 1<<20 || s.StateBytes == 0 || s.StateBytes > 1<<32 || s.ClientIdentity == ([32]byte{}) || s.ServerIdentity == ([32]byte{}) || s.ClientIdentity == s.ServerIdentity || len(s.ReadNamespaces) == 0 || len(s.ReadNamespaces) > protocolv4.MaxArtifactIssueNamespaces {
			return resourcev4.Vector{}, resourcev4.ErrConfiguration
		}
		switch s.AuthenticationKind {
		case ArtifactIssueMutualTLS:
			if s.ControlClientCertificateDigest == ([32]byte{}) || s.AuthenticationDigest != ([32]byte{}) {
				return resourcev4.Vector{}, resourcev4.ErrConfiguration
			}
		case ArtifactIssueLocalCredential:
			if s.AuthenticationDigest == ([32]byte{}) || s.ControlClientCertificateDigest != ([32]byte{}) {
				return resourcev4.Vector{}, resourcev4.ErrConfiguration
			}
		default:
			return resourcev4.Vector{}, resourcev4.ErrConfiguration
		}
		for _, previous := range c.Shares[:i] {
			if previous.Identity.StoreID == s.Identity.StoreID {
				return resourcev4.Vector{}, resourcev4.ErrOwner
			}
		}
		for j, ref := range s.ReadNamespaces {
			if len(ref.Tenant) == 0 || len(ref.Tenant) > 128 || len(ref.Authority) == 0 || len(ref.Authority) > 128 || ref.Generation == 0 || ref.CapacityDigest == ([32]byte{}) || ref.RoleMask == 0 || ref.RoleMask & ^uint64(7) != 0 {
				return resourcev4.Vector{}, resourcev4.ErrConfiguration
			}
			for _, previous := range s.ReadNamespaces[:j] {
				if previous.Tenant == ref.Tenant && previous.Authority == ref.Authority {
					return resourcev4.Vector{}, resourcev4.ErrOwner
				}
			}
		}
	}
	bytes := uint64(unsafe.Sizeof(ArtifactIssueHost{})) + protocolv4.DirectIssuePolicyBackingBytes() + uint64(len(c.Shares))*(uint64(unsafe.Sizeof(artifactIssueShare{}))+uint64(unsafe.Sizeof(artifactIssueHostAccess{}))+256+protocolv4.MaxArtifactIssueNamespaces*256)
	return (resourcev4.Vector{resourcev4.SDKBytes: bytes, resourcev4.Items: uint64(len(c.Shares)) + 1, resourcev4.WorkSlots: uint64(len(c.Shares))}).Add(resourcev4.Vector{resourcev4.SDKBytes: c.RuntimeBytes})
}

func NewArtifactIssueHost(c ArtifactIssueHostConfig, reservation, dependencies resourcev4.Reference) (_ *ArtifactIssueHost, err error) {
	cost, err := ArtifactIssueHostCharge(c)
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
	h := &ArtifactIssueHost{reservation: owned, done: make(chan struct{})}
	defer func() {
		if err != nil {
			h.Close()
		}
	}()
	h.shared, err = dependencies.Borrow()
	if err != nil {
		return nil, err
	}
	h.policy, h.trust, err = protocolv4.NewDirectIssuePolicy(c.Policy, dependencies)
	if err != nil {
		return nil, err
	}
	h.limits = h.policy.Limits()
	closure, count := h.policy.NamespaceClosure()
	var totalLeases, totalState uint64
	h.shares = make([]artifactIssueShare, len(c.Shares))
	for i, input := range c.Shares {
		if uint64(input.MaxOutstanding) > h.limits.MaxLeases || uint64(input.MaxOutstanding) > h.limits.MaxSegments || input.StateBytes > h.limits.MaxStateBytes || len(input.ReadNamespaces) != int(count) {
			return nil, ledgerv4.ErrCapacity
		}
		// Each share's fixed State reservation includes the complete header, one
		// issuer authorization and every maximum lease/policy-segment obligation.
		minimum, e := ledgerv4.SQLiteDirectIssueStateShareBytes(input.MaxOutstanding)
		if e != nil {
			return nil, e
		}
		if input.StateBytes < minimum {
			return nil, ledgerv4.ErrCapacity
		}
		if totalLeases > math.MaxUint64-uint64(input.MaxOutstanding) || totalState > math.MaxUint64-input.StateBytes {
			return nil, ledgerv4.ErrCapacity
		}
		totalLeases += uint64(input.MaxOutstanding)
		totalState += input.StateBytes
		slot := &h.shares[i]
		slot.identity = input.Identity
		slot.identity.Authority = strings.Clone(input.Identity.Authority)
		slot.outstanding, slot.stateBytes = input.MaxOutstanding, input.StateBytes
		slot.client, slot.server = input.ClientIdentity, input.ServerIdentity
		slot.kind, slot.controlClient, slot.authentication = input.AuthenticationKind, input.ControlClientCertificateDigest, input.AuthenticationDigest
		slot.readCount = count
		for j, want := range closure[:count] {
			found := false
			for _, allowed := range input.ReadNamespaces {
				if allowed == want {
					found = true
					break
				}
			}
			if !found {
				return nil, ledgerv4.ErrDenied
			}
			slot.reads[j] = want
			slot.reads[j].Tenant = strings.Clone(want.Tenant)
			slot.reads[j].Authority = strings.Clone(want.Authority)
		}
	}
	if totalLeases > h.limits.MaxLeases || totalLeases > h.limits.MaxSegments || totalState > h.limits.MaxStateBytes || h.limits.MaxIssuers < 1 || h.limits.MaxAuthorizations < 1 {
		return nil, ledgerv4.ErrCapacity
	}
	return h, nil
}

func (h *ArtifactIssueHost) checkLocked(ctx context.Context) error {
	if h.closed {
		return resourcev4.ErrClosed
	}
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	for _, ref := range []resourcev4.Reference{h.reservation, h.shared, h.trust} {
		if err := ref.Check(); err != nil {
			return err
		}
	}
	return nil
}
func (h *ArtifactIssueHost) shareLocked(identity ledgerv4.SQLiteIdentity) int {
	for i := range h.shares {
		if h.shares[i].identity == identity {
			return i
		}
	}
	return -1
}
func (h *ArtifactIssueHost) CheckDirectIssueShare(identity ledgerv4.SQLiteIdentity, limits protocolv4.DirectIssuePolicyLimits, count uint32, size uint64) error {
	if h == nil {
		return resourcev4.ErrConfiguration
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := h.checkLocked(nil); err != nil {
		return err
	}
	i := h.shareLocked(identity)
	if i < 0 || limits != h.limits || count != h.shares[i].outstanding || size != h.shares[i].stateBytes {
		return ledgerv4.ErrDenied
	}
	return nil
}
func (h *ArtifactIssueHost) AuthorizeDirectIssue(ctx context.Context, identity ledgerv4.SQLiteIdentity, request protocolv4.DirectIssueRequest, facts protocolv4.DirectIssueFacts) (ledgerv4.SQLiteDirectIssueAccess, error) {
	if h == nil || ctx == nil {
		return nil, resourcev4.ErrConfiguration
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := h.checkLocked(ctx); err != nil {
		return nil, err
	}
	i := h.shareLocked(identity)
	if i < 0 || request.RequestID == ([32]byte{}) {
		return nil, ledgerv4.ErrDenied
	}
	slot := &h.shares[i]
	switch slot.kind {
	case ArtifactIssueMutualTLS:
		client, ok := AuthenticatedDirectIssueClient(ctx)
		if !ok || client != slot.controlClient || subtle.ConstantTimeCompare(request.Authentication, slot.controlClient[:]) != 1 {
			return nil, ledgerv4.ErrDenied
		}
	case ArtifactIssueLocalCredential:
		if len(request.Authentication) < 32 || len(request.Authentication) > 256 {
			return nil, ledgerv4.ErrDenied
		}
		digest := sha256.Sum256(request.Authentication)
		if subtle.ConstantTimeCompare(digest[:], slot.authentication[:]) != 1 {
			return nil, ledgerv4.ErrDenied
		}
	default:
		return nil, ledgerv4.ErrDenied
	}
	if facts.ClientIdentity != slot.client || facts.ServerIdentity != slot.server || facts.NamespaceCount != slot.readCount {
		return nil, ledgerv4.ErrDenied
	}
	for j, ref := range facts.Namespaces {
		if j >= int(slot.readCount) {
			if ref != (protocolv4.NamespaceReference{}) {
				return nil, ledgerv4.ErrDenied
			}
			continue
		}
		found := false
		for _, allowed := range slot.reads[:slot.readCount] {
			if ref == allowed {
				found = true
				break
			}
		}
		if !found {
			return nil, ledgerv4.ErrDenied
		}
	}
	if err := h.policy.CheckFacts(facts); err != nil {
		return nil, err
	}
	if slot.active {
		return nil, ErrBusy
	}
	if slot.serial == math.MaxUint64 {
		return nil, resourcev4.ErrCapacity
	}
	slot.serial++
	slot.active = true
	return artifactIssueHostAccess{host: h, index: i, serial: slot.serial}, nil
}
func (a artifactIssueHostAccess) Check(ctx context.Context) error {
	if a.host == nil || ctx == nil {
		return resourcev4.ErrConfiguration
	}
	h := a.host
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := h.checkLocked(ctx); err != nil {
		return err
	}
	if a.index < 0 || a.index >= len(h.shares) {
		return resourcev4.ErrOwner
	}
	slot := &h.shares[a.index]
	if !slot.active || slot.serial != a.serial {
		return ledgerv4.ErrDenied
	}
	return nil
}
func (a artifactIssueHostAccess) Close() {
	if a.host == nil {
		return
	}
	h := a.host
	h.mu.Lock()
	defer h.mu.Unlock()
	if a.index >= 0 && a.index < len(h.shares) {
		slot := &h.shares[a.index]
		if slot.active && slot.serial == a.serial {
			slot.active = false
		}
	}
	h.cleanupLocked()
}
func (h *ArtifactIssueHost) cleanupLocked() {
	if !h.closed || h.cleaned {
		return
	}
	for i := range h.shares {
		if h.shares[i].active {
			return
		}
	}
	clear(h.shares)
	h.shares = nil
	h.policy = nil
	h.limits = protocolv4.DirectIssuePolicyLimits{}
	h.trust.Release()
	h.shared.Release()
	h.reservation.Release()
	h.trust, h.shared, h.reservation = resourcev4.Reference{}, resourcev4.Reference{}, resourcev4.Reference{}
	h.cleaned = true
	close(h.done)
}
func (h *ArtifactIssueHost) Close() {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.closed = true
	h.cleanupLocked()
}
func (h *ArtifactIssueHost) WaitCleanup(ctx context.Context) error {
	if h == nil || ctx == nil {
		return resourcev4.ErrConfiguration
	}
	select {
	case <-h.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (*ArtifactIssueHost) String() string   { return "Flowersec.ArtifactIssueHost" }
func (*ArtifactIssueHost) GoString() string { return "Flowersec.ArtifactIssueHost" }
func (*ArtifactIssueHost) MarshalJSON() ([]byte, error) {
	return []byte(`"Flowersec.ArtifactIssueHost"`), nil
}

var _ ledgerv4.SQLiteDirectIssueHost = (*ArtifactIssueHost)(nil)
var _ ledgerv4.SQLiteDirectIssueAccess = artifactIssueHostAccess{}
