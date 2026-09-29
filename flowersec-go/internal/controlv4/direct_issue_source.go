package controlv4

import (
	"bytes"
	"context"
	"crypto/rand"
	"net/http"
	"strings"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

type DirectIssueSourceConfig struct {
	HTTPS                                      HTTPSBootstrapConfig
	Root                                       *resourcev4.Root
	Clock                                      *timev4.Clock
	Owner                                      resourcev4.OwnerKey
	Accounts                                   []resourcev4.Account
	Trust                                      [3]*protocolv4.NamespaceTrustStore
	ClientCertificate, ServerCertificate       []byte
	ActivationSigningKeyID, ApplicationProfile string
	RPCMaxGeneralOutstanding                   uint16
	MapBytes, MapNodes                         int
	RuntimeBytes, LeaseRuntimeBytes            uint64
}

// DirectIssueSource acquires a fresh direct/local live-authority Artifact from
// the fixed reference issuer. The original client identity and independent
// namespace trust are installed before construction. Each admitted acquisition
// sends one random request ID over explicit mutual TLS, verifies the response
// and transfers a separately reserved immutable ArtifactLease to its caller.
// Neither failure nor cancellation retries issuance or manufactures activation.
type DirectIssueSource struct {
	preparation                       *directIssuePreparation
	mu                                sync.Mutex
	c                                 DirectIssueSourceConfig
	tunnels                           *artifactIssueSourceTunnels
	path                              string
	accounts                          [8]resourcev4.Account
	provider                          *HTTPSBootstrapProvider
	credentials                       [2]*protocolv4.Credential
	trustRefs                         [3]resourcev4.Reference
	reservation, shared, dependencies resourcev4.Reference
	leaseCharge                       resourcev4.Vector
	request                           [35]byte
	response                          []byte
	serial                            uint64
	cancel                            context.CancelFunc
	done                              chan struct{}
	busy, closed, cleaned             bool
}

func DirectIssueSourceCharge(c DirectIssueSourceConfig) (resourcev4.Vector, error) {
	if c.Root == nil || c.Clock == nil || len(c.Accounts) > 8 || c.RuntimeBytes == 0 || len(c.ClientCertificate) == 0 || len(c.ClientCertificate) > 8192 || len(c.ServerCertificate) == 0 || len(c.ServerCertificate) > 8192 || len(c.ActivationSigningKeyID) == 0 || len(c.ActivationSigningKeyID) > 128 || c.MapBytes < 65536 {
		return resourcev4.Vector{}, resourcev4.ErrConfiguration
	}
	for _, trust := range c.Trust {
		if trust == nil {
			return resourcev4.Vector{}, resourcev4.ErrConfiguration
		}
	}
	switch c.ApplicationProfile {
	case "transport":
		if c.RPCMaxGeneralOutstanding != 0 {
			return resourcev4.Vector{}, resourcev4.ErrConfiguration
		}
	case "services", "execution":
		if c.RPCMaxGeneralOutstanding == 0 || c.RPCMaxGeneralOutstanding > 1024 {
			return resourcev4.Vector{}, resourcev4.ErrConfiguration
		}
	default:
		return resourcev4.Vector{}, resourcev4.ErrConfiguration
	}
	if _, err := LiveHTTPSTransportCharge(LiveHTTPSConfig{HTTPS: c.HTTPS, RuntimeBytes: c.RuntimeBytes}); err != nil {
		return resourcev4.Vector{}, err
	}
	if _, err := sessionv4.ArtifactLeaseCharge(c.MapBytes, c.MapNodes, c.LeaseRuntimeBytes); err != nil {
		return resourcev4.Vector{}, err
	}
	codec, err := protocolv4.SignedMapBackingBytes("IdentityCertificate", 8192, c.MapNodes)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	credential, err := protocolv4.CredentialBackingBytes("IdentityCertificate")
	if err != nil {
		return resourcev4.Vector{}, err
	}
	return (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(DirectIssueSource{})) + uint64(unsafe.Sizeof(directIssuePreparation{})) + sessionv4.ArtifactLeaseReferencesBytes() + 65536 + 16384 + codec + 2*credential + 512, resourcev4.Items: 3, resourcev4.WorkSlots: 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: c.RuntimeBytes})
}

func NewDirectIssueSource(c DirectIssueSourceConfig, reservation, providerReservation, dependencies resourcev4.Reference) (*DirectIssueSource, error) {
	cost, err := DirectIssueSourceCharge(c)
	if err != nil {
		return nil, err
	}
	return newArtifactIssueSource(c, nil, cost, reservation, providerReservation, dependencies)
}

func newArtifactIssueSource(c DirectIssueSourceConfig, tunnels []ArtifactIssueSourceTunnel, cost resourcev4.Vector, reservation, providerReservation, dependencies resourcev4.Reference) (*DirectIssueSource, error) {
	var err error
	if err = reservation.CheckAllocationScope(c.Root, c.Owner, c.Accounts); err != nil {
		return nil, err
	}
	if err = reservation.CheckSameEnvironment(providerReservation); err != nil {
		return nil, err
	}
	if err = reservation.CheckSameEnvironment(dependencies); err != nil {
		return nil, err
	}
	owned, err := reservation.Take(cost)
	if err != nil {
		return nil, err
	}
	p := &DirectIssueSource{c: c, path: "/issue/direct", reservation: owned, dependencies: dependencies, done: make(chan struct{})}
	adopted := false
	defer func() {
		if !adopted {
			p.Close()
		}
	}()
	p.shared, err = dependencies.Borrow()
	if err != nil {
		return nil, err
	}
	for i, trust := range c.Trust {
		p.trustRefs[i], err = trust.ReferenceFor(c.Clock, p.reservation)
		if err != nil {
			return nil, err
		}
	}
	p.c.ClientCertificate, p.c.ServerCertificate = bytes.Clone(c.ClientCertificate), bytes.Clone(c.ServerCertificate)
	p.c.ActivationSigningKeyID, p.c.ApplicationProfile = strings.Clone(c.ActivationSigningKeyID), strings.Clone(c.ApplicationProfile)
	n := copy(p.accounts[:], c.Accounts)
	p.c.Accounts = p.accounts[:n:n]
	codec, err := protocolv4.NewSignedMapCodec("IdentityCertificate", 8192, c.MapNodes)
	if err != nil {
		return nil, err
	}
	for i, wire := range [][]byte{p.c.ClientCertificate, p.c.ServerCertificate} {
		cert, e := codec.VerifyCredential(wire, c.Trust[i+1])
		if e != nil {
			return nil, e
		}
		p.credentials[i], err = cert.DetachCredential()
		cert.Release()
		if err != nil {
			return nil, err
		}
		if p.credentials[i].Scope().Role != uint64(i) {
			return nil, resourcev4.ErrConfiguration
		}
	}
	client, server := p.credentials[0].Scope(), p.credentials[1].Scope()
	if client.Tenant != server.Tenant || client.Audience != server.Audience || client.Profile != server.Profile {
		return nil, resourcev4.ErrConfiguration
	}
	if err = p.checkCredentials(); err != nil {
		return nil, err
	}
	if tunnels != nil {
		if err = p.prepareArtifactSourceTunnels(tunnels); err != nil {
			return nil, err
		}
		p.path = "/issue/artifact"
	}
	borrow, err := dependencies.Borrow()
	if err != nil {
		return nil, err
	}
	p.provider, err = NewHTTPSBootstrapProvider(c.HTTPS, providerReservation, borrow)
	borrow.Release()
	if err != nil {
		return nil, err
	}
	// TLS trust and private client identity now belong to the physical provider.
	p.c.HTTPS = HTTPSBootstrapConfig{}
	p.leaseCharge, err = sessionv4.ArtifactLeaseCharge(c.MapBytes, c.MapNodes, c.LeaseRuntimeBytes, max(1, len(tunnels)))
	if err != nil {
		return nil, err
	}
	p.response = make([]byte, 65536)
	adopted = true
	return p, nil
}

func (p *DirectIssueSource) checkCredentials() error {
	for i, credential := range p.credentials {
		validation, err := p.c.Trust[i+1].ResolveCredential(credential)
		if err != nil {
			return err
		}
		if _, err = validation.CheckMaterialCredential(credential, credential.Scope().ExpiresMS, p.reservation); err != nil {
			return err
		}
	}
	return p.checkArtifactSourceTunnels()
}

func (p *DirectIssueSource) AcquireLease(ctx context.Context, q sessionv4.MaterialLeaseRequest) (*sessionv4.ArtifactLease, error) {
	return p.acquireLease(ctx, q, nil)
}

func (p *DirectIssueSource) acquireLease(ctx context.Context, q sessionv4.MaterialLeaseRequest, preparation *directIssuePreparation) (lease *sessionv4.ArtifactLease, err error) {
	if p == nil || ctx == nil {
		return nil, resourcev4.ErrConfiguration
	}
	if preparation != nil && preparation.owner != p {
		return nil, resourcev4.ErrOwner
	}
	if err = q.Requirements.Connection.CheckProfile(q.Requirements.ApplicationProfile); err != nil {
		return nil, err
	}
	q.Requirements.Connection.ApplicationProfile = nil
	if !p.mu.TryLock() {
		return nil, ErrBusy
	}
	if p.closed || p.busy || preparation == nil && p.preparation != nil {
		p.mu.Unlock()
		return nil, ErrBusy
	}
	err = p.reservation.Check()
	if err == nil {
		err = p.shared.Check()
	}
	if err != nil {
		p.mu.Unlock()
		return nil, err
	}
	if !p.validRequestLocked(q) {
		p.mu.Unlock()
		return nil, resourcev4.ErrConfiguration
	}
	var ref resourcev4.Reference
	if preparation == nil {
		ref, err = p.reserveLeaseLocked()
	} else {
		err = preparation.checkLocked()
		if err == nil && preparation.request != q {
			err = resourcev4.ErrOwner
		}
		if err == nil {
			ref = preparation.reservation
			preparation.started = true
		}
	}
	if err != nil {
		p.mu.Unlock()
		return nil, err
	}
	call := newHTTPSCallContext(p.provider)
	p.cancel, p.busy = call.stopCall, true
	c, provider := p.c, p.provider
	p.mu.Unlock()
	returned := false
	defer func() {
		if recovered := recover(); recovered != nil || !returned {
			err = ErrControlTaskExit
			call.cancel(err)
		}
		call.finish()
		ref.Release()
		p.mu.Lock()
		defer p.mu.Unlock()
		if err == nil {
			err = call.cause()
		}
		if err == nil {
			err = p.reservation.Check()
		}
		if err == nil {
			err = p.shared.Check()
		}
		if (p.closed || preparation != nil && preparation.closed) && err == nil {
			err = resourcev4.ErrClosed
		}
		if err != nil && lease != nil {
			lease.Close()
			lease = nil
		}
		clear(p.request[:])
		clear(p.response)
		call.stopCall()
		p.cancel, p.busy = nil, false
		p.releasePreparationLocked(preparation)
		p.cleanupLocked()
	}()
	if err = call.start(ctx); err == nil {
		lease, err = p.acquireLeaseBody(call, c, provider, ref, preparation)
	}
	returned = true
	return lease, err
}

func (p *DirectIssueSource) acquireLeaseBody(call *controlCallContext, c DirectIssueSourceConfig, provider *HTTPSBootstrapProvider, ref resourcev4.Reference, preparation *directIssuePreparation) (lease *sessionv4.ArtifactLease, err error) {
	if err = p.checkCredentials(); err != nil {
		return nil, err
	}
	p.request[0], p.request[1], p.request[2] = 0x81, 0x58, 0x20
	if _, err = rand.Read(p.request[3:]); err != nil {
		return nil, err
	}
	if [32]byte(p.request[3:]) == ([32]byte{}) {
		return nil, resourcev4.ErrConfiguration
	}
	if err = call.Err(); err != nil {
		return nil, err
	}
	n, _, err := provider.exchange(call, http.MethodPost, p.path, nil, p.request[:], p.response, false, false)
	if err != nil {
		return nil, err
	}
	if err = p.checkCredentials(); err != nil {
		return nil, err
	}
	if err = call.Err(); err != nil {
		return nil, err
	}
	config := sessionv4.ArtifactLeaseBytesConfig{Artifact: p.response[:n:n], ClientCertificate: c.ClientCertificate, ServerCertificate: c.ServerCertificate, Source: "live_authority", ActivationSigningKeyID: c.ActivationSigningKeyID, Trust: c.Trust, MapBytes: c.MapBytes, MapNodes: c.MapNodes, RuntimeBytes: c.LeaseRuntimeBytes}
	if p.tunnels != nil {
		if err = p.populateArtifactSourceTunnels(&config); err != nil {
			return nil, err
		}
		defer p.tunnels.clearMaterial()
	}
	if preparation == nil {
		lease, err = sessionv4.NewArtifactLeaseFromBytes(config, ref, p.dependencies)
	} else {
		lease, err = sessionv4.NewPreparedArtifactLeaseFromBytes(config, ref, p.dependencies, preparation.references)
	}
	return lease, err
}

func (p *DirectIssueSource) Close() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	if p.preparation != nil {
		p.preparation.closed = true
		p.releasePreparationLocked(p.preparation)
	}
	if p.cancel != nil {
		p.cancel()
	}
	if p.provider != nil {
		p.provider.Close()
	}
	p.cleanupLocked()
}
func (p *DirectIssueSource) cleanupLocked() {
	if !p.closed || p.busy || p.preparation != nil || p.cleaned {
		return
	}
	if p.provider != nil && p.provider.Retire() != nil {
		return
	}
	clear(p.request[:])
	clear(p.response)
	clear(p.c.ClientCertificate)
	clear(p.c.ServerCertificate)
	p.response, p.provider = nil, nil
	p.credentials = [2]*protocolv4.Credential{}
	p.tunnels.release()
	p.tunnels = nil
	for i, ref := range p.trustRefs {
		ref.Release()
		p.trustRefs[i] = resourcev4.Reference{}
	}
	p.c = DirectIssueSourceConfig{}
	p.accounts = [8]resourcev4.Account{}
	p.reservation.Release()
	p.shared.Release()
	p.reservation, p.shared = resourcev4.Reference{}, resourcev4.Reference{}
	p.dependencies = resourcev4.Reference{}
	p.cleaned = true
	close(p.done)
}
func (p *DirectIssueSource) WaitCleanup(ctx context.Context) error {
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
func (*DirectIssueSource) String() string   { return "DirectIssueSource(<redacted>)" }
func (*DirectIssueSource) GoString() string { return "DirectIssueSource(<redacted>)" }
func (*DirectIssueSource) MarshalJSON() ([]byte, error) {
	return []byte(`"DirectIssueSource(<redacted>)"`), nil
}

var _ sessionv4.MaterialLeaseProvider = (*DirectIssueSource)(nil)

// PreparationNamespaces reads only the source's immutable independent trust
// owners. It performs no issuer request, credential/key callback or clock read.
func (p *DirectIssueSource) PreparationNamespaces(clock *timev4.Clock, environment resourcev4.Reference) (namespaces [3]*protocolv4.LiveNamespace, err error) {
	if p == nil {
		return namespaces, resourcev4.ErrOwner
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return namespaces, resourcev4.ErrClosed
	}
	if clock != p.c.Clock {
		return namespaces, resourcev4.ErrOwner
	}
	if err = p.reservation.CheckSameEnvironment(environment); err != nil {
		return namespaces, err
	}
	for i, trust := range p.c.Trust {
		namespaces[i], err = trust.NamespaceForPreparation(clock, environment)
		if err != nil {
			return namespaces, err
		}
	}
	return namespaces, nil
}

var _ sessionv4.MaterialNamespaceProvider = (*DirectIssueSource)(nil)
