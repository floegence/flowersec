package interopharness

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/netip"
	"net/url"
	"strconv"
	"sync"
	"time"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/controlv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// The publication is an operation payload. It never replaces B's installed
// registry, identity, bootstrap pins, activation or relay certificate.
type registeredPoolPublication struct {
	mu                                                 sync.Mutex
	control                                            *controlv4.RegisteredControlTransport
	reservation, shared                                resourcev4.Reference
	clientGrant, serverGrant, nonce, lease, projection []byte
	grantDigest                                        [32]byte
	deadline                                           *timev4.Deadline
	acknowledged, consumed, busy, closed               bool
}

func newRegisteredPoolControl(ctx context.Context, reporter *Reporter, h *sessionv4.PublicQUICTestHarness, material Material, d *RegisteredLiveServerDeployment) (*controlv4.RegisteredControlTransport, error) {
	if ctx == nil || d == nil || material.Source != "preauthorized_pool" || material.Role != 1 || len(material.Tunnels) != 0 || !materialIdentifier(d.Control.Authority) || d.RelayControl != nil {
		return nil, errors.New("pool B requires its independently installed tunnel control")
	}
	endpoint, err := url.Parse(d.Control.Endpoint)
	if err != nil || !materialHTTPS(d.Control.Endpoint) || endpoint.Path != "/flowersec/control/tunnel" || endpoint.RawPath != "" {
		return nil, errors.New("invalid installed registered pool endpoint")
	}
	address, err := netip.ParseAddr(endpoint.Hostname())
	if endpoint.Hostname() == "localhost" {
		address, err = netip.MustParseAddr("127.0.0.1"), nil
	}
	if err != nil || !address.IsLoopback() {
		return nil, errors.New("pool control requires its installed numeric loopback address")
	}
	port, err := strconv.ParseUint(endpoint.Port(), 10, 16)
	if err != nil || port == 0 {
		return nil, errors.New("pool control requires an explicit port")
	}
	work, err := canonicalMaterialUint(d.Control.WorkMS, true)
	if err != nil || work > 60000 {
		return nil, errors.New("pool control exceeds its installed work bound")
	}
	tlsInput := d.Control.TLS
	if len(tlsInput.CertificatePEM) == 0 || len(tlsInput.CertificatePEM) > 262144 || len(tlsInput.PrivateKeyPEM) == 0 || len(tlsInput.PrivateKeyPEM) > 65536 || len(tlsInput.TrustPEM) == 0 || len(tlsInput.TrustPEM) > 262144 {
		return nil, errors.New("pool control lacks its bounded installed TLS identity")
	}
	certificate, err := tls.X509KeyPair([]byte(tlsInput.CertificatePEM), []byte(tlsInput.PrivateKeyPEM))
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(tlsInput.TrustPEM)) {
		return nil, errors.New("installed pool control trust is empty")
	}
	codec, err := protocolv4.NewSignedMapCodec("Artifact", 65536, 4096)
	if err != nil {
		return nil, err
	}
	parent, err := codec.VerifyCredential(material.Artifact, h.Lease.Trust[0])
	if err != nil {
		return nil, err
	}
	defer parent.Release()
	digest, err := parent.Digest("artifact_digest")
	if err != nil {
		return nil, err
	}
	tenant, tenantOK := parent.Field("tenant_id").Text()
	audience, audienceOK := parent.Field("audience").Text()
	if !tenantOK || !audienceOK {
		return nil, errors.New("installed pool parent lacks its application binding")
	}
	incarnation := make([]byte, 32)
	if _, err = rand.Read(incarnation); err != nil || zeroLiveMaterial(incarnation) {
		clear(incarnation)
		return nil, errors.New("pool control incarnation entropy unavailable")
	}
	key := ed25519.NewKeyFromSeed(material.IdentitySeed)
	reporter.Cleanup(func() { clear(key); clear(incarnation) })
	config := controlv4.RegisteredControlConfig{HTTPS: controlv4.HTTPSBootstrapConfig{BaseURL: d.Control.Endpoint, RemoteAddress: netip.AddrPortFrom(address, uint16(port)), TLS: &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}, RootCAs: roots, ServerName: endpoint.Hostname(), SessionTicketsDisabled: true}, HeaderBytes: 8192, Timeout: time.Duration(work) * time.Millisecond, RuntimeBytes: 65536, ProviderRuntimeBytes: 4 << 20}, Authority: d.Control.Authority, Tenant: tenant, Audience: audience, Parent: digest, Candidate: 0, Incarnation: incarnation, Identity: registeredPeerSigner{key: key}, RuntimeBytes: 65536, EndpointPath: "/flowersec/control/tunnel"}
	cost, err := controlv4.RegisteredControlTransportCharge(config)
	if err != nil {
		return nil, err
	}
	providerCost, err := controlv4.HTTPSBootstrapCharge(config.HTTPS)
	if err != nil {
		return nil, err
	}
	transport, err := controlv4.NewRegisteredControlTransport(config, h.Reserve(cost), h.Reserve(providerCost), h.Environment)
	if err != nil {
		return nil, err
	}
	reporter.Cleanup(func() {
		transport.Close()
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		reporter.ErrorIf(transport.WaitCleanup(cleanup))
	})
	return transport, nil
}

func prepareRegisteredPool(ctx context.Context, reporter *Reporter, h *sessionv4.PublicQUICTestHarness, material Material, control *controlv4.RegisteredControlTransport) (_ *registeredPoolPublication, err error) {
	codecBytes, err := protocolv4.SignedMapBackingBytes("Grant", 65536, 4096)
	if err != nil {
		return nil, err
	}
	parentBytes, err := protocolv4.DecoderBackingBytes(65536, 4096)
	if err != nil {
		return nil, err
	}
	charge := resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(registeredPoolPublication{})) + uint64(unsafe.Sizeof(registeredPoolAdmissionAuthority{})) + 2*uint64(unsafe.Sizeof(sessionv4.ArtifactLeaseTunnelBytes{})) + uint64(unsafe.Sizeof(timev4.Deadline{})) + 2*65536 + 32 + 161 + 8192 + codecBytes + parentBytes, resourcev4.Items: 1, resourcev4.WorkSlots: 1}
	reservation := h.Reserve(charge)
	owned, err := reservation.Take(charge)
	reservation.Release()
	if err != nil {
		return nil, err
	}
	p := &registeredPoolPublication{control: control, reservation: owned}
	p.shared, err = h.Environment.Borrow()
	if err != nil {
		p.close()
		return nil, err
	}
	reporter.Cleanup(p.close)
	defer func() {
		if err != nil {
			p.close()
		}
	}()
	// Control dispatch shares the installed parent's original monotonic
	// initiation boundary, including clock discontinuity checks.
	parentDecoder, err := protocolv4.NewDecoder(65536, 4096)
	if err != nil {
		return nil, err
	}
	parent, err := parentDecoder.DecodeMap(material.Artifact, "Artifact", protocolv4.DecodeContext{})
	if err != nil {
		return nil, err
	}
	end, ok := parent.Root().Named("Artifact", "initiation_not_after_ms").Uint()
	parent.Release()
	if !ok || end == 0 {
		return nil, errors.New("installed pool parent lacks its initiation boundary")
	}
	p.deadline, err = timev4.NewDeadline(h.Clock, end)
	if err != nil {
		return nil, err
	}
	guard := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return p.check()
	}
	reply, err := control.PrepareRegisteredTunnel(ctx, 0, guard)
	if err != nil {
		return nil, err
	}
	for _, part := range []struct {
		value        string
		target       *[]byte
		limit, exact int
	}{
		{reply.ClientGrant, &p.clientGrant, 65536, 0}, {reply.ServerGrant, &p.serverGrant, 65536, 0},
		{reply.Continuation, &p.nonce, 32, 32}, {reply.Lease, &p.lease, 161, 0}, {reply.Projection, &p.projection, 8192, 0},
	} {
		*part.target, err = controlv4.DecodeRegisteredControlBytes(part.value, part.limit, part.exact)
		if err != nil {
			return nil, err
		}
	}
	if len(p.lease) < 34 || len(p.projection) == 0 || zeroLiveMaterial(p.nonce) {
		return nil, errors.New("pool publication lacks its original winner selection")
	}
	codec, err := protocolv4.NewSignedMapCodec("Grant", 65536, 4096)
	if err != nil {
		return nil, err
	}
	grant, err := codec.VerifyCredential(p.serverGrant, h.Lease.Trust[0])
	if err != nil {
		return nil, err
	}
	defer grant.Release()
	p.grantDigest, err = grant.Digest("grant_digest")
	if err != nil {
		return nil, err
	}
	// Both grants and their complete original closure are verified by the
	// ArtifactLease constructed from this acquisition below. Installed bytes
	// are held separately and never reconstructed from this control reply.
	return p, nil
}

func (p *registeredPoolPublication) tunnels(relay []byte) []sessionv4.ArtifactLeaseTunnelBytes {
	return []sessionv4.ArtifactLeaseTunnelBytes{
		{CandidateIndex: 0, Role: protocolv4.ClientToServer, Grant: p.clientGrant, RelayCertificate: relay},
		{CandidateIndex: 0, Role: protocolv4.ServerToClient, Grant: p.serverGrant, RelayCertificate: relay},
	}
}

func (p *registeredPoolPublication) check() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.checkLocked()
}
func (p *registeredPoolPublication) checkLocked() error {
	if p.closed {
		return resourcev4.ErrClosed
	}
	if err := p.reservation.Check(); err != nil {
		return err
	}
	if err := p.shared.Check(); err != nil {
		return err
	}
	if p.deadline != nil {
		return p.deadline.Check()
	}
	return nil
}
func (p *registeredPoolPublication) acknowledge(ctx context.Context, guard func() error) (err error) {
	p.mu.Lock()
	if err = p.checkLocked(); err != nil {
		p.mu.Unlock()
		return err
	}
	if p.busy || p.acknowledged || p.consumed {
		p.mu.Unlock()
		return resourcev4.ErrOwner
	}
	p.busy = true
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		p.busy = false
		if err != nil {
			p.closed = true
		} else {
			p.acknowledged = true
		}
		p.cleanupLocked()
	}()
	reply, err := p.control.AcknowledgeRegisteredTunnelPreparation(ctx, 0, p.grantDigest[:], p.nonce, func() error {
		if err := guard(); err != nil {
			return err
		}
		return p.check()
	})
	if err != nil {
		return err
	}
	if !reply.Prepared {
		return controlv4.ErrResponse
	}
	return nil
}

// ContinueOriginalParentWinner receives the exact local admission
// selection. Exact bytes are compared before its single remote continuation.
func (p *registeredPoolPublication) continueWinner(ctx context.Context, lease, projection []byte, environment resourcev4.Reference, guard func() error) (err error) {
	p.mu.Lock()
	if err = p.checkLocked(); err != nil {
		p.mu.Unlock()
		return err
	}
	if p.busy || !p.acknowledged || p.consumed {
		p.mu.Unlock()
		return resourcev4.ErrOwner
	}
	p.consumed, p.busy = true, true
	p.mu.Unlock()
	defer func() { p.mu.Lock(); defer p.mu.Unlock(); p.busy, p.closed = false, true; p.cleanupLocked() }()
	if err = p.reservation.CheckSameEnvironment(environment); err != nil {
		return err
	}
	if len(lease) == 0 || len(projection) == 0 || !bytes.Equal(lease, p.lease) || !bytes.Equal(projection, p.projection) {
		return ledgerv4.ErrConflict
	}
	check := func() error {
		if err := guard(); err != nil {
			return err
		}
		return p.check()
	}
	if err = check(); err != nil {
		return err
	}
	reply, err := p.control.ContinueRegisteredTunnelWinner(ctx, 0, p.nonce, check)
	if err != nil {
		return err
	}
	if !reply.Matched {
		return controlv4.ErrResponse
	}
	return check()
}
func (p *registeredPoolPublication) cleanupLocked() {
	if !p.closed || p.busy {
		return
	}
	for _, wire := range [][]byte{p.clientGrant, p.serverGrant, p.nonce, p.lease, p.projection} {
		clear(wire)
	}
	p.clientGrant, p.serverGrant, p.nonce, p.lease, p.projection = nil, nil, nil, nil, nil
	p.grantDigest = [32]byte{}
	p.control = nil
	if p.deadline != nil {
		p.deadline.Cancel()
		p.deadline = nil
	}
	p.shared.Release()
	p.reservation.Release()
	p.shared, p.reservation = resourcev4.Reference{}, resourcev4.Reference{}
}
func (p *registeredPoolPublication) close() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	p.cleanupLocked()
}

type registeredPoolAdmissionAuthority struct {
	ledgerv4.SQLitePoolAdmissionAuthority
	publication *registeredPoolPublication
}

func (a *registeredPoolAdmissionAuthority) ContinueOriginalParentWinner(ctx context.Context, lease, projection []byte, environment resourcev4.Reference, guard func() error) error {
	return a.publication.continueWinner(ctx, lease, projection, environment, guard)
}

// ValidateOriginalPoolPublication compares late detached bytes to the original
// prepare response retained by B. It does not create or replace installation.
func (s *TunnelServer) ValidateOriginalPoolPublication(materialJSON string) error {
	if s == nil || s.Client == nil || s.Client.PoolPublication == nil {
		return resourcev4.ErrOwner
	}
	material, err := decodeInstalledLiveMaterial(materialJSON)
	if err != nil {
		return err
	}
	defer releaseOwnedMaterial(&material)
	if material.Role != 1 || material.Source != "preauthorized_pool" || len(material.Tunnels) != 2 {
		return controlv4.ErrResponse
	}
	p := s.Client.PoolPublication
	p.mu.Lock()
	defer p.mu.Unlock()
	if err = p.checkLocked(); err != nil {
		return err
	}
	if !p.acknowledged {
		return resourcev4.ErrOwner
	}
	var seen [2]bool
	for _, entry := range material.Tunnels {
		if entry.CandidateIndex != 0 || entry.Role > 1 || seen[entry.Role] || entry.GrantNamespace != 0 || entry.RelayNamespace != 0 || entry.LiveGrant != nil || !bytes.Equal(entry.RelayCertificate, s.Client.Runtime.Authority.Lease.Tunnels[entry.Role].RelayCertificate) {
			return controlv4.ErrResponse
		}
		seen[entry.Role] = true
		expected := p.clientGrant
		if entry.Role == 1 {
			expected = p.serverGrant
		}
		if !bytes.Equal(entry.Grant, expected) {
			return controlv4.ErrResponse
		}
	}
	return nil
}
