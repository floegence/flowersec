package interopharness

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net/netip"
	"net/url"
	"strconv"
	"time"

	fs "github.com/floegence/flowersec/flowersec-go/v6"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/assemblyv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/controlv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

// RegisteredPoolAllowInstallation is independently installed transport policy.
// B owns the server key and fixed A certificate pin; A owns only its client key.
// Registration metadata does not select any TLS identity, trust or destination.
type RegisteredPoolAllowInstallation struct {
	Endpoint             string                           `json:"endpoint"`
	TLS                  RegisteredControlTLSInstallation `json:"tls"`
	ClientCertificateDER []byte                           `json:"clientCertificateDER,omitempty"`
	WorkMS               string                           `json:"workMS"`
}

type RegisteredPoolClientInstallation struct {
	WireRevision int                             `json:"wire_revision"`
	Tenant       string                          `json:"tenant"`
	Audience     string                          `json:"audience"`
	ServerAllow  RegisteredPoolAllowInstallation `json:"server_allow"`
}

// PoolServerAllowBinding is public metadata from the original B registration.
// Its endpoint must match A's local installation before Connect is attempted.
type PoolServerAllowBinding struct {
	Endpoint    string `json:"endpoint"`
	Recipient   string `json:"recipient"`
	Incarnation string `json:"incarnation"`
}

func installedPoolAllowAddress(installation RegisteredPoolAllowInstallation) (netip.AddrPort, *url.URL, error) {
	endpoint, err := url.Parse(installation.Endpoint)
	if err != nil || !materialHTTPS(installation.Endpoint) || endpoint.Path != "/tunnel/server-allow" || endpoint.RawPath != "" {
		return netip.AddrPort{}, nil, errors.New("pool server Allow requires its complete installed endpoint")
	}
	address, err := netip.ParseAddr(endpoint.Hostname())
	if err != nil || !address.IsLoopback() || address.Zone() != "" {
		return netip.AddrPort{}, nil, errors.New("pool server Allow requires its installed numeric loopback address")
	}
	port, err := strconv.ParseUint(endpoint.Port(), 10, 16)
	if err != nil || port == 0 {
		return netip.AddrPort{}, nil, errors.New("pool server Allow requires its installed port")
	}
	work, err := canonicalMaterialUint(installation.WorkMS, true)
	if err != nil || work > 2000 {
		return netip.AddrPort{}, nil, errors.New("pool server Allow exceeds its original publication window")
	}
	tlsInput := installation.TLS
	if len(tlsInput.CertificatePEM) == 0 || len(tlsInput.CertificatePEM) > 262144 || len(tlsInput.PrivateKeyPEM) == 0 || len(tlsInput.PrivateKeyPEM) > 65536 || len(tlsInput.TrustPEM) == 0 || len(tlsInput.TrustPEM) > 262144 {
		return netip.AddrPort{}, nil, errors.New("pool server Allow lacks its bounded independent TLS identity")
	}
	return netip.AddrPortFrom(address, uint16(port)), endpoint, nil
}

func (s *TunnelServer) PoolServerAllowBinding() (*PoolServerAllowBinding, error) {
	if s == nil || s.Client == nil || s.Client.Material.Source != "preauthorized_pool" {
		return nil, errors.New("original pool registration required")
	}
	binding, err := s.Registration.Binding()
	if err != nil {
		return nil, err
	}
	return &PoolServerAllowBinding{Endpoint: s.address, Recipient: base64.StdEncoding.EncodeToString(binding.Recipient[:]), Incarnation: base64.StdEncoding.EncodeToString(binding.Incarnation[:])}, nil
}

// LocalPoolClientConfiguration exposes the independently provisioned sender
// only for the same-process engineering setup. Registered peers use their own
// installed A deployment and obtain only PoolServerAllowBinding from B.
func (s *TunnelServer) LocalPoolClientConfiguration() (*RegisteredPoolClientInstallation, *PoolServerAllowBinding, error) {
	if s == nil || s.localPoolClient == nil {
		return nil, nil, errors.New("local original pool sender installation required")
	}
	binding, err := s.PoolServerAllowBinding()
	if err != nil {
		return nil, nil, err
	}
	installed := *s.localPoolClient
	return &installed, binding, nil
}

// BrowserPoolServerAllowInstallation is trusted host installation input.
// The browser receives only the local forwarding capability and public B IDs;
// its original Connect supplies the verified canonical instruction after TxA-P.
type BrowserPoolServerAllowInstallation struct {
	Installation RegisteredPoolClientInstallation `json:"installation"`
	Binding      PoolServerAllowBinding           `json:"binding"`
}

func browserPoolServerAllowInstallation(installation *RegisteredPoolClientInstallation, binding *PoolServerAllowBinding) (*BrowserPoolServerAllowInstallation, error) {
	if installation == nil || installation.WireRevision != WireRevision || !materialIdentifier(installation.Tenant) || !materialIdentifier(installation.Audience) || binding == nil || installation.ServerAllow.Endpoint != binding.Endpoint || len(installation.ServerAllow.ClientCertificateDER) != 0 {
		return nil, errors.New("original browser pool sender installation and registration required")
	}
	if _, _, err := installedPoolAllowAddress(installation.ServerAllow); err != nil {
		return nil, err
	}
	for _, encoded := range []string{binding.Recipient, binding.Incarnation} {
		value, err := controlv4.DecodeRegisteredControlBytes(encoded, 16, 16)
		if err != nil {
			return nil, err
		}
		zero := zeroLiveMaterial(value)
		clear(value)
		if zero {
			return nil, errors.New("original browser pool binding is empty")
		}
	}
	return &BrowserPoolServerAllowInstallation{Installation: *installation, Binding: *binding}, nil
}

func (s *TunnelServer) BrowserPoolServerAllowInstallation() (*BrowserPoolServerAllowInstallation, error) {
	installation, binding, err := s.LocalPoolClientConfiguration()
	if err != nil {
		return nil, err
	}
	return browserPoolServerAllowInstallation(installation, binding)
}

// The scope selects only the native socket namespace; it supplies no grant,
// spend result, trust decision or publication owner.
type scopedPoolAllowTransport struct {
	transport *controlv4.TunnelServerAllowHTTPSTransport
	scope     assemblyv4.NativeDialScope
}

func (p *scopedPoolAllowTransport) PublishServerAllow(ctx context.Context, request fs.TunnelServerAllowRequest, grant []byte, guard func() error) error {
	return assemblyv4.RunNativeDial(ctx, p.scope, func() error { return p.transport.PublishServerAllow(ctx, request, grant, guard) })
}
func (p *scopedPoolAllowTransport) PrepareServerAllow(request fs.TunnelServerAllowRequest, grant []byte) (fs.TunnelServerAllowPublication, error) {
	publication, err := p.transport.PrepareServerAllow(request, grant)
	if err != nil {
		return nil, err
	}
	return &scopedPoolAllowPublication{publication: publication, scope: p.scope}, nil
}

type scopedPoolAllowPublication struct {
	publication fs.TunnelServerAllowPublication
	scope       assemblyv4.NativeDialScope
}

func (p *scopedPoolAllowPublication) PublishServerAllow(ctx context.Context, guard func() error) error {
	return assemblyv4.RunNativeDial(ctx, p.scope, func() error { return p.publication.PublishServerAllow(ctx, guard) })
}
func (p *scopedPoolAllowPublication) Close() { p.publication.Close() }

func (c *Client) configurePoolServerAllow(ctx context.Context, reporter *Reporter, installed *RegisteredPoolClientInstallation, binding *PoolServerAllowBinding, scope assemblyv4.NativeDialScope) error {
	if c == nil || ctx == nil || c.Material.Source != "preauthorized_pool" || c.Material.Role != 0 || installed == nil || installed.WireRevision != WireRevision || binding == nil || binding.Endpoint != installed.ServerAllow.Endpoint || len(installed.ServerAllow.ClientCertificateDER) != 0 {
		return errors.New("pool Connect requires its independent server Allow installation and original B binding")
	}
	address, endpoint, err := installedPoolAllowAddress(installed.ServerAllow)
	if err != nil {
		return err
	}
	workMS, err := canonicalMaterialUint(installed.ServerAllow.WorkMS, true)
	if err != nil {
		return err
	}
	recipient, err := controlv4.DecodeRegisteredControlBytes(binding.Recipient, 16, 16)
	if err != nil {
		return err
	}
	defer clear(recipient)
	incarnation, err := controlv4.DecodeRegisteredControlBytes(binding.Incarnation, 16, 16)
	if err != nil {
		return err
	}
	defer clear(incarnation)
	if zeroLiveMaterial(recipient) || zeroLiveMaterial(incarnation) {
		return errors.New("original pool B binding is empty")
	}
	h := c.Runtime.Authority
	var sdkBytes uint64
	for _, schema := range []string{"Artifact", "Grant"} {
		n, err := protocolv4.SignedMapBackingBytes(schema, 65536, 4096)
		if err != nil {
			return err
		}
		sdkBytes += n
	}
	// Reserve parser and TLS setup backing before verifying the original maps.
	setup := h.Reserve(resourcev4.Vector{resourcev4.SDKBytes: sdkBytes + 1048576, resourcev4.ProviderBytes: 1048576, resourcev4.Items: 1})
	reporter.Cleanup(setup.Release)
	certificate, err := tls.X509KeyPair([]byte(installed.ServerAllow.TLS.CertificatePEM), []byte(installed.ServerAllow.TLS.PrivateKeyPEM))
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(installed.ServerAllow.TLS.TrustPEM)) {
		return errors.New("installed pool Allow trust is empty")
	}
	parentCodec, err := protocolv4.NewSignedMapCodec("Artifact", 65536, 4096)
	if err != nil {
		return err
	}
	parent, err := parentCodec.VerifyCredential(c.Material.Artifact, h.Lease.Trust[0])
	if err != nil {
		return err
	}
	defer parent.Release()
	tenant, tenantOK := parent.Field("tenant_id").Text()
	audience, audienceOK := parent.Field("audience").Text()
	if !tenantOK || !audienceOK || tenant != installed.Tenant || audience != installed.Audience {
		return errors.New("pool Allow installation differs from verified original parent")
	}
	var wire []byte
	for _, entry := range c.Material.Tunnels {
		if entry.CandidateIndex == 0 && entry.Role == 1 {
			if wire != nil {
				return errors.New("duplicate original server Grant")
			}
			wire = entry.Grant
		}
	}
	if len(wire) == 0 {
		return errors.New("original pool Connect has no server Grant")
	}
	codec, err := protocolv4.NewSignedMapCodec("Grant", 65536, 4096)
	if err != nil {
		return err
	}
	grant, err := codec.VerifyCredential(wire, h.Lease.Trust[0])
	if err != nil {
		return err
	}
	reporter.Cleanup(grant.Release)
	credential, err := grant.DetachCredential()
	if err != nil {
		return err
	}
	validation, err := h.Lease.Trust[0].ResolveCredential(credential)
	if err != nil {
		return err
	}
	// Grant closure, activation and exact winner are checked again by the
	// existing establishment's prepareTunnelServerAllow before TxA-P.
	config := controlv4.TunnelServerAllowHTTPSConfig{HTTPS: controlv4.HTTPSBootstrapConfig{BaseURL: "https://" + endpoint.Host, RemoteAddress: address, TLS: &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}, RootCAs: roots, ServerName: endpoint.Hostname(), SessionTicketsDisabled: true}, HeaderBytes: 8192, Timeout: time.Duration(workMS) * time.Millisecond, RuntimeBytes: 65536, ProviderRuntimeBytes: 4 << 20}, RuntimeBytes: 65536}
	cost, err := controlv4.TunnelServerAllowHTTPSTransportCharge(config)
	if err != nil {
		return err
	}
	providerCost, err := controlv4.HTTPSBootstrapCharge(config.HTTPS)
	if err != nil {
		return err
	}
	transport, err := controlv4.NewTunnelServerAllowHTTPSTransport(config, h.Reserve(cost), h.Reserve(providerCost), h.Environment)
	if err != nil {
		return err
	}
	reporter.Cleanup(func() {
		transport.Close()
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		reporter.ErrorIf(transport.WaitCleanup(cleanup))
	})
	c.Runtime.ServerAllow = fs.TunnelServerAllowConfig{Provider: &scopedPoolAllowTransport{transport: transport, scope: scope}, Recipient: [16]byte(recipient), Incarnation: [16]byte(incarnation), Grant: grant, Validation: validation}
	return nil
}
