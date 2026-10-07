package interopharness

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/netip"
	"net/url"
	"strconv"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/controlv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

func newRegisteredEndpointRelay(reporter *Reporter, h *sessionv4.PublicQUICTestHarness, material Material, parent *protocolv4.SignedMap, installation *RegisteredLiveClientInstallation) (*controlv4.RegisteredEndpointRelay, error) {
	if installation == nil || installation.RelayControl == nil || parent == nil {
		return nil, errors.New("original endpoint requires its independently installed relay control")
	}
	relay := installation.RelayControl
	if !materialIdentifier(relay.Authority) || !materialHTTPS(relay.Endpoint) {
		return nil, errors.New("invalid installed original relay control authority")
	}
	endpoint, err := url.Parse(relay.Endpoint)
	if err != nil || endpoint.Path != "/" || endpoint.RawPath != "" || endpoint.RawQuery != "" || endpoint.ForceQuery || endpoint.Fragment != "" || endpoint.User != nil {
		return nil, errors.New("installed relay control must name its exact root HTTPS endpoint")
	}
	address, err := netip.ParseAddr(endpoint.Hostname())
	if endpoint.Hostname() == "localhost" {
		address = netip.MustParseAddr("127.0.0.1")
		err = nil
	}
	if err != nil || !address.IsLoopback() || address.Zone() != "" {
		return nil, errors.New("engineering relay control requires its independent numeric loopback address")
	}
	port, err := strconv.ParseUint(endpoint.Port(), 10, 16)
	if err != nil || port == 0 {
		return nil, errors.New("original relay control requires one fixed explicit port")
	}
	work, err := canonicalMaterialUint(relay.WorkMS, true)
	if err != nil || work > 30000 {
		return nil, errors.New("original relay control interval exceeds its bound")
	}
	if relay.TLS.CertificatePEM != installation.Control.TLS.CertificatePEM || relay.TLS.PrivateKeyPEM != installation.Control.TLS.PrivateKeyPEM {
		return nil, errors.New("relay control must retain this endpoint's original authority mTLS identity")
	}
	if len(relay.TLS.TrustPEM) == 0 || len(relay.TLS.TrustPEM) > 1048576 {
		return nil, errors.New("original relay control requires independent bounded server trust")
	}
	certificate, err := tls.X509KeyPair([]byte(relay.TLS.CertificatePEM), []byte(relay.TLS.PrivateKeyPEM))
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(relay.TLS.TrustPEM)) {
		return nil, errors.New("original relay control server trust is empty")
	}
	originalRoute, digest, err := parent.CopyCandidateRoute(0, make([]byte, 16384))
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(originalRoute, material.Route) || digest != [32]byte(material.RouteDigest) {
		return nil, errors.New("installed relay route differs from the verified original parent")
	}
	candidateID, ok := parent.Field("candidates").Index(0).Named("Candidate", "candidate_id").ByteString()
	if !ok || len(candidateID) != 16 {
		return nil, errors.New("original relay candidate identity is missing")
	}
	artifact, err := parent.Digest("artifact_digest")
	if err != nil {
		return nil, err
	}
	initiation, ok := parent.Field("initiation_not_after_ms").Uint()
	if !ok || initiation == 0 {
		return nil, errors.New("original relay initiation deadline is missing")
	}
	deadline, err := timev4.NewDeadline(h.Clock, initiation)
	if err != nil {
		return nil, err
	}
	decoder, err := protocolv4.NewDecoder(16384, 1024)
	if err != nil {
		return nil, err
	}
	route, err := decoder.DecodeMap(originalRoute, "Route", protocolv4.DecodeContext{})
	if err != nil {
		return nil, err
	}
	defer route.Release()
	name := "client_leg"
	if material.Role == 1 {
		name = "server_leg"
	}
	listener, ok := route.Root().Named("Route", name).Named("Leg", "listener_role").Uint()
	if !ok || listener != uint64(material.Role) && listener != 2 {
		return nil, errors.New("original relay physical listener role is invalid")
	}
	config := controlv4.RegisteredEndpointRelayConfig{HTTPS: controlv4.HTTPSBootstrapConfig{BaseURL: relay.Endpoint, RemoteAddress: netip.AddrPortFrom(address, uint16(port)), TLS: &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}, RootCAs: roots, ServerName: endpoint.Hostname(), SessionTicketsDisabled: true}, HeaderBytes: 8192, Timeout: time.Duration(work) * time.Millisecond, RuntimeBytes: 65536, ProviderRuntimeBytes: 4 << 20}, Clock: h.Clock, Deadline: deadline, Parent: artifact, Candidate: protocolv4.PoolMember{Index: 0, CandidateID: [16]byte(candidateID), RouteDigest: digest}, Role: protocolv4.Direction(material.Role), Listener: listener == uint64(material.Role), RuntimeBytes: 65536}
	cost, providerCost, err := controlv4.RegisteredEndpointRelayCharges(config)
	if err != nil {
		return nil, err
	}
	accounts := []resourcev4.Account{h.Scope[material.Role].Tenant, h.Scope[material.Role].Session}
	provider, err := controlv4.NewRegisteredEndpointRelay(config, h.Reserve(cost, accounts...), h.Reserve(providerCost, accounts...), h.Environment)
	if err != nil {
		return nil, err
	}
	reporter.Cleanup(func() {
		provider.Close()
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		reporter.ErrorIf(provider.WaitCleanup(cleanup))
	})
	return provider, nil
}
