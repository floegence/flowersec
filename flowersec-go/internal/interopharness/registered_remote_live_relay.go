package interopharness

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/controlv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

// NewRegisteredRemoteLiveAuthority runs only the original issuer service. Relay
// data listeners and the relay ledger belong to the independently installed
// relay process. prepared receives the actual authority listener and the public
// installation path only after the file has been installed durably.
func NewRegisteredRemoteLiveAuthority(ctx context.Context, reporter *Reporter, deployment *RegisteredRelayDeployment, carriers [2]string, endpointListeners [2]bool, prepared func(string, string, string) error) (*RegisteredLiveRelay, error) {
	if deployment == nil || deployment.RemoteRelay == nil || prepared == nil {
		return nil, errors.New("complete original authority remote relay installation is required")
	}
	return newRegisteredLiveAuthority(ctx, reporter, deployment, carriers, endpointListeners, func(endpoint, _ string, installation *RelayPublicLiveInstallation) error {
		if err := installation.Publish(deployment.RemoteRelay.InstallationPath); err != nil {
			return err
		}
		reporter.Cleanup(func() { reporter.ErrorIf(os.Remove(deployment.RemoteRelay.InstallationPath)) })
		return prepared(endpoint, deployment.RemoteRelay.InstallationPath, installation.Profile)
	})
}

func newRegisteredRemoteOriginalLiveRelay(reporter *Reporter, h *sessionv4.PublicQUICTestHarness, d *RegisteredRemoteRelayInstallation, endpointCertificates [2][]byte) (*controlv4.RemoteOriginalLiveRelay, error) {
	if d == nil || len(d.Endpoint) == 0 || len(d.Endpoint) > 2048 || len(d.IssuerCertificateDER) == 0 || len(d.IssuerCertificateDER) > 16384 || d.InstallationPath == "" || !materialIdentifier(d.ServerAdmissionAuthority) {
		return nil, errors.New("original issuer requires its complete remote relay configuration")
	}
	if d.Control.Endpoint != "" && d.Control.Endpoint != d.Endpoint {
		return nil, errors.New("public relay control endpoint differs from original authority installation")
	}
	endpoint, err := url.Parse(d.Endpoint)
	if err != nil {
		return nil, err
	}
	host, err := netip.ParseAddr(d.Control.Host)
	if err != nil || !host.IsValid() || host.IsUnspecified() || host.IsMulticast() || host.Zone() != "" || d.Control.Port == 0 {
		return nil, errors.New("relay control requires one installed numeric listener")
	}
	endpointHost := endpoint.Hostname()
	if endpointHost == "localhost" {
		endpointHost = "127.0.0.1"
	}
	if endpoint.Scheme != "https" || endpointHost != d.Control.Host || endpoint.Port() != strconv.Itoa(int(d.Control.Port)) || endpoint.Path != "/" || endpoint.RawPath != "" || endpoint.RawQuery != "" || endpoint.ForceQuery || endpoint.User != nil || endpoint.Fragment != "" {
		return nil, errors.New("original remote relay HTTPS endpoint differs from its fixed listener")
	}
	work, err := canonicalMaterialUint(d.Control.WorkMS, true)
	if err != nil || work > 30000 {
		return nil, errors.New("original remote relay control duration exceeds its bound")
	}
	if len(d.TLS.CertificatePEM) > 262144 || len(d.TLS.PrivateKeyPEM) > 65536 || len(d.TLS.TrustPEM) > 1048576 || len(d.Control.TLS.CertificatePEM) > 262144 || len(d.Control.TLS.PrivateKeyPEM) > 65536 || len(d.Control.TLS.ClientTrustPEM) > 1048576 {
		return nil, errors.New("remote relay TLS installation exceeds its input bound")
	}
	issuer, err := parseRegisteredOwnedTLSIdentity(d.TLS.CertificatePEM, d.TLS.PrivateKeyPEM)
	if err != nil {
		return nil, err
	}
	if len(issuer.Certificate) == 0 || !bytes.Equal(issuer.Certificate[0], d.IssuerCertificateDER) {
		return nil, errors.New("original issuer mTLS certificate differs from the relay's fixed issuer leaf")
	}
	issuerLeaf, err := x509.ParseCertificate(d.IssuerCertificateDER)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(d.TLS.TrustPEM)) {
		return nil, errors.New("issuer requires independently installed relay control trust")
	}
	relay, err := parseRegisteredOwnedTLSIdentity(d.Control.TLS.CertificatePEM, d.Control.TLS.PrivateKeyPEM)
	if err != nil {
		return nil, err
	}
	if len(relay.Certificate) == 0 {
		return nil, errors.New("relay control server identity is missing")
	}
	relayLeaf, err := x509.ParseCertificate(relay.Certificate[0])
	if err != nil {
		return nil, err
	}
	now, err := h.Clock.Sample()
	if err != nil {
		return nil, err
	}
	when := time.UnixMilli(int64(now.UpperMS))
	if _, err = relayLeaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: endpoint.Hostname(), CurrentTime: when, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return nil, err
	}
	clients := x509.NewCertPool()
	if !clients.AppendCertsFromPEM([]byte(d.Control.TLS.ClientTrustPEM)) {
		return nil, errors.New("relay control requires independently installed issuer and endpoint trust")
	}
	if _, err = issuerLeaf.Verify(x509.VerifyOptions{Roots: clients, CurrentTime: when, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return nil, err
	}
	for _, wire := range endpointCertificates {
		leaf, e := x509.ParseCertificate(wire)
		if e != nil {
			return nil, e
		}
		if _, e = leaf.Verify(x509.VerifyOptions{Roots: clients, CurrentTime: when, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); e != nil {
			return nil, e
		}
	}
	config := controlv4.RemoteOriginalLiveRelayConfig{HTTPS: controlv4.HTTPSBootstrapConfig{BaseURL: d.Endpoint, RemoteAddress: netip.AddrPortFrom(host, d.Control.Port), TLS: &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{issuer}, SessionTicketsDisabled: true}, HeaderBytes: 8192, Timeout: time.Duration(work) * time.Millisecond, RuntimeBytes: 65536, ProviderRuntimeBytes: 1 << 20}, RuntimeBytes: 65536}
	charge, provider, err := controlv4.RemoteOriginalLiveRelayCharges(config)
	if err != nil {
		return nil, err
	}
	return controlv4.NewRemoteOriginalLiveRelay(config, h.Reserve(charge), h.Reserve(provider), h.Environment)
}
