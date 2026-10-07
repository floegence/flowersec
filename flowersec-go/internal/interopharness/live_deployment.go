package interopharness

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"net/url"
	"reflect"
	"strconv"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/controlv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

type RegisteredControlTLSInstallation struct {
	CertificatePEM string `json:"certificatePEM"`
	PrivateKeyPEM  string `json:"privateKeyPEM"`
	TrustPEM       string `json:"trustPEM"`
}
type RegisteredControlInstallation struct {
	Endpoint  string                           `json:"endpoint"`
	Authority string                           `json:"authority"`
	TLS       RegisteredControlTLSInstallation `json:"tls"`
	WorkMS    string                           `json:"workMS"`
}

// RegisteredLiveClientInstallation must come from independent application
// deployment input. Material can be compared to it but cannot construct it.
type RegisteredLiveClientInstallation struct {
	Tenant       string                         `json:"tenant"`
	Audience     string                         `json:"audience"`
	Control      RegisteredControlInstallation  `json:"control"`
	RelayControl *RegisteredControlInstallation `json:"relay_control,omitempty"`
}

// RegisteredLiveServerDeployment is B's independently installed registry,
// identity and network policy. Neither live_receive nor a relay publication may
// create or replace this installation.
type RegisteredLiveServerDeployment struct {
	WireRevision     int                              `json:"wire_revision"`
	RegistrationJSON string                           `json:"registration_json"`
	IdentitySeed     []byte                           `json:"identitySeed"`
	NoiseSeed        []byte                           `json:"noiseSeed"`
	RelayCertificate []byte                           `json:"relayCertificate"`
	RelayAudience    string                           `json:"relayAudience"`
	RelayService     string                           `json:"relayService"`
	RelaySubject     string                           `json:"relaySubject"`
	Control          RegisteredControlInstallation    `json:"control"`
	RelayControl     *RegisteredControlInstallation   `json:"relay_control,omitempty"`
	ServerAllow      *RegisteredPoolAllowInstallation `json:"server_allow,omitempty"`
	TrustPEM         string                           `json:"trustPEM"`
	Origin           string                           `json:"origin"`
	CertificatePEM   string                           `json:"certificatePEM"`
	PrivateKeyPEM    string                           `json:"privateKeyPEM"`
}

func decodeInstalledLiveMaterial(wire string) (Material, error) {
	var material Material
	if len(wire) == 0 || len(wire) > 1048576 {
		return material, errors.New("installed live registry exceeds its input bound")
	}
	body := []byte(wire)
	defer clear(body)
	decoded := false
	defer func() {
		if !decoded {
			releaseOwnedMaterial(&material)
		}
	}()
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&material); err != nil {
		return Material{}, err
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return Material{}, errors.New("installed live registry has trailing JSON")
	}
	decoded = true
	return material, nil
}

// ServerMaterial returns only B's local installed pending registry. A paired
// publication is compared against it before any trust owner or socket is built.
func (d *RegisteredLiveServerDeployment) ServerMaterial(publication string, trustPEM, origin string) (Material, *RegisteredLiveClientInstallation, error) {
	if d == nil || d.WireRevision != WireRevision || len(d.IdentitySeed) != 32 || len(d.NoiseSeed) != 32 || zeroLiveMaterial(d.IdentitySeed) || zeroLiveMaterial(d.NoiseSeed) || len(d.RelayCertificate) == 0 || len(d.RelayCertificate) > 16384 || !materialIdentifier(d.RelayAudience) || !materialIdentifier(d.RelayService) || !materialIdentifier(d.RelaySubject) || len(d.CertificatePEM) > 262144 || len(d.PrivateKeyPEM) > 65536 || d.TrustPEM == "" || len(d.TrustPEM) > 1048576 || d.TrustPEM != trustPEM || d.Origin == "" || len(d.Origin) > 2048 || d.Origin != origin {
		return Material{}, nil, errors.New("live B requires its complete independent installation")
	}
	installed, err := decodeInstalledLiveMaterial(d.RegistrationJSON)
	if err != nil {
		return Material{}, nil, err
	}
	adopted := false
	defer func() {
		if !adopted {
			releaseOwnedMaterial(&installed)
		}
	}()
	installed.Role = 1
	clear(installed.IdentitySeed)
	clear(installed.DHSeed)
	installed.IdentitySeed = append([]byte(nil), d.IdentitySeed...)
	installed.DHSeed = append([]byte(nil), d.NoiseSeed...)
	pool := installed.Source == "preauthorized_pool"
	if pool {
		if d.ServerAllow == nil {
			return Material{}, nil, errors.New("pool B requires its independent server Allow installation")
		}
		if _, _, err = installedPoolAllowAddress(*d.ServerAllow); err != nil {
			return Material{}, nil, err
		}
		if len(d.ServerAllow.ClientCertificateDER) == 0 || len(d.ServerAllow.ClientCertificateDER) > 16384 {
			return Material{}, nil, errors.New("pool B requires its independently pinned Allow sender")
		}
		if len(installed.Tunnels) != 0 || d.Control.Endpoint == "" {
			return Material{}, nil, errors.New("pool B requires an independently installed unissued registry")
		}
	} else if installed.Source != "live_authority" || len(installed.Tunnels) != 2 {
		return Material{}, nil, errors.New("live B registry must contain its pending paired Grant policy")
	}
	if _, err = installed.JSON(); err != nil {
		return Material{}, nil, err
	}
	for _, entry := range installed.Tunnels {
		if !bytes.Equal(entry.RelayCertificate, d.RelayCertificate) || entry.LiveGrant == nil || entry.LiveGrant.Audience != d.RelayAudience || entry.LiveGrant.Service != d.RelayService {
			return Material{}, nil, errors.New("live B relay policy differs from its installed registry")
		}
	}
	codec, err := protocolv4.NewDecoder(65536, 4096)
	if err != nil {
		return Material{}, nil, err
	}
	relay, err := codec.DecodeMap(d.RelayCertificate, "IdentityCertificate", protocolv4.DecodeContext{})
	if err != nil {
		return Material{}, nil, err
	}
	subject, ok := relay.Root().Named("IdentityCertificate", "subject_id").Text()
	relay.Release()
	if !ok || subject != d.RelaySubject {
		return Material{}, nil, errors.New("live B relay subject differs from its installed certificate")
	}
	parent, err := codec.DecodeMap(installed.Artifact, "Artifact", protocolv4.DecodeContext{})
	if err != nil {
		return Material{}, nil, err
	}
	tenant, tenantOK := parent.Root().Named("Artifact", "tenant_id").Text()
	audience, audienceOK := parent.Root().Named("Artifact", "audience").Text()
	parent.Release()
	if !tenantOK || !audienceOK {
		return Material{}, nil, errors.New("live B registry has no application binding")
	}
	if publication != "" {
		delivered, err := decodeInstalledLiveMaterial(publication)
		if err != nil {
			return Material{}, nil, err
		}
		defer releaseOwnedMaterial(&delivered)
		if pool {
			// Grants are a late operation payload. Compare the immutable
			// registry separately and always return the local installation.
			if len(delivered.Tunnels) != 0 && len(delivered.Tunnels) != 2 {
				return Material{}, nil, errors.New("pool B publication has an invalid paired Grant payload")
			}
			delivered.Tunnels = installed.Tunnels
		}
		if delivered.Role != 1 || !bytes.Equal(delivered.IdentitySeed, d.IdentitySeed) || !bytes.Equal(delivered.DHSeed, d.NoiseSeed) || !reflect.DeepEqual(delivered, installed) {
			return Material{}, nil, errors.New("relay publication differs from independently installed live B registry")
		}
	}
	adopted = true
	return installed, &RegisteredLiveClientInstallation{Tenant: tenant, Audience: audience, Control: d.Control, RelayControl: d.RelayControl}, nil
}

type registeredPeerSigner struct{ key ed25519.PrivateKey }

func (s registeredPeerSigner) PublicKey() []byte {
	return append([]byte(nil), s.key.Public().(ed25519.PublicKey)...)
}
func (s registeredPeerSigner) Sign(message []byte) ([]byte, error) {
	return ed25519.Sign(s.key, message), nil
}

func newRegisteredLiveControl(ctx context.Context, reporter *Reporter, h *sessionv4.PublicQUICTestHarness, material Material, installation *RegisteredLiveClientInstallation, bindings ...sessionv4.TunnelServerAllowRequest) (sessionv4.LiveControlConfig, [16]byte, error) {
	var recipient [16]byte
	if ctx == nil || installation == nil || (material.Role > 1) || material.Source != "live_authority" || !materialIdentifier(installation.Tenant) || !materialIdentifier(installation.Audience) || !materialIdentifier(installation.Control.Authority) || installation.Control.Endpoint != material.LiveControlBaseURL {
		return sessionv4.LiveControlConfig{}, recipient, errors.New("live client requires its independent installed original control binding")
	}
	// This explicit engineering peer uses a fixed local control deployment. No
	// DNS record, peer hint, ambient CA or proxy selects its numeric socket.
	endpoint, err := url.Parse(installation.Control.Endpoint)
	if err != nil || !materialHTTPS(installation.Control.Endpoint) || endpoint.Path != "/flowersec/control/live" || endpoint.RawPath != "" {
		return sessionv4.LiveControlConfig{}, recipient, errors.New("invalid installed registered live endpoint")
	}
	address, err := netip.ParseAddr(endpoint.Hostname())
	if endpoint.Hostname() == "localhost" {
		address = netip.MustParseAddr("127.0.0.1")
		err = nil
	}
	if err != nil || !address.IsLoopback() {
		return sessionv4.LiveControlConfig{}, recipient, errors.New("registered engineering control requires its installed loopback address")
	}
	port, err := strconv.ParseUint(endpoint.Port(), 10, 16)
	if err != nil || port == 0 {
		return sessionv4.LiveControlConfig{}, recipient, errors.New("registered live control requires an explicit port")
	}
	work, err := canonicalMaterialUint(installation.Control.WorkMS, true)
	if err != nil || work > 90000 {
		return sessionv4.LiveControlConfig{}, recipient, errors.New("registered live control work exceeds its installed bound")
	}
	tlsInput := installation.Control.TLS
	if len(tlsInput.CertificatePEM) == 0 || len(tlsInput.CertificatePEM) > 262144 || len(tlsInput.PrivateKeyPEM) == 0 || len(tlsInput.PrivateKeyPEM) > 65536 || len(tlsInput.TrustPEM) == 0 || len(tlsInput.TrustPEM) > 262144 {
		return sessionv4.LiveControlConfig{}, recipient, errors.New("registered live control lacks its bounded independent TLS identity")
	}
	certificate, err := tls.X509KeyPair([]byte(tlsInput.CertificatePEM), []byte(tlsInput.PrivateKeyPEM))
	if err != nil {
		return sessionv4.LiveControlConfig{}, recipient, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(tlsInput.TrustPEM)) {
		return sessionv4.LiveControlConfig{}, recipient, errors.New("registered live control trust is empty")
	}

	codec, err := protocolv4.NewSignedMapCodec("Artifact", 65536, 4096)
	if err != nil {
		return sessionv4.LiveControlConfig{}, recipient, err
	}
	artifact, err := codec.VerifyCredential(material.Artifact, h.Lease.Trust[0])
	if err != nil {
		return sessionv4.LiveControlConfig{}, recipient, err
	}
	defer artifact.Release()
	digest, err := artifact.Digest("artifact_digest")
	if err != nil {
		return sessionv4.LiveControlConfig{}, recipient, err
	}
	tenant, ok := artifact.Field("tenant_id").Text()
	audience, audienceOK := artifact.Field("audience").Text()
	if !ok || !audienceOK || tenant != installation.Tenant || audience != installation.Audience {
		return sessionv4.LiveControlConfig{}, recipient, errors.New("verified live parent differs from its independent application installation")
	}
	var incarnation []byte
	if material.Role == 1 {
		if len(bindings) != 1 {
			return sessionv4.LiveControlConfig{}, recipient, errors.New("live B control requires its original SDK registration binding")
		}
		binding := bindings[0]
		if binding.Recipient == ([16]byte{}) || binding.Incarnation == ([16]byte{}) || binding.Artifact != digest || binding.Tenant != tenant || binding.Audience != audience || binding.Candidate.Index != 0 || binding.Candidate.RouteDigest != [32]byte(material.RouteDigest) {
			return sessionv4.LiveControlConfig{}, recipient, errors.New("live B control differs from its original SDK registration")
		}
		recipient = binding.Recipient
		incarnation = append([]byte(nil), binding.Incarnation[:]...)
	} else {
		if len(bindings) != 0 {
			return sessionv4.LiveControlConfig{}, recipient, errors.New("live A cannot import B registration metadata")
		}
		incarnation = make([]byte, 32)
		if _, err = rand.Read(incarnation); err != nil || zeroLiveMaterial(incarnation) {
			return sessionv4.LiveControlConfig{}, recipient, errors.New("original live peer incarnation entropy unavailable")
		}
	}
	key := ed25519.NewKeyFromSeed(material.IdentitySeed)
	reporter.Cleanup(func() { clear(key); clear(incarnation) })
	config := controlv4.RegisteredControlConfig{HTTPS: controlv4.HTTPSBootstrapConfig{BaseURL: installation.Control.Endpoint, RemoteAddress: netip.AddrPortFrom(address, uint16(port)), TLS: &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}, RootCAs: roots, ServerName: endpoint.Hostname(), SessionTicketsDisabled: true}, HeaderBytes: 8192, Timeout: time.Duration(work) * time.Millisecond, RuntimeBytes: 65536, ProviderRuntimeBytes: 4 << 20},
		Authority: installation.Control.Authority, Tenant: tenant, Audience: audience, Parent: digest, Candidate: 0, Incarnation: incarnation, Identity: registeredPeerSigner{key: key}, RuntimeBytes: 65536}
	if installation.RelayControl != nil {
		config.Relay, err = newRegisteredEndpointRelay(reporter, h, material, artifact, installation)
		if err != nil {
			return sessionv4.LiveControlConfig{}, recipient, err
		}
	}
	cost, err := controlv4.RegisteredControlTransportCharge(config)
	if err != nil {
		return sessionv4.LiveControlConfig{}, recipient, err
	}
	providerCost, err := controlv4.HTTPSBootstrapCharge(config.HTTPS)
	if err != nil {
		return sessionv4.LiveControlConfig{}, recipient, err
	}
	provider, err := controlv4.NewRegisteredControlTransport(config, h.Reserve(cost), h.Reserve(providerCost), h.Environment)
	if err != nil {
		return sessionv4.LiveControlConfig{}, recipient, err
	}
	reporter.Cleanup(func() {
		provider.Close()
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		reporter.ErrorIf(provider.WaitCleanup(cleanup))
	})
	return sessionv4.LiveControlConfig{Provider: provider, Tunnel: true, RuntimeBytes: 65536}, recipient, nil
}

func engineeringLiveLeaseConfig(reporter *Reporter, h *sessionv4.PublicQUICTestHarness, material Material) sessionv4.ArtifactLeaseBytesConfig {
	config := engineeringLeaseConfig(reporter, material)
	config.Trust = h.Lease.Trust
	codec, err := protocolv4.NewSignedMapCodec("Artifact", 65536, 4096)
	if err != nil {
		reporter.Fatal(err)
	}
	artifact, err := codec.VerifyCredential(material.Artifact, config.Trust[0])
	if err != nil {
		reporter.Fatal(err)
	}
	defer artifact.Release()
	parent, err := artifact.DetachCredential()
	if err != nil {
		reporter.Fatal(err)
	}
	scope := parent.Scope()
	parentNamespace := protocolv4.NamespaceReference{Tenant: scope.Tenant, Authority: scope.Authority, CapacityDigest: scope.CapacityDigest, Generation: scope.Generation, RoleMask: 3}
	for index, entry := range material.Tunnels {
		pending := entry.LiveGrant
		if pending == nil || entry.GrantNamespace != 0 || entry.RelayNamespace != 0 {
			reporter.Fatal("live peer requires one independently bootstrapped original namespace")
		}
		revision, err := canonicalMaterialUint(pending.RevocationPolicyRevision, true)
		if err != nil {
			reporter.Fatal(err)
		}
		expiry, err := canonicalMaterialUint(pending.MaxNotAfterMS, true)
		if err != nil {
			reporter.Fatal(err)
		}
		validation, namespace, err := config.Trust[0].ResolveIssuerPolicy(protocolv4.IssuerPolicySelection{Schema: "Grant", Issuer: [16]byte(pending.IssuerKeyID), Audience: pending.Audience, Service: pending.Service, Role: uint64(entry.Role), Parent: parentNamespace, ParentIssuer: scope.Issuer, PolicyID: pending.RevocationPolicyID, PolicyRevision: revision})
		if err != nil {
			reporter.Fatal(err)
		}
		if namespace.Authority != pending.Authority {
			reporter.Fatal("live Grant namespace differs from its independently installed issuer policy")
		}
		preparation, err := protocolv4.DeriveLiveGrantPreparation(parent, protocolv4.Direction(entry.Role), validation, protocolv4.LiveGrantPreparationConfig{Service: pending.Service, Audience: pending.Audience, IssuedAt: scope.IssuedMS, NotAfterMS: expiry}, h.Environment)
		if err != nil {
			reporter.Fatal(err)
		}
		config.Tunnels[index].LiveGrant = &preparation
		config.Tunnels[index].GrantTrust = config.Trust[0]
		config.Tunnels[index].RelayTrust = config.Trust[0]
	}
	return config
}

func zeroLiveMaterial(value []byte) bool {
	var combined byte
	for _, part := range value {
		combined |= part
	}
	return combined == 0
}
