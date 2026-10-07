package interopharness

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/controlv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/runtimehost"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

type RegisteredRelaySignerInstallation struct {
	Namespace                uint8  `json:"namespace"`
	IssuerKeyID              []byte `json:"issuer_key_id"`
	Seed                     []byte `json:"seed"`
	RevocationPolicyID       string `json:"revocation_policy_id"`
	RevocationPolicyRevision string `json:"revocation_policy_revision"`
}
type RegisteredRelayLiveInstallation struct {
	Host string `json:"host"`
	Port uint16 `json:"port"`
	TLS  struct {
		CertificatePEM string `json:"certificatePEM"`
		PrivateKeyPEM  string `json:"privateKeyPEM"`
		ClientTrustPEM string `json:"clientTrustPEM"`
	} `json:"tls"`
	ClientControlCertificateDER []byte `json:"clientControlCertificateDER"`
	ServerControlCertificateDER []byte `json:"serverControlCertificateDER"`
	SigningKeyID                string `json:"signingKeyID"`
	ActivationSeed              []byte `json:"activationSeed"`
	MaxActivationMS             string `json:"maxActivationMS"`
	MaxSessionMS                string `json:"maxSessionMS"`
	WorkMS                      string `json:"workMS"`
	ApplicationPolicy           string `json:"applicationPolicy"`
}

// RegisteredRelayDeployment is installed before any registration or response.
// NativeTLS fixes listener identities as well as the bootstrap trust root;
// dynamic control material is never promoted into an installation.
type RegisteredRelayDeployment struct {
	WireRevision            int                                  `json:"wire_revision"`
	MaterialPublicationPath string                               `json:"material_publication_path,omitempty"`
	RegistrationJSON        string                               `json:"registration_json"`
	ServerIdentitySeed      []byte                               `json:"server_identity_seed"`
	ServerDHSeed            []byte                               `json:"server_dh_seed"`
	RelayIdentitySeed       []byte                               `json:"relay_identity_seed"`
	RelayCertificate        []byte                               `json:"relay_certificate"`
	Authority               string                               `json:"authority"`
	RelayAudience           string                               `json:"relay_audience"`
	RelaySubject            string                               `json:"relay_subject"`
	Service                 string                               `json:"service"`
	ControlTrustPEM         string                               `json:"control_trust_pem"`
	Origin                  string                               `json:"origin"`
	LiveControl             *RegisteredRelayLiveInstallation     `json:"live_control,omitempty"`
	RemoteRelay             *RegisteredRemoteRelayInstallation   `json:"remote_relay,omitempty"`
	ServerControl           json.RawMessage                      `json:"server_control,omitempty"`
	Signing                 [2]RegisteredRelaySignerInstallation `json:"signing"`
	Limits                  struct {
		EnvelopeBytes      uint64 `json:"envelope_bytes"`
		TotalBytes         string `json:"total_bytes"`
		DatagramBytes      uint64 `json:"datagram_bytes"`
		RateBytesPerSecond string `json:"rate_bytes_per_second"`
		QueueBytes         uint64 `json:"queue_bytes"`
		PendingMappings    uint64 `json:"pending_mappings"`
		ResidentMappings   uint64 `json:"resident_mappings"`
		TotalMappings      uint64 `json:"total_mappings"`
		QueueItems         uint64 `json:"queue_items"`
	} `json:"limits"`
	NativeTLS struct {
		TrustPEM string                           `json:"trustPEM"`
		Relay    RegisteredControlTLSInstallation `json:"relay"`
		Client   RegisteredControlTLSInstallation `json:"client"`
		Server   RegisteredControlTLSInstallation `json:"server"`
	} `json:"native_tls"`
}

// ReleaseOwnedPrivateMaterial is called only by the deployment's process owner
// after its Reporter has joined signing, control and native work. Byte slices
// belong to that owner; immutable PEM and JSON strings are released by dropping
// references instead of modifying memory that other string owners may share.
func (d *RegisteredRelayDeployment) ReleaseOwnedPrivateMaterial() {
	if d == nil {
		return
	}
	clear(d.ServerIdentitySeed)
	d.ServerIdentitySeed = nil
	clear(d.ServerDHSeed)
	d.ServerDHSeed = nil
	clear(d.RelayIdentitySeed)
	d.RelayIdentitySeed = nil
	for side := range d.Signing {
		clear(d.Signing[side].Seed)
		d.Signing[side].Seed = nil
	}
	clear(d.ServerControl)
	d.ServerControl = nil
	d.RegistrationJSON = ""
	d.NativeTLS.Relay.PrivateKeyPEM = ""
	d.NativeTLS.Client.PrivateKeyPEM = ""
	d.NativeTLS.Server.PrivateKeyPEM = ""
	if d.LiveControl != nil {
		clear(d.LiveControl.ActivationSeed)
		d.LiveControl.ActivationSeed = nil
		d.LiveControl.TLS.PrivateKeyPEM = ""
	}
	if d.RemoteRelay != nil {
		d.RemoteRelay.TLS.PrivateKeyPEM = ""
		d.RemoteRelay.Control.TLS.PrivateKeyPEM = ""
	}
}

type RegisteredLiveRelay struct {
	*PoolRelay
	Control            *controlv4.RegisteredLiveAuthority
	Service            *controlv4.LiveAuthorizationHTTPSService
	ControlEndpoint    string
	PublicInstallation *RelayPublicLiveInstallation
}

// NewRegisteredLiveRelay exposes its actual bounded control listener first.
// prepared is called at that boundary; ready is reached only after the original
// B SDK registration has admitted its physical native carrier factory.
func NewRegisteredLiveRelay(ctx context.Context, reporter *Reporter, deployment *RegisteredRelayDeployment, carriers [2]string, endpointListeners [2]bool, prepared func(endpoint, profile string) error) (*RegisteredLiveRelay, error) {
	if prepared == nil {
		return nil, errors.New("original local relay requires its prepared callback")
	}
	if deployment != nil && deployment.RemoteRelay != nil {
		return nil, errors.New("remote original relay requires the live-authority role")
	}
	return newRegisteredLiveAuthority(ctx, reporter, deployment, carriers, endpointListeners, func(endpoint, profile string, _ *RelayPublicLiveInstallation) error {
		return prepared(endpoint, profile)
	})
}

func newRegisteredLiveAuthority(ctx context.Context, reporter *Reporter, deployment *RegisteredRelayDeployment, carriers [2]string, endpointListeners [2]bool, prepared func(string, string, *RelayPublicLiveInstallation) error) (*RegisteredLiveRelay, error) {
	return construct(reporter, func() *RegisteredLiveRelay {
		d := deployment
		if ctx == nil || d == nil || d.WireRevision != 4 || d.LiveControl == nil || len(d.ServerControl) != 0 || prepared == nil || !materialIdentifier(d.Authority) || !materialIdentifier(d.Service) || !materialIdentifier(d.RelayAudience) || !materialIdentifier(d.RelaySubject) || !materialHTTPS(d.Origin) {
			reporter.Fatal("complete independent registered live relay installation is required")
		}
		live := d.LiveControl
		if live.ApplicationPolicy != "allow" || len(live.ActivationSeed) != 32 || len(d.ServerIdentitySeed) != 32 || len(d.ServerDHSeed) != 32 || len(d.RelayIdentitySeed) != 32 || len(d.RelayCertificate) == 0 || len(d.RelayCertificate) > 16384 || len(d.ControlTrustPEM) == 0 || len(d.ControlTrustPEM) > 1048576 {
			reporter.Fatal("registered live relay signer or policy installation is incomplete")
		}
		material, err := decodeInstalledLiveMaterial(d.RegistrationJSON)
		if err != nil {
			reporter.Fatal(err)
		}
		var result *RegisteredLiveRelay
		var publicInstallation *RelayPublicLiveInstallation
		// Registered before any signer, fixture or service owner so this cleanup
		// runs last. The caller owns deployment; only detached constructor material
		// and this result's own string references are retired here.
		reporter.Cleanup(func() {
			releaseOwnedMaterial(&material)
			if result != nil {
				for side := range result.Material {
					releaseOwnedMaterial(&result.Material[side])
				}
				result.ClientTLSPrivateKeyPEM = ""
				result.ServerTLSPrivateKeyPEM = ""
			}
			publicInstallation.ReleaseOwnedPrivateMaterial()
		})
		if material.Source != "live_authority" || len(material.Namespaces) != 1 || len(material.Tunnels) != 2 || material.ActivationSigningKeyID != live.SigningKeyID {
			reporter.Fatal("registered live relay requires its installed pending paired registry")
		}
		if _, err = material.JSON(); err != nil {
			reporter.Fatal(err)
		}
		endpoint, err := url.Parse(material.LiveControlBaseURL)
		if err != nil {
			reporter.Fatal(err)
		}
		host, err := netip.ParseAddr(live.Host)
		if err != nil || !host.IsValid() || host.IsUnspecified() || host.IsMulticast() || host.Zone() != "" || live.Port == 0 {
			reporter.Fatal("registered live control requires one fixed numeric listener")
		}
		endpointHost := endpoint.Hostname()
		if endpointHost == "localhost" {
			endpointHost = "127.0.0.1"
		}
		if endpoint.Scheme != "https" || endpointHost != live.Host || endpoint.Port() != strconv.Itoa(int(live.Port)) || endpoint.Path != "/flowersec/control/live" || endpoint.RawPath != "" || endpoint.RawQuery != "" || endpoint.User != nil || endpoint.Fragment != "" {
			reporter.Fatal("registered live endpoint differs from its installed listener")
		}
		work, err := canonicalMaterialUint(live.WorkMS, true)
		if err != nil || work > 60000 {
			reporter.Fatal("registered live control duration is invalid")
		}
		maxActivation, err := canonicalMaterialUint(live.MaxActivationMS, true)
		if err != nil {
			reporter.Fatal(err)
		}
		maxSession, err := canonicalMaterialUint(live.MaxSessionMS, true)
		if err != nil {
			reporter.Fatal(err)
		}
		limits := protocolv4.RelayGrantLimits{EnvelopeBytes: d.Limits.EnvelopeBytes, DatagramBytes: d.Limits.DatagramBytes, QueueBytes: d.Limits.QueueBytes, PendingMappings: d.Limits.PendingMappings, ResidentMappings: d.Limits.ResidentMappings, TotalMappings: d.Limits.TotalMappings, QueueItems: d.Limits.QueueItems}
		limits.TotalBytes, err = canonicalMaterialUint(d.Limits.TotalBytes, true)
		if err != nil {
			reporter.Fatal(err)
		}
		limits.RateBytesPerSecond, err = canonicalMaterialUint(d.Limits.RateBytesPerSecond, true)
		if err != nil {
			reporter.Fatal(err)
		}
		if limits.EnvelopeBytes == 0 || limits.EnvelopeBytes > 65536+protocolv4.EnvelopePrefixSize || limits.DatagramBytes > 65536 || limits.PendingMappings > uint64(^uint32(0)) || limits.ResidentMappings > uint64(^uint32(0)) {
			reporter.Fatal("registered live forwarding limits exceed bounded runtime widths")
		}
		nativeRoots := x509.NewCertPool()
		if d.NativeTLS.TrustPEM == "" || !nativeRoots.AppendCertsFromPEM([]byte(d.NativeTLS.TrustPEM)) {
			reporter.Fatal("registered live relay requires its independent native TLS trust")
		}
		relayTLS, err := parseRegisteredOwnedTLSIdentity(d.NativeTLS.Relay.CertificatePEM, d.NativeTLS.Relay.PrivateKeyPEM)
		if err != nil {
			reporter.Fatal(err)
		}
		controlTLS, err := parseRegisteredOwnedTLSIdentity(live.TLS.CertificatePEM, live.TLS.PrivateKeyPEM)
		if err != nil {
			reporter.Fatal(err)
		}
		controlRoots := x509.NewCertPool()
		if !controlRoots.AppendCertsFromPEM([]byte(live.TLS.ClientTrustPEM)) {
			reporter.Fatal("registered live control requires its independent mTLS roots")
		}
		reporter.ApplicationProfile = "services"
		record := material.Namespaces[0]
		bootstrap, err := NewHTTPSBootstrap(record, d.ControlTrustPEM)
		if err != nil {
			reporter.Fatal(err)
		}
		reporter.bootstrap = bootstrap
		reporter.Cleanup(bootstrap.Close)
		reporter.rootPin = &protocolv4.NamespaceTrustRoot{Tenant: record.Tenant, Authority: record.Authority, KeyID: [16]byte(record.RootKeyID), PublicKey: [32]byte(record.RootPublicKey), MaxLifetimeMS: 30000000}
		var addresses [2]netip.AddrPort
		var tlsPolicies [2][]byte
		for side := range 2 {
			var kind string
			addresses[side], kind, tlsPolicies[side], err = materialRoute(material.Route, uint8(side))
			if err != nil {
				reporter.Fatal(err)
			}
			if kind != carriers[side] {
				reporter.Fatal("signed original route differs from relay carrier selection")
			}
		}
		parentDecoder, err := protocolv4.NewDecoder(65536, 4096)
		if err != nil {
			reporter.Fatal(err)
		}
		parentDocument, err := parentDecoder.DecodeMap(material.Artifact, "Artifact", protocolv4.DecodeContext{})
		if err != nil {
			reporter.Fatal(err)
		}
		maximum, ok := parentDocument.Root().Named("Artifact", "session_contract").Named("SessionContract", "max_streams").Uint()
		parentDocument.Release()
		if !ok || maximum == 0 || maximum > 512 {
			reporter.Fatal("installed live stream envelope is invalid")
		}
		reporter.MaxStreams = uint32(maximum)
		// This authority consumes the installed pending registry. Construction
		// must not issue a fixture activation before the original live request.
		reporter.originalLiveDeployment = true
		h := sessionv4.NewEngineeringNativeHarness(reporter, "live_authority", material.Profile, carriers[0], addresses[0], tlsPolicies[0], d.Origin, limits.DatagramBytes != 0)
		lease := engineeringLiveLeaseConfig(reporter, h, material)
		var maps [4]*protocolv4.SignedMap
		var validations [4]protocolv4.CredentialValidation
		wires := [4][]byte{material.Artifact, material.ClientCertificate, material.ServerCertificate, d.RelayCertificate}
		for index, schema := range []string{"Artifact", "IdentityCertificate", "IdentityCertificate", "IdentityCertificate"} {
			codec, e := protocolv4.NewSignedMapCodec(schema, 65536, 16384)
			if e != nil {
				reporter.Fatal(e)
			}
			maps[index], e = codec.VerifyCredential(wires[index], h.Lease.Trust[0])
			if e != nil {
				reporter.Fatal(e)
			}
			retained := maps[index]
			reporter.Cleanup(retained.Release)
			credential, e := retained.DetachCredential()
			if e != nil {
				reporter.Fatal(e)
			}
			validations[index], e = h.Lease.Trust[0].ResolveCredential(credential)
			if e != nil {
				reporter.Fatal(e)
			}
		}
		parent, err := maps[0].DetachCredential()
		if err != nil {
			reporter.Fatal(err)
		}
		parentScope := parent.Scope()
		session, err := maps[0].SessionParameters()
		if err != nil {
			reporter.Fatal(err)
		}
		activation, err := h.Lease.Trust[0].ResolveActivation(parent, material.ActivationSigningKeyID, make([]byte, 16384), make([]byte, 16384))
		if err != nil {
			reporter.Fatal(err)
		}
		activationSigner := registeredPeerSigner{key: ed25519.NewKeyFromSeed(live.ActivationSeed)}
		reporter.Cleanup(func() { clear(activationSigner.key) })
		if !bytes.Equal(activationSigner.PublicKey(), activation.Key[:]) {
			reporter.Fatal("installed activation seed differs from independent delegation")
		}
		candidate, routeDigest, err := maps[0].CopyCandidateRoute(0, make([]byte, 16384))
		if err != nil {
			reporter.Fatal(err)
		}
		if !bytes.Equal(candidate, material.Route) || routeDigest != [32]byte(material.RouteDigest) {
			reporter.Fatal("installed live route differs from its signed parent")
		}
		relaySubject, ok := maps[3].Field("subject_id").Text()
		relayKey, keyOK := maps[3].Field("ed25519_public_key").ByteString()
		if !ok || !keyOK || relaySubject != d.RelaySubject {
			reporter.Fatal("installed relay identity differs from its signed certificate")
		}
		relaySigner := registeredPeerSigner{key: ed25519.NewKeyFromSeed(d.RelayIdentitySeed)}
		reporter.Cleanup(func() { clear(relaySigner.key) })
		if !bytes.Equal(relaySigner.PublicKey(), relayKey) {
			reporter.Fatal("installed relay signer differs from its verified identity")
		}
		serverKey, ok := maps[2].Field("ed25519_public_key").ByteString()
		serverIdentityKey := ed25519.NewKeyFromSeed(d.ServerIdentitySeed)
		reporter.Cleanup(func() { clear(serverIdentityKey) })
		if !ok || !bytes.Equal(serverIdentityKey.Public().(ed25519.PublicKey), serverKey) {
			reporter.Fatal("installed B identity seed differs from its verified certificate")
		}
		mapping := protocolv4.RelayIssuerMapping{Parent: protocolv4.NamespaceReference{Tenant: parentScope.Tenant, Authority: parentScope.Authority, CapacityDigest: parentScope.CapacityDigest, Generation: parentScope.Generation, RoleMask: 7}, ParentIssuer: parentScope.Issuer, ParentKey: maps[0].Key(), Activation: activation.Binding, Service: d.Service, RelayAudience: d.RelayAudience, EndpointAudience: parentScope.Audience, Profile: material.Profile}
		var grantIssuance [2]protocolv4.LiveGrantIssuance
		for side := range 2 {
			signing := d.Signing[side]
			entry := material.Tunnels[side]
			if signing.Namespace != 0 || len(signing.IssuerKeyID) != 16 || len(signing.Seed) != 32 || entry.Role != uint8(side) || entry.CandidateIndex != 0 || entry.LiveGrant == nil || !bytes.Equal(entry.RelayCertificate, d.RelayCertificate) || !bytes.Equal(entry.LiveGrant.IssuerKeyID, signing.IssuerKeyID) || entry.LiveGrant.Service != d.Service || entry.LiveGrant.Audience != d.RelayAudience || entry.LiveGrant.RevocationPolicyID != signing.RevocationPolicyID || entry.LiveGrant.RevocationPolicyRevision != signing.RevocationPolicyRevision {
				reporter.Fatal("installed live Grant policy differs from its independent signer")
			}
			preparation := lease.Tunnels[side].LiveGrant
			if preparation == nil {
				reporter.Fatal("installed live Grant preparation is unavailable")
			}
			signer := registeredPeerSigner{key: ed25519.NewKeyFromSeed(signing.Seed)}
			reporter.Cleanup(func() { clear(signer.key) })
			if !bytes.Equal(signer.PublicKey(), preparation.Validation.Issuer.Key[:]) {
				reporter.Fatal("installed Grant seed differs from independently bootstrapped issuer")
			}
			grantIssuance[side] = protocolv4.LiveGrantIssuance{Preparation: *preparation, Limits: limits, Signer: signer}
			scope := preparation.Scope
			mapping.Grants[side] = protocolv4.RelayGrantIssuer{Namespace: protocolv4.NamespaceReference{Tenant: scope.Tenant, Authority: scope.Authority, CapacityDigest: scope.CapacityDigest, Generation: scope.Generation, RoleMask: 4 | 1<<side}, Issuer: scope.Issuer, Key: preparation.Validation.Issuer.Key}
		}
		directionDecoder, err := protocolv4.NewDecoder(16384, 1024)
		if err != nil {
			reporter.Fatal(err)
		}
		directionDocument, err := directionDecoder.DecodeMap(material.Route, "Route", protocolv4.DecodeContext{})
		if err != nil {
			reporter.Fatal(err)
		}
		for side, name := range []string{"client_leg", "server_leg"} {
			listener, ok := directionDocument.Root().Named("Route", name).Named("Leg", "listener_role").Uint()
			if !ok || (listener == uint64(side)) != endpointListeners[side] {
				directionDocument.Release()
				reporter.Fatal("signed live native direction differs from selected topology")
			}
		}
		directionDocument.Release()
		var remote *controlv4.RemoteOriginalLiveRelay
		if d.RemoteRelay != nil {
			publicInstallation, err = relayPublicLiveInstallation(d, material, maps, mapping, limits)
			if err != nil {
				reporter.Fatal(err)
			}
			remote, err = newRegisteredRemoteOriginalLiveRelay(reporter, h, d.RemoteRelay, [2][]byte{live.ClientControlCertificateDER, live.ServerControlCertificateDER})
			if err != nil {
				reporter.Fatal(err)
			}
			reporter.Cleanup(func() { remote.Close(); reporter.ErrorIf(remote.WaitCleanup(context.Background())) })
		}
		stores, identities := createRegisteredLiveStores(ctx, reporter, h, activation.Binding.SpendAuthority, activation.Binding.WinnerAuthority, d.RemoteRelay != nil)
		start := make(chan struct{})
		var native *runtimehost.NativeRelay
		var hostRuntime *runtimehost.Relay
		prepareOriginal := func(call context.Context, side protocolv4.Direction) error {
			if side > protocolv4.ServerToClient {
				return resourcev4.ErrConfiguration
			}
			if err := call.Err(); err != nil {
				return err
			}
			return h.Environment.Check()
		}
		cancelOriginal := func() {}
		var dispatchOriginal func(context.Context, sessionv4.LiveAuthorizationRequest, [3][]byte, func() error) error
		if remote != nil {
			dispatchOriginal = remote.DispatchOriginalLive
			cancelOriginal = remote.Close
		} else {
			legs := [2]runtimehost.NativeRelayLeg{}
			for side := range 2 {
				legs[side] = reporter.nativeScopedLeg(carriers[side], addresses[side], relayTLS, nativeRoots, nil)
				if carriers[side] != "raw-quic" {
					legs[side].Origin = d.Origin
				}
			}
			native, err = runtimehost.NewNativeRelay(runtimehost.NativeRelayConfig{Start: start, Root: h.Root, Owner: h.Owner(), Accounts: []resourcev4.Account{h.Scope[0].Tenant}, Clock: h.Clock, Environment: h.Environment, Route: material.Route, Deployment: material.RelayDeployment, Legs: legs})
			if err != nil {
				reporter.Fatal(err)
			}
			reporter.Cleanup(func() { native.Close(); reporter.ErrorIf(native.WaitCleanup(context.Background())) })
			relayInstance := randomRegisteredID(reporter)
			config := runtimehost.LiveRelayConfig{Root: h.Root, Owner: h.Owner(), Accounts: []resourcev4.Account{h.Scope[0].Tenant}, Clock: h.Clock, SourceStore: stores[0], RelayStore: stores[1], SourceIdentity: identities[0], RelayIdentity: identities[1], Artifact: material.Artifact, ClientCertificate: material.ClientCertificate, ServerCertificate: material.ServerCertificate, RelayCertificate: d.RelayCertificate, Mapping: mapping, Parent: validations[0], ParentDigest: session.ArtifactDigest, Candidate: 0, Limits: [2]protocolv4.RelayGrantLimits{limits, limits}, RelaySigner: relaySigner, RelayInstance: relayInstance, RelayGeneration: 1, Prepare: native.Prepare, RuntimeBytes: 65536}
			for index := range config.Trust {
				config.Trust[index] = h.Lease.Trust[0]
			}
			cost, err := runtimehost.LiveRelayCharge(config)
			if err != nil {
				reporter.Fatal(err)
			}
			hostRef, err := h.Root.Reserve(config.Owner, cost, config.Accounts...)
			if err != nil {
				reporter.Fatal(err)
			}
			reporter.Cleanup(hostRef.Release)
			hostRuntime, err = runtimehost.NewLiveRelay(ctx, config, hostRef, h.Environment)
			if err != nil {
				reporter.Fatal(err)
			}
			reporter.Cleanup(func() { hostRuntime.Close(); reporter.ErrorIf(hostRuntime.WaitCleanup(context.Background())) })
			prepareOriginal, cancelOriginal, dispatchOriginal = hostRuntime.PrepareOriginalLiveCarrier, hostRuntime.Close, hostRuntime.DispatchOriginalLive
		}
		originalHost := &registeredLiveAuthorizationHost{h: h, store: identities[0], certificate: sha256.Sum256(live.ClientControlCertificateDER), parent: parent, maps: maps, activation: activation, signer: activationSigner, tunnel: protocolv4.LiveTunnelActivationConfig{Client: maps[1], Server: maps[2], Relay: maps[3], Issuance: &grantIssuance, Bindings: [7]protocolv4.CredentialValidation{validations[0], validations[1], validations[2], grantIssuance[0].Preparation.Validation, validations[3], grantIssuance[1].Preparation.Validation, validations[3]}}, relay: hostRuntime, maxActivation: maxActivation, maxSession: maxSession}
		serviceConfig := controlv4.LiveAuthorizationHTTPSConfig{Store: stores[0], Clock: h.Clock, Host: originalHost, ClientCertificateDER: live.ClientControlCertificateDER, MaxRecordBytes: 524288, RequestsPerMinute: 60, Burst: 1, WorkMS: work, RuntimeBytes: 65536, Tunnel: true, OnOriginalTunnel: dispatchOriginal}
		serviceCost, spend, invoke, reader, read, err := controlv4.LiveAuthorizationHTTPSServiceCharges(serviceConfig)
		if err != nil {
			reporter.Fatal(err)
		}
		service, err := controlv4.NewLiveAuthorizationHTTPSService(serviceConfig, h.Reserve(serviceCost), h.Reserve(spend), h.Reserve(invoke), h.Reserve(reader), h.Reserve(read), h.Environment)
		if err != nil {
			reporter.Fatal(err)
		}
		reporter.Cleanup(func() { service.Close(); reporter.ErrorIf(service.WaitCleanup(context.Background())) })
		clientKey, ok := maps[1].Field("ed25519_public_key").ByteString()
		if !ok || len(clientKey) != 32 || len(serverKey) != 32 {
			reporter.Fatal("independent control identity key is invalid")
		}
		controlConfig := controlv4.RegisteredLiveAuthorityConfig{Authority: d.Authority, Tenant: parentScope.Tenant, Audience: parentScope.Audience, Parent: session.ArtifactDigest, Candidate: 0, ClientKey: [32]byte(clientKey), ServerKey: [32]byte(serverKey), ActivationKey: activation.Key, ServerGrantKey: grantIssuance[1].Preparation.Validation.Issuer.Key, ClientCertificateDER: live.ClientControlCertificateDER, ServerCertificateDER: live.ServerControlCertificateDER, Service: service, PrepareOriginalCarrier: prepareOriginal, CancelOriginal: cancelOriginal, WorkMS: work, RuntimeBytes: 65536}
		cost, err := controlv4.RegisteredLiveAuthorityCharge(controlConfig)
		if err != nil {
			reporter.Fatal(err)
		}
		control, err := controlv4.NewRegisteredLiveAuthority(controlConfig, h.Reserve(cost), h.Environment)
		if err != nil {
			reporter.Fatal(err)
		}
		originalHost.control = control
		reporter.Cleanup(func() { control.Close(); reporter.ErrorIf(control.WaitCleanup(context.Background())) })
		listener, err := net.ListenTCP("tcp", net.TCPAddrFromAddrPort(netip.AddrPortFrom(host, live.Port)))
		if err != nil {
			reporter.Fatal(err)
		}
		bounded := newLimitedListener(listener, 2)
		httpServer := &http.Server{Handler: control, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, Certificates: []tls.Certificate{controlTLS}, NextProtos: []string{"http/1.1"}, ClientCAs: controlRoots, ClientAuth: tls.RequireAndVerifyClientCert, SessionTicketsDisabled: true}, MaxHeaderBytes: 8192, ReadHeaderTimeout: time.Duration(work) * time.Millisecond, ReadTimeout: time.Duration(work) * time.Millisecond, WriteTimeout: time.Duration(work) * time.Millisecond, IdleTimeout: time.Second}
		exited := make(chan struct{})
		var serveErr error
		go func() {
			defer close(exited)
			serveErr = httpServer.Serve(tls.NewListener(bounded, httpServer.TLSConfig))
		}()
		reporter.Cleanup(func() {
			control.Close()
			service.Close()
			_ = httpServer.Close()
			_ = bounded.Close()
			bounded.CloseConnections()
			<-exited
			httpServer.TLSConfig = nil
			if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) && !errors.Is(serveErr, net.ErrClosed) {
				reporter.ErrorIf(serveErr)
			}
		})
		if err = prepared(material.LiveControlBaseURL, material.Profile, publicInstallation); err != nil {
			reporter.Fatal(err)
		}
		if err = control.WaitRegistered(ctx); err != nil {
			reporter.Fatal(err)
		}
		a := material
		a.Role = 0
		b := material
		b.Role = 1
		b.IdentitySeed = append([]byte(nil), d.ServerIdentitySeed...)
		b.DHSeed = append([]byte(nil), d.ServerDHSeed...)
		result = &RegisteredLiveRelay{PoolRelay: &PoolRelay{Runtime: &Runtime{Reporter: reporter, Authority: h}, Host: hostRuntime, Native: native, Material: [2]Material{a, b}, Namespace: record, TrustPEM: d.NativeTLS.TrustPEM, Origin: d.Origin, Carriers: carriers, ClientTLSCertificatePEM: d.NativeTLS.Client.CertificatePEM, ClientTLSPrivateKeyPEM: d.NativeTLS.Client.PrivateKeyPEM, ServerTLSCertificatePEM: d.NativeTLS.Server.CertificatePEM, ServerTLSPrivateKeyPEM: d.NativeTLS.Server.PrivateKeyPEM, start: start}, Control: control, Service: service, ControlEndpoint: material.LiveControlBaseURL, PublicInstallation: publicInstallation}
		return result
	})
}

// The parser's private PEM scratch is owned here. Parsed crypto/x509 private
// keys have no generic supported zeroization API and follow their TLS owner's
// joined lifecycle instead of unsafe shared-memory mutation.
func parseRegisteredOwnedTLSIdentity(certificatePEM, privateKeyPEM string) (tls.Certificate, error) {
	private := []byte(privateKeyPEM)
	defer clear(private)
	return tls.X509KeyPair([]byte(certificatePEM), private)
}

func randomRegisteredID(reporter *Reporter) (id [16]byte) {
	if _, err := rand.Read(id[:]); err != nil || id == ([16]byte{}) {
		reporter.Fatal("registered live deployment entropy is unavailable")
	}
	return id
}
func createRegisteredLiveStores(ctx context.Context, reporter *Reporter, h *sessionv4.PublicQUICTestHarness, source, relay string, sourceOnly ...bool) (stores [2]*ledgerv4.SQLiteStore, identities [2]ledgerv4.SQLiteIdentity) {
	var backing [2]*ledgerv4.SQLiteBacking
	disk := reporter.TempDir()
	limits := ledgerv4.SQLiteLimits{MaxPages: 8192, MaxRecords: 4096, MaxRecordBytes: 524288, RuntimeBytes: 65536, ProviderRuntimeBytes: 4 << 20, DiskOverheadBytes: 65536}
	reporter.Cleanup(func() {
		for _, store := range stores {
			if store != nil {
				store.Close()
				reporter.ErrorIf(store.WaitCleanup(context.Background()))
				reporter.ErrorIf(store.Retire())
			}
		}
		for _, back := range backing {
			if back != nil {
				back.Close()
			}
		}
		reporter.ErrorIf(os.RemoveAll(disk))
		for _, back := range backing {
			if back != nil {
				reporter.ErrorIf(back.ReleaseRemoved())
			}
		}
	})
	authorities := []string{source, relay}
	if len(sourceOnly) > 0 && sourceOnly[0] {
		authorities = authorities[:1]
	}
	for side, authority := range authorities {
		// A registered pool route has a TopUp journal of its own and needs
		// only the relay store here, never an unused live-spend store.
		if side == 0 && authority == "" {
			continue
		}
		identities[side] = ledgerv4.SQLiteIdentity{Authority: authority, Generation: 1}
		if _, err := rand.Read(identities[side].StoreID[:]); err != nil {
			reporter.Fatal(err)
		}
		cost, err := ledgerv4.SQLiteBackingCharge(limits)
		if err != nil {
			reporter.Fatal(err)
		}
		backing[side], err = ledgerv4.NewSQLiteBacking(filepath.Join(disk, []string{"live.db", "relay.db"}[side]), limits, h.Reserve(cost), h.Environment)
		if err != nil {
			reporter.Fatal(err)
		}
		cost, err = ledgerv4.SQLiteStoreCharge(limits)
		if err != nil {
			reporter.Fatal(err)
		}
		stores[side], err = ledgerv4.CreateSQLite(ctx, backing[side], identities[side], engineeringNewHistory{identities[side]}, h.Reserve(cost), h.Environment)
		if err != nil {
			reporter.Fatal(err)
		}
	}
	return stores, identities
}

type registeredLiveAuthorizationHost struct {
	mu                        sync.Mutex
	h                         *sessionv4.PublicQUICTestHarness
	store                     ledgerv4.SQLiteIdentity
	certificate               [32]byte
	parent                    *protocolv4.Credential
	maps                      [4]*protocolv4.SignedMap
	activation                protocolv4.ActivationConfiguration
	signer                    protocolv4.MapSigner
	tunnel                    protocolv4.LiveTunnelActivationConfig
	relay                     *runtimehost.Relay
	control                   *controlv4.RegisteredLiveAuthority
	maxActivation, maxSession uint64
	claimed                   bool
}

func (p *registeredLiveAuthorizationHost) CheckLiveAuthorizationShare(identity ledgerv4.SQLiteIdentity, rate, burst uint16) error {
	if identity != p.store || rate != 60 || burst != 1 {
		return ledgerv4.ErrDenied
	}
	return nil
}
func (p *registeredLiveAuthorizationHost) AcquireLiveAuthorization(ctx context.Context, certificate [32]byte, q sessionv4.LiveAuthorizationRequest) (controlv4.LiveAuthorizationAccess, error) {
	p.mu.Lock()
	if p.claimed || certificate != p.certificate {
		p.mu.Unlock()
		return nil, ledgerv4.ErrDenied
	}
	p.claimed = true
	p.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := p.h.Environment.Check(); err != nil {
		return nil, err
	}
	initiation, ok := p.maps[0].Field("initiation_not_after_ms").Uint()
	sessionEnd, sessionOK := p.maps[0].Field("session_not_after_ms").Uint()
	if !ok || !sessionOK {
		return nil, ledgerv4.ErrDenied
	}
	issued := p.parent.Scope().IssuedMS
	activationEnd := min(initiation, q.ActivationNotAfterMS, saturatingRegisteredAdd(issued, p.maxActivation))
	sessionEnd = min(sessionEnd, saturatingRegisteredAdd(issued, p.maxSession))
	// The public pending Grant scope is frozen by independent installation.
	// Preserve its exact issuance interval in the original signed projections.
	for _, grant := range p.tunnel.Issuance {
		activationEnd = min(activationEnd, grant.Preparation.Scope.ExpiresMS)
	}
	cost, err := protocolv4.LiveActivationPlanCharge(true)
	if err != nil {
		return nil, err
	}
	plan, err := protocolv4.NewLiveActivationPlan(p.maps[0], p.activation.Rules, p.activation.Delegation, p.activation.Once, p.signer, protocolv4.LiveActivationConfig{Tunnel: &p.tunnel, Index: q.Winner.Index, Attempt: q.Attempt, IssuedAt: issued, ActivationEnd: activationEnd, SessionEnd: sessionEnd}, p.h.Reserve(cost), p.h.Environment, p.h.Preauth)
	if err != nil {
		return nil, err
	}
	adopted := false
	defer func() {
		if !adopted {
			_ = plan.Close()
		}
	}()
	fields, _, err := plan.CopyProjection(make([]byte, 65536))
	if err != nil {
		return nil, err
	}
	if fields.Tenant != q.Tenant || fields.Audience != q.Audience || fields.Profile != q.CryptoProfile || fields.Artifact != q.Artifact || fields.Issuer != q.Issuer || fields.Lease != q.Lease || fields.ClientIdentity != q.ClientIdentity || fields.ServerIdentity != q.ServerIdentity || fields.Winner != q.Winner {
		return nil, ledgerv4.ErrDenied
	}
	deadline, err := timev4.NewDeadline(p.h.Clock, activationEnd)
	if err != nil {
		return nil, err
	}
	allow, err := p.control.ServerAllow()
	if err != nil {
		return nil, err
	}
	var publication resourcev4.Reference
	if p.relay != nil {
		local, e := p.relay.LivePublication()
		if e != nil {
			return nil, e
		}
		allow.Relay = &local
		publication = local.Reservation
	}
	access := &registeredLiveAuthorizationAccess{host: p, fields: fields, material: controlv4.LiveAuthorizationMaterial{Plan: plan, Artifact: p.parent, Trust: p.h.Lease.Trust[0], Deadline: deadline, ServerAllow: allow}, publication: publication}
	adopted = true
	return access, nil
}
func saturatingRegisteredAdd(left, right uint64) uint64 {
	if right > ^uint64(0)-left {
		return ^uint64(0)
	}
	return left + right
}

type registeredLiveAuthorizationAccess struct {
	host        *registeredLiveAuthorizationHost
	fields      protocolv4.LiveActivationFields
	material    controlv4.LiveAuthorizationMaterial
	publication resourcev4.Reference
	closed      bool
}

func (a *registeredLiveAuthorizationAccess) Material() (controlv4.LiveAuthorizationMaterial, error) {
	if a.closed {
		return controlv4.LiveAuthorizationMaterial{}, resourcev4.ErrClosed
	}
	return a.material, nil
}
func (a *registeredLiveAuthorizationAccess) Check(ctx context.Context) error {
	if a.closed {
		return resourcev4.ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return a.host.h.Environment.Check()
}
func (a *registeredLiveAuthorizationAccess) CheckLiveSpend(identity ledgerv4.SQLiteIdentity, fields protocolv4.LiveActivationFields) error {
	if a.closed || identity != a.host.store || fields != a.fields {
		return ledgerv4.ErrDenied
	}
	return a.host.h.Environment.Check()
}
func (a *registeredLiveAuthorizationAccess) Authorize(ctx context.Context) (bool, error) {
	if err := a.Check(ctx); err != nil {
		return false, err
	}
	a.host.h.PolicyCalls++
	return true, nil
}
func (a *registeredLiveAuthorizationAccess) Close() {
	if !a.closed {
		a.closed = true
		_ = a.material.Plan.Close()
		a.publication.Release()
	}
}
