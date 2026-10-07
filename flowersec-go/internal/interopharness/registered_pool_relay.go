package interopharness

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"time"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/controlv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/runtimehost"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

type RegisteredPoolRelay struct {
	*PoolRelay
	Control *controlv4.RegisteredPoolAuthority
}

type registeredPoolControlInstallation struct {
	Host string `json:"host"`
	Port uint16 `json:"port"`
	TLS  struct {
		CertificatePEM string `json:"certificatePEM"`
		PrivateKeyPEM  string `json:"privateKeyPEM"`
		ClientTrustPEM string `json:"clientTrustPEM"`
	} `json:"tls"`
	ServerControlCertificateDER []byte `json:"serverControlCertificateDER"`
	WorkMS                      string `json:"workMS"`
}

type registeredPoolIssuer struct {
	plan     *protocolv4.PoolGrantPlan
	policy   *controlv4.PoolSourceAuthority
	bundle   controlv4.PoolMaterialBundle
	codec    *protocolv4.TopUpCodec
	expiry   uint64
	grants   [2][]byte
	material []byte
}

func (p *registeredPoolIssuer) IssuePoolBatch(ctx context.Context, original ledgerv4.TopUpServerSnapshot, dst []byte) (result controlv4.PoolIssueResult, err error) {
	guard := func() error { return p.policy.CheckPoolIssuance(ctx, original) }
	if err = guard(); err != nil {
		return result, err
	}
	if original.Request.DesiredCount != 1 || original.HighestArtifact != 0 {
		return result, ledgerv4.ErrOwner
	}
	sizes, err := p.plan.Issue(p.grants, guard)
	if err != nil {
		return result, err
	}
	defer func() {
		for _, b := range p.grants {
			clear(b)
		}
		clear(p.material)
	}()
	for side := range 2 {
		p.bundle.Tunnels[side].Grant = p.grants[side][:sizes[side]]
	}
	n, err := controlv4.EncodePoolMaterial(p.material, p.bundle)
	if err != nil {
		return result, err
	}
	if err = guard(); err != nil {
		return result, err
	}
	result.ResponseBytes, err = p.codec.EncodeResponse(dst, original.Request, 1, false, 0, []protocolv4.TopUpIssueEntry{{Material: p.material[:n], ExpiryMS: p.expiry}})
	if err == nil {
		err = guard()
	}
	if err != nil {
		clear(dst)
		return controlv4.PoolIssueResult{}, err
	}
	return result, nil
}

// NewRegisteredPoolRelay retains the independently installed parent and keys.
// The registered B request enters the original pool issuer exactly once; all
// signed output crosses the real source outbox and relay publication gates.
func NewRegisteredPoolRelay(ctx context.Context, reporter *Reporter, d *RegisteredRelayDeployment, carriers [2]string, endpointListeners [2]bool, prepared func(endpoint, profile string) error) (*RegisteredPoolRelay, error) {
	return newRegisteredPoolRelay(ctx, reporter, d, carriers, endpointListeners, prepared, nil)
}

// RegisteredPoolOriginalOwner fixes the original external native relay before
// issuance. Both callbacks use its retained private control channel; neither is
// selected by B, copied Grants, a ledger lookup or a later reconnect.
type RegisteredPoolOriginalOwner struct {
	Capture     func(context.Context, *PoolRelay) error
	MatchWinner func(context.Context, []byte, []byte, func() error) error
}

func NewRegisteredPoolRelayForOriginalOwner(ctx context.Context, reporter *Reporter, d *RegisteredRelayDeployment, carriers [2]string, endpointListeners [2]bool, prepared func(string, string) error, original RegisteredPoolOriginalOwner) (*RegisteredPoolRelay, error) {
	if original.Capture == nil || original.MatchWinner == nil {
		return nil, resourcev4.ErrConfiguration
	}
	return newRegisteredPoolRelay(ctx, reporter, d, carriers, endpointListeners, prepared, &original)
}
func newRegisteredPoolRelay(ctx context.Context, reporter *Reporter, d *RegisteredRelayDeployment, carriers [2]string, endpointListeners [2]bool, prepared func(string, string) error, original *RegisteredPoolOriginalOwner) (*RegisteredPoolRelay, error) {
	return construct(reporter, func() *RegisteredPoolRelay {
		if ctx == nil || d == nil || d.WireRevision != 4 || d.LiveControl != nil || d.RemoteRelay != nil || len(d.ServerControl) == 0 || len(d.ServerControl) > 1048576 || prepared == nil || !materialIdentifier(d.Authority) || !materialIdentifier(d.Service) || !materialIdentifier(d.RelayAudience) || !materialIdentifier(d.RelaySubject) || !materialHTTPS(d.Origin) {
			reporter.Fatal("complete independent registered pool installation is required")
		}
		if len(d.ServerIdentitySeed) != 32 || len(d.ServerDHSeed) != 32 || len(d.RelayIdentitySeed) != 32 || len(d.RelayCertificate) == 0 || len(d.RelayCertificate) > 16384 {
			reporter.Fatal("registered pool identity installation is incomplete")
		}
		var control registeredPoolControlInstallation
		controlDecoder := json.NewDecoder(bytes.NewReader(d.ServerControl))
		controlDecoder.DisallowUnknownFields()
		if err := controlDecoder.Decode(&control); err != nil {
			reporter.Fatal(err)
		}
		var trailing any
		if controlDecoder.Decode(&trailing) != io.EOF {
			reporter.Fatal("registered pool control has trailing JSON")
		}
		work, err := canonicalMaterialUint(control.WorkMS, true)
		if err != nil || work > 60000 {
			reporter.Fatal("invalid registered pool control interval")
		}
		host, err := netip.ParseAddr(control.Host)
		if err != nil || !host.IsLoopback() || host.Zone() != "" || control.Port == 0 {
			reporter.Fatal("registered pool control requires its fixed loopback listener")
		}
		material, err := decodeInstalledLiveMaterial(d.RegistrationJSON)
		if err != nil {
			reporter.Fatal(err)
		}
		var result *RegisteredPoolRelay
		reporter.Cleanup(func() {
			releaseOwnedMaterial(&material)
			if result != nil {
				for side := range result.Material {
					releaseOwnedMaterial(&result.Material[side])
				}
				result.ClientTLSPrivateKeyPEM, result.ServerTLSPrivateKeyPEM = "", ""
			}
		})
		if material.Source != "preauthorized_pool" || len(material.Namespaces) != 1 || len(material.Tunnels) != 0 || len(material.Activation) == 0 || material.Role != 0 {
			reporter.Fatal("registered pool requires its unissued independent parent registry")
		}
		if _, err = material.JSON(); err != nil {
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
			reporter.Fatal("registered pool forwarding limits exceed runtime widths")
		}
		roots := x509.NewCertPool()
		if len(d.NativeTLS.TrustPEM) == 0 || len(d.NativeTLS.TrustPEM) > 1048576 || !roots.AppendCertsFromPEM([]byte(d.NativeTLS.TrustPEM)) {
			reporter.Fatal("registered pool native TLS trust is missing")
		}
		relayTLS, err := parseRegisteredOwnedTLSIdentity(d.NativeTLS.Relay.CertificatePEM, d.NativeTLS.Relay.PrivateKeyPEM)
		if err != nil {
			reporter.Fatal(err)
		}
		controlTLS, err := parseRegisteredOwnedTLSIdentity(control.TLS.CertificatePEM, control.TLS.PrivateKeyPEM)
		if err != nil {
			reporter.Fatal(err)
		}
		controlRoots := x509.NewCertPool()
		if len(control.TLS.ClientTrustPEM) > 1048576 || !controlRoots.AppendCertsFromPEM([]byte(control.TLS.ClientTrustPEM)) {
			reporter.Fatal("registered pool mTLS trust is missing")
		}
		record := material.Namespaces[0]
		bootstrap, err := NewHTTPSBootstrap(record, d.ControlTrustPEM)
		if err != nil {
			reporter.Fatal(err)
		}
		reporter.bootstrap = bootstrap
		reporter.Cleanup(bootstrap.Close)
		reporter.rootPin = &protocolv4.NamespaceTrustRoot{Tenant: record.Tenant, Authority: record.Authority, KeyID: [16]byte(record.RootKeyID), PublicKey: [32]byte(record.RootPublicKey), MaxLifetimeMS: 30000000}
		var addresses [2]netip.AddrPort
		var policies [2][]byte
		for side := range 2 {
			var kind string
			addresses[side], kind, policies[side], err = materialRoute(material.Route, uint8(side))
			if err != nil || kind != carriers[side] {
				reporter.Fatal("registered pool carrier differs from its signed route")
			}
		}
		decoder, err := protocolv4.NewDecoder(65536, 4096)
		if err != nil {
			reporter.Fatal(err)
		}
		parentDoc, err := decoder.DecodeMap(material.Artifact, "Artifact", protocolv4.DecodeContext{})
		if err != nil {
			reporter.Fatal(err)
		}
		maximum, ok := parentDoc.Root().Named("Artifact", "session_contract").Named("SessionContract", "max_streams").Uint()
		parentDoc.Release()
		if !ok || maximum == 0 || maximum > 139 {
			reporter.Fatal("invalid installed pool stream envelope")
		}
		reporter.ApplicationProfile, reporter.MaxStreams, reporter.originalPoolDeployment = "services", uint32(maximum), true
		h := sessionv4.NewEngineeringNativeHarness(reporter, "preauthorized_pool", material.Profile, carriers[0], addresses[0], policies[0], d.Origin, limits.DatagramBytes != 0)
		// Keep parsed installation owners and the bounded HTTP/TLS host charged
		// through the physical cleanup registered below.
		var installationBytes uint64 = 3*16384 + 4096
		for _, schema := range []string{"Artifact", "IdentityCertificate", "IdentityCertificate", "IdentityCertificate"} {
			cost, e := protocolv4.SignedMapBackingBytes(schema, 65536, 16384)
			if e != nil {
				reporter.Fatal(e)
			}
			installationBytes += cost
		}
		proofBacking, err := protocolv4.SignedMapBackingBytes("ActivationAuthorization", 4096, 4096)
		if err != nil {
			reporter.Fatal(err)
		}
		installationBytes += proofBacking
		installationRef := h.Reserve(resourcev4.Vector{resourcev4.SDKBytes: installationBytes, resourcev4.Items: 1})
		reporter.Cleanup(installationRef.Release)
		httpRef := h.Reserve(resourcev4.Vector{resourcev4.SDKBytes: 1048576, resourcev4.ProviderBytes: 8 << 20, resourcev4.Items: 4, resourcev4.Tasks: 6, resourcev4.WorkSlots: 2, resourcev4.Timers: 8, resourcev4.Connections: 2, resourcev4.TLSHandshakes: 2, resourcev4.NativeHandles: 3})
		reporter.Cleanup(httpRef.Release)
		var maps [4]*protocolv4.SignedMap
		var validations [4]protocolv4.CredentialValidation
		for i, wire := range [4][]byte{material.Artifact, material.ClientCertificate, material.ServerCertificate, d.RelayCertificate} {
			schema := "IdentityCertificate"
			if i == 0 {
				schema = "Artifact"
			}
			codec, e := protocolv4.NewSignedMapCodec(schema, 65536, 16384)
			if e != nil {
				reporter.Fatal(e)
			}
			maps[i], e = codec.VerifyCredential(wire, h.Lease.Trust[0])
			if e != nil {
				reporter.Fatal(e)
			}
			retained := maps[i]
			reporter.Cleanup(retained.Release)
			credential, e := retained.DetachCredential()
			if e != nil {
				reporter.Fatal(e)
			}
			validations[i], e = h.Lease.Trust[0].ResolveCredential(credential)
			if e != nil {
				reporter.Fatal(e)
			}
		}
		parent, err := maps[0].DetachCredential()
		if err != nil {
			reporter.Fatal(err)
		}
		scope := parent.Scope()
		session, err := maps[0].SessionParameters()
		if err != nil {
			reporter.Fatal(err)
		}
		activation, err := h.Lease.Trust[0].ResolveActivation(parent, material.ActivationSigningKeyID, make([]byte, 16384), make([]byte, 16384))
		if err != nil {
			reporter.Fatal(err)
		}
		if activation.Binding.WinnerAuthority != d.Authority {
			reporter.Fatal("registered pool winner authority differs from installed delegation")
		}
		proofCodec, err := protocolv4.NewSignedMapCodec("ActivationAuthorization", 4096, 4096)
		if err != nil {
			reporter.Fatal(err)
		}
		proof, err := proofCodec.Verify(material.Activation, activation.Key, protocolv4.DecodeContext{Selectors: map[string]string{"activation_source_profile": "preauthorized_pool"}})
		if err != nil {
			reporter.Fatal(err)
		}
		reporter.Cleanup(proof.Release)
		issued, issuedOK := proof.Field("issued_at_ms").Uint()
		sessionEnd, endOK := proof.Field("session_not_after_ms").Uint()
		if !issuedOK || !endOK {
			reporter.Fatal("invalid original pool activation bounds")
		}
		route, routeDigest, err := maps[0].CopyCandidateRoute(0, make([]byte, 16384))
		if err != nil || !bytes.Equal(route, material.Route) || routeDigest != [32]byte(material.RouteDigest) {
			reporter.Fatal("registered pool route differs from installed parent")
		}
		routeDoc, err := decoder.DecodeMap(route, "Route", protocolv4.DecodeContext{})
		if err != nil {
			reporter.Fatal(err)
		}
		for side, name := range []string{"client_leg", "server_leg"} {
			listener, ok := routeDoc.Root().Named("Route", name).Named("Leg", "listener_role").Uint()
			if !ok || (listener == uint64(side)) != endpointListeners[side] {
				routeDoc.Release()
				reporter.Fatal("registered pool direction differs from installed route")
			}
		}
		routeDoc.Release()
		relayKey, ok := maps[3].Field("ed25519_public_key").ByteString()
		relaySubject, subjectOK := maps[3].Field("subject_id").Text()
		relaySigner := registeredPeerSigner{key: ed25519.NewKeyFromSeed(d.RelayIdentitySeed)}
		reporter.Cleanup(func() { clear(relaySigner.key) })
		if !ok || !subjectOK || relaySubject != d.RelaySubject || !bytes.Equal(relaySigner.PublicKey(), relayKey) {
			reporter.Fatal("registered pool relay identity differs from installed certificate")
		}
		serverKey, ok := maps[2].Field("ed25519_public_key").ByteString()
		serverSigner := ed25519.NewKeyFromSeed(d.ServerIdentitySeed)
		defer clear(serverSigner)
		if !ok || !bytes.Equal(serverSigner.Public().(ed25519.PublicKey), serverKey) {
			reporter.Fatal("registered pool B identity differs from installed certificate")
		}
		curve := ecdh.X25519()
		algorithm, algorithmOK := maps[2].Field("noise_static_public_key").Named("NoiseStaticPublicKey", "algorithm").Uint()
		if !algorithmOK || algorithm > 1 {
			reporter.Fatal("registered pool B Noise algorithm is invalid")
		}
		if algorithm == 1 {
			curve = ecdh.P256()
		}
		serverDH, err := curve.NewPrivateKey(d.ServerDHSeed)
		if err != nil {
			reporter.Fatal(err)
		}
		serverNoise, noiseOK := maps[2].Field("noise_static_public_key").Named("NoiseStaticPublicKey", "public_key_bytes").ByteString()
		if !noiseOK || !bytes.Equal(serverDH.PublicKey().Bytes(), serverNoise) {
			reporter.Fatal("registered pool B Noise identity differs from installed certificate")
		}
		mapping := protocolv4.RelayIssuerMapping{Parent: protocolv4.NamespaceReference{Tenant: scope.Tenant, Authority: scope.Authority, CapacityDigest: scope.CapacityDigest, Generation: scope.Generation, RoleMask: 7}, ParentIssuer: scope.Issuer, ParentKey: maps[0].Key(), Activation: activation.Binding, Service: d.Service, RelayAudience: d.RelayAudience, EndpointAudience: scope.Audience, Profile: material.Profile}
		var issuance [2]protocolv4.LiveGrantIssuance
		tunnel := protocolv4.LiveTunnelActivationConfig{Client: maps[1], Server: maps[2], Relay: maps[3], Issuance: &issuance}
		copy(tunnel.Bindings[:3], validations[:3])
		for side, signing := range d.Signing {
			if signing.Namespace != 0 || len(signing.IssuerKeyID) != 16 || len(signing.Seed) != 32 {
				reporter.Fatal("invalid installed pool Grant signer")
			}
			revision, e := canonicalMaterialUint(signing.RevocationPolicyRevision, true)
			if e != nil {
				reporter.Fatal(e)
			}
			parentNamespace := mapping.Parent
			parentNamespace.RoleMask = 3
			validation, namespace, e := h.Lease.Trust[0].ResolveIssuerPolicy(protocolv4.IssuerPolicySelection{Schema: "Grant", Issuer: [16]byte(signing.IssuerKeyID), Audience: d.RelayAudience, Service: d.Service, Role: uint64(side), Parent: parentNamespace, ParentIssuer: scope.Issuer, PolicyID: signing.RevocationPolicyID, PolicyRevision: revision})
			if e != nil {
				reporter.Fatal(e)
			}
			signer := registeredPeerSigner{key: ed25519.NewKeyFromSeed(signing.Seed)}
			reporter.Cleanup(func() { clear(signer.key) })
			if !bytes.Equal(signer.PublicKey(), validation.Issuer.Key[:]) {
				reporter.Fatal("installed pool Grant signer differs from independent namespace")
			}
			preparation, e := protocolv4.DeriveLiveGrantPreparation(parent, protocolv4.Direction(side), validation, protocolv4.LiveGrantPreparationConfig{Service: d.Service, Audience: d.RelayAudience, IssuedAt: issued, NotAfterMS: sessionEnd}, h.Environment)
			if e != nil {
				reporter.Fatal(e)
			}
			issuance[side] = protocolv4.LiveGrantIssuance{Preparation: preparation, Limits: limits, Signer: signer}
			tunnel.Bindings[3+2*side], tunnel.Bindings[4+2*side] = validation, validations[3]
			namespace.RoleMask = 4 | 1<<uint64(side)
			mapping.Grants[side] = protocolv4.RelayGrantIssuer{Namespace: namespace, Issuer: validation.Issuer.Issuer, Key: validation.Issuer.Key}
		}
		cost, err := protocolv4.PoolGrantPlanCharge()
		if err != nil {
			reporter.Fatal(err)
		}
		plan, err := protocolv4.NewPoolGrantPlan(maps[0], proof, activation, 0, tunnel, h.Reserve(cost), h.Environment)
		if err != nil {
			reporter.Fatal(err)
		}
		reporter.Cleanup(plan.Close)
		stores, identities := createRegisteredLiveStores(ctx, reporter, h, "", d.Authority)
		start := make(chan struct{})
		var native *runtimehost.NativeRelay
		var relayHost *runtimehost.Relay
		var table *ledgerv4.SQLiteRelayAuthorityTable
		originalContext, cancelOriginal := context.WithCancel(ctx)
		reporter.Cleanup(cancelOriginal)
		if original == nil {
			legs := [2]runtimehost.NativeRelayLeg{}
			for side := range 2 {
				legs[side] = reporter.nativeScopedLeg(carriers[side], addresses[side], relayTLS, roots, nil)
				if carriers[side] != "raw-quic" {
					legs[side].Origin = d.Origin
				}
			}
			native, err = runtimehost.NewNativeRelay(runtimehost.NativeRelayConfig{Start: start, Root: h.Root, Owner: h.Owner(), Accounts: []resourcev4.Account{h.Scope[0].Tenant}, Clock: h.Clock, Environment: h.Environment, Route: material.Route, Deployment: material.RelayDeployment, Legs: legs})
			if err != nil {
				reporter.Fatal(err)
			}
			reporter.Cleanup(func() { native.Close(); reporter.ErrorIf(native.WaitCleanup(context.Background())) })
			hostConfig := runtimehost.LiveRelayConfig{Root: h.Root, Owner: h.Owner(), Accounts: []resourcev4.Account{h.Scope[0].Tenant}, Clock: h.Clock, RelayStore: stores[1], RelayIdentity: identities[1], Artifact: material.Artifact, ClientCertificate: material.ClientCertificate, ServerCertificate: material.ServerCertificate, RelayCertificate: d.RelayCertificate, Mapping: mapping, Parent: validations[0], ParentDigest: session.ArtifactDigest, Candidate: 0, Limits: [2]protocolv4.RelayGrantLimits{limits, limits}, RelaySigner: relaySigner, RelayInstance: randomRegisteredID(reporter), RelayGeneration: 1, Prepare: native.Prepare, RuntimeBytes: 65536}
			for i := range hostConfig.Trust {
				hostConfig.Trust[i] = h.Lease.Trust[0]
			}
			cost, err = runtimehost.RegisteredPoolRelayCharge(hostConfig)
			if err != nil {
				reporter.Fatal(err)
			}
			hostRef, err := h.Root.Reserve(hostConfig.Owner, cost, hostConfig.Accounts...)
			if err != nil {
				reporter.Fatal(err)
			}
			reporter.Cleanup(hostRef.Release)
			relayHost, err = runtimehost.NewRegisteredPoolRelay(ctx, hostConfig, hostRef, h.Environment)
			if err != nil {
				reporter.Fatal(err)
			}
			reporter.Cleanup(func() { relayHost.Close(); reporter.ErrorIf(relayHost.WaitCleanup(context.Background())) })
			for side := range 2 {
				if err = relayHost.PrepareOriginalLiveCarrier(ctx, protocolv4.Direction(side)); err != nil {
					reporter.Fatal(err)
				}
			}
			table, err = relayHost.RegisteredPoolTable()
			if err != nil {
				reporter.Fatal(err)
			}
		} else {
			// Issuance and the source outbox remain local; every physical
			// preparation, HOP claim and forwarding owner belongs to Rust.
			tableConfig := ledgerv4.SQLiteRelayAuthorityConfig{Identity: identities[1], MaxParents: 1, ParallelLookups: 1, RuntimeBytes: 65536}
			cost, err = ledgerv4.SQLiteRelayAuthorityCharge(tableConfig)
			if err != nil {
				reporter.Fatal(err)
			}
			table, err = ledgerv4.NewSQLiteRelayAuthorityTableContext(originalContext, stores[1], tableConfig, h.Reserve(cost), h.Environment)
			if err != nil {
				reporter.Fatal(err)
			}
			reporter.Cleanup(func() { table.Close(); reporter.ErrorIf(table.WaitCleanup(context.Background())) })
		}
		result = &RegisteredPoolRelay{PoolRelay: &PoolRelay{Runtime: &Runtime{Reporter: reporter, Authority: h}, Host: relayHost, Native: native, Namespace: record, TrustPEM: d.NativeTLS.TrustPEM, Origin: d.Origin, Carriers: carriers, Addresses: addresses, ClientTLSCertificatePEM: d.NativeTLS.Client.CertificatePEM, ClientTLSPrivateKeyPEM: d.NativeTLS.Client.PrivateKeyPEM, ServerTLSCertificatePEM: d.NativeTLS.Server.CertificatePEM, ServerTLSPrivateKeyPEM: d.NativeTLS.Server.PrivateKeyPEM, start: start}}
		issue := newRegisteredPoolIssue(originalContext, reporter, h, d, material, plan, maps, mapping, table, relayHost, result, work, original)
		controlConfig := controlv4.RegisteredPoolAuthorityConfig{Authority: d.Authority, Parent: session.ArtifactDigest, Candidate: 0, ServerKey: [32]byte(serverKey), ServerGrantKey: issuance[1].Preparation.Validation.Issuer.Key, ServerCertificateDER: control.ServerControlCertificateDER, Issue: issue, CancelOriginal: func() {
			cancelOriginal()
			if relayHost != nil {
				relayHost.Close()
			}
		}, WorkMS: work}
		cost, err = controlv4.RegisteredPoolAuthorityCharge(controlConfig)
		if err != nil {
			reporter.Fatal(err)
		}
		result.Control, err = controlv4.NewRegisteredPoolAuthority(controlConfig, h.Reserve(cost), h.Environment)
		if err != nil {
			reporter.Fatal(err)
		}
		reporter.Cleanup(func() { result.Control.Close(); reporter.ErrorIf(result.Control.WaitCleanup(context.Background())) })
		listener, err := net.ListenTCP("tcp", net.TCPAddrFromAddrPort(netip.AddrPortFrom(host, control.Port)))
		if err != nil {
			reporter.Fatal(err)
		}
		bounded := newLimitedListener(listener, 2)
		httpServer := &http.Server{Handler: result.Control, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, Certificates: []tls.Certificate{controlTLS}, NextProtos: []string{"http/1.1"}, ClientCAs: controlRoots, ClientAuth: tls.RequireAndVerifyClientCert, SessionTicketsDisabled: true}, MaxHeaderBytes: 8192, ReadHeaderTimeout: time.Duration(work) * time.Millisecond, ReadTimeout: time.Duration(work) * time.Millisecond, WriteTimeout: time.Duration(work) * time.Millisecond, IdleTimeout: time.Second}
		exited := make(chan struct{})
		var serveErr error
		go func() {
			defer close(exited)
			serveErr = httpServer.Serve(tls.NewListener(bounded, httpServer.TLSConfig))
		}()
		reporter.Cleanup(func() {
			result.Control.Close()
			_ = httpServer.Close()
			_ = bounded.Close()
			bounded.CloseConnections()
			<-exited
			httpServer.TLSConfig = nil
			if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) && !errors.Is(serveErr, net.ErrClosed) {
				reporter.ErrorIf(serveErr)
			}
		})
		endpoint := "https://" + netip.AddrPortFrom(host, control.Port).String() + "/flowersec/control/tunnel"
		if err = prepared(endpoint, material.Profile); err != nil {
			reporter.Fatal(err)
		}
		if err = result.Control.WaitPublished(ctx); err != nil {
			reporter.Fatal(err)
		}
		return result
	})
}

func newRegisteredPoolIssue(ctx context.Context, reporter *Reporter, h *sessionv4.PublicQUICTestHarness, d *RegisteredRelayDeployment, material Material, plan *protocolv4.PoolGrantPlan, maps [4]*protocolv4.SignedMap, mapping protocolv4.RelayIssuerMapping, table *ledgerv4.SQLiteRelayAuthorityTable, host *runtimehost.Relay, result *RegisteredPoolRelay, workMS uint64, original *RegisteredPoolOriginalOwner) func(context.Context) ([2][]byte, *ledgerv4.SQLitePoolWinnerContinuation, error) {
	var sourceID [16]byte
	var pool, authentication [32]byte
	var fenceSeed [32]byte
	var fenceID [16]byte
	for _, dst := range [][]byte{sourceID[:], pool[:], authentication[:], fenceSeed[:], fenceID[:]} {
		if _, err := rand.Read(dst); err != nil {
			reporter.Fatal(err)
		}
	}
	fenceSigner := registeredPeerSigner{key: ed25519.NewKeyFromSeed(fenceSeed[:])}
	clear(fenceSeed[:])
	reporter.Cleanup(func() { clear(fenceSigner.key); clear(authentication[:]) })
	now, err := h.Clock.Sample()
	if err != nil {
		reporter.Fatal(err)
	}
	clientDigest, err := maps[1].Digest("certificate_digest")
	if err != nil {
		reporter.Fatal(err)
	}
	serverDigest, err := maps[2].Digest("certificate_digest")
	if err != nil {
		reporter.Fatal(err)
	}
	identity := ledgerv4.SQLiteIdentity{Authority: mapping.Activation.SpendAuthority, Generation: 1}
	if _, err = rand.Read(identity.StoreID[:]); err != nil {
		reporter.Fatal(err)
	}
	verification := controlv4.PoolBatchVerificationConfig{Clock: h.Clock, Tenant: mapping.Parent.Tenant, Audience: mapping.EndpointAudience, CryptoProfile: material.Profile, SourceIncarnation: sourceID, ArtifactIssuer: mapping.ParentIssuer, Pool: pool, ClientIdentity: clientDigest, ServerIdentity: serverDigest, ActivationSigningKeyID: material.ActivationSigningKeyID, Trust: h.Lease.Trust, Root: h.Root, Owner: h.Owner(), Accounts: []resourcev4.Account{h.Scope[0].Tenant}, RuntimeBytes: 65536}
	verification.Routes[0] = &controlv4.PoolRelayRouteConfig{Mapping: mapping, Grants: [2]*protocolv4.NamespaceTrustStore{h.Lease.Trust[0], h.Lease.Trust[0]}, RelayTrust: h.Lease.Trust[0]}
	sourceConfig := controlv4.PoolSourceAuthorityConfig{Identity: identity, Fence: ledgerv4.TopUpSourceFence{Generation: 1, LeaseUntilMS: now.LowerMS + 60000}, Verification: verification, IssuanceLimits: controlv4.PoolSourceIssuanceLimits{MaxBatchCount: 1, MaxItemBytes: 65536}}
	cost, err := controlv4.PoolSourceAuthorityCharge(sourceConfig)
	if err != nil {
		reporter.Fatal(err)
	}
	ref, err := h.Root.Reserve(verification.Owner, cost, verification.Accounts...)
	if err != nil {
		reporter.Fatal(err)
	}
	reporter.Cleanup(ref.Release)
	source, err := controlv4.NewPoolSourceAuthority(sourceConfig, ref, h.Environment)
	if err != nil {
		reporter.Fatal(err)
	}
	reporter.Cleanup(func() { source.Close(); reporter.ErrorIf(source.WaitCleanup(context.Background())) })
	limits := ledgerv4.SQLiteLimits{MaxPages: 8192, MaxRecords: 4096, MaxRecordBytes: 524288, RuntimeBytes: 65536, ProviderRuntimeBytes: 4 << 20, DiskOverheadBytes: 65536}
	directory := reporter.TempDir()
	var backing *ledgerv4.SQLiteBacking
	var journal *ledgerv4.SQLiteTopUpServer
	reporter.Cleanup(func() {
		if journal != nil {
			journal.Close()
			reporter.ErrorIf(journal.WaitCleanup(context.Background()))
			reporter.ErrorIf(journal.Retire())
		}
		if backing != nil {
			backing.Close()
		}
		reporter.ErrorIf(os.RemoveAll(directory))
		if backing != nil {
			reporter.ErrorIf(backing.ReleaseRemoved())
		}
	})
	cost, err = ledgerv4.SQLiteBackingCharge(limits)
	if err != nil {
		reporter.Fatal(err)
	}
	backing, err = ledgerv4.NewSQLiteBacking(filepath.Join(directory, "pool-source.db"), limits, h.Reserve(cost), h.Environment)
	if err != nil {
		reporter.Fatal(err)
	}
	journalConfig := ledgerv4.SQLiteTopUpServerConfig{Tenant: mapping.Parent.Tenant, Source: sourceID, FenceKey: protocolv4.TopUpFenceAuthority{KeyID: fenceID, PublicKey: [32]byte(fenceSigner.PublicKey())}, RetirementSkewMS: 1, Clock: h.Clock, Authority: source}
	cost, err = ledgerv4.SQLiteTopUpServerCharge(limits, journalConfig)
	if err != nil {
		reporter.Fatal(err)
	}
	journal, err = ledgerv4.CreateSQLiteTopUpServer(ctx, backing, identity, engineeringNewHistory{identity}, journalConfig, h.Reserve(cost), h.Environment)
	if err != nil {
		reporter.Fatal(err)
	}
	factoryConfig := controlv4.PoolRelayFactoryConfig{Clock: h.Clock, Source: journal, Table: table, SourceIdentity: identity, Tenant: verification.Tenant, Audience: verification.Audience, CryptoProfile: verification.CryptoProfile, SourceIncarnation: sourceID, ArtifactIssuer: mapping.ParentIssuer, Pool: pool, ClientIdentity: clientDigest, ServerIdentity: serverDigest, ActivationSigningKeyID: material.ActivationSigningKeyID, Trust: h.Lease.Trust, Routes: verification.Routes, Root: h.Root, Owner: h.Owner(), Accounts: verification.Accounts, RuntimeBytes: 65536}
	cost, err = controlv4.PoolRelayFactoryCharge(factoryConfig)
	if err != nil {
		reporter.Fatal(err)
	}
	ref, err = h.Root.Reserve(factoryConfig.Owner, cost, factoryConfig.Accounts...)
	if err != nil {
		reporter.Fatal(err)
	}
	reporter.Cleanup(ref.Release)
	factory, err := controlv4.NewPoolRelayFactory(factoryConfig, ref, h.Environment)
	if err != nil {
		reporter.Fatal(err)
	}
	reporter.Cleanup(func() { factory.Close(); reporter.ErrorIf(factory.WaitCleanup(context.Background())) })
	codecCost, err := protocolv4.TopUpCodecBackingBytes()
	if err != nil {
		reporter.Fatal(err)
	}
	proofCost, err := protocolv4.SignedMapBackingBytes("OwnerFenceProof", 512, 64)
	if err != nil {
		reporter.Fatal(err)
	}
	parseCost, err := protocolv4.DecoderBackingBytes(65536, 4096)
	if err != nil {
		reporter.Fatal(err)
	}
	activationCost, err := protocolv4.DecoderBackingBytes(4096, 4096)
	if err != nil {
		reporter.Fatal(err)
	}
	// The original issuer buffers coexist with retained Grants and both
	// endpoint projections until the control owner and service have joined.
	owned := h.Reserve(resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(registeredPoolIssuer{})) + 524288 + 4096 + 512 + 9*65536 + 4*16384 + 128 + codecCost + proofCost + parseCost + activationCost, resourcev4.Items: 1, resourcev4.WorkSlots: 1})
	reporter.Cleanup(owned.Release)
	reporter.Cleanup(func() {
		for side := range result.Material {
			m := &result.Material[side]
			clear(m.IdentitySeed)
			clear(m.DHSeed)
			for _, tunnel := range m.Tunnels {
				clear(tunnel.Grant)
				clear(tunnel.RelayCertificate)
			}
			*m = Material{}
		}
	})
	codec, err := protocolv4.NewTopUpCodec()
	if err != nil {
		reporter.Fatal(err)
	}
	activationParser, err := protocolv4.NewDecoder(4096, 4096)
	if err != nil {
		reporter.Fatal(err)
	}
	activationDoc, err := activationParser.DecodeMap(material.Activation, "ActivationAuthorization", protocolv4.DecodeContext{Selectors: map[string]string{"activation_source_profile": "preauthorized_pool"}})
	if err != nil {
		reporter.Fatal(err)
	}
	expiry, ok := activationDoc.Root().Named("ActivationAuthorization", "activation_not_after_ms").Uint()
	activationDoc.Release()
	if !ok {
		reporter.Fatal("pool activation lacks its original initiation end")
	}
	issuer := &registeredPoolIssuer{plan: plan, policy: source, codec: codec, expiry: expiry, grants: [2][]byte{make([]byte, 65536), make([]byte, 65536)}, material: make([]byte, 65536), bundle: controlv4.PoolMaterialBundle{Artifact: material.Artifact, Activation: material.Activation, ClientCertificate: material.ClientCertificate, ServerCertificate: material.ServerCertificate, Tunnels: []controlv4.PoolTunnelMaterial{{CandidateIndex: 0, Role: 0, RelayCertificate: d.RelayCertificate}, {CandidateIndex: 0, Role: 1, RelayCertificate: d.RelayCertificate}}}}
	reporter.Cleanup(func() {
		for _, b := range issuer.grants {
			clear(b)
		}
		clear(issuer.material)
		issuer.bundle = controlv4.PoolMaterialBundle{}
	})
	var winner *ledgerv4.SQLitePoolWinnerContinuation
	var grants [2][]byte
	reporter.Cleanup(func() {
		winner.Close()
		for _, b := range grants {
			clear(b)
		}
	})
	serviceConfig := controlv4.PoolServiceConfig{Store: journal, Issuer: issuer, RelayPublications: factory, Tenant: mapping.Parent.Tenant, Source: sourceID, TopUpContract: sha256.Sum256([]byte("flowersec.parity.pool.top-up")), AckContract: sha256.Sum256([]byte("flowersec.parity.pool.ack")), ApplicationErrorCode: 1, CallMS: workMS, RuntimeBytes: 65536}
	serviceConfig.OriginalCommitted = func(call context.Context, request protocolv4.TopUpRequestFacts, response []byte, publication *ledgerv4.SQLitePoolRelayPublication) error {
		if original == nil {
			if err := host.DispatchOriginalRegisteredPool(call, request, response, publication); err != nil {
				return err
			}
		} else if err := publication.CheckOriginalMaterial(request, response); err != nil {
			return err
		}
		parser, err := protocolv4.NewDecoder(65536, 4096)
		if err != nil {
			return err
		}
		batch, err := codec.ParseResponse(response, request)
		if err != nil {
			return err
		}
		defer batch.Release()
		wire, err := batch.Material(0)
		if err != nil {
			return err
		}
		doc, err := parser.DecodeShape(wire, "", protocolv4.DecodeContext{})
		if err != nil {
			return err
		}
		defer doc.Release()
		for side := range 2 {
			grant, ok := doc.Root().Index(4).Index(side).Index(2).ByteString()
			if !ok {
				return ledgerv4.ErrOwner
			}
			grants[side] = bytes.Clone(grant)
		}
		lease, leaseOK := maps[0].Field("lease_id").ByteString()
		if !leaseOK || len(lease) != 16 {
			return ledgerv4.ErrOwner
		}
		proofParser, err := protocolv4.NewDecoder(4096, 4096)
		if err != nil {
			return err
		}
		proof, err := proofParser.DecodeMap(material.Activation, "ActivationAuthorization", protocolv4.DecodeContext{Selectors: map[string]string{"activation_source_profile": "preauthorized_pool"}})
		if err != nil {
			return err
		}
		attempt, ok := proof.Root().Named("ActivationAuthorization", "attempt_id").ByteString()
		if !ok || len(attempt) != 16 {
			proof.Release()
			return ledgerv4.ErrOwner
		}
		candidate, ok := maps[0].Field("candidates").Index(0).Named("Candidate", "candidate_id").ByteString()
		if !ok || len(candidate) != 16 {
			proof.Release()
			return ledgerv4.ErrOwner
		}
		key := protocolv4.RelayParentKey{Tenant: mapping.Parent.Tenant, Issuer: mapping.ParentIssuer, Lease: [16]byte(lease), Candidate: [16]byte(candidate), Attempt: [16]byte(attempt)}
		proof.Release()
		if original == nil {
			winner, err = publication.CaptureOriginalWinner(key, h.Reserve(ledgerv4.SQLitePoolWinnerContinuationCharge()), h.Environment)
		} else {
			winner, err = publication.CaptureOriginalRemoteWinner(key, h.Reserve(ledgerv4.SQLitePoolWinnerContinuationCharge()), h.Environment, original.MatchWinner)
		}
		if err != nil {
			return err
		}
		for side := range 2 {
			m := material
			m.Role = uint8(side)
			m.IdentitySeed, m.DHSeed = bytes.Clone(material.IdentitySeed), bytes.Clone(material.DHSeed)
			if side == 1 {
				clear(m.IdentitySeed)
				clear(m.DHSeed)
				m.IdentitySeed, m.DHSeed = bytes.Clone(d.ServerIdentitySeed), bytes.Clone(d.ServerDHSeed)
			}
			m.Tunnels = []TunnelMaterial{{CandidateIndex: 0, Role: 0, GrantNamespace: 0, RelayNamespace: 0, Grant: bytes.Clone(grants[0]), RelayCertificate: bytes.Clone(d.RelayCertificate)}, {CandidateIndex: 0, Role: 1, GrantNamespace: 0, RelayNamespace: 0, Grant: bytes.Clone(grants[1]), RelayCertificate: bytes.Clone(d.RelayCertificate)}}
			result.Material[side] = m
		}
		if original != nil {
			copy(result.originalRelayIdentitySeed[:], d.RelayIdentitySeed)
			identity, err := parseRegisteredOwnedTLSIdentity(d.NativeTLS.Relay.CertificatePEM, d.NativeTLS.Relay.PrivateKeyPEM)
			if err != nil {
				clear(result.originalRelayIdentitySeed[:])
				return err
			}
			result.originalRelayTLSIdentity = &identity
			defer func() { clear(result.originalRelayIdentitySeed[:]); result.originalRelayTLSIdentity = nil }()
			if err = original.Capture(call, result.PoolRelay); err != nil {
				return err
			}
			return publication.CheckOriginalMaterial(request, response)
		}
		return nil
	}
	cost, err = controlv4.PoolServiceCharge(serviceConfig)
	if err != nil {
		reporter.Fatal(err)
	}
	service, err := controlv4.NewPoolService(serviceConfig, h.Reserve(cost), h.Environment)
	if err != nil {
		reporter.Fatal(err)
	}
	reporter.Cleanup(func() { service.Close(); reporter.ErrorIf(service.WaitCleanup(context.Background())) })
	access := engineeringSourceAccess{tenant: mapping.Parent.Tenant, source: sourceID, principal: ledgerv4.AuditPrincipal{Actor: sha256.Sum256(authentication[:]), Role: 1}}
	return func(call context.Context) ([2][]byte, *ledgerv4.SQLitePoolWinnerContinuation, error) {
		fail := func(err error) ([2][]byte, *ledgerv4.SQLitePoolWinnerContinuation, error) {
			return [2][]byte{}, nil, err
		}
		sample, err := h.Clock.Sample()
		if err != nil {
			return fail(err)
		}
		request := protocolv4.TopUpRequestFacts{Tenant: mapping.Parent.Tenant, Source: sourceID, Pool: pool, Identity: clientDigest, Generation: 1, DeadlineMS: min(expiry, sample.LowerMS+workMS), DesiredCount: 1, MaxItemBytes: 65536}
		binary.BigEndian.PutUint64(request.Operation[:8], 1)
		if _, err = rand.Read(request.Operation[8:]); err != nil {
			return fail(err)
		}
		request.Digest, err = protocolv4.ComputeTopUpRequestDigest(request)
		if err != nil {
			return fail(err)
		}
		permit, err := source.AcquireTopUpCommit(identity, request.Tenant, request.Source)
		if err != nil {
			return fail(err)
		}
		defer permit.Release()
		guard := func() error {
			if err := call.Err(); err != nil {
				return err
			}
			if err := owned.Check(); err != nil {
				return err
			}
			if err := access.CheckTopUpAccess(request.Tenant, request.Source); err != nil {
				return err
			}
			if err := permit.Check(); err != nil {
				return err
			}
			current, err := source.CheckTopUpSource(identity, request.Tenant, request.Source)
			if err != nil {
				return err
			}
			if current != sourceConfig.Fence {
				return ledgerv4.ErrFenced
			}
			now, err := h.Clock.Sample()
			if err != nil {
				return err
			}
			if !now.Mark.SameEra(sample.Mark) || now.LowerMS < sample.LowerMS || !now.ValidBefore(min(request.DeadlineMS, current.LeaseUntilMS)) {
				return ledgerv4.ErrFenced
			}
			return nil
		}
		proofCodec, err := protocolv4.NewSignedMapCodec("OwnerFenceProof", 512, 64)
		if err != nil {
			return fail(err)
		}
		fields := []protocolv4.Field{{Name: "tenant_id", Kind: protocolv4.TextString, Text: request.Tenant}, {Name: "source_incarnation", Kind: protocolv4.ByteString, Bytes: request.Source[:]}, {Name: "operation_id", Kind: protocolv4.ByteString, Bytes: request.Operation[:]}, {Name: "request_digest", Kind: protocolv4.ByteString, Bytes: request.Digest[:]}, {Name: "current_generation", Number: 1}, {Name: "issued_at_ms", Number: sample.LowerMS}, {Name: "expires_at_ms", Number: min(sourceConfig.Fence.LeaseUntilMS, request.DeadlineMS)}, {Name: "authority_key_id", Kind: protocolv4.ByteString, Bytes: fenceID[:]}}
		signed, err := proofCodec.SignWith(fields, journalConfig.FenceKey.PublicKey, fenceSigner, protocolv4.DecodeContext{}, guard)
		if err != nil {
			return fail(err)
		}
		permit.Release()
		defer signed.Release()
		proof, err := signed.Bytes()
		if err != nil {
			return fail(err)
		}
		requestWire := make([]byte, 4096)
		defer clear(requestWire)
		n, err := codec.EncodeRequest(requestWire, request, proof)
		if err != nil {
			return fail(err)
		}
		output := make([]byte, 524288)
		defer clear(output)
		_, failure, err := service.Exchange(call, controlv4.ControlPoolTopUp, access, requestWire[:n], output)
		if err != nil {
			return fail(err)
		}
		if failure || winner == nil {
			return fail(ledgerv4.ErrOwner)
		}
		return [2][]byte{bytes.Clone(grants[0]), bytes.Clone(grants[1])}, winner, nil
	}
}
