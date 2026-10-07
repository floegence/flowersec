package interopharness

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

// NativeLiveTunnelInstallationOptions fixes the original topology before any
// endpoint starts. LocalRelay supports the existing local authority/relay path;
// the cross-runtime live-installation role always selects the remote owner.
type NativeLiveTunnelInstallationOptions struct {
	Carriers          [2]string
	EndpointListeners [2]bool
	Profile           string
	LocalRelay        bool
}

// NativeLiveTunnelInstallationOwner retains the original bootstrap service and
// installed policy until the driver has joined authority, relay and endpoint
// processes. Each private deployment is exported only to its intended owner.
type NativeLiveTunnelInstallationOwner struct {
	mu                                                                sync.Mutex
	reporter                                                          *Reporter
	directory                                                         string
	authorityPath, clientPath, serverPath, relayPath, publicationPath string
	controlEndpoint, relayEndpoint, profile                           string
	created                                                           []string
	projectionsDelegated, closed                                      bool
}

func (o *NativeLiveTunnelInstallationOwner) AuthorityPath() string {
	if o == nil {
		return ""
	}
	return o.authorityPath
}
func (o *NativeLiveTunnelInstallationOwner) ClientPath() string {
	if o == nil {
		return ""
	}
	return o.clientPath
}
func (o *NativeLiveTunnelInstallationOwner) ServerPath() string {
	if o == nil {
		return ""
	}
	return o.serverPath
}
func (o *NativeLiveTunnelInstallationOwner) RelayPath() string {
	if o == nil {
		return ""
	}
	return o.relayPath
}
func (o *NativeLiveTunnelInstallationOwner) PublicationPath() string {
	if o == nil {
		return ""
	}
	return o.publicationPath
}
func (o *NativeLiveTunnelInstallationOwner) Profile() string {
	if o == nil {
		return ""
	}
	return o.profile
}
func (o *NativeLiveTunnelInstallationOwner) ControlEndpoint() string {
	if o == nil {
		return ""
	}
	return o.controlEndpoint
}
func (o *NativeLiveTunnelInstallationOwner) RelayEndpoint() string {
	if o == nil {
		return ""
	}
	return o.relayEndpoint
}
func (o *NativeLiveTunnelInstallationOwner) Close() error {
	if o == nil {
		return nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return nil
	}
	err := o.reporter.Close()
	paths := append([]string(nil), o.created...)
	if o.projectionsDelegated {
		paths = append(paths, o.relayPath, o.publicationPath)
	}
	for _, path := range paths {
		if path == "" {
			continue
		}
		if e := os.Remove(path); e != nil && !errors.Is(e, os.ErrNotExist) {
			err = errors.Join(err, e)
		}
	}
	if err == nil {
		o.closed = true
	}
	return err
}

// PrepareNativeLiveTunnelInstallation creates pending original live material,
// fixed signing permissions and independent mTLS identities. No registration,
// activation authorization, Grant, durable spend or relay row is produced.
func PrepareNativeLiveTunnelInstallation(ctx context.Context, directory, origin string, options NativeLiveTunnelInstallationOptions) (owner *NativeLiveTunnelInstallationOwner, err error) {
	if ctx == nil || !filepath.IsAbs(directory) || !materialHTTPS(origin) {
		return nil, errors.New("original live installation requires an absolute empty directory and Origin")
	}
	if options.Profile == "" {
		options.Profile = protocolv4.DHProfileX25519
	}
	if options.Profile != protocolv4.DHProfileX25519 && options.Profile != protocolv4.DHProfileP256 {
		return nil, errors.New("original live installation profile is unsupported")
	}
	for _, carrier := range options.Carriers {
		if carrier != "raw-quic" && carrier != "websocket" && carrier != "webtransport" {
			return nil, errors.New("original live installation requires both selected native carriers")
		}
	}
	absolute, err := filepath.EvalSymlinks(directory)
	if err != nil {
		return nil, err
	}
	working, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	working, err = filepath.EvalSymlinks(working)
	if err != nil {
		return nil, err
	}
	for _, root := range []string{working, os.TempDir(), "/tmp", "/private/tmp"} {
		relative, e := filepath.Rel(root, absolute)
		if e == nil && relative != ".." && !filepath.IsAbs(relative) && !strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
			return nil, errors.New("original live installation must stay outside checkout and system temporary roots")
		}
	}
	entries, err := os.ReadDir(absolute)
	if err != nil || len(entries) != 0 {
		return nil, errors.New("original live installation directory must be empty")
	}
	reporter, err := NewPeerReporter()
	if err != nil {
		return nil, err
	}
	owner = &NativeLiveTunnelInstallationOwner{reporter: reporter, directory: absolute, authorityPath: filepath.Join(absolute, "live-authority-deployment.json"), clientPath: filepath.Join(absolute, "live-client-deployment.json"), serverPath: filepath.Join(absolute, "live-server-deployment.json"), relayPath: filepath.Join(absolute, "live-relay-installation.json"), publicationPath: filepath.Join(absolute, "live-endpoint-publication.json"), profile: options.Profile}
	defer func(original *NativeLiveTunnelInstallationOwner) {
		if err != nil {
			err = errors.Join(err, original.Close())
			owner = nil
		}
	}(owner)
	var declaration RegisteredRelayDeployment
	var client RegisteredLiveClientInstallation
	var server RegisteredLiveServerDeployment
	var registration Material
	// These are fixture-owned copies, registered before every bootstrap and
	// signing owner so failed construction and normal close use the same order.
	reporter.Cleanup(func() {
		declaration.ReleaseOwnedPrivateMaterial()
		releaseOwnedMaterial(&registration)
		client.Control.TLS.PrivateKeyPEM = ""
		if client.RelayControl != nil {
			client.RelayControl.TLS.PrivateKeyPEM = ""
		}
		clear(server.IdentitySeed)
		server.IdentitySeed = nil
		clear(server.NoiseSeed)
		server.NoiseSeed = nil
		server.RegistrationJSON = ""
		server.PrivateKeyPEM = ""
		server.Control.TLS.PrivateKeyPEM = ""
		if server.RelayControl != nil {
			server.RelayControl.TLS.PrivateKeyPEM = ""
		}
	})
	_, err = construct(reporter, func() bool {
		reporter.ApplicationProfile = "services"
		reporter.MaxStreams = nativeParityMaxStreams
		reporter.originalLiveDeployment = true
		var probes []io.Closer
		defer func() {
			for _, probe := range probes {
				_ = probe.Close()
			}
		}()
		reserve := func(carrier string) netip.AddrPort {
			if carrier == "websocket" {
				listener, e := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
				if e != nil {
					reporter.Fatal(e)
				}
				probes = append(probes, listener)
				return listener.Addr().(*net.TCPAddr).AddrPort()
			}
			listener, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if e != nil {
				reporter.Fatal(e)
			}
			probes = append(probes, listener)
			return listener.LocalAddr().(*net.UDPAddr).AddrPort()
		}
		addresses := [2]netip.AddrPort{reserve(options.Carriers[0]), reserve(options.Carriers[1])}
		controlAddress, relayControlAddress := reserve("websocket"), reserve("websocket")
		owner.controlEndpoint = "https://" + net.JoinHostPort("localhost", strconv.Itoa(int(controlAddress.Port()))) + "/flowersec/control/live"
		owner.relayEndpoint = "https://" + net.JoinHostPort("localhost", strconv.Itoa(int(relayControlAddress.Port()))) + "/"
		bootstrapTLS, _, bootstrapTrust, _, e := TLSMaterial("127.0.0.1")
		if e != nil {
			reporter.Fatal(e)
		}
		relayTLS, _, relayTrust, tlsPolicy, e := TLSMaterial("127.0.0.1")
		if e != nil {
			reporter.Fatal(e)
		}
		clientTLS, _, clientTrust, _, e := TLSMaterial("127.0.0.1")
		if e != nil {
			reporter.Fatal(e)
		}
		serverTLS, _, serverTrust, _, e := TLSMaterial("127.0.0.1")
		if e != nil {
			reporter.Fatal(e)
		}
		controlTLS, _, controlTrust, _, e := TLSMaterial("127.0.0.1")
		if e != nil {
			reporter.Fatal(e)
		}
		relayControlTLS, _, relayControlTrust, _, e := TLSMaterial("127.0.0.1")
		if e != nil {
			reporter.Fatal(e)
		}
		issuerTLS, _, e := engineeringControlClientTLS()
		if e != nil {
			reporter.Fatal(e)
		}
		clientControlTLS, _, e := engineeringControlClientTLS()
		if e != nil {
			reporter.Fatal(e)
		}
		serverControlTLS, _, e := engineeringControlClientTLS()
		if e != nil {
			reporter.Fatal(e)
		}
		nativeTrust := bootstrapTrust + relayTrust + clientTrust + serverTrust
		route, relayProfile, e := engineeringRelayRoute(reporter, options.Carriers, addresses, tlsPolicy, origin, options.EndpointListeners)
		if e != nil {
			reporter.Fatal(e)
		}
		var relaySeed, grantSeed [32]byte
		var grantIssuer [16]byte
		for _, value := range [][]byte{relaySeed[:], grantSeed[:], grantIssuer[:]} {
			if _, e = rand.Read(value); e != nil {
				reporter.Fatal(e)
			}
		}
		defer clear(relaySeed[:])
		defer clear(grantSeed[:])
		limits := nativeParityRelayLimits(options.Carriers)
		recipe := sessionv4.EngineeringTunnelRecipe{Route: route, RelaySubject: "parity-live-relay", RelayAudience: "flowersec.parity.live.relay", RelayIdentitySeed: relaySeed, GrantIssuerID: grantIssuer, GrantIssuerSeed: grantSeed, Limits: [2]protocolv4.RelayGrantLimits{limits, limits}}
		defer clear(recipe.RelayIdentitySeed[:])
		defer clear(recipe.GrantIssuerSeed[:])
		if e = reporter.SetTunnelRecipe(recipe); e != nil {
			reporter.Fatal(e)
		}
		authority := sessionv4.NewEngineeringNativeHarness(reporter, "live_authority", options.Profile, options.Carriers[0], addresses[0], tlsPolicy, origin, limits.DatagramBytes != 0)
		if authority.Tunnel == nil || authority.Live != nil || authority.Pool != nil || authority.Store != nil || len(authority.Lease.Proof) != 0 || len(authority.Tunnel.Grants[0]) != 0 || len(authority.Tunnel.Grants[1]) != 0 {
			reporter.Fatal("original live installation cannot contain a preissued authorization or durable invocation")
		}
		// This holder has no SDK Environment or material response. It exposes only
		// the fixture's original bootstrap service and signed pending registry.
		bootstrap := &Server{Runtime: &Runtime{Reporter: reporter, Authority: authority}, Address: addresses[0], certificate: bootstrapTLS, TrustPEM: bootstrapTrust, Origin: origin}
		namespace, e := bootstrap.startBootstrap(reporter)
		if e != nil {
			reporter.Fatal(e)
		}
		bootstrap.Namespace = namespace
		registration = bootstrap.Material()
		registration.LiveControlBaseURL = owner.controlEndpoint
		registration.Activation = nil
		registration.RelayDeployment = protocolv4.RelayDeploymentBinding{Profile: relayProfile, RouteDigest: authority.BrowserRouteDigest}
		decoder, e := protocolv4.NewDecoder(65536, 4096)
		if e != nil {
			reporter.Fatal(e)
		}
		parent, e := decoder.DecodeMap(registration.Artifact, "Artifact", protocolv4.DecodeContext{})
		if e != nil {
			reporter.Fatal(e)
		}
		defer parent.Release()
		tenant, tenantOK := parent.Root().Named("Artifact", "tenant_id").Text()
		audience, audienceOK := parent.Root().Named("Artifact", "audience").Text()
		policyID, policyOK := parent.Root().Named("Artifact", "revocation_policy_id").Text()
		revision, revisionOK := parent.Root().Named("Artifact", "revocation_policy_revision").Uint()
		initiation, endOK := parent.Root().Named("Artifact", "initiation_not_after_ms").Uint()
		maxFrame, frameOK := parent.Root().Named("Artifact", "session_contract").Named("SessionContract", "max_frame").Uint()
		if !tenantOK || !audienceOK || !policyOK || !revisionOK || !endOK || !frameOK || maxFrame == 0 || maxFrame > 65536 {
			reporter.Fatal("original live parent lacks its independently installed policy")
		}
		// The pending live contract fixes the frame bound independently of the
		// pool fixture. Its original Grant must carry that exact envelope size.
		limits.EnvelopeBytes = maxFrame + uint64(protocolv4.EnvelopePrefixSize)
		grantEnd := min(initiation, reporter.epoch+60000)
		registration.Tunnels = make([]TunnelMaterial, 2)
		for side := range 2 {
			registration.Tunnels[side] = TunnelMaterial{CandidateIndex: 0, Role: uint8(side), LiveGrant: &LiveGrantMaterial{Authority: namespace.Authority, IssuerKeyID: append([]byte(nil), grantIssuer[:]...), Audience: recipe.RelayAudience, Service: audience, RevocationPolicyID: policyID, RevocationPolicyRevision: strconv.FormatUint(revision, 10), MaxNotAfterMS: strconv.FormatUint(grantEnd, 10)}, RelayCertificate: append([]byte(nil), authority.Tunnel.RelayCertificate...), GrantNamespace: 0, RelayNamespace: 0}
		}
		registrationJSON, e := registration.JSON()
		if e != nil {
			reporter.Fatal(e)
		}
		declaration = RegisteredRelayDeployment{WireRevision: 4, MaterialPublicationPath: owner.publicationPath, RegistrationJSON: registrationJSON, ServerIdentitySeed: append([]byte(nil), authority.EngineeringServerIdentitySeed[:]...), ServerDHSeed: append([]byte(nil), authority.EngineeringServerDHSeed[:]...), RelayIdentitySeed: append([]byte(nil), relaySeed[:]...), RelayCertificate: append([]byte(nil), authority.Tunnel.RelayCertificate...), Authority: "parity.live.relay", RelayAudience: recipe.RelayAudience, RelaySubject: recipe.RelaySubject, Service: audience, ControlTrustPEM: bootstrapTrust, Origin: origin, LiveControl: &RegisteredRelayLiveInstallation{Host: controlAddress.Addr().String(), Port: controlAddress.Port(), ClientControlCertificateDER: append([]byte(nil), clientControlTLS.Certificate[0]...), ServerControlCertificateDER: append([]byte(nil), serverControlTLS.Certificate[0]...), SigningKeyID: registration.ActivationSigningKeyID, ActivationSeed: append([]byte(nil), authority.EngineeringActivationSeed[:]...), MaxActivationMS: "60000", MaxSessionMS: "840000", WorkMS: "10000", ApplicationPolicy: "allow"}}
		for side := range 2 {
			declaration.Signing[side] = RegisteredRelaySignerInstallation{Namespace: 0, IssuerKeyID: append([]byte(nil), grantIssuer[:]...), Seed: append([]byte(nil), grantSeed[:]...), RevocationPolicyID: policyID, RevocationPolicyRevision: strconv.FormatUint(revision, 10)}
		}
		declaration.Limits.EnvelopeBytes = limits.EnvelopeBytes
		declaration.Limits.TotalBytes = strconv.FormatUint(limits.TotalBytes, 10)
		declaration.Limits.DatagramBytes = limits.DatagramBytes
		declaration.Limits.RateBytesPerSecond = strconv.FormatUint(limits.RateBytesPerSecond, 10)
		declaration.Limits.QueueBytes = limits.QueueBytes
		declaration.Limits.PendingMappings = limits.PendingMappings
		declaration.Limits.ResidentMappings = limits.ResidentMappings
		declaration.Limits.TotalMappings = limits.TotalMappings
		declaration.Limits.QueueItems = limits.QueueItems
		declaration.NativeTLS.TrustPEM = nativeTrust
		declaration.NativeTLS.Relay = ownedLiveTLSInstallation(reporter, relayTLS, "")
		declaration.NativeTLS.Client = ownedLiveTLSInstallation(reporter, clientTLS, "")
		declaration.NativeTLS.Server = ownedLiveTLSInstallation(reporter, serverTLS, "")
		authorityTLS := ownedLiveTLSInstallation(reporter, controlTLS, "")
		declaration.LiveControl.TLS.CertificatePEM = authorityTLS.CertificatePEM
		declaration.LiveControl.TLS.PrivateKeyPEM = authorityTLS.PrivateKeyPEM
		authorityTLS.PrivateKeyPEM = ""
		clientIdentity := ownedLiveTLSInstallation(reporter, clientControlTLS, controlTrust)
		serverIdentity := ownedLiveTLSInstallation(reporter, serverControlTLS, controlTrust)
		issuerIdentity := ownedLiveTLSInstallation(reporter, issuerTLS, relayControlTrust)
		declaration.LiveControl.TLS.ClientTrustPEM = engineeringTrustPEM(clientControlTLS) + engineeringTrustPEM(serverControlTLS)
		client = RegisteredLiveClientInstallation{Tenant: tenant, Audience: audience, Control: RegisteredControlInstallation{Endpoint: owner.controlEndpoint, Authority: declaration.Authority, TLS: clientIdentity, WorkMS: "10000"}}
		serverMaterial := registration
		serverMaterial.Role = 1
		serverMaterial.IdentitySeed = declaration.ServerIdentitySeed
		serverMaterial.DHSeed = declaration.ServerDHSeed
		serverJSON, e := serverMaterial.JSON()
		if e != nil {
			reporter.Fatal(e)
		}
		server = RegisteredLiveServerDeployment{WireRevision: 4, RegistrationJSON: serverJSON, IdentitySeed: append([]byte(nil), declaration.ServerIdentitySeed...), NoiseSeed: append([]byte(nil), declaration.ServerDHSeed...), RelayCertificate: append([]byte(nil), authority.Tunnel.RelayCertificate...), RelayAudience: recipe.RelayAudience, RelayService: audience, RelaySubject: recipe.RelaySubject, Control: RegisteredControlInstallation{Endpoint: owner.controlEndpoint, Authority: declaration.Authority, TLS: serverIdentity, WorkMS: "10000"}, TrustPEM: nativeTrust, Origin: origin, CertificatePEM: declaration.NativeTLS.Server.CertificatePEM, PrivateKeyPEM: declaration.NativeTLS.Server.PrivateKeyPEM}
		if !options.LocalRelay {
			relayIdentity := ownedLiveTLSInstallation(reporter, relayControlTLS, "")
			remote := &RegisteredRemoteRelayInstallation{Endpoint: owner.relayEndpoint, ServerAdmissionAuthority: authority.BrowserOnceAuthority, TLS: issuerIdentity, IssuerCertificateDER: append([]byte(nil), issuerTLS.Certificate[0]...), InstallationPath: owner.relayPath, Control: RelayPublicLiveControl{Endpoint: owner.relayEndpoint, Host: relayControlAddress.Addr().String(), Port: relayControlAddress.Port(), WorkMS: "10000", TLS: RelayPublicControlTLS{CertificatePEM: relayIdentity.CertificatePEM, PrivateKeyPEM: relayIdentity.PrivateKeyPEM, ClientTrustPEM: engineeringTrustPEM(issuerTLS) + engineeringTrustPEM(clientControlTLS) + engineeringTrustPEM(serverControlTLS)}}}
			declaration.RemoteRelay = remote
			aRelay, bRelay := clientIdentity, serverIdentity
			aRelay.TrustPEM = relayControlTrust
			bRelay.TrustPEM = relayControlTrust
			client.RelayControl = &RegisteredControlInstallation{Endpoint: owner.relayEndpoint, Authority: declaration.Authority, TLS: aRelay, WorkMS: "10000"}
			server.RelayControl = &RegisteredControlInstallation{Endpoint: owner.relayEndpoint, Authority: declaration.Authority, TLS: bRelay, WorkMS: "10000"}
		}
		if e = owner.writeInstallation(owner.authorityPath, &declaration); e != nil {
			reporter.Fatal(e)
		}
		if e = owner.writeInstallation(owner.clientPath, &client); e != nil {
			reporter.Fatal(e)
		}
		if e = owner.writeInstallation(owner.serverPath, &server); e != nil {
			reporter.Fatal(e)
		}
		directoryFile, e := os.Open(absolute)
		if e != nil {
			reporter.Fatal(e)
		}
		e = errors.Join(directoryFile.Sync(), directoryFile.Close())
		if e != nil {
			reporter.Fatal(e)
		}
		owner.projectionsDelegated = true
		return true
	})
	if err != nil {
		return nil, err
	}
	return owner, nil
}

func ownedLiveTLSInstallation(reporter *Reporter, certificate tls.Certificate, trustPEM string) RegisteredControlTLSInstallation {
	if len(certificate.Certificate) == 0 || certificate.PrivateKey == nil {
		reporter.Fatal("one original TLS identity is required")
	}
	key, e := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
	if e != nil {
		reporter.Fatal(e)
	}
	defer clear(key)
	encoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})
	defer clear(encoded)
	return RegisteredControlTLSInstallation{CertificatePEM: engineeringCertificatePEM(certificate), PrivateKeyPEM: string(encoded), TrustPEM: trustPEM}
}
func (o *NativeLiveTunnelInstallationOwner) writeInstallation(path string, value any) (err error) {
	wire, err := json.Marshal(value)
	if err != nil {
		return err
	}
	defer clear(wire)
	if len(wire) == 0 || len(wire) > 4<<20 {
		return errors.New("original live installation exceeds its bounded file")
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	o.created = append(o.created, path)
	n, err := file.Write(wire)
	if err == nil && n != len(wire) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = file.Sync()
	}
	return errors.Join(err, file.Close())
}
