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

// NativeTunnelInstallationOptions selects the original physical route and an
// optional remote registered B before either peer can publish an authorization.
type NativeTunnelInstallationOptions struct {
	Carriers          [2]string
	EndpointListeners [2]bool
	RegisteredServer  bool
}

// NativeTunnelInstallationOwner prepares an original independent pool authority
// installation. No Go Grants, native attempts, relay rows or admission receipts
// are created. The installed TS original issuer owns B preparation and the first
// real paired Grant publication against its original ParentWinner store.
type NativeTunnelInstallationOwner struct {
	mu                                                sync.Mutex
	reporter                                          *Reporter
	directory, path, publication                      string
	closed, installationCreated, publicationDelegated bool
	relayPath, serverPath, clientPath                 string
	created                                           []string
}

func (o *NativeTunnelInstallationOwner) Path() string {
	if o == nil {
		return ""
	}
	return o.path
}
func (o *NativeTunnelInstallationOwner) Profile() string    { return protocolv4.DHProfileX25519 }
func (o *NativeTunnelInstallationOwner) RelayPath() string  { return o.relayPath }
func (o *NativeTunnelInstallationOwner) ServerPath() string { return o.serverPath }
func (o *NativeTunnelInstallationOwner) ClientPath() string { return o.clientPath }
func (o *NativeTunnelInstallationOwner) Close() error {
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
	if o.installationCreated {
		paths = append(paths, o.path)
	}
	if o.publicationDelegated {
		paths = append(paths, o.publication)
	}
	for _, path := range paths {
		if removeErr := os.Remove(path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			err = errors.Join(err, removeErr)
		}
	}
	if err == nil {
		o.closed = true
	}
	return err
}
func PrepareNativeTunnelInstallation(ctx context.Context, directory, origin string, selections ...NativeTunnelInstallationOptions) (owner *NativeTunnelInstallationOwner, err error) {
	options := NativeTunnelInstallationOptions{Carriers: [2]string{"raw-quic", "raw-quic"}}
	if len(selections) > 1 {
		return nil, errors.New("one original native tunnel topology is required")
	}
	if len(selections) == 1 {
		options = selections[0]
	}
	for _, carrier := range options.Carriers {
		if carrier != "raw-quic" && carrier != "websocket" {
			return nil, errors.New("unsupported original native tunnel carrier")
		}
	}
	if ctx == nil || !filepath.IsAbs(directory) || !materialHTTPS(origin) {
		return nil, errors.New("original native tunnel installation directory and Origin are required")
	}
	absolute, err := filepath.EvalSymlinks(directory)
	if err != nil {
		return nil, err
	}
	for _, root := range []string{os.TempDir(), "/tmp", "/private/tmp"} {
		relative, e := filepath.Rel(root, absolute)
		if e == nil && relative != ".." && !filepath.IsAbs(relative) && !strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
			return nil, errors.New("native installation cannot use a system temporary root")
		}
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 0 {
		return nil, errors.New("original native tunnel installation directory must be empty")
	}
	reporter, err := NewPeerReporter()
	if err != nil {
		return nil, err
	}
	owner = &NativeTunnelInstallationOwner{reporter: reporter, directory: directory, path: filepath.Join(directory, "native-tunnel-installation.json"), publication: filepath.Join(directory, "native-tunnel-material.json")}
	defer func(original *NativeTunnelInstallationOwner) {
		if err != nil {
			err = errors.Join(err, original.Close())
			owner = nil
		}
	}(owner)
	_, err = construct(reporter, func() bool {
		reporter.ApplicationProfile = "services"
		reporter.MaxStreams = nativeParityMaxStreams
		reporter.originalPoolDeployment = true
		relayTLS, relayRoots, relayTrust, tlsPolicy, e := nativeTunnelTLSMaterial("127.0.0.1")
		if e != nil {
			reporter.Fatal(e)
		}
		_ = relayRoots
		clientTLS, _, clientTrust, _, e := nativeTunnelTLSMaterial("127.0.0.1")
		if e != nil {
			reporter.Fatal(e)
		}
		serverTLS, _, serverTrust, _, e := nativeTunnelTLSMaterial("127.0.0.1")
		if e != nil {
			reporter.Fatal(e)
		}
		var probes []io.Closer
		defer func() {
			for _, probe := range probes {
				_ = probe.Close()
			}
		}()
		reserve := func(carrier string) netip.AddrPort {
			if carrier == "websocket" {
				probe, e := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
				if e != nil {
					reporter.Fatal(e)
				}
				probes = append(probes, probe)
				return probe.Addr().(*net.TCPAddr).AddrPort()
			}
			probe, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if e != nil {
				reporter.Fatal(e)
			}
			probes = append(probes, probe)
			return probe.LocalAddr().(*net.UDPAddr).AddrPort()
		}
		addresses := [2]netip.AddrPort{reserve(options.Carriers[0]), reserve(options.Carriers[1])}
		route, relayProfile, e := engineeringRelayRoute(reporter, options.Carriers, addresses, tlsPolicy, origin, options.EndpointListeners)
		if e != nil {
			reporter.Fatal(e)
		}
		var relaySeed, grantSeed [32]byte
		var grantIssuer [16]byte
		for _, bytes := range [][]byte{relaySeed[:], grantSeed[:], grantIssuer[:]} {
			if _, e = rand.Read(bytes); e != nil {
				reporter.Fatal(e)
			}
		}
		defer clear(relaySeed[:])
		defer clear(grantSeed[:])
		limits := nativeParityRelayLimits(options.Carriers)
		recipe := sessionv4.EngineeringTunnelRecipe{Route: route, RelaySubject: "parity-relay", RelayAudience: "flowersec.parity.relay", RelayIdentitySeed: relaySeed, GrantIssuerID: grantIssuer, GrantIssuerSeed: grantSeed, Limits: [2]protocolv4.RelayGrantLimits{limits, limits}}
		if e = reporter.SetTunnelRecipe(recipe); e != nil {
			reporter.Fatal(e)
		}
		authority := sessionv4.NewEngineeringNativeHarness(reporter, "preauthorized_pool", protocolv4.DHProfileX25519, options.Carriers[0], addresses[0], tlsPolicy, origin, limits.DatagramBytes != 0)
		if authority.PoolIssue == nil || authority.Tunnel == nil || len(authority.Tunnel.Grants[0]) != 0 || len(authority.Tunnel.Grants[1]) != 0 {
			reporter.Fatal("native installation requires an unissued original pool registration")
		}
		runtime, e := NewRuntime(ctx, reporter, authority, nil, nil)
		if e != nil {
			reporter.Fatal(e)
		}
		bootstrap := &Server{Runtime: runtime, Address: addresses[0], certificate: relayTLS, TrustPEM: relayTrust, Origin: origin}
		namespace, e := bootstrap.startBootstrap(reporter)
		if e != nil {
			reporter.Fatal(e)
		}
		bootstrap.Namespace = namespace
		registration := bootstrap.Material()
		// This source recipe has never issued a Grant. Its public registration does
		// not import a later material delivery or any committed relay observation.
		registration.Tunnels = []TunnelMaterial{}
		registration.RelayDeployment = protocolv4.RelayDeploymentBinding{RouteDigest: authority.BrowserRouteDigest, Profile: relayProfile}
		registrationJSON, e := registration.JSON()
		if e != nil {
			reporter.Fatal(e)
		}
		source := authority.PoolIssue
		certMap, e := protocolv4.NewSignedMapCodec("IdentityCertificate", 16384, 4096)
		if e != nil {
			reporter.Fatal(e)
		}
		relay, e := certMap.VerifyCredential(authority.Tunnel.RelayCertificate, source.Base.Trust[0])
		if e != nil {
			reporter.Fatal(e)
		}
		credential, e := relay.DetachCredential()
		relay.Release()
		if e != nil {
			reporter.Fatal(e)
		}
		relayScope := credential.Scope()
		grantSigner := RegisteredRelaySignerInstallation{Namespace: 0, IssuerKeyID: append([]byte(nil), grantIssuer[:]...), Seed: append([]byte(nil), grantSeed[:]...), RevocationPolicyID: source.Base.RevocationPolicyID, RevocationPolicyRevision: strconv.FormatUint(source.Base.RevocationPolicyRevision, 10)}
		defer clear(grantSigner.Seed)
		declaration := RegisteredRelayDeployment{WireRevision: 4, MaterialPublicationPath: owner.publication, RegistrationJSON: registrationJSON, ServerIdentitySeed: append([]byte(nil), source.ServerIdentitySeed[:]...), ServerDHSeed: append([]byte(nil), source.ServerDHSeed[:]...), RelayIdentitySeed: append([]byte(nil), relaySeed[:]...), RelayCertificate: append([]byte(nil), authority.Tunnel.RelayCertificate...), Authority: "winner-1", RelayAudience: relayScope.Audience, RelaySubject: relayScope.Subject, Service: source.Base.Audience, ControlTrustPEM: relayTrust, Origin: origin, Signing: [2]RegisteredRelaySignerInstallation{grantSigner, grantSigner}}
		defer clear(declaration.ServerIdentitySeed)
		defer clear(declaration.ServerDHSeed)
		defer clear(declaration.RelayIdentitySeed)
		limits = authority.Tunnel.Limits[0]
		declaration.Limits.EnvelopeBytes = limits.EnvelopeBytes
		declaration.Limits.TotalBytes = strconv.FormatUint(limits.TotalBytes, 10)
		declaration.Limits.DatagramBytes = limits.DatagramBytes
		declaration.Limits.RateBytesPerSecond = strconv.FormatUint(limits.RateBytesPerSecond, 10)
		declaration.Limits.QueueBytes = limits.QueueBytes
		declaration.Limits.PendingMappings = limits.PendingMappings
		declaration.Limits.ResidentMappings = limits.ResidentMappings
		declaration.Limits.TotalMappings = limits.TotalMappings
		declaration.Limits.QueueItems = limits.QueueItems
		tlsFields := func(certificate tls.Certificate) map[string]string {
			var certificatePEM strings.Builder
			for _, der := range certificate.Certificate {
				certificatePEM.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
			}
			key, e := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
			if e != nil {
				reporter.Fatal(e)
			}
			defer clear(key)
			return map[string]string{"certificatePEM": certificatePEM.String(), "privateKeyPEM": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}))}
		}
		// Independently provision A's Allow sender and B's exact mTLS pin.
		allowAddress := reserve("websocket")
		allowTLS, _, allowTrust, _, e := nativeTunnelTLSMaterial("127.0.0.1")
		if e != nil {
			reporter.Fatal(e)
		}
		allowClientTLS, _, e := engineeringControlClientTLS()
		if e != nil {
			reporter.Fatal(e)
		}
		allowEndpoint := "https://" + allowAddress.String() + "/tunnel/server-allow"
		serverAllow := &RegisteredPoolAllowInstallation{Endpoint: allowEndpoint, TLS: ownedLiveTLSInstallation(reporter, allowTLS, engineeringTrustPEM(allowClientTLS)), ClientCertificateDER: append([]byte(nil), allowClientTLS.Certificate[0]...), WorkMS: "2000"}
		client := RegisteredPoolClientInstallation{WireRevision: 4, Tenant: namespace.Tenant, Audience: source.Base.Audience, ServerAllow: RegisteredPoolAllowInstallation{Endpoint: allowEndpoint, TLS: ownedLiveTLSInstallation(reporter, allowClientTLS, allowTrust), WorkMS: "2000"}}
		if options.RegisteredServer {
			controlAddress := reserve("websocket")
			controlTLS, _, controlTrust, _, e := nativeTunnelTLSMaterial("127.0.0.1")
			if e != nil {
				reporter.Fatal(e)
			}
			serverControlTLS, _, e := engineeringControlClientTLS()
			if e != nil {
				reporter.Fatal(e)
			}
			controlIdentity := tlsFields(controlTLS)
			control, e := json.Marshal(map[string]any{"host": controlAddress.Addr().String(), "port": controlAddress.Port(), "workMS": "10000",
				"tls":                         map[string]string{"certificatePEM": controlIdentity["certificatePEM"], "privateKeyPEM": controlIdentity["privateKeyPEM"], "clientTrustPEM": engineeringTrustPEM(serverControlTLS)},
				"serverControlCertificateDER": serverControlTLS.Certificate[0]})
			if e != nil {
				reporter.Fatal(e)
			}
			declaration.ServerControl = control
			defer clear(control)
			declaration.NativeTLS.TrustPEM = relayTrust + clientTrust + serverTrust
			declaration.NativeTLS.Relay = ownedLiveTLSInstallation(reporter, relayTLS, "")
			declaration.NativeTLS.Client = ownedLiveTLSInstallation(reporter, clientTLS, "")
			declaration.NativeTLS.Server = ownedLiveTLSInstallation(reporter, serverTLS, "")
			serverMaterial := registration
			serverMaterial.Role = 1
			serverMaterial.IdentitySeed = declaration.ServerIdentitySeed
			serverMaterial.DHSeed = declaration.ServerDHSeed
			serverJSON, e := serverMaterial.JSON()
			if e != nil {
				reporter.Fatal(e)
			}
			server := RegisteredLiveServerDeployment{WireRevision: 4, RegistrationJSON: serverJSON, IdentitySeed: declaration.ServerIdentitySeed, NoiseSeed: declaration.ServerDHSeed,
				RelayCertificate: declaration.RelayCertificate, RelayAudience: declaration.RelayAudience, RelayService: declaration.Service, RelaySubject: declaration.RelaySubject,
				Control:  RegisteredControlInstallation{Endpoint: "https://" + controlAddress.String() + "/flowersec/control/tunnel", Authority: declaration.Authority, TLS: ownedLiveTLSInstallation(reporter, serverControlTLS, controlTrust), WorkMS: "10000"},
				TrustPEM: declaration.NativeTLS.TrustPEM, Origin: origin, CertificatePEM: declaration.NativeTLS.Server.CertificatePEM, PrivateKeyPEM: declaration.NativeTLS.Server.PrivateKeyPEM}
			server.ServerAllow = serverAllow
			owner.clientPath = filepath.Join(directory, "pool-client-deployment.json")
			owner.relayPath = filepath.Join(directory, "pool-relay-deployment.json")
			owner.serverPath = filepath.Join(directory, "pool-server-deployment.json")
			for _, installed := range []struct {
				path  string
				value any
			}{{owner.relayPath, &declaration}, {owner.serverPath, &server}, {owner.clientPath, &client}} {
				wire, e := json.Marshal(installed.value)
				if e != nil {
					reporter.Fatal(e)
				}
				if len(wire) == 0 || len(wire) > 4<<20 {
					clear(wire)
					reporter.Fatal("original pool installation exceeds its input bound")
				}
				file, e := os.OpenFile(installed.path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
				if e != nil {
					clear(wire)
					reporter.Fatal(e)
				}
				owner.created = append(owner.created, installed.path)
				count, e := file.Write(wire)
				if e == nil && count != len(wire) {
					e = io.ErrShortWrite
				}
				clear(wire)
				if e == nil {
					e = file.Sync()
				}
				if e = errors.Join(e, file.Close()); e != nil {
					reporter.Fatal(e)
				}
			}
		}
		relayIdentity := tlsFields(relayTLS)
		installation := map[string]any{"schema_version": 1, "deployment": declaration, "origin": origin, "trustPEM": relayTrust + clientTrust + serverTrust, "certificatePEM": relayIdentity["certificatePEM"], "privateKeyPEM": relayIdentity["privateKeyPEM"], "serverListenerTLS": tlsFields(serverTLS), "clientListenerTLS": tlsFields(clientTLS), "server_allow": serverAllow, "pool_client_deployment": client}
		wire, e := json.Marshal(installation)
		if e != nil {
			reporter.Fatal(e)
		}
		defer clear(wire)
		if len(wire) > 4<<20 {
			reporter.Fatal("native installation exceeds its original bounded file")
		}
		file, e := os.OpenFile(owner.path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			reporter.Fatal(e)
		}
		owner.installationCreated = true
		count, e := file.Write(wire)
		if e == nil && count != len(wire) {
			e = errors.New("native installation short write")
		}
		if e == nil {
			e = file.Sync()
		}
		e = errors.Join(e, file.Close())
		if e != nil {
			reporter.Fatal(e)
		}
		parent, e := os.Open(directory)
		if e != nil {
			reporter.Fatal(e)
		}
		e = errors.Join(parent.Sync(), parent.Close())
		if e != nil {
			reporter.Fatal(e)
		}
		owner.publicationDelegated = true
		return true
	})
	if err != nil {
		return nil, err
	}
	return owner, nil
}
