package interopharness

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"time"

	fs "github.com/floegence/flowersec/flowersec-go/v6"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/assemblyv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/tlspolicy"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/controlv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/runtimehost"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

type Client struct {
	Runtime         *Runtime
	Carrier         fs.ConsumerCarrierFactory
	Material        Material
	Kind            string
	TrustPEM        string
	LiveControl     *controlv4.RegisteredControlTransport
	LiveRecipient   [16]byte
	PoolControl     *controlv4.RegisteredControlTransport
	PoolPublication *registeredPoolPublication
}

type ClientOptions struct {
	LiveDeployment                      *RegisteredLiveClientInstallation
	PoolDeployment                      *RegisteredLiveServerDeployment
	PoolClientDeployment                *RegisteredPoolClientInstallation
	ServerAllowBinding                  *PoolServerAllowBinding
	DialScope                           assemblyv4.NativeDialScope
	BridgeToken                         string
	DeferCarrier                        bool
	TLSCertificatePEM, TLSPrivateKeyPEM string
}

type carrierCleanupOwner interface {
	Close()
	WaitCleanup(context.Context) error
}

// CloseOwners starts shutdown of the Client's carrier and Runtime owners. It
// is intentionally idempotent and is used by bounded test harness cleanup so
// a later wait can continue observing the same physical objects.
func (c *Client) CloseOwners() {
	if c == nil {
		return
	}
	if owner, ok := c.Carrier.(carrierCleanupOwner); ok {
		owner.Close()
	}
	if c.Runtime != nil {
		c.Runtime.CloseOwners()
	}
}

func (c *Client) WaitOwners(ctx context.Context) error {
	if c == nil {
		return nil
	}
	var result error
	if owner, ok := c.Carrier.(carrierCleanupOwner); ok {
		result = errors.Join(result, owner.WaitCleanup(ctx))
	}
	if c.Runtime != nil {
		result = errors.Join(result, c.Runtime.WaitOwners(ctx))
	}
	return result
}

func NewClient(ctx context.Context, reporter *Reporter, artifactJSON, trustPEM, origin string, handlers HandlerConfig, options ...ClientOptions) (*Client, error) {
	return construct(reporter, func() *Client {
		var material Material
		reporter.Cleanup(func() { releaseOwnedMaterial(&material) })
		sourceDecoder := json.NewDecoder(bytes.NewBufferString(artifactJSON))
		sourceDecoder.DisallowUnknownFields()
		if err := sourceDecoder.Decode(&material); err != nil {
			reporter.Fatal(err)
		}
		if _, err := material.JSON(); err != nil {
			reporter.Fatal(err)
		}
		if material.Role > 1 || len(material.Namespaces) != 1 {
			reporter.Fatal("current peer requires one independently pinned authority")
		}
		if material.Source == "live_authority" && (len(options) != 1 || options[0].LiveDeployment == nil) {
			reporter.Fatal("live client requires its independent original control installation")
		}
		record := material.Namespaces[0]
		if len(record.RootKeyID) != 16 || len(record.RootPublicKey) != 32 || record.Generation == 0 {
			reporter.Fatal("invalid independent namespace root pin")
		}
		if len(options) > 1 {
			reporter.Fatal("one original client network configuration is required")
		}
		var dialScope assemblyv4.NativeDialScope
		if len(options) == 1 {
			dialScope = options[0].DialScope
		}
		bootstrap, err := NewHTTPSBootstrap(record, trustPEM, dialScope)
		if err != nil {
			reporter.Fatal(err)
		}
		reporter.Cleanup(bootstrap.Close)
		reporter.bootstrap = bootstrap
		reporter.rootPin = &protocolv4.NamespaceTrustRoot{Tenant: record.Tenant, Authority: record.Authority, KeyID: [16]byte(record.RootKeyID), PublicKey: [32]byte(record.RootPublicKey), MaxLifetimeMS: 30000000}
		address, kind, tlsPolicy, err := materialRoute(material.Route, material.Role)
		if err != nil {
			reporter.Fatal(err)
		}
		decoder, err := protocolv4.NewDecoder(65536, 4096)
		if err != nil {
			reporter.Fatal(err)
		}
		document, err := decoder.DecodeMap(material.Artifact, "Artifact", protocolv4.DecodeContext{})
		if err != nil {
			reporter.Fatal(err)
		}
		contract := document.Root().Named("Artifact", "session_contract").Named("SessionContract", "max_streams")
		maximum, ok := contract.Uint()
		applicationValue, applicationOK := document.Root().Named("Artifact", "session_contract").Named("SessionContract", "application_profile").Uint()
		document.Release()
		if !ok || maximum == 0 || maximum > 139 || !applicationOK {
			reporter.Fatal("signed engineering stream envelope is invalid")
		}
		application := ""
		for _, name := range []string{"transport", "services", "execution"} {
			value, err := protocolv4.EnumValue("SessionContract", "application_profile", name)
			if err != nil {
				reporter.Fatal(err)
			}
			if value == applicationValue {
				application = name
				break
			}
		}
		if application == "" || reporter.ApplicationProfile != "" && reporter.ApplicationProfile != application {
			reporter.Fatal("original engineering application profile differs from signed material")
		}
		reporter.ApplicationProfile = application
		if reporter.MaxStreams != 0 && uint64(reporter.MaxStreams) != maximum {
			reporter.Fatal("original engineering active capacity differs from signed material")
		}
		reporter.MaxStreams = uint32(maximum)
		// Installed live endpoints obtain activation only through their original
		// control service, after the pending material is adopted below.
		reporter.originalLiveDeployment = material.Source == "live_authority"
		authority := sessionv4.NewEngineeringNativeHarness(reporter, material.Source, material.Profile, kind, address, tlsPolicy, origin, kind != "websocket" && kind != "local-websocket")
		config := engineeringLeaseConfig(reporter, material)
		var liveControl *controlv4.RegisteredControlTransport
		var liveRecipient [16]byte
		var poolControl *controlv4.RegisteredControlTransport
		var poolPublication *registeredPoolPublication
		if material.Source == "preauthorized_pool" && len(options) == 1 && options[0].PoolDeployment != nil {
			if material.Role != 1 || len(material.Tunnels) != 0 {
				reporter.Fatal("registered pool B must adopt its unissued independent installation")
			}
			poolControl, err = newRegisteredPoolControl(ctx, reporter, authority, material, options[0].PoolDeployment)
			if err != nil {
				reporter.Fatal(err)
			}
			poolPublication, err = prepareRegisteredPool(ctx, reporter, authority, material, poolControl)
			if err != nil {
				reporter.Fatal(err)
			}
			config.Tunnels = poolPublication.tunnels(options[0].PoolDeployment.RelayCertificate)
		}
		if material.Source == "live_authority" {
			config = engineeringLiveLeaseConfig(reporter, authority, material)
			var control sessionv4.LiveControlConfig
			var admissionIdentity ledgerv4.SQLiteIdentity
			if material.Role == 1 {
				// B owns a fresh independent admission store before adopting any
				// request material; no issuer spend or activation is synthesized.
				stores, identities := createRegisteredLiveStores(ctx, reporter, authority, authority.BrowserOnceAuthority, "", true)
				authority.Store, admissionIdentity = stores[0], identities[0]
			}
			if material.Role == 0 {
				var recipient [16]byte
				control, recipient, err = newRegisteredLiveControl(ctx, reporter, authority, material, options[0].LiveDeployment)
				if err != nil {
					reporter.Fatal(err)
				}
				liveControl = control.Provider.(*controlv4.RegisteredControlTransport)
				liveRecipient = recipient
			}
			authority.UseEngineeringLivePeerMaterial(reporter, config, [32]byte(material.IdentitySeed), [32]byte(material.DHSeed), control, protocolv4.Direction(material.Role), admissionIdentity)
		} else {
			authority.UseEngineeringPeerMaterial(reporter, config, [32]byte(material.IdentitySeed), [32]byte(material.DHSeed), protocolv4.Direction(material.Role))
		}
		if poolPublication != nil {
			local, ok := authority.Authority.(ledgerv4.SQLitePoolAdmissionAuthority)
			if !ok {
				reporter.Fatal("registered pool B requires its local shared winner authority")
			}
			authority.Authority = &registeredPoolAdmissionAuthority{SQLitePoolAdmissionAuthority: local, publication: poolPublication}
		}
		authority.Generation = fs.MaterialGeneration{Source: [16]byte(material.Generation.Source), Generation: material.Generation.Generation}
		runtime, err := NewRuntime(ctx, reporter, authority, []uint8{material.Role}, handlers)
		if err != nil {
			reporter.Fatal(err)
		}
		client := &Client{Runtime: runtime, Material: material, Kind: kind, TrustPEM: trustPEM, LiveControl: liveControl, LiveRecipient: liveRecipient, PoolControl: poolControl, PoolPublication: poolPublication}
		if material.Role == 0 && material.Source == "preauthorized_pool" && len(material.Tunnels) != 0 {
			if len(options) > 1 {
				reporter.Fatal("at most one pool server Allow configuration is accepted")
			}
			if len(options) == 1 && (options[0].PoolClientDeployment != nil || options[0].ServerAllowBinding != nil) {
				if err = client.configurePoolServerAllow(ctx, reporter, options[0].PoolClientDeployment, options[0].ServerAllowBinding, options[0].DialScope); err != nil {
					reporter.Fatal(err)
				}
			}
		}
		if len(options) > 1 {
			reporter.Fatal("at most one local bridge configuration is accepted")
		}
		roots := x509.NewCertPool()
		if kind == "local-websocket" {
			roots = nil
		} else if !roots.AppendCertsFromPEM([]byte(trustPEM)) {
			reporter.Fatal("peer TLS root is missing")
		}
		deferCarrier := len(options) == 1 && options[0].DeferCarrier
		if deferCarrier && material.Role != 1 {
			reporter.Fatal("only an original server registration may defer native preparation")
		}
		if !deferCarrier {
			if err := client.prepareCarrier(ctx, address, roots, origin, options...); err != nil {
				reporter.Fatal(err)
			}
		}
		return client
	})
}

func (c *Client) Connect(ctx context.Context) (*fs.Session, error) {
	if c == nil || c.Material.Role != 0 {
		return nil, errors.New("only the original client endpoint may Connect")
	}
	return c.Runtime.Connect(ctx, c.Carrier)
}

func engineeringLeaseConfig(reporter *Reporter, material Material) fs.ArtifactLeaseBytesConfig {
	config := fs.ArtifactLeaseBytesConfig{Artifact: material.Artifact, Proof: material.Activation, ClientCertificate: material.ClientCertificate, ServerCertificate: material.ServerCertificate, Source: material.Source, ActivationSigningKeyID: material.ActivationSigningKeyID, MapBytes: 65536, MapNodes: 4096, RuntimeBytes: 65536}
	if len(material.Tunnels) == 0 {
		return config
	}
	entries := make([]fs.ArtifactLeaseTunnelBytes, len(material.Tunnels))
	for i, entry := range material.Tunnels {
		if int(entry.GrantNamespace) >= len(material.Namespaces) || int(entry.RelayNamespace) >= len(material.Namespaces) {
			reporter.Fatal("tunnel namespace selector is outside the independently pinned set")
		}
		entries[i] = fs.ArtifactLeaseTunnelBytes{CandidateIndex: entry.CandidateIndex, Role: protocolv4.Direction(entry.Role), Grant: entry.Grant, RelayCertificate: entry.RelayCertificate}
	}
	config.Tunnels = entries
	return config
}

func directRoute(wire []byte) (netip.AddrPort, string, []byte, error) { return materialRoute(wire, 0) }

func materialRoute(wire []byte, role uint8) (netip.AddrPort, string, []byte, error) {
	decoder, err := protocolv4.NewDecoder(16384, 1024)
	if err != nil {
		return netip.AddrPort{}, "", nil, err
	}
	document, err := decoder.DecodeShape(wire, "Route", protocolv4.DecodeContext{})
	if err != nil {
		return netip.AddrPort{}, "", nil, err
	}
	defer document.Release()
	path, _ := document.Root().Named("Route", "path_kind").Uint()
	legName := "direct_leg"
	if path == 1 {
		legName = "client_leg"
		if role == 1 {
			legName = "server_leg"
		}
	} else if path != 0 {
		return netip.AddrPort{}, "", nil, errors.New("unknown current route kind")
	}
	leg := document.Root().Named("Route", legName)
	host, _ := leg.Named("Leg", "host").Text()
	port, _ := leg.Named("Leg", "port").Uint()
	carrier, _ := leg.Named("Leg", "carrier").Uint()
	// localhost is an explicitly installed loopback address binding, never DNS.
	if host == "localhost" {
		host = "127.0.0.1"
	}
	address, err := netip.ParseAddrPort(net.JoinHostPort(host, strconv.FormatUint(port, 10)))
	if err != nil {
		return netip.AddrPort{}, "", nil, err
	}
	kind := "raw-quic"
	if carrier == 1 {
		kind = "websocket"
	} else if carrier == 2 {
		kind = "webtransport"
	} else if carrier != 0 {
		return netip.AddrPort{}, "", nil, errors.New("unknown current carrier")
	}
	access, _ := leg.Named("Leg", "access_class").Uint()
	if access == 1 {
		if carrier != 1 {
			return netip.AddrPort{}, "", nil, errors.New("local access requires WebSocket")
		}
		kind = "local-websocket"
	}
	return address, kind, append([]byte(nil), leg.Named("Leg", "tls_policy").Encoded()...), nil
}

func (c *Client) prepareCarrier(ctx context.Context, address netip.AddrPort, roots *x509.CertPool, origin string, options ...ClientOptions) error {
	if ctx == nil {
		return errors.New("original carrier preparation requires its context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	_, err := construct(c.Runtime.Reporter, func() bool {
		h := c.Runtime.Authority
		runtime := c.Runtime
		kind := c.Kind
		reporter := runtime.Reporter
		client := c
		var dialScope assemblyv4.NativeDialScope
		if len(options) == 1 {
			dialScope = options[0].DialScope
		}
		decoder, err := protocolv4.NewDecoder(16384, 1024)
		if err != nil {
			reporter.Fatal(err)
		}
		document, err := decoder.DecodeMap(h.Route, "Route", protocolv4.DecodeContext{})
		if err != nil {
			reporter.Fatal(err)
		}
		legName := "direct_leg"
		path, _ := document.Root().Named("Route", "path_kind").Uint()
		if path == 1 {
			legName = "client_leg"
			if c.Material.Role == 1 {
				legName = "server_leg"
			}
		}
		if !h.LocalLoopback {
			policy, err := tlspolicy.Capture(document.Root().Named("Route", legName).Named("Leg", "tls_policy"))
			if err != nil {
				document.Release()
				reporter.Fatal(err)
			}
			if !policy.RequiresRoots() {
				roots = nil
			}
		}
		listener, listenerOK := document.Root().Named("Route", legName).Named("Leg", "listener_role").Uint()
		document.Release()
		if !listenerOK {
			reporter.Fatal("signed physical listener role is missing")
		}
		if path == 1 && listener == uint64(client.Material.Role) {
			if len(options) != 1 || options[0].TLSCertificatePEM == "" || options[0].TLSPrivateKeyPEM == "" {
				reporter.Fatal("signed endpoint listener requires its independent native TLS certificate and key")
			}
			certificate, err := tls.X509KeyPair([]byte(options[0].TLSCertificatePEM), []byte(options[0].TLSPrivateKeyPEM))
			if err != nil {
				reporter.Fatal(err)
			}
			config := runtimehost.NativeTunnelListenerConfig{Root: h.Root, Owner: h.Owner(), Accounts: []resourcev4.Account{h.Scope[client.Material.Role].Tenant}, Environment: h.Environment, Clock: h.Clock, Route: h.Route, Deployment: client.Material.RelayDeployment, Side: protocolv4.Direction(client.Material.Role), Session: h.Admission[client.Material.Role].Core.Session, RuntimeBytes: 65536, Leg: reporter.nativeScopedLeg(kind, address, certificate, roots, dialScope)}
			cost, err := runtimehost.NativeTunnelListenerCharge(config)
			if err != nil {
				reporter.Fatal(err)
			}
			native, err := runtimehost.NewNativeTunnelListener(config, h.Reserve(cost, config.Accounts...), h.Environment)
			if err != nil {
				reporter.Fatal(err)
			}
			reporter.Owner(native.Close, native.WaitCleanup)
			reporter.Cleanup(func() {
				native.Close()
				cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				reporter.ErrorIf(native.WaitCleanup(cleanup))
			})
			client.Carrier = native
			if client.LiveControl != nil {
				if err = client.LiveControl.AnnounceOriginalRelayReady(ctx, func() error {
					if err := ctx.Err(); err != nil {
						return err
					}
					return h.Environment.Check()
				}); err != nil {
					reporter.Fatal(err)
				}
			}
			return true
		}
		switch kind {
		case "websocket", "local-websocket":
			token := ""
			if len(options) == 1 {
				token = options[0].BridgeToken
			}
			c := fs.WebSocketFactoryConfig{DialScope: dialScope, Root: h.Root, Owner: h.Owner(), Clock: h.Clock, Role: protocolv4.Direction(client.Material.Role), Deployment: client.Material.RelayDeployment, Route: h.Route, RemoteAddress: address, Roots: roots, Origin: origin, LocalBridgeToken: token, Options: reporter.webSocketProvider(), Connections: 1, RuntimeBytes: 65536}
			factory, err := fs.NewWebSocketCarrierFactory(c, runtime.reserve(fs.WebSocketCarrierFactoryCharge(c)), h.Environment)
			if err != nil {
				reporter.Fatal(err)
			}
			reporter.Owner(factory.Close, factory.WaitCleanup)
			reporter.Cleanup(func() {
				factory.Close()
				cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				reporter.ErrorIf(factory.WaitCleanup(cleanup))
			})
			client.Carrier = factory
		case "raw-quic":
			c := fs.QUICFactoryConfig{DialScope: dialScope, Root: h.Root, Owner: h.Owner(), Clock: h.Clock, Role: protocolv4.Direction(client.Material.Role), Deployment: client.Material.RelayDeployment, Route: h.Route, RemoteAddress: address, Roots: roots, Options: reporter.quicProviderFor(h.Admission[client.Material.Role].Core.Session.Contract.Limits().MaxStreams), Connections: 1, RuntimeBytes: 65536}
			factory, err := fs.NewQUICCarrierFactory(c, runtime.reserve(fs.QUICCarrierFactoryCharge(c)), h.Environment)
			if err != nil {
				reporter.Fatal(err)
			}
			reporter.Owner(factory.Close, factory.WaitCleanup)
			reporter.Cleanup(func() {
				factory.Close()
				cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				reporter.ErrorIf(factory.WaitCleanup(cleanup))
			})
			client.Carrier = factory
		case "webtransport":
			c := fs.WebTransportFactoryConfig{DialScope: dialScope, Origin: origin, Root: h.Root, Owner: h.Owner(), Clock: h.Clock, Role: protocolv4.Direction(client.Material.Role), Deployment: client.Material.RelayDeployment, Route: h.Route, RemoteAddress: address, Roots: roots, Options: reporter.webTransportProviderFor(h.Admission[client.Material.Role].Core.Session.Contract.Limits().MaxStreams), Connections: 1, RuntimeBytes: 65536}
			factory, err := fs.NewWebTransportCarrierFactory(c, runtime.reserve(fs.WebTransportCarrierFactoryCharge(c)), h.Environment)
			if err != nil {
				reporter.Fatal(err)
			}
			reporter.Owner(factory.Close, factory.WaitCleanup)
			reporter.Cleanup(func() {
				factory.Close()
				cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				reporter.ErrorIf(factory.WaitCleanup(cleanup))
			})
			client.Carrier = factory
		default:
			reporter.Fatal("unknown signed current carrier")
		}
		return true
	})
	return err
}
