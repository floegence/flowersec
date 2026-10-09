package interopharness

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	fs "github.com/floegence/flowersec/flowersec-go/v6"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/tlspolicy"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

type ServerOptions struct {
	Carrier, Profile, Source, Origin, ListenHost string
	Handlers                                     HandlerConfig
	LocalBridgeToken                             string
	// ExternalHTTP and ExternalNative keep the application listener with its host owner.
	ExternalHTTP          bool
	ExternalNative        bool
	Address               netip.AddrPort
	SourceFactory         func(*Runtime) fs.AcceptedMaterialSource
	NextAccepted          func(context.Context, *Server) (*Server, error)
	OnSession             func(*Server, *fs.Session, error)
	OnTransportError      func(string, error)
	Connections           uint16
	AcceptedRouteCapacity uint16
	Certificate           *tls.Certificate
	Roots                 *x509.CertPool
	TrustPEM              string
	TLSPolicy             []byte
	TunnelRecipe          *sessionv4.EngineeringTunnelRecipe
}

type SessionResult struct {
	Session *fs.Session
	Err     error
}

type Server struct {
	Runtime                   *Runtime
	Carrier, Origin, TrustPEM string
	Address                   netip.AddrPort
	Namespace                 NamespaceRecord
	results                   chan SessionResult
	webSocket                 *fs.WebSocketServer
	quic                      *fs.QUICServer
	webTransport              *fs.WebTransportServer
	listener                  *net.TCPListener
	certificate               tls.Certificate
	roots                     *x509.CertPool
	context                   context.Context
	HTTPHandler               http.Handler
	localBridgeToken          string
	externalHTTP              bool
	externalNative            bool
	acceptedSource            fs.AcceptedMaterialSource
	transportJoin             func(context.Context) error
	acceptReady               chan struct{}
	routeMu                   sync.Mutex
	acceptedRoutes            [][]byte
	UpgradeAuthorizations     atomic.Int32
	nextAccepted              func(context.Context, *Server) (*Server, error)
	positionOnly              bool
	connections               uint16
	acceptedRouteCapacity     uint16
	wsAccept                  func(http.ResponseWriter, *http.Request, *fs.WebSocketServer)
	quicAccept                func(*fs.QUICIngress)
	wtAccept                  func(*fs.WebTransportIngress)
	onSession                 func(*Server, *fs.Session, error)
	onTransportError          func(string, error)
	admissionGate             chan struct{}
}

func NewServer(ctx context.Context, reporter *Reporter, options ServerOptions) (result *Server, err error) {
	return construct(reporter, func() *Server {
		if options.Profile == "" {
			options.Profile = protocolv4.DHProfileX25519
		}
		if options.Source == "" {
			options.Source = "preauthorized_pool"
		}
		if options.TunnelRecipe != nil {
			if err := reporter.SetTunnelRecipe(*options.TunnelRecipe); err != nil {
				reporter.Fatal(err)
			}
		}
		if options.ListenHost == "" {
			options.ListenHost = "127.0.0.1"
		}
		if options.Origin == "" {
			options.Origin = "https://client.example"
		}
		if options.Connections == 0 {
			options.Connections = 2
		}
		s := &Server{onTransportError: options.OnTransportError, acceptedRouteCapacity: options.AcceptedRouteCapacity, onSession: options.OnSession, nextAccepted: options.NextAccepted, connections: options.Connections, localBridgeToken: options.LocalBridgeToken, externalHTTP: options.ExternalHTTP, externalNative: options.ExternalNative, Carrier: options.Carrier, Origin: options.Origin, context: ctx, results: make(chan SessionResult, 2)}
		host, parseErr := netip.ParseAddr(options.ListenHost)
		if parseErr != nil || !host.IsValid() || host.IsUnspecified() {
			reporter.Fatal("engineering listener requires a numeric host")
		}
		if options.ExternalHTTP || options.ExternalNative {
			if options.ExternalHTTP && options.Carrier != "websocket" || options.ExternalNative && options.Carrier != "raw-quic" && options.Carrier != "webtransport" {
				reporter.Fatal("external listener handoff does not match its native carrier")
			}
			if !options.Address.IsValid() || options.Address.Port() == 0 || options.Address.Addr() != host {
				reporter.Fatal("external listener owner requires its original numeric address")
			}
			s.Address = options.Address
		} else if options.Carrier == "websocket" || options.Carrier == "local-websocket" {
			s.listener, err = net.ListenTCP("tcp", &net.TCPAddr{IP: net.IP(host.AsSlice())})
			if err != nil {
				reporter.Fatal(err)
			}
			reporter.Cleanup(func() {
				if err := s.listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
					reporter.Error(err)
				}
			})
			s.Address = s.listener.Addr().(*net.TCPAddr).AddrPort()
		} else {
			probe, probeErr := net.ListenUDP("udp", &net.UDPAddr{IP: net.IP(host.AsSlice())})
			if probeErr != nil {
				reporter.Fatal(probeErr)
			}
			s.Address = probe.LocalAddr().(*net.UDPAddr).AddrPort()
			if err = probe.Close(); err != nil {
				reporter.Fatal(err)
			}
		}
		certificate, roots, trustPEM, tlsPolicy, tlsErr := TLSMaterial(options.ListenHost)
		if tlsErr != nil {
			reporter.Fatal(tlsErr)
		}
		if options.Certificate != nil {
			if options.Roots == nil || options.TrustPEM == "" || len(options.TLSPolicy) == 0 {
				reporter.Fatal("external TLS requires original roots, PEM and complete signed policy")
			}
			certificate, roots, trustPEM, tlsPolicy = *options.Certificate, options.Roots, options.TrustPEM, options.TLSPolicy
		}
		s.certificate, s.roots, s.TrustPEM = certificate, roots, trustPEM
		if options.Carrier == "local-websocket" {
			if !host.IsLoopback() || options.LocalBridgeToken == "" {
				reporter.Fatal("private bridge needs an explicit token and numeric loopback listener")
			}
			s.Origin = "http://" + s.Address.String()
			options.Origin = s.Origin
		}
		authority := sessionv4.NewEngineeringNativeHarness(reporter, options.Source, options.Profile, options.Carrier, s.Address, tlsPolicy, options.Origin, options.Carrier != "websocket" && options.Carrier != "local-websocket")
		runtime, runtimeErr := NewRuntime(ctx, reporter, authority, []uint8{1}, options.Handlers)
		if runtimeErr != nil {
			reporter.Fatal(runtimeErr)
		}
		s.Runtime = runtime
		if options.SourceFactory != nil {
			s.acceptedSource = options.SourceFactory(runtime)
		}
		s.Namespace, err = s.startBootstrap(reporter)
		if err != nil {
			reporter.Fatal(err)
		}
		if err = s.startTransport(reporter); err != nil {
			reporter.Fatal(err)
		}
		return s
	})
}

func (s *Server) WaitSession(ctx context.Context) (*fs.Session, error) {
	select {
	case result := <-s.results:
		return result.Session, result.Err
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	}
}

func (s *Server) Material() Material {

	h := s.Runtime.Authority
	return Material{WireRevision: 4, Profile: h.Admission[0].Initial.Profile, Source: h.Lease.Source, Generation: Generation{Source: h.Generation.Source[:], Generation: h.Generation.Generation},
		Role: 0, Artifact: h.Lease.Artifact, Activation: h.Lease.Proof, ClientCertificate: h.Lease.ClientCertificate, ServerCertificate: h.Lease.ServerCertificate, Route: h.Route, RouteDigest: h.BrowserRouteDigest[:],
		ActivationSigningKeyID: h.Lease.ActivationSigningKeyID, IdentitySeed: h.BrowserIdentitySeed[:], DHSeed: h.BrowserDHSeed[:], Namespaces: []NamespaceRecord{s.Namespace}, Tunnels: engineeringMaterialTunnels(h)}
}

// ServerMaterial exports the original role-1 engineering installation alongside
// the same signed lease bytes used by the client material. Both private seeds
// must be the ones that produced the role-1 identity certificate.
func (s *Server) ServerMaterial() (Material, error) {
	h := s.Runtime.Authority
	identitySeed, dhSeed := h.EngineeringServerIdentitySeed, h.EngineeringServerDHSeed
	identity := ed25519.NewKeyFromSeed(identitySeed[:])
	defer clear(identity)
	decoder, err := protocolv4.NewDecoder(65536, 4096)
	if err != nil {
		return Material{}, err
	}
	certificate, err := decoder.DecodeMap(h.Lease.ServerCertificate, "IdentityCertificate", protocolv4.DecodeContext{})
	if err != nil {
		return Material{}, err
	}
	defer certificate.Release()
	identityPublic, ok := certificate.Root().Named("IdentityCertificate", "ed25519_public_key").ByteString()
	if !ok || !bytes.Equal(identity.Public().(ed25519.PublicKey), identityPublic) {
		return Material{}, errors.New("original server identity seed differs from its signed certificate")
	}
	var curve ecdh.Curve
	switch h.Admission[0].Initial.Profile {
	case protocolv4.DHProfileX25519:
		curve = ecdh.X25519()
	case protocolv4.DHProfileP256:
		curve = ecdh.P256()
	default:
		return Material{}, protocolv4.ErrRecordProfile
	}
	dhKey, err := curve.NewPrivateKey(dhSeed[:])
	if err != nil {
		return Material{}, err
	}
	dhPublic, ok := certificate.Root().Named("IdentityCertificate", "noise_static_public_key").Named("NoiseStaticPublicKey", "public_key_bytes").ByteString()
	if !ok || !bytes.Equal(dhKey.PublicKey().Bytes(), dhPublic) {
		return Material{}, errors.New("original server DH seed differs from its signed certificate")
	}
	material := s.Material()
	material.Role = 1
	material.IdentitySeed = append([]byte(nil), identitySeed[:]...)
	material.DHSeed = append([]byte(nil), dhSeed[:]...)
	return material, nil
}

func engineeringMaterialTunnels(h *sessionv4.PublicQUICTestHarness) []TunnelMaterial {
	if h == nil || h.Tunnel == nil {
		return []TunnelMaterial{}
	}
	result := make([]TunnelMaterial, 2)
	for role := range 2 {
		result[role] = TunnelMaterial{CandidateIndex: 0, Role: uint8(role), Grant: append([]byte(nil), h.Tunnel.Grants[role]...), RelayCertificate: append([]byte(nil), h.Tunnel.RelayCertificate...), GrantNamespace: 0, RelayNamespace: 0}
	}
	return result
}

type acceptedMaterial struct {
	material *fs.ConnectionMaterial
	hello    fs.InitialHello
}

func (s acceptedMaterial) ResolveAcceptedMaterial(context.Context, []byte) (*fs.ConnectionMaterial, fs.InitialHello, error) {
	return s.material, s.hello, nil
}

func (s *Server) startTransport(reporter *Reporter) error {
	r, h := s.Runtime, s.Runtime.Authority
	config := fs.ServeConfig{Positions: 2, RuntimeBytes: 16384, DrainTimeoutMS: 1000, Clock: h.Clock}
	serve, err := fs.NewAcceptor(s.context, fs.AcceptorOptions{Environment: r.Environment, ServeOptions: fs.ServeOptions{Config: config, Reservation: r.reserve(fs.ServeCharge(config))}})
	if err != nil {
		return err
	}
	reporter.Cleanup(func() {
		serve.Close()
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		reporter.ErrorIf(serve.WaitCleanup(cleanup))
	})
	entrance := fs.AcceptedEntranceConfig{Initial: h.Admission[1].Initial, RuntimeBytes: 8192, InitialRuntimeBytes: 8192, CarrierRuntimeBytes: 8192}
	input := fs.AcceptedSessionInput{Config: h.Admission[1], Root: h.Root, ResourceOwner: h.Owner(), Environment: h.Environment, Preauth: h.Preauth, Scope: h.Scope[1], Store: h.Store, Authority: h.Authority}
	accounts := []fs.ResourceAccount{h.Scope[1].Tenant}
	source := fs.AcceptedMaterialSource(acceptedMaterial{r.Materials[1], h.Hello})
	if s.acceptedSource != nil {
		source = s.acceptedSource
	}
	recordBytes := uint32(4096)
	if h.Lease.Source == "live_authority" {
		recordBytes = 16384
	}
	deliver := func(session *fs.Session, err error) {
		if err != nil && s.onTransportError != nil {
			s.onTransportError("admission", err)
		}
		if err == nil {
			err = r.retainSession(1, session)
		}
		if s.onSession != nil {
			s.onSession(s, session, err)
			return
		}
		select {
		case s.results <- SessionResult{session, err}:
		case <-s.context.Done():
			if session != nil {
				_ = session.Close()
			}
		}
	}
	switch s.Carrier {
	case "websocket", "local-websocket":
		provider := reporter.webSocketProvider()
		options := fs.WebSocketAcceptOptions{Input: input, Source: source, Limits: h.Limits, Entrance: entrance, Dependencies: h.Environment, Accounts: accounts, LocalCapabilities: h.Hello.Offered,
			RuntimeBytes: 8192, IngressRuntimeBytes: 8192, IntakeRuntimeBytes: 8192, MaxAdmissionRecordBytes: recordBytes, Provider: provider}
		s.wsAccept = func(w http.ResponseWriter, request *http.Request, server *fs.WebSocketServer) {
			if _, scheduled := s.acceptedSource.(*AcceptedRegistrySource); !scheduled {
				if err := s.acquireAdmission(request.Context()); err != nil {
					deliver(nil, err)
					return
				}
				defer s.releaseAdmission()
			}
			current := options
			current.Server = server
			session, upgraded, err := serve.AcceptWebSocket(s.context, w, request, current)
			if upgraded {
				deliver(session, err)
			} else if err != nil {
				deliver(nil, err)
			}
		}
		if s.positionOnly {
			return nil
		}
		if s.Carrier == "local-websocket" || s.externalHTTP {
			upgrade, err := s.originalHTTPPolicy()
			if err != nil {
				return err
			}
			options.Upgrade = upgrade
			s.HTTPHandler = http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				if _, scheduled := s.acceptedSource.(*AcceptedRegistrySource); !scheduled {
					if err := s.acquireAdmission(request.Context()); err != nil {
						deliver(nil, err)
						return
					}
					defer s.releaseAdmission()
				}
				session, upgraded, err := serve.AcceptWebSocket(s.context, w, request, options)
				if upgraded {
					deliver(session, err)
				} else if err != nil {
					if s.onTransportError != nil {
						s.onTransportError("upgrade", err)
					}
					http.Error(w, "transport policy rejected request", http.StatusForbidden)
				}
			})
			if s.externalHTTP {
				return nil
			}
			return s.ServeHTTPListener(reporter, s.listener, nil, false)
		}
		handler := http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
			position := s
			if s.nextAccepted != nil {
				var err error
				position, err = s.nextAccepted(request.Context(), s)
				if err != nil {
					http.Error(w, "current acceptance position unavailable", http.StatusServiceUnavailable)
					return
				}
			}
			position.wsAccept(w, request, s.webSocket)
			position.retireUnused()
		})
		serverConfig := fs.WebSocketServerConfig{AcceptedRouteCapacity: s.acceptedRouteCapacity, Root: h.Root, Clock: h.Clock, Route: h.Route, Certificate: s.certificate, Roots: s.roots, Handler: handler, Connections: s.connections, HeaderBytes: 8192, HeaderTimeout: reporter.operationDuration(5 * time.Second), IdleTimeout: reporter.operationDuration(30 * time.Second), RuntimeBytes: 65536, ProviderBytesPerConnection: 1 << 20}
		s.webSocket, err = fs.NewWebSocketServer(serverConfig, r.reserve(fs.WebSocketServerCharge(serverConfig)), h.Environment)
		if err != nil {
			return err
		}
		reporter.Cleanup(func() {
			s.webSocket.Close()
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cleanupErr := s.webSocket.WaitCleanup(cleanup)
			reporter.ErrorIf(cleanupErr)
			if s.transportJoin != nil {
				// Close can retire this original listener before its sole Serve
				// goroutine enters. Dismiss only that exact closed result after
				// the provider has physically cleaned up; joined failures remain.
				joinErr := s.transportJoin(cleanup)
				if joinErr != resourcev4.ErrClosed || cleanupErr != nil {
					reporter.ErrorIf(joinErr)
				}
			}
		})
		if err = s.installCachedAcceptedRoutes(); err != nil {
			return err
		}
		done := make(chan struct{})
		var serveErr error
		go func() { defer close(done); serveErr = s.webSocket.Serve(s.listener) }()
		s.transportJoin = func(ctx context.Context) error {
			select {
			case <-done:
				if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) && !errors.Is(serveErr, net.ErrClosed) {
					return serveErr
				}
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	case "raw-quic":
		provider := reporter.quicProviderFor(h.Admission[1].Core.Session.Contract.Limits().MaxStreams)
		options := fs.QUICAcceptOptions{Input: input, Source: source, Limits: h.Limits, Entrance: entrance, Dependencies: h.Environment, Accounts: accounts, LocalCapabilities: h.Hello.Offered, IngressRuntimeBytes: 8192, IntakeRuntimeBytes: 8192, MaxAdmissionRecordBytes: recordBytes}
		s.quicAccept = func(ingress *fs.QUICIngress) {
			defer ingress.Close()
			if _, scheduled := s.acceptedSource.(*AcceptedRegistrySource); !scheduled {
				if err := s.acquireAdmission(s.context); err != nil {
					deliver(nil, err)
					return
				}
				defer s.releaseAdmission()
			}
			session, err := serve.AcceptQUIC(s.context, ingress, options)
			deliver(session, err)
		}
		if s.positionOnly || s.externalNative {
			return nil
		}
		c := fs.QUICServerConfig{AcceptedRouteCapacity: s.acceptedRouteCapacity, Root: h.Root, Owner: h.Owner(), Clock: h.Clock, Accounts: accounts, Address: s.Address, Route: h.Route, Certificate: s.certificate, Roots: s.roots, Connection: provider, Connections: s.connections, RuntimeBytes: 65536, ListenerRuntimeBytes: 65536, ListenerProviderBytes: 1 << 20, ListenerProviderTasks: 4}
		charge, err := fs.QUICServerCharge(c)
		if err != nil {
			return err
		}
		reservation, err := h.Root.Reserve(c.Owner, charge, c.Accounts...)
		if err != nil {
			return err
		}
		defer reservation.Release()
		s.quic, err = fs.NewQUICServer(c, reservation, h.Environment)
		if err != nil {
			return err
		}
		reporter.Cleanup(func() {
			_ = s.quic.Close()
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			reporter.ErrorIf(s.quic.WaitCleanup(cleanup))
		})
		if err = s.installCachedAcceptedRoutes(); err != nil {
			return err
		}
		s.startNativeAcceptLoop(reporter, func(ctx context.Context, position *Server, callbacks *httpCallbackGate) error {
			entrance := fs.AcceptedEntranceConfig{Initial: position.Runtime.Authority.Admission[1].Initial, RuntimeBytes: 8192, InitialRuntimeBytes: 8192, CarrierRuntimeBytes: 8192}
			ingress, err := s.quic.Accept(ctx, entrance)
			if err != nil {
				return err
			}
			if !callbacks.enter() {
				ingress.Close()
				return context.Canceled
			}
			go func() { defer callbacks.leave(); position.quicAccept(ingress); position.retireUnused() }()
			return nil
		}, func() { _ = s.quic.Close() })
	case "webtransport":
		provider := reporter.webTransportProviderFor(h.Admission[1].Core.Session.Contract.Limits().MaxStreams)
		options := fs.WebTransportAcceptOptions{Input: input, Source: source, Limits: h.Limits, Entrance: entrance, Dependencies: h.Environment, Accounts: accounts, LocalCapabilities: h.Hello.Offered, IngressRuntimeBytes: 8192, IntakeRuntimeBytes: 8192, MaxAdmissionRecordBytes: recordBytes}
		s.wtAccept = func(ingress *fs.WebTransportIngress) {
			defer ingress.Close()
			if _, scheduled := s.acceptedSource.(*AcceptedRegistrySource); !scheduled {
				if err := s.acquireAdmission(s.context); err != nil {
					deliver(nil, err)
					return
				}
				defer s.releaseAdmission()
			}
			session, err := serve.AcceptWebTransport(s.context, ingress, options)
			deliver(session, err)
		}
		if s.positionOnly || s.externalNative {
			return nil
		}
		c := fs.WebTransportServerConfig{AcceptedRouteCapacity: s.acceptedRouteCapacity, Root: h.Root, Owner: h.Owner(), Clock: h.Clock, Accounts: accounts, Address: s.Address, Route: h.Route, Certificate: s.certificate, Roots: s.roots, Connection: provider, Connections: s.connections, RuntimeBytes: 65536, ListenerRuntimeBytes: 65536, ListenerProviderBytes: 1 << 20, ListenerProviderTasks: 4}
		charge, err := fs.WebTransportServerCharge(c)
		if err != nil {
			return err
		}
		reservation, err := h.Root.Reserve(c.Owner, charge, c.Accounts...)
		if err != nil {
			return err
		}
		defer reservation.Release()
		s.webTransport, err = fs.NewWebTransportServer(c, reservation, h.Environment)
		if err != nil {
			return err
		}
		reporter.Cleanup(func() {
			_ = s.webTransport.Close()
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			reporter.ErrorIf(s.webTransport.WaitCleanup(cleanup))
		})
		if err = s.installCachedAcceptedRoutes(); err != nil {
			return err
		}
		s.startNativeAcceptLoop(reporter, func(ctx context.Context, position *Server, callbacks *httpCallbackGate) error {
			entrance := fs.AcceptedEntranceConfig{Initial: position.Runtime.Authority.Admission[1].Initial, RuntimeBytes: 8192, InitialRuntimeBytes: 8192, CarrierRuntimeBytes: 8192}
			ingress, err := s.webTransport.Accept(ctx, entrance)
			if err != nil {
				return err
			}
			if !callbacks.enter() {
				ingress.Close()
				return context.Canceled
			}
			go func() { defer callbacks.leave(); position.wtAccept(ingress); position.retireUnused() }()
			return nil
		}, func() { _ = s.webTransport.Close() })
	default:
		return errors.New("unknown engineering carrier")
	}
	return nil
}

// Each original accepted position keeps its own finite resource and connection
// owners while waiting for the shared durable admission connection. This is
// scheduling before admission, never a retry of consumed authority or work.
func (s *Server) acquireAdmission(ctx context.Context) error {
	if s.admissionGate == nil {
		return nil
	}
	deadline := s.Runtime.Authority.Admission[1].Initial.Deadline
	remaining, err := deadline.RemainingMS()
	if err != nil {
		return err
	}
	// Recheck this same original deadline after every wakeup. Waiting never
	// constructs another age window or retries a durable admission operation.
	timer := time.NewTimer(time.Duration(min(remaining, uint64((1<<63-1)/int64(time.Millisecond)))) * time.Millisecond)
	defer timer.Stop()
	for {
		select {
		case s.admissionGate <- struct{}{}:
			if err := ctx.Err(); err != nil {
				s.releaseAdmission()
				return context.Cause(ctx)
			}
			if err := s.context.Err(); err != nil {
				s.releaseAdmission()
				return context.Cause(s.context)
			}
			if err := deadline.Check(); err != nil {
				s.releaseAdmission()
				return err
			}
			return nil
		case <-ctx.Done():
			return context.Cause(ctx)
		case <-s.context.Done():
			return context.Cause(s.context)
		case <-timer.C:
			remaining, err = deadline.RemainingMS()
			if err != nil {
				return err
			}
			timer.Reset(time.Duration(min(remaining, uint64((1<<63-1)/int64(time.Millisecond)))) * time.Millisecond)
		}
	}
}

func (s *Server) releaseAdmission() {
	if s.admissionGate != nil {
		<-s.admissionGate
	}
}

func (s *Server) startBootstrap(reporter *Reporter) (NamespaceRecord, error) {
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IP(s.Address.Addr().AsSlice())})
	if err != nil {
		return NamespaceRecord{}, err
	}
	h := s.Runtime.Authority
	declaration := resourcev4.Vector{resourcev4.ProviderBytes: 64 << 20, resourcev4.Tasks: 16, resourcev4.WorkSlots: 8, resourcev4.NativeHandles: 5, resourcev4.Connections: 4, resourcev4.Items: 8, resourcev4.Timers: 4}
	reservation := h.Reserve(declaration)
	reporter.Cleanup(reservation.Release)
	bounded := newLimitedListener(tls.NewListener(listener, &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, Certificates: []tls.Certificate{s.certificate}}), 4)
	rootKeyID, rootPublic := h.BrowserRootKeyID, h.BrowserRootPublicKey
	host := reporter.RouteHost
	if host == "" {
		host = s.Address.Addr().String()
	}
	base := "https://" + net.JoinHostPort(host, portOf(listener.Addr().String()))
	record := NamespaceRecord{Tenant: h.BrowserTenant, Authority: h.BrowserAuthority, Generation: 1, RootKeyID: rootKeyID[:], RootPublicKey: rootPublic[:], BootstrapURL: base + "/flowersec/v4/trust/bootstrap", StateURL: base + "/flowersec/v4/trust/state"}
	authorityGate := make(chan struct{}, 1)
	initial, err := construct(reporter, func() BootstrapResponse {
		wire, state := h.BrowserBootstrap([32]byte{1})
		return BootstrapResponse{wire, state}
	})
	if err != nil {
		_ = listener.Close()
		return NamespaceRecord{}, err
	}
	var queries uint32
	handler := http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodGet && request.URL.Path == "/flowersec/v4/trust/state" {
			w.Header().Set("Content-Type", "application/cbor")
			_, _ = w.Write(initial.State)
			return
		}
		if request.Method != http.MethodPost || request.URL.Path != "/flowersec/v4/trust/bootstrap" {
			http.NotFound(w, request)
			return
		}
		select {
		case authorityGate <- struct{}{}:
			defer func() { <-authorityGate }()
		case <-request.Context().Done():
			return
		}
		if queries >= 4096 {
			http.Error(w, "bootstrap query budget exhausted", http.StatusServiceUnavailable)
			return
		}
		queries++
		data, err := io.ReadAll(io.LimitReader(request.Body, 2049))
		if err != nil || len(data) > 2048 {
			http.Error(w, "invalid bootstrap query", http.StatusBadRequest)
			return
		}
		var query BootstrapRequest
		if err = json.Unmarshal(data, &query); err != nil || query.Tenant != record.Tenant || query.Authority != record.Authority || len(query.Nonce) != 32 {
			http.Error(w, "invalid independent namespace query", http.StatusBadRequest)
			return
		}
		reply, err := construct(reporter, func() BootstrapResponse {
			wire, state := h.BrowserBootstrap([32]byte(query.Nonce))
			return BootstrapResponse{wire, state}
		})
		if err != nil {
			http.Error(w, "authority unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(reply)
	})
	callbacks := newHTTPCallbackGate()
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !callbacks.enter() {
			http.Error(w, "authority is closing", http.StatusServiceUnavailable)
			return
		}
		defer callbacks.leave()
		handler.ServeHTTP(w, r)
	}), ReadHeaderTimeout: reporter.operationDuration(5 * time.Second), ReadTimeout: reporter.operationDuration(5 * time.Second), WriteTimeout: reporter.operationDuration(5 * time.Second), IdleTimeout: reporter.operationDuration(5 * time.Second), MaxHeaderBytes: 4096}
	done := make(chan struct{})
	var serveErr error
	go func() {
		serveErr = server.Serve(bounded)
		close(done)
	}()
	closeBootstrap := func() {
		callbacks.seal()
		_ = server.Close()
		_ = bounded.Close()
		bounded.CloseConnections()
	}
	waitBootstrap := func(ctx context.Context) error {
		var result error
		select {
		case <-done:
			if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) && !errors.Is(serveErr, net.ErrClosed) {
				result = serveErr
			}
		case <-ctx.Done():
			return ctx.Err()
		}
		select {
		case <-callbacks.drained:
			return result
		case <-ctx.Done():
			return errors.Join(result, ctx.Err())
		}
	}
	// Keep the listener, Serve loop, and admitted request callbacks as one
	// retryable physical owner. A bounded WaitOwners failure must leave the
	// reservation alive so a later close can observe the same owner drain.
	reporter.Owner(closeBootstrap, waitBootstrap)
	// Reporter.Close is also used directly by callers that do not have a
	// separate owner waiter. Finish this owner before the reservation cleanup
	// runs, without introducing a second timeout that could refund early.
	reporter.Cleanup(func() {
		closeBootstrap()
		if err := waitBootstrap(context.Background()); err != nil {
			reporter.Error(err)
		}
	})
	return record, nil
}

func portOf(address string) string { _, port, _ := net.SplitHostPort(address); return port }

type limitedListener struct {
	net.Listener
	slots       chan struct{}
	mu          sync.Mutex
	closed      bool
	done        chan struct{}
	connections map[*limitedConnection]struct{}
}

func newLimitedListener(listener net.Listener, capacity int) *limitedListener {
	return &limitedListener{Listener: listener, slots: make(chan struct{}, capacity), done: make(chan struct{}), connections: make(map[*limitedConnection]struct{})}
}
func (l *limitedListener) Accept() (net.Conn, error) {
	select {
	case l.slots <- struct{}{}:
	case <-l.done:
		return nil, net.ErrClosed
	}
	connection, err := l.Listener.Accept()
	if err != nil {
		<-l.slots
		return nil, err
	}
	retained := &limitedConnection{Conn: connection}
	retained.release = func() { l.mu.Lock(); delete(l.connections, retained); l.mu.Unlock(); <-l.slots }
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		_ = retained.Close()
		return nil, net.ErrClosed
	}
	l.connections[retained] = struct{}{}
	l.mu.Unlock()
	return retained, nil
}
func (l *limitedListener) Close() error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	close(l.done)
	l.mu.Unlock()
	return l.Listener.Close()
}
func (l *limitedListener) CloseConnections() {
	l.mu.Lock()
	connections := make([]*limitedConnection, 0, len(l.connections))
	for connection := range l.connections {
		connections = append(connections, connection)
	}
	l.mu.Unlock()
	for _, connection := range connections {
		_ = connection.Close()
	}
}

type limitedConnection struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitedConnection) Close() error { err := c.Conn.Close(); c.once.Do(c.release); return err }

// originalHTTPPolicy checks deployment facts before Upgrade and independently
// compares the admitted complete signed route before durable admission.
func (s *Server) originalHTTPPolicy() (fs.WebSocketUpgradeConfig, error) {
	h := s.Runtime.Authority
	decoder, err := protocolv4.NewDecoder(16384, 1024)
	if err != nil {
		return fs.WebSocketUpgradeConfig{}, err
	}
	document, err := decoder.DecodeShape(h.Route, "Route", protocolv4.DecodeContext{})
	if err != nil {
		return fs.WebSocketUpgradeConfig{}, err
	}
	defer document.Release()
	leg := document.Root().Named("Route", "direct_leg")
	subprotocol, _ := leg.Named("Leg", "subprotocol").Text()
	path, _ := leg.Named("Leg", "path").Text()
	var policy tlspolicy.Policy
	if !h.LocalLoopback {
		policy, err = tlspolicy.Capture(leg.Named("Leg", "tls_policy"))
		if err != nil {
			return fs.WebSocketUpgradeConfig{}, err
		}
	}
	return fs.WebSocketUpgradeConfig{Subprotocol: subprotocol, CheckPolicy: func(request *http.Request) error {
		if request.Method != http.MethodGet || request.ProtoMajor != 1 || request.ProtoMinor != 1 || request.Host != s.Address.String() || request.URL.Path != path || request.URL.RawQuery != "" || request.Header.Get("Origin") != s.Origin || len(request.Header.Values("Origin")) != 1 {
			return errors.New("request differs from the original signed HTTP deployment")
		}
		if h.LocalLoopback {
			remote, err := netip.ParseAddrPort(request.RemoteAddr)
			local, _ := request.Context().Value(http.LocalAddrContextKey).(net.Addr)
			if err != nil || !remote.Addr().IsLoopback() || local == nil || local.String() != s.Address.String() || request.TLS != nil || len(request.Header.Values("X-Flowersec-Private-Bridge-Token")) != 1 || subtle.ConstantTimeCompare([]byte(request.Header.Get("X-Flowersec-Private-Bridge-Token")), []byte(s.localBridgeToken)) != 1 {
				return errors.New("local bridge origin, address or token rejected before upgrade")
			}
		} else {
			if request.TLS == nil || request.TLS.Version != tls.VersionTLS13 || request.TLS.DidResume {
				return errors.New("network transport requires the original TLS 1.3 connection")
			}
			now, err := h.Clock.Sample()
			if err != nil {
				return err
			}
			prepared, err := policy.Prepare(now.Interval)
			if err != nil {
				return err
			}
			chain := make([]*x509.Certificate, len(s.certificate.Certificate))
			for i, wire := range s.certificate.Certificate {
				chain[i], err = x509.ParseCertificate(wire)
				if err != nil {
					return err
				}
			}
			_, err = prepared.Verify(tls.ConnectionState{Version: tls.VersionTLS13, PeerCertificates: chain}, s.Address.Addr().String(), s.roots, now.Interval)
			if err != nil {
				return err
			}
		}
		s.UpgradeAuthorizations.Add(1)
		return nil
	}, CheckAcceptedRoute: func(_ protocolv4.AcceptedWebSocketEndpoint, artifact *protocolv4.SignedMap, index uint64, _ protocolv4.HelloPolicy) error {
		var scratch [16384]byte
		route, digest, err := artifact.CopyCandidateRoute(index, scratch[:])
		if err != nil {
			return err
		}
		if digest != h.BrowserRouteDigest || !bytes.Equal(route, h.Route) {
			return errors.New("accepted complete route differs from original deployment")
		}
		return nil
	}}, nil
}

func WebSocketProvider() fs.WebSocketProviderOptions {
	return fs.WebSocketProviderOptions{MaxMessageBytes: 65544, ReadBufferBytes: 1024, WriteBufferBytes: 1024, HandshakeBytes: 8192, MaxControlsPerSecond: 16, HandshakeTimeout: 5 * time.Second, MessageTimeout: 30 * time.Second, RuntimeBytes: 32768, ProviderRuntimeBytes: 1 << 20, ProviderTasks: 4}
}
func QUICProvider() fs.QUICProviderOptions {
	limits := fs.DefaultQUICLimits()
	limits.MaxInboundStreams = 32
	return fs.QUICProviderOptions{Limits: limits, StreamSlots: 32, RuntimeBytes: 65536, ProviderBytes: 32 << 20, ProviderTasks: 16}
}
func WebTransportProvider() fs.WebTransportProviderOptions {
	limits := fs.DefaultWebTransportLimits()
	limits.MaxInboundStreams = 32
	return fs.WebTransportProviderOptions{Limits: limits, StreamSlots: 32, RuntimeBytes: 65536, ProviderBytes: 32 << 20, ProviderTasks: 16}
}

func QUICProviderFor(streams uint32) fs.QUICProviderOptions {
	options := QUICProvider()
	// Active streams and pending OPEN positions coexist with maintenance.
	capacity := max(uint64(32), uint64(streams)+uint64(min(streams, 128))+1)
	options.Limits.MaxInboundStreams = int64(capacity)
	// Preserve an invalid oversized declaration for provider validation instead
	// of allowing conversion overflow to produce a smaller usable envelope.
	options.StreamSlots = uint16(min(capacity, 65535))
	options.ProviderBytes = capacity * (1 << 20)
	return options
}
func WebTransportProviderFor(streams uint32) fs.WebTransportProviderOptions {
	options := WebTransportProvider()
	// Active streams and pending OPEN positions coexist with maintenance.
	capacity := max(uint64(32), uint64(streams)+uint64(min(streams, 128))+1)
	options.Limits.MaxInboundStreams = int64(capacity)
	// Preserve an invalid oversized declaration for provider validation instead
	// of allowing conversion overflow to produce a smaller usable envelope.
	options.StreamSlots = uint16(min(capacity, 65535))
	options.ProviderBytes = capacity * (1 << 20)
	return options
}
func (s *Server) CertificateDER() []byte { return append([]byte(nil), s.certificate.Certificate[0]...) }

// TLSPrivateKeyPKCS8 returns the exact private key paired with CertificateDER
// for an explicitly local engineering handoff to a prebound native listener.
func (s *Server) TLSPrivateKeyPKCS8() ([]byte, error) {
	if s == nil || s.certificate.PrivateKey == nil {
		return nil, errors.New("original TLS private key is unavailable")
	}
	return x509.MarshalPKCS8PrivateKey(s.certificate.PrivateKey)
}
func (s *Server) installAcceptedRoute(route []byte) error {
	switch s.Carrier {
	case "websocket":
		return s.webSocket.InstallAcceptedRoute(route)
	case "raw-quic":
		return s.quic.InstallAcceptedRoute(route)
	case "webtransport":
		return s.webTransport.InstallAcceptedRoute(route)
	default:
		return errors.New("this listener has no network route policy positions")
	}
}
func (s *Server) installCachedAcceptedRoutes() error {
	s.routeMu.Lock()
	defer s.routeMu.Unlock()
	for _, route := range s.acceptedRoutes {
		if err := s.installAcceptedRoute(route); err != nil {
			return err
		}
	}
	return nil
}
func (s *Server) InstallAcceptedRoute(route []byte) error {
	s.routeMu.Lock()
	defer s.routeMu.Unlock()
	if err := s.installAcceptedRoute(route); err != nil {
		return err
	}
	for _, installed := range s.acceptedRoutes {
		if bytes.Equal(installed, route) {
			return nil
		}
	}
	s.acceptedRoutes = append(s.acceptedRoutes, bytes.Clone(route))
	return nil
}

func (s *Server) InterruptConnections() error {
	switch s.Carrier {
	case "websocket":
		return s.webSocket.InterruptConnections()
	case "raw-quic":
		return s.quic.InterruptConnections()
	case "webtransport":
		return s.webTransport.InterruptConnections()
	}
	return errors.New("network listener is required")
}
