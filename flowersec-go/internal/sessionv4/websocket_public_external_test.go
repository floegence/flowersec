package sessionv4_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	fs "github.com/floegence/flowersec/flowersec-go/v6"
	"github.com/floegence/flowersec/flowersec-go/v6/controlplane"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

func TestPublicWebSocketEnvironmentServeNoiseReadyAndStreams(t *testing.T) {
	for _, source := range []string{"preauthorized_pool", "live_authority"} {
		for _, profile := range []string{protocolv4.DHProfileX25519, protocolv4.DHProfileP256} {
			for _, pin := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/pin=%t", source, profile, pin), func(t *testing.T) {
					publicWebSocketEnvironmentRoundTrip(t, source, profile, pin, webSocketRoundTripOptions{})
				})
			}
		}
	}
}

func TestPublicWebSocketDirectExporter(t *testing.T) {
	for _, source := range []string{"preauthorized_pool", "live_authority"} {
		for _, profile := range []string{protocolv4.DHProfileX25519, protocolv4.DHProfileP256} {
			t.Run(source+"/"+profile, func(t *testing.T) {
				publicWebSocketEnvironmentRoundTrip(t, source, profile, true, webSocketRoundTripOptions{directExporter: true})
			})
		}
	}
}

func TestPublicWebSocketApplicationRefusalBeforeAdmission(t *testing.T) {
	publicWebSocketEnvironmentRoundTrip(t, "preauthorized_pool", protocolv4.DHProfileX25519, true, webSocketRoundTripOptions{rejectApplication: true})
}

// Playwright supplies only its origin/profile and bootstrap nonce. The Go
// authority signs the complete material; the browser reaches the production
// Serve/AcceptWebSocket, durable admission and application handler boundaries.
// Self-signed browser TLS trust and fixture clocks do not qualify public CA
// deployment trust, real-time freshness or rollback resistance.
func TestPublicWebSocketBrowserInterop(t *testing.T) {
	if os.Getenv("FLOWERSEC_BROWSER_PUBLIC_WSS") != "1" {
		t.Skip("requires the Chromium public WSS runner")
	}
	var setup publicBrowserSetup
	if err := json.NewDecoder(os.Stdin).Decode(&setup); err != nil {
		t.Fatal(err)
	}
	if setup.Profile != protocolv4.DHProfileX25519 && setup.Profile != protocolv4.DHProfileP256 {
		t.Fatal("unsupported browser profile")
	}
	if setup.Source == "" {
		setup.Source = "preauthorized_pool"
	}
	if setup.Source != "preauthorized_pool" && setup.Source != "live_authority" {
		t.Fatal("unsupported browser source")
	}
	if setup.ControlFailure != "" && (setup.Source != "live_authority" || setup.ControlFailure != "credential" && setup.ControlFailure != "signature") {
		t.Fatal("unsupported browser control failure")
	}
	publicWebSocketEnvironmentRoundTrip(t, setup.Source, setup.Profile, false, webSocketRoundTripOptions{browser: &setup})
}

type publicBrowserSetup struct{ Origin, Profile, Source, ControlFailure string }

type webSocketRoundTripOptions struct {
	directExporter, rejectApplication bool
	browser                           *publicBrowserSetup
	streamRegistration                *fs.RawStreamHandlerConfig
	streamWorkflow                    func(context.Context, [2]*fs.Session)
}

type publicBrowserMaterialSource struct {
	material *fs.ConnectionMaterial
	hello    func() fs.InitialHello
	lookups  *atomic.Int32
}

func (s publicBrowserMaterialSource) ResolveAcceptedMaterial(context.Context, []byte) (*fs.ConnectionMaterial, fs.InitialHello, error) {
	s.lookups.Add(1)
	return s.material, s.hello(), nil
}

// This controlled test terminator authenticates a fixed bearer and origin. Its
// authority uses the same actual SQLite TxA/policy/TxB chain as native clients.
// It is not public-CA or deployment qualification evidence.
func publicBrowserLiveControl(t *testing.T, h *sessionv4.PublicQUICTestHarness, certificate tls.Certificate, origin string, invalidProof bool) (string, func() int32) {
	t.Helper()
	codecBytes, err := controlplane.LiveAuthorizationCodecBackingBytes()
	if err != nil {
		t.Fatal(err)
	}
	h.Reserve(fs.ResourceVector{fs.SDKBytes: codecBytes + 5120})
	codec, err := controlplane.NewLiveAuthorizationCodec()
	if err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || r.TLS.Version != tls.VersionTLS13 || r.TLS.DidResume || r.URL.Path != "/live/authorize" || r.Header.Get("Origin") != origin {
			http.Error(w, "control binding refused", http.StatusForbidden)
			return
		}
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Methods", "POST")
		w.Header().Set("Access-Control-Allow-Headers", "authorization, content-type, cache-control")
		w.Header().Set("Access-Control-Expose-Headers", "content-type, content-length, content-encoding, transfer-encoding, trailer")
		w.Header().Set("Cache-Control", "no-store")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		requests.Add(1)
		if r.Method != http.MethodPost || r.Header.Get("Authorization") != "Bearer flowersec-browser-live-test" || r.Header.Get("Cookie") != "" ||
			r.Header.Get("Content-Type") != "application/cbor" || r.ContentLength < 1 || r.ContentLength > 1024 {
			http.Error(w, "control authentication refused", http.StatusForbidden)
			return
		}
		defer r.Body.Close()
		body, err := io.ReadAll(io.LimitReader(r.Body, 1025))
		if err != nil || len(body) > 1024 {
			http.Error(w, "control request refused", http.StatusBadRequest)
			return
		}
		query, err := codec.Decode(body)
		if err != nil {
			http.Error(w, "control request refused", http.StatusBadRequest)
			return
		}
		var output [4096]byte
		defer clear(output[:])
		n, err := h.BrowserAuthorize(r.Context(), query, sha256.Sum256(body), output[:])
		if err != nil {
			t.Errorf("browser live authority: %v", err)
			http.Error(w, "control authorization refused", http.StatusConflict)
			return
		}
		if invalidProof {
			output[n-1] ^= 1
		}
		w.Header().Set("Content-Type", "application/cbor")
		w.Header().Set("Content-Length", strconv.Itoa(n))
		_, _ = w.Write(output[:n])
	}))
	server.Config.MaxHeaderBytes = 8192
	server.Config.ReadTimeout, server.Config.WriteTimeout, server.Config.IdleTimeout = 5*time.Second, 5*time.Second, 5*time.Second
	server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		SessionTicketsDisabled: true, NextProtos: []string{"http/1.1"}}
	server.StartTLS()
	t.Cleanup(server.Close)
	return strings.Replace(server.URL, "127.0.0.1", "localhost", 1), requests.Load
}

func publicBrowserWSSCertificate(t *testing.T) (tls.Certificate, *x509.CertPool, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		DNSNames: []string{"localhost"}, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	policy, err := protocolv4.EncodeMap(make([]byte, 256), "TLSPolicy", []protocolv4.Field{
		{Name: "mode"}, {Name: "require_consumer_tls13_verification", Kind: protocolv4.Boolean},
	})
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, roots, policy
}

func publicBrowserTLSClock(t *testing.T) *timev4.Clock {
	t.Helper()
	clock, err := timev4.NewClock(timev4.Profile{Rate: timev4.Rate{Denominator: 1}, MaxWidthMS: 100, MaxAgeMS: 100000, MaxRoundTripMS: 100},
		func() (timev4.Tick, error) { return timev4.Tick{Incarnation: [16]byte{1}}, nil })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(clock.Close)
	mark, err := clock.Monotonic()
	if err != nil {
		t.Fatal(err)
	}
	now := uint64(time.Now().UnixMilli())
	if err := clock.InstallTrusted(mark, timev4.Interval{LowerMS: now, UpperMS: now}); err != nil {
		t.Fatal(err)
	}
	return clock
}

func publicWebSocketEnvironmentRoundTrip(t *testing.T, source, profile string, pin bool, options webSocketRoundTripOptions) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	address := listener.Addr().(*net.TCPAddr).AddrPort()
	var h *sessionv4.PublicQUICTestHarness
	var authorized, released [2]atomic.Int32
	emit := func(event string, value any) {
		if options.browser == nil {
			return
		}
		wire, err := json.Marshal(struct {
			Event string `json:"event"`
			Value any    `json:"value"`
		}{event, value})
		if err != nil {
			t.Fatal(err)
		}
		fmt.Printf("FLOWERSEC_PUBLIC %s\n", wire)
	}
	if options.browser != nil {
		t.Cleanup(func() {
			if h == nil {
				return
			}
			emit("cleanup", map[string]any{"reservations": h.Root.Snapshot().Reservations,
				"authorized": [2]int32{authorized[0].Load(), authorized[1].Load()}, "released": [2]int32{released[0].Load(), released[1].Load()}})
		})
	}
	certificate, roots, tlsPolicy := publicTestTLS(t, pin, address)
	if options.browser != nil {
		certificate, roots, tlsPolicy = publicBrowserWSSCertificate(t)
	}
	t.Cleanup(func() {
		if h != nil {
			if snapshot := h.Root.Snapshot(); !snapshot.CleanupComplete || snapshot.Reservations != 0 || snapshot.References != 0 {
				t.Error("public WebSocket graph retained original owners after cleanup", snapshot)
			}
		}
	})
	if options.browser != nil {
		h = sessionv4.NewPublicWSSBrowserTestHarness(t, source, profile, address, tlsPolicy, options.browser.Origin)
	} else {
		h = sessionv4.NewPublicWSSTestHarness(t, source, profile, address, tlsPolicy)
	}
	var requireRelease bool
	t.Cleanup(func() {
		if requireRelease && (released[0].Load() != 1 || released[1].Load() != 1) {
			t.Error("application leases did not retire exactly once", released[0].Load(), released[1].Load())
		}
	})
	if options.directExporter {
		h.Hello.Policy.BindingMode, h.Hello.BindingModes = 0, 1
	}
	reserve := func(cost fs.ResourceVector, err error) fs.ResourceReference {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return h.Reserve(cost)
	}
	cleanupContext := func() (context.Context, context.CancelFunc) {
		return context.WithTimeout(context.Background(), 5*time.Second)
	}
	executorConfig := fs.ApplicationExecutorConfig{Running: 8, ResidentRunning: 4, CompletionRunning: 1, CompletionReserved: 4, RuntimeBytes: 8192, RuntimeBytesPerTask: 65536}
	executor, err := fs.NewApplicationExecutor(executorConfig, reserve(fs.ApplicationExecutorCharge(executorConfig)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		executor.Close()
		cleanup, stop := cleanupContext()
		defer stop()
		select {
		case <-executor.Done():
		case <-cleanup.Done():
			t.Error("public WebSocket executor retained callbacks")
		}
	})
	config := fs.EnvironmentConfig{Positions: 2, Materials: 2, MaterialCreateMS: 1000, Clock: h.Clock, Verification: h.Verification, RuntimeBytes: 65536}
	environment, err := fs.NewTransportEnvironment(fs.EnvironmentOptions{Config: config, Reservation: reserve(fs.EnvironmentCharge(config)), Dependencies: h.Environment})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		environment.Close()
		cleanup, stop := cleanupContext()
		defer stop()
		if err := environment.WaitCleanup(cleanup); err != nil {
			t.Error("public WebSocket Environment cleanup", err)
		}
	})
	var materials [2]*fs.ConnectionMaterial
	for role := range materials {
		if options.browser != nil && role == 0 {
			continue
		}
		lease, err := fs.NewArtifactLeaseFromBytes(h.Lease, reserve(fs.ArtifactLeaseCharge(h.Lease.MapBytes, h.Lease.MapNodes, h.Lease.RuntimeBytes)), h.Preauth)
		if err != nil {
			t.Fatal("lease", role, err)
		}
		t.Cleanup(func() {
			lease.Close()
			cleanup, stop := cleanupContext()
			defer stop()
			if err := lease.WaitCleanup(cleanup); err != nil {
				t.Error("lease cleanup", role, err)
			}
		})
		identityConfig := h.Identity[role]
		identity, err := fs.NewApplicationIdentityFromBytes(identityConfig, reserve(fs.ApplicationIdentityCharge(identityConfig.MapNodes, identityConfig.RuntimeBytes)), h.Preauth)
		if err != nil {
			t.Fatal("identity", role, err)
		}
		t.Cleanup(func() {
			identity.Close()
			cleanup, stop := cleanupContext()
			defer stop()
			if err := identity.WaitCleanup(cleanup); err != nil {
				t.Error("identity cleanup", role, err)
			}
		})
		material, err := fs.NewConnectionMaterial(lease, identity, h.Generation, 8192, reserve(fs.ConnectionMaterialCharge(8192)))
		if err != nil {
			t.Fatal("material", role, err)
		}
		materials[role] = material
		t.Cleanup(func() {
			material.Close()
			cleanup, stop := cleanupContext()
			defer stop()
			if err := material.WaitCleanup(cleanup); err != nil {
				t.Error("material cleanup", role, err)
			}
		})
	}
	if options.browser == nil {
		materials[0], err = environment.CreateMaterial(ctx, func(context.Context) (*fs.ConnectionMaterial, error) { return materials[0], nil })
		if err != nil {
			t.Fatal("host material", err)
		}
	}
	reports := make(chan error, 2)
	for role := range 2 {
		if options.browser != nil && role == 0 {
			continue
		}
		role := role
		handlersConfig := fs.StreamHandlerPlanConfig{RuntimeBytes: 8192, Handlers: []fs.RawStreamHandlerConfig{{
			Kind: "example/websocket", Slots: 2, WorkClass: fs.WorkResident,
			AuthorizeOpen: func(_ context.Context, binding any, _ []byte) error {
				if binding != role {
					return fmt.Errorf("unexpected application binding %v", binding)
				}
				return nil
			},
			Handler: func(ctx context.Context, _ any, _ []byte, stream *fs.StreamOwnership) error {
				if options.browser != nil {
					err := publicBrowserEcho(ctx, stream)
					reports <- err
					return err
				}
				var payload [64]byte
				read, err := stream.ReadInto(ctx, payload[:])
				if err == nil {
					_, err = stream.WriteAll(ctx, payload[:read.Progress.Filled])
				}
				reports <- err
				<-ctx.Done()
				return ctx.Err()
			},
		}}}
		if options.streamRegistration != nil {
			handlersConfig.Handlers = []fs.RawStreamHandlerConfig{*options.streamRegistration}
		}
		delegates, err := h.Environment.Borrow()
		if err != nil {
			t.Fatal(err)
		}
		handlers, err := fs.NewStreamHandlerPlan(handlersConfig, executor, reserve(fs.StreamHandlerPlanCharge(handlersConfig)), delegates)
		if err != nil {
			delegates.Release()
			t.Fatal("handler plan", err)
		}
		t.Cleanup(func() {
			handlers.Close()
			cleanup, stop := cleanupContext()
			defer stop()
			if err := handlers.WaitCleanup(cleanup); err != nil {
				t.Error("handler plan cleanup", err)
			} else if err := handlers.Retire(); err != nil {
				t.Error("handler plan retirement", err)
			}
		})
		plan, err := (fs.SessionPlanFactory{Root: h.Root, Executor: executor, Dependencies: h.Environment}).Create(fs.SessionPlanConfig{
			RuntimeBytes: 8192, Handlers: handlers,
			AuthorizeApplication: func(_ context.Context, request fs.AuthenticatedRequestContext) (fs.AuthorizeApplicationResult, error) {
				authorized[role].Add(1)
				lease, err := request.ReserveLease(request.Binding(), role, func(context.Context) error { released[role].Add(1); return nil })
				if err == nil && role == 1 && options.rejectApplication {
					return fs.AuthorizeApplicationResult{Handlers: handlers, Lease: lease}, errors.New("application refused")
				}
				return fs.AuthorizeApplicationResult{Handlers: handlers, Lease: lease}, err
			},
		}, h.Owner(), h.Scope[role].Tenant, h.Scope[role].Session)
		if err != nil {
			t.Fatal("session plan", err)
		}
		t.Cleanup(func() {
			plan.Close()
			if err := plan.Retire(); err != nil {
				t.Error("application plan retirement", err)
			}
		})
		h.Admission[role].Application = plan
		h.Admission[role].Core.Handlers = fs.SessionStreamHandlerConfig{Plan: handlers, Concurrency: 2, TimeoutMS: 3000, RuntimeBytes: 8192, RuntimeBytesPerInvocation: 32768}
		if options.streamRegistration != nil {
			h.Admission[role].Core.Handlers.ServiceTarget = 1
		}
	}
	provider := fs.WebSocketProviderOptions{MaxMessageBytes: 65544, ReadBufferBytes: 256, WriteBufferBytes: 256,
		HandshakeBytes: 8192, MaxControlsPerSecond: 16, HandshakeTimeout: 5 * time.Second, MessageTimeout: 5 * time.Second,
		RuntimeBytes: 16384, ProviderRuntimeBytes: 65536, ProviderTasks: 4}
	accounts := []fs.ResourceAccount{h.Scope[1].Tenant}
	serveConfig := fs.ServeConfig{Positions: 2, RuntimeBytes: 8192, DrainTimeoutMS: 1000, Clock: h.Clock}
	serve, err := fs.NewAcceptor(ctx, fs.AcceptorOptions{Environment: environment, ServeOptions: fs.ServeOptions{Config: serveConfig, Reservation: reserve(fs.ServeCharge(serveConfig))}})
	if err != nil {
		t.Fatal("serve", err)
	}
	t.Cleanup(func() {
		serve.Close()
		cleanup, stop := cleanupContext()
		defer stop()
		if err := serve.WaitCleanup(cleanup); err != nil {
			t.Error("serve cleanup", err)
		}
	})
	entrance := fs.AcceptedEntranceConfig{Initial: h.Admission[1].Initial, RuntimeBytes: 8192, InitialRuntimeBytes: 8192, CarrierRuntimeBytes: 8192}
	acceptOptions := fs.WebSocketAcceptOptions{Input: fs.AcceptedSessionInput{Config: h.Admission[1], Root: h.Root, ResourceOwner: h.Owner(),
		Environment: h.Environment, Preauth: h.Preauth, Scope: h.Scope[1], Store: h.Store, Authority: h.Authority},
		Source: publicQUICMaterialSource{materials[1], h.Hello}, Limits: h.Limits, Entrance: entrance, Dependencies: h.Environment,
		Accounts: accounts, LocalCapabilities: h.Hello.Offered, RuntimeBytes: 8192, IngressRuntimeBytes: 8192, IntakeRuntimeBytes: 8192,
		MaxAdmissionRecordBytes: 16384, Provider: provider}
	if source == "preauthorized_pool" {
		acceptOptions.MaxAdmissionRecordBytes = 4096
	}
	liveControlBaseURL := ""
	liveRequests := func() int32 { return 0 }
	var browserLookups atomic.Int32
	if options.browser != nil {
		hello := func() fs.InitialHello { return h.Hello }
		if source == "live_authority" {
			hello = h.BrowserHello
			liveControlBaseURL, liveRequests = publicBrowserLiveControl(t, h, certificate, options.browser.Origin, options.browser.ControlFailure == "signature")
		}
		acceptOptions.Source = publicBrowserMaterialSource{materials[1], hello, &browserLookups}
	}
	type result struct {
		session  *fs.Session
		hijacked bool
		err      error
	}
	accepted := make(chan result, 1)
	var server *fs.WebSocketServer
	var httpIngress atomic.Int32
	serverClock := h.Clock
	if options.browser != nil {
		serverClock = publicBrowserTLSClock(t)
	}
	serverConfig := fs.WebSocketServerConfig{Root: h.Root, Clock: serverClock, Route: h.Route, Certificate: certificate, Roots: roots,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			httpIngress.Add(1)
			acceptOptions.Server = server
			session, hijacked, err := serve.AcceptWebSocket(ctx, w, r, acceptOptions)
			if err != nil && !hijacked {
				http.Error(w, "Flowersec admission failed", http.StatusForbidden)
			}
			accepted <- result{session: session, hijacked: hijacked, err: err}
		}),
		Connections: 2, HeaderBytes: 8192, HeaderTimeout: 5 * time.Second, IdleTimeout: 5 * time.Second,
		RuntimeBytes: 65536, ProviderBytesPerConnection: 1 << 20}
	server, err = fs.NewWebSocketServer(serverConfig, reserve(fs.WebSocketServerCharge(serverConfig)), h.Environment)
	if err != nil {
		t.Fatal("server", err)
	}
	ended := make(chan error, 1)
	go func() { ended <- server.Serve(listener) }()
	t.Cleanup(func() {
		server.Close()
		cleanup, stop := cleanupContext()
		defer stop()
		if err := server.WaitCleanup(cleanup); err != nil {
			t.Error("server cleanup", err)
		}
		select {
		case err := <-ended:
			if err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
				t.Error("native WebSocket Serve", err)
			}
		case <-cleanup.Done():
			t.Error("native WebSocket Serve did not exit")
		}
	})
	var factory *fs.WebSocketCarrierFactory
	if options.browser == nil {
		factoryConfig := fs.WebSocketFactoryConfig{Root: h.Root, Owner: h.Owner(), Clock: h.Clock, Route: h.Route,
			RemoteAddress: address, Roots: roots, Options: provider, Connections: 1, RuntimeBytes: 65536}
		factory, err = fs.NewWebSocketCarrierFactory(factoryConfig, reserve(fs.WebSocketCarrierFactoryCharge(factoryConfig)), h.Environment)
		if err != nil {
			t.Fatal("factory", err)
		}
		t.Cleanup(func() {
			factory.Close()
			cleanup, stop := cleanupContext()
			defer stop()
			if err := factory.WaitCleanup(cleanup); err != nil {
				t.Error("factory cleanup", err)
			}
		})
	}
	preparation := fs.SourceConnectConfig{Generation: h.Generation, LocalCapabilities: h.Hello.Offered,
		Requirements: fs.MaterialRequirements{ApplicationProfile: "transport", Connection: fs.RequiredGuarantees{LocalConsumerTls13Verification: true}},
		Carrier:      factory, Hello: h.Hello, Limits: h.Limits, Admission: h.Admission[0], Root: h.Root, Owner: h.Owner(),
		Environment: h.Environment, Preauth: h.Preauth, Dependencies: h.Environment, Scope: h.Scope[0], RuntimeBytes: 8192, CarrierRuntimeBytes: 8192,
		AddressAttempts: 1, AttemptBudget: fs.CarrierAttemptBudget{PreauthBytes: 131072, WorkUnits: 128}, LiveIssuance: h.LiveIssuance}
	if options.browser != nil {
		emit("fixture", map[string]any{
			"port": address.Port(), "routeDigest": h.BrowserRouteDigest[:], "profile": profile,
			"artifact": h.Lease.Artifact, "activation": h.Lease.Proof,
			"clientCertificate": h.Lease.ClientCertificate, "serverCertificate": h.Lease.ServerCertificate,
			"rootKeyID": h.BrowserRootKeyID[:], "rootPublicKey": h.BrowserRootPublicKey[:],
			"identitySeed": h.BrowserIdentitySeed[:], "dhSeed": h.BrowserDHSeed[:],
			"tenant": h.BrowserTenant, "authority": h.BrowserAuthority, "audience": h.BrowserAudience,
			"clientSubject": h.BrowserClientSubject, "serverSubject": h.BrowserServerSubject,
			"onceAuthority": h.BrowserOnceAuthority, "issuerKeyID": h.BrowserIssuerKeyID[:],
			"liveControlBaseURL": liveControlBaseURL,
		})
		decoder := json.NewDecoder(os.Stdin)
		var bootstrap struct{ Nonce []byte }
		if err := decoder.Decode(&bootstrap); err != nil || len(bootstrap.Nonce) != 32 {
			t.Fatal("browser bootstrap nonce", err)
		}
		var nonce [32]byte
		copy(nonce[:], bootstrap.Nonce)
		response, state := h.BrowserBootstrap(nonce)
		emit("bootstrap", map[string]any{"response": response, "state": state})
		finished := make(chan bool, 1)
		go func() {
			var finish struct{ Finish bool }
			err := decoder.Decode(&finish)
			finished <- err == nil && finish.Finish
		}()
		var peer result
		select {
		case peer = <-accepted:
		case <-finished:
			return
		case <-ctx.Done():
			t.Fatal("browser public WSS admission timed out", ctx.Err())
		}
		if options.browser.ControlFailure != "" {
			if peer.err == nil || peer.session != nil || authorized[1].Load() != 0 || browserLookups.Load() != 0 {
				t.Fatalf("failed browser control reached admission: %v, authorization=%d, lookups=%d", peer.err, authorized[1].Load(), browserLookups.Load())
			}
			emit("refused", map[string]any{"liveRequests": liveRequests(), "liveAuthorizations": h.BrowserPolicyCalls(), "materialLookups": browserLookups.Load()})
			if !<-finished {
				t.Fatal("browser public WSS failure finish was not acknowledged")
			}
			return
		}
		if peer.err != nil || !peer.hijacked || peer.session == nil || authorized[1].Load() != 1 {
			t.Fatalf("browser public WSS admission: %v, hijacked=%t, authorization=%d", peer.err, peer.hijacked, authorized[1].Load())
		}
		t.Cleanup(func() {
			_ = peer.session.Close()
			cleanup, stop := cleanupContext()
			defer stop()
			if err := peer.session.WaitCleanup(cleanup); err != nil {
				t.Error("browser public WSS Session cleanup", err)
			}
		})
		for range 2 {
			select {
			case err := <-reports:
				if err != nil {
					t.Fatal("browser public WSS stream", err)
				}
			case <-ctx.Done():
				t.Fatal("browser public WSS stream timed out", ctx.Err())
			}
		}
		liveAuthorizations := 0
		if h.BrowserPolicyCalls != nil {
			liveAuthorizations = h.BrowserPolicyCalls()
		}
		emit("served", map[string]any{"streams": 2, "liveAuthorizations": liveAuthorizations, "liveRequests": liveRequests(), "materialLookups": browserLookups.Load()})
		if !<-finished {
			t.Fatal("browser public WSS finish was not acknowledged")
		}
		requireRelease = false
		return
	}
	for _, check := range []struct {
		name        string
		requirement fs.RequiredGuarantees
	}{
		{"independent_read", fs.RequiredGuarantees{LocalConsumerTls13Verification: true, IndependentReliableReadProgress: true}},
		{"input_isolation", fs.RequiredGuarantees{LocalConsumerTls13Verification: true, BoundStreamInputIsolation: true}},
		{"datagram", fs.RequiredGuarantees{LocalConsumerTls13Verification: true, Datagram: true}},
	} {
		unavailable := preparation
		unavailable.Requirements.Connection = check.requirement
		if session, err := fs.ConnectMaterial(ctx, materials[0], fs.ConnectorOptions{Environment: environment, ConnectOptions: fs.ConnectOptions{Pool: h.Pool, Live: h.Live, Preparation: unavailable}}); session != nil || !errors.Is(err, protocolv4.ErrRequiredGuaranteeUnavailable) {
			t.Fatalf("WSS %s requirement: session=%v error=%v", check.name, session, err)
		}
		if httpIngress.Load() != 0 || authorized[0].Load() != 0 || authorized[1].Load() != 0 {
			t.Fatal("WSS requirement reached network or application admission", check.name)
		}
	}
	client, clientErr := fs.ConnectMaterial(ctx, materials[0], fs.ConnectorOptions{Environment: environment, ConnectOptions: fs.ConnectOptions{Pool: h.Pool, Live: h.Live, Preparation: preparation}})
	var peer result
	select {
	case peer = <-accepted:
	case <-ctx.Done():
		peer.err = ctx.Err()
	}
	sessions := [2]*fs.Session{client, peer.session}
	t.Cleanup(func() {
		for _, session := range sessions {
			if session != nil {
				_ = session.Close()
			}
		}
		cleanup, stop := cleanupContext()
		defer stop()
		for role, session := range sessions {
			if session != nil {
				if err := session.WaitCleanup(cleanup); err != nil {
					t.Error("Session cleanup", role, err)
				}
			}
		}
	})
	if options.rejectApplication {
		if clientErr == nil || peer.err == nil || !peer.hijacked || authorized[1].Load() != 1 || authorized[0].Load() != 1 {
			t.Fatalf("application refusal crossed admission: consumer=%v accepted=%v hijacked=%t authorization=%d/%d",
				clientErr, peer.err, peer.hijacked, authorized[0].Load(), authorized[1].Load())
		}
		requireRelease = true
		return
	}
	if clientErr != nil || peer.err != nil || !peer.hijacked {
		t.Fatalf("public WebSocket establishment: consumer=%v accepted=%v hijacked=%t", clientErr, peer.err, peer.hijacked)
	}
	for role, session := range sessions {
		registry := "native_websocket_tls13"
		if role == 1 {
			registry = "accepted_websocket"
		}
		guarantees, ok := protocolv4.ConnectionAssurance(registry)
		info := session.Info()
		if !ok || info.ApplicationProfile != "transport" || info.Guarantees != guarantees || authorized[role].Load() != 1 {
			t.Fatal("READY did not publish the authenticated WebSocket guarantees", role, info, authorized[role].Load())
		}
		if options.streamWorkflow != nil {
			continue
		}
		stream, err := session.OpenStream(ctx, "example/websocket", fs.EmptyStreamMetadata())
		if err != nil {
			t.Fatal("open", role, err)
		}
		t.Cleanup(func() { _ = stream.Close() })
		payload := []byte(fmt.Sprintf("public WebSocket stream role %d", role))
		if n, err := stream.WriteAll(ctx, payload); err != nil || n != len(payload) {
			t.Fatal("write", role, n, err)
		}
		reply := make([]byte, len(payload))
		if _, err := io.ReadFull(stream, reply); err != nil || string(reply) != string(payload) {
			t.Fatal("read", role, string(reply), err)
		}
		if err := <-reports; err != nil {
			t.Fatal("handler", role, err)
		}
	}
	if options.streamWorkflow != nil {
		options.streamWorkflow(ctx, sessions)
	}
	if source == "live_authority" && h.PolicyCalls != 1 {
		t.Fatal("live policy was not called exactly once", h.PolicyCalls)
	}
	requireRelease = true
}

func publicBrowserEcho(ctx context.Context, stream *fs.StreamOwnership) error {
	var payload [64]byte
	for {
		read, err := stream.ReadInto(ctx, payload[:])
		if err != nil {
			return err
		}
		if read.Progress.Filled != 0 {
			if _, err := stream.WriteAll(ctx, payload[:read.Progress.Filled]); err != nil {
				return err
			}
		}
		if read.ReadTerminal == protocolv4.V4ReadTerminalEof {
			return stream.Finish(ctx)
		}
		if read.ReadTerminal != protocolv4.V4ReadTerminalOpen {
			return fmt.Errorf("unexpected stream terminal: %v", read.ReadTerminal)
		}
	}
}
