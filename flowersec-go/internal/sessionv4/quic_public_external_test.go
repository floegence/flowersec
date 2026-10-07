package sessionv4_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	fs "github.com/floegence/flowersec/flowersec-go/v6"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/tlspolicy"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

type publicQUICMaterialSource struct {
	material *fs.ConnectionMaterial
	hello    fs.InitialHello
}

func (s publicQUICMaterialSource) ResolveAcceptedMaterial(context.Context, []byte) (*fs.ConnectionMaterial, fs.InitialHello, error) {
	return s.material, s.hello, nil
}

type publicControllerSource func(context.Context, fs.ControllerRequest) (*fs.ControllerPreparation, error)

func (s publicControllerSource) PrepareConnection(ctx context.Context, r fs.ControllerRequest) (*fs.ControllerPreparation, error) {
	return s(ctx, r)
}

type publicControllerLeaseSource struct{ lease *fs.ArtifactLease }

func (s publicControllerLeaseSource) AcquireLease(context.Context, fs.MaterialLeaseRequest) (*fs.ArtifactLease, error) {
	return s.lease, nil
}

func publicQUICTestTLS(t *testing.T, pin bool) (netip.AddrPort, tls.Certificate, *x509.CertPool, []byte) {
	t.Helper()
	probe, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	address := probe.LocalAddr().(*net.UDPAddr).AddrPort()
	if err = probe.Close(); err != nil {
		t.Fatal(err)
	}
	certificate, roots, policy := publicTestTLS(t, pin, address)
	return address, certificate, roots, policy
}

func publicTestTLS(t *testing.T, pin bool, address netip.AddrPort) (tls.Certificate, *x509.CertPool, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.UnixMilli(1000), NotAfter: time.UnixMilli(200000),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	encode := func(schema string, fields ...protocolv4.Field) []byte {
		t.Helper()
		wire, err := protocolv4.EncodeMap(make([]byte, 4096), schema, fields)
		if err != nil {
			t.Fatal(err)
		}
		return wire
	}
	fields := []protocolv4.Field{{Name: "mode"}, {Name: "require_consumer_tls13_verification", Kind: protocolv4.Boolean, Number: 1}}
	if pin {
		digest := sha256.Sum256(der)
		entry := encode("TLSPin", protocolv4.Field{Name: "leaf_der_sha256", Kind: protocolv4.ByteString, Bytes: digest[:]},
			protocolv4.Field{Name: "not_before_ms", Number: 1100}, protocolv4.Field{Name: "not_after_ms", Number: 190000},
			protocolv4.Field{Name: "certificate_profile", Kind: protocolv4.TextString, Text: tlspolicy.CertificateProfile})
		fields[0].Number = 1
		fields = append(fields, protocolv4.Field{Name: "pin_kind"}, protocolv4.Field{Name: "pins", Kind: protocolv4.EncodedArray, Bytes: append([]byte{0x81}, entry...)})
		roots = nil
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, roots, encode("TLSPolicy", fields...)
}

// These cases use only public Go constructors for Environment, real UDP/TLS
// preparation, material, Serve, Session and Stream. The harness supplies signed
// authority documents and an actual SQLite store, never handshake outcomes.
func TestPublicQUICEnvironmentSourcesNoiseReadyAndStreams(t *testing.T) {
	for _, source := range []string{"preauthorized_pool", "live_authority"} {
		for _, profile := range []string{protocolv4.DHProfileX25519, protocolv4.DHProfileP256} {
			for _, pin := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/pin=%t", source, profile, pin), func(t *testing.T) {
					publicQUICEnvironmentRoundTrip(t, source, profile, pin)
				})
			}
		}
	}
}

func TestPublicQUICUnreliableMessages(t *testing.T) {
	for _, profile := range []string{protocolv4.DHProfileX25519, protocolv4.DHProfileP256} {
		t.Run(profile, func(t *testing.T) { publicQUICEnvironmentRoundTrip(t, "preauthorized_pool", profile, true, true) })
	}
}

func TestPublicQUICDirectExporter(t *testing.T) {
	for _, source := range []string{"preauthorized_pool", "live_authority"} {
		for _, profile := range []string{protocolv4.DHProfileX25519, protocolv4.DHProfileP256} {
			t.Run(source+"/"+profile, func(t *testing.T) {
				publicQUICEnvironmentRoundTrip(t, source, profile, true, true, true)
			})
		}
	}
}

func TestPublicControllerQUICSourceAndCandidateIdentity(t *testing.T) {
	for _, source := range []string{"preauthorized_pool", "live_authority"} {
		t.Run(source, func(t *testing.T) {
			publicQUICEnvironmentRoundTrip(t, source, protocolv4.DHProfileX25519, true, false, false, true)
		})
	}
}

func TestPublicControllerQUICFailureProjection(t *testing.T) {
	publicQUICEnvironmentRoundTrip(t, "preauthorized_pool", protocolv4.DHProfileX25519, true, false, false, true, true)
}

func publicQUICEnvironmentRoundTrip(t *testing.T, source, profile string, pin bool, enableDatagrams ...bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	address, certificate, roots, tlsPolicy := publicQUICTestTLS(t, pin)
	var h *sessionv4.PublicQUICTestHarness
	t.Cleanup(func() {
		if h != nil {
			if snapshot := h.Root.Snapshot(); !snapshot.CleanupComplete || snapshot.Reservations != 0 || snapshot.References != 0 {
				t.Error("public QUIC graph retained original owners after cleanup", snapshot)
			}
		}
	})
	datagrams := len(enableDatagrams) != 0 && enableDatagrams[0]
	viaController := len(enableDatagrams) > 2 && enableDatagrams[2]
	failInitialization := len(enableDatagrams) > 3 && enableDatagrams[3]
	h = sessionv4.NewPublicQUICTestHarness(t, source, profile, address, tlsPolicy, datagrams)
	if len(enableDatagrams) > 1 && enableDatagrams[1] {
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
			t.Error("public QUIC executor retained callbacks")
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
			t.Error("public QUIC Environment cleanup", err)
		}
	})
	var materials [2]*fs.ConnectionMaterial
	var clientLease *fs.ArtifactLease
	var clientIdentity *fs.ApplicationIdentity
	for role := range 2 {
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
		materials[role], err = fs.NewConnectionMaterial(lease, identity, h.Generation, 8192, reserve(fs.ConnectionMaterialCharge(8192)))
		if err != nil {
			t.Fatal("material", role, err)
		}
		if role == 0 {
			clientLease, clientIdentity = lease, identity
		}
		t.Cleanup(func() {
			materials[role].Close()
			cleanup, stop := cleanupContext()
			defer stop()
			if err := materials[role].WaitCleanup(cleanup); err != nil {
				t.Error("material cleanup", role, err)
			}
		})
	}
	if !viaController {
		materials[0], err = environment.CreateMaterial(ctx, func(context.Context) (*fs.ConnectionMaterial, error) { return materials[0], nil })
		if err != nil {
			t.Fatal("host material", err)
		}
	} else {
		materials[0].Close()
	}
	var authorized, released [2]atomic.Int32
	reports := make(chan error, 2)
	for role := range 2 {
		handlersConfig := fs.StreamHandlerPlanConfig{RuntimeBytes: 8192, Handlers: []fs.RawStreamHandlerConfig{{
			Kind: "example/quic", Slots: 2, WorkClass: fs.WorkResident,
			AuthorizeOpen: func(_ context.Context, binding any, _ []byte) error {
				if binding != role {
					return fmt.Errorf("unexpected application binding %v", binding)
				}
				return nil
			},
			Handler: func(ctx context.Context, _ any, _ []byte, stream *fs.StreamOwnership) error {
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
		delegates, err := h.Environment.Borrow()
		if err != nil {
			t.Fatal(err)
		}
		handlers, err := fs.NewStreamHandlerPlan(handlersConfig, executor, reserve(fs.StreamHandlerPlanCharge(handlersConfig)), delegates)
		if err != nil {
			delegates.Release()
			t.Fatal("handler plan", err)
		}
		t.Cleanup(handlers.Close)
		plan, err := (fs.SessionPlanFactory{Root: h.Root, Executor: executor, Dependencies: h.Environment}).Create(fs.SessionPlanConfig{
			RuntimeBytes: 8192, Handlers: handlers,
			AuthorizeApplication: func(_ context.Context, request fs.AuthenticatedRequestContext) (fs.AuthorizeApplicationResult, error) {
				authorized[role].Add(1)
				lease, err := request.ReserveLease(request.Binding(), role, func(context.Context) error { released[role].Add(1); return nil })
				return fs.AuthorizeApplicationResult{Handlers: handlers, Lease: lease}, err
			},
		}, h.Owner(), h.Scope[role].Tenant, h.Scope[role].Session)
		if err != nil {
			t.Fatal("session plan", err)
		}
		t.Cleanup(func() { plan.Close(); _ = plan.Retire() })
		h.Admission[role].Application = plan
		h.Admission[role].Core.Handlers = fs.SessionStreamHandlerConfig{Plan: handlers, Concurrency: 2, TimeoutMS: 3000, RuntimeBytes: 8192, RuntimeBytesPerInvocation: 32768}
	}
	limits := fs.DefaultQUICLimits()
	limits.MaxInboundStreams = 8
	provider := fs.QUICProviderOptions{Limits: limits, StreamSlots: 8, RuntimeBytes: 65536, ProviderBytes: 32 << 20, ProviderTasks: 16}
	accounts := []fs.ResourceAccount{h.Scope[1].Tenant}
	serverConfig := fs.QUICServerConfig{Root: h.Root, Owner: h.Owner(), Clock: h.Clock, Accounts: accounts, Address: address,
		Route: h.Route, Certificate: certificate, Roots: roots, Connection: provider, Connections: 2, RuntimeBytes: 65536,
		ListenerRuntimeBytes: 65536, ListenerProviderBytes: 1 << 20, ListenerProviderTasks: 4}
	serverCharge, err := fs.QUICServerCharge(serverConfig)
	if err != nil {
		t.Fatal("server charge", err)
	}
	server, err := fs.NewQUICServer(serverConfig, h.Reserve(serverCharge, accounts...), h.Environment)
	if err != nil {
		t.Fatal("server", err)
	}
	t.Cleanup(func() {
		_ = server.Close()
		cleanup, stop := cleanupContext()
		defer stop()
		if err := server.WaitCleanup(cleanup); err != nil {
			t.Error("server cleanup", err)
		}
	})
	factoryConfig := fs.QUICFactoryConfig{Root: h.Root, Owner: h.Owner(), Clock: h.Clock, Route: h.Route, RemoteAddress: address, Roots: roots, Options: provider, Connections: 1, RuntimeBytes: 65536}
	factory, err := fs.NewQUICCarrierFactory(factoryConfig, reserve(fs.QUICCarrierFactoryCharge(factoryConfig)), h.Environment)
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
	acceptOptions := fs.QUICAcceptOptions{Input: fs.AcceptedSessionInput{Config: h.Admission[1], Root: h.Root, ResourceOwner: h.Owner(),
		Environment: h.Environment, Preauth: h.Preauth, Scope: h.Scope[1], Store: h.Store, Authority: h.Authority},
		Source: publicQUICMaterialSource{materials[1], h.Hello}, Limits: h.Limits, Entrance: entrance, Dependencies: h.Environment,
		Accounts: accounts, LocalCapabilities: h.Hello.Offered, IngressRuntimeBytes: 8192, IntakeRuntimeBytes: 8192, MaxAdmissionRecordBytes: 16384}
	if source == "preauthorized_pool" {
		acceptOptions.MaxAdmissionRecordBytes = 4096
	}
	type result struct {
		session *fs.Session
		err     error
	}
	accepted := make(chan result, 1)
	go func() {
		ingress, err := server.Accept(ctx, entrance)
		if err != nil {
			accepted <- result{err: err}
			return
		}
		defer ingress.Close()
		session, err := serve.AcceptQUIC(ctx, ingress, acceptOptions)
		accepted <- result{session, err}
	}()
	preparation := fs.SourceConnectConfig{Generation: h.Generation, LocalCapabilities: h.Hello.Offered, Requirements: fs.MaterialRequirements{ApplicationProfile: "transport", Connection: fs.RequiredGuarantees{LocalConsumerTls13Verification: true, Datagram: datagrams}},
		Carrier: factory, Hello: h.Hello, Limits: h.Limits, Admission: h.Admission[0], Root: h.Root, Owner: h.Owner(),
		Environment: h.Environment, Preauth: h.Preauth, Dependencies: h.Environment, Scope: h.Scope[0], RuntimeBytes: 8192, CarrierRuntimeBytes: 8192,
		AddressAttempts: 1, AttemptBudget: fs.CarrierAttemptBudget{PreauthBytes: 131072, WorkUnits: 128}, LiveIssuance: h.LiveIssuance}
	var client *fs.Session
	var clientErr error
	if viaController {
		preparation.Identity, preparation.Provider, preparation.MaterialRuntimeBytes = clientIdentity, publicControllerLeaseSource{clientLease}, 8192
		var candidate *fs.Session
		options := fs.ControllerOptions{Clock: h.Clock, SourceIncarnation: h.Generation.Source, Executor: executor,
			AttemptTimeoutMS: 1000, DrainTimeoutMS: 1000, RuntimeBytes: 65536, MaximumAttempts: 1,
			Source: publicControllerSource(func(_ context.Context, request fs.ControllerRequest) (*fs.ControllerPreparation, error) {
				if request.Attempt != 1 {
					return nil, fmt.Errorf("unexpected replay: %d", request.Attempt)
				}
				return &fs.ControllerPreparation{Config: preparation, Pool: h.Pool, Live: h.Live}, nil
			}), InitializeSession: func(_ context.Context, session *fs.Session) error {
				candidate = session
				if failInitialization {
					return errors.New("private initializer failure")
				}
				return nil
			}}
		metadata, task, completion, chargeErr := fs.ControllerCharges(options)
		if chargeErr != nil {
			t.Fatal(chargeErr)
		}
		options.Reservation, options.InitializeTask, options.InitializeCompletion = h.Reserve(metadata), h.Reserve(task), h.Reserve(completion)
		controller, createErr := fs.NewConnectionController(ctx, fs.ConnectionControllerOptions{Environment: environment, ControllerOptions: options})
		if createErr != nil {
			t.Fatal(createErr)
		}
		t.Cleanup(func() {
			controller.Close()
			cleanup, stop := cleanupContext()
			defer stop()
			if err := controller.WaitCleanup(cleanup); err != nil {
				t.Error("Controller cleanup", err)
			}
		})
		clientErr = controller.Start(ctx)
		if clientErr == nil {
			client, clientErr = controller.WaitForSession(ctx)
		}
		if failInitialization {
			snapshot := controller.Snapshot()
			if !errors.Is(clientErr, fs.ErrControllerInitialization) || snapshot.LastError == nil ||
				snapshot.LastError.Code() != fs.SessionOperationFailed || snapshot.Current || snapshot.Pending ||
				strings.Contains(clientErr.Error(), "private initializer failure") {
				t.Fatalf("public Controller failure projection: error=%v snapshot=%+v", clientErr, snapshot)
			}
		} else if clientErr == nil && (client != candidate || candidate == nil) {
			t.Fatal("initializer candidate public identity changed at publication")
		}
	} else {
		client, clientErr = fs.ConnectMaterial(ctx, materials[0], fs.ConnectorOptions{Environment: environment, ConnectOptions: fs.ConnectOptions{Pool: h.Pool, Live: h.Live, Preparation: preparation}})
	}
	if clientErr != nil {
		cancel()
	}
	peer := <-accepted
	if failInitialization {
		if peer.session != nil {
			_ = peer.session.Close()
			cleanup, stop := cleanupContext()
			if err := peer.session.WaitCleanup(cleanup); err != nil {
				t.Error("failed-candidate peer cleanup", err)
			}
			stop()
		}
		return
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
		if clientErr == nil && peer.err == nil && (released[0].Load() != 1 || released[1].Load() != 1) {
			t.Error("application leases did not retire exactly once", released[0].Load(), released[1].Load())
		}
	})
	if clientErr != nil || peer.err != nil {
		t.Fatalf("public QUIC establishment: consumer=%v accepted=%v", clientErr, peer.err)
	}
	for role, session := range sessions {
		info := session.Info()
		registry := "native_quic_tls13"
		if role == 1 {
			registry = "accepted_quic"
		}
		guarantees, ok := protocolv4.ConnectionAssurance(registry)
		guarantees.Datagram = datagrams
		if !ok || info.ApplicationProfile != "transport" || info.Guarantees != guarantees || authorized[role].Load() != 1 {
			t.Fatal("READY did not publish the original authenticated guarantees", role, info, authorized[role].Load())
		}
		stream, err := session.OpenStream(ctx, "example/quic", fs.EmptyStreamMetadata())
		if err != nil {
			t.Fatal("open", role, err)
		}
		t.Cleanup(func() { _ = stream.Close() })
		payload := []byte(fmt.Sprintf("original public QUIC stream role %d", role))
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
	if datagrams {
		left, err := sessions[0].UnreliableMessages()
		if err != nil {
			t.Fatal(err)
		}
		right, err := sessions[1].UnreliableMessages()
		if err != nil {
			t.Fatal(err)
		}
		channels := [2]fs.UnreliableMessageChannel{left, right}
		for role, channel := range channels {
			if channel.MaxMessageBytes() != 949 {
				t.Fatal(channel.MaxMessageBytes())
			}
			if status, err := channel.Send(ctx, []byte("public native datagram"), fs.UnreliableSendOptions{ExpiresAt: time.UnixMilli(3900)}); err != nil || status != fs.UnreliableAccepted {
				t.Fatal(status, err)
			}
			payload, err := channels[1-role].Receive(ctx)
			if err != nil || string(payload) != "public native datagram" {
				t.Fatal(string(payload), err)
			}
		}
	}
	if source == "live_authority" && h.PolicyCalls != 1 {
		t.Fatal("live policy was not called exactly once", h.PolicyCalls)
	}
}
