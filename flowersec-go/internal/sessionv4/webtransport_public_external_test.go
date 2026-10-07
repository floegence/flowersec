package sessionv4_test

import (
	"context"
	"fmt"
	"io"
	"sync/atomic"
	"testing"
	"time"

	fs "github.com/floegence/flowersec/flowersec-go/v6"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

// These cases use only public Go constructors for Environment, real UDP/TLS
// preparation, material, Serve, Session and Stream. The harness supplies signed
// authority documents and an actual SQLite store, never handshake outcomes.
func TestPublicWebTransportEnvironmentSourcesNoiseReadyAndStreams(t *testing.T) {
	for _, source := range []string{"preauthorized_pool", "live_authority"} {
		for _, profile := range []string{protocolv4.DHProfileX25519, protocolv4.DHProfileP256} {
			for _, pin := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/pin=%t", source, profile, pin), func(t *testing.T) {
					publicWebTransportEnvironmentRoundTrip(t, source, profile, pin)
				})
			}
		}
	}
}

func TestPublicWebTransportUnreliableMessages(t *testing.T) {
	for _, profile := range []string{protocolv4.DHProfileX25519, protocolv4.DHProfileP256} {
		t.Run(profile, func(t *testing.T) {
			publicWebTransportEnvironmentRoundTrip(t, "preauthorized_pool", profile, true, true)
		})
	}
}

func TestPublicWebTransportDirectExporter(t *testing.T) {
	for _, source := range []string{"preauthorized_pool", "live_authority"} {
		for _, profile := range []string{protocolv4.DHProfileX25519, protocolv4.DHProfileP256} {
			t.Run(source+"/"+profile, func(t *testing.T) {
				publicWebTransportEnvironmentRoundTrip(t, source, profile, true, true, true)
			})
		}
	}
}

func publicWebTransportEnvironmentRoundTrip(t *testing.T, source, profile string, pin bool, enableDatagrams ...bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	address, certificate, roots, tlsPolicy := publicQUICTestTLS(t, pin)
	var h *sessionv4.PublicQUICTestHarness
	t.Cleanup(func() {
		if h != nil {
			if snapshot := h.Root.Snapshot(); !snapshot.CleanupComplete || snapshot.Reservations != 0 || snapshot.References != 0 {
				t.Error("public WebTransport graph retained original owners after cleanup", snapshot)
			}
		}
	})
	datagrams := len(enableDatagrams) != 0 && enableDatagrams[0]
	h = sessionv4.NewPublicWebTransportTestHarness(t, source, profile, address, tlsPolicy, datagrams)
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
			t.Error("public WebTransport executor retained callbacks")
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
			t.Error("public WebTransport Environment cleanup", err)
		}
	})
	var materials [2]*fs.ConnectionMaterial
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
		t.Cleanup(func() {
			materials[role].Close()
			cleanup, stop := cleanupContext()
			defer stop()
			if err := materials[role].WaitCleanup(cleanup); err != nil {
				t.Error("material cleanup", role, err)
			}
		})
	}
	materials[0], err = environment.CreateMaterial(ctx, func(context.Context) (*fs.ConnectionMaterial, error) { return materials[0], nil })
	if err != nil {
		t.Fatal("host material", err)
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
	limits := fs.DefaultWebTransportLimits()
	limits.MaxInboundStreams = 8
	provider := fs.WebTransportProviderOptions{Limits: limits, StreamSlots: 8, RuntimeBytes: 65536, ProviderBytes: 32 << 20, ProviderTasks: 16}
	accounts := []fs.ResourceAccount{h.Scope[1].Tenant}
	serverConfig := fs.WebTransportServerConfig{Root: h.Root, Owner: h.Owner(), Clock: h.Clock, Accounts: accounts, Address: address,
		Route: h.Route, Certificate: certificate, Roots: roots, Connection: provider, Connections: 2, RuntimeBytes: 65536,
		ListenerRuntimeBytes: 65536, ListenerProviderBytes: 1 << 20, ListenerProviderTasks: 4}
	serverCharge, err := fs.WebTransportServerCharge(serverConfig)
	if err != nil {
		t.Fatal("server charge", err)
	}
	server, err := fs.NewWebTransportServer(serverConfig, h.Reserve(serverCharge, accounts...), h.Environment)
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
	factoryConfig := fs.WebTransportFactoryConfig{Root: h.Root, Owner: h.Owner(), Clock: h.Clock, Route: h.Route, RemoteAddress: address, Roots: roots, Options: provider, Connections: 1, RuntimeBytes: 65536}
	factory, err := fs.NewWebTransportCarrierFactory(factoryConfig, reserve(fs.WebTransportCarrierFactoryCharge(factoryConfig)), h.Environment)
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
	acceptOptions := fs.WebTransportAcceptOptions{Input: fs.AcceptedSessionInput{Config: h.Admission[1], Root: h.Root, ResourceOwner: h.Owner(),
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
		session, err := serve.AcceptWebTransport(ctx, ingress, acceptOptions)
		accepted <- result{session, err}
	}()
	client, clientErr := fs.ConnectMaterial(ctx, materials[0], fs.ConnectorOptions{Environment: environment, ConnectOptions: fs.ConnectOptions{Pool: h.Pool, Live: h.Live,
		Preparation: fs.SourceConnectConfig{Generation: h.Generation, LocalCapabilities: h.Hello.Offered, Requirements: fs.MaterialRequirements{ApplicationProfile: "transport", Connection: fs.RequiredGuarantees{LocalConsumerTls13Verification: true, Datagram: datagrams}},
			Carrier: factory, Hello: h.Hello, Limits: h.Limits, Admission: h.Admission[0], Root: h.Root, Owner: h.Owner(),
			Environment: h.Environment, Preauth: h.Preauth, Dependencies: h.Environment, Scope: h.Scope[0], RuntimeBytes: 8192, CarrierRuntimeBytes: 8192,
			AddressAttempts: 1, AttemptBudget: fs.CarrierAttemptBudget{PreauthBytes: 131072, WorkUnits: 128}, LiveIssuance: h.LiveIssuance}}})
	if clientErr != nil {
		cancel()
	}
	peer := <-accepted
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
		t.Fatalf("public WebTransport establishment: consumer=%v accepted=%v", clientErr, peer.err)
	}
	for role, session := range sessions {
		info := session.Info()
		registry := "native_webtransport_tls13"
		if role == 1 {
			registry = "accepted_webtransport"
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
		payload := []byte(fmt.Sprintf("original public WebTransport stream role %d", role))
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
