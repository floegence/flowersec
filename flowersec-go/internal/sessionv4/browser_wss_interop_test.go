package sessionv4

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	carrierws "github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/websocket"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

type browserInteropDH struct{ key *ecdh.PrivateKey }

func (k browserInteropDH) PublicKey() []byte { return k.key.PublicKey().Bytes() }
func (k browserInteropDH) SharedSecret(wire []byte) ([]byte, error) {
	peer, err := k.key.Curve().NewPublicKey(wire)
	if err != nil {
		return nil, err
	}
	return k.key.ECDH(peer)
}

// Playwright starts this test binary explicitly. The fixture trust/once policy
// is not a production Serve deployment: this test qualifies cross-language
// canonical bindings, both crypto profiles, actual WSS I/O and core cleanup.
// Browser durable consumption is exercised by its original IndexedDB adapter.
func TestBrowserWSSInteropPeer(t *testing.T) {
	if os.Getenv("FLOWERSEC_BROWSER_WSS_INTEROP") != "1" {
		t.Skip("requires the Chromium interop runner")
	}
	input := json.NewDecoder(os.Stdin)
	var setup struct {
		Certificate, Key []byte
		Origin, Profile  string
	}
	if err := input.Decode(&setup); err != nil {
		t.Fatal(err)
	}
	emit := func(value any) {
		wire, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Printf("FLOWERSEC_INTEROP %s\n", wire)
	}
	certificate, err := tls.X509KeyPair(setup.Certificate, setup.Key)
	if err != nil {
		t.Fatal(err)
	}
	var f initialCoreFixture
	var observed *observedWebSocketMessages
	ready := make(chan struct{})
	accepted := make(chan *carrierws.Messages, 1)
	failures := make(chan error, 1)
	options := carrierws.Options{MaxMessageBytes: 65544, ReadBufferBytes: 256, WriteBufferBytes: 256,
		HandshakeBytes: 8192, MaxControlsPerSecond: 16, HandshakeTimeout: 5 * time.Second, MessageTimeout: 5 * time.Second,
		RuntimeBytes: 16384, ProviderRuntimeBytes: 65536, ProviderTasks: 4}
	var providerReservation resourcev4.Reference
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-ready
		messages, err := carrierws.Upgrade(r.Context(), w, r, carrierws.UpgradeConfig{
			Subprotocol: carrierws.SubprotocolDirect,
			CheckPolicy: func(r *http.Request) error {
				if r.URL.RequestURI() != "/flowersec/v4/direct" || r.Header.Get("Origin") != setup.Origin || r.TLS == nil || r.TLS.Version != tls.VersionTLS13 {
					return resourcev4.ErrConfiguration
				}
				return nil
			},
		}, options, providerReservation, f.environment)
		if err != nil {
			failures <- err
			return
		}
		accepted <- messages
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, NextProtos: []string{"http/1.1"}}
	server.StartTLS()
	t.Cleanup(server.Close)
	emit(map[string]any{"event": "listening", "port": server.Listener.Addr().(*net.TCPAddr).Port})
	var material struct {
		Artifact, ClientCertificate, ServerCertificate, Activation []byte
		TimeOrigin                                                 uint64
	}
	if err := input.Decode(&material); err != nil {
		t.Fatal(err)
	}
	limit := resourcev4.Vector{}
	for i := range limit {
		limit[i] = 1 << 28
	}
	f.root, err = resourcev4.NewRoot(resourcev4.Config{ProfileRevision: [32]byte{1}, Limit: limit,
		AccountSlots: 32, ReservationSlots: 256, ReferenceSlots: 512})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.root.Close)
	t.Cleanup(func() {
		remaining := f.root.Snapshot().Reservations
		if remaining != 0 {
			t.Errorf("original Go owners leaked: %d reservations", remaining)
		}
		var frames [17]uint32
		if observed != nil {
			observed.mu.Lock()
			frames = observed.frames
			observed.mu.Unlock()
		}
		emit(map[string]any{"event": "cleanup", "reservations": remaining, "frames": frames})
	})
	f.scope = corePlanTestScope(t, f.root, limit, 1)
	f.environment = f.reserve(t, resourcev4.Vector{resourcev4.SDKBytes: 1 << 20, resourcev4.Items: 1})
	charge, err := carrierws.Charge(options)
	if err != nil {
		t.Fatal(err)
	}
	providerReservation = f.reserve(t, charge)
	close(ready)
	start := time.Now()
	clock, err := timev4.NewClock(timev4.Profile{Rate: timev4.Rate{Denominator: 1}, MaxWidthMS: 100, MaxAgeMS: 1000000, MaxRoundTripMS: 100},
		func() (timev4.Tick, error) {
			return timev4.Tick{Milliseconds: uint64(time.Since(start).Milliseconds()), Incarnation: [16]byte{1}}, nil
		})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(clock.Close)
	mark, err := clock.Monotonic()
	if err != nil {
		t.Fatal(err)
	}
	if err := clock.InstallTrusted(mark, timev4.Interval{LowerMS: material.TimeOrigin + 1000, UpperMS: material.TimeOrigin + 1000}); err != nil {
		t.Fatal(err)
	}
	verify := func(schema string, wire []byte, seed byte, context protocolv4.DecodeContext) *protocolv4.SignedMap {
		codec, err := protocolv4.NewSignedMapCodec(schema, 65536, 16384)
		if err != nil {
			t.Fatal(schema, err)
		}
		signed, err := codec.Verify(wire, [32]byte(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32)).Public().(ed25519.PublicKey)), context)
		if err != nil {
			t.Fatal(schema, err)
		}
		t.Cleanup(signed.Release)
		return signed
	}
	artifact := verify("Artifact", material.Artifact, 12, protocolv4.DecodeContext{})
	client := verify("IdentityCertificate", material.ClientCertificate, 11, protocolv4.DecodeContext{})
	peer := verify("IdentityCertificate", material.ServerCertificate, 11, protocolv4.DecodeContext{})
	proof := verify("ActivationAuthorization", material.Activation, 13, protocolv4.DecodeContext{Selectors: map[string]string{"activation_source_profile": "preauthorized_pool"}})
	selection, err := protocolv4.NewPoolSelectionWorkspace(65536, 65536)
	if err != nil {
		t.Fatal(err)
	}
	activation, err := selection.BindActivation(artifact, proof, "preauthorized_pool", 0)
	if err != nil {
		t.Fatal("activation", err)
	}
	if err := activation.MatchCertificates(client, peer); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var provider *carrierws.Messages
	select {
	case provider = <-accepted:
	case err := <-failures:
		t.Fatal("upgrade", err)
	case <-ctx.Done():
		t.Fatal("waiting for Chromium", ctx.Err())
	}
	observed = &observedWebSocketMessages{Messages: provider}
	t.Cleanup(func() {
		_ = provider.Close()
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if err := provider.WaitCleanup(cleanup); err != nil {
			t.Error(err)
		}
		if err := provider.Retire(); err != nil {
			t.Error(err)
		}
	})
	deadline, err := timev4.NewDeadline(clock, material.TimeOrigin+10000)
	if err != nil {
		t.Fatal(err)
	}
	initial := InitialConfig{Role: protocolv4.ServerToClient, Profile: setup.Profile, ActivationSourceProfile: "preauthorized_pool",
		Limits: InitialLimits{MaxFrame: 65536, Nodes: 16384}, Deadline: deadline, Authorization: testAuthorization{}}
	charge, err = InitialCharge(initial.Limits)
	if err != nil {
		t.Fatal(err)
	}
	initial.Reservation = f.reserve(t, charge)
	exchange, err := NewInitialMessages(ctx, initial, observed)
	if err != nil {
		t.Fatal(err)
	}
	cleanupInitial(t, exchange)
	helloWorkspace, err := protocolv4.NewHelloWorkspace(protocolv4.HelloLimits{HelloBytes: 8192, HelloNodes: 4096, RouteBytes: 65536, ContextBytes: 16384})
	if err != nil {
		t.Fatal(err)
	}
	attempt, _ := proof.Field("attempt_id").ByteString()
	hello, err := exchange.NegotiateServer(InitialHello{Artifact: artifact, Index: 0, Attempt: [16]byte(attempt), Workspace: helloWorkspace,
		Policy: protocolv4.HelloPolicy{BindingMode: 1}, BindingModes: 2})
	if err != nil {
		t.Fatal("HELLO", err)
	}
	var fsb *protocolv4.SignedMap
	var admission [32]byte
	if err := exchange.Receive(protocolv4.FrameAdmission, func(wire []byte) error {
		codec, err := protocolv4.NewSignedMapCodec("FSB4", 65536, 16384)
		if err != nil {
			return err
		}
		fsb, err = codec.Verify(wire, [32]byte(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{14}, 32)).Public().(ed25519.PublicKey)), protocolv4.DecodeContext{Selectors: map[string]string{"activation_source_profile": "preauthorized_pool"}})
		if err != nil {
			return err
		}
		t.Cleanup(fsb.Release)
		admission, err = hello.MatchFSB(activation, fsb, client)
		return err
	}); err != nil {
		t.Fatal("FSB", err)
	}
	serverIdentity, err := peer.Digest("certificate_digest")
	if err != nil {
		t.Fatal(err)
	}
	codec, err := protocolv4.NewSignedMapCodec("FSA4", 65536, 16384)
	if err != nil {
		t.Fatal(err)
	}
	signer := bootstrapSigner{ed25519.NewKeyFromSeed(bytes.Repeat([]byte{15}, 32))}
	fsa, _, err := exchange.SendAdmissionResponse(codec, peer, protocolv4.AdmissionResponse{Admitted: true, ServerEpoch: 1,
		ReservationKey: [32]byte{27}, AdmissionBinding: admission, ServerIdentityDigest: serverIdentity}, signer, deadline.Check)
	if err != nil {
		t.Fatal("FSA", err)
	}
	t.Cleanup(fsa.Release)
	handshakeMaterial, err := hello.BindHandshakeMaterial(artifact, activation, client, peer, fsb, fsa)
	if err != nil {
		t.Fatal("bound handshake material", err)
	}
	t.Cleanup(handshakeMaterial.Close)
	curve := ecdh.X25519()
	if setup.Profile == protocolv4.DHProfileP256 {
		curve = ecdh.P256()
	}
	key, err := curve.NewPrivateKey(bytes.Repeat([]byte{17}, 32))
	if err != nil {
		t.Fatal(err)
	}
	handshake, err := cryptov4.AdmissionHandshakeConfig(handshakeMaterial, cryptov4.AdmissionKeyConfig{Role: protocolv4.ServerToClient,
		LocalDH: browserInteropDH{key}, Signer: signer, Deadline: deadline, Clock: clock, SessionDeadlineMS: material.TimeOrigin + 30000,
		Authorization: initial.Authorization}, make([]byte, 65536), make([]byte, 65536))
	if err != nil {
		t.Fatal("handshake configuration", err)
	}
	defer clear(handshake.PSK[:])
	plan := corePlanUnitConfig(t, false)
	plan.Session, plan.Clock = handshake.Session, clock
	plan.MessageCarrier, plan.MessageRuntimeBytes, plan.Streams = true, 65536, factoryStreamConfig()
	plan.Maintenance = cryptov4.MaintenanceReserve{Calls: 64, Blocks: 8192, Bytes: 1048576}
	f.plan, err = NewSessionCorePlan(plan, f.root, resourcev4.OwnerKey{ProfileRevision: [32]byte{1}, Environment: [16]byte{1}, Instance: [16]byte{3}, Backing: [16]byte{1}, Kind: 2}, f.environment, f.scope)
	if err != nil {
		t.Fatal("Session plan", err)
	}
	cleanupCorePlanUnit(t, f.plan)
	core, err := exchange.AuthenticateCore(handshake, f.plan)
	if err != nil {
		observed.mu.Lock()
		frames := observed.frames
		observed.mu.Unlock()
		exchange.mu.Lock()
		phase, sent, received := exchange.phase, exchange.readySent, exchange.readyReceived
		exchange.mu.Unlock()
		t.Fatalf("Noise/READY: %v; phase=%d ready=%t/%t sent_frames=%v", err, phase, sent, received, frames)
	}
	emit(map[string]any{"event": "authenticated", "profile": setup.Profile})
	running := make(chan error, 1)
	go func() { running <- core.Runtime().Run(ctx) }()
	t.Cleanup(func() {
		core.Close()
		select {
		case <-running:
		case <-time.After(5 * time.Second):
			t.Error("Go runtime did not terminate")
		}
	})
	for round := 0; round < 2; round++ {
		handle, err := core.Admission().NextPending(ctx)
		if err != nil {
			t.Fatal("OPEN", round, err, core.Runtime().Err())
		}
		stream, err := core.AcceptStream(ctx, handle)
		if err != nil {
			t.Fatal("accept", round, err)
		}
		t.Cleanup(func() {
			_ = stream.Cancel()
			if err := stream.Release(); err != nil {
				t.Error(err)
			}
		})
		var payload [64]byte
		read, err := stream.ReadInto(ctx, payload[:])
		if err != nil || read.Progress.Filled == 0 {
			t.Fatal("read", round, read, err)
		}
		if n, err := stream.WriteAll(ctx, payload[:read.Progress.Filled]); err != nil || uint64(n) != read.Progress.Filled {
			t.Fatal("echo", round, n, err)
		}
		if err := stream.Finish(ctx); err != nil {
			t.Fatal("finish", round, err)
		}
	}
	observed.mu.Lock()
	frames := observed.frames
	observed.mu.Unlock()
	emit(map[string]any{"event": "served", "frames": frames, "streams": 2})
	// The runner ends stdin only after checking the browser's cleanup facts.
	var stop any
	if err := input.Decode(&stop); err == nil {
		t.Fatal("unexpected second material")
	}
}
