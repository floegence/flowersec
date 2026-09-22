package sessionv4

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	carrierws "github.com/floegence/flowersec/flowersec-go/v5/internal/carrierv4/websocket"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

// These tests join the real provider to the same isolated identity/admission
// fixtures as the initial core tests. They prove transport, Noise, READY,
// Stream ownership and accounting composition, not issuer or deployment trust.
func websocketCorePrepare(t *testing.T, fixtures *[2]initialCoreFixture) func(*cryptov4.HandshakeConfig, *InitialConfig) {
	t.Helper()
	return func(h *cryptov4.HandshakeConfig, initial *InitialConfig) {
		f := &fixtures[h.Role]
		config := resourcev4.Config{ProfileRevision: [32]byte{1}, AccountSlots: 8, ReservationSlots: 256, ReferenceSlots: 512,
			Limit: resourcev4.Vector{resourcev4.SDKBytes: 64 << 20, resourcev4.ProviderBytes: 2 << 20, resourcev4.Items: 4096,
				resourcev4.Tasks: 256, resourcev4.WorkSlots: 256, resourcev4.Timers: 64, resourcev4.Sessions: 1,
				resourcev4.Connections: 1, resourcev4.NativeHandles: 2, resourcev4.TLSHandshakes: 1}}
		var err error
		f.root, err = resourcev4.NewRoot(config)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(f.root.Close)
		f.limit = config.Limit
		f.scope = corePlanTestScope(t, f.root, config.Limit, 1)
		f.environment = f.reserve(t, resourcev4.Vector{resourcev4.SDKBytes: 1 << 20, resourcev4.Items: 1})
		charge, err := InitialCharge(initial.Limits)
		if err != nil {
			t.Fatal(err)
		}
		initial.Reservation.Release()
		initial.Reservation = f.reserve(t, charge)
		plan := corePlanUnitConfig(t, false)
		plan.Session, plan.Clock = h.Session, h.Clock
		plan.MessageCarrier, plan.MessageRuntimeBytes = true, 64<<10
		plan.Streams = factoryStreamConfig()
		f.plan, err = NewSessionCorePlan(plan, f.root, resourcev4.OwnerKey{ProfileRevision: [32]byte{1}, Environment: [16]byte{1}, Instance: [16]byte{3}, Backing: [16]byte{1}, Kind: 2}, f.environment, f.scope)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := f.plan.Abort(ctx); err != nil {
				t.Error(err)
			}
		})
	}
}

type observedWebSocketMessages struct {
	*carrierws.Messages
	mu     sync.Mutex
	frames [17]uint32
	closes atomic.Uint32
}

func (m *observedWebSocketMessages) WriteMessage(ctx context.Context, wire []byte) error {
	err := m.Messages.WriteMessage(ctx, wire)
	if err == nil && len(wire) >= protocolv4.EnvelopePrefixSize && int(wire[4]) < len(m.frames) {
		m.mu.Lock()
		m.frames[wire[4]]++
		m.mu.Unlock()
	}
	return err
}

func (m *observedWebSocketMessages) Close() error {
	m.closes.Add(1)
	return m.Messages.Close()
}

func websocketCoreCarrierPair(t *testing.T, fixtures *[2]initialCoreFixture) [2]*observedWebSocketMessages {
	t.Helper()
	options := carrierws.Options{MaxMessageBytes: 65536 + protocolv4.EnvelopePrefixSize, ReadBufferBytes: 256, WriteBufferBytes: 256,
		HandshakeBytes: 4096, MaxControlsPerSecond: 16, HandshakeTimeout: 5 * time.Second, MessageTimeout: 5 * time.Second,
		RuntimeBytes: 16384, ProviderRuntimeBytes: 65536, ProviderTasks: 4}
	charge, err := carrierws.Charge(options)
	if err != nil {
		t.Fatal(err)
	}
	reservations := [2]resourcev4.Reference{fixtures[0].reserve(t, charge), fixtures[1].reserve(t, charge)}
	type result struct {
		messages *carrierws.Messages
		err      error
	}
	upgraded := make(chan result, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		messages, err := carrierws.Upgrade(r.Context(), w, r, carrierws.UpgradeConfig{Subprotocol: carrierws.SubprotocolLocal, CheckPolicy: func(r *http.Request) error {
			host, _, err := net.SplitHostPort(r.Host)
			if err != nil || r.TLS != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() ||
				r.URL.Path != "/flowersec/v4/local" || r.Header.Get("Origin") != "http://"+r.Host || r.Header.Get("Authorization") != "Bearer local-test-application" {
				return resourcev4.ErrConfiguration
			}
			return nil
		}}, options, reservations[1], fixtures[1].environment)
		upgraded <- result{messages, err}
	}))
	t.Cleanup(server.Close)
	address := "ws" + strings.TrimPrefix(server.URL, "http") + "/flowersec/v4/local"
	remoteAddress, err := netip.ParseAddrPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	prepared, cancelPrepare := context.WithCancel(context.Background())
	left, err := carrierws.Dial(prepared, carrierws.DialConfig{URL: address, RemoteAddress: remoteAddress, Subprotocol: carrierws.SubprotocolLocal,
		Header: http.Header{"Origin": {server.URL}, "Authorization": {"Bearer local-test-application"}},
		CheckPolicy: func(u *url.URL, remote netip.AddrPort, header http.Header) error {
			if remote != remoteAddress || u.String() != address || u.Scheme != "ws" || net.ParseIP(u.Hostname()) == nil || !net.ParseIP(u.Hostname()).IsLoopback() || header.Get("Origin") != server.URL {
				return resourcev4.ErrConfiguration
			}
			return nil
		}}, options, reservations[0], fixtures[0].environment)
	cancelPrepare()
	if err != nil {
		t.Fatal(err)
	}
	right := <-upgraded
	if right.err != nil {
		t.Fatal(right.err)
	}
	providers := [2]*observedWebSocketMessages{{Messages: left}, {Messages: right.messages}}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		for _, provider := range providers {
			_ = provider.Messages.Close()
			if err := provider.WaitCleanup(ctx); err != nil {
				t.Error(err)
				continue
			}
			if err := provider.Retire(); err != nil {
				t.Error(err)
			}
		}
	})
	return providers
}

func TestWebSocketInitialCoreBothProfilesReadyAndFactoryDuplex(t *testing.T) {
	for _, profile := range []string{protocolv4.DHProfileX25519, protocolv4.DHProfileP256} {
		t.Run(profile, func(t *testing.T) {
			var fixtures [2]initialCoreFixture
			// Zero flights means every hello/admission/Noise/READY byte below
			// travels over the real provider from the start of the exchange.
			pair, configs := initialTestPairPrepared(t, profile, "messages", 0, websocketCorePrepare(t, &fixtures))
			providers := websocketCoreCarrierPair(t, &fixtures)
			for role := range 2 {
				pair[role].mu.Lock()
				unused := pair[role].messages
				pair[role].messages = providers[role]
				pair[role].mu.Unlock()
				_ = unused.Close()
			}
			wires := [][]byte{initialHelloProfile(t, initialFixture(t, "client_hello_fields"), "ClientHello", profile),
				initialHelloProfile(t, initialFixture(t, "server_hello_fields"), "ServerHello", profile), configs[0].FSB, configs[0].FSA}
			for phase, wire := range wires {
				frame, sender := initialFlight(uint8(phase))
				done := make(chan error, 1)
				go func() { done <- pair[1-sender].Receive(frame, initialExact(wire)) }()
				if _, err := pair[sender].Send(frame, initialCopy(wire)); err != nil {
					t.Fatal("initial send", phase, err)
				}
				if err := waitRuntime(t, done); err != nil {
					t.Fatal("initial receive", phase, err)
				}
			}
			results := startInitialCorePair(pair, configs, &fixtures)
			var cores [2]*SessionCore
			for role := range 2 {
				result := waitInitialCoreOutcome(t, results[role])
				if result.err != nil {
					t.Fatal(role, result.err)
				}
				cores[role] = result.core
				if err := result.core.Engine().ApplicationInputReady(0); err != nil {
					t.Fatal("READY gate", role, err)
				}
				pair[role].mu.Lock()
				ready := pair[role].readySent && pair[role].readyReceived && pair[role].transferred
				pair[role].mu.Unlock()
				if !ready {
					t.Fatal("initial owner did not transfer after both READY", role)
				}
				providers[role].mu.Lock()
				counts := providers[role].frames
				providers[role].mu.Unlock()
				if counts[protocolv4.FrameReady] != 1 || counts[protocolv4.FrameHandshake] == 0 || counts[protocolv4.FrameNegotiate] != 1 {
					t.Fatal("required flights did not traverse WebSocket", role, counts)
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			ended := make(chan error, 2)
			for role := range 2 {
				go func() { ended <- cores[role].Runtime().Run(ctx) }()
			}
			t.Cleanup(func() {
				for _, core := range cores {
					core.Close()
				}
			})
			streams := factoryOpenPair(t, cores, ctx)
			for source := range 2 {
				body := []byte("duplex over real WebSocket")
				if n, err := streams[source].WriteAll(ctx, body); err != nil || n != len(body) {
					t.Fatal("write", source, n, err)
				}
				var dst [64]byte
				read, err := streams[1-source].ReadInto(ctx, dst[:])
				if err != nil || string(dst[:read.Progress.Filled]) != string(body) {
					t.Fatal("read", source, read, err)
				}
			}
			for _, stream := range streams {
				_ = stream.Cancel()
				if err := stream.Release(); err != nil {
					t.Fatal(err)
				}
			}
			for _, core := range cores {
				core.Close()
			}
			for range 2 {
				_ = waitRuntime(t, ended)
			}
			for role, core := range cores {
				if err := pair[role].WaitCleanup(ctx); err != nil {
					t.Fatal(role, err)
				}
				if err := core.WaitCleanup(ctx); err != nil {
					t.Fatal(role, err)
				}
				if err := core.Retire(); err != nil {
					t.Fatal(role, err)
				}
				if providers[role].closes.Load() != 1 {
					t.Fatal("provider original Close count", role, providers[role].closes.Load())
				}
				if err := providers[role].WaitCleanup(ctx); err != nil {
					t.Fatal(role, err)
				}
				before := fixtures[role].root.Snapshot()
				if before.Reservations != 2 || before.Charged[resourcev4.ProviderBytes] == 0 || before.Charged[resourcev4.Connections] != 1 {
					t.Fatal("provider charge escaped before retirement", role, before)
				}
				if err := providers[role].Retire(); err != nil {
					t.Fatal(role, err)
				}
				after := fixtures[role].root.Snapshot()
				if after.Reservations != 1 || after.References != 1 || after.Charged[resourcev4.ProviderBytes] != 0 || after.Charged[resourcev4.Connections] != 0 {
					t.Fatal("retained beyond original Environment", role, after)
				}
				fixtures[role].environment.Release()
				fixtures[role].root.Close()
				if snapshot := fixtures[role].root.Snapshot(); !snapshot.CleanupComplete || snapshot.Reservations != 0 || snapshot.References != 0 {
					t.Fatal("root cleanup incomplete", role, snapshot)
				}
			}
		})
	}
}
