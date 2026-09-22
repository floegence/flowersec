package connectv4

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/carrierv4/websocket"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/sessionv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
	ws "github.com/gorilla/websocket"
)

type websocketServeFixture struct {
	root   *resourcev4.Root
	shared resourcev4.Reference
	clock  *timev4.Clock
	owner  resourcev4.OwnerKey
	next   byte
}

func (f *websocketServeFixture) reserve(t *testing.T, c resourcev4.Vector) resourcev4.Reference {
	t.Helper()
	f.next++
	owner := f.owner
	owner.Backing[0] = f.next
	r, err := f.root.Reserve(owner, c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Release)
	return r
}
func websocketServeTestOwner(t *testing.T) *websocketServeFixture {
	t.Helper()
	f := &websocketServeFixture{next: 1, owner: resourcev4.OwnerKey{ProfileRevision: [32]byte{1}, Environment: [16]byte{1}, Instance: [16]byte{1}, Backing: [16]byte{1}, Kind: 1}}
	limit := resourcev4.Vector{}
	for i := range limit {
		limit[i] = 1 << 28
	}
	var err error
	f.root, err = resourcev4.NewRoot(resourcev4.Config{ProfileRevision: [32]byte{1}, Limit: limit, AccountSlots: 8, ReservationSlots: 64, ReferenceSlots: 128})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.root.Close)
	f.shared = f.reserve(t, resourcev4.Vector{resourcev4.SDKBytes: 1 << 20, resourcev4.Items: 1})
	f.clock, err = timev4.NewClock(timev4.Profile{Rate: timev4.Rate{Denominator: 1}, MaxWidthMS: 1000, MaxAgeMS: 10000, MaxRoundTripMS: 1000}, func() (timev4.Tick, error) { return timev4.Tick{Incarnation: [16]byte{1}}, nil })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.clock.Close)
	mark, err := f.clock.Monotonic()
	if err != nil {
		t.Fatal(err)
	}
	if err := f.clock.InstallTrusted(mark, timev4.Interval{LowerMS: 1000, UpperMS: 1100}); err != nil {
		t.Fatal(err)
	}
	return f
}
func (f *websocketServeFixture) accepted(t *testing.T) WebSocketAcceptedConfig {
	t.Helper()
	deadline, err := timev4.NewDeadline(f.clock, 10000)
	if err != nil {
		t.Fatal(err)
	}
	owner := f.owner
	owner.Backing[0] = 60
	return WebSocketAcceptedConfig{Root: f.root, Owner: owner, Environment: f.shared, RuntimeBytes: 8192,
		Options: websocket.Options{MaxMessageBytes: 264, ReadBufferBytes: 125, WriteBufferBytes: 125, HandshakeBytes: 4096, MaxControlsPerSecond: 8, HandshakeTimeout: time.Second, MessageTimeout: time.Second, RuntimeBytes: 16384, ProviderRuntimeBytes: 65536, ProviderTasks: 4},
		Upgrade: websocket.UpgradeConfig{Subprotocol: websocket.SubprotocolLocal, CheckPolicy: func(*http.Request) error { return nil }, CheckAcceptedRoute: func(protocolv4.AcceptedWebSocketEndpoint, *protocolv4.SignedMap, uint64, protocolv4.HelloPolicy) error {
			return nil
		}},
		Entrance: sessionv4.AcceptedEntranceConfig{Initial: sessionv4.InitialConfig{Role: protocolv4.ServerToClient, Profile: protocolv4.DHProfileX25519, ActivationSourceProfile: "preauthorized_pool", Limits: sessionv4.InitialLimits{MaxFrame: 256, Nodes: 4096}, Deadline: deadline}, RuntimeBytes: 8192, InitialRuntimeBytes: 8192, CarrierRuntimeBytes: 8192}}
}

func TestWebSocketAcceptedFactoryRetainsActualHTTPCallback(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		t.Run(map[bool]string{false: "upgrade", true: "cancel_during_policy"}[cancelled], func(t *testing.T) {
			f := websocketServeTestOwner(t)
			c := f.accepted(t)
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			defer once.Do(func() { close(release) })
			c.Upgrade.CheckPolicy = func(*http.Request) error { close(entered); <-release; return nil }
			cost, err := WebSocketAcceptedCharge(c)
			if err != nil {
				t.Fatal(err)
			}
			reservation := f.reserve(t, cost)
			before := f.root.Snapshot().Reservations
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			factories := make(chan *WebSocketAcceptedFactory, 1)
			finished := make(chan error, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				factory, err := NewWebSocketAcceptedFactory(w, r, c, reservation)
				if err != nil {
					finished <- err
					return
				}
				factories <- factory
				entrance, err := factory.PrepareAccepted(ctx, c.Entrance.Initial.Deadline)
				if entrance != nil {
					entrance.Close()
					_ = entrance.WaitCleanup(context.Background())
					_ = entrance.Retire()
				}
				factory.Close()
				_ = factory.WaitCleanup(context.Background())
				_ = factory.Retire()
				finished <- err
			}))
			defer server.Close()
			dialDone := make(chan error, 1)
			go func() {
				d := ws.Dialer{Subprotocols: []string{websocket.SubprotocolLocal}, HandshakeTimeout: 2 * time.Second}
				conn, _, err := d.Dial("ws"+strings.TrimPrefix(server.URL, "http")+"/flowersec/v4/local", nil)
				if conn != nil {
					_ = conn.Close()
				}
				dialDone <- err
			}()
			factory := <-factories
			<-entered
			if cancelled {
				cancel()
				factory.Close()
				wait, stop := context.WithCancel(context.Background())
				stop()
				if err := factory.WaitCleanup(wait); !errors.Is(err, context.Canceled) {
					t.Fatal("policy tail returned HTTP writer", err)
				}
				if err := factory.Retire(); !errors.Is(err, cryptov4.ErrCapacity) {
					t.Fatal(err)
				}
			}
			once.Do(func() { close(release) })
			if err := <-finished; (err != nil) != cancelled {
				t.Fatal(err)
			}
			if err := <-dialDone; !cancelled && err != nil {
				t.Fatal(err)
			}
			if f.root.Snapshot().Reservations != before-1 {
				t.Fatal("original factory/provider leaked")
			}
		})
	}
}

func TestWebSocketRouteDrainKeepsBorrowedHostAndCallback(t *testing.T) {
	f := websocketServeTestOwner(t)
	eConfig := sessionv4.EnvironmentConfig{Positions: 2, RuntimeBytes: 8192}
	eCharge, err := sessionv4.EnvironmentCharge(eConfig)
	if err != nil {
		t.Fatal(err)
	}
	e, err := sessionv4.NewEnvironment(eConfig, f.reserve(t, eCharge), f.shared)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { e.Close(); _ = e.WaitCleanup(context.Background()); _ = e.Retire() }()
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	cost, err := WebSocketRouteCharge(8192)
	if err != nil {
		t.Fatal(err)
	}
	route, err := NewWebSocketRoute(func() (WebSocketIngressPlan, error) {
		close(entered)
		<-release
		return WebSocketIngressPlan{}, cryptov4.ErrClosed
	}, func(*sessionv4.EnvironmentSession) { t.Error("unpublished Session delivered") }, 8192, f.reserve(t, cost), f.shared)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { route.Close(); _ = route.WaitCleanup(context.Background()); _ = route.Retire() }()
	config := sessionv4.ServeConfig{Positions: 1, RuntimeBytes: 8192, DrainTimeoutMS: 1000, Clock: f.clock}
	cost, err = sessionv4.ServeCharge(config)
	if err != nil {
		t.Fatal(err)
	}
	reservation := f.reserve(t, cost)
	group, err := route.Serve(context.Background(), e, config, reservation)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := route.Serve(context.Background(), e, config, reservation); !errors.Is(err, cryptov4.ErrTransition) {
		t.Fatal("competing route claim", err)
	}
	mux := http.NewServeMux()
	mux.Handle("/flowersec", route)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	server := httptest.NewServer(mux)
	defer server.Close()
	first := make(chan error, 1)
	go func() {
		response, err := http.Get(server.URL + "/flowersec")
		if response != nil {
			response.Body.Close()
		}
		first <- err
	}()
	<-entered
	op, err := group.Drain(0, 0)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result, err := op.Wait(ctx)
	if err != nil || result.Outcome != sessionv4.Drained {
		t.Fatal(result, err)
	}
	if group.CleanupStatus() {
		t.Fatal("held HTTP callback forgotten")
	}
	for path, want := range map[string]int{"/flowersec": http.StatusServiceUnavailable, "/health": http.StatusNoContent} {
		response, err := http.Get(server.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != want {
			t.Fatal(path, response.StatusCode)
		}
	}
	once.Do(func() { close(release) })
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	if err := route.WaitCleanup(ctx); err != nil {
		t.Fatal(err)
	}
	if err := f.shared.Check(); err != nil {
		t.Fatal("borrowed dependencies closed", err)
	}
}
