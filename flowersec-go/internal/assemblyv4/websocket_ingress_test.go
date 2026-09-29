package assemblyv4

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/websocket"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

func newTestIngress(t *testing.T, f *webSocketFactoryFixture, w http.ResponseWriter, r *http.Request, policy func(*http.Request) error, server ...*WebSocketServer) *WebSocketIngress {
	t.Helper()
	c := WebSocketIngressConfig{Root: f.root, Owner: admissionResourceKey(f.factory.c.Owner, 500), Environment: f.request.Config.Environment,
		Dependencies: f.request.Config.Environment, Accounts: []resourcev4.Account{f.request.Scope.Tenant}, RuntimeBytes: 8192, Options: f.factory.c.Options,
		Entrance: sessionv4.AcceptedEntranceConfig{RuntimeBytes: 8192, InitialRuntimeBytes: 8192, CarrierRuntimeBytes: 8192,
			Initial: sessionv4.InitialConfig{Role: protocolv4.ServerToClient, Profile: protocolv4.DHProfileX25519,
				ActivationSourceProfile: "preauthorized_pool", Deadline: f.request.Config.Deadline, Limits: sessionv4.InitialLimits{MaxFrame: 4096, Nodes: 4096}}},
		Upgrade: websocket.UpgradeConfig{Subprotocol: websocket.SubprotocolDirect, CheckPolicy: policy,
			// These tests stop before ClientHello. Never admit a synthetic route.
			CheckAcceptedRoute: func(protocolv4.AcceptedWebSocketEndpoint, *protocolv4.SignedMap, uint64, protocolv4.HelloPolicy) error {
				return protocolv4.CBORFailure("accepted_listener_binding")
			}}}
	if len(server) != 0 {
		c.Server, c.Upgrade = server[0], websocket.UpgradeConfig{}
	}
	charge, err := WebSocketIngressCharge(c)
	if err != nil {
		t.Fatal(err)
	}
	reservation, err := f.root.Reserve(c.Owner, charge, c.Accounts...)
	if err != nil {
		t.Fatal(err)
	}
	defer reservation.Release()
	ingress, err := NewWebSocketIngress(w, r, c, reservation)
	if err != nil {
		t.Fatal(err)
	}
	return ingress
}

func TestWebSocketIngressNativeUpgradeRetainsPolicyUntilPhysicalRetirement(t *testing.T) {
	type result struct {
		factory  *WebSocketIngress
		entrance *sessionv4.AcceptedEntrance
		err      error
	}
	accepted := make(chan result, 1)
	f := webSocketFactoryTest(t, true, func(f *webSocketFactoryFixture, w http.ResponseWriter, r *http.Request) {
		factory := newTestIngress(t, f, w, r, func(request *http.Request) error {
			if request != r || request.TLS == nil || !request.TLS.HandshakeComplete {
				return websocket.ErrEndpoint
			}
			return nil
		})
		entrance, err := factory.PrepareAccepted(r.Context(), f.request.Config.Deadline)
		factory.FinishHTTP()
		accepted <- result{factory, entrance, err}
	})
	prepared, err := f.factory.PrepareCarrier(context.Background(), f.request)
	if err != nil {
		t.Fatal(err)
	}
	cleanupPreparedTest(t, prepared)
	r := <-accepted
	if r.err != nil || r.entrance == nil || !r.factory.Hijacked() {
		t.Fatal("native entrance was not created", r.err)
	}
	if err := r.factory.reservation.Check(); err != nil {
		t.Fatal("HTTP return released live policy backing", err)
	}
	if again, err := r.factory.PrepareAccepted(context.Background(), f.request.Config.Deadline); again != nil || err == nil {
		t.Fatal("physical ingress reused")
	}
	r.entrance.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := r.entrance.WaitCleanup(ctx); err != nil {
		t.Fatal(err)
	}
	if err := r.factory.reservation.Check(); err != nil {
		t.Fatal("physical cleanup refunded unretired policy", err)
	}
	if err := r.entrance.Retire(); err != nil {
		t.Fatal(err)
	}
	if r.factory.reservation.Check() == nil {
		t.Fatal("retired entrance retained factory backing")
	}
}

func TestWebSocketIngressFinishHTTPJoinsOriginalUpgradeBorrow(t *testing.T) {
	f := webSocketFactoryTest(t, false)
	entered, release := make(chan struct{}), make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	request := httptest.NewRequest(http.MethodGet, "https://127.0.0.1/flowersec/v4/direct", nil)
	factory := newTestIngress(t, f, httptest.NewRecorder(), request, func(*http.Request) error {
		close(entered)
		<-release
		return context.Canceled
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, err := factory.PrepareAccepted(ctx, f.request.Config.Deadline)
		result <- err
	}()
	<-entered
	cancel()
	finished := make(chan struct{})
	go func() { factory.FinishHTTP(); close(finished) }()
	select {
	case <-finished:
		t.Fatal("HTTP writer returned while original policy still used request")
	case <-time.After(10 * time.Millisecond):
	}
	if err := factory.reservation.Check(); err != nil {
		t.Fatal("actual callback tail refunded", err)
	}
	close(release)
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	<-finished
	if factory.Hijacked() || factory.reservation.Check() == nil {
		t.Fatal("failed original upgrade retained ownership or reported hijack")
	}
}

func TestWebSocketIngressUnstartedFinishFencesLateProvider(t *testing.T) {
	f := webSocketFactoryTest(t, false)
	called := false
	factory := newTestIngress(t, f, httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "https://example.test/", nil), func(*http.Request) error { called = true; return nil })
	factory.FinishHTTP()
	if entrance, err := factory.PrepareAccepted(context.Background(), f.request.Config.Deadline); entrance != nil || err == nil || called {
		t.Fatal("late Environment work accessed returned HTTP request")
	}
	if factory.reservation.Check() == nil {
		t.Fatal("unused factory was not released")
	}
}
