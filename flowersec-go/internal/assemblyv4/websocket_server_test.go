package assemblyv4

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

func nativeWebSocketServerTest(t *testing.T, pin bool, handler http.Handler) (*webSocketFactoryFixture, *WebSocketServer) {
	t.Helper()
	f := webSocketFactoryTest(t, pin)
	f.server.Close()
	listener, err := net.ListenTCP("tcp", net.TCPAddrFromAddrPort(f.factory.c.RemoteAddress))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	config := WebSocketServerConfig{Root: f.root, Clock: f.factory.c.Clock,
		Route: f.factory.document.Bytes(), Certificate: f.server.TLS.Certificates[0], Roots: f.factory.c.Roots, Handler: handler,
		Connections: 2, HeaderBytes: 8192, HeaderTimeout: time.Second, IdleTimeout: time.Second, RuntimeBytes: 65536, ProviderBytesPerConnection: 65536}
	charge, err := WebSocketServerCharge(config)
	if err != nil {
		t.Fatal(err)
	}
	reservation, err := f.root.Reserve(admissionResourceKey(f.factory.c.Owner, 600), charge)
	if err != nil {
		t.Fatal(err)
	}
	defer reservation.Release()
	server, err := NewWebSocketServer(config, reservation, f.request.Config.Environment)
	if err != nil {
		t.Fatal(err)
	}
	ended := make(chan error, 1)
	go func() { ended <- server.Serve(listener) }()
	t.Cleanup(func() {
		server.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := server.WaitCleanup(ctx); err != nil {
			t.Error(err)
		}
		select {
		case err := <-ended:
			if err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
				t.Error(err)
			}
		case <-ctx.Done():
			t.Error("native Serve did not exit")
		}
	})
	// The policy test may finish without making a network request. Wait for
	// Serve to own the listener so cleanup cannot race its initial admission.
	startup := time.NewTimer(time.Second)
	defer startup.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		server.mu.Lock()
		running := server.running
		server.mu.Unlock()
		if running {
			break
		}
		select {
		case <-startup.C:
			t.Fatal("native Serve did not start")
		case <-tick.C:
		}
	}
	return f, server
}

func TestWebSocketServerOwnsNativeTLSAndUpgradedSocket(t *testing.T) {
	for _, pin := range []bool{false, true} {
		t.Run(map[bool]string{false: "ca", true: "pin"}[pin], func(t *testing.T) {
			type result struct {
				entrance *sessionv4.AcceptedEntrance
				err      error
			}
			accepted := make(chan result, 1)
			var f *webSocketFactoryFixture
			var server *WebSocketServer
			f, server = nativeWebSocketServerTest(t, pin, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				factory := newTestIngress(t, f, w, r, nil, server)
				entrance, err := factory.PrepareAccepted(r.Context(), f.request.Config.Deadline)
				factory.FinishHTTP()
				accepted <- result{entrance, err}
			}))
			prepared, err := f.factory.PrepareCarrier(context.Background(), f.request)
			if err != nil {
				t.Fatal(err)
			}
			cleanupPreparedTest(t, prepared)
			r := <-accepted
			if r.err != nil {
				t.Fatal(r.err)
			}
			server.Close()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			pending, stop := context.WithTimeout(ctx, 10*time.Millisecond)
			if err := server.WaitCleanup(pending); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("server forgot unretired policy owner", err)
			}
			stop()
			r.entrance.Close()
			if err := r.entrance.WaitCleanup(ctx); err != nil {
				t.Fatal(err)
			}
			if err := r.entrance.Retire(); err != nil {
				t.Fatal(err)
			}
			if err := server.WaitCleanup(ctx); err != nil {
				t.Fatal("server retained retired native ownership", err)
			}
		})
	}
}

func TestWebSocketServerRetainsOriginalHTTPHandlerTail(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	f, server := nativeWebSocketServerTest(t, false, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-release
	}))
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	result := make(chan error, 1)
	go func() {
		_, err := f.factory.PrepareCarrier(context.Background(), f.request)
		result <- err
	}()
	<-entered
	server.Close()
	wait, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	if err := server.WaitCleanup(wait); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("blocked HTTP callback refunded", err)
	}
	cancel()
	if err := server.reservation.Check(); err != nil {
		t.Fatal("original handler lost server backing", err)
	}
	close(release)
	ctx, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if err := server.WaitCleanup(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err == nil {
		t.Fatal("failed original HTTP exchange returned a carrier")
	}
}

func TestWebSocketServerPolicyCannotAuthorizeAnotherHTTPServer(t *testing.T) {
	_, server := nativeWebSocketServerTest(t, true, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	request := httptest.NewRequest(http.MethodGet, "https://"+server.Address()+"/flowersec/v4/direct", nil)
	if err := server.UpgradePolicy().CheckPolicy(request); err == nil {
		t.Fatal("detached HTTP observations substituted for original TLS owner")
	}
}
