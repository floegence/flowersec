package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/endpoint/serve"
	"github.com/floegence/flowersec/flowersec-go/proxy"
	"github.com/gorilla/websocket"
)

type fakeRoute struct {
	srv *serve.Server
}

func (c *fakeRoute) OpenStream(ctx context.Context, kind string) (io.ReadWriteCloser, error) {
	a, b := net.Pipe()
	go c.srv.HandleStream(ctx, kind, b)
	return a, nil
}

func TestGatewayHTTPProxiesToServerEndpoint(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/hello" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "ok")
	}))
	defer up.Close()

	streamSrv, err := serve.New(serve.Options{})
	if err != nil {
		t.Fatalf("serve.New: %v", err)
	}
	if err := proxy.Register(streamSrv, proxy.Options{
		Upstream:       up.URL,
		UpstreamOrigin: "http://127.0.0.1:5173",
	}); err != nil {
		t.Fatalf("proxy.Register: %v", err)
	}

	bridge := mustBridge(t, proxy.BridgeOptions{})
	gw := newGateway(map[string]streamOpener{
		"127.0.0.1": &fakeRoute{srv: streamSrv},
	}, bridge, browserPolicy{allowedOrigins: []string{"https://gateway.example.com"}}, nil)
	s := httptest.NewServer(gw)
	defer s.Close()

	req, _ := http.NewRequest(http.MethodGet, s.URL+"/hello", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if string(b) != "ok" {
		t.Fatalf("unexpected body: %q", string(b))
	}
}

func TestGatewayHTTPRejectsCrossSitePOSTBeforeOpeningRoute(t *testing.T) {
	called := false
	bridge := mustBridge(t, proxy.BridgeOptions{})
	gw := newGateway(map[string]streamOpener{
		"127.0.0.1": openerFunc(func(ctx context.Context, kind string) (io.ReadWriteCloser, error) {
			called = true
			return noopReadWriteCloser{}, nil
		}),
	}, bridge, browserPolicy{allowedOrigins: []string{"https://gateway.example.com"}}, nil)
	s := httptest.NewServer(gw)
	defer s.Close()

	req, _ := http.NewRequest(http.MethodPost, s.URL+"/submit", strings.NewReader("x=1"))
	req.Header.Set("Origin", "https://evil.example.com")
	req.Header.Set("Cookie", "sess=1")
	req.Header.Set("Sec-Fetch-Site", "cross-site")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status want=%d got=%d", http.StatusForbidden, resp.StatusCode)
	}
	if called {
		t.Fatal("expected route to stay unopened on cross-site POST")
	}
}

func TestGatewayHTTPRejectsCrossSiteCredentialedGETWithoutOrigin(t *testing.T) {
	called := false
	bridge := mustBridge(t, proxy.BridgeOptions{})
	gw := newGateway(map[string]streamOpener{
		"127.0.0.1": openerFunc(func(ctx context.Context, kind string) (io.ReadWriteCloser, error) {
			called = true
			return noopReadWriteCloser{}, nil
		}),
	}, bridge, browserPolicy{allowedOrigins: []string{"https://gateway.example.com"}}, nil)
	s := httptest.NewServer(gw)
	defer s.Close()

	req, _ := http.NewRequest(http.MethodGet, s.URL+"/hello", nil)
	req.Header.Set("Cookie", "sess=1")
	req.Header.Set("Sec-Fetch-Site", "cross-site")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status want=%d got=%d", http.StatusForbidden, resp.StatusCode)
	}
	if called {
		t.Fatal("expected route to stay unopened on cross-site credentialed GET")
	}
}

func TestGatewayHTTPAllowsSameOriginNavigationWithoutOrigin(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "ok")
	}))
	defer up.Close()

	streamSrv, err := serve.New(serve.Options{})
	if err != nil {
		t.Fatalf("serve.New: %v", err)
	}
	if err := proxy.Register(streamSrv, proxy.Options{
		Upstream:       up.URL,
		UpstreamOrigin: "http://127.0.0.1:5173",
	}); err != nil {
		t.Fatalf("proxy.Register: %v", err)
	}

	bridge := mustBridge(t, proxy.BridgeOptions{})
	gw := newGateway(map[string]streamOpener{
		"127.0.0.1": &fakeRoute{srv: streamSrv},
	}, bridge, browserPolicy{allowedOrigins: []string{"https://gateway.example.com"}}, nil)
	s := httptest.NewServer(gw)
	defer s.Close()

	req, _ := http.NewRequest(http.MethodGet, s.URL+"/hello", nil)
	req.Header.Set("Cookie", "sess=1")
	req.Header.Set("Sec-Fetch-Site", "same-origin")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status want=%d got=%d", http.StatusOK, resp.StatusCode)
	}
}

func TestGatewayWSAllowsConfiguredOriginAndProxiesToServerEndpoint(t *testing.T) {
	seen := make(chan map[string]string, 1)
	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ws" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		select {
		case seen <- map[string]string{
			"origin": r.Header.Get("Origin"),
			"cookie": r.Header.Get("Cookie"),
			"proto":  r.Header.Get("Sec-WebSocket-Protocol"),
		}:
		default:
		}
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		for {
			mt, msg, err := c.ReadMessage()
			if err != nil {
				return
			}
			_ = c.WriteMessage(mt, msg)
		}
	}))
	defer up.Close()

	streamSrv, err := serve.New(serve.Options{})
	if err != nil {
		t.Fatalf("serve.New: %v", err)
	}
	if err := proxy.Register(streamSrv, proxy.Options{
		Upstream:       up.URL,
		UpstreamOrigin: "http://127.0.0.1:5173",
	}); err != nil {
		t.Fatalf("proxy.Register: %v", err)
	}

	bridge := mustBridge(t, proxy.BridgeOptions{})
	gw := newGateway(map[string]streamOpener{
		"127.0.0.1": &fakeRoute{srv: streamSrv},
	}, bridge, browserPolicy{allowedOrigins: []string{"https://gateway.example.com"}}, nil)
	s := httptest.NewServer(gw)
	defer s.Close()

	wsURL := "ws" + strings.TrimPrefix(s.URL, "http") + "/ws"
	d := websocket.Dialer{}
	h := http.Header{}
	h.Set("Origin", "https://gateway.example.com")
	h.Set("Cookie", "a=1")
	h.Set("Sec-WebSocket-Protocol", "demo")
	c, _, err := d.Dial(wsURL, h)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	if err := c.WriteMessage(websocket.TextMessage, []byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, msg, err := c.ReadMessage()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(msg) != "ping" {
		t.Fatalf("unexpected msg: %q", string(msg))
	}

	raw := <-seen
	b, _ := json.Marshal(raw)
	if raw["origin"] != "http://127.0.0.1:5173" {
		t.Fatalf("unexpected origin: %s", b)
	}
	if raw["cookie"] != "a=1" {
		t.Fatalf("unexpected cookie: %s", b)
	}
	if !strings.Contains(raw["proto"], "demo") {
		t.Fatalf("unexpected proto: %s", b)
	}
}

func TestGatewayWSRejectsForeignOriginBeforeOpeningRoute(t *testing.T) {
	called := false
	bridge := mustBridge(t, proxy.BridgeOptions{})
	gw := newGateway(map[string]streamOpener{
		"127.0.0.1": openerFunc(func(ctx context.Context, kind string) (io.ReadWriteCloser, error) {
			called = true
			return noopReadWriteCloser{}, nil
		}),
	}, bridge, browserPolicy{allowedOrigins: []string{"https://gateway.example.com"}}, nil)
	s := httptest.NewServer(gw)
	defer s.Close()

	wsURL := "ws" + strings.TrimPrefix(s.URL, "http") + "/ws"
	_, resp, err := websocket.DefaultDialer.Dial(wsURL, http.Header{"Origin": []string{"https://evil.example.com"}})
	if err == nil {
		t.Fatal("expected dial error")
	}
	if resp == nil || resp.StatusCode != http.StatusForbidden {
		if resp == nil {
			t.Fatalf("expected 403 response, got nil resp (err=%v)", err)
		}
		t.Fatalf("expected 403 response, got %d", resp.StatusCode)
	}
	if called {
		t.Fatal("expected route to stay unopened on foreign origin")
	}
}

func TestGatewayWSAllowsNoOriginWhenConfigured(t *testing.T) {
	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		for {
			mt, msg, err := c.ReadMessage()
			if err != nil {
				return
			}
			_ = c.WriteMessage(mt, msg)
		}
	}))
	defer up.Close()

	streamSrv, err := serve.New(serve.Options{})
	if err != nil {
		t.Fatalf("serve.New: %v", err)
	}
	if err := proxy.Register(streamSrv, proxy.Options{
		Upstream:       up.URL,
		UpstreamOrigin: "http://127.0.0.1:5173",
	}); err != nil {
		t.Fatalf("proxy.Register: %v", err)
	}

	bridge := mustBridge(t, proxy.BridgeOptions{})
	gw := newGateway(map[string]streamOpener{
		"127.0.0.1": &fakeRoute{srv: streamSrv},
	}, bridge, browserPolicy{allowNoOrigin: true}, nil)
	s := httptest.NewServer(gw)
	defer s.Close()

	wsURL := "ws" + strings.TrimPrefix(s.URL, "http") + "/ws"
	c, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	if err := c.WriteMessage(websocket.TextMessage, []byte("pong")); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, msg, err := c.ReadMessage()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(msg) != "pong" {
		t.Fatalf("unexpected msg: %q", string(msg))
	}
}

func TestGatewayCanonicalizesRequestHost(t *testing.T) {
	called := false
	bridge := mustBridge(t, proxy.BridgeOptions{})
	gw := newGateway(map[string]streamOpener{
		"example.com": openerFunc(func(ctx context.Context, kind string) (io.ReadWriteCloser, error) {
			called = true
			return &noopReadWriteCloser{}, nil
		}),
	}, bridge, browserPolicy{allowedOrigins: []string{"https://gateway.example.com"}}, nil)

	req := httptest.NewRequest(http.MethodGet, "http://gateway.invalid/hello", nil)
	req.Host = "Example.COM:8443"
	rr := httptest.NewRecorder()
	gw.ServeHTTP(rr, req)
	if !called {
		t.Fatal("expected canonical host route to be used")
	}
}

func TestGatewayHealthz(t *testing.T) {
	gw := newGateway(nil, nil, browserPolicy{}, nil)
	req := httptest.NewRequest(http.MethodGet, "http://gateway.invalid/_flowersec/healthz", nil)
	rr := httptest.NewRecorder()
	gw.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if rr.Body.String() != "ok" {
		t.Fatalf("unexpected body: %q", rr.Body.String())
	}
}

func mustBridge(t *testing.T, opts proxy.BridgeOptions) *proxy.Bridge {
	t.Helper()
	bridge, err := proxy.NewBridge(opts)
	if err != nil {
		t.Fatalf("proxy.NewBridge: %v", err)
	}
	return bridge
}

type openerFunc func(ctx context.Context, kind string) (io.ReadWriteCloser, error)

func (fn openerFunc) OpenStream(ctx context.Context, kind string) (io.ReadWriteCloser, error) {
	return fn(ctx, kind)
}

type noopReadWriteCloser struct{}

func (noopReadWriteCloser) Read(p []byte) (int, error)  { return 0, io.EOF }
func (noopReadWriteCloser) Write(p []byte) (int, error) { return len(p), nil }
func (noopReadWriteCloser) Close() error                { return nil }
