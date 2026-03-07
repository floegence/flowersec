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

	gw := newGateway(map[string]streamOpener{
		"127.0.0.1": &fakeRoute{srv: streamSrv},
	}, nil)
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

func TestGatewayWSProxiesToServerEndpoint(t *testing.T) {
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

	gw := newGateway(map[string]streamOpener{
		"127.0.0.1": &fakeRoute{srv: streamSrv},
	}, nil)
	s := httptest.NewServer(gw)
	defer s.Close()

	wsURL := "ws" + strings.TrimPrefix(s.URL, "http") + "/ws"
	d := websocket.Dialer{}
	h := http.Header{}
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

func TestGatewayCanonicalizesRequestHost(t *testing.T) {
	called := false
	gw := newGateway(map[string]streamOpener{
		"example.com": openerFunc(func(ctx context.Context, kind string) (io.ReadWriteCloser, error) {
			called = true
			return &noopReadWriteCloser{}, nil
		}),
	}, nil)

	req := httptest.NewRequest(http.MethodGet, "http://gateway.invalid/hello", nil)
	req.Host = "Example.COM:8443"
	rr := httptest.NewRecorder()
	gw.ServeHTTP(rr, req)
	if !called {
		t.Fatal("expected canonical host route to be used")
	}
}

func TestGatewayHealthz(t *testing.T) {
	gw := newGateway(nil, nil)
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

type openerFunc func(ctx context.Context, kind string) (io.ReadWriteCloser, error)

func (fn openerFunc) OpenStream(ctx context.Context, kind string) (io.ReadWriteCloser, error) {
	return fn(ctx, kind)
}

type noopReadWriteCloser struct{}

func (noopReadWriteCloser) Read(p []byte) (int, error)  { return 0, io.EOF }
func (noopReadWriteCloser) Write(p []byte) (int, error) { return len(p), nil }
func (noopReadWriteCloser) Close() error                { return nil }
