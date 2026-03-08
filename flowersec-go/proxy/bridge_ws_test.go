package proxy

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/endpoint/serve"
	"github.com/gorilla/websocket"
)

func TestBridgeProxyWSForwardsOriginCookieAndProtocol(t *testing.T) {
	seen := make(chan map[string]string, 1)
	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	if err := Register(streamSrv, Options{
		Upstream:       up.URL,
		UpstreamOrigin: "http://127.0.0.1:5173",
	}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	bridge, err := NewBridge(BridgeOptions{})
	if err != nil {
		t.Fatalf("NewBridge: %v", err)
	}
	proxyErrCh := make(chan error, 1)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := bridge.ProxyWS(w, r, &bridgeTestRoute{srv: streamSrv}, websocket.Upgrader{CheckOrigin: func(r *http.Request) bool {
			return r.Header.Get("Origin") == "https://gateway.example.com"
		}}); err != nil {
			var bridgeErr *BridgeError
			if !errors.As(err, &bridgeErr) || bridgeErr.Status >= 500 {
				select {
				case proxyErrCh <- err:
				default:
				}
			}
		}
	})

	server := httptest.NewServer(handler)
	defer server.Close()
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	h := http.Header{}
	h.Set("Origin", "https://gateway.example.com")
	h.Set("Cookie", "a=1")
	h.Set("Sec-WebSocket-Protocol", "demo")
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, h)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if err := conn.WriteMessage(websocket.TextMessage, []byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, msg, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(msg) != "hello" {
		t.Fatalf("unexpected msg: %q", string(msg))
	}

	select {
	case err := <-proxyErrCh:
		t.Fatalf("ProxyWS: %v", err)
	default:
	}
	raw := <-seen
	if raw["origin"] != "http://127.0.0.1:5173" {
		t.Fatalf("unexpected upstream origin: %q", raw["origin"])
	}
	if raw["cookie"] != "a=1" {
		t.Fatalf("unexpected upstream cookie: %q", raw["cookie"])
	}
	if !strings.Contains(raw["proto"], "demo") {
		t.Fatalf("unexpected upstream protocol: %q", raw["proto"])
	}
}

func TestBridgeProxyWSRejectsOriginBeforeOpeningRoute(t *testing.T) {
	bridge, err := NewBridge(BridgeOptions{})
	if err != nil {
		t.Fatalf("NewBridge: %v", err)
	}
	opened := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = bridge.ProxyWS(w, r, openerFunc(func(ctx context.Context, kind string) (io.ReadWriteCloser, error) {
			opened = true
			return noopBridgeReadWriteCloser{}, nil
		}), websocket.Upgrader{CheckOrigin: func(r *http.Request) bool {
			return r.Header.Get("Origin") == "https://gateway.example.com"
		}})
	})
	server := httptest.NewServer(handler)
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
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
	if opened {
		t.Fatal("expected route to remain unopened")
	}
}

type openerFunc func(ctx context.Context, kind string) (io.ReadWriteCloser, error)

func (fn openerFunc) OpenStream(ctx context.Context, kind string) (io.ReadWriteCloser, error) {
	return fn(ctx, kind)
}

type noopBridgeReadWriteCloser struct{}

func (noopBridgeReadWriteCloser) Read(p []byte) (int, error)  { return 0, io.EOF }
func (noopBridgeReadWriteCloser) Write(p []byte) (int, error) { return len(p), nil }
func (noopBridgeReadWriteCloser) Close() error                { return nil }
