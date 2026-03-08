package proxy

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/endpoint/serve"
)

type bridgeTestRoute struct {
	srv *serve.Server
}

func (c *bridgeTestRoute) OpenStream(ctx context.Context, kind string) (io.ReadWriteCloser, error) {
	a, b := net.Pipe()
	go c.srv.HandleStream(ctx, kind, b)
	return a, nil
}

func TestBridgeProxyHTTPFiltersCookiesAndResponseHeaders(t *testing.T) {
	seenCookie := make(chan string, 1)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case seenCookie <- r.Header.Get("Cookie"):
		default:
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("X-Not-Allowed", "secret")
		_, _ = io.WriteString(w, "ok")
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

	bridge, err := NewBridge(BridgeOptions{
		ForbiddenCookieNamePrefixes: []string{"x-"},
	})
	if err != nil {
		t.Fatalf("NewBridge: %v", err)
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := bridge.ProxyHTTP(w, r, &bridgeTestRoute{srv: streamSrv}); err != nil {
			t.Fatalf("ProxyHTTP: %v", err)
		}
	})

	req := httptest.NewRequest(http.MethodGet, "http://gateway.invalid/hello", nil)
	req.Header.Set("Cookie", "a=1; x-secret=1; b=2")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%q", rr.Code, rr.Body.String())
	}
	if rr.Body.String() != "ok" {
		t.Fatalf("unexpected body: %q", rr.Body.String())
	}
	if got := rr.Header().Get("X-Not-Allowed"); got != "" {
		t.Fatalf("expected filtered response header, got %q", got)
	}
	if got := <-seenCookie; got != "a=1; b=2" {
		t.Fatalf("unexpected upstream cookie: %q", got)
	}
}
