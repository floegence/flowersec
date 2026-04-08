package proxy

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/endpoint/serve"
	"github.com/floegence/flowersec/flowersec-go/framing/jsonframe"
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

type timeoutCaptureRoute struct {
	timeoutCh chan int64
	errCh     chan error
}

func TestBridgeProxyHTTPAppliesDefaultRequestTimeout(t *testing.T) {
	timeoutMS := int64(30000)
	bridge, err := NewBridge(BridgeOptions{
		DefaultHTTPRequestTimeoutMS: &timeoutMS,
	})
	if err != nil {
		t.Fatalf("NewBridge: %v", err)
	}

	route := &timeoutCaptureRoute{
		timeoutCh: make(chan int64, 1),
		errCh:     make(chan error, 1),
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := bridge.ProxyHTTP(w, r, route); err != nil {
			t.Fatalf("ProxyHTTP: %v", err)
		}
	})

	req := httptest.NewRequest(http.MethodGet, "http://gateway.invalid/hello", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%q", rr.Code, rr.Body.String())
	}
	select {
	case err := <-route.errCh:
		t.Fatalf("route handler failed: %v", err)
	default:
	}
	if got := <-route.timeoutCh; got != timeoutMS {
		t.Fatalf("unexpected timeout_ms: %d", got)
	}
}

func (r *timeoutCaptureRoute) OpenStream(ctx context.Context, kind string) (io.ReadWriteCloser, error) {
	client, server := net.Pipe()
	go func() {
		defer server.Close()

		metaBytes, err := jsonframe.ReadJSONFrame(server, jsonframe.DefaultMaxJSONFrameBytes)
		if err != nil {
			r.errCh <- err
			return
		}
		var meta HTTPRequestMeta
		if err := json.Unmarshal(metaBytes, &meta); err != nil {
			r.errCh <- err
			return
		}
		r.timeoutCh <- meta.TimeoutMS

		var recv int64
		for {
			_, done, err := readChunkFrame(server, DefaultMaxChunkBytes, DefaultMaxBodyBytes, &recv)
			if err != nil {
				r.errCh <- err
				return
			}
			if done {
				break
			}
		}

		if err := jsonframe.WriteJSONFrame(server, HTTPResponseMeta{
			V:         ProtocolVersion,
			RequestID: meta.RequestID,
			OK:        true,
			Status:    http.StatusOK,
			Headers:   []Header{{Name: "Content-Type", Value: "text/plain"}},
		}); err != nil {
			r.errCh <- err
			return
		}
		var sent int64
		if err := writeChunkFrame(server, []byte("ok"), DefaultMaxChunkBytes, DefaultMaxBodyBytes, &sent); err != nil {
			r.errCh <- err
			return
		}
		if err := writeChunkTerminator(server); err != nil {
			r.errCh <- err
			return
		}
	}()
	return client, nil
}
