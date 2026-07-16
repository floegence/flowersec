package proxy

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	fsstream "github.com/floegence/flowersec/flowersec-go/stream"

	"github.com/floegence/flowersec/flowersec-go/endpoint/serve"
	"github.com/gorilla/websocket"
)

func TestClientHTTPAndWebSocketAgainstRegisteredServer(t *testing.T) {
	upgrader := websocket.Upgrader{
		CheckOrigin:  func(*http.Request) bool { return true },
		Subprotocols: []string{"flowersec.test.v1"},
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/socket" {
			conn, err := upgrader.Upgrade(w, r, nil)
			if err != nil {
				return
			}
			defer conn.Close()
			messageType, payload, err := conn.ReadMessage()
			if err == nil {
				_ = conn.WriteMessage(messageType, payload)
			}
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("X-Not-Allowed", "secret")
		if r.Method == http.MethodPost {
			payload, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			_, _ = w.Write(payload)
			return
		}
		_, _ = io.WriteString(w, "hello")
	}))
	defer upstream.Close()

	server, err := serve.New(serve.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := Register(server, Options{
		Upstream:       upstream.URL,
		UpstreamOrigin: upstream.URL,
	}); err != nil {
		t.Fatal(err)
	}
	route := &bridgeTestRoute{srv: server}
	client, err := NewClient(ContractOptions{})
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(context.Background(), route, ClientHTTPRequest{
		Method: "GET",
		Path:   "/hello?value=1",
		Header: http.Header{"Authorization": {"Bearer secret"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "hello" || response.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%q", response.StatusCode, body)
	}
	if response.Header.Get("X-Not-Allowed") != "" {
		t.Fatal("unexpected disallowed response header")
	}
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}

	response, err = client.Do(nil, route, ClientHTTPRequest{
		Method:  "post",
		Path:    "/echo",
		Timeout: 1500 * time.Millisecond,
		Body:    strings.NewReader("request body"),
	})
	if err != nil {
		t.Fatal(err)
	}
	body, err = io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "request body" {
		t.Fatalf("unexpected echoed body: %q", body)
	}

	ws, err := client.OpenWebSocket(nil, route, "/socket", http.Header{
		"Sec-WebSocket-Protocol": {"unsupported, flowersec.test.v1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if ws.Protocol() != "flowersec.test.v1" {
		t.Fatalf("unexpected WebSocket protocol: %q", ws.Protocol())
	}
	if err := ws.WriteFrame(3, nil); err == nil {
		t.Fatal("expected invalid WebSocket op error")
	}
	if err := ws.WriteFrame(1, []byte("hello websocket")); err != nil {
		t.Fatal(err)
	}
	op, payload, err := ws.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	if op != 1 || string(payload) != "hello websocket" {
		t.Fatalf("op=%d payload=%q", op, payload)
	}
	_ = ws.Close()
}

type clientTestRouteFunc func(context.Context, string) (io.ReadWriteCloser, error)

func (fn clientTestRouteFunc) OpenStream(ctx context.Context, kind string) (fsstream.Stream, error) {
	value, err := fn(ctx, kind)
	if err != nil || value == nil {
		return nil, err
	}
	return proxyTestStream{ReadWriteCloser: value}, nil
}

type proxyTestStream struct{ io.ReadWriteCloser }

func (s proxyTestStream) Reset() error { return s.Close() }

func TestClientValidationAndStructuredErrors(t *testing.T) {
	var nilClient *Client
	if _, err := nilClient.Do(context.Background(), nil, ClientHTTPRequest{}); clientErrorCode(err) != "client_not_configured" {
		t.Fatalf("unexpected nil client error: %v", err)
	}
	if _, err := nilClient.OpenWebSocket(context.Background(), nil, "/socket", nil); clientErrorCode(err) != "client_not_configured" {
		t.Fatalf("unexpected nil WebSocket client error: %v", err)
	}

	client, err := NewClient(ContractOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewClient(ContractOptions{MaxChunkBytes: -1}); err == nil {
		t.Fatal("expected invalid client options error")
	}

	tests := []struct {
		name string
		req  ClientHTTPRequest
		code string
	}{
		{name: "missing route", req: ClientHTTPRequest{Method: http.MethodGet, Path: "/"}, code: "route_missing"},
		{name: "missing method", req: ClientHTTPRequest{Path: "/"}, code: "invalid_request_meta"},
		{name: "invalid path", req: ClientHTTPRequest{Method: http.MethodGet, Path: "https://example.com/"}, code: "invalid_request_meta"},
		{name: "negative timeout", req: ClientHTTPRequest{Method: http.MethodGet, Path: "/", Timeout: -time.Second}, code: "invalid_request_meta"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var route StreamOpener
			if test.name != "missing route" {
				route = clientTestRouteFunc(func(context.Context, string) (io.ReadWriteCloser, error) {
					t.Fatal("validation failure must happen before opening a stream")
					return nil, nil
				})
			}
			if _, err := client.Do(context.Background(), route, test.req); clientErrorCode(err) != test.code {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}

	openErr := errors.New("route unavailable")
	failingRoute := clientTestRouteFunc(func(context.Context, string) (io.ReadWriteCloser, error) {
		return nil, openErr
	})
	_, err = client.Do(context.Background(), failingRoute, ClientHTTPRequest{Method: http.MethodGet, Path: "/"})
	if clientErrorCode(err) != "stream_open_failed" || !errors.Is(err, openErr) {
		t.Fatalf("unexpected stream open error: %v", err)
	}
	if got := err.Error(); !strings.Contains(got, "stream_open_failed") || !strings.Contains(got, openErr.Error()) {
		t.Fatalf("unexpected structured error text: %q", got)
	}

	if _, err := client.OpenWebSocket(context.Background(), nil, "/socket", nil); clientErrorCode(err) != "route_missing" {
		t.Fatalf("unexpected missing WebSocket route error: %v", err)
	}
	if _, err := client.OpenWebSocket(context.Background(), failingRoute, "https://example.com/socket", nil); clientErrorCode(err) != "invalid_ws_open_meta" {
		t.Fatalf("unexpected invalid WebSocket path error: %v", err)
	}
	if _, err := client.OpenWebSocket(context.Background(), failingRoute, "/socket", nil); clientErrorCode(err) != "stream_open_failed" || !errors.Is(err, openErr) {
		t.Fatalf("unexpected WebSocket stream open error: %v", err)
	}

	var nilClientErr *ClientError
	if nilClientErr.Error() != "<nil>" || nilClientErr.Unwrap() != nil {
		t.Fatal("nil ClientError contract changed")
	}
	plainErr := &ClientError{Code: "proxy_failed", Message: "request rejected"}
	if plainErr.Error() != "proxy_failed: request rejected" || plainErr.Unwrap() != nil {
		t.Fatalf("unexpected plain ClientError behavior: %v", plainErr)
	}

	var nilWS *ClientWebSocket
	if nilWS.Protocol() != "" {
		t.Fatal("nil WebSocket must not report a protocol")
	}
	if !errors.Is(nilWS.WriteFrame(1, nil), io.ErrClosedPipe) {
		t.Fatal("nil WebSocket write must fail as closed")
	}
	if _, _, err := nilWS.ReadFrame(); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal("nil WebSocket read must fail as closed")
	}
	if err := nilWS.Close(); err != nil {
		t.Fatalf("nil WebSocket close failed: %v", err)
	}
}

func clientErrorCode(err error) string {
	var clientErr *ClientError
	if errors.As(err, &clientErr) {
		return clientErr.Code
	}
	return ""
}
