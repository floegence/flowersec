package flowersec

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/gorilla/websocket"
)

func TestProxyServerHTTPApplicationRoundTrip(t *testing.T) {
	var wantHost string
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.RequestURI() != "/public/../api//items?q=%7euser" {
			t.Errorf("upstream path = %q", request.URL.RequestURI())
		}
		if request.Host != wantHost {
			t.Errorf("upstream host = %q, want %q", request.Host, wantHost)
		}
		if request.Header.Get("X-Forwarded-Proto") != "https" {
			t.Errorf("X-Forwarded-Proto = %q", request.Header.Get("X-Forwarded-Proto"))
		}
		writer.Header().Set("Content-Type", "text/plain")
		writer.Header().Set("X-Frame-Options", "DENY")
		_, _ = writer.Write([]byte("proxy-ok"))
	}))
	defer upstream.Close()
	wantHost = strings.TrimPrefix(upstream.URL, "http://")

	handlers := &StreamHandlerPlanConfig{}
	proxy, err := NewProxyServer(ProxyServerOptions{
		Upstream: upstream.URL, UpstreamOrigin: upstream.URL,
		AllowedOrigins:         []string{"https://app.example"},
		BlockedResponseHeaders: []string{"x-frame-options"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	if err := proxy.RegisterStreamHandlers(handlers, allowProxyApplicationTestOpen); err != nil {
		t.Fatal(err)
	}

	client := serveProxyTestStream(t, proxy, handlers, proxyHTTPStreamKind)
	if err := writeProxyMetadata(client, proxyHTTPRequest{
		Version: proxyWireVersion, RequestID: "request-1", Method: http.MethodGet,
		Path: "/public/../api//items?q=%7euser", Headers: []proxyHeader{{Name: "accept", Value: "text/plain"}},
		ExternalOrigin: "https://app.example",
	}); err != nil {
		t.Fatal(err)
	}
	if err := writeProxyTerminator(client); err != nil {
		t.Fatal(err)
	}
	var response proxyHTTPResponse
	if err := readProxyMetadata(client, 1<<20, &response); err != nil {
		t.Fatal(err)
	}
	if !response.OK || response.Status != http.StatusOK || response.RequestID != "request-1" {
		t.Fatalf("proxy response = %+v", response)
	}
	for _, header := range response.Headers {
		if strings.EqualFold(header.Name, "x-frame-options") {
			t.Fatalf("blocked response header escaped: %+v", response.Headers)
		}
	}
	var body []byte
	var total int64
	for {
		chunk, done, err := readProxyChunk(client, 1<<20, &total, 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		if done {
			break
		}
		body = append(body, chunk...)
	}
	if string(body) != "proxy-ok" {
		t.Fatalf("proxy body = %q", body)
	}
}

func TestProxyWebSocketClosePayloadTruncatesAtUTF8Boundary(t *testing.T) {
	reason := strings.Repeat("界", 100)
	payload := proxyWebSocketClosePayload(websocket.CloseNormalClosure, reason)
	if len(payload) != 125 {
		t.Fatalf("payload length = %d, want 125", len(payload))
	}
	if !utf8.Valid(payload[2:]) {
		t.Fatal("close reason is not valid UTF-8")
	}
	if got := string(payload[2:]); !strings.HasPrefix(reason, got) {
		t.Fatalf("close reason %q is not a prefix of %q", got, reason)
	}
}

func TestProxyServerCanonicalPathContract(t *testing.T) {
	tests := []struct {
		raw  string
		want string
	}{
		{raw: "/safe/../admin?mode=raw", want: "/safe/../admin?mode=raw"},
		{raw: "/safe/%2e%2e/admin?mode=encoded", want: "/safe/%2e%2e/admin?mode=encoded"},
		{raw: "/safe//child?mode=double", want: "/safe//child?mode=double"},
		{raw: "/objects/a%2Fb?x=%2f&x=+&x=%41", want: "/objects/a%2Fb?x=%2f&x=+&x=%41"},
		{raw: "/literal%25/a;b/%ff", want: "/literal%25/a;b/%ff"},
		{raw: "/?", want: "/?"},
		{raw: "//other.example/a?", want: "//other.example/a?"},
		{raw: "/", want: "/"},
	}
	for _, test := range tests {
		t.Run(test.raw, func(t *testing.T) {
			parsed, err := parseProxyPath(test.raw)
			if err != nil {
				t.Fatal(err)
			}
			if parsed.RequestURI() != test.want {
				t.Fatalf("canonical path = %q, want %q", parsed.RequestURI(), test.want)
			}
		})
	}
	for _, raw := range []string{
		"/\\evil.example/admin", "/safe\\..\\admin", "/bad%", "/bad%xy", "/a#fragment", "/a b", "/é",
	} {
		t.Run("reject "+raw, func(t *testing.T) {
			if _, err := parseProxyPath(raw); err == nil {
				t.Fatalf("invalid request target accepted: %q", raw)
			}
		})
	}
}

func TestProxyServerWebSocketRoundTripUsesFlowersecWire(t *testing.T) {
	upgrader := websocket.Upgrader{
		CheckOrigin: func(request *http.Request) bool { return request.Header.Get("Origin") != "" },
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.RequestURI() != "/public/../api//socket?q=%7euser" {
			t.Errorf("upstream WebSocket path = %q", request.URL.RequestURI())
		}
		connection, err := upgrader.Upgrade(writer, request, nil)
		if err != nil {
			return
		}
		defer connection.Close()
		messageType, payload, err := connection.ReadMessage()
		if err != nil {
			return
		}
		if err := connection.WriteMessage(messageType, payload); err != nil {
			return
		}
		_, _, _ = connection.ReadMessage()
	}))
	defer upstream.Close()

	handlers := &StreamHandlerPlanConfig{}
	proxy, err := NewProxyServer(ProxyServerOptions{Upstream: upstream.URL, UpstreamOrigin: upstream.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	if err := proxy.RegisterStreamHandlers(handlers, allowProxyApplicationTestOpen); err != nil {
		t.Fatal(err)
	}

	client := serveProxyTestStream(t, proxy, handlers, proxyWSStreamKind)
	if err := writeProxyMetadata(client, proxyWebSocketOpen{
		Version: proxyWireVersion, ConnID: "socket-1", Path: "/public/../api//socket?q=%7euser",
	}); err != nil {
		t.Fatal(err)
	}
	var opened proxyWebSocketResponse
	if err := readProxyMetadata(client, 1<<20, &opened); err != nil {
		t.Fatal(err)
	}
	if !opened.OK || opened.ConnID != "socket-1" {
		t.Fatalf("open response = %+v", opened)
	}
	if err := writeProxyWebSocketFrame(client, 2, []byte("echo"), 1<<20); err != nil {
		t.Fatal(err)
	}
	operation, payload, err := readProxyWebSocketFrame(client, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if operation != 2 || string(payload) != "echo" {
		t.Fatalf("echo = %d %q", operation, payload)
	}
}

func TestProxyServerWebSocketUpstreamCloseWaitsForDownstreamAndJoinsRelays(t *testing.T) {
	for _, cancelExchange := range []bool{false, true} {
		name := "reply"
		if cancelExchange {
			name = "cancel"
		}
		t.Run(name, func(t *testing.T) {
			harness := newProxyWebSocketRelayHarness(t, func(connection *websocket.Conn) {
				_ = connection.WriteMessage(websocket.TextMessage, []byte("queued-before-close"))
				_ = connection.WriteMessage(websocket.CloseMessage,
					websocket.FormatCloseMessage(websocket.CloseNormalClosure, "done"))
				_, _, _ = connection.ReadMessage()
			})
			operation, payload, err := readProxyWebSocketFrame(harness.client, 1<<20)
			if err != nil {
				t.Fatal(err)
			}
			if operation != 1 || string(payload) != "queued-before-close" {
				t.Fatalf("queued frame = %d %q", operation, payload)
			}
			operation, payload, err = readProxyWebSocketFrame(harness.client, 1<<20)
			if err != nil {
				t.Fatal(err)
			}
			if operation != 8 || !bytes.Equal(payload, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "done")) {
				t.Fatalf("close frame = operation %d payload %x", operation, payload)
			}
			select {
			case err := <-harness.done:
				t.Fatalf("handler completed before downstream Close: %v", err)
			default:
			}
			if harness.stream.resets.Load() != 0 {
				t.Fatal("stream reset before downstream Close")
			}
			if cancelExchange {
				if err := harness.proxy.Close(); err != nil {
					t.Fatal(err)
				}
				select {
				case err := <-harness.done:
					if !errors.Is(err, context.Canceled) {
						t.Fatalf("cancel error = %v", err)
					}
				case <-time.After(time.Second):
					t.Fatal("canceled exchange did not join both relays")
				}
				if harness.stream.resets.Load() != 1 {
					t.Fatalf("Reset count = %d, want 1", harness.stream.resets.Load())
				}
				return
			}
			if err := writeProxyWebSocketFrame(harness.client, 8, payload, 1<<20); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-harness.done:
				if err != nil {
					t.Fatalf("WebSocket handler error = %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("WebSocket handler did not join both relays")
			}
			if harness.stream.resets.Load() != 0 {
				t.Fatalf("Reset count = %d, want 0", harness.stream.resets.Load())
			}
		})
	}
}

func TestProxyServerWebSocketDownstreamCloseForwardsUpstreamResponse(t *testing.T) {
	upstreamRead := make(chan struct{})
	harness := newProxyWebSocketRelayHarness(t, func(connection *websocket.Conn) {
		_, _, _ = connection.ReadMessage()
		close(upstreamRead)
	})

	payload := websocket.FormatCloseMessage(websocket.CloseNormalClosure, "done")
	if err := writeProxyWebSocketFrame(harness.client, 8, payload, 1<<20); err != nil {
		t.Fatal(err)
	}
	select {
	case <-upstreamRead:
	case <-time.After(time.Second):
		t.Fatal("upstream WebSocket did not receive downstream close")
	}
	operation, forwarded, err := readProxyWebSocketFrame(harness.client, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if operation != 8 || len(forwarded) < 2 || binary.BigEndian.Uint16(forwarded[:2]) != websocket.CloseNormalClosure {
		t.Fatalf("forwarded close frame = operation %d payload %x", operation, forwarded)
	}
	awaitProxyWebSocketRelayDone(t, harness.done)
	if harness.stream.resets.Load() != 0 {
		t.Fatalf("stream Reset count = %d, want 0", harness.stream.resets.Load())
	}
}

func TestProxyServerWebSocketDownstreamCloseJoinsRelays(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	harness := newProxyWebSocketRelayHarness(t, func(connection *websocket.Conn) {
		<-release
	})

	if err := harness.client.Close(); err != nil {
		t.Fatal(err)
	}
	awaitProxyWebSocketRelayDone(t, harness.done)
	if harness.stream.resets.Load() != 1 {
		t.Fatalf("stream Reset count = %d, want 1", harness.stream.resets.Load())
	}
}

func TestProxyServerWebSocketSimultaneousRelayErrorsJoinOnce(t *testing.T) {
	trigger := make(chan struct{})
	upstreamClosed := make(chan struct{})
	harness := newProxyWebSocketRelayHarness(t, func(connection *websocket.Conn) {
		<-trigger
		_ = connection.UnderlyingConn().Close()
		close(upstreamClosed)
	})

	close(trigger)
	_ = harness.client.Close()
	select {
	case <-upstreamClosed:
	case <-time.After(time.Second):
		t.Fatal("upstream WebSocket did not close")
	}
	awaitProxyWebSocketRelayDone(t, harness.done)
	if harness.stream.resets.Load() != 1 {
		t.Fatalf("stream Reset count = %d, want 1", harness.stream.resets.Load())
	}
}

func TestProxyServerCloseCancelsAndJoinsWebSocketRelays(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	harness := newProxyWebSocketRelayHarness(t, func(connection *websocket.Conn) {
		<-release
	})

	closed := make(chan error, 1)
	go func() { closed <- harness.proxy.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatalf("ProxyServer.Close error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("ProxyServer.Close did not join WebSocket relays")
	}
	awaitProxyWebSocketRelayDone(t, harness.done)
	if harness.stream.resets.Load() != 1 {
		t.Fatalf("stream Reset count = %d, want 1", harness.stream.resets.Load())
	}
}

func TestProxyServerCloseCancelsActiveAndRejectsFutureDispatch(t *testing.T) {
	received := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		close(received)
		<-request.Context().Done()
	}))
	defer upstream.Close()

	proxy, err := NewProxyServer(ProxyServerOptions{Upstream: upstream.URL, UpstreamOrigin: upstream.URL})
	if err != nil {
		t.Fatal(err)
	}
	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	go func() { _, _ = io.Copy(io.Discard, client) }()
	stream := &proxyServerTestStream{Conn: server, kind: proxyHTTPStreamKind}
	done := make(chan error, 1)
	go func() {
		done <- proxy.runLimited(context.Background(), stream, func(ctx context.Context) error {
			proxy.serveHTTPStream(ctx, stream)
			return nil
		})
	}()
	if err := writeProxyMetadata(client, proxyHTTPRequest{
		Version: proxyWireVersion, RequestID: "close", Method: http.MethodGet, Path: "/slow",
	}); err != nil {
		t.Fatal(err)
	}
	if err := writeProxyTerminator(client); err != nil {
		t.Fatal(err)
	}
	select {
	case <-received:
	case <-time.After(time.Second):
		t.Fatal("upstream request did not start")
	}
	if err := proxy.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("ProxyServer.Close returned before active handler completed")
	}
	handlers := &StreamHandlerPlanConfig{}
	if err := proxy.RegisterStreamHandlers(handlers, allowProxyApplicationTestOpen); !errors.Is(err, ErrInvalidProxyServer) {
		t.Fatalf("Register after Close error = %v", err)
	}
}

func TestProxyServerHTTPStreamResetCancelsUpstream(t *testing.T) {
	started := make(chan struct{})
	canceled := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		close(started)
		<-request.Context().Done()
		close(canceled)
	}))
	defer upstream.Close()

	proxy, err := NewProxyServer(ProxyServerOptions{
		Upstream: upstream.URL, UpstreamOrigin: upstream.URL,
		DefaultHTTPRequestTimeout: 15 * time.Second,
		MaxHTTPRequestTimeout:     15 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	client, server := net.Pipe()
	stream := &proxyResetTestStream{Conn: server, kind: proxyHTTPStreamKind}
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	done := make(chan struct{})
	go func() {
		proxy.serveHTTPStream(context.Background(), stream)
		close(done)
	}()
	if err := writeProxyMetadata(client, proxyHTTPRequest{
		Version: proxyWireVersion, RequestID: "cancel", Method: http.MethodGet, Path: "/slow",
	}); err != nil {
		t.Fatal(err)
	}
	if err := writeProxyTerminator(client); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("upstream request did not start")
	}
	stream.markReset()
	_ = client.Close()
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("stream reset did not cancel upstream request")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("proxy handler did not finish after stream reset")
	}
}

func TestProxyServerCloseInterruptsPartialHTTPFrames(t *testing.T) {
	for _, testCase := range []struct {
		name  string
		write func(net.Conn) error
	}{
		{name: "metadata", write: func(client net.Conn) error {
			_, err := client.Write([]byte{0, 0})
			return err
		}},
		{name: "body terminator", write: func(client net.Conn) error {
			if err := writeProxyMetadata(client, proxyHTTPRequest{
				Version: proxyWireVersion, RequestID: "partial", Method: http.MethodGet, Path: "/slow",
			}); err != nil {
				return err
			}
			_, err := client.Write([]byte{0, 0})
			return err
		}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			proxy, err := NewProxyServer(ProxyServerOptions{
				Upstream: "http://127.0.0.1:1", UpstreamOrigin: "http://127.0.0.1:1",
			})
			if err != nil {
				t.Fatal(err)
			}
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			started := make(chan struct{})
			stream := &proxyServerTestStream{Conn: server, kind: proxyHTTPStreamKind}
			go func() {
				_ = proxy.runLimited(context.Background(), stream, func(ctx context.Context) error {
					close(started)
					proxy.serveHTTPStream(ctx, stream)
					return nil
				})
			}()
			<-started
			if err := testCase.write(client); err != nil {
				t.Fatal(err)
			}
			closed := make(chan struct{})
			go func() {
				_ = proxy.Close()
				close(closed)
			}()
			select {
			case <-closed:
			case <-time.After(time.Second):
				t.Fatal("ProxyServer.Close did not interrupt the partial frame")
			}
		})
	}
}

func TestProxyServerRejectsUnsafeAndDuplicateRegistration(t *testing.T) {
	for _, options := range []ProxyServerOptions{
		{},
		{Upstream: "http://example.com:80", UpstreamOrigin: "http://example.com"},
		{Upstream: "http://127.0.0.1:80", UpstreamOrigin: "http://127.0.0.1", ExtraRequestHeaders: []string{"authorization"}},
		{Upstream: "http://127.0.0.1:80", UpstreamOrigin: "http://127.0.0.1/"},
		{Upstream: "http://127.0.0.1:80", UpstreamOrigin: "http://127.0.0.1", AllowedOrigins: []string{"https://app.example/"}},
	} {
		if _, err := NewProxyServer(options); !errors.Is(err, ErrInvalidProxyServer) {
			t.Fatalf("NewProxyServer(%+v) error = %v", options, err)
		}
	}
	handlers := &StreamHandlerPlanConfig{}
	proxy, err := NewProxyServer(ProxyServerOptions{Upstream: "http://127.0.0.1:8080", UpstreamOrigin: "http://127.0.0.1:8080"})
	if err != nil {
		t.Fatal(err)
	}
	if err := proxy.RegisterStreamHandlers(handlers, allowProxyApplicationTestOpen); err != nil {
		t.Fatal(err)
	}
	if err := proxy.RegisterStreamHandlers(handlers, allowProxyApplicationTestOpen); !errors.Is(err, ErrInvalidProxyServer) {
		t.Fatalf("duplicate Register error = %v", err)
	}
}

func TestProxyServerRegistersIntoCurrentApplicationPlan(t *testing.T) {
	handlers := &StreamHandlerPlanConfig{}
	proxy, err := NewProxyServer(ProxyServerOptions{
		Upstream: "http://127.0.0.1:8080", UpstreamOrigin: "http://127.0.0.1:8080",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = proxy.Close() })
	if err := proxy.RegisterStreamHandlers(handlers, allowProxyApplicationTestOpen); err != nil {
		t.Fatalf("ProxyServer.RegisterStreamHandlers(StreamHandlerPlanConfig) error = %v", err)
	}
	if err := proxy.RegisterStreamHandlers(handlers, allowProxyApplicationTestOpen); !errors.Is(err, ErrInvalidProxyServer) {
		t.Fatalf("duplicate ProxyServer.RegisterStreamHandlers(StreamHandlerPlanConfig) error = %v, want ErrInvalidProxyServer", err)
	}
}

func allowProxyApplicationTestOpen(context.Context, any, []byte) error { return nil }

// Wire-level application tests register the current declarations, then exercise
// their shared application I/O directly. Original StreamOwnership lifecycle and
// carrier admission remain covered by the current session integration fixtures.
func serveProxyTestStream(t *testing.T, proxy *ProxyServer, plan *StreamHandlerPlanConfig, kind string) net.Conn {
	t.Helper()
	registered := false
	for _, declaration := range plan.Handlers {
		if declaration.Kind != kind {
			continue
		}
		if declaration.Handler == nil || declaration.AuthorizeOpen == nil {
			t.Fatal("incomplete current proxy declaration")
		}
		if err := declaration.AuthorizeOpen(context.Background(), nil, nil); err != nil {
			t.Fatal(err)
		}
		registered = true
	}
	if !registered {
		t.Fatalf("proxy kind %q is absent from current application plan", kind)
	}
	client, server := net.Pipe()
	stream := &proxyServerTestStream{Conn: server, kind: kind}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		defer server.Close()
		done <- proxy.runLimited(ctx, stream, func(ctx context.Context) error {
			switch kind {
			case proxyHTTPStreamKind:
				proxy.serveHTTPStream(ctx, stream)
				return nil
			case proxyWSStreamKind:
				return proxy.serveWebSocketStream(ctx, stream)
			default:
				return ErrInvalidProxyServer
			}
		})
	}()
	t.Cleanup(func() {
		cancel()
		_ = client.Close()
		_ = server.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("proxy application handler did not stop")
		}
	})
	return client
}

type proxyServerTestStream struct {
	net.Conn
	kind string
}

type countingProxyServerTestStream struct {
	proxyServerTestStream
	resets atomic.Int32
}

type proxyWebSocketRelayHarness struct {
	proxy  *ProxyServer
	client net.Conn
	stream *countingProxyServerTestStream
	done   <-chan error
}

func newProxyWebSocketRelayHarness(
	t *testing.T,
	handle func(*websocket.Conn),
) proxyWebSocketRelayHarness {
	t.Helper()
	upgrader := websocket.Upgrader{
		CheckOrigin: func(request *http.Request) bool { return request.Header.Get("Origin") != "" },
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		connection, err := upgrader.Upgrade(writer, request, nil)
		if err != nil {
			return
		}
		defer connection.Close()
		handle(connection)
	}))
	t.Cleanup(upstream.Close)

	proxy, err := NewProxyServer(ProxyServerOptions{
		Upstream: upstream.URL, UpstreamOrigin: upstream.URL,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = proxy.Close() })
	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	stream := &countingProxyServerTestStream{
		proxyServerTestStream: proxyServerTestStream{Conn: server, kind: proxyWSStreamKind},
	}
	done := make(chan error, 1)
	go func() {
		done <- proxy.runLimited(context.Background(), stream, func(ctx context.Context) error {
			return proxy.serveWebSocketStream(ctx, stream)
		})
	}()
	if err := writeProxyMetadata(client, proxyWebSocketOpen{
		Version: proxyWireVersion, ConnID: "relay-harness", Path: "/socket",
	}); err != nil {
		t.Fatal(err)
	}
	var opened proxyWebSocketResponse
	if err := readProxyMetadata(client, 1<<20, &opened); err != nil {
		t.Fatal(err)
	}
	if !opened.OK {
		t.Fatalf("open response = %+v", opened)
	}
	return proxyWebSocketRelayHarness{proxy: proxy, client: client, stream: stream, done: done}
}

func awaitProxyWebSocketRelayDone(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("WebSocket handler did not join both relays")
	}
}

func (stream *countingProxyServerTestStream) Reset() error {
	stream.resets.Add(1)
	return stream.Close()
}

type proxyResetTestStream struct {
	net.Conn
	kind     string
	terminal atomic.Pointer[SessionError]
}

func (stream *proxyResetTestStream) markReset() {
	stream.terminal.Store(&SessionError{code: SessionStreamReset})
}
func (stream *proxyResetTestStream) Read(buffer []byte) (int, error) {
	count, err := stream.Conn.Read(buffer)
	if errors.Is(err, io.EOF) && stream.TerminalError() != nil {
		return count, stream.TerminalError()
	}
	return count, err
}
func (stream *proxyResetTestStream) Kind() string { return stream.kind }
func (stream *proxyResetTestStream) TerminalError() *SessionError {
	return stream.terminal.Load()
}
func (*proxyResetTestStream) CloseWrite() error   { return nil }
func (stream *proxyResetTestStream) Reset() error { return stream.Close() }

func (stream *proxyServerTestStream) Kind() string          { return stream.kind }
func (*proxyServerTestStream) TerminalError() *SessionError { return nil }
func (stream *proxyServerTestStream) CloseWrite() error {
	if connection, ok := stream.Conn.(interface{ CloseWrite() error }); ok {
		return connection.CloseWrite()
	}
	return nil
}
func (stream *proxyServerTestStream) Reset() error { return stream.Close() }

var _ proxyStream = (*proxyServerTestStream)(nil)
var _ io.ReadWriteCloser = (*proxyServerTestStream)(nil)

func TestProxyServerPreservesContentCodedRepresentation(t *testing.T) {
	var coded bytes.Buffer
	encoder := gzip.NewWriter(&coded)
	if _, err := encoder.Write([]byte("origin representation")); err != nil {
		t.Fatal(err)
	}
	if err := encoder.Close(); err != nil {
		t.Fatal(err)
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept-Encoding") != "" {
			t.Error("core added Accept-Encoding")
		}
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write(coded.Bytes())
	}))
	defer upstream.Close()
	server, err := NewProxyServer(ProxyServerOptions{Upstream: upstream.URL, UpstreamOrigin: upstream.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	handlers := &StreamHandlerPlanConfig{}
	if err := server.RegisterStreamHandlers(handlers, allowProxyApplicationTestOpen); err != nil {
		t.Fatal(err)
	}
	client := serveProxyTestStream(t, server, handlers, proxyHTTPStreamKind)
	if err := writeProxyMetadata(client, proxyHTTPRequest{Version: proxyWireVersion, RequestID: "coded", Method: "GET", Path: "/"}); err != nil {
		t.Fatal(err)
	}
	if err := writeProxyTerminator(client); err != nil {
		t.Fatal(err)
	}
	var response proxyHTTPResponse
	if err := readProxyMetadata(client, 1<<20, &response); err != nil {
		t.Fatal(err)
	}
	coding := ""
	for _, header := range response.Headers {
		if header.Name == "content-encoding" {
			coding = header.Value
		}
	}
	if !response.OK || coding != "gzip" {
		t.Fatal("lost origin coding", response)
	}
	var body []byte
	var total int64
	for {
		chunk, done, err := readProxyChunk(client, 1<<20, &total, 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		if done {
			break
		}
		body = append(body, chunk...)
	}
	if !bytes.Equal(body, coded.Bytes()) {
		t.Fatal("server transformed coded bytes")
	}
	if _, err = NewProxyServer(ProxyServerOptions{Upstream: upstream.URL, UpstreamOrigin: upstream.URL, BlockedResponseHeaders: []string{"content-encoding"}}); !errors.Is(err, ErrInvalidProxyServer) {
		t.Fatal("policy can erase coding", err)
	}
}

func TestProxyServerPreservesRawTargetAndHeadRepresentationLength(t *testing.T) {
	for _, target := range []string{"/files//secret?x=%2f&x=+&x=%41", "/?", "/objects/a%2Fb/literal%25/a;b/%ff"} {
		t.Run(target, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.RequestURI != target {
					t.Errorf("wire target = %q, want %q", r.RequestURI, target)
				}
				w.Header().Set("Content-Length", "1073741824")
				w.WriteHeader(http.StatusOK)
			}))
			defer upstream.Close()
			handlers := &StreamHandlerPlanConfig{}
			proxy, err := NewProxyServer(ProxyServerOptions{Upstream: upstream.URL, UpstreamOrigin: upstream.URL})
			if err != nil {
				t.Fatal(err)
			}
			defer proxy.Close()
			if err := proxy.RegisterStreamHandlers(handlers, allowProxyApplicationTestOpen); err != nil {
				t.Fatal(err)
			}
			client := serveProxyTestStream(t, proxy, handlers, proxyHTTPStreamKind)
			if err := writeProxyMetadata(client, proxyHTTPRequest{Version: proxyWireVersion, RequestID: "head", Method: http.MethodHead, Path: target}); err != nil {
				t.Fatal(err)
			}
			if err := writeProxyTerminator(client); err != nil {
				t.Fatal(err)
			}
			var response proxyHTTPResponse
			if err := readProxyMetadata(client, 1<<20, &response); err != nil {
				t.Fatal(err)
			}
			if !response.OK || response.Status != http.StatusOK {
				t.Fatalf("response = %+v", response)
			}
			var total int64
			chunk, done, err := readProxyChunk(client, 1<<20, &total, 1<<20)
			if err != nil || !done || len(chunk) != 0 {
				t.Fatalf("HEAD body = %q, done=%v, err=%v", chunk, done, err)
			}
		})
	}
}
