package flowersec

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestProxyServerHTTPRoundTripUsesSessionHandlers(t *testing.T) {
	var wantHost string
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.RequestURI() != "/files?id=7" {
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

	handlers, err := NewSessionHandlers(SessionHandlerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	proxy, err := NewProxyServer(ProxyServerOptions{
		Upstream: upstream.URL, UpstreamOrigin: upstream.URL,
		AllowedOrigins:         []string{"https://app.example"},
		BlockedResponseHeaders: []string{"x-frame-options"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	if err := proxy.Register(handlers); err != nil {
		t.Fatal(err)
	}

	client := serveProxyTestStream(t, handlers, proxyHTTPStreamKind)
	if err := writeProxyJSON(client, proxyHTTPRequest{
		Version: proxyWireVersion, RequestID: "request-1", Method: http.MethodGet,
		Path: "/files?id=7", Headers: []proxyHeader{{Name: "accept", Value: "text/plain"}},
		ExternalOrigin: "https://app.example",
	}); err != nil {
		t.Fatal(err)
	}
	if err := writeProxyTerminator(client); err != nil {
		t.Fatal(err)
	}
	var response proxyHTTPResponse
	if err := readProxyJSON(client, 1<<20, &response); err != nil {
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

func TestProxyServerWebSocketRoundTripUsesFlowersecWire(t *testing.T) {
	upgrader := websocket.Upgrader{
		CheckOrigin: func(request *http.Request) bool { return request.Header.Get("Origin") != "" },
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
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

	handlers, err := NewSessionHandlers(SessionHandlerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	proxy, err := NewProxyServer(ProxyServerOptions{Upstream: upstream.URL, UpstreamOrigin: upstream.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	if err := proxy.Register(handlers); err != nil {
		t.Fatal(err)
	}

	client := serveProxyTestStream(t, handlers, proxyWSStreamKind)
	if err := writeProxyJSON(client, proxyWebSocketOpen{
		Version: proxyWireVersion, ConnID: "socket-1", Path: "/socket",
	}); err != nil {
		t.Fatal(err)
	}
	var opened proxyWebSocketResponse
	if err := readProxyJSON(client, 1<<20, &opened); err != nil {
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
	handler := proxy.limit(func(ctx context.Context, incoming IncomingStream) error {
		proxy.serveHTTP(ctx, incoming)
		return nil
	})
	done := make(chan error, 1)
	go func() {
		done <- handler(context.Background(), IncomingStream{
			Kind: proxyHTTPStreamKind, Metadata: EmptyStreamMetadata(), Stream: stream,
		})
	}()
	if err := writeProxyJSON(client, proxyHTTPRequest{
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
	handlers, err := NewSessionHandlers(SessionHandlerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := proxy.Register(handlers); !errors.Is(err, ErrInvalidProxyServer) {
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
		proxy.serveHTTP(context.Background(), IncomingStream{
			Kind: proxyHTTPStreamKind, Metadata: EmptyStreamMetadata(), Stream: stream,
		})
		close(done)
	}()
	if err := writeProxyJSON(client, proxyHTTPRequest{
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
			if err := writeProxyJSON(client, proxyHTTPRequest{
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
			handler := proxy.limit(func(ctx context.Context, incoming IncomingStream) error {
				close(started)
				proxy.serveHTTP(ctx, incoming)
				return nil
			})
			go func() {
				_ = handler(context.Background(), IncomingStream{
					Kind: proxyHTTPStreamKind, Metadata: EmptyStreamMetadata(),
					Stream: &proxyServerTestStream{Conn: server, kind: proxyHTTPStreamKind},
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
	handlers, _ := NewSessionHandlers(SessionHandlerOptions{})
	proxy, err := NewProxyServer(ProxyServerOptions{Upstream: "http://127.0.0.1:8080", UpstreamOrigin: "http://127.0.0.1:8080"})
	if err != nil {
		t.Fatal(err)
	}
	if err := proxy.Register(handlers); err != nil {
		t.Fatal(err)
	}
	if err := proxy.Register(handlers); !errors.Is(err, ErrInvalidProxyServer) {
		t.Fatalf("duplicate Register error = %v", err)
	}
}

func serveProxyTestStream(t *testing.T, handlers *SessionHandlers, kind string) net.Conn {
	t.Helper()
	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	session := &serverTestSession{incoming: make(chan IncomingStream, 1), closed: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() { done <- handlers.Serve(ctx, session) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("SessionHandlers did not stop")
		}
	})
	session.incoming <- IncomingStream{Kind: kind, Metadata: EmptyStreamMetadata(), Stream: &proxyServerTestStream{Conn: server, kind: kind}}
	return client
}

type proxyServerTestStream struct {
	net.Conn
	kind string
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

var _ ByteStream = (*proxyServerTestStream)(nil)
var _ io.ReadWriteCloser = (*proxyServerTestStream)(nil)
