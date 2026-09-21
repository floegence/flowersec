package flowersec

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestProxyEventStreamOutlivesFiniteResponseLimits(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
		for i := 0; i < 8; i++ {
			_, _ = w.Write([]byte("data: alive\n\n"))
			w.(http.Flusher).Flush()
			select {
			case <-r.Context().Done():
				return
			case <-time.After(25 * time.Millisecond):
			}
		}
	}))
	defer upstream.Close()
	proxy, err := NewProxyServer(ProxyServerOptions{
		Upstream: upstream.URL, UpstreamOrigin: upstream.URL,
		MaxBodyBytes: 16, DefaultHTTPRequestTimeout: 100 * time.Millisecond, MaxHTTPRequestTimeout: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	handlers, _ := NewSessionHandlers(SessionHandlerOptions{})
	if err := proxy.RegisterStreamHandlers(handlers); err != nil {
		t.Fatal(err)
	}
	client := serveProxyTestStream(t, handlers, proxyHTTPStreamKind)
	if err := writeProxyJSON(client, proxyHTTPRequest{Version: proxyWireVersion, RequestID: "events", Method: "GET", Path: "/", Headers: []proxyHeader{{Name: "accept", Value: "text/event-stream"}}}); err != nil {
		t.Fatal(err)
	}
	if err := writeProxyTerminator(client); err != nil {
		t.Fatal(err)
	}
	var response proxyHTTPResponse
	if err := readProxyJSON(client, 1<<20, &response); err != nil {
		t.Fatal(err)
	}
	if !response.OK {
		t.Fatalf("response: %+v", response)
	}
	var total int64
	for {
		_, done, err := readProxyChunk(client, 1<<20, &total, 1<<20)
		if err != nil {
			t.Fatalf("active event stream ended after %d bytes: %v", total, err)
		}
		if done {
			break
		}
	}
	if total != 8*13 {
		t.Fatalf("received %d bytes", total)
	}
}

func TestProxyEventCapacityPreservesFiniteRequestsAndReleasesCanceledObservers(t *testing.T) {
	canceled := make(chan struct{}, 16)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/events" {
			w.Header().Set("Content-Type", "text/event-stream")
			w.(http.Flusher).Flush()
			<-r.Context().Done()
			canceled <- struct{}{}
		} else {
			_, _ = w.Write([]byte("ok"))
		}
	}))
	defer upstream.Close()
	proxy, err := NewProxyServer(ProxyServerOptions{Upstream: upstream.URL, UpstreamOrigin: upstream.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	handlers, _ := NewSessionHandlers(SessionHandlerOptions{})
	if err := proxy.RegisterStreamHandlers(handlers); err != nil {
		t.Fatal(err)
	}
	open := func(path string) (net.Conn, proxyHTTPResponse) {
		t.Helper()
		client, peer := net.Pipe()
		t.Cleanup(func() { client.Close(); peer.Close() })
		go proxy.limit(func(ctx context.Context, incoming IncomingStream) error {
			proxy.serveHTTP(ctx, incoming)
			return nil
		})(context.Background(), IncomingStream{Stream: &resetEventTestStream{proxyServerTestStream{Conn: peer, kind: proxyHTTPStreamKind}}})
		var headers []proxyHeader
		if path == "/events" {
			headers = []proxyHeader{{Name: "accept", Value: "text/event-stream"}}
		}
		if err := writeProxyJSON(client, proxyHTTPRequest{Version: proxyWireVersion, RequestID: "capacity", Method: "GET", Path: path, Headers: headers}); err != nil {
			t.Fatal(err)
		}
		if err := writeProxyTerminator(client); err != nil {
			t.Fatal(err)
		}
		var response proxyHTTPResponse
		if err := readProxyJSON(client, 1<<20, &response); err != nil {
			t.Fatal(err)
		}
		return client, response
	}
	var clients []net.Conn
	for i := 0; i < 16; i++ {
		client, response := open("/events")
		clients = append(clients, client)
		if !response.OK {
			t.Fatalf("subscription %d: %+v", i, response)
		}
	}
	rejected, response := open("/events")
	if response.OK || response.Error == nil || response.Error.Code != "resource_exhausted" {
		t.Fatalf("exhausted response: %+v", response)
	}
	rejected.Close()
	finite, response := open("/api")
	if !response.OK || response.Status != 200 {
		t.Fatalf("finite response: %+v", response)
	}
	finite.Close()
	for _, client := range clients {
		client.Close()
	}
	for range clients {
		select {
		case <-canceled:
		case <-time.After(time.Second):
			t.Fatal("upstream observer survived cancellation")
		}
	}
	if err := proxy.Close(); err != nil {
		t.Fatal(err)
	}
	if len(proxy.eventPermits) != 0 || len(proxy.httpPermits) != 0 {
		t.Fatal("leaked permits")
	}
}

// A reset is distinct from a FIN (io.EOF), which closes only request writes.
type resetEventTestStream struct{ proxyServerTestStream }

func (s *resetEventTestStream) Read(p []byte) (int, error) {
	n, err := s.Conn.Read(p)
	if errors.Is(err, io.EOF) {
		err = io.ErrClosedPipe
	}
	return n, err
}
