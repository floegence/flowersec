package flowersec

import (
	"context"
	"math"
	"net"
	"testing"
	"time"
)

func TestProxyTimeoutClampsBeforeDurationConversion(t *testing.T) {
	server := &ProxyServer{config: proxyServerConfig{defaultTimeout: time.Second, maxTimeout: 2 * time.Second}}
	for _, value := range []int64{2001, 9223372036855, math.MaxInt64} {
		got, err := server.proxyTimeout(value)
		if err != nil || got != 2*time.Second {
			t.Fatalf("timeout(%d) = %s, %v", value, got, err)
		}
	}
	_, err := NewProxyServer(ProxyServerOptions{
		Upstream: "http://127.0.0.1:1", UpstreamOrigin: "http://127.0.0.1:1",
		DefaultHTTPRequestTimeout: 2 * time.Second, MaxHTTPRequestTimeout: time.Second,
	})
	if err == nil {
		t.Fatal("accepted default timeout above maximum")
	}
}

func TestProxyDeadlineBoundsIncompleteMetadataAndBody(t *testing.T) {
	for _, method := range []string{"", "GET", "HEAD", "POST"} {
		t.Run(method, func(t *testing.T) {
			proxy, err := NewProxyServer(ProxyServerOptions{
				Upstream: "http://127.0.0.1:1", UpstreamOrigin: "http://127.0.0.1:1",
				DefaultHTTPRequestTimeout: 30 * time.Millisecond, MaxHTTPRequestTimeout: 30 * time.Millisecond,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer proxy.Close()
			local, remote := net.Pipe()
			defer remote.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan struct{})
			go func() {
				defer close(done)
				proxy.serveHTTP(ctx, IncomingStream{Stream: &proxyServerTestStream{Conn: local, kind: proxyHTTPStreamKind}})
			}()
			if method != "" {
				if err := writeProxyJSON(remote, proxyHTTPRequest{Version: proxyWireVersion, RequestID: "stalled", Method: method, Path: "/", TimeoutMS: 20}); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case <-done:
			case <-time.After(time.Second):
				cancel()
				remote.Close()
				<-done
				t.Fatal("incomplete request outlived deadline")
			}
		})
	}
}
