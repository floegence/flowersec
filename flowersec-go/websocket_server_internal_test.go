package flowersec

import (
	"crypto/tls"
	"net/http"
	"testing"
	"time"
)

func TestWebSocketHTTPServerAppliesBoundedDefaultHeaderTimeout(t *testing.T) {
	handler := &webSocketBoundary{handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), enabled: true}
	server, err := NewWebSocketHTTPServer(WebSocketHTTPServerOptions{
		Handler: handler,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{{
			Certificate: [][]byte{{1}},
		}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if server.httpServer.ReadHeaderTimeout != defaultWebSocketReadHeaderTimeout {
		t.Fatalf("default read-header timeout = %s, want %s", server.httpServer.ReadHeaderTimeout, defaultWebSocketReadHeaderTimeout)
	}
	if server.httpServer.ReadHeaderTimeout <= 0 || server.httpServer.ReadHeaderTimeout > 10*time.Second {
		t.Fatalf("default read-header timeout is not safely bounded: %s", server.httpServer.ReadHeaderTimeout)
	}
}
