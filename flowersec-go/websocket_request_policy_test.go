package flowersec_test

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	flowersec "github.com/floegence/flowersec/flowersec-go/v5"
	"github.com/floegence/flowersec/flowersec-go/v5/controlplane"
	carrierws "github.com/floegence/flowersec/flowersec-go/v5/internal/carrier/websocketv3"
	gorillaws "github.com/gorilla/websocket"
)

func TestWebSocketHTTPServerRequestPolicy(t *testing.T) {
	for _, tunnel := range []bool{false, true} {
		path, protocol := flowersec.WebSocketDirectPath, carrierws.SubprotocolDirect
		if tunnel {
			path, protocol = flowersec.WebSocketTunnelPath, carrierws.SubprotocolTunnel
		}
		t.Run(path, func(t *testing.T) {
			for _, enforce := range []bool{false, true} {
				name := "default"
				if enforce {
					name = "restricted"
				}
				t.Run(name, func(t *testing.T) {
					var authorizations, policies atomic.Int32
					var handler http.Handler
					if tunnel {
						runtime, err := flowersec.NewTunnelRuntime(flowersec.TunnelRuntimeOptions{
							AllowedOrigins: []string{"https://app.example"},
							Listeners:      []flowersec.TunnelListener{flowersec.NewWebSocketTunnelListener()},
							Authorize: func(context.Context, controlplane.RuntimeAuthorizationRequest) (controlplane.TunnelAuthorizationResponse, error) {
								authorizations.Add(1)
								return controlplane.TunnelAuthorizationResponse{}, nil
							},
						})
						if err != nil {
							t.Fatal(err)
						}
						handler = runtime.Handler()
					} else {
						acceptor, err := flowersec.NewAcceptor(flowersec.AcceptorOptions{
							AllowedOrigins: []string{"https://app.example"},
							Authorize: func(context.Context, controlplane.RuntimeAuthorizationRequest) (controlplane.AuthorizationResponse, error) {
								authorizations.Add(1)
								return controlplane.AuthorizationResponse{}, nil
							},
							OnSession: func(context.Context, flowersec.Session, string) error { return nil },
						})
						if err != nil {
							t.Fatal(err)
						}
						handler = acceptor.Handler()
					}
					serverTLS, roots := testWebSocketTLS(t)
					listener, err := net.Listen("tcp4", "127.0.0.1:0")
					if err != nil {
						t.Fatal(err)
					}
					defer listener.Close()
					authority := listener.Addr().String()
					options := flowersec.WebSocketHTTPServerOptions{
						Handler: handler, TLSConfig: serverTLS,
						ApplicationHandler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }),
					}
					if enforce {
						options.AuthorizeWebSocketRequest = func(r *http.Request) bool {
							policies.Add(1)
							return r.Host == authority
						}
					}
					server, err := flowersec.NewWebSocketHTTPServer(options)
					if err != nil {
						t.Fatal(err)
					}
					done := make(chan error, 1)
					go func() { done <- server.Serve(listener) }()
					defer func() { _ = server.Close(); <-done }()
					clientTLS := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "localhost"}
					dialer := gorillaws.Dialer{TLSClientConfig: clientTLS, Subprotocols: []string{protocol}, HandshakeTimeout: time.Second}
					for _, request := range []struct {
						host, origin string
						want         int
					}{
						{authority, "https://app.example", http.StatusSwitchingProtocols},
						{"unlisted.example:443", "https://app.example", map[bool]int{false: http.StatusSwitchingProtocols, true: http.StatusForbidden}[enforce]},
						{authority, "https://untrusted.example", http.StatusForbidden},
					} {
						conn, response, dialErr := dialer.Dial("wss://"+authority+path, http.Header{"Host": []string{request.host}, "Origin": []string{request.origin}})
						if conn != nil {
							_ = conn.Close()
						}
						if response == nil {
							t.Fatalf("handshake: %v", dialErr)
						}
						response.Body.Close()
						if response.StatusCode != request.want {
							t.Fatalf("Host %s Origin %s: status %d, want %d", request.host, request.origin, response.StatusCode, request.want)
						}
					}
					if got := authorizations.Load(); got != 0 {
						t.Fatalf("unauthenticated requests reached session authorization %d times", got)
					}
					before := policies.Load()
					if enforce && before != 3 {
						t.Fatalf("request policy calls = %d, want 3", before)
					}
					client := &http.Client{Transport: &http.Transport{TLSClientConfig: clientTLS}, Timeout: time.Second}
					defer client.CloseIdleConnections()
					response, err := client.Get("https://" + authority + "/health")
					if err != nil {
						t.Fatal(err)
					}
					response.Body.Close()
					if response.StatusCode != http.StatusNoContent || policies.Load() != before {
						t.Fatal("WebSocket request policy changed application routing")
					}
				})
			}
		})
	}
}
