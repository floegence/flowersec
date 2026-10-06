package flowersec

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/egress"
)

func TestConnectorExplicitHTTPSProxy(t *testing.T) {
	for _, allowed := range []bool{true, false} {
		t.Run(map[bool]string{true: "allowed", false: "denied"}[allowed], func(t *testing.T) {
			serverTLS, roots := controllerNetworkTLS(t)
			source := &webSocketHandlerRestartSource{serverTLS: serverTLS}
			defer source.stopAll()
			lease, acquisitionErr := source.Acquire(t.Context())
			if acquisitionErr != nil {
				t.Fatal(acquisitionErr)
			}
			var proxyCalls atomic.Int32
			proxy := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				proxyCalls.Add(1)
				if !allowed {
					http.Error(w, "denied", http.StatusForbidden)
					return
				}
				if r.Method != http.MethodConnect {
					http.Error(w, "CONNECT required", http.StatusMethodNotAllowed)
					return
				}
				upstream, err := net.Dial("tcp", r.Host)
				if err != nil {
					t.Error(err)
					return
				}
				defer upstream.Close()
				client, buffered, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Error(err)
					return
				}
				defer client.Close()
				_, _ = buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
				_ = buffered.Flush()
				done := make(chan struct{})
				go func() { _, _ = io.Copy(upstream, buffered); _ = upstream.Close(); close(done) }()
				_, _ = io.Copy(client, upstream)
				_ = client.Close()
				<-done
			}))
			defer proxy.Close()
			proxyRoots := x509.NewCertPool()
			proxyRoots.AddCert(proxy.Certificate())
			proxyRoute, err := egress.NewHTTPSProxy(egress.HTTPSProxyOptions{URL: proxy.URL, TLSConfig: &tls.Config{RootCAs: proxyRoots}})
			if err != nil {
				t.Fatal(err)
			}
			handlers := NewRPCHandlers()
			if err := handlers.HandleRPC(controllerClientRPC, func(context.Context, json.RawMessage) (any, *RPCError) { return "through proxy", nil }); err != nil {
				t.Fatal(err)
			}
			current, err := Connect(t.Context(), lease, ConnectorOptions{TrustRoots: roots, Origin: "https://client.example", ConnectTimeout: 3 * time.Second, HTTPSProxy: proxyRoute, RPCHandlers: handlers})
			if !allowed {
				if err == nil {
					current.Close()
					t.Fatal("proxy denial fell back to reachable direct endpoint")
				}
				if proxyCalls.Load() != 1 {
					t.Fatalf("proxy attempts=%d", proxyCalls.Load())
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer current.Close()
			peer := source.takeGeneration(t, 0).waitSession(t)
			defer peer.Close()
			var response string
			if err := peer.RPC().Call(t.Context(), controllerClientRPC, nil, &response); err != nil || response != "through proxy" {
				t.Fatalf("RPC=%q err=%v", response, err)
			}
			if proxyCalls.Load() != 1 {
				t.Fatalf("proxy attempts=%d", proxyCalls.Load())
			}
		})
	}
}

func TestConnectorProxyRejectsQUICBeforeDialOrSpend(t *testing.T) {
	serverTLS, roots := controllerNetworkTLS(t)
	source := &networkRestartSource{serverTLS: serverTLS}
	defer source.stopAll()
	lease, acquisitionErr := source.Acquire(t.Context())
	if acquisitionErr != nil {
		t.Fatal(acquisitionErr)
	}
	var spends atomic.Int32
	lease, err := NewArtifactLease(lease.artifact, func(context.Context) error { spends.Add(1); return nil })
	if err != nil {
		t.Fatal(err)
	}
	var proxyCalls atomic.Int32
	proxy := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { proxyCalls.Add(1); w.WriteHeader(http.StatusForbidden) }))
	defer proxy.Close()
	proxyRoots := x509.NewCertPool()
	proxyRoots.AddCert(proxy.Certificate())
	route, err := egress.NewHTTPSProxy(egress.HTTPSProxyOptions{URL: proxy.URL, TLSConfig: &tls.Config{RootCAs: proxyRoots}})
	if err != nil {
		t.Fatal(err)
	}
	current, err := Connect(t.Context(), lease, ConnectorOptions{TrustRoots: roots, HTTPSProxy: route, ConnectTimeout: time.Second})
	if err == nil {
		current.Close()
		t.Fatal("QUIC bypassed explicit proxy route")
	}
	if proxyCalls.Load() != 0 || spends.Load() != 0 {
		t.Fatalf("unsupported route attempted: proxy=%d spends=%d", proxyCalls.Load(), spends.Load())
	}
}
