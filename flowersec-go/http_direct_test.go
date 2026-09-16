package flowersec_test

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	flowersec "github.com/floegence/flowersec/flowersec-go/v5"
	"github.com/floegence/flowersec/flowersec-go/v5/controlplane"
)

func TestTLSWebSocketServerServesApplicationOnSamePort(t *testing.T) {
	serverTLS, roots := testWebSocketTLS(t)
	server, err := flowersec.NewWebSocketHTTPServer(flowersec.WebSocketHTTPServerOptions{
		Handler: testWebSocketAcceptor(t).Handler(), TLSConfig: serverTLS,
		ApplicationHandler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "secure application") }),
	})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	defer func() { _ = server.Close(); <-done }()
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS13}}
	defer transport.CloseIdleConnections()
	response, err := (&http.Client{Transport: transport, Timeout: time.Second}).Get("https://" + listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil || string(body) != "secure application" {
		t.Fatalf("TLS application: %s %v", body, err)
	}
}

func TestHTTPDirectSharesApplicationPortWithoutRelaxingTLSServer(t *testing.T) {
	acceptor := testWebSocketAcceptor(t)
	app := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "application")
	})
	handler, err := acceptor.HTTPDirectHandler(flowersec.HTTPDirectHandlerOptions{
		AuthorizeRequest: func(*http.Request) bool { return true },
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := flowersec.NewWebSocketHTTPServer(flowersec.WebSocketHTTPServerOptions{Handler: handler}); err == nil {
		t.Fatal("TLS server accepted an HTTP-only handler")
	}
	if _, err := flowersec.NewHTTPDirectServer(flowersec.HTTPDirectServerOptions{Handler: acceptor.Handler()}); err == nil {
		t.Fatal("HTTP server accepted a TLS handler")
	}
	server, err := flowersec.NewHTTPDirectServer(flowersec.HTTPDirectServerOptions{Handler: handler, ApplicationHandler: app})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	defer func() { _ = server.Close(); <-done }()
	response, err := http.Get("http://" + listener.Addr().String() + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil || response.StatusCode != 200 || string(body) != "application" {
		t.Fatalf("application response: %d %s %v", response.StatusCode, body, err)
	}
	response, err = http.Get("http://" + listener.Addr().String() + flowersec.WebSocketDirectPath)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("unadmitted direct route = %d", response.StatusCode)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestIssueHTTPDirectAcceptsNetworkEndpointsWithoutPrivateCapability(t *testing.T) {
	for _, endpoint := range []string{"ws://192.168.1.20:23998/flowersec/v3/direct", "ws://localhost:23998/flowersec/v3/direct", "ws://[2001:db8::1]:23998/flowersec/v3/direct", "ws://localhost/flowersec/v3/direct", "ws://localhost:443/flowersec/v3/direct"} {
		issued, err := controlplane.NewIssuer().IssueHTTPDirect(controlplane.HTTPDirectIssueOptions{
			Session:  controlplane.SessionOptions{ChannelID: "http-client", ExpiresAt: time.Now().Add(time.Minute)},
			Endpoint: endpoint, RendezvousGroupID: "group", ListenerAudience: "http-direct", UpstreamAddress: "127.0.0.1:23998",
		})
		if err != nil {
			t.Fatalf("%s: %v", endpoint, err)
		}
		if issued.LookupKey() == "" || len(issued.ArtifactJSON()) == 0 {
			t.Fatal("missing independent authorization")
		}
		if _, err := flowersec.ParseArtifact(issued.ArtifactJSON()); err == nil {
			t.Fatal("TLS artifact parser accepted HTTP profile")
		}
	}
}

func TestHTTPDirectRequiresExplicitRequestAdmission(t *testing.T) {
	acceptor := testWebSocketAcceptor(t)
	if _, err := acceptor.HTTPDirectHandler(flowersec.HTTPDirectHandlerOptions{}); err == nil {
		t.Fatal("missing authorization callback accepted")
	}
	var calls atomic.Int32
	handler, err := acceptor.HTTPDirectHandler(flowersec.HTTPDirectHandlerOptions{
		AuthorizeRequest: func(*http.Request) bool { calls.Add(1); return false },
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, flowersec.WebSocketDirectPath, nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || calls.Load() != 0 {
		t.Fatal("HTTP handler accepted installation outside its owned server")
	}
	server, err := flowersec.NewHTTPDirectServer(flowersec.HTTPDirectServerOptions{Handler: handler})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	defer func() { _ = server.Close(); <-done }()
	origin := "http://" + listener.Addr().String()
	for _, requestedOrigin := range []string{"", "http://192.168.1.20:23998", origin} {
		r, err := http.NewRequest(http.MethodGet, origin+flowersec.WebSocketDirectPath, nil)
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Connection", "Upgrade")
		r.Header.Set("Upgrade", "websocket")
		r.Header.Set("Sec-WebSocket-Version", "13")
		r.Header.Set("Sec-WebSocket-Protocol", "flowersec.direct.v3")
		r.Header.Set("Sec-WebSocket-Key", "MDEyMzQ1Njc4OWFiY2RlZg==")
		r.Header.Set("Origin", requestedOrigin)
		resp, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("unadmitted origin %q: %d", requestedOrigin, resp.StatusCode)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("invalid origins reached authorization: %d calls", calls.Load())
	}
}
