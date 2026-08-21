package flowersec_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	flowersec "github.com/floegence/flowersec/flowersec-go/v3"
	"github.com/floegence/flowersec/flowersec-go/v3/controlplane"
)

func TestWebSocketHTTPServerRejectsUnsafeConstructionAndFixesTLSProfile(t *testing.T) {
	acceptor := testWebSocketAcceptor(t)
	serverTLS, _ := testWebSocketTLS(t)
	serverTLS.MinVersion = tls.VersionTLS12
	serverTLS.MaxVersion = tls.VersionTLS13
	serverTLS.SessionTicketsDisabled = false
	original := serverTLS.Clone()
	server, err := flowersec.NewWebSocketHTTPServer(flowersec.WebSocketHTTPServerOptions{
		Handler:   acceptor.Handler(),
		TLSConfig: serverTLS,
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = server
	if serverTLS.MinVersion != original.MinVersion || serverTLS.MaxVersion != original.MaxVersion || serverTLS.SessionTicketsDisabled != original.SessionTicketsDisabled {
		t.Fatal("NewWebSocketHTTPServer mutated caller TLS configuration")
	}

	for name, config := range map[string]*tls.Config{
		"missing certificate": {MinVersion: tls.VersionTLS13},
		"dynamic config": {
			MinVersion:   tls.VersionTLS13,
			Certificates: serverTLS.Certificates,
			GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
				return &tls.Config{MinVersion: tls.VersionTLS12}, nil
			},
		},
		"custom session ticket callbacks": {
			MinVersion: tls.VersionTLS13, Certificates: serverTLS.Certificates,
			WrapSession:   func(tls.ConnectionState, *tls.SessionState) ([]byte, error) { return nil, nil },
			UnwrapSession: func([]byte, tls.ConnectionState) (*tls.SessionState, error) { return nil, nil },
		},
	} {
		t.Run(name, func(t *testing.T) {
			if got, err := flowersec.NewWebSocketHTTPServer(flowersec.WebSocketHTTPServerOptions{Handler: acceptor.Handler(), TLSConfig: config}); err == nil || got != nil {
				t.Fatal("unsafe WebSocket TLS configuration unexpectedly succeeded")
			}
		})
	}
	if _, err := flowersec.NewWebSocketHTTPServer(flowersec.WebSocketHTTPServerOptions{Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), TLSConfig: serverTLS}); err == nil {
		t.Fatal("non-Flowersec handler unexpectedly accepted")
	}
	for name, mutate := range map[string]func(*flowersec.WebSocketHTTPServerOptions){
		"read header": func(options *flowersec.WebSocketHTTPServerOptions) { options.ReadHeaderTimeout = -time.Second },
		"read":        func(options *flowersec.WebSocketHTTPServerOptions) { options.ReadTimeout = -time.Second },
		"write":       func(options *flowersec.WebSocketHTTPServerOptions) { options.WriteTimeout = -time.Second },
		"idle":        func(options *flowersec.WebSocketHTTPServerOptions) { options.IdleTimeout = -time.Second },
	} {
		t.Run("negative "+name+" timeout", func(t *testing.T) {
			options := flowersec.WebSocketHTTPServerOptions{Handler: acceptor.Handler(), TLSConfig: serverTLS}
			mutate(&options)
			if server, err := flowersec.NewWebSocketHTTPServer(options); err == nil || server != nil {
				t.Fatal("negative WebSocket server timeout unexpectedly accepted")
			}
		})
	}
	response := httptest.NewRecorder()
	acceptor.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, flowersec.WebSocketDirectPath, nil))
	if response.Code != http.StatusForbidden {
		t.Fatalf("raw Acceptor.Handler status = %d, want fail-closed 403", response.Code)
	}
	runtime, err := flowersec.NewTunnelRuntime(flowersec.TunnelRuntimeOptions{
		AllowedOrigins: []string{"https://app.example"}, Listeners: []flowersec.TunnelListener{flowersec.NewWebSocketTunnelListener()},
		Authorize: func(context.Context, controlplane.RuntimeAuthorizationRequest) (controlplane.TunnelAuthorizationResponse, error) {
			return controlplane.TunnelAuthorizationResponse{}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := flowersec.NewWebSocketHTTPServer(flowersec.WebSocketHTTPServerOptions{Handler: runtime.Handler(), TLSConfig: serverTLS}); err != nil {
		t.Fatalf("tunnel Handler wrapper = %v", err)
	}
}

func TestWebSocketHTTPServerDisablesTLS13ResumptionAcrossConnections(t *testing.T) {
	acceptor := testWebSocketAcceptor(t)
	serverTLS, roots := testWebSocketTLS(t)
	serverTLS.NextProtos = []string{"h2"}
	var resumed atomic.Int32
	serverTLS.VerifyConnection = func(state tls.ConnectionState) error {
		if state.Version != tls.VersionTLS13 {
			return fmt.Errorf("server negotiated TLS %x", state.Version)
		}
		if state.NegotiatedProtocol != "http/1.1" {
			return fmt.Errorf("server negotiated ALPN %q", state.NegotiatedProtocol)
		}
		if state.DidResume {
			resumed.Add(1)
		}
		return nil
	}
	server, err := flowersec.NewWebSocketHTTPServer(flowersec.WebSocketHTTPServerOptions{Handler: acceptor.Handler(), TLSConfig: serverTLS})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(listener) }()
	defer func() {
		_ = server.Close()
		<-serveDone
	}()

	cache := &recordingSessionCache{}
	clientTLS := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "localhost", ClientSessionCache: cache}
	for attempt := 0; attempt < 2; attempt++ {
		connection, dialErr := tls.Dial("tcp", listener.Addr().String(), clientTLS)
		if dialErr != nil {
			t.Fatalf("TLS connection %d: %v", attempt+1, dialErr)
		}
		_, _ = fmt.Fprintf(connection, "GET %s HTTP/1.1\r\nHost: localhost\r\nOrigin: https://app.example\r\nConnection: close\r\n\r\n", flowersec.WebSocketDirectPath)
		_, _ = io.ReadAll(connection)
		_ = connection.Close()
	}
	if got := resumed.Load(); got != 0 {
		t.Fatalf("resumed TLS connections = %d, want 0", got)
	}
	if got := cache.puts.Load(); got != 0 {
		t.Fatalf("TLS session tickets cached by client = %d, want 0", got)
	}

	legacyClient := clientTLS.Clone()
	legacyClient.MaxVersion = tls.VersionTLS12
	if connection, dialErr := tls.Dial("tcp", listener.Addr().String(), legacyClient); dialErr == nil {
		_ = connection.Close()
		t.Fatal("TLS 1.2 connection unexpectedly succeeded")
	}
}

type recordingSessionCache struct {
	mu    sync.Mutex
	state *tls.ClientSessionState
	puts  atomic.Int32
}

func (cache *recordingSessionCache) Get(string) (*tls.ClientSessionState, bool) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if cache.state == nil {
		return nil, false
	}
	return cache.state, true
}

func (cache *recordingSessionCache) Put(_ string, state *tls.ClientSessionState) {
	cache.mu.Lock()
	cache.state = state
	cache.mu.Unlock()
	cache.puts.Add(1)
}

func testWebSocketAcceptor(t *testing.T) *flowersec.Acceptor {
	t.Helper()
	acceptor, err := flowersec.NewAcceptor(flowersec.AcceptorOptions{
		AllowedOrigins: []string{"https://app.example"},
		Authorize: func(context.Context, controlplane.RuntimeAuthorizationRequest) (controlplane.AuthorizationResponse, error) {
			return controlplane.AuthorizationResponse{}, nil
		},
		OnSession: func(context.Context, flowersec.Session, string) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	return acceptor
}

func testWebSocketTLS(t *testing.T) (*tls.Config, *x509.CertPool) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: privateKey}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})) {
		t.Fatal("failed to build test trust roots")
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}}, roots
}
