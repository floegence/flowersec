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
	carrierws "github.com/floegence/flowersec/flowersec-go/v3/internal/carrier/websocketv3"
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

func TestWebSocketHTTPServerCloseTerminatesSilentAdmissionAndReleasesCapacity(t *testing.T) {
	var authorizations atomic.Int32
	acceptor, err := flowersec.NewAcceptor(flowersec.AcceptorOptions{
		AllowedOrigins:    []string{"https://consumer.example"},
		MaxDirectSessions: 1,
		Authorize: func(context.Context, controlplane.RuntimeAuthorizationRequest) (controlplane.AuthorizationResponse, error) {
			authorizations.Add(1)
			return controlplane.AuthorizationResponse{}, nil
		},
		OnSession: func(context.Context, flowersec.Session, string) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	serverTLS, roots := acceptorListenerTLS(t)
	server, err := startWebSocketTestServer(acceptor.Handler(), serverTLS)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.Close)

	silent := dialAdmissionWebSocket(t, server.URL, flowersec.WebSocketDirectPath, carrierws.SubprotocolDirect, roots)
	capacityProbe := dialAdmissionWebSocket(t, server.URL, flowersec.WebSocketDirectPath, carrierws.SubprotocolDirect, roots)
	_ = capacityProbe.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, readErr := capacityProbe.ReadMessage(); readErr == nil {
		t.Fatal("capacity probe remained open while the silent admission owned the only direct slot")
	} else if networkErr, ok := readErr.(net.Error); ok && networkErr.Timeout() {
		t.Fatal("silent admission did not acquire the direct slot before shutdown")
	}

	closeDone := make(chan error, 1)
	go func() { closeDone <- server.endpoint.Close() }()
	select {
	case closeErr := <-closeDone:
		if closeErr != nil {
			t.Fatal(closeErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not terminate the silent upgraded connection")
	}
	_ = silent.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, readErr := silent.ReadMessage(); readErr == nil {
		t.Fatal("silent upgraded connection remained open after Close")
	} else if networkErr, ok := readErr.(net.Error); ok && networkErr.Timeout() {
		t.Fatal("timed out waiting for Close to terminate the silent upgraded connection")
	}
	if got := authorizations.Load(); got != 0 {
		t.Fatalf("silent admission authorizations = %d, want 0", got)
	}

	replacement, err := startWebSocketTestServer(acceptor.Handler(), serverTLS)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(replacement.Close)
	reusedSlot := dialAdmissionWebSocket(t, replacement.URL, flowersec.WebSocketDirectPath, carrierws.SubprotocolDirect, roots)
	_ = reusedSlot.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if _, _, readErr := reusedSlot.ReadMessage(); readErr == nil {
		t.Fatal("silent replacement admission unexpectedly produced a message")
	} else if networkErr, ok := readErr.(net.Error); !ok || !networkErr.Timeout() {
		t.Fatalf("replacement admission could not reuse released direct capacity: %v", readErr)
	}
}

func TestWebSocketHTTPServerShutdownWaitsForEstablishedHandlerAndLeaseRelease(t *testing.T) {
	var record controlplane.AuthorizationRecord
	sessionStarted := make(chan struct{})
	sessionStopped := make(chan struct{})
	releases := make(chan struct {
		leaseID string
		ctxErr  error
	}, 1)
	acceptor, err := flowersec.NewAcceptor(flowersec.AcceptorOptions{
		AllowedOrigins: []string{"https://consumer.example"},
		Authorize: func(_ context.Context, request controlplane.RuntimeAuthorizationRequest) (controlplane.AuthorizationResponse, error) {
			return controlplane.AuthorizeRuntime(request, record, "lease-websocket-shutdown")
		},
		Release: func(ctx context.Context, leaseID string) {
			releases <- struct {
				leaseID string
				ctxErr  error
			}{leaseID: leaseID, ctxErr: ctx.Err()}
		},
		OnSession: func(ctx context.Context, _ flowersec.Session, _ string) error {
			close(sessionStarted)
			<-ctx.Done()
			close(sessionStopped)
			return context.Cause(ctx)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	serverTLS, _ := acceptorListenerTLS(t)
	server, err := startWebSocketTestServer(acceptor.Handler(), serverTLS)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.Close)
	issued, err := controlplane.NewIssuer().IssueDirect(controlplane.DirectIssueOptions{
		Session:           controlplane.SessionOptions{ChannelID: "websocket-shutdown", ExpiresAt: time.Now().Add(time.Minute)},
		Endpoints:         mustEndpointSet(t, websocketURL(server.URL, flowersec.WebSocketDirectPath)),
		RendezvousGroupID: "websocket-shutdown-group",
		ListenerAudience:  "test",
		UpstreamAddress:   "127.0.0.1:8080",
	})
	if err != nil {
		t.Fatal(err)
	}
	record = issued.AuthorizationRecord()
	session := connectIssued(t, server, issued, "https://consumer.example")
	t.Cleanup(func() { _ = session.Close() })
	select {
	case <-sessionStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("established WebSocket handler did not start")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := server.endpoint.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	select {
	case <-sessionStopped:
	default:
		t.Fatal("Shutdown returned before the established handler stopped")
	}
	select {
	case released := <-releases:
		if released.leaseID != "lease-websocket-shutdown" || released.ctxErr != nil {
			t.Fatalf("lease release = %+v, want exact lease with live cleanup context", released)
		}
	default:
		t.Fatal("Shutdown returned before the accepted lease was released")
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
