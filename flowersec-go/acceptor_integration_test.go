package flowersec_test

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	flowersec "github.com/floegence/flowersec/flowersec-go/v2"
	"github.com/floegence/flowersec/flowersec-go/v2/controlplane"
)

func TestAcceptorResolvesHandlersBeforeDirectSessionEstablishment(t *testing.T) {
	t.Parallel()

	var record controlplane.AuthorizationRecord
	handlers := echoHandlers(t, "direct")
	sessionStarted := make(chan struct{})
	releaseSession := make(chan struct{})
	var released atomic.Int32
	acceptor, err := flowersec.NewAcceptor(flowersec.AcceptorOptions{
		AllowedOrigins: []string{"https://consumer.example"},
		Authorize: func(_ context.Context, request controlplane.RuntimeAuthorizationRequest) (controlplane.AuthorizationResponse, error) {
			return controlplane.AuthorizeRuntime(request, record, "lease-direct")
		},
		ResolveHandlers: func(_ context.Context, request controlplane.RuntimeAuthorizationRequest) (*flowersec.SessionHandlers, error) {
			if request.LookupKey() == "" {
				return nil, fmt.Errorf("missing lookup key")
			}
			return handlers, nil
		},
		Release: func(context.Context, string) { released.Add(1) },
		OnSession: func(_ context.Context, _ flowersec.Session, channelID string) error {
			if channelID != "direct-handler" {
				return fmt.Errorf("accepted direct channel = %q, want direct-handler", channelID)
			}
			close(sessionStarted)
			<-releaseSession
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(acceptor.Handler())
	defer server.Close()

	issued, err := controlplane.NewIssuer().IssueDirect(controlplane.DirectIssueOptions{
		Session:           controlplane.SessionOptions{ChannelID: "direct-handler", ExpiresAt: time.Now().Add(time.Minute)},
		Endpoints:         mustEndpointSet(t, websocketURL(server.URL, flowersec.WebSocketDirectPath)),
		RendezvousGroupID: "direct-group",
		ListenerAudience:  "test",
		UpstreamAddress:   "127.0.0.1:8080",
	})
	if err != nil {
		t.Fatal(err)
	}
	record = issued.AuthorizationRecord()

	session := connectIssued(t, server, issued, "https://consumer.example")
	defer session.Close()
	select {
	case <-sessionStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("accepted direct session did not start")
	}
	assertEchoRPC(t, session, "direct")
	close(releaseSession)
	for deadline := time.Now().Add(5 * time.Second); released.Load() != 1 && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
	}
	if released.Load() != 1 {
		t.Fatalf("lease release count = %d, want 1", released.Load())
	}
}

func TestAcceptorEstablishesPlaintextLoopbackDirectSession(t *testing.T) {
	var record controlplane.AuthorizationRecord
	origins := []string{"pending"}
	handlers := echoHandlers(t, "loopback")
	streamPayload := make(chan []byte, 1)
	if err := handlers.HandleStream("loopback-echo", func(_ context.Context, incoming flowersec.IncomingStream) error {
		payload, err := io.ReadAll(incoming.Stream)
		if err == nil {
			streamPayload <- payload
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	sessionStarted := make(chan struct{})
	releaseSession := make(chan struct{})
	sessionFinished := make(chan struct{})
	var released atomic.Int32
	acceptor, err := flowersec.NewAcceptor(flowersec.AcceptorOptions{
		AllowedOrigins: origins,
		Authorize: func(_ context.Context, request controlplane.RuntimeAuthorizationRequest) (controlplane.AuthorizationResponse, error) {
			return controlplane.AuthorizeRuntime(request, record, "lease-loopback")
		},
		ResolveHandlers: func(context.Context, controlplane.RuntimeAuthorizationRequest) (*flowersec.SessionHandlers, error) {
			return handlers, nil
		},
		OnSession: func(context.Context, flowersec.Session, string) error {
			close(sessionStarted)
			<-releaseSession
			close(sessionFinished)
			return nil
		},
		Release: func(context.Context, string) { released.Add(1) },
	})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(acceptor.Handler())
	defer server.Close()
	origins[0] = server.URL

	issued, err := controlplane.NewIssuer().IssueDirect(controlplane.DirectIssueOptions{
		Session:           controlplane.SessionOptions{ChannelID: "loopback-direct", ExpiresAt: time.Now().Add(time.Minute)},
		Endpoints:         mustEndpointSet(t, "ws"+strings.TrimPrefix(server.URL, "http")+flowersec.WebSocketDirectPath),
		RendezvousGroupID: "loopback-direct",
		ListenerAudience:  "test",
		UpstreamAddress:   server.Listener.Addr().String(),
	})
	if err != nil {
		t.Fatal(err)
	}
	record = issued.AuthorizationRecord()

	artifact, err := flowersec.ParseArtifact(issued.ArtifactJSON())
	if err != nil {
		t.Fatal(err)
	}
	lease, err := flowersec.NewArtifactLease(artifact, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	session, err := flowersec.Connect(ctx, lease, flowersec.ConnectorOptions{Origin: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	select {
	case <-sessionStarted:
	case <-ctx.Done():
		t.Fatal("plaintext loopback accepted session did not start")
	}
	assertEchoRPC(t, session, "loopback")
	if _, err := session.ProbeLiveness(ctx); err != nil {
		t.Fatalf("plaintext loopback ProbeLiveness() error = %v", err)
	}
	stream, err := session.OpenStream(ctx, "loopback-echo", flowersec.EmptyStreamMetadata())
	if err != nil {
		t.Fatalf("plaintext loopback OpenStream() error = %v", err)
	}
	if _, err := stream.Write([]byte("loopback-stream")); err != nil {
		t.Fatalf("plaintext loopback stream Write() error = %v", err)
	}
	if err := stream.CloseWrite(); err != nil {
		t.Fatalf("plaintext loopback stream CloseWrite() error = %v", err)
	}
	select {
	case payload := <-streamPayload:
		if string(payload) != "loopback-stream" {
			t.Fatalf("plaintext loopback stream payload = %q", payload)
		}
	case <-ctx.Done():
		t.Fatal("plaintext loopback stream handler did not receive payload")
	}
	_ = stream.Close()
	close(releaseSession)
	select {
	case <-sessionFinished:
	case <-ctx.Done():
		t.Fatal("plaintext loopback accepted session did not finish")
	}
	for deadline := time.Now().Add(time.Second); released.Load() != 1 && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
	}
	if released.Load() != 1 {
		t.Fatalf("plaintext loopback release count = %d, want 1", released.Load())
	}
}

func TestTunnelRuntimeBridgesOpaqueEndpointSessions(t *testing.T) {
	t.Parallel()

	var records sync.Map
	var released atomic.Int32
	runtime, err := flowersec.NewTunnelRuntime(flowersec.TunnelRuntimeOptions{
		AllowedOrigins: []string{"https://consumer.example"},
		Listeners:      []flowersec.TunnelListener{flowersec.NewWebSocketTunnelListener()},
		Authorize: func(_ context.Context, request controlplane.RuntimeAuthorizationRequest) (controlplane.TunnelAuthorizationResponse, error) {
			stored, ok := records.Load(request.LookupKey())
			if !ok {
				return controlplane.TunnelAuthorizationResponse{}, fmt.Errorf("unknown authorization record")
			}
			return controlplane.AuthorizeTunnelRuntime(request, stored.(controlplane.AuthorizationRecord), "lease-"+request.LookupKey()[:8])
		},
		Release: func(context.Context, string) { released.Add(1) },
	})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(runtime.Handler())
	defer server.Close()

	pair, err := controlplane.NewIssuer().IssueTunnelPair(controlplane.TunnelIssueOptions{
		Session:           controlplane.SessionOptions{ChannelID: "tunnel-handlers", ExpiresAt: time.Now().Add(time.Minute)},
		Endpoints:         mustEndpointSet(t, websocketURL(server.URL, flowersec.WebSocketTunnelPath)),
		RendezvousGroupID: "tunnel-group",
		ListenerAudience:  "test",
		FirstEndpointID:   "first",
		SecondEndpointID:  "second",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		issued controlplane.IssuedArtifact
		name   string
	}{{pair.First, "first"}, {pair.Second, "second"}} {
		records.Store(item.issued.LookupKey(), item.issued.AuthorizationRecord())
	}

	type result struct {
		session flowersec.Session
		err     error
	}
	results := make(chan result, 2)
	for _, issued := range []controlplane.IssuedArtifact{pair.First, pair.Second} {
		issued := issued
		go func() {
			session, err := connectIssuedResult(server, issued, "https://consumer.example")
			results <- result{session: session, err: err}
		}()
	}
	connected := make([]flowersec.Session, 0, 2)
	for range 2 {
		result := <-results
		if result.err != nil {
			t.Fatal(result.err)
		}
		connected = append(connected, result.session)
		defer result.session.Close()
	}
	for _, session := range connected {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, err := session.ProbeLiveness(ctx)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, session := range connected {
		_ = session.Close()
	}
	for deadline := time.Now().Add(5 * time.Second); released.Load() != 2 && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
	}
	if released.Load() != 2 {
		t.Fatalf("lease release count = %d, want 2", released.Load())
	}
}

func echoHandlers(t *testing.T, name string) *flowersec.SessionHandlers {
	t.Helper()
	handlers, err := flowersec.NewSessionHandlers(flowersec.SessionHandlerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := handlers.HandleRPC(7001, func(context.Context, json.RawMessage) (any, *flowersec.RPCError) {
		return map[string]string{"server": name}, nil
	}); err != nil {
		t.Fatal(err)
	}
	return handlers
}

func connectIssued(t *testing.T, server *httptest.Server, issued controlplane.IssuedArtifact, origin string) flowersec.Session {
	t.Helper()
	session, err := connectIssuedResult(server, issued, origin)
	if err != nil {
		t.Fatal(err)
	}
	return session
}

func connectIssuedResult(server *httptest.Server, issued controlplane.IssuedArtifact, origin string) (flowersec.Session, error) {
	artifact, err := flowersec.ParseArtifact(issued.ArtifactJSON())
	if err != nil {
		return nil, err
	}
	lease, err := flowersec.NewArtifactLease(artifact, func(context.Context) error { return nil })
	if err != nil {
		return nil, err
	}
	trustRoots := x509.NewCertPool()
	trustRoots.AddCert(server.Certificate())
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return flowersec.Connect(ctx, lease, flowersec.ConnectorOptions{TrustRoots: trustRoots, Origin: origin})
}

func assertEchoRPC(t *testing.T, session flowersec.Session, want string) {
	t.Helper()
	var response struct {
		Server string `json:"server"`
	}
	if err := session.RPC().Call(context.Background(), 7001, map[string]string{"message": "ping"}, &response); err != nil {
		t.Fatal(err)
	}
	if response.Server != want {
		t.Fatalf("RPC response = %q, want %q", response.Server, want)
	}
}

func mustEndpointSet(t *testing.T, endpoints ...string) controlplane.EndpointSet {
	t.Helper()
	set, err := controlplane.NewEndpointSet(endpoints...)
	if err != nil {
		t.Fatal(err)
	}
	return set
}

func websocketURL(serverURL, path string) string {
	return "wss" + strings.TrimPrefix(serverURL, "https") + path
}
