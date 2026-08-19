package flowersec_test

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	flowersec "github.com/floegence/flowersec/flowersec-go/v3"
	"github.com/floegence/flowersec/flowersec-go/v3/controlplane"
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

func TestAcceptorReleasesAuthorizedLeaseWhenHandlerResolutionFails(t *testing.T) {
	t.Parallel()

	var record controlplane.AuthorizationRecord
	releases := make(chan struct {
		leaseID string
		ctxErr  error
	}, 2)
	acceptor, err := flowersec.NewAcceptor(flowersec.AcceptorOptions{
		AllowedOrigins: []string{"https://consumer.example"},
		Authorize: func(_ context.Context, request controlplane.RuntimeAuthorizationRequest) (controlplane.AuthorizationResponse, error) {
			return controlplane.AuthorizeRuntime(request, record, "lease-handler-failure")
		},
		ResolveHandlers: func(context.Context, controlplane.RuntimeAuthorizationRequest) (*flowersec.SessionHandlers, error) {
			return nil, errors.New("handler resolution failed")
		},
		Release: func(ctx context.Context, leaseID string) {
			releases <- struct {
				leaseID string
				ctxErr  error
			}{leaseID: leaseID, ctxErr: ctx.Err()}
		},
		OnSession: func(context.Context, flowersec.Session, string) error {
			return errors.New("session must not start")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(acceptor.Handler())
	defer server.Close()

	issued, err := controlplane.NewIssuer().IssueDirect(controlplane.DirectIssueOptions{
		Session:           controlplane.SessionOptions{ChannelID: "handler-failure", ExpiresAt: time.Now().Add(time.Minute)},
		Endpoints:         mustEndpointSet(t, websocketURL(server.URL, flowersec.WebSocketDirectPath)),
		RendezvousGroupID: "handler-failure",
		ListenerAudience:  "test",
		UpstreamAddress:   "127.0.0.1:8080",
	})
	if err != nil {
		t.Fatal(err)
	}
	record = issued.AuthorizationRecord()

	if session, connectErr := connectIssuedResult(server, issued, "https://consumer.example"); connectErr == nil {
		_ = session.Close()
		t.Fatal("connect error = nil, want handler resolution failure")
	}
	select {
	case released := <-releases:
		if released.leaseID != "lease-handler-failure" || released.ctxErr != nil {
			t.Fatalf("release = %+v, want uncanceled exact lease", released)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("authorized lease was not released")
	}
	select {
	case duplicate := <-releases:
		t.Fatalf("duplicate release = %+v", duplicate)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestAcceptorRejectsPlaintextLoopbackDirectArtifact(t *testing.T) {
	_, err := controlplane.NewEndpointSet(controlplane.EndpointConfig{
		ID: "loopback", URL: "ws://127.0.0.1/flowersec/v3/direct", TLS: controlplane.CAPolicy(),
	})
	var typed *controlplane.ControlPlaneError
	if !errors.As(err, &typed) || typed.Code() != controlplane.InvalidEndpointURL {
		t.Fatalf("plaintext v3 endpoint error = %#v, want invalid_endpoint_url", err)
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
	configs := make([]controlplane.EndpointConfig, 0, len(endpoints))
	for index, endpoint := range endpoints {
		configs = append(configs, controlplane.EndpointConfig{
			ID: fmt.Sprintf("endpoint-%d", index+1), URL: endpoint, TLS: controlplane.CAPolicy(),
		})
	}
	set, err := controlplane.NewEndpointSet(configs...)
	if err != nil {
		t.Fatal(err)
	}
	return set
}

func websocketURL(serverURL, path string) string {
	return "wss" + strings.TrimPrefix(serverURL, "https") + path
}
