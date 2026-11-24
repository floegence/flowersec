package flowersec

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v7/controlplane"
)

func TestWebSocketRequestPolicyWithoutApplicationHandler(t *testing.T) {
	var requests, policies int
	server := newWebSocketHTTPServer(WebSocketHTTPServerOptions{
		AuthorizeWebSocketRequest: func(*http.Request) bool { policies++; return false },
	}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		w.WriteHeader(http.StatusNotFound)
	}), nil, true)
	for _, path := range []string{WebSocketDirectPath, WebSocketTunnelPath} {
		response := httptest.NewRecorder()
		server.httpServer.Handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusForbidden {
			t.Fatalf("%s: status %d, want 403", path, response.Code)
		}
	}
	if requests != 0 || policies != 0 {
		t.Fatalf("protocol requests reached transport: requests=%d policies=%d", requests, policies)
	}
	response := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/unknown", nil))
	if response.Code != http.StatusNotFound || requests != 1 || policies != 0 {
		t.Fatal("request policy changed unrelated routing")
	}
}

func TestTunnelRequestPolicySharesAdmissionCapacity(t *testing.T) {
	listener := NewWebSocketTunnelListener()
	runtime, err := NewTunnelRuntime(TunnelRuntimeOptions{
		Listeners: []TunnelListener{listener}, IngressEndpoints: map[TunnelListener]string{listener: "wss://relay.example" + WebSocketTunnelPath},
		AllowedOrigins: []string{"https://app.example"}, Release: func(context.Context, string) {},
		Authorize: func(context.Context, controlplane.RuntimeAuthorizationRequest) (controlplane.TunnelAuthorizationResponse, error) {
			t.Fatal("unexpected credential authorization")
			return controlplane.TunnelAuthorizationResponse{}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	var releases []func()
	for {
		release, ok := runtime.coordinator.TryReserveAdmission()
		if !ok {
			break
		}
		releases = append(releases, release)
	}
	defer func() {
		for _, release := range releases {
			release()
		}
	}()
	request := httptest.NewRequest(http.MethodGet, "https://relay.example"+WebSocketTunnelPath, nil)
	request.TLS.Version = tls.VersionTLS13
	request.Header.Set("Origin", "https://app.example")
	request.Header.Set("Connection", "Upgrade")
	request.Header.Set("Upgrade", "websocket")
	calls := 0
	policy := func(*http.Request) bool { calls++; return false }
	check := func(status int) {
		t.Helper()
		response := httptest.NewRecorder()
		runtime.handleWebSocket(response, request, "wss://relay.example"+WebSocketTunnelPath, policy)
		if response.Code != status {
			t.Fatalf("status = %d, want %d", response.Code, status)
		}
	}
	check(http.StatusServiceUnavailable)
	releases[0]()
	check(http.StatusForbidden)
	check(http.StatusForbidden)
	if calls != 2 {
		t.Fatalf("policy invoked %d times", calls)
	}
}
