package flowersec_test

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"

	flowersec "github.com/floegence/flowersec/flowersec-go/v7"
	"github.com/floegence/flowersec/flowersec-go/v7/controlplane"
)

func TestTunnelRuntimeHandlerRejectsResumedTLSBeforeAuthorization(t *testing.T) {
	var authorized atomic.Int32
	listener := flowersec.NewWebSocketTunnelListener()
	runtime, err := flowersec.NewTunnelRuntime(flowersec.TunnelRuntimeOptions{
		AllowedOrigins: []string{"https://app.example"},
		Listeners:      []flowersec.TunnelListener{listener}, IngressEndpoints: map[flowersec.TunnelListener]string{listener: "wss://relay.example" + flowersec.WebSocketTunnelPath},
		Release: func(context.Context, string) { t.Error("resumed connection released a lease") },
		Authorize: func(context.Context, controlplane.RuntimeAuthorizationRequest) (controlplane.TunnelAuthorizationResponse, error) {
			authorized.Add(1)
			return controlplane.TunnelAuthorizationResponse{}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, flowersec.WebSocketTunnelPath, nil)
	request.Header.Set("Origin", "https://app.example")
	request.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, DidResume: true}
	response := httptest.NewRecorder()
	runtime.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || authorized.Load() != 0 {
		t.Fatalf("resumed request status/authorizations = %d/%d, want 403/0", response.Code, authorized.Load())
	}
}

func TestDirectAndTunnelRuntimePublicBoundariesAreDistinct(t *testing.T) {
	var direct []flowersec.DirectListener
	direct = append(direct, flowersec.NewWebSocketDirectListener())
	_ = flowersec.AcceptorOptions{Listeners: direct}

	var tunnel []flowersec.TunnelListener
	tunnel = append(tunnel, flowersec.NewWebSocketTunnelListener())
	options := flowersec.TunnelRuntimeOptions{
		AllowedOrigins:   []string{"https://app.example"},
		Listeners:        tunnel,
		IngressEndpoints: map[flowersec.TunnelListener]string{tunnel[0]: "wss://relay.example" + flowersec.WebSocketTunnelPath},
		Authorize: func(context.Context, controlplane.RuntimeAuthorizationRequest) (controlplane.TunnelAuthorizationResponse, error) {
			return controlplane.TunnelAuthorizationResponse{}, nil
		},
		Release: func(context.Context, string) {},
	}
	runtime, err := flowersec.NewTunnelRuntime(options)
	if err != nil {
		t.Fatal(err)
	}
	var _ http.Handler = runtime.Handler()
	var _ = (*flowersec.TunnelRuntime).Serve
}

func TestAcceptorDoesNotServeTunnelRoute(t *testing.T) {
	acceptor, err := flowersec.NewAcceptor(flowersec.AcceptorOptions{
		AllowedOrigins: []string{"https://app.example"},
		Release:        func(context.Context, string) { t.Error("tunnel route released a direct lease") },
		Authorize: func(context.Context, controlplane.RuntimeAuthorizationRequest) (controlplane.AuthorizationResponse, error) {
			return controlplane.AuthorizationResponse{}, nil
		},
		OnSession: func(context.Context, flowersec.Session, string) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, flowersec.WebSocketTunnelPath, nil)
	request.Header.Set("Origin", "https://app.example")
	response := httptest.NewRecorder()
	acceptor.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("Acceptor tunnel route status = %d, want fail-closed 403", response.Code)
	}
}

func TestTunnelRuntimeCannotOwnApplicationSessions(t *testing.T) {
	typeOf := reflect.TypeOf(flowersec.TunnelRuntimeOptions{})
	for _, forbidden := range []string{"OnSession", "ResolveHandlers", "SessionHandlers", "PSK", "E2EEPSK"} {
		if _, ok := typeOf.FieldByName(forbidden); ok {
			t.Fatalf("TunnelRuntimeOptions exposes application-session field %s", forbidden)
		}
	}
}
