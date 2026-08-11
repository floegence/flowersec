package flowersec_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	flowersec "github.com/floegence/flowersec/flowersec-go/v2"
	"github.com/floegence/flowersec/flowersec-go/v2/controlplane"
)

func TestDirectAndTunnelRuntimePublicBoundariesAreDistinct(t *testing.T) {
	var direct []flowersec.DirectListener
	direct = append(direct, flowersec.NewWebSocketDirectListener())
	_ = flowersec.AcceptorOptions{Listeners: direct}

	var tunnel []flowersec.TunnelListener
	tunnel = append(tunnel, flowersec.NewWebSocketTunnelListener())
	options := flowersec.TunnelRuntimeOptions{
		AllowedOrigins: []string{"https://app.example"},
		Listeners:      tunnel,
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
	if response.Code != http.StatusNotFound {
		t.Fatalf("Acceptor tunnel route status = %d, want 404", response.Code)
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
