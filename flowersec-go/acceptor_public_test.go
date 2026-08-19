package flowersec_test

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"

	flowersec "github.com/floegence/flowersec/flowersec-go/v3"
	"github.com/floegence/flowersec/flowersec-go/v3/controlplane"
)

func TestAcceptorHandlerRejectsResumedTLSBeforeAuthorization(t *testing.T) {
	var authorized atomic.Int32
	acceptor, err := flowersec.NewAcceptor(flowersec.AcceptorOptions{
		AllowedOrigins: []string{"https://app.example"},
		Authorize: func(context.Context, controlplane.RuntimeAuthorizationRequest) (controlplane.AuthorizationResponse, error) {
			authorized.Add(1)
			return controlplane.AuthorizationResponse{}, nil
		},
		OnSession: func(context.Context, flowersec.Session, string) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, flowersec.WebSocketDirectPath, nil)
	request.Header.Set("Origin", "https://app.example")
	request.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, DidResume: true}
	response := httptest.NewRecorder()
	acceptor.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || authorized.Load() != 0 {
		t.Fatalf("resumed request status/authorizations = %d/%d, want 403/0", response.Code, authorized.Load())
	}
}

func TestAcceptorPublicSurfaceIsCarrierNeutral(t *testing.T) {
	for _, value := range []any{flowersec.AcceptorOptions{}, flowersec.Acceptor{}} {
		typeOf := reflect.TypeOf(value)
		for index := 0; index < typeOf.NumField(); index++ {
			field := typeOf.Field(index)
			if field.PkgPath != "" {
				continue
			}
			if field.Name == "AllowedOrigins" || field.Name == "Listeners" || field.Name == "MaxInboundStreams" || field.Name == "MaxDirectSessions" || field.Name == "Authorize" || field.Name == "Release" || field.Name == "ResolveHandlers" || field.Name == "OnSession" {
				continue
			}
			t.Fatalf("%s exposes an unexpected implementation field %s", typeOf, field.Name)
		}
	}
}

func TestAcceptorResolveHandlersHasCarrierNeutralContract(t *testing.T) {
	typeOf := reflect.TypeOf(flowersec.AcceptorOptions{})
	field, ok := typeOf.FieldByName("ResolveHandlers")
	if !ok {
		t.Fatal("AcceptorOptions.ResolveHandlers is missing")
	}
	want := reflect.TypeOf((func(context.Context, controlplane.RuntimeAuthorizationRequest) (*flowersec.SessionHandlers, error))(nil))
	if field.Type != want {
		t.Fatalf("ResolveHandlers type = %v, want %v", field.Type, want)
	}
}

func TestAcceptorRejectsIncompleteOptions(t *testing.T) {
	if _, err := flowersec.NewAcceptor(flowersec.AcceptorOptions{}); err == nil {
		t.Fatal("empty acceptor options unexpectedly succeeded")
	}
}

func TestAcceptorListenerRegistrationValidation(t *testing.T) {
	serverTLS, _ := acceptorListenerTLS(t)
	native, err := flowersec.NewRawQUICDirectListener(flowersec.RawQUICListenerOptions{
		Address: "127.0.0.1:0", TLSConfig: serverTLS,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer native.Close()
	base := flowersec.AcceptorOptions{
		Authorize: func(context.Context, controlplane.RuntimeAuthorizationRequest) (controlplane.AuthorizationResponse, error) {
			return controlplane.AuthorizationResponse{}, nil
		},
		OnSession: func(context.Context, flowersec.Session, string) error { return nil },
	}

	nativeOnly := base
	nativeOnly.Listeners = []flowersec.DirectListener{native}
	if _, err := flowersec.NewAcceptor(nativeOnly); err != nil {
		t.Fatalf("native-only acceptor unexpectedly required HTTP origins: %v", err)
	}

	duplicate := base
	duplicate.Listeners = []flowersec.DirectListener{native, native}
	if _, err := flowersec.NewAcceptor(duplicate); err == nil {
		t.Fatal("duplicate carrier/path registration unexpectedly succeeded")
	}

	webSocket := base
	webSocket.Listeners = []flowersec.DirectListener{flowersec.NewWebSocketDirectListener()}
	if _, err := flowersec.NewAcceptor(webSocket); err == nil {
		t.Fatal("WebSocket acceptor without an exact origin allowlist unexpectedly succeeded")
	}
	webSocket.AllowedOrigins = []string{"https://app.example"}
	acceptor, err := flowersec.NewAcceptor(webSocket)
	if err != nil {
		t.Fatal(err)
	}
	if handler := acceptor.Handler(); handler == nil {
		t.Fatal("WebSocket acceptor returned a nil handler")
	}
}

func TestAcceptorListenerConstructorsRejectInvalidOptions(t *testing.T) {
	serverTLS, _ := acceptorListenerTLS(t)
	if listener, err := flowersec.NewRawQUICDirectListener(flowersec.RawQUICListenerOptions{
		Address: "", TLSConfig: serverTLS,
	}); err == nil || listener != nil {
		t.Fatal("invalid raw QUIC options unexpectedly succeeded")
	}
	if listener, err := flowersec.NewWebTransportDirectListener(flowersec.WebTransportListenerOptions{
		Address: "127.0.0.1:0", TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13},
		CheckOrigin: nil,
	}); err == nil || listener != nil {
		t.Fatal("invalid WebTransport options unexpectedly succeeded")
	}
}
