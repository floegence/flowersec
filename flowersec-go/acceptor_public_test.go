package flowersec_test

import (
	"context"
	"crypto/tls"
	"net/http"
	"reflect"
	"testing"

	flowersec "github.com/floegence/flowersec/flowersec-go/v2"
	"github.com/floegence/flowersec/flowersec-go/v2/controlplane"
)

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
	native, err := flowersec.NewRawQUICAcceptorListener(flowersec.RawQUICAcceptorListenerOptions{
		Address: "127.0.0.1:0", TLSConfig: serverTLS, Path: flowersec.AcceptorPathDirect,
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
	nativeOnly.Listeners = []flowersec.AcceptorListener{native}
	if _, err := flowersec.NewAcceptor(nativeOnly); err != nil {
		t.Fatalf("native-only acceptor unexpectedly required HTTP origins: %v", err)
	}

	duplicate := base
	duplicate.Listeners = []flowersec.AcceptorListener{native, native}
	if _, err := flowersec.NewAcceptor(duplicate); err == nil {
		t.Fatal("duplicate carrier/path registration unexpectedly succeeded")
	}

	webSocket := base
	webSocket.Listeners = []flowersec.AcceptorListener{flowersec.NewWebSocketAcceptorListener(flowersec.AcceptorPathDirect)}
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

func TestAcceptorListenerConstructorsRejectInvalidPath(t *testing.T) {
	serverTLS, _ := acceptorListenerTLS(t)
	if listener := flowersec.NewWebSocketAcceptorListener(flowersec.AcceptorPath("invalid")); listener != nil {
		t.Fatal("invalid WebSocket path unexpectedly succeeded")
	}
	if listener, err := flowersec.NewRawQUICAcceptorListener(flowersec.RawQUICAcceptorListenerOptions{
		Address: "127.0.0.1:0", TLSConfig: serverTLS, Path: flowersec.AcceptorPath("invalid"),
	}); err == nil || listener != nil {
		t.Fatal("invalid raw QUIC path unexpectedly succeeded")
	}
	if listener, err := flowersec.NewWebTransportAcceptorListener(flowersec.WebTransportAcceptorListenerOptions{
		Address: "127.0.0.1:0", TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13},
		Path: flowersec.AcceptorPath("invalid"), CheckOrigin: func(*http.Request) bool { return true },
	}); err == nil || listener != nil {
		t.Fatal("invalid WebTransport path unexpectedly succeeded")
	}
}
