package flowersec_test

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	flowersec "github.com/floegence/flowersec/flowersec-go/v5"
	"github.com/floegence/flowersec/flowersec-go/v5/controlplane"
	gorillaws "github.com/gorilla/websocket"
)

func TestPublicArtifactParserRejectsPrivateLoopbackProfileAndAcceptsOnlyItsNestedArtifact(t *testing.T) {
	raw, err := os.ReadFile("../testdata/private_loopback_v1/profile_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Positive []struct {
			ArtifactJSON string `json:"artifact_json"`
		} `json:"positive"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil || len(vectors.Positive) == 0 {
		t.Fatalf("parse private loopback vectors: %v", err)
	}
	for _, positive := range vectors.Positive {
		outer := []byte(positive.ArtifactJSON)
		if _, err := flowersec.ParseArtifact(outer); err == nil {
			t.Fatal("public parser unexpectedly accepted the private loopback envelope")
		}
		var envelope struct {
			ArtifactBase64URL string `json:"artifact_b64u"`
		}
		if err := json.Unmarshal(outer, &envelope); err != nil {
			t.Fatal(err)
		}
		inner, err := base64.RawURLEncoding.DecodeString(envelope.ArtifactBase64URL)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := flowersec.ParseArtifact(inner); err != nil {
			t.Fatalf("public parser rejected the nested flowersec/3 artifact: %v", err)
		}
	}
}

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

func TestPrivateLoopbackHandlerRequiresExactLoopbackAndCallerAuthorization(t *testing.T) {
	acceptor, err := flowersec.NewAcceptor(flowersec.AcceptorOptions{
		Authorize: func(context.Context, controlplane.RuntimeAuthorizationRequest) (controlplane.AuthorizationResponse, error) {
			return controlplane.AuthorizationResponse{}, nil
		},
		OnSession: func(context.Context, flowersec.Session, string) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	var bridgeAuthorized atomic.Int32
	handler, err := acceptor.PrivateLoopbackHandler(flowersec.PrivateLoopbackHandlerOptions{
		AuthorizeRequest: func(*http.Request) bool {
			bridgeAuthorized.Add(1)
			return false
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodGet, flowersec.WebSocketDirectPath, nil)
	request.Host = "127.0.0.1:23998"
	request.RemoteAddr = "127.0.0.1:53000"
	request.Header.Set("Origin", "http://127.0.0.1:23998")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || bridgeAuthorized.Load() != 0 {
		t.Fatalf("non-upgrade loopback status/callbacks = %d/%d, want 403/0", response.Code, bridgeAuthorized.Load())
	}

	request.Header.Set("Connection", "Upgrade")
	request.Header.Set("Upgrade", "websocket")
	request.Header.Set("Sec-WebSocket-Version", "13")
	request.Header.Set("Sec-WebSocket-Protocol", "flowersec.direct.v3")
	request.Header.Set("Sec-WebSocket-Key", "AAECAwQFBgcICQoLDA0ODw==")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || bridgeAuthorized.Load() != 1 {
		t.Fatalf("valid upgrade status/callbacks = %d/%d, want 403/1", response.Code, bridgeAuthorized.Load())
	}

	for _, mutate := range []func(*http.Request){
		func(candidate *http.Request) { candidate.Method = http.MethodPost },
		func(candidate *http.Request) { candidate.Host = "localhost:23998" },
		func(candidate *http.Request) { candidate.RemoteAddr = "192.0.2.1:53000" },
		func(candidate *http.Request) { candidate.Header.Set("Origin", "http://127.0.0.1:23999") },
		func(candidate *http.Request) { candidate.Header.Add("Origin", "http://127.0.0.1:23998") },
		func(candidate *http.Request) { candidate.Header.Del("Connection") },
		func(candidate *http.Request) { candidate.Header.Del("Upgrade") },
		func(candidate *http.Request) { candidate.Header.Set("Sec-WebSocket-Version", "12") },
		func(candidate *http.Request) { candidate.Header.Add("Sec-WebSocket-Version", "13") },
		func(candidate *http.Request) { candidate.Header.Set("Sec-WebSocket-Protocol", "flowersec.tunnel.v3") },
		func(candidate *http.Request) {
			candidate.Header.Set("Sec-WebSocket-Protocol", "flowersec.direct.v3, flowersec.tunnel.v3")
		},
		func(candidate *http.Request) { candidate.Header.Set("Sec-WebSocket-Key", "not-base64") },
		func(candidate *http.Request) { candidate.Header.Add("Sec-WebSocket-Key", "AAECAwQFBgcICQoLDA0ODw==") },
		func(candidate *http.Request) {
			candidate.URL.RawQuery = "query=1"
			candidate.RequestURI = flowersec.WebSocketDirectPath + "?query=1"
		},
		func(candidate *http.Request) { candidate.TLS = &tls.ConnectionState{Version: tls.VersionTLS13} },
		func(candidate *http.Request) {
			candidate.URL.RawPath = "/flowersec/v3/%64irect"
			candidate.RequestURI = "/flowersec/v3/%64irect"
		},
		func(candidate *http.Request) {
			candidate.URL.Scheme = "http"
			candidate.URL.Host = candidate.Host
		},
	} {
		bridgeAuthorized.Store(0)
		candidate := request.Clone(request.Context())
		candidate.Header = request.Header.Clone()
		mutate(candidate)
		response = httptest.NewRecorder()
		handler.ServeHTTP(response, candidate)
		if response.Code != http.StatusForbidden || bridgeAuthorized.Load() != 0 {
			t.Fatalf("invalid loopback status/callbacks = %d/%d, want 403/0", response.Code, bridgeAuthorized.Load())
		}
	}

	bridgeAuthorized.Store(0)
	ipv6 := request.Clone(request.Context())
	ipv6.Header = request.Header.Clone()
	ipv6.Host = "[::1]:23998"
	ipv6.RemoteAddr = "[::1]:53000"
	ipv6.Header.Set("Origin", "http://[::1]:23998")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, ipv6)
	if response.Code != http.StatusForbidden || bridgeAuthorized.Load() != 1 {
		t.Fatalf("valid IPv6 upgrade status/callbacks = %d/%d, want 403/1", response.Code, bridgeAuthorized.Load())
	}
}

func TestPrivateLoopbackHandlerAuthorizesOnceBeforePlaintextUpgrade(t *testing.T) {
	acceptor, err := flowersec.NewAcceptor(flowersec.AcceptorOptions{
		Authorize: func(context.Context, controlplane.RuntimeAuthorizationRequest) (controlplane.AuthorizationResponse, error) {
			return controlplane.AuthorizationResponse{}, nil
		},
		OnSession: func(context.Context, flowersec.Session, string) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	var bridgeAuthorized atomic.Int32
	handler, err := acceptor.PrivateLoopbackHandler(flowersec.PrivateLoopbackHandlerOptions{
		AuthorizeRequest: func(*http.Request) bool {
			bridgeAuthorized.Add(1)
			return true
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	origin := server.URL
	endpoint := "ws" + strings.TrimPrefix(server.URL, "http") + flowersec.WebSocketDirectPath
	dialer := *gorillaws.DefaultDialer
	dialer.Subprotocols = []string{"flowersec.direct.v3"}
	connection, response, err := dialer.Dial(endpoint, http.Header{"Origin": []string{origin}})
	if err != nil {
		t.Fatalf("private loopback upgrade failed: %v (response=%v)", err, response)
	}
	_ = connection.Close()
	if bridgeAuthorized.Load() != 1 {
		t.Fatalf("private bridge authorization callbacks = %d, want 1", bridgeAuthorized.Load())
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
	acceptor, err := flowersec.NewAcceptor(webSocket)
	if err != nil {
		t.Fatalf("private-capable acceptor unexpectedly required public origins: %v", err)
	}
	if server, err := flowersec.NewWebSocketHTTPServer(flowersec.WebSocketHTTPServerOptions{
		Handler: acceptor.Handler(), TLSConfig: serverTLS,
	}); err == nil || server != nil {
		t.Fatal("public WebSocket handler without an exact origin allowlist unexpectedly enabled")
	}
	webSocket.AllowedOrigins = []string{"https://app.example"}
	acceptor, err = flowersec.NewAcceptor(webSocket)
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
