package flowersec_test

import (
	"context"
	"crypto/tls"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	flowersec "github.com/floegence/flowersec/flowersec-go/v5"
	"github.com/floegence/flowersec/flowersec-go/v5/controlplane"
	ws "github.com/floegence/flowersec/flowersec-go/v5/internal/carrier/websocketv3"
	"github.com/gorilla/websocket"
)

func TestAcceptorDynamicOriginFollowsCurrentPolicyWithoutRestart(t *testing.T) {
	var origin atomic.Value
	origin.Store("https://192.0.2.10")
	var authorizations atomic.Int32
	options := flowersec.AcceptorOptions{
		CheckOrigin: func(r *http.Request) bool { return r.Header.Get("Origin") == origin.Load().(string) },
		Authorize: func(context.Context, controlplane.RuntimeAuthorizationRequest) (controlplane.AuthorizationResponse, error) {
			authorizations.Add(1)
			return controlplane.RejectRuntime("permission_denied", false)
		},
		OnSession: func(context.Context, flowersec.Session, string) error { return nil },
	}
	acceptor, err := flowersec.NewAcceptor(options)
	if err != nil {
		t.Fatal(err)
	}
	serverTLS, roots := acceptorListenerTLS(t)
	server, err := startWebSocketTestServer(acceptor.Handler(), serverTLS)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.Close)
	dialer := websocket.Dialer{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}, Subprotocols: []string{ws.SubprotocolDirect}}
	check := func(value string, allowed bool) {
		t.Helper()
		conn, response, err := dialer.Dial(strings.Replace(server.URL, "https://", "wss://", 1)+flowersec.WebSocketDirectPath, http.Header{"Origin": []string{value}})
		if conn != nil {
			defer conn.Close()
		}
		if allowed {
			if err != nil {
				t.Fatalf("current Origin rejected: %v", err)
			}
		} else if err == nil || response == nil || response.StatusCode != http.StatusForbidden {
			t.Fatalf("removed or untrusted Origin admitted: response=%v err=%v", response, err)
		}
	}
	check("https://192.0.2.10", true)
	check("https://192.0.2.20", false)
	origin.Store("https://192.0.2.20")
	check("https://192.0.2.10", false)
	check("https://192.0.2.20", true)
	check("https://attacker.example", false)
	if authorizations.Load() != 0 {
		t.Fatal("Origin admission bypassed the authenticated artifact handshake")
	}
	options.AllowedOrigins = []string{"https://192.0.2.10"}
	if _, err := flowersec.NewAcceptor(options); err == nil {
		t.Fatal("ambiguous static and dynamic origin policies accepted")
	}
}
