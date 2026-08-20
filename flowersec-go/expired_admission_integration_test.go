package flowersec_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	flowersec "github.com/floegence/flowersec/flowersec-go/v3"
	"github.com/floegence/flowersec/flowersec-go/v3/controlplane"
	"github.com/floegence/flowersec/flowersec-go/v3/internal/artifactv3"
	carrierws "github.com/floegence/flowersec/flowersec-go/v3/internal/carrier/websocketv3"
	gorillaws "github.com/gorilla/websocket"
)

var expiredArtifactFSA3 = []byte("FSA3\x03\x02\x00\x10expired_artifact")

func TestDirectProductionAdmissionEmitsRetryableExpiryAndCloses(t *testing.T) {
	var sessions atomic.Int32
	acceptor, err := flowersec.NewAcceptor(flowersec.AcceptorOptions{
		AllowedOrigins: []string{"https://consumer.example"},
		Authorize: func(context.Context, controlplane.RuntimeAuthorizationRequest) (controlplane.AuthorizationResponse, error) {
			return controlplane.RejectRuntime(artifactv3.ReasonExpiredArtifact, true)
		},
		OnSession: func(context.Context, flowersec.Session, string) error {
			sessions.Add(1)
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	serverTLS, roots := acceptorListenerTLS(t)
	server := newWebSocketTestServer(t, acceptor.Handler(), serverTLS)
	issued, err := controlplane.NewIssuer().IssueDirect(controlplane.DirectIssueOptions{
		Session:           controlplane.SessionOptions{ChannelID: "expired-direct-production", ExpiresAt: time.Now().Add(time.Minute)},
		Endpoints:         mustEndpointSet(t, websocketURL(server.URL, flowersec.WebSocketDirectPath)),
		RendezvousGroupID: "expired-direct-group", ListenerAudience: "expired-direct-audience",
		UpstreamAddress: "127.0.0.1:9000",
	})
	if err != nil {
		t.Fatal(err)
	}
	connection := dialAdmissionWebSocket(t, server.URL, flowersec.WebSocketDirectPath, carrierws.SubprotocolDirect, roots)
	assertExpiredAdmissionAndClose(t, connection, rawIssuedAdmission(t, issued))
	if sessions.Load() != 0 {
		t.Fatalf("direct sessions established = %d, want 0", sessions.Load())
	}
}

func TestTunnelRuntimePreservesRetryableExpiryAndClosesWithoutPair(t *testing.T) {
	var authorizations atomic.Int32
	runtime, err := flowersec.NewTunnelRuntime(flowersec.TunnelRuntimeOptions{
		AllowedOrigins: []string{"https://consumer.example"},
		Listeners:      []flowersec.TunnelListener{flowersec.NewWebSocketTunnelListener()},
		Authorize: func(context.Context, controlplane.RuntimeAuthorizationRequest) (controlplane.TunnelAuthorizationResponse, error) {
			authorizations.Add(1)
			return controlplane.RejectTunnelRuntime(artifactv3.ReasonExpiredArtifact, true)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	serverTLS, roots := acceptorListenerTLS(t)
	server := newWebSocketTestServer(t, runtime.Handler(), serverTLS)
	pair, err := controlplane.NewIssuer().IssueTunnelPair(controlplane.TunnelIssueOptions{
		Session:           controlplane.SessionOptions{ChannelID: "expired-tunnel-production", ExpiresAt: time.Now().Add(time.Minute)},
		Endpoints:         mustEndpointSet(t, websocketURL(server.URL, flowersec.WebSocketTunnelPath)),
		RendezvousGroupID: "expired-tunnel-group", ListenerAudience: "expired-tunnel-audience",
		FirstEndpointID: "expired-a", SecondEndpointID: "expired-b",
	})
	if err != nil {
		t.Fatal(err)
	}
	connection := dialAdmissionWebSocket(t, server.URL, flowersec.WebSocketTunnelPath, carrierws.SubprotocolTunnel, roots)
	assertExpiredAdmissionAndClose(t, connection, rawIssuedAdmission(t, pair.First))
	if authorizations.Load() != 1 {
		t.Fatalf("tunnel authorizations = %d, want 1", authorizations.Load())
	}
}

func TestTunnelRuntimeFailsClosedForUnknownRetryReason(t *testing.T) {
	runtime, err := flowersec.NewTunnelRuntime(flowersec.TunnelRuntimeOptions{
		AllowedOrigins: []string{"https://consumer.example"},
		Listeners:      []flowersec.TunnelListener{flowersec.NewWebSocketTunnelListener()},
		Authorize: func(context.Context, controlplane.RuntimeAuthorizationRequest) (controlplane.TunnelAuthorizationResponse, error) {
			return controlplane.RejectTunnelRuntime("unknown_policy_reason", true)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	serverTLS, roots := acceptorListenerTLS(t)
	server := newWebSocketTestServer(t, runtime.Handler(), serverTLS)
	pair, err := controlplane.NewIssuer().IssueTunnelPair(controlplane.TunnelIssueOptions{
		Session:           controlplane.SessionOptions{ChannelID: "unknown-tunnel-reason", ExpiresAt: time.Now().Add(time.Minute)},
		Endpoints:         mustEndpointSet(t, websocketURL(server.URL, flowersec.WebSocketTunnelPath)),
		RendezvousGroupID: "unknown-reason-group", ListenerAudience: "unknown-reason-audience",
		FirstEndpointID: "unknown-a", SecondEndpointID: "unknown-b",
	})
	if err != nil {
		t.Fatal(err)
	}
	connection := dialAdmissionWebSocket(t, server.URL, flowersec.WebSocketTunnelPath, carrierws.SubprotocolTunnel, roots)
	_ = connection.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_ = connection.SetReadDeadline(time.Now().Add(2 * time.Second))
	if err := connection.WriteMessage(gorillaws.BinaryMessage, rawIssuedAdmission(t, pair.First)); err != nil {
		t.Fatal(err)
	}
	messageType, response, err := connection.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	want := []byte("FSA3\x03\x01\x00\x12invalid_credential")
	if messageType != gorillaws.BinaryMessage || !bytes.Equal(response, want) {
		t.Fatalf("unknown retry reason response = %d/%x, want audited reject %x", messageType, response, want)
	}
	if _, _, err := connection.ReadMessage(); err == nil {
		t.Fatal("tunnel connection remained open after fail-closed rejection")
	} else if networkError, ok := err.(net.Error); ok && networkError.Timeout() {
		t.Fatal("timed out waiting for fail-closed tunnel connection close")
	}
}

func rawIssuedAdmission(t *testing.T, issued controlplane.IssuedArtifact) []byte {
	t.Helper()
	artifact, err := artifactv3.DecodeArtifactJSON(bytes.NewReader(issued.ArtifactJSON()))
	if err != nil {
		t.Fatal(err)
	}
	request, err := artifactv3.BuildRequest(*artifact, artifact.Path.Candidates[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := artifactv3.MarshalRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func dialAdmissionWebSocket(t *testing.T, serverURL, path, subprotocol string, roots *x509.CertPool) *gorillaws.Conn {
	t.Helper()
	dialer := gorillaws.Dialer{
		TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13},
		Subprotocols:    []string{subprotocol},
	}
	header := make(http.Header)
	header.Set("Origin", "https://consumer.example")
	connection, response, err := dialer.Dial("wss"+strings.TrimPrefix(serverURL, "https")+path, header)
	if err != nil {
		if response != nil {
			t.Fatalf("WebSocket dial returned HTTP %d: %v", response.StatusCode, err)
		}
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	return connection
}

func assertExpiredAdmissionAndClose(t *testing.T, connection *gorillaws.Conn, rawFSB3 []byte) {
	t.Helper()
	_ = connection.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_ = connection.SetReadDeadline(time.Now().Add(2 * time.Second))
	if err := connection.WriteMessage(gorillaws.BinaryMessage, rawFSB3); err != nil {
		t.Fatal(err)
	}
	messageType, response, err := connection.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	if messageType != gorillaws.BinaryMessage || !bytes.Equal(response, expiredArtifactFSA3) {
		t.Fatalf("expired admission response type/frame = %d/%x, want binary/%x", messageType, response, expiredArtifactFSA3)
	}
	if _, _, err := connection.ReadMessage(); err == nil {
		t.Fatal("admission connection remained open after retryable expiry")
	} else if networkError, ok := err.(net.Error); ok && networkError.Timeout() {
		t.Fatal("timed out waiting for admission connection close")
	}
}
