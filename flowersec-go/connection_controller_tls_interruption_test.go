package flowersec

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/controlplane"
)

func TestConnectionControllerRetriesTLSInterruptionAfterDisconnect(t *testing.T) {
	serverTLS, roots := controllerNetworkTLS(t)
	healthy := &webSocketHandlerRestartSource{serverTLS: serverTLS}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	clientHello := make(chan bool, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			clientHello <- false
			return
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		var header [5]byte
		_, readErr := io.ReadFull(conn, header[:])
		if readErr == nil {
			_, readErr = io.CopyN(io.Discard, conn, int64(binary.BigEndian.Uint16(header[3:])))
		}
		clientHello <- readErr == nil && header[0] == 22
		// Interrupt TLS before a certificate or admission credential is exchanged.
	}()
	endpoints, err := controlplane.NewEndpointSet(controlplane.EndpointConfig{
		ID: "interrupted", URL: "wss://" + listener.Addr().String() + WebSocketDirectPath, TLS: controlplane.CAPolicy(),
	})
	if err != nil {
		t.Fatal(err)
	}
	issued, err := controlplane.NewIssuer().IssueDirect(controlplane.DirectIssueOptions{
		Session: controlplane.SessionOptions{
			ChannelID: "tls-interruption", ExpiresAt: time.Now().Add(time.Minute), MaxInboundStreams: 8,
		},
		Endpoints: endpoints, RendezvousGroupID: "tls-interruption-group",
		ListenerAudience: "tls-interruption-listener", UpstreamAddress: "127.0.0.1:23998",
	})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := ParseArtifact(issued.ArtifactJSON())
	if err != nil {
		t.Fatal(err)
	}
	interrupted, err := NewArtifactLease(artifact, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	source := &tlsInterruptionSource{healthy: healthy, interrupted: interrupted}
	handlers := NewRPCHandlers()
	if err := handlers.HandleRPC(controllerClientRPC, func(context.Context, json.RawMessage) (any, *RPCError) {
		return "recovered", nil
	}); err != nil {
		t.Fatal(err)
	}
	controller, err := NewConnectionController(source, ConnectionControllerOptions{Connector: ConnectorOptions{
		Origin: "https://client.example", TrustRoots: roots, ConnectTimeout: 5 * time.Second, RPCHandlers: handlers,
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		closeController(t, controller)
		healthy.stopAll()
	})
	controller.Start(context.Background())
	first := waitWebSocketControllerSession(t, controller, nil, 5*time.Second)
	_ = healthy.takeGeneration(t, 0).waitSession(t).Close()
	select {
	case received := <-clientHello:
		if !received {
			t.Fatal("retry did not reach the TLS ClientHello")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("controller did not attempt a new TLS handshake")
	}
	_ = waitWebSocketControllerSession(t, controller, first, 5*time.Second)
	recovered := healthy.takeGeneration(t, 1).waitSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var response string
	if err := recovered.RPC().Call(ctx, controllerClientRPC, nil, &response); err != nil || response != "recovered" {
		t.Fatalf("recovered RPC = %q, %v", response, err)
	}
	if got := source.calls.Load(); got != 3 {
		t.Fatalf("artifact acquisitions = %d, want one per connection attempt (3)", got)
	}
}

type tlsInterruptionSource struct {
	healthy     ArtifactSource
	interrupted ArtifactLease
	calls       atomic.Int32
}

func (source *tlsInterruptionSource) Acquire(ctx context.Context) (ArtifactLease, *ArtifactSourceError) {
	if source.calls.Add(1) == 2 {
		return source.interrupted, nil
	}
	return source.healthy.Acquire(ctx)
}
