package flowersec

import (
	"context"
	"encoding/json"
	"sync/atomic"
	"testing"
	"time"
)

func TestDynamicNotificationsShareInboundRouter(t *testing.T) {
	serverTLS, roots := controllerNetworkTLS(t)
	source := &webSocketHandlerRestartSource{serverTLS: serverTLS}
	defer source.stopAll()
	lease, sourceErr := source.Acquire(context.Background())
	if sourceErr != nil {
		t.Fatal(sourceErr)
	}
	var registered atomic.Int32
	handlers := NewRPCHandlers()
	if err := handlers.HandleNotification(902, func(context.Context, json.RawMessage) error {
		registered.Add(1)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	client, err := Connect(context.Background(), lease, ConnectorOptions{
		Origin: "https://client.example", TrustRoots: roots, RPCHandlers: handlers,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server := source.takeGeneration(t, 0).waitSession(t)
	received := make(chan json.RawMessage, 2)
	panicking := client.RPC().OnNotify(902, func(context.Context, json.RawMessage) { panic("isolated") })
	defer panicking()
	unsubscribe := client.RPC().OnNotify(902, func(_ context.Context, payload json.RawMessage) { received <- payload })
	defer unsubscribe()
	if err := server.RPC().Notify(context.Background(), 902, "first"); err != nil {
		t.Fatal(err)
	}
	select {
	case payload := <-received:
		if string(payload) != `"first"` {
			t.Fatalf("payload = %s", payload)
		}
	case <-time.After(time.Second):
		t.Fatal("dynamic subscription missed peer notification")
	}
	if registered.Load() != 1 {
		t.Fatal("registered handler was displaced")
	}
	unsubscribe()
	unsubscribe()
	if err := server.RPC().Notify(context.Background(), 902, "second"); err != nil {
		t.Fatal(err)
	}
	waitAtomicCount(t, &registered, 2)
	select {
	case <-received:
		t.Fatal("unsubscribed handler ran")
	default:
	}
}
