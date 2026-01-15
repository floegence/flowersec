package rpc_test

import (
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"

	rpcv1 "github.com/flowersec/flowersec/gen/flowersec/rpc/v1"
	"github.com/flowersec/flowersec/rpc"
)

func TestRPC_NotificationAndRequest(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	router := rpc.NewRouter()
	notify3 := make(chan json.RawMessage, 1)
	router.Register(3, func(ctx context.Context, payload json.RawMessage) (json.RawMessage, *rpcv1.RpcError) {
		_ = ctx
		select {
		case notify3 <- payload:
		default:
		}
		return nil, nil
	})

	srv := rpc.NewServer(a, router)
	done := make(chan struct{})
	go func() {
		_ = srv.Serve(ctx)
		close(done)
	}()

	c := rpc.NewClient(b)
	defer c.Close()

	// Server -> client notification.
	got2 := make(chan json.RawMessage, 1)
	unsub := c.OnNotify(2, func(payload json.RawMessage) {
		select {
		case got2 <- payload:
		default:
		}
	})
	defer unsub()
	if err := srv.Notify(2, json.RawMessage(`{"hello":"world"}`)); err != nil {
		t.Fatal(err)
	}
	select {
	case payload := <-got2:
		if string(payload) != `{"hello":"world"}` {
			t.Fatalf("unexpected notification payload: %s", string(payload))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for notification")
	}

	// Client -> server notification (no response expected).
	if err := c.Notify(3, json.RawMessage(`{"x":1}`)); err != nil {
		t.Fatal(err)
	}
	select {
	case payload := <-notify3:
		if string(payload) != `{"x":1}` {
			t.Fatalf("unexpected server notification payload: %s", string(payload))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for server handler")
	}

	_ = a.Close()
	<-done
}
