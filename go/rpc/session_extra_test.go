package rpc_test

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"testing"
	"time"

	rpcv1 "github.com/floegence/flowersec/gen/flowersec/rpc/v1"
	"github.com/floegence/flowersec/rpc"
)

func TestRPCClientCallTimeout(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	client := rpc.NewClient(a)
	defer client.Close()

	// Drain request so the client is waiting for response.
	go func() {
		_, _ = rpc.ReadJSONFrame(b, 1<<20)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	_, _, err := client.Call(ctx, 1, json.RawMessage(`{}`))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline exceeded, got %v", err)
	}
}

func TestRPCServerNotificationHandlerErrorDoesNotStop(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	router := rpc.NewRouter()
	router.Register(1, func(ctx context.Context, payload json.RawMessage) (json.RawMessage, *rpcv1.RpcError) {
		_ = ctx
		return nil, &rpcv1.RpcError{Code: 500, Message: stringPtr("oops")}
	})
	router.Register(2, func(ctx context.Context, payload json.RawMessage) (json.RawMessage, *rpcv1.RpcError) {
		_ = ctx
		return payload, nil
	})

	srv := rpc.NewServer(a, router)
	done := make(chan struct{})
	go func() {
		_ = srv.Serve(ctx)
		close(done)
	}()

	// Send notification that returns error.
	notify := rpcv1.RpcEnvelope{TypeId: 1, RequestId: 0, ResponseTo: 0, Payload: json.RawMessage(`{"n":true}`)}
	if err := rpc.WriteJSONFrame(b, notify); err != nil {
		t.Fatalf("write notify failed: %v", err)
	}

	// Send a request and ensure we still get a response.
	req := rpcv1.RpcEnvelope{TypeId: 2, RequestId: 7, ResponseTo: 0, Payload: json.RawMessage(`{"ok":true}`)}
	if err := rpc.WriteJSONFrame(b, req); err != nil {
		t.Fatalf("write request failed: %v", err)
	}
	respBytes, err := rpc.ReadJSONFrame(b, 1<<20)
	if err != nil {
		t.Fatalf("read response failed: %v", err)
	}
	var resp rpcv1.RpcEnvelope
	if err := json.Unmarshal(respBytes, &resp); err != nil {
		t.Fatalf("unmarshal response failed: %v", err)
	}
	if resp.ResponseTo != 7 {
		t.Fatalf("unexpected response_to: %d", resp.ResponseTo)
	}

	cancel()
	_ = a.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for server shutdown")
	}
}

func stringPtr(s string) *string { return &s }
