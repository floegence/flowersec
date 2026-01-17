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

func TestRPCServerHandlerPanicReturns500AndContinues(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	router := rpc.NewRouter()
	router.Register(1, func(ctx context.Context, payload json.RawMessage) (json.RawMessage, *rpcv1.RpcError) {
		_ = ctx
		_ = payload
		panic("boom")
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

	req1 := rpcv1.RpcEnvelope{TypeId: 1, RequestId: 7, ResponseTo: 0, Payload: json.RawMessage(`{"x":1}`)}
	if err := rpc.WriteJSONFrame(b, req1); err != nil {
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
	if resp.Error == nil || resp.Error.Code != 500 {
		t.Fatalf("expected 500 error, got %#v", resp.Error)
	}

	req2 := rpcv1.RpcEnvelope{TypeId: 2, RequestId: 8, ResponseTo: 0, Payload: json.RawMessage(`{"ok":true}`)}
	if err := rpc.WriteJSONFrame(b, req2); err != nil {
		t.Fatalf("write request failed: %v", err)
	}
	respBytes2, err := rpc.ReadJSONFrame(b, 1<<20)
	if err != nil {
		t.Fatalf("read response failed: %v", err)
	}
	var resp2 rpcv1.RpcEnvelope
	if err := json.Unmarshal(respBytes2, &resp2); err != nil {
		t.Fatalf("unmarshal response failed: %v", err)
	}
	if resp2.ResponseTo != 8 {
		t.Fatalf("unexpected response_to: %d", resp2.ResponseTo)
	}
	if string(resp2.Payload) != `{"ok":true}` {
		t.Fatalf("unexpected payload: %s", string(resp2.Payload))
	}

	cancel()
	_ = a.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for server shutdown")
	}
}

func TestRPCClientNotifyHandlerPanicDoesNotCrashAndOtherHandlersRun(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	c := rpc.NewClient(a)
	defer c.Close()

	got := make(chan struct{}, 1)
	unsub1 := c.OnNotify(2, func(payload json.RawMessage) {
		_ = payload
		panic("boom")
	})
	defer unsub1()
	unsub2 := c.OnNotify(2, func(payload json.RawMessage) {
		_ = payload
		select {
		case got <- struct{}{}:
		default:
		}
	})
	defer unsub2()

	notify := rpcv1.RpcEnvelope{TypeId: 2, RequestId: 0, ResponseTo: 0, Payload: json.RawMessage(`{"ping":true}`)}
	if err := rpc.WriteJSONFrame(b, notify); err != nil {
		t.Fatalf("write notify failed: %v", err)
	}

	select {
	case <-got:
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for notification")
	}
}

func TestRPCClientClosesAfterInvalidJSONFrames(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	client := rpc.NewClient(a)
	defer client.Close()

	invalidPayload := []byte("not-json")
	for i := 0; i < 3; i++ {
		if err := writeRawFrame(b, invalidPayload); err != nil {
			t.Fatalf("write invalid frame failed: %v", err)
		}
	}

	// The client should close its end after maxInvalidJSONFrames invalid payloads,
	// which should make subsequent writes fail.
	deadline := time.Now().Add(2 * time.Second)
	for {
		if err := writeRawFrame(b, invalidPayload); err != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("expected peer write to fail after client closes")
		}
		time.Sleep(10 * time.Millisecond)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, _, err := client.Call(ctx, 1, json.RawMessage(`{}`))
	if err == nil {
		t.Fatalf("expected call to fail after invalid json frames")
	}
}

func stringPtr(s string) *string { return &s }
