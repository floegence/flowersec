package rpc_test

import (
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"

	rpcv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/rpc/v1"
	"github.com/floegence/flowersec/flowersec-go/observability"
	"github.com/floegence/flowersec/flowersec-go/rpc"
)

type resultObserver struct {
	serverCh chan observability.RPCResult
	clientCh chan observability.RPCResult
	notifyCh chan struct{}
}

func newResultObserver() *resultObserver {
	return &resultObserver{
		serverCh: make(chan observability.RPCResult, 8),
		clientCh: make(chan observability.RPCResult, 8),
		notifyCh: make(chan struct{}, 1),
	}
}

func (o *resultObserver) ServerRequest(result observability.RPCResult) {
	o.serverCh <- result
}

func (o *resultObserver) ServerFrameError(observability.RPCFrameDirection) {}

func (o *resultObserver) ClientFrameError(observability.RPCFrameDirection) {}

func (o *resultObserver) ClientCall(result observability.RPCResult, _ time.Duration) {
	o.clientCh <- result
}

func (o *resultObserver) ClientNotify() {
	o.notifyCh <- struct{}{}
}

func TestRPCObserverResults(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	router := rpc.NewRouter()
	router.Register(1, func(ctx context.Context, payload json.RawMessage) (json.RawMessage, *rpcv1.RpcError) {
		_ = ctx
		return payload, nil
	})
	router.Register(2, func(ctx context.Context, payload json.RawMessage) (json.RawMessage, *rpcv1.RpcError) {
		_ = ctx
		return nil, &rpcv1.RpcError{Code: 500, Message: strPtr("oops")}
	})

	obs := newResultObserver()
	srv := rpc.NewServer(a, router)
	srv.SetObserver(obs)
	done := make(chan struct{})
	go func() {
		_ = srv.Serve(ctx)
		close(done)
	}()

	client := rpc.NewClient(b)
	client.SetObserver(obs)
	defer client.Close()

	if _, _, err := client.Call(ctx, 1, json.RawMessage(`{"ok":true}`)); err != nil {
		t.Fatalf("call ok failed: %v", err)
	}
	if _, _, err := client.Call(ctx, 2, json.RawMessage(`{"ok":false}`)); err != nil {
		t.Fatalf("call rpc error failed: %v", err)
	}
	if _, _, err := client.Call(ctx, 3, json.RawMessage(`{"ok":false}`)); err != nil {
		t.Fatalf("call handler not found failed: %v", err)
	}

	if err := srv.Notify(9, json.RawMessage(`{"notify":true}`)); err != nil {
		t.Fatalf("notify failed: %v", err)
	}

	expectResult(t, obs.clientCh, observability.RPCResultOK)
	expectResult(t, obs.serverCh, observability.RPCResultOK)
	expectResult(t, obs.clientCh, observability.RPCResultRPCError)
	expectResult(t, obs.serverCh, observability.RPCResultRPCError)
	expectResult(t, obs.clientCh, observability.RPCResultHandlerNotFound)
	expectResult(t, obs.serverCh, observability.RPCResultHandlerNotFound)
	expectNotify(t, obs.notifyCh)

	cancel()
	_ = a.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for server shutdown")
	}
}

func expectResult(t *testing.T, ch <-chan observability.RPCResult, want observability.RPCResult) {
	t.Helper()
	select {
	case got := <-ch:
		if got != want {
			t.Fatalf("unexpected result: %s", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for result: %s", want)
	}
}

func expectNotify(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for notify")
	}
}

func strPtr(s string) *string { return &s }
