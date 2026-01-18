package typed

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"testing"
	"time"

	rpcwirev1 "github.com/floegence/flowersec/gen/flowersec/rpc/v1"
	"github.com/floegence/flowersec/rpc"
)

type req struct {
	A int `json:"a"`
}

type resp struct {
	OK bool `json:"ok"`
}

func TestCallAndRegister(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	router := rpc.NewRouter()
	Register[req, resp](router, 1, func(ctx context.Context, r *req) (*resp, *rpcwirev1.RpcError) {
		_ = ctx
		if r.A != 1 {
			return nil, &rpcwirev1.RpcError{Code: 400, Message: strPtr("bad a")}
		}
		return &resp{OK: true}, nil
	})

	srv := rpc.NewServer(a, router)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx) }()

	cli := rpc.NewClient(b)
	callCtx, callCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer callCancel()

	out, err := Call[req, resp](callCtx, cli, 1, &req{A: 1})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if out == nil || !out.OK {
		t.Fatalf("unexpected response: %+v", out)
	}
}

func TestCallRPCError(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	router := rpc.NewRouter()
	Register[req, resp](router, 1, func(ctx context.Context, r *req) (*resp, *rpcwirev1.RpcError) {
		_ = ctx
		if r.A != 1 {
			return nil, &rpcwirev1.RpcError{Code: 400, Message: strPtr("bad a")}
		}
		return &resp{OK: true}, nil
	})

	srv := rpc.NewServer(a, router)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx) }()

	cli := rpc.NewClient(b)
	callCtx, callCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer callCancel()

	_, err := Call[req, resp](callCtx, cli, 1, &req{A: 2})
	var ce *rpc.CallError
	if err == nil || !errors.As(err, &ce) {
		t.Fatalf("expected CallError, got %T %v", err, err)
	}
	if ce.Code != 400 {
		t.Fatalf("unexpected code: %d", ce.Code)
	}
}

func TestRegisterInvalidPayload(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	router := rpc.NewRouter()
	Register[req, resp](router, 1, func(ctx context.Context, r *req) (*resp, *rpcwirev1.RpcError) {
		_ = ctx
		_ = r
		return &resp{OK: true}, nil
	})

	srv := rpc.NewServer(a, router)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx) }()

	cli := rpc.NewClient(b)
	callCtx, callCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer callCancel()

	_, rpcErr, err := cli.Call(callCtx, 1, json.RawMessage(`{"a":"not-int"}`))
	if err != nil {
		t.Fatalf("Call transport: %v", err)
	}
	if rpcErr == nil || rpcErr.Code != 400 {
		t.Fatalf("expected rpc error code=400, got %+v", rpcErr)
	}
}
