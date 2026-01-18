package serve

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	rpcv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/rpc/v1"
	"github.com/floegence/flowersec/flowersec-go/rpc"
)

func TestServerHandleStreamRPC(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s := New(Options{
		RPC: RPCOptions{
			Register: func(r *rpc.Router, _srv *rpc.Server) {
				r.Register(1, func(ctx context.Context, payload json.RawMessage) (json.RawMessage, *rpcv1.RpcError) {
					_ = ctx
					_ = payload
					return json.RawMessage(`{"ok":true}`), nil
				})
			},
		},
	})

	serverConn, clientConn := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.HandleStream(ctx, "rpc", serverConn)
	}()

	c := rpc.NewClient(clientConn)
	defer c.Close()

	resp, rpcErr, err := c.Call(ctx, 1, json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("call failed: %v", err)
	}
	if rpcErr != nil {
		t.Fatalf("unexpected rpc error: %v", rpcErr)
	}
	if string(resp) != `{"ok":true}` {
		t.Fatalf("unexpected response: %s", string(resp))
	}

	cancel()
	_ = clientConn.Close()
	<-done
}

func TestServerHandleStreamUnknownCloses(t *testing.T) {
	t.Parallel()

	s := New(Options{})
	serverConn, clientConn := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.HandleStream(context.Background(), "unknown", serverConn)
	}()

	_ = clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err := clientConn.Read(make([]byte, 1))
	if err == nil {
		t.Fatal("expected read error")
	}
	if !errors.Is(err, io.EOF) {
		t.Fatalf("expected EOF, got %v", err)
	}
	<-done
}
