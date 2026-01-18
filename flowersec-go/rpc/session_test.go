package rpc_test

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	rpcv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/rpc/v1"
	"github.com/floegence/flowersec/flowersec-go/rpc"
	"github.com/floegence/flowersec/flowersec-go/rpc/frame"
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

func TestRPC_ClientCallFailsWhenTransportCloses(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	c := rpc.NewClient(a)
	defer c.Close()

	// Drain the request so Client.Call can move past the write and wait for the response.
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		_, _ = frame.ReadJSONFrame(b, 1<<20)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		_, _, err := c.Call(ctx, 1, json.RawMessage(`{}`))
		errCh <- err
	}()

	select {
	case <-drained:
		_ = b.Close()
	case <-ctx.Done():
		t.Fatal("timeout waiting to drain request")
	}

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	case <-ctx.Done():
		t.Fatal("timeout waiting for Call to return")
	}
}

func TestRPC_CallCancelDoesNotPanicOnLateResponse(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	c := rpc.NewClient(a)
	defer c.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		bs, err := frame.ReadJSONFrame(b, 1<<20)
		if err != nil {
			return
		}
		var env rpcv1.RpcEnvelope
		if err := json.Unmarshal(bs, &env); err != nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
		resp := rpcv1.RpcEnvelope{
			TypeId:     env.TypeId,
			RequestId:  0,
			ResponseTo: env.RequestId,
			Payload:    json.RawMessage(`{}`),
		}
		_ = frame.WriteJSONFrame(b, resp)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	_, _, err := c.Call(ctx, 1, json.RawMessage(`{}`))
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for server goroutine")
	}
}

func TestRPC_ServerServeHonorsContextCancel(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	ctx, cancel := context.WithCancel(context.Background())
	router := rpc.NewRouter()
	srv := rpc.NewServer(a, router)
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Serve(ctx)
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context canceled, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for server to exit")
	}
}

func TestRPC_ServerServeRejectsInvalidJSON(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	router := rpc.NewRouter()
	srv := rpc.NewServer(a, router)
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Serve(ctx)
	}()

	for i := 0; i < 3; i++ {
		if err := writeRawFrame(b, []byte("{")); err != nil {
			t.Fatalf("write raw frame: %v", err)
		}
	}

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for server to exit")
	}
}

func writeRawFrame(w io.Writer, payload []byte) error {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}
