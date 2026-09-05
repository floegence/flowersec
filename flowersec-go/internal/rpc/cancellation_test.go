package rpc

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"testing"
	"time"
)

func TestCanceledCallDoesNotWrite(t *testing.T) {
	local, remote := net.Pipe()
	defer remote.Close()
	client := NewClient(local)
	defer client.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err := client.Call(ctx, 1, json.RawMessage(`null`))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Call = %v", err)
	}
	if len(client.pending) != 0 {
		t.Fatal("canceled call retained pending request")
	}
}

func TestRPCCancellationInterruptsBlockedWrite(t *testing.T) {
	for _, notify := range []bool{false, true} {
		local, remote := net.Pipe()
		client := NewClient(local)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
		done := make(chan error, 1)
		go func() {
			if notify {
				done <- client.NotifyContext(ctx, 1, json.RawMessage(`null`))
				return
			}
			_, _, err := client.Call(ctx, 1, json.RawMessage(`null`))
			done <- err
		}()
		select {
		case err := <-done:
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Errorf("operation = %v", err)
			}
		case <-time.After(time.Second):
			t.Error("blocked write ignored deadline")
		}
		cancel()
		remote.Close()
		client.Close()
	}
}

func TestQueuedRPCCancellationDoesNotCloseStream(t *testing.T) {
	local, remote := net.Pipe()
	defer remote.Close()
	client := NewClient(local)
	defer client.Close()
	client.writePermit <- struct{}{}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, _, err := client.Call(ctx, 1, json.RawMessage(`null`)); done <- err }()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Call = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("queued call ignored cancellation")
	}
	<-client.writePermit
	if client.notifyCtx.Err() != nil {
		t.Fatal("queued cancellation closed the RPC stream")
	}
}
