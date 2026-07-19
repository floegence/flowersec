package rpc

import (
	"context"
	"testing"
	"time"

	rpcv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/rpc/v1"
)

func TestRequestSchedulerIsIdleUntilSubmit(t *testing.T) {
	started := make(chan struct{}, 1)
	scheduler := newRequestScheduler(context.Background(), 1, 1, func(context.Context, rpcv1.RpcEnvelope) {
		started <- struct{}{}
	})
	t.Cleanup(scheduler.Close)

	scheduler.mu.Lock()
	active := scheduler.active
	queued := len(scheduler.pending)
	scheduler.mu.Unlock()
	if active != 0 || queued != 0 {
		t.Fatalf("new scheduler has active=%d queued=%d, want both zero", active, queued)
	}

	if !scheduler.Submit(rpcv1.RpcEnvelope{RequestId: 1}) {
		t.Fatal("first request was rejected")
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("submitted request did not start")
	}
}

func TestRequestSchedulerBoundsConcurrencyAndPreservesFIFO(t *testing.T) {
	started := make(chan uint64, 4)
	finished := make(chan uint64, 4)
	release := make(chan struct{})
	scheduler := newRequestScheduler(context.Background(), 1, 2, func(ctx context.Context, env rpcv1.RpcEnvelope) {
		started <- env.RequestId
		select {
		case <-release:
		case <-ctx.Done():
		}
		finished <- env.RequestId
	})
	t.Cleanup(scheduler.Close)

	if !scheduler.Submit(rpcv1.RpcEnvelope{RequestId: 1}) {
		t.Fatal("first request was rejected")
	}
	expectRequestID(t, started, 1, "start")
	for requestID := uint64(2); requestID <= 3; requestID++ {
		if !scheduler.Submit(rpcv1.RpcEnvelope{RequestId: requestID}) {
			t.Fatalf("request %d was rejected", requestID)
		}
	}
	if scheduler.Submit(rpcv1.RpcEnvelope{RequestId: 4}) {
		t.Fatal("request beyond the queue limit was accepted")
	}

	for want := uint64(1); want <= 3; want++ {
		release <- struct{}{}
		expectRequestID(t, finished, want, "finish")
		if want < 3 {
			expectRequestID(t, started, want+1, "start")
		}
	}

	if !scheduler.Submit(rpcv1.RpcEnvelope{RequestId: 4}) {
		t.Fatal("scheduler did not accept a request after becoming idle")
	}
	expectRequestID(t, started, 4, "start")
	release <- struct{}{}
	expectRequestID(t, finished, 4, "finish")
}

func TestRequestSchedulerCloseCancelsAndWaitsForActiveHandlers(t *testing.T) {
	started := make(chan uint64, 2)
	canceled := make(chan struct{})
	release := make(chan struct{})
	scheduler := newRequestScheduler(context.Background(), 1, 1, func(ctx context.Context, env rpcv1.RpcEnvelope) {
		started <- env.RequestId
		<-ctx.Done()
		close(canceled)
		<-release
	})
	if !scheduler.Submit(rpcv1.RpcEnvelope{RequestId: 1}) {
		t.Fatal("request was rejected")
	}
	expectRequestID(t, started, 1, "start")
	if !scheduler.Submit(rpcv1.RpcEnvelope{RequestId: 2}) {
		t.Fatal("queued request was rejected")
	}

	done := make(chan struct{})
	go func() {
		scheduler.Close()
		close(done)
	}()

	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("active handler was not canceled")
	}
	select {
	case <-done:
		t.Fatal("Close returned before the active handler finished")
	default:
	}
	close(release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Close did not wait for the active handler")
	}
	if scheduler.Submit(rpcv1.RpcEnvelope{RequestId: 3}) {
		t.Fatal("closed scheduler accepted a request")
	}
	select {
	case got := <-started:
		t.Fatalf("queued request %d started during Close", got)
	default:
	}
}

func TestRequestSchedulerUsesConfiguredConcurrency(t *testing.T) {
	started := make(chan uint64, 2)
	finished := make(chan struct{}, 2)
	release := make(chan struct{})
	scheduler := newRequestScheduler(context.Background(), 2, 0, func(ctx context.Context, env rpcv1.RpcEnvelope) {
		started <- env.RequestId
		select {
		case <-release:
		case <-ctx.Done():
		}
		finished <- struct{}{}
	})
	t.Cleanup(scheduler.Close)

	if !scheduler.Submit(rpcv1.RpcEnvelope{RequestId: 1}) ||
		!scheduler.Submit(rpcv1.RpcEnvelope{RequestId: 2}) {
		t.Fatal("requests within the concurrency limit were rejected")
	}
	seen := map[uint64]bool{}
	for range 2 {
		select {
		case id := <-started:
			seen[id] = true
		case <-time.After(time.Second):
			t.Fatal("configured concurrent handlers did not start")
		}
	}
	if !seen[1] || !seen[2] {
		t.Fatalf("started requests = %v, want 1 and 2", seen)
	}
	if scheduler.Submit(rpcv1.RpcEnvelope{RequestId: 3}) {
		t.Fatal("request beyond concurrency with no queue was accepted")
	}
	release <- struct{}{}
	release <- struct{}{}
	for range 2 {
		select {
		case <-finished:
		case <-time.After(time.Second):
			t.Fatal("concurrent handler did not finish")
		}
	}
}

func TestRequestSchedulerParentCancelDoesNotStartQueuedHandlers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan uint64, 2)
	scheduler := newRequestScheduler(ctx, 1, 1, func(ctx context.Context, env rpcv1.RpcEnvelope) {
		started <- env.RequestId
		<-ctx.Done()
	})
	t.Cleanup(scheduler.Close)

	if !scheduler.Submit(rpcv1.RpcEnvelope{RequestId: 1}) {
		t.Fatal("active request was rejected")
	}
	expectRequestID(t, started, 1, "start")
	if !scheduler.Submit(rpcv1.RpcEnvelope{RequestId: 2}) {
		t.Fatal("queued request was rejected")
	}

	cancel()
	scheduler.Close()
	select {
	case got := <-started:
		t.Fatalf("queued request %d started after parent cancellation", got)
	default:
	}
	if scheduler.Submit(rpcv1.RpcEnvelope{RequestId: 3}) {
		t.Fatal("scheduler accepted a request after parent cancellation")
	}
}

func expectRequestID(t *testing.T, ch <-chan uint64, want uint64, action string) {
	t.Helper()
	select {
	case got := <-ch:
		if got != want {
			t.Fatalf("%s request = %d, want %d", action, got, want)
		}
	case <-time.After(time.Second):
		t.Fatalf("request %d did not %s", want, action)
	}
}
