package tunnelworkload

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func newCleanupTestEndpoint(t *testing.T, pending ...*preparedTunnel) *Endpoint {
	t.Helper()
	ctx, cancel := context.WithCancelCause(context.Background())
	t.Cleanup(func() { cancel(context.Canceled) })
	endpoint := &Endpoint{
		topology:               TopologyQQ,
		ctx:                    ctx,
		cancel:                 cancel,
		slots:                  make([]*Pair, 1),
		building:               make([]bool, 1),
		constructionDone:       make(chan struct{}),
		pendingPreparedTunnels: append([]*preparedTunnel(nil), pending...),
	}
	return endpoint
}

func blockingPreparedTunnel(release <-chan struct{}) *preparedTunnel {
	return &preparedTunnel{
		cleanupWaiters: []func(context.Context) error{func(ctx context.Context) error {
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}},
	}
}

func TestPreparedCleanupNeverReturnsToConnectableQueue(t *testing.T) {
	release := make(chan struct{})
	prepared := blockingPreparedTunnel(release)
	endpoint := newCleanupTestEndpoint(t)
	endpoint.preparedTunnels = []*preparedTunnel{prepared}

	endpoint.retainPreparedCleanup(prepared)
	if len(endpoint.preparedTunnels) != 0 || len(endpoint.pendingPreparedTunnels) != 1 {
		t.Fatalf("prepared cleanup item was left connectable: ready=%d pending=%d", len(endpoint.preparedTunnels), len(endpoint.pendingPreparedTunnels))
	}
	if _, err := endpoint.Connect(context.Background()); err == nil {
		t.Fatal("Connect acquired a prepared deployment that still required cleanup")
	}
	if err := endpoint.PrepareCapacity(context.Background(), 1); err == nil {
		t.Fatal("PrepareCapacity replaced a pending prepared deployment")
	}

	close(release)
	if err := endpoint.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(endpoint.pendingPreparedTunnels) != 0 {
		t.Fatal("completed cleanup retained a prepared deployment")
	}
}

func TestPreparedCleanupRetainsFinitePositionAfterCloseTimeout(t *testing.T) {
	release := make(chan struct{})
	prepared := blockingPreparedTunnel(release)
	endpoint := newCleanupTestEndpoint(t, prepared)

	cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	err := endpoint.Close(cleanup)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Close error = %v, want cleanup timeout", err)
	}
	if prepared.isCleaned() {
		t.Fatal("prepared deployment was marked cleaned before its owner exited")
	}
	if len(endpoint.pendingPreparedTunnels) != 1 || len(endpoint.preparedTunnels) != 0 {
		t.Fatalf("timed out cleanup changed queue ownership: ready=%d pending=%d", len(endpoint.preparedTunnels), len(endpoint.pendingPreparedTunnels))
	}

	close(release)
	if err := endpoint.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(endpoint.pendingPreparedTunnels) != 0 {
		t.Fatal("retry did not release the completed cleanup position")
	}
}

func TestPreparedCleanupRetriesWhenContextCancelsAfterLastWaiter(t *testing.T) {
	cleanup, cancel := context.WithCancel(context.Background())
	defer cancel()
	var calls atomic.Int32
	prepared := &preparedTunnel{cleanupWaiters: []func(context.Context) error{func(context.Context) error {
		if calls.Add(1) == 1 {
			// Simulate the physical owner reaching its terminal state at the
			// exact boundary where the bounded cleanup context is canceled.
			cancel()
		}
		return nil
	}}}
	endpoint := newCleanupTestEndpoint(t, prepared)
	if err := endpoint.Close(cleanup); !errors.Is(err, context.Canceled) {
		t.Fatalf("first cleanup error = %v, want cancellation", err)
	}
	if prepared.isCleaned() {
		t.Fatal("prepared deployment was marked cleaned before finalization completed")
	}
	if len(endpoint.preparedTunnels) != 0 || len(endpoint.pendingPreparedTunnels) != 1 {
		t.Fatalf("canceled cleanup lost ownership: ready=%d pending=%d", len(endpoint.preparedTunnels), len(endpoint.pendingPreparedTunnels))
	}
	if err := endpoint.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !prepared.isCleaned() {
		t.Fatal("retry did not complete prepared cleanup")
	}
}
