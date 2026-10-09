package protocolv4

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// Build through the configured factory's current allocation policy while
// leaving the work slot free for the explicit recovery observer under test.
func retirementRecoveryOperation(t *testing.T, factory *NamespaceReferenceFactory, registry *NamespaceRegistry, previous *NamespaceTrustStore) *NamespaceOnlineRetirement {
	t.Helper()
	// Recovery starts from retained closed history. Join its real watchdog
	// before requesting exclusivity; an in-flight clock read is still an owner.
	previous.Close()
	previous.mu.Lock()
	original := previous.namespace
	previous.mu.Unlock()
	if original != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := original.WaitCleanup(ctx); err != nil {
			t.Fatal(err)
		}
	}
	factory.mu.Lock()
	config := factory.slots[0].config
	factory.mu.Unlock()
	next, job, allocation, err := factory.allocate(config, true)
	if err != nil {
		t.Fatal(err)
	}
	operation, err := NewNamespaceOnlineRetirement(factory.ctx, registry, previous, next, config.Bootstrap, allocation, job)
	if err != nil {
		job.Release()
		disposeNamespaceReferenceCandidate(next)
		t.Fatal(err)
	}
	return operation
}

func TestRetirementPreservationConcurrentObserversTransferHistoryOnce(t *testing.T) {
	f, registry, _ := retirementFixture(t)
	factory := referenceFactoryFixture(t, f, registry)
	operation := retirementRecoveryOperation(t, factory, registry, f.owner)
	next := operation.next
	var err error
	provider := bootstrapTestProvider{
		query: func(context.Context, NamespaceBootstrapRequest, []byte) (int, error) {
			return 0, errors.New("independent authority unavailable")
		},
		fetch: func(context.Context, NamespaceContent, []byte) (int, error) {
			t.Error("failed query dispatched content fetch")
			return 0, errors.New("unexpected fetch")
		},
	}
	if err = operation.Run(context.Background(), provider); err == nil {
		t.Fatal("refused proof succeeded")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	results := make(chan error, 2)
	start := make(chan struct{})
	for i := 0; i < 2; i++ {
		go func() { <-start; results <- operation.PreserveForReplacement(ctx) }()
	}
	close(start)
	for i := 0; i < 2; i++ {
		select {
		case err := <-results:
			if err != nil {
				t.Fatal("same preservation observer failed", err)
			}
		case <-ctx.Done():
			t.Fatal("concurrent preservation did not exit", ctx.Err())
		}
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	entry := registry.entries[0]
	if registry.used != 1 || entry.historyCount != 1 || entry.history[0].trust != f.owner || entry.trust != next || entry.retirement != nil || !entry.retirementFailed {
		t.Fatal("concurrent observers duplicated history or opened pressure retry")
	}
}

func TestReferenceResolveContinuesCanceledPreservationInOriginalSlot(t *testing.T) {
	f, registry, originalNamespace := retirementFixture(t)
	factory := referenceFactoryFixture(t, f, registry)
	operation := retirementRecoveryOperation(t, factory, registry, f.owner)
	next := operation.next
	var err error
	var queries atomic.Uint32
	provider := bootstrapTestProvider{
		query: func(context.Context, NamespaceBootstrapRequest, []byte) (int, error) {
			queries.Add(1)
			return 0, errors.New("independent authority unavailable")
		},
		fetch: func(context.Context, NamespaceContent, []byte) (int, error) {
			t.Error("failed query dispatched content fetch")
			return 0, errors.New("unexpected fetch")
		},
	}
	if err = operation.Run(context.Background(), provider); err == nil {
		t.Fatal("refused proof succeeded")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err = operation.PreserveForReplacement(canceled); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled preservation did not detach its observer", err)
	}
	registry.mu.Lock()
	pending := registry.used == 1 && registry.entries[0].retirement == operation && registry.entries[0].trust == f.owner
	registry.mu.Unlock()
	if !pending || originalNamespace.destroyed {
		t.Fatal("canceled observer forgot original pending job/history")
	}
	ctx, stop := context.WithTimeout(context.Background(), 3*time.Second)
	defer stop()
	owner, err := factory.Resolve(ctx, f.owner.root.Tenant, f.owner.root.Authority)
	if err != nil {
		t.Fatal("explicit Resolve could not continue original preservation", err)
	}
	registry.mu.Lock()
	entry := registry.entries[0]
	registry.mu.Unlock()
	if registry.used != 1 || entry.historyCount != 2 || entry.history[0].trust != f.owner || entry.history[1].trust != next || entry.trust != owner || !owner.continuityReady {
		t.Fatal("recovery lost same-slot history or skipped independent replacement bootstrap")
	}
	if queries.Load() != 1 || originalNamespace.destroyed {
		t.Fatal("recovery restarted failed proof or deleted original history")
	}
}

func TestReferenceFactoryFailedProofPreservesBeforeReleasingWorkSlot(t *testing.T) {
	f, registry, _ := retirementFixture(t)
	factory := referenceFactoryFixture(t, f, registry)
	var queries atomic.Uint32
	factory.mu.Lock()
	factory.slots[0].config.Provider = bootstrapTestProvider{
		query: func(context.Context, NamespaceBootstrapRequest, []byte) (int, error) {
			queries.Add(1)
			return 0, errors.New("independent authority unavailable")
		},
		fetch: func(context.Context, NamespaceContent, []byte) (int, error) {
			t.Error("failed query dispatched content fetch")
			return 0, errors.New("unexpected fetch")
		},
	}
	factory.mu.Unlock()
	operation, provider, err := factory.PrepareNamespaceRetirement(context.Background(), registry, f.owner)
	if err != nil {
		t.Fatal(err)
	}
	factory.mu.Lock()
	cleanup := factory.slots[0].cleanup
	factory.mu.Unlock()
	if err = operation.Run(context.Background(), provider); err == nil {
		t.Fatal("refused proof succeeded")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	select {
	case <-cleanup:
	case <-ctx.Done():
		t.Fatal("original failed job's physical cleanup did not exit", ctx.Err())
	}
	registry.mu.Lock()
	entry := registry.entries[0]
	registry.mu.Unlock()
	if registry.used != 1 || entry.retirement != nil || entry.trust != operation.next || entry.historyCount != 1 || !entry.retirementFailed {
		t.Fatal("factory released its slot without preserving same-job history")
	}
	factory.mu.Lock()
	factory.slots[0].config.Provider = f.provider
	factory.mu.Unlock()
	owner, err := factory.Resolve(ctx, f.owner.root.Tenant, f.owner.root.Authority)
	if err != nil {
		t.Fatal("preserved slot could not independently recover", err)
	}
	if queries.Load() != 1 || owner == operation.next || !owner.continuityReady {
		t.Fatal("failed proof repeated or replacement skipped its own bootstrap")
	}
}
