package protocolv4

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

func replacementBootstrap(t *testing.T, f *onlineBootstrapFixture, trust *NamespaceTrustStore) *NamespaceOnlineBootstrap {
	t.Helper()
	limits := f.operation.limits
	cost, err := NamespaceBootstrapCharge(limits)
	if err != nil {
		t.Fatal(err)
	}
	var op *NamespaceOnlineBootstrap
	if trust.continuity == DurableRestore {
		original := f.owner.namespace.durable
		charge, chargeErr := NamespaceDurabilityCharge(original.scope.Limits)
		if chargeErr != nil {
			t.Fatal(chargeErr)
		}
		dep := f.namespace.reserve(t, resourcev4.Vector{resourcev4.Items: 1})
		borrow, borrowErr := dep.Borrow()
		if borrowErr != nil {
			t.Fatal(borrowErr)
		}
		config := NamespaceDurabilityConfig{Scope: original.scope, Store: original.store, Reservation: f.namespace.reserve(t, charge), Dependencies: borrow}
		op, err = NewNamespaceDurableBootstrap(context.Background(), trust, limits, f.namespace.namespaceAllocation(t), f.namespace.reserve(t, cost), config)
	} else {
		op, err = NewNamespaceOnlineBootstrap(context.Background(), trust, limits, f.namespace.namespaceAllocation(t), f.namespace.reserve(t, cost))
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		op.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := op.WaitCleanup(ctx); err != nil {
			t.Error(err)
		}
		if err := op.Retire(); err != nil {
			t.Error(err)
		}
		trust.Close()
		if trust.namespace != nil {
			if err := trust.namespace.WaitCleanup(ctx); err != nil {
				t.Error(err)
			}
		}
		f.namespace.resources.Close()
		if err := trust.DestroyEnvironment(); err != nil {
			t.Error(err)
		}
	})
	return op
}

func replacementObservedHead(t *testing.T, f *onlineBootstrapFixture, sequence uint64) *NamespaceHead {
	t.Helper()
	raw, _ := f.namespace.bindHead(t, sequence, [2]uint64{})
	limit, _ := SchemaByteLimit("FreshnessHead")
	decoder, err := NewDecoder(limit, limit)
	if err != nil {
		t.Fatal(err)
	}
	codec, err := NewSignedMapCodec("FreshnessHead", limit, limit)
	if err != nil {
		t.Fatal(err)
	}
	head, err := f.owner.bindHead(decoder, codec, nil, raw.bytes)
	if err != nil {
		t.Fatal(err)
	}
	return head
}

func TestNamespaceReplacementKeepsSameSlotAndOriginalHistory(t *testing.T) {
	f, r := registryFixture(t, OnlineBootstrap, 1)
	old, err := f.operation.Run(context.Background(), f.provider)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.operation.Retire(); err != nil {
		t.Fatal(err)
	}
	next := registryAnchor(t, f, f.owner.root.Authority)
	if err = r.ReplaceFailed(f.owner, next); err == nil {
		t.Fatal("replaced healthy owner")
	}
	old.Close(errors.New("original continuity failure"))
	before := f.namespace.resources.Snapshot().Charged
	if err = r.ReplaceFailed(f.owner, next); err != nil {
		t.Fatal(err)
	}
	if r.used != 1 || r.entries[0].historyCount != 1 || r.entries[0].history[0].trust != f.owner || f.namespace.resources.Snapshot().Charged != before {
		t.Fatal("replacement evicted old responsibility or allocated another slot")
	}
	if err = r.CheckNamespace(old); err == nil {
		t.Fatal("old namespace regained authorization")
	}
	if next.continuityReady || next.count != f.owner.count {
		t.Fatal("copied history opened bootstrap gate")
	}
	op := replacementBootstrap(t, f, next)
	current, err := op.Run(context.Background(), f.provider)
	if err != nil {
		t.Fatal(err)
	}
	if err = r.CheckNamespace(current); err != nil {
		t.Fatal(err)
	}
	got, err := r.Lookup("tenant-1", "revocation-1")
	if err != nil || got != next || old.terminal == nil || f.owner.continuityReady != true {
		t.Fatal("replacement rewrote original incarnation", err)
	}
	if current.active == old.active || current.active.workspace == old.active.workspace {
		t.Fatal("new owner reused failed mutable state")
	}
	if err = r.CheckNamespace(old); err == nil {
		t.Fatal("bootstrap success revived old subscription")
	}
}

func TestNamespaceReplacementCannotForgetObservedFrontier(t *testing.T) {
	f, r := registryFixture(t, OnlineBootstrap, 1)
	old, err := f.operation.Run(context.Background(), f.provider)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.operation.Retire(); err != nil {
		t.Fatal(err)
	}
	newer := replacementObservedHead(t, f, 2)
	if err = old.Observe(newer); err != nil {
		t.Fatal(err)
	}
	old.Close(errors.New("continuity failure after observation"))
	next := registryAnchor(t, f, f.owner.root.Authority)
	if err = r.ReplaceFailed(f.owner, next); err != nil {
		t.Fatal(err)
	}
	op := replacementBootstrap(t, f, next)
	if current, err := op.Run(context.Background(), f.provider); err == nil || current != nil {
		t.Fatal("fresh nonce reset observed sequence")
	}
	if next.continuityReady {
		t.Fatal("failed coverage opened authorization")
	}
	if old.observed.sequence != 2 || r.used != 1 || r.entries[0].history[0].trust != f.owner {
		t.Fatal("failed replacement forgot old evidence")
	}
}

func TestNamespaceReplacementRetainsEarlierHistoryAcrossFailedBootstrap(t *testing.T) {
	f, r := registryFixture(t, OnlineBootstrap, 1)
	old, err := f.operation.Run(context.Background(), f.provider)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.operation.Retire(); err != nil {
		t.Fatal(err)
	}
	newer := replacementObservedHead(t, f, 2)
	if err = old.Observe(newer); err != nil {
		t.Fatal(err)
	}
	old.Close(errors.New("continuity failure"))
	middle := registryAnchor(t, f, f.owner.root.Authority)
	if err = r.ReplaceFailed(f.owner, middle); err != nil {
		t.Fatal(err)
	}
	middle.Close() // Failure before the new owner obtained any complete State.
	next := registryAnchor(t, f, f.owner.root.Authority)
	if err = r.ReplaceFailed(middle, next); err != nil {
		t.Fatal(err)
	}
	op := replacementBootstrap(t, f, next)
	if current, err := op.Run(context.Background(), f.provider); err == nil || current != nil {
		t.Fatal("second replacement forgot earlier observed history")
	}
	if r.used != 1 || r.entries[0].historyCount != 2 {
		t.Fatal("replacement lost original cleanup owners")
	}
}

type lostNamespaceCommitReply struct{ NamespaceContinuityStore }

func (s lostNamespaceCommitReply) CommitNamespace(ctx context.Context, before NamespaceContinuityVersion, wire []byte) (NamespaceContinuityVersion, error) {
	_, err := s.NamespaceContinuityStore.CommitNamespace(ctx, before, wire)
	if err != nil {
		return NamespaceContinuityVersion{}, err
	}
	return NamespaceContinuityVersion{}, errors.New("commit reply lost")
}

func TestNamespaceDurableReplacementConfirmsExactUncertainOriginal(t *testing.T) {
	f, r := registryFixture(t, DurableRestore, 1)
	old, err := f.operation.Run(context.Background(), f.provider)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.operation.Retire(); err != nil {
		t.Fatal(err)
	}
	store := old.durable.store
	old.durable.store = lostNamespaceCommitReply{store}
	newer := replacementObservedHead(t, f, 2)
	if err = old.Observe(newer); err == nil {
		t.Fatal("lost commit reply did not fail continuity")
	}
	if old.terminal == nil || old.durable.version.Revision != 1 || old.durable.attempted.Revision != 2 {
		t.Fatal("lost original write fact")
	}
	old.durable.store = store
	f.head, f.state = f.namespace.bindHead(t, 2, [2]uint64{})
	next := registryAnchor(t, f, f.owner.root.Authority)
	if err = r.ReplaceFailed(f.owner, next); err != nil {
		t.Fatal(err)
	}
	op := replacementBootstrap(t, f, next)
	current, err := op.Run(context.Background(), f.provider)
	if err != nil {
		t.Fatal(err)
	}
	if err = r.CheckNamespace(current); err != nil {
		t.Fatal(err)
	}
	if current.durable == nil || current.durable.version.Revision != 3 || current.observed.sequence != 2 {
		t.Fatal("replacement guessed predecessor or reset frontier")
	}
	if old.terminal == nil || old.durable.version.Revision != 1 {
		t.Fatal("confirmation revived original owner")
	}
}

type blockedReplacementLoad struct {
	NamespaceContinuityStore
	entered chan struct{}
	release chan struct{}
}

func (s *blockedReplacementLoad) LoadNamespace(ctx context.Context, dst []byte) (NamespaceContinuityVersion, int, error) {
	close(s.entered)
	select {
	case <-s.release:
		return s.NamespaceContinuityStore.LoadNamespace(ctx, dst)
	case <-ctx.Done():
		return NamespaceContinuityVersion{}, 0, ctx.Err()
	}
}

func TestNamespaceReplacementFencesUnpublishedOwnerDuringStoreRead(t *testing.T) {
	f, registry := registryFixture(t, DurableRestore, 1)
	old, err := f.operation.Run(context.Background(), f.provider)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.operation.Retire(); err != nil {
		t.Fatal(err)
	}
	old.Close(errors.New("continuity failure"))
	next := registryAnchor(t, f, f.owner.root.Authority)
	if err = registry.ReplaceFailed(f.owner, next); err != nil {
		t.Fatal(err)
	}
	op := replacementBootstrap(t, f, next)
	store := &blockedReplacementLoad{NamespaceContinuityStore: op.durable.store, entered: make(chan struct{}), release: make(chan struct{})}
	op.durable.store = store
	done := make(chan error, 1)
	go func() { _, err := op.Run(context.Background(), f.provider); done <- err }()
	<-store.entered
	defer func() {
		close(store.release)
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	next.mu.Lock()
	candidate := next.namespace
	next.mu.Unlock()
	if candidate == nil {
		t.Fatal("unpublished history not retained")
	}
	if err := registry.CheckNamespace(candidate); err == nil {
		t.Fatal("registry authorized unfinished replacement")
	}
	if err := candidate.Observe(candidate.observed); !errors.Is(err, timev4.ErrUnavailable) {
		t.Fatal("unfinished replacement accepted mutation", err)
	}
	if _, _, err := candidate.CheckDetachedCredential(nil, IssuerPermission{}, 0, 0, 0); !errors.Is(err, timev4.ErrUnavailable) {
		t.Fatal("unfinished replacement reached credential authorization", err)
	}
	candidate.NotifyTrust()
	candidate.mu.Lock()
	if !candidate.initializing || candidate.durable.busy || candidate.durable.version.Revision != 0 {
		t.Error("watcher published before predecessor validation")
	}
	candidate.mu.Unlock()
}
