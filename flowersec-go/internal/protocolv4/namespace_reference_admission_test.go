package protocolv4

import (
	"context"
	"errors"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

func occupyNamespaceReferences(t *testing.T, ref resourcev4.Reference) []resourcev4.Reference {
	t.Helper()
	var held []resourcev4.Reference
	for {
		alias, err := ref.Borrow()
		if errors.Is(err, resourcev4.ErrCapacity) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, alias)
	}
	t.Cleanup(func() {
		for _, ref := range held {
			ref.Release()
		}
	})
	return held
}

func TestNamespaceSubscriptionsReuseOriginalReferencesAtFullRoot(t *testing.T) {
	f := newNamespaceFixture(t)
	n, _, _ := liveNamespaceFixture(t, f, 4000, false)
	stale := n.subscribers[0].reservation
	occupyNamespaceReferences(t, n.reservation)
	full := f.resources.Snapshot()
	for range 3 {
		var subscriptions [8]namespaceSubscription
		for i := range subscriptions {
			var err error
			subscriptions[i], err = n.subscribe(make(chan struct{}, 1))
			if err != nil {
				t.Fatal("subscription requested another reference", err)
			}
		}
		if err := stale.Check(); !errors.Is(err, resourcev4.ErrOwner) {
			t.Fatal("original idle alias remained live", err)
		}
		stale.Release()
		if _, err := n.subscribe(make(chan struct{}, 1)); err != CBORFailure("revocation_subscription_capacity") {
			t.Fatal(err)
		}
		for _, subscription := range subscriptions {
			subscription.release()
			subscription.release()
		}
		if n.SubscriptionCount() != 0 || f.resources.Snapshot() != full {
			t.Fatal("release lost original namespace capacity")
		}
	}
}

func TestNamespaceReferenceShortageRejectsUnpublishedWholeOwner(t *testing.T) {
	f := newNamespaceFixture(t)
	clock, _ := namespaceClockFixture(t, f, false)
	head, content := f.bindHead(t, 1, [2]uint64{})
	allocation := f.namespaceAllocation(t)
	fill := f.reserve(t, resourcev4.Vector{resourcev4.Items: 1})
	held := occupyNamespaceReferences(t, fill)
	// Three primary owners and only seven of the eight subscriber references.
	for _, ref := range held[:10] {
		ref.Release()
	}
	before := f.resources.Snapshot()
	n, err := NewBootstrappedNamespace(context.Background(), clock, &testNamespaceTrust{}, NamespaceBootstrap{Rules: f.rules, Head: head, State: content}, 4000, 2, 8, allocation)
	if n != nil || !errors.Is(err, resourcev4.ErrCapacity) || f.resources.Snapshot() != before {
		t.Fatal("partial namespace publication or retained references", err, before, f.resources.Snapshot())
	}
}
