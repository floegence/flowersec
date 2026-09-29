package sessionv4

import (
	"context"
	"errors"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

func TestApplicationWorkloadKeepsEightActualAncestorsWithNoFreeRootSlots(t *testing.T) {
	f := newExecutorFixture(t, 2, 1)
	var owners [maxApplicationAncestors]resourcev4.Reference
	var exits [maxApplicationAncestors]func()
	var current context.Context = context.Background()
	for i := range owners {
		owners[i] = f.reserve(t, 1, resourcev4.Vector{resourcev4.SDKBytes: applicationContextBytes(), resourcev4.Items: 1})
		parents, err := captureApplicationDependencies(current)
		if err != nil {
			t.Fatal(err)
		}
		current, exits[i], err = enterApplicationContext(context.Background(), f.executor, ordinaryApplicationLane, ApplicationShort, owners[i], &parents)
		parents.release()
		if err != nil {
			t.Fatal(err)
		}
		defer exits[i]()
	}
	charge, err := resourcev4.BorrowPoolCharge(2 * maxApplicationAncestors)
	if err != nil {
		t.Fatal(err)
	}
	floor, err := resourcev4.NewBorrowPoolForSources(f.reserve(t, 1, charge), 2*maxApplicationAncestors)
	if err != nil {
		t.Fatal(err)
	}
	defer floor.Close()
	pressure := f.reserve(t, 1, resourcev4.Vector{resourcev4.SDKBytes: 1})
	var occupied []resourcev4.Reference
	defer func() {
		for _, ref := range occupied {
			ref.Release()
		}
	}()
	for {
		ref, err := pressure.Borrow()
		if errors.Is(err, resourcev4.ErrCapacity) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		occupied = append(occupied, ref)
	}
	before := f.root.Snapshot()
	dependencies, err := captureApplicationDependenciesWithFloor(current, floor)
	if err != nil {
		t.Fatal(err)
	}
	defer dependencies.release()
	var child applicationDependencies
	if err := child.merge(&dependencies); err != nil {
		t.Fatal(err)
	}
	defer child.release()
	if dependencies.count != maxApplicationAncestors || child.count != maxApplicationAncestors || f.root.Snapshot() != before {
		t.Fatal("capture or merge lost ancestors or allocated another reference")
	}
	for i := range owners {
		exits[i]()
		owners[i].Release()
	}
	if f.root.Snapshot().Charged != before.Charged {
		t.Fatal("parent exit refunded accepted descendants")
	}
	child.release()
	if f.root.Snapshot().Charged != before.Charged {
		t.Fatal("one descendant released another descendant's parents")
	}
	dependencies.release()
	if got := f.root.Snapshot().Charged[resourcev4.SDKBytes]; got != before.Charged[resourcev4.SDKBytes]-maxApplicationAncestors*applicationContextBytes() {
		t.Fatal("final descendant did not release all actual parents", got)
	}
	if floor.CheckAvailable() != nil {
		t.Fatal("physical dependency positions did not return")
	}
}

func TestInvocationServiceRetainsRegistrationAndDistinctOriginThroughClose(t *testing.T) {
	f, r, _, definition := serviceShapesFixture(t)
	client, err := r.bindMethods(context.Background(), definition, UnaryServiceBindOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	selector := UnaryMethodSelector{Namespace: definition.Namespace, Type: 1}
	services := invocationDeclarations(t, f.f, []ServiceDependency{{Alias: "files", Client: client, Methods: []ServiceDependencyMethod{{Method: selector}}}})
	backing := f.f.reserve(t, 1, resourcev4.Vector{resourcev4.SDKBytes: applicationContextBytes(), resourcev4.Items: 1})
	ctx, exit, err := enterApplicationContext(context.Background(), f.f.executor, ordinaryApplicationLane, ApplicationShort, backing, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer exit()
	if err := attachInvocationServices(ctx, services); err != nil {
		t.Fatal(err)
	}
	view, err := InvocationServiceFromContext(ctx, "files")
	if err != nil {
		t.Fatal(err)
	}
	selected, use, err := view.selectMethod(ctx, selector)
	if err != nil || selected != client {
		t.Fatal("could not select declared method", err)
	}
	defer use.Release()
	if use.origin.CheckBorrowedFrom(backing) != nil || use.registration.CheckBorrowedFrom(services.primary) != nil {
		t.Fatal("view confused its invocation origin and registration")
	}
	exit()
	services.close()
	backing.Release()
	if len(services.bindings) != 1 || services.bindings[0].client != client || services.visits != 1 || use.origin.CheckRetained() != nil {
		t.Fatal("close cleared resources still used by the selected view")
	}
	if _, _, err := view.selectMethod(ctx, selector); !errors.Is(err, ErrApplicationDependency) {
		t.Fatal("exited origin selected more work", err)
	}
	use.Release()
	if services.bindings != nil || services.backing != (resourcev4.Reference{}) || services.visits != 0 {
		t.Fatal("last selected method failed to settle closed registration")
	}
}
