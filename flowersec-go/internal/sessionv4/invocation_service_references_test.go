package sessionv4

import (
	"context"
	"errors"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

func TestInvocationViewUsesAdmittedReferencesAtFullRootCapacity(t *testing.T) {
	f, r, _, definition := serviceShapesFixture(t)
	client, err := r.bindMethods(context.Background(), definition, UnaryServiceBindOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	selector := UnaryMethodSelector{Namespace: definition.Namespace, Type: 1}
	declarations := []ServiceDependency{{Alias: "files", Client: client, Methods: []ServiceDependencyMethod{{Method: selector}}}}
	services := invocationDeclarations(t, f.f, declarations)
	runSynchronousParent(t, f, ApplicationShort, func(ctx context.Context) {
		if err := attachInvocationServices(ctx, services); err != nil {
			t.Fatal(err)
		}
		view, err := InvocationServiceFromContext(ctx, "files")
		if err != nil {
			t.Fatal(err)
		}
		var occupied []resourcev4.Reference
		defer func() {
			for _, ref := range occupied {
				ref.Release()
			}
		}()
		for {
			ref, err := services.primary.Borrow()
			if errors.Is(err, resourcev4.ErrCapacity) {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			occupied = append(occupied, ref)
		}
		before := f.f.root.Snapshot()
		selected, use, err := view.selectMethod(ctx, selector)
		if err != nil || selected != client {
			t.Fatal("admitted view competed for a fresh reference", err)
		}
		defer use.Release()
		if f.f.root.Snapshot() != before || use.registration.CheckBorrowedFrom(services.primary) != nil {
			t.Fatal("view lost its exact registration or changed admission")
		}
		services.close()
		if len(services.bindings) == 0 || use.origin.Check() != nil || use.registration.Check() != nil {
			t.Fatal("registration close refunded a selected view")
		}
		use.Release()
		if services.bindings == nil || services.viewReferences == nil {
			t.Fatal("selected-view exit refunded a live invocation declaration")
		}
	})
	if services.bindings != nil || services.viewReferences != nil {
		t.Fatal("last invocation exit failed to settle original admission")
	}
}

func TestInvocationReferenceCapacityDeduplicatesAliasesAndIncludesGenericCalls(t *testing.T) {
	f, r, _, definition := serviceShapesFixture(t)
	_ = f
	client, err := r.bindMethods(context.Background(), definition, UnaryServiceBindOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	method := ServiceDependencyMethod{Method: UnaryMethodSelector{Namespace: definition.Namespace, Type: 1}}
	declarations := []ServiceDependency{{Alias: "first", Client: client, Methods: []ServiceDependencyMethod{method}}, {Alias: "second", Client: client, Methods: []ServiceDependencyMethod{method}}}
	capacity, err := invocationViewReferenceCapacity(declarations)
	if err != nil || capacity != uint32(2*len(client.calls)) {
		t.Fatal("aliases duplicated the generic binding capacity", capacity, err)
	}
	client.mu.Lock()
	client.methods[0].workload.Calls = 7
	client.mu.Unlock()
	capacity, err = invocationViewReferenceCapacity(declarations)
	if err != nil || capacity != uint32(2*(len(client.calls)+7)) {
		t.Fatal("declared workload did not retain generic call capacity", capacity, err)
	}
}
