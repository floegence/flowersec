package sessionv4

import (
	"errors"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

func TestControllerWorkloadDispatchKeepsAliasesAfterSessionRetirement(t *testing.T) {
	f, services, controller, sessions, _ := controllerReselectionFixture(t)
	r := services[0]
	limit := f.f.root.Snapshot().Limit
	tenant, err := f.f.root.Account(resourcev4.AccountKey{Kind: resourcev4.TenantAccount, ID: [16]byte{211}}, limit)
	if err != nil {
		t.Fatal(err)
	}
	defer tenant.Close()
	session, err := f.f.root.Account(resourcev4.AccountKey{Kind: resourcev4.SessionAccount, ID: [16]byte{212}}, limit)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	r.accounts[0], r.accounts[1], r.accountCount = tenant, session, 2
	method := controllerServiceDefinition(f).Methods[0].Method
	w, err := r.reserveUnaryWorkload(method, 8, 1024, 1)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { w.seal(); r.advanceWorkloads() })
	if err := w.reserveController(controller); err != nil {
		t.Fatal(err)
	}
	d, err := controller.reserveOperationDispatch(sessions[0], controllerRoutingIdentity{}, w.slots[0].controller)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.close)
	session.Close()
	w.seal()
	r.advanceWorkloads()
	if w.cleaned {
		t.Fatal("retired Session refunded the actual Controller owner")
	}
	saturateWorkloadRoot(t, f)
	before := f.f.root.Snapshot()
	var clones [3]controllerDispatch
	for i := range clones {
		clones[i], err = d.clone()
		if err != nil {
			t.Fatal("retirement lost an original tentative-route alias", err)
		}
		t.Cleanup(clones[i].close)
	}
	if _, err := d.clone(); !errors.Is(err, resourcev4.ErrCapacity) {
		t.Fatal("dispatch exceeded admitted aliases", err)
	}
	if f.f.root.Snapshot() != before {
		t.Fatal("clone allocated instead of consuming its original alias")
	}
	d.close()
	r.advanceWorkloads()
	if w.cleaned {
		t.Fatal("original handle release refunded surviving invocation aliases")
	}
	for i := range clones {
		clones[i].close()
	}
	r.advanceWorkloads()
	if !w.cleaned {
		t.Fatal("actual invocation exit retained the retired target")
	}
	if usage, _ := tenant.Usage(); usage != (resourcev4.Vector{}) {
		t.Fatal("Controller tail retained tenant responsibility", usage)
	}
}

func TestControllerWorkloadDispatchPartialAdmissionUnwinds(t *testing.T) {
	f, services, controller, _, _ := controllerReselectionFixture(t)
	r := services[0]
	w, err := r.reserveUnaryWorkload(controllerServiceDefinition(f).Methods[0].Method, 8, 1024, 2)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { w.seal(); r.advanceWorkloads() })
	fill := f.f.reserve(t, 1, resourcev4.Vector{resourcev4.SDKBytes: 32})
	var held []resourcev4.Reference
	for {
		alias, err := fill.Borrow()
		if errors.Is(err, resourcev4.ErrCapacity) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, alias)
	}
	t.Cleanup(func() {
		for _, alias := range held {
			alias.Release()
		}
		fill.Release()
	})
	// One actual floor needs its primary, Controller anchor and three aliases.
	// The second target must unwind that successful first admission.
	for range 5 {
		last := len(held) - 1
		held[last].Release()
		held = held[:last]
	}
	before := f.f.root.Snapshot()
	if err := w.reserveController(controller); !errors.Is(err, resourcev4.ErrCapacity) {
		t.Fatal("partial Controller target was returned", err)
	}
	if f.f.root.Snapshot() != before || controller.dispatches != 0 {
		t.Fatal("failed Controller target retained original backing")
	}
	for _, p := range controller.workloadPositions {
		if p != nil {
			t.Fatal("failed Controller target retained a future position")
		}
	}
}
