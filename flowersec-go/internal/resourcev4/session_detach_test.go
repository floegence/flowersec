package resourcev4

import (
	"errors"
	"testing"
)

func TestDetachSessionKeepsActualAliasesAndSharedBudget(t *testing.T) {
	limit := Vector{SDKBytes: 1024, Items: 4}
	r := testRoot(t, limit, 4, 8)
	tenant := account(t, r, TenantAccount, 1, limit)
	environment := account(t, r, EnvironmentAccount, 1, limit)
	session := account(t, r, SessionAccount, 1, limit)
	direction := account(t, r, DirectionAccount, 1, limit)
	charge := Vector{SDKBytes: 128, Items: 1}
	ref, err := r.ReserveResult(owner(1), charge, tenant, environment, session, direction)
	if err != nil {
		t.Fatal(err)
	}
	defer ref.Release()
	alias, err := ref.Borrow()
	if err != nil {
		t.Fatal(err)
	}
	defer alias.Release()
	before := r.Snapshot()
	if err := ref.DetachSessionScope(); err != nil {
		t.Fatal(err)
	}
	if r.Snapshot() != before {
		t.Fatal("private ownership transfer changed root backing")
	}
	for _, scope := range []Account{tenant, environment, session, direction} {
		if usage, _ := scope.Usage(); usage != charge {
			t.Fatal("real alias lost its scope", usage)
		}
	}
	session.Close()
	direction.Close()
	if err := ref.Check(); err != nil {
		t.Fatal("Session closure fenced detached result", err)
	}
	if err := alias.Check(); !errors.Is(err, ErrClosed) {
		t.Fatal("Session alias bypassed closure", err)
	}
	alias.Release()
	for _, scope := range []Account{tenant, environment} {
		if usage, _ := scope.Usage(); usage != charge {
			t.Fatal("detached result escaped shared accounting", usage)
		}
	}
	if r.Snapshot().ResultOwners != 1 {
		t.Fatal("transfer refunded result-owner position")
	}
	environment.Close()
	if err := ref.Check(); !errors.Is(err, ErrClosed) {
		t.Fatal("detached result bypassed Environment closure", err)
	}
}

func TestDetachSessionRejectsReusableProtectedBacking(t *testing.T) {
	minimum := Vector{SDKBytes: 128, Items: 1}
	charge, _ := ProtectedCharge(minimum)
	r := testRoot(t, charge, 1, 2)
	session := account(t, r, SessionAccount, 1, charge)
	ref, err := r.Reserve(owner(1), charge, session)
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewProtectedReservation(ref, minimum)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	live, err := p.Checkout()
	if err != nil {
		t.Fatal(err)
	}
	defer live.Release()
	before := r.Snapshot()
	if err := live.DetachSessionScope(); !errors.Is(err, ErrOwner) || r.Snapshot() != before {
		t.Fatal("reusable floor escaped original Session", err)
	}
}

func TestProtectedResultKeepsFloorUntilRealReturnAndDetachesAtRetirement(t *testing.T) {
	minimum := Vector{SDKBytes: 128, Items: 1}
	charge, _ := ProtectedCharge(minimum)
	r := testRoot(t, charge, 1, 3)
	tenant := account(t, r, TenantAccount, 1, charge)
	environment := account(t, r, EnvironmentAccount, 1, charge)
	session := account(t, r, SessionAccount, 1, charge)
	ref, err := r.ReserveResult(owner(1), charge, tenant, environment, session)
	if err != nil {
		t.Fatal(err)
	}
	anchor, err := ref.Borrow()
	if err != nil {
		t.Fatal(err)
	}
	alias, err := ref.Borrow()
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewProtectedResultReservation(ref, minimum, anchor, alias)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	before := r.Snapshot()
	for range 3 {
		live, err := p.Checkout()
		if err != nil {
			t.Fatal(err)
		}
		tail, err := live.Borrow()
		if err != nil {
			t.Fatal(err)
		}
		if err := live.DetachSessionScope(); err != nil {
			t.Fatal(err)
		}
		if err := tail.DetachSessionScope(); err != nil {
			t.Fatal(err)
		}
		if usage, _ := session.Usage(); usage != charge {
			t.Fatal("active Session floor escaped its account", usage)
		}
		live.Release()
		if _, err := p.Checkout(); !errors.Is(err, ErrCapacity) {
			t.Fatal("duplicated live result tail", err)
		}
		tail.Release()
		if r.Snapshot() != before {
			t.Fatal("floor did not return its original references", before, r.Snapshot())
		}
	}
	live, err := p.Checkout()
	if err != nil {
		t.Fatal(err)
	}
	defer live.Release()
	tail, err := live.Borrow()
	if err != nil {
		t.Fatal(err)
	}
	defer tail.Release()
	if err := live.DetachSessionScope(); err != nil {
		t.Fatal(err)
	}
	if err := tail.DetachSessionScope(); err != nil {
		t.Fatal(err)
	}
	p.CloseAfterUse()
	if !p.CleanupComplete() {
		t.Fatal("independent result blocked retired Session floor")
	}
	if usage, _ := session.Usage(); usage != (Vector{}) {
		t.Fatal("retired Session still held independent result", usage)
	}
	session.Close()
	if err := live.Check(); err != nil {
		t.Fatal("Session retirement revoked independent result", err)
	}
	if r.Snapshot().ResultOwners != 1 {
		t.Fatal("retired floor refunded live result")
	}
	live.Release()
	if r.Snapshot().ResultOwners != 1 {
		t.Fatal("remaining actual tail was refunded")
	}
	tail.Release()
	if r.Snapshot().ResultOwners != 0 {
		t.Fatal("independent result leaked")
	}
}
