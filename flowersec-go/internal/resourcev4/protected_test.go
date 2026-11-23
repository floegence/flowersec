package resourcev4

import (
	"errors"
	"sync"
	"testing"
)

func TestProtectedReservationPreservesAllScopesAndOriginalReferencePosition(t *testing.T) {
	minimum := Vector{SDKBytes: 1024, Items: 2, Tasks: 1, WorkSlots: 1}
	charge, err := ProtectedCharge(minimum)
	if err != nil {
		t.Fatal(err)
	}
	r := testRoot(t, charge, 1, 1)
	tenant := account(t, r, TenantAccount, 1, charge)
	session := account(t, r, SessionAccount, 2, charge)
	ref, err := r.Reserve(owner(1), charge, tenant, session)
	if err != nil {
		t.Fatal(err)
	}
	before := r.Snapshot()
	p, err := NewProtectedReservation(ref, minimum)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if ref.Check() == nil {
		t.Fatal("constructor left original authority live")
	}
	for range 100 {
		live, err := p.Checkout()
		if err != nil {
			t.Fatal(err)
		}
		if err := live.CheckAllocationScope(r, owner(1), []Account{tenant, session}); err != nil {
			t.Fatal(err)
		}
		if _, err := p.Checkout(); !errors.Is(err, ErrCapacity) {
			t.Fatal("two concurrent users", err)
		}
		moved, err := live.Take(minimum)
		if err != nil {
			t.Fatal(err)
		}
		live.Release()
		ref.Release()
		if err := moved.Check(); err != nil {
			t.Fatal("stale handle released current use", err)
		}
		moved.Release()
		if after := r.Snapshot(); after != before {
			t.Fatal("protected bytes became generally available", before, after)
		}
	}
	p.Close()
	if !p.CleanupComplete() {
		t.Fatal("idle protected reservation did not close")
	}
	if _, err := p.Checkout(); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
}

func TestProtectedReservationWaitsForTransferredAndBorrowedTails(t *testing.T) {
	minimum := Vector{SDKBytes: 1024, Items: 2}
	charge, _ := ProtectedCharge(minimum)
	r := testRoot(t, charge, 1, 4)
	ref, err := r.Reserve(owner(1), charge)
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewProtectedReservation(ref, minimum)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	first, err := p.Checkout()
	if err != nil {
		t.Fatal(err)
	}
	alias, err := first.Borrow()
	if err != nil {
		t.Fatal(err)
	}
	target := owner(2)
	target.Backing = owner(1).Backing
	transferred, err := first.Transfer(target, [16]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	first.Release()
	if _, err := p.Checkout(); !errors.Is(err, ErrCapacity) {
		t.Fatal("overlapped transferred owner", err)
	}
	transferred.Release()
	if _, err := p.Checkout(); !errors.Is(err, ErrCapacity) {
		t.Fatal("overlapped actual alias", err)
	}
	alias.Release()
	second, err := p.Checkout()
	if err != nil {
		t.Fatal(err)
	}
	first.Release()
	alias.Release()
	transferred.Release()
	if err := second.Check(); err != nil {
		t.Fatal(err)
	}
	late, err := second.Borrow()
	if err != nil {
		t.Fatal(err)
	}
	p.Close()
	second.Release()
	if p.CleanupComplete() {
		t.Fatal("closed ahead of late physical borrow")
	}
	late.Release()
	if !p.CleanupComplete() {
		t.Fatal("last physical release did not retire protected charge")
	}
}

func TestProtectedReservationConcurrentCheckoutAndClosure(t *testing.T) {
	minimum := Vector{SDKBytes: 64}
	charge, _ := ProtectedCharge(minimum)
	r := testRoot(t, charge, 1, 1)
	ref, err := r.Reserve(owner(1), charge)
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewProtectedReservation(ref, minimum)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan Reference, 16)
	for range 16 {
		wg.Go(func() {
			if ref, err := p.Checkout(); err == nil {
				results <- ref
			} else if !errors.Is(err, ErrCapacity) {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	close(results)
	if len(results) != 1 {
		t.Fatal("multiple physical checkouts", len(results))
	}
	p.Close()
	for ref := range results {
		ref.Release()
	}
	if !p.CleanupComplete() {
		t.Fatal("closure failed")
	}
}

func TestProtectedReservationCannotBypassClosedOriginalAccounts(t *testing.T) {
	minimum := Vector{SDKBytes: 64}
	charge, _ := ProtectedCharge(minimum)
	r := testRoot(t, charge, 1, 1)
	a := account(t, r, SessionAccount, 3, charge)
	ref, err := r.Reserve(owner(1), charge, a)
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewProtectedReservation(ref, minimum)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	ref, err = p.Checkout()
	if err != nil {
		t.Fatal(err)
	}
	ref.Seal()
	ref.Release()
	a.Close()
	if _, err := p.Checkout(); !errors.Is(err, ErrClosed) {
		t.Fatal("reopened original account fence", err)
	}
}

func TestProtectedReservationReusesPreadmittedBorrowAtReferenceCapacity(t *testing.T) {
	minimum := Vector{SDKBytes: 64}
	charge, _ := ProtectedCharge(minimum)
	r := testRoot(t, charge, 1, 2)
	a := account(t, r, SessionAccount, 3, charge)
	ref, err := r.Reserve(owner(1), charge, a)
	if err != nil {
		t.Fatal(err)
	}
	alias, err := ref.Borrow()
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewProtectedReservation(ref, minimum, alias)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	before := r.Snapshot()
	for range 100 {
		live, err := p.Checkout()
		if err != nil {
			t.Fatal(err)
		}
		borrow, err := live.Borrow()
		if err != nil {
			t.Fatal("lost preadmitted execution reference", err)
		}
		moved, err := borrow.TakeBorrow()
		if err != nil {
			t.Fatal(err)
		}
		alias.Release()
		borrow.Release()
		if err := moved.Check(); err != nil {
			t.Fatal("stale alias released real tail", err)
		}
		if _, err := live.Borrow(); !errors.Is(err, ErrCapacity) {
			t.Fatal("duplicated execution reference", err)
		}
		live.Release()
		if _, err := p.Checkout(); !errors.Is(err, ErrCapacity) {
			t.Fatal("overlapped actual execution tail", err)
		}
		moved.Release()
		if after := r.Snapshot(); after != before {
			t.Fatal("reused alias changed original accounting", before, after)
		}
	}
	live, _ := p.Checkout()
	borrow, _ := live.Borrow()
	p.Close()
	live.Release()
	if p.CleanupComplete() {
		t.Fatal("closed with live execution tail")
	}
	borrow.Release()
	if !p.CleanupComplete() || r.Snapshot().References != 0 {
		t.Fatal("retained closed protected alias", r.Snapshot())
	}
}

func TestProtectedReservationDoesNotLendAliasAcrossTransferredScopes(t *testing.T) {
	minimum := Vector{SDKBytes: 64}
	charge, _ := ProtectedCharge(minimum)
	r := testRoot(t, charge, 1, 4)
	a := account(t, r, SessionAccount, 3, charge)
	b := account(t, r, SessionAccount, 4, charge)
	ref, err := r.Reserve(owner(1), charge, a)
	if err != nil {
		t.Fatal(err)
	}
	alias, _ := ref.Borrow()
	p, err := NewProtectedReservation(ref, minimum, alias)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	live, _ := p.Checkout()
	target := owner(2)
	target.Backing = owner(1).Backing
	transferred, err := live.Transfer(target, [16]byte{1}, b)
	if err != nil {
		t.Fatal(err)
	}
	borrow, err := transferred.Borrow()
	if err != nil {
		t.Fatal(err)
	}
	if borrow.index == p.borrowIndex {
		t.Fatal("changed original protected scopes")
	}
	if _, err := transferred.Borrow(); !errors.Is(err, ErrCapacity) {
		t.Fatal(err)
	}
	live.Release()
	transferred.Release()
	p.Close()
	if p.CleanupComplete() {
		t.Fatal("dropped transferred scopes early")
	}
	borrow.Release()
	if !p.CleanupComplete() {
		t.Fatal("failed actual scope cleanup")
	}
}

func TestProtectedBatchIsAtomicAcrossActualTails(t *testing.T) {
	minimum := Vector{SDKBytes: 64}
	charge, _ := ProtectedCharge(minimum)
	total, _ := charge.Add(charge)
	r := testRoot(t, total, 2, 3)
	var protected [2]*ProtectedReservation
	for i := range protected {
		ref, err := r.Reserve(owner(byte(i+1)), charge)
		if err != nil {
			t.Fatal(err)
		}
		protected[i], err = NewProtectedReservation(ref, minimum)
		if err != nil {
			t.Fatal(err)
		}
		defer protected[i].Close()
	}
	busy, _ := protected[1].Checkout()
	alias, _ := busy.Borrow()
	busy.Release()
	var output [2]Reference
	before := r.Snapshot()
	if err := CheckoutProtectedBatch(protected[:], output[:]); !errors.Is(err, ErrCapacity) || output != ([2]Reference{}) || r.Snapshot() != before {
		t.Fatal("partial checkout escaped", err, output)
	}
	first, err := protected[0].Checkout()
	if err != nil {
		t.Fatal("failed batch consumed first component", err)
	}
	first.Release()
	alias.Release()
	if err := CheckoutProtectedBatch(protected[:], output[:]); err != nil {
		t.Fatal(err)
	}
	for _, ref := range output {
		ref.Release()
	}
}
