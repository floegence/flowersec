package resourcev4

import (
	"errors"
	"testing"
)

func TestProtectedScopeChargesSessionsAndRetainsPhysicalTail(t *testing.T) {
	limit := Vector{SDKBytes: 16384, Items: 32}
	r := testRoot(t, limit, 4, 12)
	tenant := account(t, r, TenantAccount, 1, limit)
	first := account(t, r, SessionAccount, 2, limit)
	second := account(t, r, SessionAccount, 3, limit)
	metadata := Vector{SDKBytes: 64, Items: 1}
	a, err := r.Reserve(owner(1), metadata, tenant, first)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Release()
	b, err := r.Reserve(owner(2), metadata, tenant, second)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Release()
	minimum := Vector{SDKBytes: 1024, Items: 1}
	charge, _ := ProtectedCharge(minimum)
	ref, err := r.Reserve(owner(3), charge, tenant)
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewProtectedReservation(ref, minimum)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	before := r.Snapshot().Charged
	sa, err := p.BorrowScope(a)
	if err != nil {
		t.Fatal(err)
	}
	defer sa.Release()
	sb, err := p.BorrowScope(b)
	if err != nil {
		t.Fatal(err)
	}
	defer sb.Release()
	if r.Snapshot().Charged != before {
		t.Fatal("shared backing charged twice at root")
	}
	want, _ := charge.Add(metadata)
	for _, s := range []Account{first, second} {
		if used, err := s.Usage(); err != nil || used != want {
			t.Fatal("missing Session floor", used, err)
		}
	}
	for range 3 {
		use, err := p.Checkout()
		if err != nil {
			t.Fatal(err)
		}
		use.Release()
	}
	live, err := p.Checkout()
	if err != nil {
		t.Fatal(err)
	}
	tail, err := live.Borrow()
	if err != nil {
		t.Fatal(err)
	}
	p.CloseAfterUse()
	live.Release()
	if p.UseComplete() || p.CleanupComplete() {
		t.Fatal("provider/output alias refunded early")
	}
	tail.Release()
	if !p.UseComplete() || p.CleanupComplete() {
		t.Fatal("scope anchors confused with physical tail")
	}
	sa.Release()
	sb.Release()
	if !p.CleanupComplete() {
		t.Fatal("scope anchors retained completed protection")
	}
	for _, s := range []Account{first, second} {
		if used, _ := s.Usage(); used != metadata {
			t.Fatal(used)
		}
	}
}

func TestProtectedScopeRejectsTenantSubstitutionAndCapacityAtomically(t *testing.T) {
	limit := Vector{SDKBytes: 8192, Items: 16}
	r := testRoot(t, limit, 4, 8)
	tenant := account(t, r, TenantAccount, 1, limit)
	other := account(t, r, TenantAccount, 2, limit)
	small := account(t, r, SessionAccount, 3, Vector{SDKBytes: 64, Items: 1})
	minimum := Vector{SDKBytes: 1024, Items: 1}
	charge, _ := ProtectedCharge(minimum)
	ref, err := r.Reserve(owner(1), charge, tenant)
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewProtectedReservation(ref, minimum)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	a, err := r.Reserve(owner(2), Vector{SDKBytes: 64, Items: 1}, tenant, small)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Release()
	b, err := r.Reserve(owner(3), Vector{SDKBytes: 64, Items: 1}, other)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Release()
	before := r.Snapshot()
	if _, err = p.BorrowScope(a); !errors.Is(err, ErrCapacity) || r.Snapshot() != before {
		t.Fatal("failed vector mutated accounting", err)
	}
	if _, err = p.BorrowScope(b); !errors.Is(err, ErrOwner) || r.Snapshot() != before {
		t.Fatal("tenant substitution", err)
	}
}

func TestProtectedScopeManySessionsShareOnePhysicalAllocation(t *testing.T) {
	limit := Vector{SDKBytes: 1 << 22, Items: 2048}
	config := Config{ProfileRevision: [32]byte{1}, Limit: limit, AccountSlots: 260, ReservationSlots: 260, ReferenceSlots: 1024}
	r, err := NewRoot(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		r.Close()
		if !r.Snapshot().CleanupComplete {
			t.Fatal("retained scope anchors", r.Snapshot())
		}
	})
	minimum := Vector{SDKBytes: 1024, Items: 1}
	charge, _ := ProtectedCharge(minimum)
	ref, err := r.Reserve(owner(1), charge)
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewProtectedReservation(ref, minimum)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	var scopes [256]Reference
	var accounts [256]Account
	for j := range scopes {
		key := AccountKey{Kind: SessionAccount, ID: [16]byte{byte(j), byte(j >> 8), 1}}
		accounts[j], err = r.Account(key, limit)
		if err != nil {
			t.Fatal(err)
		}
		keyOwner := owner(2)
		keyOwner.Instance = [16]byte{byte(j), byte(j >> 8), 2}
		keyOwner.Backing = keyOwner.Instance
		metadata, err := r.Reserve(keyOwner, Vector{Items: 1}, accounts[j])
		if err != nil {
			t.Fatal(err)
		}
		scopes[j], err = p.BorrowScope(metadata)
		metadata.Release()
		if err != nil {
			t.Fatal(j, err)
		}
		defer scopes[j].Release()
		if used, _ := accounts[j].Usage(); used != charge {
			t.Fatal(j, used)
		}
	}
	for range 3 {
		live, err := p.Checkout()
		if err != nil {
			t.Fatal(err)
		}
		live.Release()
	}
	p.CloseAfterUse()
	if p.CleanupComplete() {
		t.Fatal("forgot actual scope references")
	}
	for j := len(scopes) - 1; j >= 0; j-- {
		scopes[j].Release()
		if used, _ := accounts[j].Usage(); used != (Vector{}) {
			t.Fatal(j, used)
		}
	}
	if !p.CleanupComplete() {
		t.Fatal("completed anchors did not release backing")
	}
}
