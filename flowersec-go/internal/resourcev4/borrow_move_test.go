package resourcev4

import (
	"errors"
	"math"
	"sync"
	"testing"
)

func TestTakeBorrowMovesSaturatedSlotAndPreservesAccountFences(t *testing.T) {
	limit := Vector{SDKBytes: 128, Items: 1}
	r := testRoot(t, limit, 1, 2)
	environment := account(t, r, EnvironmentAccount, 1, limit)
	primary, err := r.Reserve(owner(1), limit, environment)
	if err != nil {
		t.Fatal(err)
	}
	defer primary.Release()
	borrow, err := primary.Borrow()
	if err != nil {
		t.Fatal(err)
	}
	defer borrow.Release()
	if _, err := primary.Borrow(); !errors.Is(err, ErrCapacity) {
		t.Fatal("reference slab was not full", err)
	}
	before := r.Snapshot()
	moved, err := borrow.TakeBorrow()
	if err != nil {
		t.Fatal(err)
	}
	defer moved.Release()
	if r.Snapshot() != before || moved == borrow || moved.Check() != nil {
		t.Fatal("move changed original backing or acquired capacity")
	}
	borrow.Release()
	if _, err := borrow.TakeBorrow(); !errors.Is(err, ErrOwner) || r.Snapshot() != before {
		t.Fatal("stale alias retained ownership", err)
	}
	if _, err := moved.Borrow(); !errors.Is(err, ErrOwner) {
		t.Fatal("moved borrow minted another alias", err)
	}
	if _, err := moved.Take(Vector{}); !errors.Is(err, ErrOwner) {
		t.Fatal("moved borrow became a primary owner", err)
	}
	key := owner(2)
	key.Backing = owner(1).Backing
	if _, err := moved.Transfer(key, [16]byte{1}); !errors.Is(err, ErrOwner) {
		t.Fatal("moved borrow forged a distinct owner", err)
	}
	environment.Close()
	if !errors.Is(moved.Check(), ErrClosed) {
		t.Fatal("move detached the original Environment fence")
	}
	if _, err := moved.TakeBorrow(); !errors.Is(err, ErrClosed) || r.Snapshot() != before {
		t.Fatal("closed borrow moved or refunded", err)
	}
}

func TestTakeBorrowHasOneWinnerAmongCopiedAliases(t *testing.T) {
	r := testRoot(t, Vector{SDKBytes: 32}, 1, 2)
	primary, err := r.Reserve(owner(1), Vector{SDKBytes: 32})
	if err != nil {
		t.Fatal(err)
	}
	defer primary.Release()
	borrow, err := primary.Borrow()
	if err != nil {
		t.Fatal(err)
	}
	defer borrow.Release()
	before := r.Snapshot()
	results := make(chan Reference, 16)
	var workers sync.WaitGroup
	for range 16 {
		workers.Go(func() {
			moved, err := borrow.TakeBorrow()
			if err == nil {
				results <- moved
			} else if !errors.Is(err, ErrOwner) {
				t.Error(err)
			}
		})
	}
	workers.Wait()
	close(results)
	if len(results) != 1 {
		for ref := range results {
			ref.Release()
		}
		t.Fatal("copied aliases transferred multiple references")
	}
	moved := <-results
	defer moved.Release()
	if r.Snapshot() != before {
		t.Fatal("concurrent move changed charges")
	}
	primary.Release()
	if r.Snapshot().Charged != before.Charged {
		t.Fatal("original primary released a live moved borrower")
	}
	moved.Release()
	if r.Snapshot().Reservations != 0 {
		t.Fatal("moved borrow did not release its original backing")
	}
}

func TestTakeBorrowRejectsPrimaryAndNamedTransferPredecessor(t *testing.T) {
	r := testRoot(t, Vector{SDKBytes: 32}, 1, 2)
	primary, err := r.Reserve(owner(1), Vector{SDKBytes: 32})
	if err != nil {
		t.Fatal(err)
	}
	defer primary.Release()
	before := r.Snapshot()
	for _, ref := range []Reference{{}, primary} {
		if _, err := ref.TakeBorrow(); !errors.Is(err, ErrOwner) || r.Snapshot() != before {
			t.Fatal("non-borrow was moved", err)
		}
	}
	key := owner(2)
	key.Backing = owner(1).Backing
	transferred, err := primary.Transfer(key, [16]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	defer transferred.Release()
	before = r.Snapshot()
	if _, err := primary.TakeBorrow(); !errors.Is(err, ErrOwner) || r.Snapshot() != before {
		t.Fatal("named predecessor lost replay identity", err)
	}
	if replay, err := primary.Transfer(key, [16]byte{1}); err != nil || replay != transferred {
		t.Fatal("failed borrow move altered original transfer", err)
	}
}

func TestTakeBorrowExhaustionAndClosureDoNotChangeOwnership(t *testing.T) {
	for _, closed := range []bool{false, true} {
		r := testRoot(t, Vector{SDKBytes: 32}, 1, 2)
		primary, err := r.Reserve(owner(1), Vector{SDKBytes: 32})
		if err != nil {
			t.Fatal(err)
		}
		defer primary.Release()
		borrow, err := primary.Borrow()
		if err != nil {
			t.Fatal(err)
		}
		want := ErrCapacity
		if closed {
			r.Close()
			want = ErrClosed
		} else {
			r.mu.Lock()
			r.refs[borrow.index].generation = math.MaxUint64
			borrow.generation = math.MaxUint64
			r.mu.Unlock()
		}
		defer borrow.Release()
		before := r.Snapshot()
		if _, err := borrow.TakeBorrow(); !errors.Is(err, want) || r.Snapshot() != before {
			t.Fatal("failed move changed original quota", err)
		}
		if !closed && borrow.Check() != nil {
			t.Fatal("exhausted generation invalidated original live reference")
		}
	}
}

func TestBorrowInScopesOfRetainsBackingAcrossOriginalScopes(t *testing.T) {
	limit := Vector{SDKBytes: 1 << 20, Items: 32, WorkSlots: 32}
	r := testRoot(t, limit, 8, 32)
	tenant := account(t, r, TenantAccount, 1, limit)
	environment := account(t, r, EnvironmentAccount, 1, limit)
	session := account(t, r, SessionAccount, 1, limit)
	direction := account(t, r, DirectionAccount, 1, limit)
	ownerA := owner(1)
	ownerA.Environment = [16]byte{1}
	ownerB := owner(2)
	ownerB.Environment = [16]byte{1}
	charge := Vector{SDKBytes: 128, Items: 1, WorkSlots: 1}
	native, err := r.Reserve(ownerA, charge, tenant, environment)
	if err != nil {
		t.Fatal(err)
	}
	paired, err := r.Reserve(ownerB, charge, tenant, environment, session, direction)
	if err != nil {
		t.Fatal(err)
	}
	before := r.Snapshot()
	scoped, err := native.BorrowInScopesOf(paired)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := charge.Add(charge)
	if got, _ := session.Usage(); got != want {
		t.Fatalf("missing new scope charge: %#v", got)
	}
	if got := r.Snapshot(); got.Charged != before.Charged {
		t.Fatalf("duplicated physical charge: %#v vs %#v", got, before)
	}
	native.Release()
	if err := scoped.CheckRetained(); err != nil {
		t.Fatal(err)
	}
	scoped.Release()
	paired.Release()
	environment.Close()
	tenant.Close()
	session.Close()
	direction.Close()
}

func TestBorrowInScopesOfRefusalPreservesAllCharges(t *testing.T) {
	limit := Vector{SDKBytes: 4096, Items: 16}
	r := testRoot(t, limit, 8, 32)
	environment := account(t, r, EnvironmentAccount, 1, limit)
	session := account(t, r, SessionAccount, 1, Vector{SDKBytes: 64, Items: 4})
	native, err := r.Reserve(owner(1), Vector{SDKBytes: 128, Items: 1}, environment)
	if err != nil {
		t.Fatal(err)
	}
	defer native.Release()
	paired, err := r.Reserve(owner(2), Vector{SDKBytes: 32, Items: 1}, environment, session)
	if err != nil {
		t.Fatal(err)
	}
	defer paired.Release()
	before, sessionBefore := r.Snapshot(), Vector{}
	sessionBefore, _ = session.Usage()
	if scoped, err := native.BorrowInScopesOf(paired); scoped != (Reference{}) || !errors.Is(err, ErrCapacity) {
		t.Fatal("exhausted original account accepted", scoped, err)
	}
	if after := r.Snapshot(); after != before {
		t.Fatal("failed scope attachment changed root", before, after)
	}
	if after, _ := session.Usage(); after != sessionBefore {
		t.Fatal("failed scope attachment changed account", sessionBefore, after)
	}
	alias, err := native.Borrow()
	if err != nil {
		t.Fatal(err)
	}
	defer alias.Release()
	before = r.Snapshot()
	if scoped, err := alias.BorrowInScopesOf(native); scoped != (Reference{}) || !errors.Is(err, ErrOwner) {
		t.Fatal("borrowed alias manufactured another owner", scoped, err)
	}
	if after := r.Snapshot(); after != before {
		t.Fatal("refused alias changed root", before, after)
	}
	session.Close()
	before = r.Snapshot()
	if scoped, err := native.BorrowInScopesOf(paired); scoped != (Reference{}) || !errors.Is(err, ErrClosed) {
		t.Fatal("closed paired account accepted", scoped, err)
	}
	if after := r.Snapshot(); after != before {
		t.Fatal("closed scope attachment changed root", before, after)
	}
}

func TestBorrowInScopesOfRejectsDifferentTrustedAncestry(t *testing.T) {
	limit := Vector{SDKBytes: 4096, Items: 16}
	r := testRoot(t, limit, 8, 32)
	environment := account(t, r, EnvironmentAccount, 1, limit)
	tenant := account(t, r, TenantAccount, 1, limit)
	otherTenant := account(t, r, TenantAccount, 2, limit)
	native, err := r.Reserve(owner(1), Vector{SDKBytes: 128, Items: 1}, tenant, environment)
	if err != nil {
		t.Fatal(err)
	}
	defer native.Release()
	paired, err := r.Reserve(owner(2), Vector{SDKBytes: 32, Items: 1}, otherTenant, environment)
	if err != nil {
		t.Fatal(err)
	}
	defer paired.Release()
	before := r.Snapshot()
	if scoped, err := native.BorrowInScopesOf(paired); scoped != (Reference{}) || !errors.Is(err, ErrOwner) {
		t.Fatal("different trusted tenant accepted", scoped, err)
	}
	if after := r.Snapshot(); after != before {
		t.Fatal("refused ancestry changed root", before, after)
	}
}
