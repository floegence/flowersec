package resourcev4

import (
	"context"
	"errors"
	"math"
	"testing"
)

func fullGenerationScopes(t *testing.T, r *Root, limit Vector) [MaxAccountsPerCharge]Account {
	t.Helper()
	var scopes [MaxAccountsPerCharge]Account
	kinds := [MaxAccountsPerCharge]AccountKind{TenantAccount, EnvironmentAccount, SessionAccount, DirectionAccount, PoolAccount, PoolAccount, PoolAccount, PoolAccount}
	for i, kind := range kinds {
		// Exercise generations whose low 32 bits match a different stale handle.
		r.accounts[i].generation = 1<<32 + 5
		if i == 6 {
			r.accounts[i].generation = math.MaxUint64 - 1
		}
		id := byte(i + 1)
		if kind == EnvironmentAccount {
			id = 1
		}
		scopes[i] = account(t, r, kind, id, limit)
	}
	return scopes
}

func TestAccountSlotKeysPreserveFullScopesThroughResultOwnership(t *testing.T) {
	limit := Vector{SDKBytes: 16384, Items: 64, Sessions: 64}
	r := testRoot(t, limit, 4, 12)
	scopes := fullGenerationScopes(t, r, limit)
	value := Vector{SDKBytes: 64, Items: 1, Sessions: 1}
	ref, err := r.ReserveResult(owner(1), value, scopes[:]...)
	if err != nil {
		t.Fatal(err)
	}
	defer ref.Release()
	var projected [MaxAccountsPerCharge]Account
	if key, count, err := ref.CopyAllocationScope(r, projected[:]); err != nil || key != owner(1) || count != len(scopes) || projected != scopes {
		t.Fatal("allocation projection lost an original scope or generation", key, count, err)
	}
	borrow, err := ref.Borrow()
	if err != nil {
		t.Fatal(err)
	}
	defer borrow.Release()
	other, err := r.Reserve(owner(2), value, scopes[:]...)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Release()
	union, err := ref.BorrowInScopesOf(other)
	if err != nil {
		t.Fatal("eight-scope union rejected", err)
	}
	defer union.Release()
	if err := union.CheckSessionScope(scopes[0], scopes[2]); err != nil {
		t.Fatal(err)
	}
	union.Release()
	other.Release()
	nextOwner := owner(1)
	nextOwner.Kind, nextOwner.Instance = 2, [16]byte{3}
	next, err := ref.Transfer(nextOwner, [16]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	defer next.Release()
	reversed := scopes
	for i := range reversed {
		reversed[i] = scopes[len(scopes)-1-i]
	}
	if replay, err := ref.Transfer(nextOwner, [16]byte{1}, reversed[:]...); err != nil || replay != next {
		t.Fatal("full-scope transfer replay changed ownership", err)
	}
	ref.Release()
	if count, err := next.CopyResultAccounts(projected[:]); err != nil || count != len(scopes) || projected != scopes {
		t.Fatal("result projection lost an original scope or generation", count, err)
	}
	if err := next.DetachSessionScope(); err != nil {
		t.Fatal(err)
	}
	if count, err := next.CopyResultAccounts(projected[:]); err != nil || count != len(scopes)-2 {
		t.Fatal("result did not detach only Session and direction", count, err)
	}
	if used, err := scopes[2].Usage(); err != nil || used != value || !borrow.RetainsCleanupScope(scopes[2], Reference{}) {
		t.Fatal("detached result refunded a live original alias", used, err)
	}
	if err := next.RestoreOriginalScopes(borrow); err != nil {
		t.Fatal(err)
	}
	if count, err := next.CopyResultAccounts(projected[:]); err != nil || count != len(scopes) || projected != scopes {
		t.Fatal("restoration lost an original scope or generation", count, err)
	}
	scopes[7].Close()
	if !errors.Is(next.Check(), ErrClosed) {
		t.Fatal("eighth account did not seal the result")
	}
	next.Release()
	borrow.Release()
	replacement := account(t, r, PoolAccount, 8, limit)
	if replacement.generation != scopes[7].generation+1 {
		t.Fatal("account reuse did not retain its full generation")
	}
	scopes[7].Close()
	last, err := r.Reserve(owner(4), value, replacement)
	if err != nil {
		t.Fatal("stale close sealed the reused account", err)
	}
	defer last.Release()
	last.Release()
	scopes[6].Close()
	if _, err := r.Account(AccountKey{Kind: PoolAccount, ID: [16]byte{7}}, limit); !errors.Is(err, ErrCapacity) {
		t.Fatal("exhausted account generation wrapped or was reused", err)
	}
}

func TestAccountSlotKeysRejectForeignRootAndTruncatedGeneration(t *testing.T) {
	limit := Vector{SDKBytes: 65536, Items: 64, Sessions: 64, WorkSlots: 64}
	r, foreignRoot := testRoot(t, limit, 4, 12), testRoot(t, limit, 1, 2)
	scopes, foreign := fullGenerationScopes(t, r, limit), fullGenerationScopes(t, foreignRoot, limit)
	value := Vector{SDKBytes: 64, Items: 1, Sessions: 1}
	ref, err := r.Reserve(owner(1), value, scopes[:]...)
	if err != nil {
		t.Fatal(err)
	}
	defer ref.Release()
	waitCharge, err := ReservationWaiterCharge(1)
	if err != nil {
		t.Fatal(err)
	}
	waitRef, err := r.Reserve(owner(2), waitCharge, scopes[:]...)
	if err != nil {
		t.Fatal(err)
	}
	defer waitRef.Release()
	waiter, err := NewReservationWaiter(r, waitRef, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer waiter.Close()
	protectedCharge, err := ProtectedCharge(value)
	if err != nil {
		t.Fatal(err)
	}
	protectedRef, err := r.Reserve(owner(3), protectedCharge, scopes[:]...)
	if err != nil {
		t.Fatal(err)
	}
	defer protectedRef.Release()
	protected, err := NewProtectedReservation(protectedRef, value)
	if err != nil {
		t.Fatal(err)
	}
	defer protected.Close()
	nextOwner := owner(1)
	nextOwner.Kind, nextOwner.Instance = 2, [16]byte{5}
	before, foreignBefore := r.Snapshot(), foreignRoot.Snapshot()
	for i := range scopes {
		if scopes[i].index != foreign[i].index || scopes[i].generation != foreign[i].generation {
			t.Fatal("foreign fixture does not collide with the local slot")
		}
		stale := scopes[i]
		stale.generation = uint64(uint32(stale.generation))
		for _, invalid := range [...]Account{foreign[i], stale} {
			changed := scopes
			changed[i] = invalid
			if got, err := r.Reserve(owner(4), value, changed[:]...); !errors.Is(err, ErrOwner) {
				got.Release()
				t.Fatal("reservation accepted another root or generation", i, err)
			}
			if got, err := ref.Transfer(nextOwner, [16]byte{1}, changed[:]...); !errors.Is(err, ErrOwner) {
				got.Release()
				t.Fatal("transfer accepted another root or generation", i, err)
			}
			if err := ref.CheckRequest(Request{Owner: owner(1), Charge: value, Accounts: changed[:]}); !errors.Is(err, ErrOwner) {
				t.Fatal("request accepted another root or generation", i, err)
			}
			if err := protected.CheckAdmissionRequest(Request{Owner: owner(3), Charge: protectedCharge, Accounts: changed[:]}); !errors.Is(err, ErrOwner) {
				t.Fatal("protected admission accepted another root or generation", i, err)
			}
			if err := ref.CheckAllocationScope(r, owner(1), changed[:]); !errors.Is(err, ErrOwner) {
				t.Fatal("allocation scope accepted another root or generation", i, err)
			}
			var output [1]Reference
			request := [1]Request{{Owner: owner(4), Charge: value, Accounts: changed[:]}}
			if err := waiter.Reserve(context.Background(), request[:], output[:]); !errors.Is(err, ErrOwner) {
				output[0].Release()
				t.Fatal("waiter accepted another root or generation", i, err)
			}
			if r.Snapshot() != before || foreignRoot.Snapshot() != foreignBefore {
				t.Fatal("rejected account mutated a root", i)
			}
		}
	}
	if err := ref.CheckSessionScope(foreign[0], scopes[2]); !errors.Is(err, ErrOwner) {
		t.Fatal("Session scope accepted a foreign tenant", err)
	}
	if ref.RetainsCleanupScope(foreign[2], Reference{}) {
		t.Fatal("cleanup scope accepted a foreign Session")
	}
	scopeBorrow, err := protected.BorrowScope(ref)
	if err != nil {
		t.Fatal("protection rejected eight original scopes", err)
	}
	defer scopeBorrow.Release()
	live, err := protected.Checkout()
	if err != nil {
		t.Fatal(err)
	}
	defer live.Release()
	var projected [MaxAccountsPerCharge]Account
	if _, count, err := live.CopyAllocationScope(r, projected[:]); err != nil || count != len(scopes) || projected != scopes {
		t.Fatal("protected checkout lost an original scope or generation", count, err)
	}
	tail, err := live.Borrow()
	if err != nil {
		t.Fatal(err)
	}
	defer tail.Release()
	protected.CloseAfterUse()
	live.Release()
	if protected.UseComplete() || protected.CleanupComplete() || r.Snapshot().Charged != before.Charged {
		t.Fatal("protected close refunded an eight-scope physical tail")
	}
	tail.Release()
	if !protected.UseComplete() || protected.CleanupComplete() {
		t.Fatal("protected scope anchor did not retain original backing")
	}
	scopeBorrow.Release()
	if !protected.CleanupComplete() {
		t.Fatal("protected backing survived its final original reference")
	}
}

func TestAccountSlotKeysKeepEightScopeHotPathAllocationFree(t *testing.T) {
	limit := Vector{SDKBytes: 4096, Items: 16, Sessions: 16}
	r := testRoot(t, limit, 2, 8)
	scopes := fullGenerationScopes(t, r, limit)
	value := Vector{SDKBytes: 64, Items: 1, Sessions: 1}
	nextOwner := owner(1)
	nextOwner.Kind, nextOwner.Instance = 2, [16]byte{2}
	var projected [MaxAccountsPerCharge]Account
	allocations := testing.AllocsPerRun(100, func() {
		ref, err := r.ReserveResult(owner(1), value, scopes[:]...)
		if err != nil {
			t.Fatal(err)
		}
		defer ref.Release()
		if err := ref.CheckRequest(Request{Owner: owner(1), Charge: value, Accounts: scopes[:], ResultOwner: true}); err != nil {
			t.Fatal(err)
		}
		if _, count, err := ref.CopyAllocationScope(r, projected[:]); err != nil || count != len(scopes) || projected != scopes {
			t.Fatal(count, err)
		}
		borrow, err := ref.Borrow()
		if err != nil {
			t.Fatal(err)
		}
		defer borrow.Release()
		next, err := ref.Transfer(nextOwner, [16]byte{1}, scopes[:]...)
		if err != nil {
			t.Fatal(err)
		}
		defer next.Release()
		if err := next.DetachSessionScope(); err != nil {
			t.Fatal(err)
		}
		if err := next.RestoreOriginalScopes(borrow); err != nil {
			t.Fatal(err)
		}
		if count, err := next.CopyResultAccounts(projected[:]); err != nil || count != len(scopes) || projected != scopes {
			t.Fatal(count, err)
		}
	})
	if allocations != 0 {
		t.Fatal("eight-scope ownership path allocated outside admitted slabs", allocations)
	}
}
