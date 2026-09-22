package resourcev4

import (
	"errors"
	"math"
	"sync"
	"testing"
)

func testRoot(t *testing.T, limit Vector, charges, refs uint32) *Root {
	t.Helper()
	config := Config{ProfileRevision: [32]byte{1}, AccountSlots: 8, ReservationSlots: charges, ReferenceSlots: refs}
	backing, err := BackingBytes(config)
	if err != nil {
		t.Fatal(err)
	}
	config.Limit = limit
	config.Limit[SDKBytes] += backing
	r, err := NewRoot(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		r.Close()
		if got := r.Snapshot(); !got.CleanupComplete || got.References != 0 || got.Charged != (Vector{SDKBytes: backing}) {
			t.Error("test left actual resource charges", got)
		}
	})
	return r
}

func owner(id byte) OwnerKey {
	return OwnerKey{ProfileRevision: [32]byte{1}, Environment: [16]byte{1}, Kind: 1, Instance: [16]byte{id}, Backing: [16]byte{id}, Direction: 1}
}

func account(t *testing.T, r *Root, kind AccountKind, id byte, limit Vector) Account {
	t.Helper()
	a, err := r.Account(AccountKey{Kind: kind, ID: [16]byte{id}}, limit)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestSharedTenantAcrossEnvironmentsAndAtomicAllDimensions(t *testing.T) {
	limit := Vector{SDKBytes: 1024, Sessions: 4, WorkSlots: 4}
	r := testRoot(t, limit, 8, 16)
	tenant := account(t, r, TenantAccount, 7, Vector{SDKBytes: 256, Sessions: 1, WorkSlots: 2})
	if again := account(t, r, TenantAccount, 7, Vector{SDKBytes: 256, Sessions: 1, WorkSlots: 2}); again != tenant {
		t.Fatal("another Environment created a second tenant allowance")
	}
	if _, err := r.Account(AccountKey{TenantAccount, [16]byte{7}}, limit); !errors.Is(err, ErrConfiguration) {
		t.Fatal("same tenant changed its budget", err)
	}
	environments := [2]Account{account(t, r, EnvironmentAccount, 1, limit), account(t, r, EnvironmentAccount, 2, limit)}
	var wg sync.WaitGroup
	results := make(chan Reference, 2)
	for i, environment := range environments {
		wg.Add(1)
		go func() {
			defer wg.Done()
			key := owner(byte(i + 1))
			key.Environment = [16]byte{byte(i + 1)}
			ref, err := r.Reserve(key, Vector{SDKBytes: 128, Sessions: 1, WorkSlots: 1}, tenant, environment, tenant)
			if err != nil && !errors.Is(err, ErrCapacity) {
				t.Error(err)
			}
			if err == nil {
				results <- ref
			}
		}()
	}
	wg.Wait()
	close(results)
	if len(results) != 1 {
		t.Fatal("tenant session slot oversubscribed", len(results))
	}
	winner := <-results
	defer winner.Release()
	want := Vector{SDKBytes: 128, Sessions: 1, WorkSlots: 1}
	if got, _ := tenant.Usage(); got != want {
		t.Fatal("partial or duplicate ancestor charge", got)
	}
	before := r.Snapshot()
	if _, err := r.Reserve(owner(3), Vector{SDKBytes: 129}, tenant); !errors.Is(err, ErrCapacity) || r.Snapshot() != before {
		t.Fatal("failed byte admission mutated root", err)
	}
	if _, err := r.Reserve(owner(3), Vector{WorkSlots: 2}, tenant); !errors.Is(err, ErrCapacity) || r.Snapshot() != before {
		t.Fatal("failed work admission mutated root", err)
	}
	if _, err := r.Reserve(owner(3), Vector{ProviderBytes: 1}, tenant); !errors.Is(err, ErrCapacity) || r.Snapshot() != before {
		t.Fatal("unconfigured external provider allowance", err)
	}
}

func TestForeignRootsAndSharedAccountClosure(t *testing.T) {
	limit := Vector{SDKBytes: 256, Items: 4}
	r, other := testRoot(t, limit, 4, 8), testRoot(t, limit, 2, 4)
	a := account(t, r, EnvironmentAccount, 1, limit)
	b := account(t, r, EnvironmentAccount, 2, limit)
	foreign := account(t, other, TenantAccount, 1, limit)
	before, otherBefore := r.Snapshot(), other.Snapshot()
	if _, err := r.Reserve(owner(1), Vector{SDKBytes: 8}, a, foreign); !errors.Is(err, ErrOwner) || r.Snapshot() != before || other.Snapshot() != otherBefore {
		t.Fatal("cross-root partial reservation", err)
	}
	x, err := r.Reserve(owner(1), Vector{SDKBytes: 8}, a)
	if err != nil {
		t.Fatal(err)
	}
	defer x.Release()
	key := owner(2)
	key.Environment = [16]byte{2}
	y, err := r.Reserve(key, Vector{SDKBytes: 8}, b)
	if err != nil {
		t.Fatal(err)
	}
	defer y.Release()
	before = r.Snapshot()
	a.Close()
	if !errors.Is(x.Check(), ErrClosed) || y.Check() != nil || r.Snapshot() != before {
		t.Fatal("Environment closure changed sibling or actual charges")
	}
	if _, err := r.Account(AccountKey{EnvironmentAccount, [16]byte{1}}, limit); !errors.Is(err, ErrClosed) {
		t.Fatal("closing Environment reused while resources remain", err)
	}
	x.Release()
	replacement := account(t, r, EnvironmentAccount, 1, limit)
	a.Close()
	z, err := r.Reserve(owner(3), Vector{SDKBytes: 8}, replacement)
	if err != nil {
		t.Fatal("stale close affected new account generation", err)
	}
	z.Release()
}

func TestTransferHoldsOneBackingUntilEveryOriginalReferenceExits(t *testing.T) {
	r := testRoot(t, Vector{SDKBytes: 128, Items: 1}, 2, 8)
	ref, err := r.Reserve(owner(1), Vector{SDKBytes: 128, Items: 1})
	if err != nil {
		t.Fatal(err)
	}
	borrow, err := ref.Borrow()
	if err != nil {
		t.Fatal(err)
	}
	before := r.Snapshot().Charged
	key := owner(1)
	key.Kind, key.Instance = 2, [16]byte{2}
	transferred, err := ref.Transfer(key, [16]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	if got := r.Snapshot(); got.Charged != before || got.Reservations != 1 || got.References != 3 {
		t.Fatal("transfer allocated second backing", got)
	}
	if replay, err := ref.Transfer(key, [16]byte{1}); err != nil || replay != transferred {
		t.Fatal("original transfer not idempotent", err)
	}
	if _, err := ref.Transfer(key, [16]byte{2}); !errors.Is(err, ErrOwner) {
		t.Fatal("different event reused old owner", err)
	}
	if _, err := ref.Borrow(); !errors.Is(err, ErrOwner) {
		t.Fatal("old owner created new work", err)
	}
	ref.Release()
	if transferred.Check() != nil {
		t.Fatal("old owner release sealed current owner")
	}
	transferred.Seal()
	transferred.Release()
	if got := r.Snapshot(); got.Charged != before || got.References != 1 {
		t.Fatal("current close refunded old task", got)
	}
	if _, err := r.Reserve(owner(3), Vector{Items: 1}); !errors.Is(err, ErrCapacity) {
		t.Fatal("cleanup-incomplete quota reused", err)
	}
	borrow.Release()
	if got := r.Snapshot(); got.Reservations != 0 || got.References != 0 {
		t.Fatal("last real reference did not return charge", got)
	}
}

func TestUnregisteredAliasesAndTransferBinding(t *testing.T) {
	r := testRoot(t, Vector{SDKBytes: 64}, 4, 8)
	ref, err := r.Reserve(owner(1), Vector{SDKBytes: 16})
	if err != nil {
		t.Fatal(err)
	}
	defer ref.Release()
	before := r.Snapshot()
	if _, err := r.Reserve(owner(1), Vector{SDKBytes: 16}); !errors.Is(err, ErrOwner) || r.Snapshot() != before {
		t.Fatal("duplicate registry owner created", err)
	}
	alias := owner(1)
	alias.Instance = [16]byte{2}
	independent, err := r.Reserve(alias, Vector{SDKBytes: 16})
	if err != nil {
		t.Fatal(err)
	}
	if r.Snapshot().Charged[SDKBytes] != before.Charged[SDKBytes]+16 {
		t.Fatal("unregistered alias received free backing")
	}
	independent.Release()
	for _, change := range []func(*OwnerKey){
		func(k *OwnerKey) { k.Backing = [16]byte{2} },
		func(k *OwnerKey) { k.ProfileRevision = [32]byte{2} },
		func(k *OwnerKey) { k.Environment = [16]byte{2} },
		func(k *OwnerKey) { k.Direction = 2 },
	} {
		key := alias
		change(&key)
		if _, err := ref.Transfer(key, [16]byte{1}); !errors.Is(err, ErrOwner) || r.Snapshot() != before {
			t.Fatal("mismatched backing/profile/direction transferred", err)
		}
	}
}

func TestTakeAndStaleHandlesCannotReleaseReusedSlots(t *testing.T) {
	r := testRoot(t, Vector{SDKBytes: 64}, 1, 2)
	ref, err := r.Reserve(owner(1), Vector{SDKBytes: 64})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ref.Take(Vector{SDKBytes: 65}); !errors.Is(err, ErrCapacity) || ref.Check() != nil {
		t.Fatal("failed attachment consumed original reservation", err)
	}
	attached, err := ref.Take(Vector{SDKBytes: 64})
	if err != nil {
		t.Fatal(err)
	}
	ref.Release()
	if _, err := ref.Take(Vector{}); !errors.Is(err, ErrOwner) || attached.Check() != nil {
		t.Fatal("stale constructor handle remained usable", err)
	}
	borrow, err := attached.Borrow()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := attached.Borrow(); !errors.Is(err, ErrCapacity) {
		t.Fatal("unbounded reference metadata", err)
	}
	attached.Release()
	borrow.Release()
	replacement, err := r.Reserve(owner(2), Vector{SDKBytes: 64})
	if err != nil {
		t.Fatal(err)
	}
	defer replacement.Release()
	ref.Release()
	attached.Release()
	borrow.Release()
	if replacement.Check() != nil || r.Snapshot().Reservations != 1 {
		t.Fatal("stale release returned replacement capacity")
	}
}

func TestPreauthToSessionTransferPreservesRealOverlapAndRootCharge(t *testing.T) {
	limit := Vector{SDKBytes: 128}
	r := testRoot(t, limit, 4, 8)
	tenant := account(t, r, TenantAccount, 1, limit)
	environment := account(t, r, EnvironmentAccount, 1, limit)
	preauth := account(t, r, PoolAccount, 1, limit)
	session := account(t, r, SessionAccount, 1, limit)
	ref, err := r.Reserve(owner(1), limit, tenant, environment, preauth)
	if err != nil {
		t.Fatal(err)
	}
	oldTask, err := ref.Borrow()
	if err != nil {
		t.Fatal(err)
	}
	key := owner(1)
	key.Kind, key.Instance = 2, [16]byte{2}
	before := r.Snapshot().Charged
	if _, err := ref.Transfer(key, [16]byte{1}, environment, session); !errors.Is(err, ErrOwner) {
		t.Fatal("owner transfer escaped original tenant", err)
	}
	next, err := ref.Transfer(key, [16]byte{1}, tenant, environment, session)
	if err != nil {
		t.Fatal("same backing required duplicate root budget", err)
	}
	for _, a := range []Account{tenant, environment, preauth, session} {
		if used, _ := a.Usage(); used != limit {
			t.Fatal("missing or duplicated overlap scope", used)
		}
	}
	if r.Snapshot().Charged != before {
		t.Fatal("same root backing counted twice")
	}
	if _, err := ref.Transfer(key, [16]byte{1}, tenant, environment, preauth); !errors.Is(err, ErrOwner) {
		t.Fatal("same transfer ID changed its recorded target scopes", err)
	}
	ref.Release()
	preauth.Close()
	if next.Check() != nil {
		t.Fatal("closed old pool revoked new Session owner")
	}
	if got, _ := preauth.Usage(); got != limit {
		t.Fatal("old task's real preauth charge refunded", got)
	}
	oldTask.Release()
	if _, err := preauth.Usage(); !errors.Is(err, ErrOwner) {
		t.Fatal("old account not retired after its final real ref", err)
	}
	if r.Snapshot().Charged != before {
		t.Fatal("old scope release refunded current Session backing")
	}
	next.Release()
	if got, _ := session.Usage(); got != (Vector{}) {
		t.Fatal("new Session scope did not return charge", got)
	}
}

func TestTransferTargetQuotaFailureLeavesOriginalOwnership(t *testing.T) {
	r := testRoot(t, Vector{SDKBytes: 128}, 2, 4)
	preauth := account(t, r, PoolAccount, 1, Vector{SDKBytes: 128})
	session := account(t, r, SessionAccount, 1, Vector{SDKBytes: 63})
	ref, err := r.Reserve(owner(1), Vector{SDKBytes: 64}, preauth)
	if err != nil {
		t.Fatal(err)
	}
	defer ref.Release()
	key := owner(1)
	key.Instance = [16]byte{2}
	before := r.Snapshot()
	if _, err := ref.Transfer(key, [16]byte{1}, session); !errors.Is(err, ErrCapacity) || r.Snapshot() != before {
		t.Fatal("target failure partially transferred backing", err)
	}
	if ref.Check() != nil {
		t.Fatal("target failure revoked original owner")
	}
	if used, _ := session.Usage(); used != (Vector{}) {
		t.Fatal("failed target retained partial charge", used)
	}
	borrow, err := ref.Borrow()
	if err != nil {
		t.Fatal("failed transfer consumed original owner's rights", err)
	}
	borrow.Release()
}

func TestCloseReserveAndReleaseRace(t *testing.T) {
	r := testRoot(t, Vector{SDKBytes: 64}, 64, 128)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := byte(1); i <= 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			ref, err := r.Reserve(owner(i), Vector{SDKBytes: 1})
			if err != nil {
				if !errors.Is(err, ErrClosed) {
					t.Error(err)
				}
				return
			}
			ref.Release()
			ref.Release()
		}()
	}
	close(start)
	r.Close()
	wg.Wait()
	if _, err := r.Reserve(owner(1), Vector{SDKBytes: 1}); !errors.Is(err, ErrClosed) {
		t.Fatal("closed root accepted work", err)
	}
}

func TestRootChargesItsSlabsAndRejectsOverflow(t *testing.T) {
	config := Config{ProfileRevision: [32]byte{1}, AccountSlots: 1, ReservationSlots: 1, ReferenceSlots: 2}
	cost, err := BackingBytes(config)
	if err != nil || cost == 0 {
		t.Fatal(cost, err)
	}
	config.Limit = Vector{SDKBytes: cost - 1}
	if _, err := NewRoot(config); !errors.Is(err, ErrConfiguration) {
		t.Fatal("root metadata uncharged", err)
	}
	config.AllocationOverheadBytes = math.MaxUint64
	if _, err := BackingBytes(config); !errors.Is(err, ErrConfiguration) {
		t.Fatal("backing overflow accepted", err)
	}
	if _, err := (Vector{SDKBytes: math.MaxUint64}).Add(Vector{SDKBytes: 1}); !errors.Is(err, ErrConfiguration) {
		t.Fatal("vector overflow accepted", err)
	}
}

func TestReservationHotPathUsesOnlyAdmittedSlabs(t *testing.T) {
	r := testRoot(t, Vector{SDKBytes: 64}, 1, 4)
	allocs := testing.AllocsPerRun(100, func() {
		ref, err := r.Reserve(owner(1), Vector{SDKBytes: 64})
		if err != nil {
			panic(err)
		}
		borrow, err := ref.Borrow()
		if err != nil {
			panic(err)
		}
		key := owner(1)
		key.Instance = [16]byte{2}
		moved, err := ref.Transfer(key, [16]byte{1})
		if err != nil {
			panic(err)
		}
		ref.Release()
		moved.Release()
		borrow.Release()
	})
	if allocs != 0 {
		t.Fatal("admission created unreserved per-operation metadata", allocs)
	}
}
