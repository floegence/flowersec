package resourcev4

import (
	"errors"
	"testing"
)

func TestApplicationExecutorClaimBelongsToRootRatherThanBorrower(t *testing.T) {
	limit := Vector{SDKBytes: 1024, Items: 8}
	r := testRoot(t, limit, 8, 16)
	env := account(t, r, EnvironmentAccount, 1, limit)
	scoped, err := r.Reserve(owner(1), Vector{SDKBytes: 128}, env)
	if err != nil {
		t.Fatal(err)
	}
	defer scoped.Release()
	if err := scoped.ClaimApplicationExecutor(); !errors.Is(err, ErrOwner) {
		t.Fatal("borrower installed shared executor", err)
	}
	shared, err := r.Reserve(owner(2), Vector{SDKBytes: 128})
	if err != nil {
		t.Fatal(err)
	}
	defer shared.Release()
	borrow, err := shared.Borrow()
	if err != nil {
		t.Fatal(err)
	}
	defer borrow.Release()
	if err := borrow.ClaimApplicationExecutor(); !errors.Is(err, ErrOwner) {
		t.Fatal("alias acquired root factory ownership", err)
	}
	if err := shared.ClaimApplicationExecutor(); err != nil {
		t.Fatal(err)
	}
	env.Close()
	if err := shared.Check(); err != nil {
		t.Fatal("borrower close fenced shared executor", err)
	}
	shared.Release()
	newRef, err := r.Reserve(owner(3), Vector{SDKBytes: 128})
	if err != nil {
		t.Fatal(err)
	}
	defer newRef.Release()
	if err := newRef.ClaimApplicationExecutor(); !errors.Is(err, ErrOwner) {
		t.Fatal("root recycled executor after logical close", err)
	}
}

func TestSharedRootCheckDoesNotConflateEnvironmentOrPrivateRoot(t *testing.T) {
	limit := Vector{SDKBytes: 1024, Items: 8}
	r := testRoot(t, limit, 8, 16)
	a, err := r.Reserve(owner(1), Vector{SDKBytes: 128})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Release()
	key := owner(2)
	key.Environment = [16]byte{2}
	b, err := r.Reserve(key, Vector{SDKBytes: 128})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Release()
	if a.CheckSameRoot(b) != nil || !errors.Is(a.CheckSameEnvironment(b), ErrOwner) {
		t.Fatal("shared-root check changed Environment identity")
	}
	other := testRoot(t, limit, 8, 16)
	foreign, err := other.Reserve(owner(1), Vector{SDKBytes: 128})
	if err != nil {
		t.Fatal(err)
	}
	defer foreign.Release()
	if err := a.CheckSameRoot(foreign); !errors.Is(err, ErrOwner) {
		t.Fatal("labels equated private roots", err)
	}
	b.Release()
	if err := a.CheckSameRoot(b); !errors.Is(err, ErrOwner) {
		t.Fatal("stale reference retained shared service authority", err)
	}
}
