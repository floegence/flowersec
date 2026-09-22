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
