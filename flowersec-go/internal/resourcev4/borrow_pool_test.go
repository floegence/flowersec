package resourcev4

import (
	"errors"
	"testing"
)

func reserveBorrowPool(t *testing.T, r *Root, id byte, capacity uint32, accounts ...Account) *BorrowPool {
	t.Helper()
	charge, err := BorrowPoolCharge(capacity)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := r.Reserve(owner(id), charge, accounts...)
	if err != nil {
		t.Fatal(err)
	}
	defer metadata.Release()
	p, err := NewBorrowPoolForSources(metadata, capacity)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return p
}

func TestBorrowPoolInBackingPreservesSharedPrimaryAndExactParents(t *testing.T) {
	r := testRoot(t, Vector{SDKBytes: 4096, Items: 16}, 2, 5)
	charge, err := BorrowPoolCharge(2)
	if err != nil {
		t.Fatal(err)
	}
	charge[SDKBytes] += 64
	backing, err := r.Reserve(owner(1), charge)
	if err != nil {
		t.Fatal(err)
	}
	defer backing.Release()
	parent, err := r.Reserve(owner(2), Vector{SDKBytes: 64})
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Release()
	p, err := NewBorrowPoolInBacking(backing, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if backing.Check() != nil {
		t.Fatal("component admission took the shared primary")
	}
	before := r.Snapshot()
	if _, err := backing.Borrow(); !errors.Is(err, ErrCapacity) {
		t.Fatal("fixture did not exhaust root references", err)
	}
	a, err := p.Borrow(backing)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Release()
	b, err := p.Borrow(parent)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Release()
	if a.CheckBorrowedFrom(backing) != nil || b.CheckBorrowedFrom(parent) != nil || r.Snapshot() != before {
		t.Fatal("shared component borrowed another source or acquired fresh capacity")
	}
	next, err := backing.Take(charge)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Release()
	a.Release()
	a, err = p.Borrow(next)
	if err != nil {
		t.Fatal("aggregate adoption invalidated its admitted component", err)
	}
	p.Close()
	if p.CleanupComplete() {
		t.Fatal("Close refunded an actual component tail")
	}
	a.Release()
	b.Release()
	if !p.CleanupComplete() || next.Check() != nil || r.Snapshot().Charged != before.Charged {
		t.Fatal("component cleanup changed the shared aggregate owner")
	}
}

func TestBorrowPoolInBackingFailedAdmissionPreservesAggregate(t *testing.T) {
	r := testRoot(t, Vector{SDKBytes: 4096, Items: 16}, 1, 3)
	charge, err := BorrowPoolCharge(2)
	if err != nil {
		t.Fatal(err)
	}
	backing, err := r.Reserve(owner(1), charge)
	if err != nil {
		t.Fatal(err)
	}
	defer backing.Release()
	before := r.Snapshot()
	if p, err := NewBorrowPoolInBacking(backing, 2); p != nil || !errors.Is(err, ErrCapacity) {
		t.Fatal(p, err)
	}
	if backing.Check() != nil || r.Snapshot() != before {
		t.Fatal("failed component admission consumed the aggregate or leaked aliases")
	}
}

func TestBorrowPoolRetainsDifferentParentsAtFullReferenceCapacity(t *testing.T) {
	r := testRoot(t, Vector{SDKBytes: 4096, Items: 16}, 3, 5)
	first, err := r.Reserve(owner(1), Vector{SDKBytes: 64})
	if err != nil {
		t.Fatal(err)
	}
	defer first.Release()
	second, err := r.Reserve(owner(2), Vector{SDKBytes: 128})
	if err != nil {
		t.Fatal(err)
	}
	defer second.Release()
	p := reserveBorrowPool(t, r, 3, 2)
	before := r.Snapshot()
	if _, err := first.Borrow(); !errors.Is(err, ErrCapacity) {
		t.Fatal("fixture did not exhaust the root reference slab", err)
	}
	a, err := p.Borrow(first)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Release()
	b, err := p.Borrow(second)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Release()
	if r.Snapshot() != before || a.CheckBorrowedFrom(first) != nil || b.CheckBorrowedFrom(second) != nil {
		t.Fatal("checkout did not reuse the admitted positions and exact parents")
	}
	if _, err := p.Borrow(first); !errors.Is(err, ErrCapacity) {
		t.Fatal("occupied pool manufactured an extra dependency", err)
	}
	a.Release()
	reused, err := p.Borrow(second)
	if err != nil {
		t.Fatal(err)
	}
	defer reused.Release()
	a.Release()
	if reused.Check() != nil || a == reused || r.Snapshot() != before {
		t.Fatal("stale borrower released a later use or changed charges")
	}
	first.Release()
	if r.Snapshot().Charged[SDKBytes] != before.Charged[SDKBytes]-64 {
		t.Fatal("idle pool retained a parent after its final actual use")
	}
	second.Release()
	p.Close()
	if p.CleanupComplete() {
		t.Fatal("close refunded live dependency tails")
	}
	b.Release()
	if p.CleanupComplete() {
		t.Fatal("one of two actual tails released both")
	}
	reused.Release()
	if !p.CleanupComplete() || r.Snapshot().References != 0 {
		t.Fatal("last tail failed to settle pool metadata and original parent")
	}
}

func TestBorrowPoolPreservesParentFencesAndDetachedResultCapacity(t *testing.T) {
	limit := Vector{SDKBytes: 4096, Items: 16}
	r := testRoot(t, limit, 4, 8)
	environment := account(t, r, EnvironmentAccount, 1, limit)
	session := account(t, r, SessionAccount, 2, limit)
	direction := account(t, r, DirectionAccount, 3, limit)
	p := reserveBorrowPool(t, r, 1, 2, environment, session, direction)
	parent, err := r.Reserve(owner(2), Vector{SDKBytes: 64}, environment)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Release()
	foreignKey := owner(3)
	foreignKey.Environment = [16]byte{2}
	foreign, err := r.Reserve(foreignKey, Vector{SDKBytes: 64})
	if err != nil {
		t.Fatal(err)
	}
	defer foreign.Release()
	if _, err := p.Borrow(foreign); !errors.Is(err, ErrOwner) {
		t.Fatal("another Environment consumed the original workload", err)
	}
	session.Close()
	direction.Close()
	alias, err := p.Borrow(parent)
	if err != nil {
		t.Fatal("transport close removed an independent result's capacity", err)
	}
	defer alias.Release()
	if alias.CheckBorrowedFrom(parent) != nil {
		t.Fatal("result borrowed transport authority instead of its actual parent")
	}
	environment.Close()
	if _, err := p.Borrow(parent); !errors.Is(err, ErrClosed) {
		t.Fatal("capacity reopened a closed Environment", err)
	}
	if !errors.Is(alias.Check(), ErrClosed) {
		t.Fatal("borrow lost its actual parent's fence")
	}
}

func TestBorrowPoolRetiresProtectedParentBeforeReturningPosition(t *testing.T) {
	r := testRoot(t, Vector{SDKBytes: 4096, Items: 16}, 2, 4)
	minimum := Vector{SDKBytes: 64}
	charge, err := ProtectedCharge(minimum)
	if err != nil {
		t.Fatal(err)
	}
	primary, err := r.Reserve(owner(1), charge)
	if err != nil {
		t.Fatal(err)
	}
	defer primary.Release()
	protected, err := NewProtectedReservation(primary, minimum)
	if err != nil {
		t.Fatal(err)
	}
	defer protected.CloseAfterUse()
	p := reserveBorrowPool(t, r, 2, 2)
	use, err := protected.Checkout()
	if err != nil {
		t.Fatal(err)
	}
	defer use.Release()
	alias, err := p.Borrow(use)
	if err != nil {
		t.Fatal(err)
	}
	defer alias.Release()
	use.Release()
	if !errors.Is(protected.CheckAvailable(), ErrCapacity) {
		t.Fatal("parent floor reused a live dependency tail")
	}
	alias.Release()
	if protected.CheckAvailable() != nil || p.CheckAvailable() != nil {
		t.Fatal("actual tail failed to return both original responsibilities")
	}
	next, err := protected.Checkout()
	if err != nil {
		t.Fatal(err)
	}
	defer next.Release()
	if _, err := p.Borrow(use); !errors.Is(err, ErrOwner) {
		t.Fatal("retired parent generation created another use", err)
	}
	borrowed, err := p.Borrow(next)
	if err != nil {
		t.Fatal(err)
	}
	defer borrowed.Release()
	protected.CloseAfterUse()
	next.Release()
	if protected.CleanupComplete() {
		t.Fatal("protected close refunded an outstanding parent")
	}
	borrowed.Release()
	if !protected.CleanupComplete() {
		t.Fatal("last dependency failed to retire protected backing")
	}
}

func TestBorrowPoolFailedAdmissionReturnsEveryUnpublishedPosition(t *testing.T) {
	r := testRoot(t, Vector{SDKBytes: 4096, Items: 16}, 1, 2)
	charge, err := BorrowPoolCharge(2)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := r.Reserve(owner(1), charge)
	if err != nil {
		t.Fatal(err)
	}
	defer metadata.Release()
	if p, err := NewBorrowPoolForSources(metadata, 2); p != nil || !errors.Is(err, ErrCapacity) {
		t.Fatal("incomplete reference admission succeeded", p, err)
	}
	if got := r.Snapshot(); got.References != 0 || got.Reservations != 0 {
		t.Fatal("failed admission leaked its partial slots or metadata", got)
	}
}
