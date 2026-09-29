package resourcev4

import "testing"

func TestRetainsCleanupScopeObservesOriginalAliasesAfterClose(t *testing.T) {
	limit := Vector{SDKBytes: 1024}
	r := testRoot(t, limit, 8, 16)
	session := account(t, r, SessionAccount, 1, limit)
	other := account(t, r, SessionAccount, 2, limit)
	ref, err := r.Reserve(owner(1), Vector{SDKBytes: 16}, session)
	if err != nil {
		t.Fatal(err)
	}
	defer ref.Release()
	alias, err := ref.Borrow()
	if err != nil {
		t.Fatal(err)
	}
	defer alias.Release()
	if err := alias.DetachSessionScope(); err != nil {
		t.Fatal(err)
	}
	if alias.RetainsCleanupScope(session, Reference{}) || !alias.RetainsCleanupScope(Account{}, ref) {
		t.Fatal("detached scope and original plan backing were confused")
	}
	session.Close()
	ref.Seal()
	r.Close()
	before := r.Snapshot()
	if !ref.RetainsCleanupScope(session, Reference{}) || ref.RetainsCleanupScope(other, Reference{}) || !alias.RetainsCleanupScope(Account{}, ref) {
		t.Fatal("logical close erased original callback attribution")
	}
	if before != r.Snapshot() {
		t.Fatal("passive attribution changed resource ownership")
	}
	alias.Release()
	if alias.RetainsCleanupScope(Account{}, ref) {
		t.Fatal("released callback retained attribution")
	}
}
