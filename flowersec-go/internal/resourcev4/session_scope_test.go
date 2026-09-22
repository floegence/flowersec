package resourcev4

import (
	"errors"
	"testing"
)

func TestCheckSessionScopeRequiresExactAccountsAndOnePosition(t *testing.T) {
	limit := Vector{SDKBytes: 1024, Sessions: 8}
	r, foreign := testRoot(t, limit, 8, 16), testRoot(t, limit, 2, 4)
	tenant := account(t, r, TenantAccount, 1, limit)
	session := account(t, r, SessionAccount, 1, limit)
	otherTenant := account(t, r, TenantAccount, 2, limit)
	otherSession := account(t, r, SessionAccount, 2, limit)
	foreignTenant := account(t, foreign, TenantAccount, 1, limit)
	foreignSession := account(t, foreign, SessionAccount, 1, limit)
	ref, err := r.Reserve(owner(1), Vector{SDKBytes: 16, Sessions: 1}, tenant, session)
	if err != nil {
		t.Fatal(err)
	}
	defer ref.Release()
	for _, tc := range []struct {
		name            string
		tenant, session Account
		want            error
	}{
		{"exact", tenant, session, nil},
		{"other-tenant", otherTenant, session, ErrOwner},
		{"other-session", tenant, otherSession, ErrOwner},
		{"foreign-tenant-same-key", foreignTenant, session, ErrOwner},
		{"foreign-session-same-key", tenant, foreignSession, ErrOwner},
		{"swapped-kinds", session, tenant, ErrOwner},
		{"missing-account-handle", Account{}, session, ErrOwner},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before, foreignBefore := r.Snapshot(), foreign.Snapshot()
			if err := ref.CheckSessionScope(tc.tenant, tc.session); !errors.Is(err, tc.want) {
				t.Fatalf("scope check: %v, want %v", err, tc.want)
			}
			if r.Snapshot() != before || foreign.Snapshot() != foreignBefore {
				t.Fatal("scope check changed an account or reservation")
			}
		})
	}
	for i, tc := range []struct {
		name     string
		charge   Vector
		accounts []Account
		want     error
	}{
		{"no-session-position", Vector{SDKBytes: 1}, []Account{tenant, session}, ErrCapacity},
		{"aggregate-session-positions", Vector{SDKBytes: 1, Sessions: 2}, []Account{tenant, session}, ErrCapacity},
		{"tenant-not-attached", Vector{SDKBytes: 1, Sessions: 1}, []Account{session}, ErrOwner},
		{"session-not-attached", Vector{SDKBytes: 1, Sessions: 1}, []Account{tenant}, ErrOwner},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate, err := r.Reserve(owner(byte(i+2)), tc.charge, tc.accounts...)
			if err != nil {
				t.Fatal(err)
			}
			defer candidate.Release()
			before := r.Snapshot()
			if err := candidate.CheckSessionScope(tenant, session); !errors.Is(err, tc.want) {
				t.Fatalf("scope check: %v, want %v", err, tc.want)
			}
			if r.Snapshot() != before || candidate.Check() != nil {
				t.Fatal("failed check consumed or sealed the original reservation")
			}
		})
	}
}

func TestCheckSessionScopeTracksOriginalReferenceAcrossTransferAndBorrow(t *testing.T) {
	limit := Vector{SDKBytes: 128, Sessions: 1}
	r := testRoot(t, limit, 2, 8)
	tenant := account(t, r, TenantAccount, 1, limit)
	preauth := account(t, r, PoolAccount, 1, limit)
	session := account(t, r, SessionAccount, 1, limit)
	ref, err := r.Reserve(owner(1), limit, tenant, preauth)
	if err != nil {
		t.Fatal(err)
	}
	defer ref.Release()
	oldTask, err := ref.Borrow()
	if err != nil {
		t.Fatal(err)
	}
	defer oldTask.Release()
	key := owner(1)
	key.Instance = [16]byte{2}
	current, err := ref.Transfer(key, [16]byte{1}, tenant, session)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { current.Release() }()
	for _, old := range []Reference{ref, oldTask} {
		if err := old.CheckSessionScope(tenant, session); !errors.Is(err, ErrOwner) {
			t.Fatal("preauth reference borrowed the successor's Session scope", err)
		}
	}
	if err := current.CheckSessionScope(tenant, session); err != nil {
		t.Fatal(err)
	}
	task, err := current.Borrow()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { task.Release() }()
	staleTask := task
	task, err = task.TakeBorrow()
	if err != nil {
		t.Fatal(err)
	}
	if err := staleTask.CheckSessionScope(tenant, session); !errors.Is(err, ErrOwner) {
		t.Fatal("moved borrow's stale handle remained admissible", err)
	}
	before := r.Snapshot().Charged
	staleCurrent := current
	current, err = current.Take(limit)
	if err != nil {
		t.Fatal(err)
	}
	if err := staleCurrent.CheckSessionScope(tenant, session); !errors.Is(err, ErrOwner) {
		t.Fatal("taken primary's stale handle remained admissible", err)
	}
	for _, live := range []Reference{current, task} {
		if err := live.CheckSessionScope(tenant, session); err != nil {
			t.Fatal("handoff lost the exact original scope", err)
		}
	}
	preauth.Close()
	if err := current.CheckSessionScope(tenant, session); err != nil {
		t.Fatal("closing the predecessor scope fenced its successor", err)
	}
	session.Close()
	for _, live := range []Reference{current, task} {
		if err := live.CheckSessionScope(tenant, session); !errors.Is(err, ErrClosed) {
			t.Fatal("Session close did not fence a real reference", err)
		}
	}
	if r.Snapshot().Charged != before {
		t.Fatal("closing an account refunded held backing")
	}
}

func TestCheckSessionScopeRejectsReusedAccountAndReferenceGenerations(t *testing.T) {
	limit := Vector{SDKBytes: 128, Sessions: 1}
	r := testRoot(t, limit, 2, 4)
	oldTenant := account(t, r, TenantAccount, 1, limit)
	oldTenant.Close()
	tenant := account(t, r, TenantAccount, 1, limit)
	oldSession := account(t, r, SessionAccount, 1, limit)
	oldSession.Close()
	session := account(t, r, SessionAccount, 1, limit)
	if tenant.index != oldTenant.index || tenant.generation == oldTenant.generation || session.index != oldSession.index || session.generation == oldSession.generation {
		t.Fatal("test did not recycle the original account slots")
	}
	ref, err := r.Reserve(owner(1), limit, tenant, session)
	if err != nil {
		t.Fatal(err)
	}
	if err := ref.CheckSessionScope(oldTenant, session); !errors.Is(err, ErrOwner) {
		t.Fatal("stale tenant generation matched its replacement", err)
	}
	if err := ref.CheckSessionScope(tenant, oldSession); !errors.Is(err, ErrOwner) {
		t.Fatal("stale Session generation matched its replacement", err)
	}
	ref.Release()
	replacement, err := r.Reserve(owner(2), limit, tenant, session)
	if err != nil {
		t.Fatal(err)
	}
	defer replacement.Release()
	if err := ref.CheckSessionScope(tenant, session); !errors.Is(err, ErrOwner) {
		t.Fatal("stale reference matched its replacement", err)
	}
	oldTenant.Close()
	oldSession.Close()
	if err := replacement.CheckSessionScope(tenant, session); err != nil {
		t.Fatal("stale account close affected the current generation", err)
	}
}

func TestCheckSessionScopeHonorsAdmissionFencesWithoutRefund(t *testing.T) {
	for _, fence := range []string{"tenant", "session", "reservation", "root"} {
		t.Run(fence, func(t *testing.T) {
			limit := Vector{SDKBytes: 128, Sessions: 1}
			r := testRoot(t, limit, 2, 4)
			tenant := account(t, r, TenantAccount, 1, limit)
			session := account(t, r, SessionAccount, 1, limit)
			ref, err := r.Reserve(owner(1), limit, tenant, session)
			if err != nil {
				t.Fatal(err)
			}
			defer ref.Release()
			borrow, err := ref.Borrow()
			if err != nil {
				t.Fatal(err)
			}
			defer borrow.Release()
			before := r.Snapshot().Charged
			switch fence {
			case "tenant":
				tenant.Close()
			case "session":
				session.Close()
			case "reservation":
				ref.Seal()
			case "root":
				r.Close()
			}
			for _, live := range []Reference{ref, borrow} {
				if err := live.CheckSessionScope(tenant, session); !errors.Is(err, ErrClosed) {
					t.Fatal("closed admission remained usable", err)
				}
			}
			if r.Snapshot().Charged != before {
				t.Fatal("check returned quota while original references remained")
			}
		})
	}
	if err := (Reference{}).CheckSessionScope(Account{}, Account{}); !errors.Is(err, ErrOwner) {
		t.Fatal("zero reference acquired a Session scope", err)
	}
}
