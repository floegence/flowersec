package resourcev4

import (
	"errors"
	"testing"
)

func TestProtectedRequestCheckRetainsOriginalScopeAndGeneration(t *testing.T) {
	minimum := Vector{SDKBytes: 1024, Items: 2}
	charge, err := ProtectedCharge(minimum)
	if err != nil {
		t.Fatal(err)
	}
	r := testRoot(t, charge, 1, 2)
	tenant := account(t, r, TenantAccount, 1, charge)
	session := account(t, r, SessionAccount, 2, charge)
	ref, err := r.Reserve(owner(1), charge, tenant, session)
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewProtectedReservation(ref, minimum)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	request := Request{Owner: owner(1), Charge: charge, Accounts: []Account{tenant, session}}
	before := r.Snapshot()
	if err := p.CheckAdmissionRequest(request); err != nil {
		t.Fatal(err)
	}
	if r.Snapshot() != before || !errors.Is(ref.CheckRequest(request), ErrOwner) {
		t.Fatal("request check revived stale owner or changed admission")
	}
	for _, changed := range []Request{
		{Owner: owner(2), Charge: charge, Accounts: request.Accounts},
		{Owner: owner(1), Charge: charge, Accounts: []Account{tenant}},
		{Owner: owner(1), Charge: charge, Accounts: []Account{tenant, tenant}},
		{Owner: owner(1), Charge: charge, Accounts: request.Accounts, ResultOwner: true},
	} {
		if err := p.CheckAdmissionRequest(changed); !errors.Is(err, ErrOwner) {
			t.Fatal("accepted changed original owner", err)
		}
	}
	changed := request
	changed.Charge[SDKBytes]++
	if err := p.CheckAdmissionRequest(changed); !errors.Is(err, ErrCapacity) {
		t.Fatal(err)
	}
	live, err := p.Checkout()
	if err != nil {
		t.Fatal(err)
	}
	if err := p.CheckAdmissionRequest(request); !errors.Is(err, ErrCapacity) {
		t.Fatal("active backing accepted as unused admission", err)
	}
	live.Release()
	if err := p.CheckAdmissionRequest(request); !errors.Is(err, ErrOwner) {
		t.Fatal("returned use became a new original admission", err)
	}
	session.Close()
	if err := p.CheckAdmissionRequest(request); !errors.Is(err, ErrClosed) {
		t.Fatal("closed Session scope accepted", err)
	}
}
