package resourcev4

import (
	"errors"
	"testing"
)

func TestRootApplicationServiceIsPhysicalOnceAndChargedInEveryBorrower(t *testing.T) {
	limit := Vector{SDKBytes: 16384, Items: 128, Tasks: 8, WorkSlots: 8}
	r := testRoot(t, limit, 8, 32)
	serviceCharge := Vector{SDKBytes: 1024, Items: 4, Tasks: 2, WorkSlots: 2}
	service, err := r.Reserve(owner(1), serviceCharge)
	if err != nil {
		t.Fatal(err)
	}
	defer service.Release()
	if err := service.ClaimApplicationExecutor(); err != nil {
		t.Fatal(err)
	}
	tenant := account(t, r, TenantAccount, 7, limit)
	environments := [2]Account{account(t, r, EnvironmentAccount, 1, limit), account(t, r, EnvironmentAccount, 2, limit)}
	var inputs [2]Reference
	for i := range inputs {
		key := owner(byte(i + 2))
		key.Environment = [16]byte{byte(i + 1)}
		inputs[i], err = r.Reserve(key, Vector{SDKBytes: 128, Items: 1}, tenant, environments[i])
		if err != nil {
			t.Fatal(err)
		}
		defer inputs[i].Release()
	}
	physical := r.Snapshot().Charged
	var aliases [3]Reference
	for i, input := range []Reference{inputs[0], inputs[1], inputs[0]} {
		aliases[i], err = service.BorrowApplicationService(input)
		if err != nil {
			t.Fatal(err)
		}
		defer aliases[i].Release()
	}
	if r.Snapshot().Charged != physical {
		t.Fatal("borrower aliases duplicated physical root service", r.Snapshot(), physical)
	}
	if got, err := tenant.Usage(); err != nil || got[SDKBytes] != 1024+256 || got[Tasks] != 2 {
		t.Fatal("same tenant received duplicate service capacity or zero charge", got, err)
	}
	for _, environment := range environments {
		if got, err := environment.Usage(); err != nil || got[SDKBytes] != 1024+128 || got[Tasks] != 2 {
			t.Fatal("enabled Environment missed its shared service responsibility", got, err)
		}
	}
	environments[0].Close()
	if err := aliases[0].Check(); !errors.Is(err, ErrClosed) {
		t.Fatal("closed Environment retained new service authority", err)
	}
	if err := aliases[1].Check(); err != nil {
		t.Fatal("one borrower closed the other Environment's service", err)
	}
	aliases[0].Release()
	if got, _ := environments[0].Usage(); got[SDKBytes] != 1024+128 {
		t.Fatal("one released alias refunded a live callback", got)
	}
	aliases[2].Release()
	if got, _ := environments[0].Usage(); got[SDKBytes] != 128 {
		t.Fatal("last original tail failed to refund its service scope", got)
	}
	if _, err := aliases[1].BorrowApplicationService(inputs[1]); !errors.Is(err, ErrOwner) {
		t.Fatal("borrowed service capability minted another primary service", err)
	}
}

func TestApplicationServiceScopeRefusalKeepsTheOriginalInput(t *testing.T) {
	limit := Vector{SDKBytes: 4096, Items: 16}
	r := testRoot(t, limit, 4, 16)
	service, err := r.Reserve(owner(1), Vector{SDKBytes: 1024, Items: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Release()
	if err := service.ClaimApplicationExecutor(); err != nil {
		t.Fatal(err)
	}
	tenant := account(t, r, TenantAccount, 7, Vector{SDKBytes: 1024, Items: 16})
	input, err := r.Reserve(owner(2), Vector{SDKBytes: 128, Items: 1}, tenant)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Release()
	before := r.Snapshot()
	if _, err := service.BorrowApplicationService(input); !errors.Is(err, ErrCapacity) || r.Snapshot() != before {
		t.Fatal("failed shared-service admission mutated its original vector", err, r.Snapshot(), before)
	}
	if err := input.Check(); err != nil {
		t.Fatal("local profile refusal revoked an unsubmitted input", err)
	}
}
