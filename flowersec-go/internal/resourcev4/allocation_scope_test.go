package resourcev4

import (
	"errors"
	"testing"
)

func TestAllocationScopePreservesEveryOriginalAccount(t *testing.T) {
	config := Config{ProfileRevision: [32]byte{1}, AccountSlots: 4, ReservationSlots: 8, ReferenceSlots: 16, Limit: Vector{SDKBytes: 1 << 20, Items: 64}}
	root, err := NewRoot(config)
	if err != nil {
		t.Fatal(err)
	}
	tenant, err := root.Account(AccountKey{Kind: TenantAccount, ID: [16]byte{1}}, Vector{SDKBytes: 65536, Items: 16})
	if err != nil {
		t.Fatal(err)
	}
	env, err := root.Account(AccountKey{Kind: EnvironmentAccount, ID: [16]byte{2}}, Vector{SDKBytes: 65536, Items: 16})
	if err != nil {
		t.Fatal(err)
	}
	owner := OwnerKey{ProfileRevision: [32]byte{1}, Environment: [16]byte{2}, Instance: [16]byte{3}, Backing: [16]byte{4}, Kind: 1}
	ref, err := root.Reserve(owner, Vector{SDKBytes: 128, Items: 1}, tenant, env)
	if err != nil {
		t.Fatal(err)
	}
	defer ref.Release()
	if err := ref.CheckAllocationScope(root, owner, []Account{env, tenant}); err != nil {
		t.Fatal(err)
	}
	for _, accounts := range [][]Account{nil, {env}, {tenant}, {env, env}} {
		if err := ref.CheckAllocationScope(root, owner, accounts); !errors.Is(err, ErrOwner) {
			t.Fatal("omitted/substituted original account", err)
		}
	}
	other, err := NewRoot(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := ref.CheckAllocationScope(other, owner, []Account{tenant, env}); !errors.Is(err, ErrOwner) {
		t.Fatal("foreign root accepted", err)
	}
	owner.Environment[0]++
	if err := ref.CheckAllocationScope(root, owner, []Account{tenant, env}); !errors.Is(err, ErrOwner) {
		t.Fatal("foreign Environment accepted", err)
	}
	tenant.Close()
	if err := ref.CheckAllocationScope(root, owner, []Account{tenant, env}); !errors.Is(err, ErrClosed) {
		t.Fatal("closed original account accepted", err)
	}
}
