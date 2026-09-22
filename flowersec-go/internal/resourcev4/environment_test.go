package resourcev4

import (
	"errors"
	"testing"
)

func TestOriginalEnvironmentCompositionAndDestructionFence(t *testing.T) {
	limit := Vector{SDKBytes: 1024, Items: 8}
	r := testRoot(t, limit, 8, 16)
	env := account(t, r, EnvironmentAccount, 1, limit)
	first, err := r.Reserve(owner(1), Vector{SDKBytes: 128}, env)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Release()
	second, err := r.Reserve(owner(2), Vector{Items: 1}, env)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Release()
	if err := first.CheckSameEnvironment(second); err != nil || first.EnvironmentClosed() {
		t.Fatal("valid Environment composition rejected", err)
	}
	other := testRoot(t, limit, 8, 16)
	private, _ := other.Reserve(owner(3), Vector{Items: 1})
	defer private.Release()
	if err := first.CheckSameEnvironment(private); !errors.Is(err, ErrOwner) {
		t.Fatal("equal Environment label hid a private root", err)
	}
	key := owner(4)
	key.Environment = [16]byte{2}
	foreign, _ := r.Reserve(key, Vector{Items: 1})
	defer foreign.Release()
	if err := first.CheckSameEnvironment(foreign); !errors.Is(err, ErrOwner) {
		t.Fatal("another Environment could share the namespace", err)
	}
	first.Seal()
	if first.EnvironmentClosed() || !errors.Is(first.CheckSameEnvironment(second), ErrClosed) {
		t.Fatal("individual owner closure substituted for Environment destruction")
	}
	env.Close()
	if !first.EnvironmentClosed() || !second.EnvironmentClosed() || foreign.EnvironmentClosed() {
		t.Fatal("Environment destruction fence has the wrong scope")
	}
	first.Release()
	if first.EnvironmentClosed() {
		t.Fatal("stale handle proved Environment destruction")
	}
	r.Close()
	if !foreign.EnvironmentClosed() {
		t.Fatal("root destruction failed to fence its real owners")
	}
}
