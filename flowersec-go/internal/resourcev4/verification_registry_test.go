package resourcev4

import (
	"errors"
	"testing"
)

func TestVerificationRegistryOriginalEnvironmentClaim(t *testing.T) {
	r := testRoot(t, Vector{SDKBytes: 4096, Items: 16}, 8, 32)
	first, err := r.Reserve(owner(1), Vector{Items: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer first.Release()
	borrow, err := first.Borrow()
	if err != nil {
		t.Fatal(err)
	}
	defer borrow.Release()
	if err := borrow.ClaimVerificationRegistry(); !errors.Is(err, ErrOwner) {
		t.Fatal("borrow acquired primary registry identity", err)
	}
	if err := first.ClaimVerificationRegistry(); err != nil {
		t.Fatal(err)
	}
	second, err := r.Reserve(owner(2), Vector{Items: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer second.Release()
	first.Seal()
	if err := second.ClaimVerificationRegistry(); !errors.Is(err, ErrOwner) {
		t.Fatal("sealed live history permitted a second registry", err)
	}
	first.Release()
	if err := second.ClaimVerificationRegistry(); !errors.Is(err, ErrOwner) {
		t.Fatal("retained original borrow lost registry identity", err)
	}
	key := owner(3)
	key.Environment = [16]byte{2}
	other, err := r.Reserve(key, Vector{Items: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer other.Release()
	if err := other.ClaimVerificationRegistry(); err != nil {
		t.Fatal("independent Environment could not own its own registry", err)
	}
}
