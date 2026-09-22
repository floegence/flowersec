package resourcev4

import (
	"encoding/binary"
	"errors"
	"testing"
)

func TestResultOwnerCapIsSharedAndFollowsActualAliases(t *testing.T) {
	r := testRoot(t, Vector{SDKBytes: 1 << 20}, MaxResultOwners+2, MaxResultOwners+4)
	key := func(i uint64) OwnerKey {
		k := owner(1)
		binary.BigEndian.PutUint64(k.Instance[:8], i+1)
		k.Backing = k.Instance
		k.Environment[0] = byte(1 + i%2)
		return k
	}
	refs := make([]Reference, MaxResultOwners)
	defer func() {
		for _, ref := range refs {
			ref.Release()
		}
	}()
	for i := range refs {
		var err error
		refs[i], err = r.ReserveResult(key(uint64(i)), Vector{SDKBytes: 1})
		if err != nil {
			t.Fatal(i, err)
		}
	}
	before := r.Snapshot()
	if _, err := r.ReserveResult(key(MaxResultOwners), Vector{SDKBytes: 1}); !errors.Is(err, ErrCapacity) || r.Snapshot() != before {
		t.Fatal("exceeded root result owners", err)
	}
	alias, err := refs[0].Borrow()
	if err != nil {
		t.Fatal(err)
	}
	refs[0].Release()
	if _, err := r.ReserveResult(key(MaxResultOwners), Vector{SDKBytes: 1}); !errors.Is(err, ErrCapacity) {
		t.Fatal("logical result release lost physical alias", err)
	}
	alias.Release()
	refs[0], err = r.ReserveResult(key(MaxResultOwners), Vector{SDKBytes: 1})
	if err != nil {
		t.Fatal(err)
	}
	// A complete batch rolls back ordinary bytes too when its result position
	// is unavailable. No half-admitted request is exposed to the publisher.
	var output [2]Reference
	before = r.Snapshot()
	requests := []Request{{Owner: key(MaxResultOwners + 1), Charge: Vector{SDKBytes: 1}}, {Owner: key(MaxResultOwners + 2), Charge: Vector{SDKBytes: 1}, ResultOwner: true}}
	if err := r.ReserveBatch(requests, output[:]); !errors.Is(err, ErrCapacity) || r.Snapshot() != before || output != ([2]Reference{}) {
		t.Fatal("partial result batch", err)
	}
}

func TestProtectedResultPositionRemainsReservedBetweenCalls(t *testing.T) {
	minimum := Vector{SDKBytes: 128}
	charge, _ := ProtectedCharge(minimum)
	r := testRoot(t, charge, 1, 1)
	ref, err := r.ReserveResult(owner(1), charge)
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewProtectedReservation(ref, minimum)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	for range 10 {
		ref, err := p.Checkout()
		if err != nil {
			t.Fatal(err)
		}
		if err := ref.CheckResultOwner(); err != nil {
			t.Fatal(err)
		}
		ref.Release()
		if r.Snapshot().ResultOwners != 1 {
			t.Fatal("idle floor refunded result position")
		}
	}
	p.Close()
	if r.Snapshot().ResultOwners != 0 {
		t.Fatal("closed floor retained result position")
	}
}
