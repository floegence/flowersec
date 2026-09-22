package sessionv4

import (
	"errors"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

// Isolated root/profile for internal tests; no provider/allocator qualification
// is inferred from these small synthetic charges.
func testReceiveReservation(t *testing.T, capacity uint64, flows uint32) (*resourcev4.Root, resourcev4.Reference) {
	t.Helper()
	charge, err := ReceivePoolCharge(capacity, flows)
	if err != nil {
		t.Fatal(err)
	}
	return testResourceReservation(t, charge, flows+1)
}

func testResourceReservation(t *testing.T, charge resourcev4.Vector, references uint32) (*resourcev4.Root, resourcev4.Reference) {
	t.Helper()
	config := resourcev4.Config{ProfileRevision: [32]byte{1}, AccountSlots: 4, ReservationSlots: 1, ReferenceSlots: references}
	backing, err := resourcev4.BackingBytes(config)
	if err != nil {
		t.Fatal(err)
	}
	config.Limit = charge
	config.Limit[resourcev4.SDKBytes] += backing
	root, err := resourcev4.NewRoot(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(root.Close)
	key := resourcev4.OwnerKey{ProfileRevision: config.ProfileRevision, Environment: [16]byte{1}, Kind: 1, Instance: [16]byte{1}, Backing: [16]byte{1}, Direction: 1}
	ref, err := root.Reserve(key, charge)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ref.Release)
	return root, ref
}

func testReceivePool(t *testing.T, signed, capacity uint64) (*ReceivePool, error) {
	t.Helper()
	_, ref := testReceiveReservation(t, capacity, 32)
	pool, err := NewReceivePool(signed, capacity, 32, ref)
	if err == nil {
		t.Cleanup(pool.Close)
	}
	return pool, err
}

func TestReceivePoolUsesOriginalReservationAndRetainsCleanupCharge(t *testing.T) {
	root, ref := testReceiveReservation(t, 32, 2)
	if _, err := NewReceivePool(32, 32, 2, resourcev4.Reference{}); !errors.Is(err, resourcev4.ErrOwner) {
		t.Fatal("unreserved receive pool accepted", err)
	}
	pool, err := NewReceivePool(32, 32, 2, ref)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if _, err := NewReceivePool(32, 32, 2, ref); !errors.Is(err, resourcev4.ErrOwner) {
		t.Fatal("one reservation attached to two pools", err)
	}
	ref.Release()
	if root.Snapshot().Reservations != 1 {
		t.Fatal("stale constructor caller released attached pool")
	}
	a, err := NewReceiveFlow(pool, 1, protocolv4.ClientToServer, 0, TerminalTuple{}, 16)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewReceiveFlow(pool, 3, protocolv4.ClientToServer, 0, TerminalTuple{}, 16)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewReceiveFlow(pool, 5, protocolv4.ClientToServer, 0, TerminalTuple{}, 0); !errors.Is(err, resourcev4.ErrCapacity) {
		t.Fatal("zero-byte flow bypassed owner item cap", err)
	}
	before := root.Snapshot()
	pool.Close()
	if got := root.Snapshot(); got.Charged != before.Charged || got.References != 2 {
		t.Fatal("close returned live flow backing", got)
	}
	if err := a.Cleanup(); err != nil {
		t.Fatal(err)
	}
	if got := root.Snapshot(); got.Charged != before.Charged || got.References != 1 {
		t.Fatal("first cleanup returned sibling's pool", got)
	}
	if err := b.Cleanup(); err != nil {
		t.Fatal(err)
	}
	if got := root.Snapshot(); got.Reservations != 0 || got.References != 0 {
		t.Fatal("real cleanup retained pool charge", got)
	}
	if err := b.Cleanup(); err != nil || pool.backingUsed != 0 || pool.flows != 0 {
		t.Fatal("duplicate cleanup changed accounting", err)
	}
}

func TestReceivePoolChargesBackingEvenWithoutCredit(t *testing.T) {
	pool, err := testReceivePool(t, 32, 16)
	if err != nil {
		t.Fatal("local pool may be smaller than signed credit cap", err)
	}
	flow, err := NewReceiveFlow(pool, 1, protocolv4.ClientToServer, 0, TerminalTuple{}, 16)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewReceiveFlow(pool, 3, protocolv4.ClientToServer, 0, TerminalTuple{}, 1); !errors.Is(err, resourcev4.ErrCapacity) {
		t.Fatal("zero promise made actual ring allocation free", err)
	}
	if err := flow.Grant(17); !errors.Is(err, ErrCredit) || pool.Outstanding() != 0 {
		t.Fatal("local physical cap exceeded", err)
	}
	if err := flow.releaseUnpublished(true); err != nil {
		t.Fatal(err)
	}
	replacement, err := NewReceiveFlow(pool, 3, protocolv4.ClientToServer, 16, TerminalTuple{}, 16)
	if err != nil {
		t.Fatal("real unpublished cleanup did not return capacity", err)
	}
	pool.Close()
	if err := replacement.Cleanup(); err != nil {
		t.Fatal(err)
	}
}

func TestReceivePoolRootCloseFencesNewCreditAndDelivery(t *testing.T) {
	root, ref := testReceiveReservation(t, 32, 2)
	pool, err := NewReceivePool(32, 32, 2, ref)
	if err != nil {
		t.Fatal(err)
	}
	flow, err := NewReceiveFlow(pool, 1, protocolv4.ClientToServer, 16, TerminalTuple{}, 16)
	if err != nil {
		t.Fatal(err)
	}
	wire := newFlowTransport(t)
	if err := wire.data(t, flow, 0, false, "queued"); err != nil {
		t.Fatal(err)
	}
	before := root.Snapshot().Charged
	root.Close()
	if err := flow.Grant(17); !errors.Is(err, resourcev4.ErrClosed) {
		t.Fatal("closed root granted more credit", err)
	}
	var dst [16]byte
	if n, terminal, err := flow.TryRead(dst[:]); n != 0 || terminal != protocolv4.V4ReadTerminalUnknown || !errors.Is(err, resourcev4.ErrClosed) {
		t.Fatal("closed root delivered queued bytes", n, terminal, err)
	}
	if root.Snapshot().Charged != before {
		t.Fatal("root close refunded live references")
	}
	pool.Close()
	flow.Abandon()
	if err := flow.Cleanup(); err != nil || !root.Snapshot().CleanupComplete {
		t.Fatal("actual cleanup incomplete", err)
	}
}
