package rpcv4

import (
	"errors"
	"testing"
)

func TestNetworkShortOpportunityUsesOriginalKAndNeverRestrictsIncoming(t *testing.T) {
	f := newNetworkFixture(t, "services", 32)
	n := f.network
	n.config.ProtectShortCall = true
	h := header(t, "transient_unary_request")
	var held []Ticket
	defer func() {
		for _, ticket := range held {
			_ = n.Release(ticket)
		}
	}()
	for range 31 {
		ticket, err := n.ReserveOutgoing(h, Association{Channel: [16]byte{1}})
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, ticket)
	}
	if _, err := n.ReserveOutgoing(h, Association{Channel: [16]byte{1}}); !errors.Is(err, ErrCapacity) {
		t.Fatal("resident consumed unused short opportunity", err)
	}
	short, err := n.ReserveOutgoingShort(h, Association{Channel: [16]byte{1}})
	if err != nil {
		t.Fatal(err)
	}
	held = append(held, short)
	if n.Snapshot().OutgoingGeneral != 32 {
		t.Fatal("short acquired separate network pool")
	}
	if _, err := n.ReserveOutgoingShort(h, Association{Channel: [16]byte{1}}); !errors.Is(err, ErrCapacity) {
		t.Fatal("short exceeded signed K", err)
	}
	for i := range 32 {
		ticket, err := n.AcceptIncoming(h, Association{Channel: [16]byte{1}, Serial: uint64(i + 1)})
		if err != nil {
			t.Fatal("local short floor narrowed peer K", i, err)
		}
		held = append(held, ticket)
	}
	if err := n.Release(short); err != nil {
		t.Fatal(err)
	}
	if _, err := n.ReserveOutgoing(h, Association{Channel: [16]byte{1}}); !errors.Is(err, ErrCapacity) {
		t.Fatal("short completion lent floor to resident", err)
	}
}
