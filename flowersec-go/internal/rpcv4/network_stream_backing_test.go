package rpcv4

import (
	"errors"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

func TestProtectedStreamBackingMovesOriginalAliasAtFullRoot(t *testing.T) {
	f := newNetworkFixture(t, "execution", 2)
	n := f.network
	var positions [1]OutgoingProtection
	if err := n.ProtectOutgoing(positions[:]); err != nil {
		t.Fatal(err)
	}
	p := positions[0]
	defer p.Close()
	if err := p.ProtectStreamBacking(); err != nil {
		t.Fatal(err)
	}
	var held []resourcev4.Reference
	defer func() {
		for _, ref := range held {
			ref.Release()
		}
	}()
	for {
		ref, err := n.reservation.Borrow()
		if errors.Is(err, resourcev4.ErrCapacity) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, ref)
	}
	for i := range 3 {
		ref, err := n.RetainProtectedStream(n.config.Session, held[0], p)
		if err != nil {
			t.Fatal("admitted stream needed a new root alias", i, err)
		}
		ticket, err := n.ReserveProtectedStream(p, header(t, "execution_stream_request"), Association{Channel: [16]byte{byte(i + 1)}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := n.RetainProtectedStream(n.config.Session, held[0], p); err == nil {
			t.Fatal("stream alias checked out twice")
		}
		if err := n.Release(ticket); err != nil {
			t.Fatal(err)
		}
		if err := p.ReleaseUse(ticket); !errors.Is(err, ErrOwner) {
			t.Fatal("network reset refunded a retained physical alias", err)
		}
		p.ReturnStreamBacking(ref)
		if err := ref.Check(); err == nil {
			t.Fatal("returned alias remained usable")
		}
		if err := p.ReleaseUse(ticket); err != nil {
			t.Fatal(err)
		}
	}
}

func TestProtectedStreamBackingCloseRetainsActualBorrow(t *testing.T) {
	for _, closeNetwork := range []bool{false, true} {
		t.Run(map[bool]string{false: "declaration", true: "network"}[closeNetwork], func(t *testing.T) {
			f := newNetworkFixture(t, "execution", 2)
			n := f.network
			var positions [1]OutgoingProtection
			if err := n.ProtectOutgoing(positions[:]); err != nil {
				t.Fatal(err)
			}
			p := positions[0]
			if err := p.ProtectStreamBacking(); err != nil {
				t.Fatal(err)
			}
			ref, err := n.RetainProtectedStream(n.config.Session, n.reservation, p)
			if err != nil {
				t.Fatal(err)
			}
			defer ref.Release()
			if closeNetwork {
				n.Close()
			} else {
				p.Close()
			}
			if closeNetwork {
				if snapshot := f.root.Snapshot(); snapshot.Charged[resourcev4.SDKBytes] < f.charge[resourcev4.SDKBytes] {
					t.Fatal("close refunded original physical borrow", snapshot)
				}
			} else if err := ref.Check(); err != nil {
				t.Fatal("declaration close erased original physical borrow", err)
			}
			p.ReturnStreamBacking(ref)
			p.Close()
			if err := ref.Check(); err == nil {
				t.Fatal("retired alias remained live")
			}
		})
	}
}
