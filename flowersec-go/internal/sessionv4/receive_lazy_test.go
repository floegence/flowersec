package sessionv4

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

func TestReceiveFlowLazyRingKeepsFullBackingAndCreditReservation(t *testing.T) {
	root, ref := testReceiveReservation(t, 32, 2)
	pool, err := NewReceivePool(32, 32, 2, ref)
	if err != nil {
		t.Fatal(err)
	}
	flow, err := NewReceiveFlow(pool, 1, protocolv4.ClientToServer, 0, TerminalTuple{}, 32)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		flow.Abandon()
		pool.Close()
		if err := flow.Cleanup(); err != nil {
			t.Error(err)
		}
	})
	before := root.Snapshot()
	if flow.storage != nil || pool.backingUsed != 32 || pool.flows != 1 || pool.Outstanding() != 0 {
		t.Fatal("unused receive flow allocated a ring or lost its declared reservation")
	}
	if err := flow.Grant(32); err != nil || flow.storage != nil {
		t.Fatal("grant required eager storage", err)
	}
	if err := flow.Grant(33); !errors.Is(err, ErrCredit) {
		t.Fatal("lazy ring increased declared credit capacity", err)
	}
	if _, err := NewReceiveFlow(pool, 3, protocolv4.ClientToServer, 0, TerminalTuple{}, 1); !errors.Is(err, resourcev4.ErrCapacity) {
		t.Fatal("unused ring donated its full backing reservation", err)
	}
	var out [32]byte
	if n, terminal, err := flow.TryRead(out[:]); n != 0 || terminal != protocolv4.V4ReadTerminalOpen || err != nil || flow.storage != nil {
		t.Fatal("empty read allocated or changed the lazy flow", n, terminal, err)
	}
	wire := newFlowTransport(t)
	if err := wire.data(t, flow, 0, false, ""); err != nil || flow.storage != nil {
		t.Fatal("empty DATA allocated a payload ring", err)
	}
	body := string(bytes.Repeat([]byte{'x'}, 32))
	if err := wire.data(t, flow, 0, false, body); err != nil || len(flow.storage) != 32 || root.Snapshot() != before {
		t.Fatal("first DATA changed full backing admission", err)
	}
	storage := flow.storage
	if n, terminal, err := flow.TryRead(out[:]); n != 32 || terminal != protocolv4.V4ReadTerminalOpen || err != nil || string(out[:]) != body {
		t.Fatal("first lazy ring lost original payload", n, terminal, err)
	}
	if flow.storage != nil || !bytes.Equal(storage, make([]byte, len(storage))) || flow.capacity != 32 || pool.backingUsed != 32 || pool.flows != 1 || root.Snapshot() != before {
		t.Fatal("empty ring retained physical bytes or returned its original backing charge")
	}
	if err := flow.Grant(64); err != nil {
		t.Fatal(err)
	}
	if err := wire.data(t, flow, 32, true, "tail"); err != nil || len(flow.storage) != 32 || flow.capacity != 32 || root.Snapshot() != before {
		t.Fatal("later DATA lost the original full ring allowance", err)
	}
	if n, terminal, err := flow.TryRead(out[:]); n != 4 || terminal != protocolv4.V4ReadTerminalEof || err != nil || string(out[:n]) != "tail" {
		t.Fatal("lazy ring lost FIN or unread data", n, terminal, err)
	}
	if flow.storage != nil || root.Snapshot() != before {
		t.Fatal("EOF retained an empty physical ring or refunded the live owner")
	}
	if err := flow.Cleanup(); err != nil || pool.backingUsed != 0 || pool.flows != 0 || flow.storage != nil {
		t.Fatal("cleanup did not return the complete declared ring", err)
	}
}

func TestReceiveFlowLazyRingCleanupWithoutPayload(t *testing.T) {
	for _, mode := range []string{"credit_refusal", "empty_fin", "abandoned_discard", "pool_close"} {
		t.Run(mode, func(t *testing.T) {
			root, ref := testReceiveReservation(t, 16, 1)
			pool, err := NewReceivePool(16, 16, 1, ref)
			if err != nil {
				t.Fatal(err)
			}
			initial := uint64(16)
			if mode == "credit_refusal" {
				initial = 0
			}
			flow, err := NewReceiveFlow(pool, 1, protocolv4.ClientToServer, initial, TerminalTuple{}, 16)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				flow.Abandon()
				pool.Close()
				if err := flow.Cleanup(); err != nil {
					t.Error(err)
				}
			})
			before := root.Snapshot().Charged
			wire := newFlowTransport(t)
			switch mode {
			case "credit_refusal":
				if err := wire.data(t, flow, 0, false, "x"); !errors.Is(err, ErrCredit) {
					t.Fatal("unpromised DATA allocated credit", err)
				}
				pool.Close()
			case "empty_fin":
				if err := wire.data(t, flow, 0, true, ""); err != nil {
					t.Fatal(err)
				}
			case "abandoned_discard":
				flow.Abandon()
				if err := wire.data(t, flow, 0, true, "discard"); err != nil {
					t.Fatal(err)
				}
			case "pool_close":
				pool.Close()
				if err := wire.data(t, flow, 0, false, "x"); !errors.Is(err, ErrFlowClosed) {
					t.Fatal("closed pool accepted DATA", err)
				}
			}
			if flow.storage != nil || pool.backingUsed != 16 || root.Snapshot().Charged != before {
				t.Fatal("payload-free termination allocated storage or refunded its live owner")
			}
			if err := flow.Cleanup(); err != nil || pool.backingUsed != 0 || pool.flows != 0 {
				t.Fatal("unused ring retained its declared backing", err)
			}
			pool.Close()
			if got := root.Snapshot(); got.Reservations != 0 || got.References != 0 {
				t.Fatal("unused receive direction retained original resources", got)
			}
		})
	}
}

func TestNativeAssemblyAllocatesOnlyTheOriginalRingOnFirstBody(t *testing.T) {
	f := newNativeAssemblyFixture(t, 512)
	flow, assembly := f.flows[0], f.assemblies[0]
	before := f.root.Snapshot()
	if flow.storage != nil || f.flows[1].storage != nil || f.pool.backingUsed != 1024 {
		t.Fatal("native assembly eagerly allocated an unread ring or lost its reservation")
	}
	body := bytes.Repeat([]byte{'n'}, 512)
	wire := f.data(t, 0, 0, false, body)
	if err := assembly.Read(context.Background(), bytes.NewReader(wire)); err != nil {
		t.Fatal(err)
	}
	if len(flow.storage) != 512 || f.flows[1].storage != nil || f.root.Snapshot() != before {
		t.Fatal("native input acquired backing outside its original flow")
	}
	storage := flow.storage
	var out [512]byte
	if n, terminal, err := flow.TryRead(out[:]); n != 0 || terminal != protocolv4.V4ReadTerminalOpen || err != nil {
		t.Fatal("unverified native ring bytes became readable", n, terminal, err)
	}
	if err := assembly.Authenticate(context.Background(), f.receiver); err != nil {
		t.Fatal(err)
	}
	if len(flow.storage) != 512 || &flow.storage[0] != &storage[0] {
		t.Fatal("native authentication replaced the ring between ciphertext and plaintext transfer")
	}
	if n, terminal, err := flow.TryRead(out[:]); n != len(body) || terminal != protocolv4.V4ReadTerminalOpen || err != nil || !bytes.Equal(out[:n], body) {
		t.Fatal("native authentication lost the original lazy ring", n, terminal, err)
	}
	if flow.storage != nil || !bytes.Equal(storage, make([]byte, len(storage))) || flow.capacity != 512 || f.pool.backingUsed != 1024 || f.root.Snapshot() != before {
		t.Fatal("native read retained an empty ring or returned its original backing charge")
	}
}

func TestReceiveFlowEmptyRingKeepsHeadAndFullCapacityAcrossFragments(t *testing.T) {
	for _, fragmented := range []bool{false, true} {
		t.Run(map[bool]string{false: "single", true: "fragmented"}[fragmented], func(t *testing.T) {
			root, ref := testReceiveReservation(t, 64, 1)
			pool, err := NewReceivePool(64, 64, 1, ref)
			if err != nil {
				t.Fatal(err)
			}
			flow, err := NewReceiveFlow(pool, 1, protocolv4.ClientToServer, 64, TerminalTuple{}, 64)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				flow.Abandon()
				pool.Close()
				if err := flow.Cleanup(); err != nil {
					t.Error(err)
				}
			})
			before := root.Snapshot()
			wire := newFlowTransport(t)
			if err := wire.data(t, flow, 0, false, string(bytes.Repeat([]byte{'a'}, 60))); err != nil {
				t.Fatal(err)
			}
			var out [64]byte
			if n, _, err := flow.TryRead(out[:]); n != 60 || err != nil || flow.head != 60 || flow.storage != nil {
				t.Fatal("empty ring rewound the original nonzero head", n, err)
			}
			if err := flow.Grant(124); err != nil {
				t.Fatal(err)
			}
			if err := flow.Grant(125); !errors.Is(err, ErrCredit) {
				t.Fatal("empty ring widened the original full credit", err)
			}
			body := bytes.Repeat([]byte("01234567"), 8)
			pieces := []int{64}
			if fragmented {
				pieces = []int{1, 3, 7, 53}
			}
			offset := 0
			for _, length := range pieces {
				if err := wire.data(t, flow, uint64(60+offset), false, string(body[offset:offset+length])); err != nil {
					t.Fatal(err)
				}
				offset += length
			}
			if len(flow.storage) != 64 || flow.size != 64 || flow.head != 60 || pool.Outstanding() != 64 || root.Snapshot() != before {
				t.Fatal("recreated ring lost its full original wrap or reservation")
			}
			storage := flow.storage
			if n, _, err := flow.TryRead(out[:3]); n != 3 || err != nil || !bytes.Equal(out[:3], body[:3]) || len(flow.storage) != 64 || &flow.storage[0] != &storage[0] {
				t.Fatal("partial read retired unread wrapped bytes", n, err)
			}
			if n, _, err := flow.TryRead(out[:]); n != 61 || err != nil || !bytes.Equal(out[:n], body[3:]) || flow.head != 60 || flow.storage != nil || pool.Outstanding() != 0 {
				t.Fatal("wrapped full read lost original data or credit", n, err)
			}
			if err := wire.data(t, flow, 124, false, ""); err != nil || flow.storage != nil || flow.head != 60 {
				t.Fatal("empty DATA allocated or rewound the original ring", err)
			}
			if err := wire.data(t, flow, 124, true, ""); err != nil {
				t.Fatal(err)
			}
			if n, terminal, err := flow.TryRead(out[:]); n != 0 || terminal != protocolv4.V4ReadTerminalEof || err != nil || flow.storage != nil || flow.capacity != 64 || pool.backingUsed != 64 || root.Snapshot() != before {
				t.Fatal("empty FIN lost EOF or released the original backing owner", n, terminal, err)
			}
		})
	}
}

func TestReceiveFlowEmptyRingDropPreservesUnreceivedPromiseAndDelivery(t *testing.T) {
	for _, abandon := range []bool{false, true} {
		t.Run(map[bool]string{false: "conn_drain", true: "abandon"}[abandon], func(t *testing.T) {
			root, ref := testReceiveReservation(t, 16, 1)
			pool, err := NewReceivePool(16, 16, 1, ref)
			if err != nil {
				t.Fatal(err)
			}
			flow, err := NewReceiveFlow(pool, 1, protocolv4.ClientToServer, 16, TerminalTuple{}, 16)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				flow.Abandon()
				pool.Close()
				if err := flow.Cleanup(); err != nil {
					t.Error(err)
				}
			})
			before := root.Snapshot()
			wire := newFlowTransport(t)
			if err := wire.data(t, flow, 0, false, "abc"); err != nil {
				t.Fatal(err)
			}
			storage := flow.storage
			if abandon {
				flow.Abandon()
			} else if !flow.drainConnBuffered() {
				t.Fatal("original closing owner could not drain its authenticated queue")
			}
			if flow.storage != nil || !bytes.Equal(storage, make([]byte, len(storage))) || flow.released != 3 || flow.delivered != 0 || pool.Outstanding() != 13 || flow.capacity != 16 || pool.backingUsed != 16 || root.Snapshot() != before {
				t.Fatal("discarded bytes became delivered progress or revoked the unreceived promise")
			}
			if err := wire.data(t, flow, 3, true, "tail"); err != nil {
				t.Fatal(err)
			}
			var out [8]byte
			n, terminal, err := flow.TryRead(out[:])
			if abandon {
				if n != 0 || terminal != protocolv4.V4ReadTerminalAbandoned || !errors.Is(err, ErrAbandoned) || flow.delivered != 0 {
					t.Fatal("authenticated late tail revived abandoned delivery", n, terminal, err)
				}
			} else if n != 4 || terminal != protocolv4.V4ReadTerminalEof || err != nil || string(out[:n]) != "tail" || flow.delivered != 4 {
				t.Fatal("closing-owner discard erased a later original tail", n, terminal, err)
			}
			if flow.storage != nil || flow.released != 7 || pool.Outstanding() != 0 || flow.capacity != 16 || pool.backingUsed != 16 || root.Snapshot() != before {
				t.Fatal("final original tail retained an empty ring or refunded the live owner")
			}
		})
	}
}
