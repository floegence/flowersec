package rpcv4

import (
	"errors"
	"math"
	"sync"
	"testing"
)

func TestOutgoingProtectionSharesKWithCallsAndPreservesShortAndIncoming(t *testing.T) {
	f := newNetworkFixture(t, "execution", 32)
	n := f.network
	n.config.ProtectShortCall = true
	before := f.root.Snapshot()
	var protected [30]OutgoingProtection
	if err := n.ProtectOutgoing(protected[:]); err != nil {
		t.Fatal(err)
	}
	for _, p := range protected {
		defer p.Close()
	}
	h := header(t, "execution_unary_request")
	path := Association{Channel: [16]byte{1}}
	ordinary, err := n.ReserveOutgoing(h, path)
	if err != nil {
		t.Fatal(err)
	}
	defer n.Release(ordinary)
	var extra [1]OutgoingProtection
	if err := n.ProtectOutgoing(extra[:]); !errors.Is(err, ErrCapacity) || extra[0] != (OutgoingProtection{}) {
		t.Fatal("future workload took the separate short opportunity", err)
	}
	if _, err := n.ReserveOutgoing(h, path); !errors.Is(err, ErrCapacity) {
		t.Fatal("ordinary call took protected capacity", err)
	}
	short, err := n.ReserveOutgoingShort(h, path)
	if err != nil {
		t.Fatal("workload consumed short floor", err)
	}
	defer n.Release(short)
	for i, p := range protected {
		request, association := h, path
		if i%2 == 0 {
			request = header(t, "execution_stream_request")
			association.Channel = [16]byte{byte(i + 2)}
		}
		ticket, err := p.Reserve(request, association, false)
		if err != nil {
			t.Fatal("general saturation stole an admitted position", i, err)
		}
		defer func() {
			if err := n.Release(ticket); err != nil {
				t.Error(err)
			}
			if err := p.ReleaseUse(ticket); err != nil {
				t.Error(err)
			}
		}()
	}
	if snapshot := n.Snapshot(); snapshot.OutgoingGeneral != 32 || snapshot.OutgoingProtected != 30 || snapshot.OutgoingProtectedInUse != 30 {
		t.Fatal("workload created a second K table", snapshot)
	}
	for i := range 32 {
		ticket, err := n.AcceptIncoming(h, Association{Channel: [16]byte{100}, Serial: uint64(i + 1)})
		if err != nil {
			t.Fatal("local workload reduced signed incoming K", err)
		}
		defer n.Release(ticket)
	}
	query := header(t, "query_contracts_request")
	for range 2 {
		ticket, err := n.ReserveOutgoing(query, Association{Channel: [16]byte{101}})
		if err != nil {
			t.Fatal("general workload consumed Q", err)
		}
		defer n.Release(ticket)
	}
	if after := f.root.Snapshot(); after != before {
		t.Fatal("future positions duplicated the admitted Network backing", before, after)
	}
}

func TestOutgoingProtectionRetainsCompletedUseUntilRealTailRelease(t *testing.T) {
	n := newNetworkFixture(t, "services", 2).network
	var protected [2]OutgoingProtection
	if err := n.ProtectOutgoing(protected[:]); err != nil {
		t.Fatal(err)
	}
	defer protected[1].Close()
	p := protected[0]
	h, path := header(t, "transient_unary_request"), Association{Channel: [16]byte{1}}
	first, err := p.Reserve(h, path, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.ReleaseUse(first); !errors.Is(err, ErrOwner) {
		t.Fatal("workload returned a still-live network use", err)
	}
	if err := n.BindOutgoing(first, 1); err != nil {
		t.Fatal(err)
	}
	if err := n.Abandon(first); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Reserve(h, path, true); !errors.Is(err, ErrCapacity) {
		t.Fatal("late call duplicated target", err)
	}
	if err := n.Release(first); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Reserve(h, path, true); !errors.Is(err, ErrCapacity) {
		t.Fatal("network completion refunded result/provider tails", err)
	}
	if _, err := n.ReserveOutgoingShort(h, path); !errors.Is(err, ErrCapacity) {
		t.Fatal("ordinary call borrowed outstanding workload tail", err)
	}
	if err := p.ReleaseUse(first); err != nil {
		t.Fatal(err)
	}
	second, err := p.Reserve(h, path, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.ReleaseUse(first); !errors.Is(err, ErrOwner) {
		t.Fatal("stale result tail refunded a newer use", err)
	}
	p.Close()
	if err := n.Release(second); err != nil {
		t.Fatal(err)
	}
	if _, err := n.ReserveOutgoing(h, path); !errors.Is(err, ErrCapacity) {
		t.Fatal("logical Close refunded the real workload tail", err)
	}
	if err := p.ReleaseUse(second); err != nil {
		t.Fatal(err)
	}
	var replacement [1]OutgoingProtection
	if err := n.ProtectOutgoing(replacement[:]); err != nil {
		t.Fatal(err)
	}
	defer replacement[0].Close()
	p.Close()
	if err := p.ReleaseUse(second); !errors.Is(err, ErrOwner) {
		t.Fatal("stale protection altered replacement", err)
	}
	if _, err := n.ReserveOutgoing(h, path); !errors.Is(err, ErrCapacity) {
		t.Fatal("stale Close released replacement", err)
	}
}

func TestOutgoingProtectionBatchIsAtomicAndClosesWithOriginalNetwork(t *testing.T) {
	n := newNetworkFixture(t, "services", 2).network
	n.slots[outgoing][0].protectionGeneration = math.MaxUint64
	var positions [2]OutgoingProtection
	before := n.Snapshot()
	if err := n.ProtectOutgoing(positions[:]); !errors.Is(err, ErrCapacity) || positions != ([2]OutgoingProtection{}) || n.Snapshot() != before {
		t.Fatal("failed batch retained partial positions", err, n.Snapshot())
	}
	if err := n.ProtectOutgoing(positions[:1]); err != nil {
		t.Fatal(err)
	}
	if err := n.ProtectOutgoing(positions[:]); !errors.Is(err, ErrOwner) {
		t.Fatal("nonempty output lost its original owner", err)
	}
	p := positions[0]
	h := header(t, "transient_unary_request")
	if _, err := p.Reserve(header(t, "query_contracts_request"), Association{Channel: [16]byte{1}}, false); !errors.Is(err, ErrMethod) {
		t.Fatal("protected general slot acquired Q authority", err)
	}
	ticket, err := p.Reserve(h, Association{Channel: [16]byte{1}}, false)
	if err != nil {
		t.Fatal(err)
	}
	n.Close()
	if n.Snapshot().CleanupComplete {
		t.Fatal("Close released a physical network tail")
	}
	if _, err := p.Reserve(h, Association{Channel: [16]byte{1}}, false); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
	if err := n.Release(ticket); err != nil || !n.Snapshot().CleanupComplete {
		t.Fatal("closed Network retained revoked capacity", err, n.Snapshot())
	}
	p.Close()
}

func TestOutgoingProtectionConcurrentCheckoutHasOneOwner(t *testing.T) {
	n := newNetworkFixture(t, "services", 2).network
	var positions [1]OutgoingProtection
	if err := n.ProtectOutgoing(positions[:]); err != nil {
		t.Fatal(err)
	}
	p := positions[0]
	defer p.Close()
	h := header(t, "transient_unary_request")
	var group sync.WaitGroup
	var tickets [16]Ticket
	var failures [16]error
	for i := range tickets {
		group.Go(func() { tickets[i], failures[i] = p.Reserve(h, Association{Channel: [16]byte{1}}, false) })
	}
	group.Wait()
	wins := 0
	for i, err := range failures {
		if err == nil {
			wins++
			if err := n.Release(tickets[i]); err != nil {
				t.Fatal(err)
			}
			if err := p.ReleaseUse(tickets[i]); err != nil {
				t.Fatal(err)
			}
		} else if !errors.Is(err, ErrCapacity) {
			t.Fatal(err)
		}
	}
	if wins != 1 {
		t.Fatal("concurrent work duplicated a declared position", wins)
	}
}
