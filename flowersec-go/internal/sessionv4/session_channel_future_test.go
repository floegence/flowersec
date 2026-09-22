package sessionv4

import (
	"errors"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

func futureChannelFixture(t *testing.T) (*executorFixture, *RPCServices) {
	t.Helper()
	f, p, c := rpcServicesPlanFixture(t)
	r, err := p.InstallRPCServices(c)
	if err != nil {
		t.Fatal(err)
	}
	charge, err := ReceivePoolCharge(c.Bootstrap.ReceivePoolBytes, 10)
	if err != nil {
		t.Fatal(err)
	}
	pool, err := NewReceivePool(c.Session.Limits().MaxCredit, c.Bootstrap.ReceivePoolBytes, 10, f.reserve(t, 1, charge))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err := r.prepareReceive(pool); err != nil {
		t.Fatal(err)
	}
	return f, r
}

func TestRPCServicesFutureChannelsUseOriginalBackingAtSaturatedRoot(t *testing.T) {
	f, r := futureChannelFixture(t)
	snapshot := f.root.Snapshot()
	var unused resourcev4.Vector
	for i := range unused {
		unused[i] = snapshot.Limit[i] - snapshot.Charged[i]
	}
	hold := f.reserve(t, 1, unused)
	var aliases []resourcev4.Reference
	defer func() {
		for _, alias := range aliases {
			alias.Release()
		}
	}()
	for {
		alias, err := hold.Borrow()
		if errors.Is(err, resourcev4.ErrCapacity) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		aliases = append(aliases, alias)
	}
	before := f.root.Snapshot()
	var allocations [9]*internalChannelAllocation
	defer func() {
		for _, allocation := range allocations {
			allocation.release()
		}
	}()
	for position := 1; position <= len(allocations); position++ {
		a, err := r.checkoutInternalChannel(position)
		if err != nil {
			t.Fatal("future needed new budget or a reference", position, err)
		}
		allocations[position-1] = a
		s := a.stream.reservation
		if s.SendQueue.Capacity < 16384 || s.InitialReceiveLimit != 16384 || s.ReceiveCapacity != 16384 {
			t.Fatal("future lost continuous channel service", position)
		}
		rx, err := s.ReceiveProtection.newFlow(uint64(2*position+1), protocolv4.ClientToServer, s.InitialReceiveLimit, TerminalTuple{}, s.ReceiveCapacity)
		if err != nil {
			t.Fatal("protected receive needed a new reference", position, err)
		}
		if err := rx.releaseUnpublished(true); err != nil {
			t.Fatal(err)
		}
		if position < 8 {
			for _, ref := range a.rpc {
				if err := ref.Check(); err != nil {
					t.Fatal("RPC future omitted reader or publisher", position, err)
				}
			}
		} else {
			if a.rpc != ([internalChannelRPCOwners]resourcev4.Reference{}) {
				t.Fatal("notification transport borrowed an RPC engine")
			}
			for _, ref := range a.notify {
				if err := ref.Check(); err != nil {
					t.Fatal("notification future omitted reader or publisher", position, err)
				}
			}
		}
		if after := f.root.Snapshot(); after != before {
			t.Fatal("future changed original quota", before, after)
		}
	}
	for position, allocation := range allocations {
		if _, err := r.checkoutInternalChannel(position + 1); !errors.Is(err, resourcev4.ErrCapacity) {
			t.Fatal("active position checked out twice", position, err)
		}
		allocation.release()
		allocations[position] = nil
		next, err := r.checkoutInternalChannel(position + 1)
		if err != nil {
			t.Fatal("fully returned original position was not reusable", err)
		}
		next.release()
	}
	if after := f.root.Snapshot(); after != before {
		t.Fatal("idle future backing was refunded", before, after)
	}
}

func TestRPCServicesFutureChannelRetainsActualAliasThroughClose(t *testing.T) {
	f, r := futureChannelFixture(t)
	a, err := r.checkoutInternalChannel(1)
	if err != nil {
		t.Fatal(err)
	}
	alias, err := a.stream.refs[streamFactoryQueue].Borrow()
	if err != nil {
		t.Fatal(err)
	}
	defer alias.Release()
	a.release()
	before := f.root.Snapshot()
	if _, err := r.checkoutInternalChannel(1); !errors.Is(err, resourcev4.ErrCapacity) {
		t.Fatal("future reused a live queue/provider alias", err)
	}
	if after := f.root.Snapshot(); after != before {
		t.Fatal("failed checkout partially consumed other owners")
	}
	r.Close()
	if err := alias.Check(); !errors.Is(err, resourcev4.ErrClosed) || r.futureChannels[0].owners[streamFactoryQueue].CleanupComplete() {
		t.Fatal("close refunded live queue backing", err)
	}
	alias.Release()
	if !r.futureChannels[0].owners[streamFactoryQueue].CleanupComplete() {
		t.Fatal("actual alias exit retained closed future")
	}
}
