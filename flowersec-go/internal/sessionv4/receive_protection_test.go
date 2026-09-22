package sessionv4

import (
	"errors"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

func TestReceiveProtectionPreservesFutureCapacityAndOriginalReference(t *testing.T) {
	root, ref := testReceiveReservation(t, 32, 2)
	pool, err := NewReceivePool(32, 32, 2, ref)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	guard, err := pool.Protect(16, 16)
	if err != nil {
		t.Fatal(err)
	}
	ordinary, err := NewReceiveFlow(pool, 3, protocolv4.ServerToClient, 16, TerminalTuple{}, 16)
	if err != nil {
		t.Fatal(err)
	}
	before := root.Snapshot()
	if _, err := NewReceiveFlow(pool, 5, protocolv4.ServerToClient, 1, TerminalTuple{}, 1); err == nil {
		t.Fatal("ordinary flow borrowed the internal floor")
	}
	for i := range 3 {
		f, err := guard.newFlow(uint64(7+2*i), protocolv4.ServerToClient, 16, TerminalTuple{}, 16)
		if err != nil {
			t.Fatal("protected flow required a new reference", err)
		}
		if got := root.Snapshot(); got != before {
			t.Fatal("checkout reserved new ownership", before, got)
		}
		if _, err := guard.newFlow(25, protocolv4.ServerToClient, 16, TerminalTuple{}, 16); !errors.Is(err, resourcev4.ErrCapacity) {
			t.Fatal("two flows shared one protected position", err)
		}
		if err := f.releaseUnpublished(true); err != nil {
			t.Fatal(err)
		}
		if got := root.Snapshot(); got != before {
			t.Fatal("cleanup refunded the future floor", before, got)
		}
	}
	if err := ordinary.releaseUnpublished(true); err != nil {
		t.Fatal(err)
	}
	guard.Close()
	pool.Close()
	if got := root.Snapshot(); got.Reservations != 0 || got.References != 0 {
		t.Fatal(got)
	}
}

func TestReceiveProtectionRetainsCreditUntilPhysicalReadTail(t *testing.T) {
	pool, err := testReceivePool(t, 32, 48)
	if err != nil {
		t.Fatal(err)
	}
	guard, err := pool.Protect(16, 16)
	if err != nil {
		t.Fatal(err)
	}
	f, err := guard.newFlow(1, protocolv4.ClientToServer, 16, TerminalTuple{}, 16)
	if err != nil {
		t.Fatal(err)
	}
	ordinary, err := NewReceiveFlow(pool, 3, protocolv4.ClientToServer, 0, TerminalTuple{}, 32)
	if err != nil {
		t.Fatal(err)
	}
	pool.mu.Lock()
	f.hasTerminal, f.graceful = true, true
	f.readTails = 1
	// The terminal has returned unused wire credit, but the original read
	// still owns the ring and the internal channel's future opportunity.
	pool.used -= f.limit - f.released
	f.limit = f.released
	pool.mu.Unlock()
	if err := f.Cleanup(); !errors.Is(err, ErrReadInProgress) {
		t.Fatal(err)
	}
	if err := ordinary.Grant(17); !errors.Is(err, ErrCredit) {
		t.Fatal("tail lent future credit", err)
	}
	if err := ordinary.Grant(16); err != nil {
		t.Fatal(err)
	}
	if _, err := guard.newFlow(5, protocolv4.ClientToServer, 16, TerminalTuple{}, 16); !errors.Is(err, resourcev4.ErrCapacity) {
		t.Fatal(err)
	}
	pool.mu.Lock()
	f.readTails = 0
	pool.mu.Unlock()
	if err := f.Cleanup(); err != nil {
		t.Fatal(err)
	}
	second, err := guard.newFlow(5, protocolv4.ClientToServer, 16, TerminalTuple{}, 16)
	if err != nil {
		t.Fatal(err)
	}
	if err := second.releaseUnpublished(true); err != nil {
		t.Fatal(err)
	}
	if err := ordinary.releaseUnpublished(true); err != nil {
		t.Fatal(err)
	}
	guard.Close()
}

func TestReceiveProtectionCloseKeepsActualUseCharged(t *testing.T) {
	root, ref := testReceiveReservation(t, 16, 1)
	pool, err := NewReceivePool(16, 16, 1, ref)
	if err != nil {
		t.Fatal(err)
	}
	guard, err := pool.Protect(16, 16)
	if err != nil {
		t.Fatal(err)
	}
	f, err := guard.newFlow(1, protocolv4.ClientToServer, 16, TerminalTuple{}, 16)
	if err != nil {
		t.Fatal(err)
	}
	before := root.Snapshot().Charged
	pool.Close()
	guard.Close()
	if root.Snapshot().Charged != before {
		t.Fatal("close refunded the live flow")
	}
	if err := f.Cleanup(); err != nil {
		t.Fatal(err)
	}
	if got := root.Snapshot(); got.Reservations != 0 || got.References != 0 {
		t.Fatal(got)
	}
	if _, err := guard.newFlow(3, protocolv4.ClientToServer, 16, TerminalTuple{}, 16); !errors.Is(err, ErrFlowClosed) {
		t.Fatal(err)
	}
}
