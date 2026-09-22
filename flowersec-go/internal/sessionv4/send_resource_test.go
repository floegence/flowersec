package sessionv4

import (
	"context"
	"errors"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

func TestSendFlowCapacityRejectedBeforeReservationTransfer(t *testing.T) {
	root, ref := testSendReservation(t, 64)
	wire := newFlowTransport(t)
	required, err := protocolv4.StreamDataPlaintextSize(wire.writer.scope, protocolv4.ClientToServer, 64)
	if err != nil {
		t.Fatal(err)
	}
	before := root.Snapshot().Charged
	if _, err := NewSendFlow(wire.writer, protocolv4.ClientToServer, 64, TerminalTuple{}, 64, required-1, ref); !errors.Is(err, cryptov4.ErrConfiguration) {
		t.Fatal("future DATA widths exceeded admitted codec capacity", err)
	}
	if _, err := NewSendFlow(wire.writer, protocolv4.ClientToServer, 64, TerminalTuple{}, 64, int(wire.writer.engine.MaxFrame()), ref); err == nil {
		t.Fatal("record header/tag omitted from frame admission")
	}
	if err := ref.Check(); err != nil || root.Snapshot().Charged != before || wire.wire.Len() != 0 {
		t.Fatal("configuration failure consumed original owner or ticket", err)
	}
	flow, err := NewSendFlow(wire.writer, protocolv4.ClientToServer, 64, TerminalTuple{}, 64, required, ref)
	if err != nil {
		t.Fatal("exact maximum capacity refused", err)
	}
	defer func() { flow.Stop(); _ = flow.retire() }()
	if result, err := flow.Write(context.Background(), make([]byte, 64), true); err != nil || !result.Complete {
		t.Fatal("admitted DATA failed publication", result, err)
	}
}

func testSendReservation(t *testing.T, capacity uint64) (*resourcev4.Root, resourcev4.Reference) {
	t.Helper()
	charge, err := SendFlowCharge(capacity)
	if err != nil {
		t.Fatal(err)
	}
	return testResourceReservation(t, charge, 1)
}

func testSendFlow(t *testing.T, writer *RecordWriter, direction protocolv4.Direction, peerLimit uint64, frontier TerminalTuple, capacity uint64, maxPlaintext int) (*SendFlow, error) {
	t.Helper()
	_, ref := testSendReservation(t, capacity)
	flow, err := NewSendFlow(writer, direction, peerLimit, frontier, capacity, maxPlaintext, ref)
	if err == nil {
		t.Cleanup(func() { flow.Stop(); _ = flow.retire() })
	}
	return flow, err
}

func TestSendFlowRequiresUniqueReservationAndFencesRootClosure(t *testing.T) {
	root, ref := testSendReservation(t, 64)
	wire := newFlowTransport(t)
	if _, err := NewSendFlow(wire.writer, protocolv4.ClientToServer, 64, TerminalTuple{}, 64, 128, resourcev4.Reference{}); !errors.Is(err, resourcev4.ErrOwner) {
		t.Fatal("unreserved send buffer allocated", err)
	}
	flow, err := NewSendFlow(wire.writer, protocolv4.ClientToServer, 64, TerminalTuple{}, 64, 128, ref)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { flow.Stop(); _ = flow.retire() }()
	ref.Release()
	if _, err := ref.Take(resourcev4.Vector{}); !errors.Is(err, resourcev4.ErrOwner) || root.Snapshot().Reservations != 1 {
		t.Fatal("original reservation remained reusable", err)
	}
	root.Close()
	result, err := flow.Write(context.Background(), []byte("private"), false)
	if !errors.Is(err, resourcev4.ErrClosed) || result.Submitted || wire.wire.Len() != 0 {
		t.Fatal("root closure allowed new send ticket", result, err)
	}
	if root.Snapshot().CleanupComplete {
		t.Fatal("root closure refunded still-owned backing")
	}
	flow.Stop()
	if err := flow.WaitCleanup(context.Background()); err != nil {
		t.Fatal("unused send owner not cleaned", err)
	}
	if err := flow.retire(); err != nil || !root.Snapshot().CleanupComplete {
		t.Fatal("unused original direction owner not retired", err)
	}
}

func TestSendFlowCloseRetainsActualProviderTailCharge(t *testing.T) {
	root, ref := testSendReservation(t, 64)
	engine := ioEngine(t, protocolv4.ClientToServer)
	provider := &blockedWriter{make(chan struct{}), make(chan struct{})}
	writer, err := NewRecordWriter(engine, 1, provider)
	if err != nil {
		t.Fatal(err)
	}
	flow, err := NewSendFlow(writer, protocolv4.ClientToServer, 64, TerminalTuple{}, 64, 128, ref)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		_, _ = flow.Write(context.Background(), []byte("actual provider still owns this write"), false)
		close(done)
	}()
	<-provider.entered
	before := root.Snapshot().Charged
	flow.Stop()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := flow.WaitCleanup(ctx); !errors.Is(err, context.Canceled) || root.Snapshot().Charged != before {
		t.Fatal("cancelled waiter refunded provider tail", err)
	}
	close(provider.finish)
	<-done
	if err := flow.WaitCleanup(context.Background()); err != nil || root.Snapshot().Reservations != 1 {
		t.Fatal("DATA cleanup erased still-retained Stream metadata charge", err)
	}
	if len(flow.storage) != 0 {
		t.Fatal("cleaned owner retained private send buffer")
	}
	if err := flow.retire(); err != nil || root.Snapshot().Reservations != 0 {
		t.Fatal("original owner retirement failed to return backing", err)
	}
}

func TestSendFlowUsesOneCleanupSignalAcrossWrites(t *testing.T) {
	wire := newFlowTransport(t)
	flow, err := testSendFlow(t, wire.writer, protocolv4.ClientToServer, 64, TerminalTuple{}, 64, 128)
	if err != nil {
		t.Fatal(err)
	}
	original := flow.idle
	for i := range 4 {
		if result, err := flow.Write(context.Background(), []byte{byte(i)}, i == 3); err != nil || !result.Complete {
			t.Fatal(result, err)
		}
		if flow.idle != original {
			t.Fatal("write allocated replacement cleanup notification")
		}
	}
	if err := flow.WaitCleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
}
