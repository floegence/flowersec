package weaknet

import (
	"context"
	"errors"
	"net"
	"reflect"
	"sync"
	"testing"
	"time"
)

func TestPacketPumpUsesRealPacketConnsAndSchedulerOrder(t *testing.T) {
	expected := Counters{
		InputUnits: 3, InputBytes: 3,
		OutputUnits: 3, OutputBytes: 3,
		DroppedUnits: 1, DroppedBytes: 1, OrdinalLossUnits: 1,
		DelayUnits: 3, JitterUnits: 3, ReorderedUnits: 1,
		DuplicateUnits: 1, DuplicateBytes: 1, RateLimitedUnits: 2,
	}
	relay, err := NewUDPRelay(UDPProfile{
		Phase: "packet-pump", Direction: ClientToServer, Seed: 42,
		LossOrdinals: []uint64{2}, ReorderOrdinals: []uint64{1}, DuplicateOrdinals: []uint64{3},
		Delay: time.Millisecond, JitterScript: []time.Duration{time.Millisecond},
		Rate: RateLimit{BytesPerSecond: 1, BurstBytes: 1}, Expected: &expected,
	}, UDPOptions{})
	if err != nil {
		t.Fatal(err)
	}

	source := listenPacket(t)
	output := listenPacket(t)
	receiver := listenPacket(t)
	sender := listenPacket(t)
	clock := newInstantPumpClock()
	pump, err := NewPacketPump(source, output, receiver.LocalAddr(), relay, PumpOptions{Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- pump.Run(ctx) }()

	for _, payload := range [][]byte{{1}, {2}, {3}} {
		if _, err := sender.WriteTo(payload, source.LocalAddr()); err != nil {
			t.Fatal(err)
		}
	}
	if err := receiver.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var received []byte
	for range 3 {
		buffer := make([]byte, 8)
		n, _, err := receiver.ReadFrom(buffer)
		if err != nil {
			t.Fatal(err)
		}
		received = append(received, buffer[:n]...)
	}
	if !reflect.DeepEqual(received, []byte{3, 3, 1}) {
		t.Fatalf("packet delivery order = %v, want [3 3 1]", received)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run cancellation error = %v", err)
	}
	if err := relay.Verify(); err != nil {
		t.Fatalf("verify: %v; report=%+v", err, relay.Report())
	}
	if got := len(clock.Deadlines()); got != 3 {
		t.Fatalf("clock waits = %d, want 3", got)
	}
}

func TestPacketPumpPreservesResolvedTargetAcrossReorder(t *testing.T) {
	expected := Counters{InputUnits: 2, InputBytes: 2, OutputUnits: 2, OutputBytes: 2, ReorderedUnits: 1}
	relay, err := NewUDPRelay(UDPProfile{
		Phase: "resolved-target", Direction: ClientToServer, Seed: 42,
		ReorderOrdinals: []uint64{1}, Expected: &expected,
	}, UDPOptions{})
	if err != nil {
		t.Fatal(err)
	}
	source := listenPacket(t)
	output := listenPacket(t)
	firstReceiver := listenPacket(t)
	secondReceiver := listenPacket(t)
	firstSender := listenPacket(t)
	secondSender := listenPacket(t)
	targets := map[string]net.Addr{
		firstSender.LocalAddr().String():  firstReceiver.LocalAddr(),
		secondSender.LocalAddr().String(): secondReceiver.LocalAddr(),
	}
	pump, err := NewPacketPump(source, output, nil, relay, PumpOptions{
		Clock: newInstantPumpClock(),
		PacketTargetResolver: func(source net.Addr) (net.Addr, error) {
			return targets[source.String()], nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- pump.Run(ctx) }()
	if _, err := firstSender.WriteTo([]byte{1}, source.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	if _, err := secondSender.WriteTo([]byte{2}, source.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	assertPacketPayload(t, firstReceiver, 1)
	assertPacketPayload(t, secondReceiver, 2)
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run cancellation error = %v", err)
	}
	if err := relay.Verify(); err != nil {
		t.Fatal(err)
	}
}

func assertPacketPayload(t *testing.T, conn net.PacketConn, want byte) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 8)
	n, _, err := conn.ReadFrom(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 || buffer[0] != want {
		t.Fatalf("packet payload = %v, want [%d]", buffer[:n], want)
	}
}

func TestUDPQueueOverflowDropsAndPreservesConservation(t *testing.T) {
	expected := Counters{
		InputUnits: 2, InputBytes: 2,
		OutputUnits: 1, OutputBytes: 1,
		DroppedUnits: 1, DroppedBytes: 1,
		QueueOverflowUnits: 1, QueueOverflowBytes: 1,
	}
	relay, err := NewUDPRelay(UDPProfile{
		Phase: "queue-overflow", Direction: ClientToServer, Seed: 42,
		QueueUnits: 1, QueueBytes: 1, Expected: &expected,
	}, UDPOptions{})
	if err != nil {
		t.Fatal(err)
	}
	first, err := relay.Process(context.Background(), Datagram{Payload: []byte{1}})
	if err != nil || len(first) != 1 {
		t.Fatalf("first delivery = %+v, %v", first, err)
	}
	second, err := relay.Process(context.Background(), Datagram{Payload: []byte{2}})
	if err != nil {
		t.Fatal(err)
	}
	if len(second) != 0 {
		t.Fatalf("overflow delivery = %+v", second)
	}
	if err := relay.Acknowledge(0); !errors.Is(err, ErrInvalidAcknowledge) {
		t.Fatalf("partial acknowledgement error = %v, want ErrInvalidAcknowledge", err)
	}
	if err := relay.Acknowledge(len(first[0].Payload)); err != nil {
		t.Fatal(err)
	}
	if err := relay.Verify(); err != nil {
		t.Fatalf("verify: %v; report=%+v", err, relay.Report())
	}
}

func TestPacketPumpCloseUnblocksReadFrom(t *testing.T) {
	relay, err := NewUDPRelay(UDPProfile{
		Phase: "packet-close", Direction: ClientToServer, Seed: 42, Expected: &Counters{},
	}, UDPOptions{})
	if err != nil {
		t.Fatal(err)
	}
	source := listenPacket(t)
	output := listenPacket(t)
	receiver := listenPacket(t)
	pump, err := NewPacketPump(source, output, receiver.LocalAddr(), relay, PumpOptions{})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- pump.Run(context.Background()) }()
	if err := pump.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, ErrPumpClosed) {
			t.Fatalf("Run close error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("PacketPump.Close did not unblock ReadFrom")
	}
}

func TestUDPDiscardAccountsForUnacknowledgedDeliveries(t *testing.T) {
	relay, err := NewUDPRelay(UDPProfile{
		Phase: "packet-discard", Direction: ClientToServer, Seed: 42, Expected: &Counters{},
	}, UDPOptions{})
	if err != nil {
		t.Fatal(err)
	}
	deliveries, err := relay.Process(context.Background(), Datagram{Payload: []byte("pending")})
	if err != nil || len(deliveries) != 1 {
		t.Fatalf("Process() deliveries = %d error = %v", len(deliveries), err)
	}
	relay.discardPending()
	report := relay.Report().Actual
	if report.OutputUnits != 0 || report.OutputBytes != 0 || report.CanceledUnits != 1 || report.CanceledBytes != 7 {
		t.Fatalf("discarded delivery terminal accounting = %+v", report)
	}
	if err := report.CheckUDPConservation(); err != nil {
		t.Fatalf("discarded delivery conservation: %v", err)
	}
}

func TestPacketPumpRejectsBuffersThatCouldHideDatagramTruncation(t *testing.T) {
	relay, err := NewUDPRelay(UDPProfile{
		Phase: "packet-buffer", Direction: ClientToServer, Seed: 42, Expected: &Counters{},
	}, UDPOptions{})
	if err != nil {
		t.Fatal(err)
	}
	source := listenPacket(t)
	output := listenPacket(t)
	receiver := listenPacket(t)
	if _, err := NewPacketPump(source, output, receiver.LocalAddr(), relay, PumpOptions{ReadBufferBytes: 1024}); !errors.Is(err, ErrInvalidPump) {
		t.Fatalf("NewPacketPump buffer error = %v, want ErrInvalidPump", err)
	}
}

func listenPacket(t *testing.T) net.PacketConn {
	t.Helper()
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

type instantPumpClock struct {
	mu        sync.Mutex
	now       time.Time
	deadlines []time.Time
}

func newInstantPumpClock() *instantPumpClock {
	return &instantPumpClock{now: time.Unix(100, 0)}
}

func (clock *instantPumpClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.now
}

func (clock *instantPumpClock) WaitUntil(ctx context.Context, deadline time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	clock.mu.Lock()
	clock.deadlines = append(clock.deadlines, deadline)
	clock.mu.Unlock()
	return nil
}

func (clock *instantPumpClock) Deadlines() []time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return append([]time.Time(nil), clock.deadlines...)
}
