package sessionv4

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
)

type flowTransport struct {
	writer   *RecordWriter
	receiver *RecordReceiver
	wire     bytes.Buffer
}

func newFlowTransport(t *testing.T) *flowTransport {
	t.Helper()
	c, s := ioEngine(t, protocolv4.ClientToServer), ioEngine(t, protocolv4.ServerToClient)
	transport := new(flowTransport)
	var err error
	transport.writer, err = NewRecordWriter(c, 1, &transport.wire)
	if err != nil {
		t.Fatal(err)
	}
	transport.receiver, err = newTestRecordReceiver(t, s, protocolv4.ClientToServer, 4096, 128, protocolv4.DecodeContext{Limits: map[string]uint64{"max_data_payload_bytes": 1024}})
	if err != nil {
		t.Fatal(err)
	}
	return transport
}
func (transport *flowTransport) data(t *testing.T, flow *ReceiveFlow, offset uint64, fin bool, value string) error {
	t.Helper()
	transport.wire.Reset()
	if _, err := transport.writer.WriteData(context.Background(), protocolv4.ClientToServer, offset, fin, []byte(value), 128); err != nil {
		t.Fatal(err)
	}
	received, err := transport.receiver.Read(context.Background(), bytes.NewReader(transport.wire.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	defer received.Release()
	frame, err := received.Body()
	if err != nil {
		t.Fatal(err)
	}
	return flow.ApplyData(frame)
}

func TestReceiveFlowCreditRingAndGracefulEOF(t *testing.T) {
	pool, err := testReceivePool(t, 16, 16)
	if err != nil {
		t.Fatal(err)
	}
	flow, err := NewReceiveFlow(pool, 1, protocolv4.ClientToServer, 8, TerminalTuple{}, 8)
	if err != nil {
		t.Fatal(err)
	}
	wire := newFlowTransport(t)
	if err = wire.data(t, flow, 0, false, "abcdef"); err != nil {
		t.Fatal(err)
	}
	if pool.Outstanding() != 8 {
		t.Fatal("receipt added a second promise charge")
	}
	var out [8]byte
	if n, terminal, err := flow.TryRead(out[:4]); n != 4 || terminal != protocolv4.V4ReadTerminalOpen || err != nil || string(out[:4]) != "abcd" {
		t.Fatal(n, terminal, err)
	}
	if pool.Outstanding() != 4 {
		t.Fatal("delivered bytes still charged")
	}
	if err = flow.Grant(12); err != nil {
		t.Fatal(err)
	}
	if err = wire.data(t, flow, 6, true, "ghij"); err != nil {
		t.Fatal(err)
	}
	if pool.Outstanding() != 6 {
		t.Fatal("FIN did not return only the unused tail")
	}
	proof, ok := flow.DrainProof()
	if !ok || proof.Aborted || proof.Terminal.Offset != 10 {
		t.Fatal("wire drain proof", proof, ok)
	}
	if err = flow.Cleanup(); !errors.Is(err, ErrCredit) {
		t.Fatal("unread graceful data released", err)
	}
	if n, terminal, err := flow.TryRead(out[:]); n != 6 || terminal != protocolv4.V4ReadTerminalEof || err != nil || string(out[:6]) != "efghij" {
		t.Fatal(n, terminal, err, string(out[:]))
	}
	if pool.Outstanding() != 0 {
		t.Fatal("promise leaked")
	}
	flow.Fence()
	if err = flow.Cleanup(); err != nil {
		t.Fatal(err)
	}
	pool.Close()
	if _, terminal, err := flow.TryRead(out[:]); terminal != protocolv4.V4ReadTerminalEof || err != nil {
		t.Fatal("cleanup/fence erased EOF fact", terminal, err)
	}
}

func TestReceiveFlowAbandonRetainsInFlightPromise(t *testing.T) {
	pool, _ := testReceivePool(t, 64, 64)
	flow, _ := NewReceiveFlow(pool, 1, protocolv4.ClientToServer, 64, TerminalTuple{}, 64)
	wire := newFlowTransport(t)
	if err := wire.data(t, flow, 0, false, "abc"); err != nil {
		t.Fatal(err)
	}
	flow.Abandon()
	if pool.Outstanding() != 61 {
		t.Fatal("Reset revoked unobserved promise")
	}
	terminal := TerminalTuple{NextSequence: 2, Offset: 6}
	if err := flow.ApplyStopped(terminal); err != nil {
		t.Fatal(err)
	}
	if pool.Outstanding() != 3 {
		t.Fatal("STOPPED tail accounting")
	}
	if _, ok := flow.DrainProof(); ok {
		t.Fatal("unseen DATA falsely drained")
	}
	if err := wire.data(t, flow, 3, true, "def"); err != nil {
		t.Fatal(err)
	}
	if pool.Outstanding() != 0 {
		t.Fatal("authenticated discard leaked credit")
	}
	var out [8]byte
	if n, state, err := flow.TryRead(out[:]); n != 0 || state != protocolv4.V4ReadTerminalAbandoned || !errors.Is(err, ErrAbandoned) {
		t.Fatal("late FIN revived delivery", n, state, err)
	}
	proof, ok := flow.DrainProof()
	if !ok || proof.Aborted || proof.Observed != terminal {
		t.Fatal(proof, ok)
	}
	if err := flow.AdvanceEpoch(1); err != nil {
		t.Fatal(err)
	}
	proof, _ = flow.DrainProof()
	if proof.Terminal != terminal {
		t.Fatal("terminal tuple changed with rekey")
	}
	if err := flow.ApplyStopped(TerminalTuple{Epoch: 1, NextSequence: 0, Offset: 6}); !errors.Is(err, ErrTerminal) {
		t.Fatal("conflicting terminal accepted", err)
	}
}

func TestReceiveFlowFencedAbortDoesNotInventACK(t *testing.T) {
	pool, _ := testReceivePool(t, 64, 64)
	flow, _ := NewReceiveFlow(pool, 1, protocolv4.ClientToServer, 64, TerminalTuple{}, 64)
	wire := newFlowTransport(t)
	if err := wire.data(t, flow, 0, false, "abc"); err != nil {
		t.Fatal(err)
	}
	if err := flow.ApplyStopped(TerminalTuple{NextSequence: 2, Offset: 6}); err != nil {
		t.Fatal(err)
	}
	flow.Fence()
	proof, ok := flow.DrainProof()
	if !ok || !proof.Aborted || proof.Observed.Offset != 3 || proof.Observed.NextSequence != 1 {
		t.Fatal(proof, ok)
	}
	if pool.Outstanding() != 0 {
		t.Fatal("fenced promise not revoked")
	}
	if _, ok = flow.DrainProof(); !ok || pool.Outstanding() != 0 {
		t.Fatal("proof was not idempotent")
	}
	if err := wire.data(t, flow, 3, false, "def"); !errors.Is(err, ErrFlowClosed) {
		t.Fatal("fenced receive revived", err)
	}
	if err := flow.Cleanup(); err != nil {
		t.Fatal(err)
	}
}

func TestReceiveFlowLateTerminalUsesOnlyEstablishedEpochFrontiers(t *testing.T) {
	for _, test := range []struct {
		name     string
		terminal TerminalTuple
		valid    bool
	}{
		{"last_record", TerminalTuple{NextSequence: 1, Offset: 3}, true},
		{"installed_empty_epoch", TerminalTuple{Epoch: 1, Offset: 3}, true},
		{"invented_old_sequence", TerminalTuple{NextSequence: 2, Offset: 3}, false},
		{"invented_old_bytes", TerminalTuple{NextSequence: 1, Offset: 4}, false},
		{"erased_old_record", TerminalTuple{Offset: 3}, false},
		{"invented_empty_epoch_record", TerminalTuple{Epoch: 1, NextSequence: 1, Offset: 3}, false},
		{"unknown_future_epoch", TerminalTuple{Epoch: 3, Offset: 3}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			pool, _ := testReceivePool(t, 64, 64)
			flow, _ := NewReceiveFlow(pool, 1, protocolv4.ClientToServer, 64, TerminalTuple{}, 64)
			if err := newFlowTransport(t).data(t, flow, 0, false, "abc"); err != nil {
				t.Fatal(err)
			}
			for _, epoch := range []uint32{1, 2} {
				if err := flow.AdvanceEpoch(epoch); err != nil {
					t.Fatal(err)
				}
			}
			err := flow.ApplyStopped(test.terminal)
			if test.valid {
				proof, ok := flow.DrainProof()
				if err != nil || !ok || proof.Aborted || proof.Terminal != test.terminal || proof.Observed != test.terminal || pool.Outstanding() != 0 {
					t.Fatal("original late terminal not settled", err, proof, ok)
				}
			} else {
				observed, _, _, _ := flow.Snapshot()
				if !errors.Is(err, ErrTerminal) || observed != (TerminalTuple{Epoch: 2, Offset: 3}) || pool.Outstanding() != 64 {
					t.Fatal("invalid terminal changed original frontier or charge", err, observed)
				}
			}
		})
	}
}

func TestReceiveFlowAtomicAggregateCredit(t *testing.T) {
	pool, _ := testReceivePool(t, 16, 32)
	a, _ := NewReceiveFlow(pool, 1, protocolv4.ClientToServer, 0, TerminalTuple{}, 16)
	b, _ := NewReceiveFlow(pool, 3, protocolv4.ClientToServer, 0, TerminalTuple{}, 16)
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, flow := range []*ReceiveFlow{a, b} {
		wg.Add(1)
		go func() { defer wg.Done(); results <- flow.Grant(16) }()
	}
	wg.Wait()
	close(results)
	winners := 0
	for err := range results {
		if err == nil {
			winners++
		} else if !errors.Is(err, ErrCredit) {
			t.Fatal(err)
		}
	}
	if winners != 1 || pool.Outstanding() != 16 {
		t.Fatal("aggregate oversubscription", winners, pool.Outstanding())
	}
}
