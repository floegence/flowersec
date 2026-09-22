package sessionv4

import (
	"bytes"
	"context"
	"errors"
	"io"
	"runtime"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
)

// The peer can consume these bytes while the original local provider call
// still owns its input and return tail.
type publishedQueueWriter struct {
	bytes.Buffer
	entered, release chan struct{}
}

func (w *publishedQueueWriter) Write(p []byte) (int, error) {
	n, err := w.Buffer.Write(p)
	close(w.entered)
	<-w.release
	return n, err
}

func TestSendQueueFINAndAuthenticatedFinishPrecedeProviderReturn(t *testing.T) {
	provider := &publishedQueueWriter{entered: make(chan struct{}), release: make(chan struct{})}
	q, send, root := sendQueueFixture(t, 4, 4, 4, 2, provider)
	if n, err := q.Write(context.Background(), []byte("data")); n != 4 || err != nil {
		t.Fatal(n, err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := q.CloseWrite(canceled); !errors.Is(err, context.Canceled) {
		t.Fatal("unsubmitted FIN did not preserve wait cancellation", err)
	}
	if n, err := q.Write(context.Background(), []byte("x")); n != 0 || !errors.Is(err, ErrFlowClosed) {
		t.Fatal("cancelled CloseWrite reopened acceptance", n, err)
	}
	pump := make(chan error, 1)
	go func() { _, _, err := q.Pump(context.Background()); pump <- err }()
	<-provider.entered
	if err := q.CloseWrite(canceled); err != nil {
		t.Fatal("FIN ticket incorrectly waited for provider return", err)
	}
	if err := q.Finish(canceled); !errors.Is(err, context.Canceled) {
		t.Fatal("local FIN ticket invented authenticated drain", err)
	}
	if err := q.retire(); !errors.Is(err, cryptov4.ErrCapacity) {
		t.Fatal("live provider/observation retired", err)
	}
	status := q.SendStatus()
	if status.AcceptedBytes != 4 || !status.FINSubmitted || status.PeerAuthenticatedBytes != 0 || status.SendDrained {
		t.Fatal(status)
	}

	server := ioEngine(t, protocolv4.ServerToClient)
	peerWriter, _ := NewRecordWriter(server, 1, io.Discard)
	peerSend, err := testSendFlow(t, peerWriter, protocolv4.ServerToClient, 4, TerminalTuple{}, 4, 128)
	if err != nil {
		t.Fatal(err)
	}
	peerPool, _ := testReceivePool(t, 4, 4)
	peerReceive, _ := NewReceiveFlow(peerPool, 1, protocolv4.ClientToServer, 4, TerminalTuple{}, 4)
	peerStream, err := NewStreamFlow(peerSend, peerReceive)
	if err != nil {
		t.Fatal(err)
	}
	localPool, _ := testReceivePool(t, 4, 4)
	localReceive, _ := NewReceiveFlow(localPool, 1, protocolv4.ServerToClient, 4, TerminalTuple{}, 4)
	localStream, err := NewStreamFlow(send, localReceive)
	if err != nil {
		t.Fatal(err)
	}
	bounds := protocolv4.DecodeContext{Limits: map[string]uint64{"max_data_payload_bytes": 4}}
	peerReader, err := newTestRecordReceiver(t, server, protocolv4.ClientToServer, 4096, 128, bounds)
	if err != nil {
		t.Fatal(err)
	}
	localReader, err := newTestRecordReceiver(t, send.writer.engine, protocolv4.ServerToClient, 4096, 128, bounds)
	if err != nil {
		t.Fatal(err)
	}
	deliver := func(wire []byte, reader *RecordReceiver, stream *StreamFlow) {
		t.Helper()
		record, err := reader.Read(context.Background(), bytes.NewReader(wire))
		if err != nil {
			t.Fatal(err)
		}
		defer record.Release()
		if err := stream.Apply(record); err != nil {
			t.Fatal(err)
		}
	}
	deliver(provider.Bytes(), peerReader, peerStream)
	var proof [256]byte
	encoded, err := peerStream.EncodeDrained(proof[:])
	if err != nil {
		t.Fatal(err)
	}
	var controlWire bytes.Buffer
	control, _ := NewRecordWriter(server, 0, &controlWire)
	if _, err := control.Write(context.Background(), protocolv4.FrameStreamAck, encoded); err != nil {
		t.Fatal(err)
	}
	deliver(controlWire.Bytes(), localReader, localStream)
	if err := q.Finish(canceled); err != nil {
		t.Fatal("authenticated drain waited for unrelated local return tail", err)
	}
	status = q.SendStatus()
	if status.PeerAuthenticatedBytes != 4 || !status.SendDrained || status.FirstError != nil {
		t.Fatal(status)
	}
	result := localStream.CloseResult()
	if result.ReadTerminal != protocolv4.V4ReadTerminalOpen || !result.SendDrained {
		t.Fatal("Finish changed reverse read ownership", result)
	}
	if err := q.WaitCleanup(canceled); !errors.Is(err, context.Canceled) || root.Snapshot().Reservations != 2 {
		t.Fatal("peer drain refunded actual provider tail", err)
	}
	close(provider.release)
	if err := <-pump; err != nil {
		t.Fatal(err)
	}
	q.Stop(nil)
	if err := q.retire(); err != nil {
		t.Fatal(err)
	}
	if err := q.CloseWrite(canceled); err != nil {
		t.Fatal("retirement erased committed FIN", err)
	}
	if err := q.Finish(canceled); err != nil || q.SendStatus() != status {
		t.Fatal("retirement erased successful original Finish", err, q.SendStatus())
	}
	if q.flow != nil || len(q.slots) != 0 || len(q.storage) != 0 {
		t.Fatal("retired observations retained I/O graph or wait slab")
	}
}

func TestSendQueueFINSubmissionSurvivesProviderFailure(t *testing.T) {
	provider := &blockedWriter{make(chan struct{}), make(chan struct{})}
	q, _, _ := sendQueueFixture(t, 4, 4, 4, 1, provider)
	if n, err := q.Write(context.Background(), []byte("data")); n != 4 || err != nil {
		t.Fatal(n, err)
	}
	q.Seal()
	pump := make(chan error, 1)
	go func() { _, _, err := q.Pump(context.Background()); pump <- err }()
	<-provider.entered
	if err := q.CloseWrite(context.Background()); err != nil {
		t.Fatal(err)
	}
	close(provider.finish)
	if err := <-pump; !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal(err)
	}
	if err := q.Finish(context.Background()); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal("failed FIN reported normal drain", err)
	}
	if err := q.CloseWrite(context.Background()); err != nil {
		t.Fatal("later failure erased established FIN ticket", err)
	}
	status := q.SendStatus()
	if status.AcceptedBytes != 4 || !status.FINSubmitted || status.SendDrained || !errors.Is(status.FirstError, io.ErrClosedPipe) {
		t.Fatal(status)
	}
}

func TestSendQueueCloseWaitersUseOriginalBoundAndKeepTailCharge(t *testing.T) {
	q, _, root := sendQueueFixture(t, 4, 4, 4, 1, io.Discard)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- q.Finish(ctx) }()
	until := time.Now().Add(5 * time.Second)
	for {
		q.mu.Lock()
		waiting := q.observers == 1
		q.mu.Unlock()
		if waiting {
			break
		}
		if time.Now().After(until) {
			t.Fatal("original Finish did not enter its bounded wait")
		}
		runtime.Gosched()
	}
	if err := q.CloseWrite(context.Background()); !errors.Is(err, cryptov4.ErrCapacity) {
		t.Fatal("close waiter escaped fixed original slab", err)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if result, _, err := q.Pump(context.Background()); err != nil || !result.Complete {
		t.Fatal("wait cancellation erased original empty FIN", result, err)
	}
	if root.Snapshot().Reservations != 2 {
		t.Fatal("local DATA cleanup refunded usable Finish observation capacity")
	}
	if err := q.retire(); !errors.Is(err, cryptov4.ErrCapacity) {
		t.Fatal("pending drain observation retired", err)
	}
	q.Stop(ErrAbandoned)
	if err := q.Finish(context.Background()); !errors.Is(err, ErrAbandoned) {
		t.Fatal("reset left a permanently unfulfillable Finish", err)
	}
}

func TestSendQueueAbortedDrainDoesNotBecomeNormalFinish(t *testing.T) {
	q, flow, _ := sendQueueFixture(t, 4, 4, 4, 1, io.Discard)
	if n, err := q.Write(context.Background(), []byte("data")); n != 4 || err != nil {
		t.Fatal(n, err)
	}
	q.Seal()
	if result, _, err := q.Pump(context.Background()); err != nil || !result.Complete {
		t.Fatal(result, err)
	}
	terminal, ok := flow.Terminal()
	if !ok {
		t.Fatal("missing original FIN terminal tuple")
	}
	if err := flow.ApplyDrained(DrainProof{Terminal: terminal, Aborted: true}); err != nil {
		t.Fatal(err)
	}
	if err := q.CloseWrite(context.Background()); err != nil {
		t.Fatal("aborted peer proof erased original FIN ticket", err)
	}
	if err := q.Finish(context.Background()); !errors.Is(err, ErrAbandoned) {
		t.Fatal("aborted DRAINED falsely finished normally", err)
	}
	status := q.SendStatus()
	if status.SendDrained || status.PeerAuthenticatedBytes != 0 || status.AcceptedBytes != 4 {
		t.Fatal("aborted proof erased acceptance or invented authentication", status)
	}
}

func TestSendQueuePublicationReturnTailDelaysStreamCleanup(t *testing.T) {
	provider := &publishedQueueWriter{entered: make(chan struct{}), release: make(chan struct{})}
	q, flow, root := sendQueueFixture(t, 4, 4, 4, 1, provider)
	q.Seal()
	done := make(chan error, 1)
	go func() { _, _, err := q.Pump(context.Background()); done <- err }()
	<-provider.entered
	before := root.Snapshot().Charged
	// Hold the original application publication-return gate. The record
	// writer can exit, but this still-running queue owner cannot clean up yet.
	q.mu.Lock()
	close(provider.release)
	until := time.Now().Add(5 * time.Second)
	for {
		flow.mu.Lock()
		writerCleaned := flow.cleaned
		flow.mu.Unlock()
		if writerCleaned {
			break
		}
		if time.Now().After(until) {
			q.mu.Unlock()
			t.Fatal("record provider did not finish")
		}
		runtime.Gosched()
	}
	_, _, _, _, cleaned := flow.Snapshot()
	retired := flow.retire()
	charged := root.Snapshot().Charged
	q.mu.Unlock()
	if cleaned || !errors.Is(retired, cryptov4.ErrCapacity) || charged != before {
		t.Fatal("Stream cleanup or retirement outran its application queue tail", cleaned, retired)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, cleaned := flow.Snapshot(); !cleaned {
		t.Fatal("completed original queue did not release Stream cleanup")
	}
	flow.Stop()
	if err := flow.retire(); err != nil || root.Snapshot().Reservations != 0 || len(q.slots) != 0 {
		t.Fatal("original Stream retirement left queue observation resources behind", err)
	}
}
