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
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

func sendQueueFixture(t *testing.T, credit, capacity uint64, chunk int, waiters uint32, provider io.Writer) (*SendQueue, *SendFlow, *resourcev4.Root) {
	t.Helper()
	queueCharge, err := SendQueueCharge(capacity, waiters)
	if err != nil {
		t.Fatal(err)
	}
	flowCharge, err := SendFlowCharge(uint64(chunk))
	if err != nil {
		t.Fatal(err)
	}
	limit, err := queueCharge.Add(flowCharge)
	if err != nil {
		t.Fatal(err)
	}
	config := resourcev4.Config{ProfileRevision: [32]byte{1}, AccountSlots: 4, ReservationSlots: 2, ReferenceSlots: 4}
	metadata, err := resourcev4.BackingBytes(config)
	if err != nil {
		t.Fatal(err)
	}
	limit[resourcev4.SDKBytes] += metadata
	config.Limit = limit
	root, err := resourcev4.NewRoot(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(root.Close)
	owner := resourcev4.OwnerKey{ProfileRevision: config.ProfileRevision, Environment: [16]byte{1}, Instance: [16]byte{1}, Backing: [16]byte{1}, Kind: 1}
	flowRef, err := root.Reserve(owner, flowCharge)
	if err != nil {
		t.Fatal(err)
	}
	owner.Instance, owner.Backing = [16]byte{2}, [16]byte{2}
	queueRef, err := root.Reserve(owner, queueCharge)
	if err != nil {
		t.Fatal(err)
	}
	writer, err := NewRecordWriter(ioEngine(t, protocolv4.ClientToServer), 1, provider)
	if err != nil {
		t.Fatal(err)
	}
	flow, err := NewSendFlow(writer, protocolv4.ClientToServer, credit, TerminalTuple{}, uint64(chunk), 128, flowRef)
	if err != nil {
		t.Fatal(err)
	}
	queue, err := NewSendQueue(flow, capacity, waiters, chunk, queueRef)
	if err != nil {
		t.Fatal(err)
	}
	flowRef.Release()
	queueRef.Release()
	t.Cleanup(func() {
		queue.Stop(nil)
		flow.Stop()
		if err := queue.retire(); err != nil {
			t.Error("send queue observation owner did not exit", err)
		}
		if err := flow.retire(); err != nil || root.Snapshot().Reservations != 0 {
			t.Error("actual send queue/flow owners did not exit", err, root.Snapshot().Reservations)
		}
	})
	return queue, flow, root
}

func readQueueRecords(t *testing.T, wire []byte, count int) (string, bool) {
	t.Helper()
	r, err := newTestRecordReceiver(t, ioEngine(t, protocolv4.ServerToClient), protocolv4.ClientToServer, 4096, 128, protocolv4.DecodeContext{Limits: map[string]uint64{"max_data_payload_bytes": 1024}})
	if err != nil {
		t.Fatal(err)
	}
	reader := bytes.NewReader(wire)
	var payload []byte
	var fin bool
	for range count {
		record, err := r.Read(context.Background(), reader)
		if err != nil {
			t.Fatal(err)
		}
		frame, err := record.Body()
		if err != nil {
			t.Fatal(err)
		}
		offset, _ := frame.Field("offset").Uint()
		data, _ := frame.Field("data").ByteString()
		if offset != uint64(len(payload)) || fin {
			t.Fatal("record publication replayed or crossed the original FIN", offset, len(payload), fin)
		}
		payload = append(payload, data...)
		fin, _ = frame.Field("fin").Bool()
		record.Release()
	}
	if reader.Len() != 0 {
		t.Fatal("extra record was published")
	}
	return string(payload), fin
}

func TestSendQueueStableAcceptanceSurvivesCancellationAndCreditWait(t *testing.T) {
	var wire bytes.Buffer
	q, flow, root := sendQueueFixture(t, 3, 8, 4, 2, &wire)
	ctx, cancel := context.WithCancel(context.Background())
	input := []byte("abcdefghXYZ")
	n, err := q.Write(ctx, input)
	if err != nil || n != 8 || wire.Len() != 0 {
		t.Fatal("acceptance was tied to provider progress", n, err)
	}
	cancel()
	clear(input)
	q.Seal()
	first, n, err := q.Pump(context.Background())
	if err != nil || !first.Complete || n != 3 {
		t.Fatal(first, n, err)
	}
	blocked, n, err := q.Pump(context.Background())
	if !errors.Is(err, ErrCredit) || blocked.Submitted || n != 0 {
		t.Fatal("queue exceeded peer credit", blocked, n, err)
	}
	accepted, published, pending, _, _, _, _ := q.Snapshot()
	if accepted != 8 || published != 3 || pending != 5 || root.Snapshot().Reservations != 2 {
		t.Fatal("credit wait lost local acceptance responsibility", accepted, published, pending)
	}
	if err := flow.ApplyCredit(3, 8); err != nil {
		t.Fatal(err)
	}
	for _, want := range []int{4, 1} {
		result, n, err := q.Pump(context.Background())
		if err != nil || !result.Complete || n != want {
			t.Fatal(result, n, err)
		}
	}
	accepted, published, pending, sealed, fin, cleanup, failure := q.Snapshot()
	if accepted != 8 || published != 8 || pending != 0 || !sealed || !fin || !cleanup || failure != nil {
		t.Fatal("ordered FIN lost stable acceptance facts", accepted, published, pending, sealed, fin, cleanup, failure)
	}
	if _, _, _, drained, _ := flow.Snapshot(); drained {
		t.Fatal("local FIN publication pretended to be peer drain")
	}
	size := wire.Len()
	if result, _, err := q.Pump(context.Background()); err != nil || result.Submitted || wire.Len() != size {
		t.Fatal("repeated FIN submitted a new record", result, err)
	}
	if data, fin := readQueueRecords(t, wire.Bytes(), 3); data != "abcdefgh" || !fin {
		t.Fatal("cancelled caller or mutable input changed accepted bytes", data, fin)
	}
	q.Stop(nil)
	if _, _, _, _, fin, _, failure := q.Snapshot(); !fin || failure != nil {
		t.Fatal("later cleanup rewrote completed FIN as failed", fin, failure)
	}
}

func waitSendQueueWriters(t *testing.T, q *SendQueue, count int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		q.mu.Lock()
		actual := q.waiters
		q.mu.Unlock()
		if actual == count {
			return
		}
		runtime.Gosched()
	}
	t.Fatal("write waiter did not reach its original FIFO slot")
}

type queuedWriteResult struct {
	n   int
	err error
}

func TestSendQueueBoundedFIFOAndCanceledWaiterDoNotStealBytes(t *testing.T) {
	var wire bytes.Buffer
	q, _, _ := sendQueueFixture(t, 32, 4, 4, 2, &wire)
	if n, err := q.Write(context.Background(), []byte("AAAA")); n != 4 || err != nil {
		t.Fatal(n, err)
	}
	firstCtx, cancelFirst := context.WithCancel(context.Background())
	defer cancelFirst()
	secondCtx, cancelSecond := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelSecond()
	first, second := make(chan queuedWriteResult, 1), make(chan queuedWriteResult, 1)
	go func() { n, err := q.Write(firstCtx, []byte("BBBB")); first <- queuedWriteResult{n, err} }()
	waitSendQueueWriters(t, q, 1)
	go func() { n, err := q.Write(secondCtx, []byte("CCCC")); second <- queuedWriteResult{n, err} }()
	waitSendQueueWriters(t, q, 2)
	if n, err := q.Write(secondCtx, []byte("DDDD")); n != 0 || !errors.Is(err, cryptov4.ErrCapacity) {
		t.Fatal("full waiter slab accepted another hidden waiter", n, err)
	}
	cancelFirst()
	if result := <-first; result.n != 0 || !errors.Is(result.err, context.Canceled) {
		t.Fatal("cancelled waiter consumed bytes", result)
	}
	if _, n, err := q.Pump(secondCtx); n != 4 || err != nil {
		t.Fatal(n, err)
	}
	if result := <-second; result.n != 4 || result.err != nil {
		t.Fatal("cancelled FIFO predecessor lost the next writer", result)
	}
	q.Seal()
	if _, n, err := q.Pump(secondCtx); n != 4 || err != nil {
		t.Fatal(n, err)
	}
	if data, fin := readQueueRecords(t, wire.Bytes(), 2); data != "AAAACCCC" || !fin {
		t.Fatal("FIFO cancellation reordered or published rejected bytes", data, fin)
	}
}

func TestSendQueueRekeyAndPumpCancellationRetainSamePrefix(t *testing.T) {
	var wire bytes.Buffer
	q, flow, _ := sendQueueFixture(t, 8, 8, 4, 1, &wire)
	if n, err := q.Write(context.Background(), []byte("abcd")); n != 4 || err != nil {
		t.Fatal(n, err)
	}
	var scopes [4]protocolv4.RecordHeader
	freeze, _, err := flow.writer.engine.FreezeApplication(scopes[:])
	if err != nil {
		t.Fatal(err)
	}
	if n, err := q.Write(context.Background(), []byte("efgh")); n != 4 || err != nil {
		t.Fatal("legal ticket freeze revoked bounded local acceptance", n, err)
	}
	q.Seal()
	if result, n, err := q.Pump(context.Background()); !errors.Is(err, cryptov4.ErrTransition) || result.Submitted || n != 0 {
		t.Fatal("frozen queue acquired a ticket", result, n, err)
	}
	if err := freeze.Cancel(); err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if result, n, err := q.Pump(canceled); !errors.Is(err, context.Canceled) || result.Submitted || n != 0 {
		t.Fatal(result, n, err)
	}
	if accepted, published, pending, _, _, _, _ := q.Snapshot(); accepted != 8 || published != 0 || pending != 8 {
		t.Fatal("no-ticket attempt lost its original queue", accepted, published, pending)
	}
	for range 2 {
		if result, n, err := q.Pump(context.Background()); err != nil || !result.Complete || n != 4 {
			t.Fatal(result, n, err)
		}
	}
	if data, fin := readQueueRecords(t, wire.Bytes(), 2); data != "abcdefgh" || !fin {
		t.Fatal("resumed publication replayed or lost bytes", data, fin)
	}
}

type queueHeldWriter struct{ entered, finish chan struct{} }

func (w *queueHeldWriter) Write(p []byte) (int, error) {
	close(w.entered)
	<-w.finish
	return len(p), nil
}

func TestSendQueueStopRetainsProviderAndOriginalAcceptedFacts(t *testing.T) {
	provider := &queueHeldWriter{make(chan struct{}), make(chan struct{})}
	q, flow, root := sendQueueFixture(t, 8, 8, 4, 1, provider)
	if n, err := q.Write(context.Background(), []byte("abcdefgh")); n != 8 || err != nil {
		t.Fatal(n, err)
	}
	done := make(chan queuedWriteResult, 1)
	go func() { _, n, err := q.Pump(context.Background()); done <- queuedWriteResult{n, err} }()
	<-provider.entered
	before := root.Snapshot().Charged
	q.Stop(context.Canceled)
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := q.WaitCleanup(canceled); !errors.Is(err, context.Canceled) || root.Snapshot().Charged != before {
		t.Fatal("Close or cleanup timeout refunded a live publication", err)
	}
	if err := flow.retire(); !errors.Is(err, cryptov4.ErrCapacity) {
		t.Fatal("original send metadata retired while queue/provider still owned it", err)
	}
	if n, err := q.Write(context.Background(), []byte("later")); n != 0 || !errors.Is(err, context.Canceled) {
		t.Fatal("stopped queue reopened", n, err)
	}
	close(provider.finish)
	if result := <-done; result.n != 4 || !errors.Is(result.err, context.Canceled) {
		t.Fatal("late complete provider return erased original bytes or close cause", result)
	}
	if err := q.WaitCleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	accepted, published, pending, _, _, cleanup, failure := q.Snapshot()
	if accepted != 8 || published != 4 || pending != 0 || !cleanup || !errors.Is(failure, context.Canceled) || root.Snapshot().Reservations != 2 {
		t.Fatal("abort erased local acceptance or refunded retained observation charge", accepted, published, pending, cleanup, failure)
	}
}

func TestSendQueuePartialProviderFailureDoesNotEraseAcceptedOrInventPublication(t *testing.T) {
	provider := &blockedWriter{make(chan struct{}), make(chan struct{})}
	q, _, _ := sendQueueFixture(t, 8, 8, 4, 1, provider)
	if n, err := q.Write(context.Background(), []byte("abcdefgh")); n != 8 || err != nil {
		t.Fatal(n, err)
	}
	done := make(chan error, 1)
	go func() {
		result, n, err := q.Pump(context.Background())
		if !result.Submitted || result.Complete || result.EnvelopeBytes != 2 || n != 0 {
			t.Error("partial wire progress was rewritten", result, n)
		}
		done <- err
	}()
	<-provider.entered
	close(provider.finish)
	if err := <-done; !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal(err)
	}
	accepted, published, pending, _, _, cleanup, failure := q.Snapshot()
	if accepted != 8 || published != 0 || pending != 0 || !cleanup || !errors.Is(failure, io.ErrClosedPipe) {
		t.Fatal("partial failure rewrote local responsibility", accepted, published, pending, cleanup, failure)
	}
	if result, _, err := q.Pump(context.Background()); !errors.Is(err, io.ErrClosedPipe) || result.Submitted {
		t.Fatal("ticketed failure replayed accepted prefix", result, err)
	}
}

func TestSendQueueOriginalOwnershipAndEmptyFIN(t *testing.T) {
	var wire bytes.Buffer
	q, flow, root := sendQueueFixture(t, 0, 4, 4, 1, &wire)
	if result, err := flow.Write(context.Background(), []byte("x"), false); !errors.Is(err, cryptov4.ErrConfiguration) || result.Submitted {
		t.Fatal("raw flow bypassed its attached application queue", result, err)
	}
	if _, err := NewSendQueue(flow, 4, 1, 4, resourcev4.Reference{}); err == nil || root.Snapshot().Reservations != 2 {
		t.Fatal("second queue attached to original flow", err)
	}
	q.Seal()
	if result, n, err := q.Pump(context.Background()); err != nil || !result.Complete || n != 0 {
		t.Fatal("empty ordered FIN needed application credit", result, n, err)
	}
	if data, fin := readQueueRecords(t, wire.Bytes(), 1); data != "" || !fin {
		t.Fatal(data, fin)
	}
}

type firstQueueBlockWriter struct {
	bytes.Buffer
	entered, release chan struct{}
	first            bool
}

func (w *firstQueueBlockWriter) Write(p []byte) (int, error) {
	if !w.first {
		w.first = true
		close(w.entered)
		<-w.release
	}
	return w.Buffer.Write(p)
}

func TestSendQueueKeepsAcceptingOwnedSuffixDuringOriginalPublication(t *testing.T) {
	provider := &firstQueueBlockWriter{entered: make(chan struct{}), release: make(chan struct{})}
	q, _, _ := sendQueueFixture(t, 8, 8, 4, 1, provider)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	first := []byte("abcd")
	if n, err := q.Write(ctx, first); n != 4 || err != nil {
		t.Fatal(n, err)
	}
	done := make(chan error, 1)
	go func() { _, _, err := q.Pump(context.Background()); done <- err }()
	<-provider.entered
	cancel()
	clear(first)
	second := []byte("efgh")
	if n, err := q.Write(context.Background(), second); n != 4 || err != nil {
		t.Fatal("provider tail blocked unrelated queue capacity", n, err)
	}
	clear(second)
	if result, _, err := q.Pump(context.Background()); !errors.Is(err, cryptov4.ErrCapacity) || result.Submitted {
		t.Fatal("two pump owners touched the original prefix", result, err)
	}
	q.Seal()
	close(provider.release)
	if err := <-done; err != nil {
		t.Fatal("Write wait cancellation aborted accepted bytes", err)
	}
	if result, n, err := q.Pump(context.Background()); err != nil || !result.Complete || n != 4 {
		t.Fatal(result, n, err)
	}
	if data, fin := readQueueRecords(t, provider.Bytes(), 2); data != "abcdefgh" || !fin {
		t.Fatal("queued suffix changed or crossed FIN", data, fin)
	}
}

func TestSendQueueRejectsPrivateBudgetRootAndChecksOriginalClosure(t *testing.T) {
	var wire bytes.Buffer
	writer, _ := NewRecordWriter(ioEngine(t, protocolv4.ClientToServer), 1, &wire)
	flow, err := testSendFlow(t, writer, protocolv4.ClientToServer, 4, TerminalTuple{}, 4, 128)
	if err != nil {
		t.Fatal(err)
	}
	charge, _ := SendQueueCharge(4, 1)
	_, foreign := testResourceReservation(t, charge, 1)
	if _, err := NewSendQueue(flow, 4, 1, 4, foreign); !errors.Is(err, resourcev4.ErrOwner) {
		t.Fatal("private roots bypassed shared aggregate admission", err)
	}
	q, _, root := sendQueueFixture(t, 4, 4, 4, 1, &wire)
	if n, err := q.Write(context.Background(), []byte("live")); n != 4 || err != nil {
		t.Fatal(n, err)
	}
	root.Close()
	if n, err := q.Write(context.Background(), []byte("late")); n != 0 || !errors.Is(err, resourcev4.ErrClosed) {
		t.Fatal("resource closure accepted more bytes", n, err)
	}
	if result, n, err := q.Pump(context.Background()); n != 0 || !errors.Is(err, resourcev4.ErrClosed) || result.Submitted || wire.Len() != 0 {
		t.Fatal("resource closure acquired a new queue ticket", result, n, err)
	}
	if accepted, _, pending, _, _, _, _ := q.Snapshot(); accepted != 4 || pending != 4 || root.Snapshot().CleanupComplete {
		t.Fatal("root Close refunded live acceptance responsibility", accepted, pending)
	}
}

func TestSendQueueWriteAllKeepsCumulativeAcceptanceOnCancellation(t *testing.T) {
	var wire bytes.Buffer
	q, _, _ := sendQueueFixture(t, 8, 4, 4, 1, &wire)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	input := []byte("abcdefgh")
	done := make(chan queuedWriteResult, 1)
	go func() { n, err := q.WriteAll(ctx, input); done <- queuedWriteResult{n, err} }()
	waitSendQueueWriters(t, q, 1)
	cancel()
	if result := <-done; result.n != 4 || !errors.Is(result.err, context.Canceled) {
		t.Fatal("WriteAll erased its earlier accepted prefix", result)
	}
	clear(input)
	if result, n, err := q.Pump(context.Background()); err != nil || !result.Complete || n != 4 {
		t.Fatal("cancelled WriteAll discarded its sending responsibility", result, n, err)
	}
	if data, fin := readQueueRecords(t, wire.Bytes(), 1); data != "abcd" || fin {
		t.Fatal("WriteAll replayed input or implicitly ended the direction", data, fin)
	}
}
