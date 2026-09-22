package sessionv4

import (
	"bytes"
	"context"
	"errors"
	"math"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

func copyFixture(t *testing.T, capacity, chunk uint64) (*ReceiveFlow, *SendQueue, *resourcev4.Root, resourcev4.Reference, *bytes.Buffer) {
	t.Helper()
	poolCharge, err := ReceivePoolCharge(64, 1)
	if err != nil {
		t.Fatal(err)
	}
	flowCharge, err := SendFlowCharge(64)
	if err != nil {
		t.Fatal(err)
	}
	queueCharge, err := SendQueueCharge(capacity, 2)
	if err != nil {
		t.Fatal(err)
	}
	copyCharge, err := CopyCharge(chunk)
	if err != nil {
		t.Fatal(err)
	}
	charges := []resourcev4.Vector{poolCharge, flowCharge, queueCharge, copyCharge}
	config := resourcev4.Config{ProfileRevision: [32]byte{1}, AccountSlots: 4, ReservationSlots: 4, ReferenceSlots: 8}
	for _, charge := range charges {
		config.Limit, err = config.Limit.Add(charge)
		if err != nil {
			t.Fatal(err)
		}
	}
	metadata, err := resourcev4.BackingBytes(config)
	if err != nil {
		t.Fatal(err)
	}
	config.Limit[resourcev4.SDKBytes] += metadata
	root, err := resourcev4.NewRoot(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(root.Close)
	var refs [4]resourcev4.Reference
	for i, charge := range charges {
		key := resourcev4.OwnerKey{ProfileRevision: config.ProfileRevision, Environment: [16]byte{1}, Instance: [16]byte{byte(i + 1)}, Backing: [16]byte{byte(i + 1)}, Kind: 1}
		refs[i], err = root.Reserve(key, charge)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(refs[i].Release)
	}
	pool, err := NewReceivePool(64, 64, 1, refs[0])
	if err != nil {
		t.Fatal(err)
	}
	f, err := NewReceiveFlow(pool, 1, protocolv4.ClientToServer, 64, TerminalTuple{}, 64)
	if err != nil {
		t.Fatal(err)
	}
	wire := new(bytes.Buffer)
	writer, err := NewRecordWriter(ioEngine(t, protocolv4.ClientToServer), 1, wire)
	if err != nil {
		t.Fatal(err)
	}
	flow, err := NewSendFlow(writer, protocolv4.ClientToServer, 64, TerminalTuple{}, 64, 128, refs[1])
	if err != nil {
		t.Fatal(err)
	}
	q, err := NewSendQueue(flow, capacity, 2, 64, refs[2])
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		f.Fence()
		pool.Close()
		if err := f.Cleanup(); err != nil {
			t.Error(err)
		}
		q.Stop(nil)
		if err := q.retire(); err != nil {
			t.Error(err)
		}
		if err := flow.retire(); err != nil {
			t.Error(err)
		}
	})
	return f, q, root, refs[3], wire
}

type copyRun struct {
	result CopyResult
	err    error
	done   chan struct{}
	cancel context.CancelFunc
}

func startCopy(t *testing.T, q *SendQueue, f *ReceiveFlow, chunk uint64, ref resourcev4.Reference) *copyRun {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	run := &copyRun{done: make(chan struct{}), cancel: cancel}
	go func() {
		run.result, run.err = Copy(ctx, q, f, chunk, ref)
		close(run.done)
	}()
	t.Cleanup(func() { cancel(); <-run.done })
	return run
}

func TestCopyEOFChunksUseOriginalFIFOWithoutImplicitFIN(t *testing.T) {
	f, q, root, ref, wire := copyFixture(t, 64, 4)
	transport := newFlowTransport(t)
	if err := transport.data(t, f, 0, true, "abcdefghij"); err != nil {
		t.Fatal(err)
	}
	r, err := Copy(context.Background(), q, f, 4, ref)
	if err != nil || r.SourceTerminal != protocolv4.V4ReadTerminalEof || r.Progress.SourceReadBytes != 10 || r.Progress.DestinationAcceptedBytes != 10 || r.Progress.Validate(protocolv4.TransferContext{ChunkBytes: 4}) != nil {
		t.Fatal(r, err)
	}
	if root.Snapshot().Reservations != 3 {
		t.Fatal("copy backing was not handed off", root.Snapshot())
	}
	if _, n, err := q.Pump(context.Background()); err != nil || n != 10 {
		t.Fatal(n, err)
	}
	if data, fin := readQueueRecords(t, wire.Bytes(), 1); data != "abcdefghij" || fin {
		t.Fatal(data, fin)
	}
	if _, err := q.Write(context.Background(), []byte("after copy")); err != nil {
		t.Fatal("copy sealed destination", err)
	}
}

func TestCopyDestinationStopEndsIdleSourceWaitAndActualHelperTail(t *testing.T) {
	f, q, _, ref, _ := copyFixture(t, 8, 4)
	run := startCopy(t, q, f, 4, ref)
	waitReadAdmitted(t, f)
	q.Stop(ErrTerminal)
	<-run.done
	if !errors.Is(run.err, ErrTerminal) || run.result.Progress.SourceReadBytes != 0 || run.result.Progress.DestinationAcceptedBytes != 0 {
		t.Fatal("target failure lost original cause or consumed input", run.result, run.err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := q.WaitCleanup(ctx); err != nil {
		t.Fatal("terminated destination retained idle Copy tail", err)
	}
}

func TestCopyPartialAcceptanceReturnsExactTailAndOwnsReadUntilExit(t *testing.T) {
	f, q, root, ref, wire := copyFixture(t, 2, 4)
	transport := newFlowTransport(t)
	if err := transport.data(t, f, 0, true, "abcdefgh"); err != nil {
		t.Fatal(err)
	}
	run := startCopy(t, q, f, 4, ref)
	waitSendQueueWriters(t, q, 1)
	_, _, released, _ := f.Snapshot()
	if released != 4 || root.Snapshot().Reservations != 4 {
		t.Fatal("pre-read or early refund", released, root.Snapshot())
	}
	if _, _, err := f.TryRead(make([]byte, 8)); !errors.Is(err, ErrReadInProgress) {
		t.Fatal(err)
	}
	if err := f.Cleanup(); !errors.Is(err, ErrReadInProgress) {
		t.Fatal(err)
	}
	run.cancel()
	<-run.done
	r := run.result
	if !errors.Is(run.err, context.Canceled) || r.Progress.SourceReadBytes != 4 || r.Progress.DestinationAcceptedBytes != 2 || string(r.Progress.UnacceptedTail) != "cd" || cap(r.Progress.UnacceptedTail) != 2 || r.Progress.Validate(protocolv4.TransferContext{ChunkBytes: 4}) != nil {
		t.Fatal(r, run.err)
	}
	if root.Snapshot().Reservations != 3 {
		t.Fatal("actual return leaked copy charge")
	}
	var rest [8]byte
	if n, terminal, err := f.TryRead(rest[:]); n != 4 || terminal != protocolv4.V4ReadTerminalEof || err != nil || string(rest[:n]) != "efgh" {
		t.Fatal(n, terminal, err, string(rest[:n]))
	}
	if _, n, err := q.Pump(context.Background()); n != 2 || err != nil {
		t.Fatal(n, err)
	}
	if data, fin := readQueueRecords(t, wire.Bytes(), 1); data != "ab" || fin {
		t.Fatal(data, fin)
	}
	if string(r.Progress.UnacceptedTail) != "cd" {
		t.Fatal("later owner changed delivered tail")
	}
}

func TestCopyEOFDataKeepsClaimWhileDestinationBlocked(t *testing.T) {
	f, q, _, ref, _ := copyFixture(t, 1, 4)
	transport := newFlowTransport(t)
	if err := transport.data(t, f, 0, true, "tail"); err != nil {
		t.Fatal(err)
	}
	run := startCopy(t, q, f, 4, ref)
	waitSendQueueWriters(t, q, 1)
	if err := f.Cleanup(); !errors.Is(err, ErrReadInProgress) {
		t.Fatal("EOF freed live read owner", err)
	}
	q.Stop(cryptov4.ErrAuthentication)
	<-run.done
	if !errors.Is(run.err, cryptov4.ErrAuthentication) || run.result.SourceTerminal != protocolv4.V4ReadTerminalEof || run.result.Progress.SourceReadBytes != 4 || run.result.Progress.DestinationAcceptedBytes != 1 || string(run.result.Progress.UnacceptedTail) != "ail" {
		t.Fatal(run.result, run.err)
	}
	if err := f.Cleanup(); err != nil {
		t.Fatal(err)
	}
}

func TestCopyProgressExcludesOtherFIFORequests(t *testing.T) {
	f, q, _, ref, wire := copyFixture(t, 2, 4)
	if _, err := q.Write(context.Background(), []byte("00")); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	other := make(chan error, 1)
	go func() { _, err := q.Write(ctx, []byte("XY")); other <- err }()
	waitSendQueueWriters(t, q, 1)
	transport := newFlowTransport(t)
	if err := transport.data(t, f, 0, true, "abcd"); err != nil {
		t.Fatal(err)
	}
	run := startCopy(t, q, f, 4, ref)
	waitSendQueueWriters(t, q, 2)
	if _, n, err := q.Pump(ctx); n != 2 || err != nil {
		t.Fatal(n, err)
	}
	if err := <-other; err != nil {
		t.Fatal(err)
	}
	if _, n, err := q.Pump(ctx); n != 2 || err != nil {
		t.Fatal(n, err)
	}
	// Wait until this copy's original request has actually accepted a prefix
	// and is waiting on its suffix, not merely still linked before acceptance.
	deadline := time.After(time.Second)
	for {
		q.mu.Lock()
		accepted, waiting := q.accepted, q.waiters
		q.mu.Unlock()
		if accepted == 6 && waiting == 1 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("copy did not advance behind older FIFO writer")
		default:
		}
		time.Sleep(time.Millisecond)
	}
	run.cancel()
	<-run.done
	if !errors.Is(run.err, context.Canceled) || run.result.Progress.SourceReadBytes != 4 || run.result.Progress.DestinationAcceptedBytes != 2 || string(run.result.Progress.UnacceptedTail) != "cd" {
		t.Fatal("copy borrowed another request's progress", run.result, run.err)
	}
	if _, n, err := q.Pump(ctx); n != 2 || err != nil {
		t.Fatal(n, err)
	}
	if data, fin := readQueueRecords(t, wire.Bytes(), 3); data != "00XYab" || fin {
		t.Fatal("copy bypassed FIFO or replayed accepted input", data, fin)
	}
}

func TestCopySourceFailureKeepsEarlierAcceptedProgress(t *testing.T) {
	f, q, _, ref, _ := copyFixture(t, 64, 4)
	transport := newFlowTransport(t)
	if err := transport.data(t, f, 0, false, "data"); err != nil {
		t.Fatal(err)
	}
	run := startCopy(t, q, f, 4, ref)
	deadline := time.After(time.Second)
	for {
		accepted, _, _, _, _, _, _ := q.Snapshot()
		if accepted == 4 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("copy did not accept original chunk")
		default:
		}
		time.Sleep(time.Millisecond)
	}
	f.Abandon()
	<-run.done
	if !errors.Is(run.err, ErrAbandoned) || run.result.SourceTerminal != protocolv4.V4ReadTerminalAbandoned || run.result.Progress.SourceReadBytes != 4 || run.result.Progress.DestinationAcceptedBytes != 4 || len(run.result.Progress.UnacceptedTail) != 0 {
		t.Fatal(run.result, run.err)
	}
}

func TestCopyRejectsUnownedBudgetAndCompetingReaderBeforeConsumption(t *testing.T) {
	f, q, _, ref, _ := copyFixture(t, 8, 4)
	charge, _ := CopyCharge(4)
	_, foreign := testResourceReservation(t, charge, 1)
	if _, err := Copy(context.Background(), q, f, 4, foreign); !errors.Is(err, resourcev4.ErrOwner) {
		t.Fatal(err)
	}
	if err := foreign.Check(); err != nil {
		t.Fatal("rejection consumed foreign reservation", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _, _ = f.ReadInto(ctx, make([]byte, 1)) }()
	t.Cleanup(func() { cancel(); <-done })
	waitReadAdmitted(t, f)
	if _, err := Copy(context.Background(), q, f, 4, ref); !errors.Is(err, ErrReadInProgress) {
		t.Fatal(err)
	}
	if err := ref.Check(); err != nil {
		t.Fatal("read refusal consumed copy budget", err)
	}
}

func TestCopyCounterOverflowRefusesBeforeOriginalConsumptionAndAcceptance(t *testing.T) {
	f, q, _, ref, _ := copyFixture(t, 8, 4)
	transport := newFlowTransport(t)
	if err := transport.data(t, f, 0, false, "ab"); err != nil {
		t.Fatal(err)
	}
	s := copyState{storage: make([]byte, 4), sourceRead: math.MaxUint64 - 1, reservation: ref}
	if _, err := f.copyRead(context.Background(), &s); !errors.Is(err, ErrStreamData) {
		t.Fatal(err)
	}
	if _, _, released, _ := f.Snapshot(); released != 0 {
		t.Fatal("overflow consumed source", released)
	}
	s.filled, s.sourceRead, s.targetTaken = 2, math.MaxUint64, math.MaxUint64
	copy(s.storage, "ab")
	if n, err := q.write(context.Background(), s.storage[:2], &s); n != 0 || !errors.Is(err, ErrStreamData) {
		t.Fatal(n, err)
	}
	if accepted, _, _, _, _, _, _ := q.Snapshot(); accepted != 0 || string(s.storage[:2]) != "ab" {
		t.Fatal("overflow accepted input", accepted)
	}
}

func TestCopyCanceledBeforeClaimPreservesSource(t *testing.T) {
	f, q, _, ref, _ := copyFixture(t, 8, 4)
	transport := newFlowTransport(t)
	if err := transport.data(t, f, 0, true, "data"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r, err := Copy(ctx, q, f, 4, ref)
	if !errors.Is(err, context.Canceled) || r.Progress.SourceReadBytes != 0 || r.Progress.DestinationAcceptedBytes != 0 || len(r.Progress.UnacceptedTail) != 0 {
		t.Fatal("cancelled copy consumed input", r, err)
	}
	var input [4]byte
	if n, terminal, err := f.TryRead(input[:]); n != 4 || terminal != protocolv4.V4ReadTerminalEof || err != nil || string(input[:]) != "data" {
		t.Fatal(n, terminal, err, string(input[:]))
	}
}

func TestCopyInsufficientChunkReservationPreservesSourceAndReservation(t *testing.T) {
	f, q, _, ref, _ := copyFixture(t, 8, 4)
	transport := newFlowTransport(t)
	if err := transport.data(t, f, 0, true, "data"); err != nil {
		t.Fatal(err)
	}
	r, err := Copy(context.Background(), q, f, 8, ref)
	if !errors.Is(err, resourcev4.ErrCapacity) || r.Progress.SourceReadBytes != 0 || r.Progress.DestinationAcceptedBytes != 0 {
		t.Fatal("insufficient reservation consumed input", r, err)
	}
	if err := ref.Check(); err != nil {
		t.Fatal("failed admission consumed original reservation", err)
	}
	var input [4]byte
	if n, _, err := f.TryRead(input[:]); n != 4 || err != nil || string(input[:]) != "data" {
		t.Fatal(n, err, string(input[:]))
	}
}

func TestCopyPartialLaterChunkPreservesCumulativeProgress(t *testing.T) {
	f, q, _, ref, _ := copyFixture(t, 6, 4)
	transport := newFlowTransport(t)
	if err := transport.data(t, f, 0, true, "abcdefghijkl"); err != nil {
		t.Fatal(err)
	}
	run := startCopy(t, q, f, 4, ref)
	waitSendQueueWriters(t, q, 1)
	run.cancel()
	<-run.done
	p := run.result.Progress
	if !errors.Is(run.err, context.Canceled) || p.SourceReadBytes != 8 || p.DestinationAcceptedBytes != 6 || string(p.UnacceptedTail) != "gh" || p.Validate(protocolv4.TransferContext{ChunkBytes: 4}) != nil {
		t.Fatal("partial later chunk lost historical progress", p, run.err)
	}
	var remaining [4]byte
	if n, _, err := f.TryRead(remaining[:]); n != 4 || err != nil || string(remaining[:]) != "ijkl" {
		t.Fatal("copy pre-read another chunk", n, err, string(remaining[:]))
	}
}

func TestCopyFailureDetachesOpaqueProviderCause(t *testing.T) {
	for _, hostile := range []bool{false, true} {
		f, q, _, ref, _ := copyFixture(t, 1, 4)
		transport := newFlowTransport(t)
		if err := transport.data(t, f, 0, true, "data"); err != nil {
			t.Fatal(err)
		}
		run := startCopy(t, q, f, 4, ref)
		waitSendQueueWriters(t, q, 1)
		var cause error = &retainingReadError{backing: make([]byte, 4096), owner: f}
		if hostile {
			cause = callbackReadError{}
		}
		q.Stop(cause)
		<-run.done
		var retained *retainingReadError
		if !errors.Is(run.err, ErrReadOwnerUnavailable) || errors.As(run.err, &retained) || run.result.Progress.SourceReadBytes != 4 || run.result.Progress.DestinationAcceptedBytes != 1 || string(run.result.Progress.UnacceptedTail) != "ata" {
			t.Fatal("copy retained provider graph or erased prefix", run.result, run.err)
		}
	}
}
