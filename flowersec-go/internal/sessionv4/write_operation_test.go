package sessionv4

import (
	"bytes"
	"context"
	"errors"
	"math"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

func runWriteService(t *testing.T, f *serviceFixture) {
	t.Helper()
	f.run(t)
	until := time.Now().Add(3 * time.Second)
	for !f.service.running.Load() {
		if time.Now().After(until) {
			t.Fatal("send coordinator did not start")
		}
		runtime.Gosched()
	}
}

func prepareWrite(t *testing.T, f *serviceFixture, q *SendQueue, input []byte, ms uint64) *WriteOperation {
	t.Helper()
	op, err := q.PrepareWrite(input, WriteOptions{TimeoutMS: ms, HardDeadline: streamTestDeadline(t, f.local.engine)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(op.Cancel)
	return op
}

func waitWriteProgress(t *testing.T, op *WriteOperation, accepted uint64) protocolv4.V4WriteProgress {
	t.Helper()
	until := time.Now().Add(3 * time.Second)
	for {
		p := op.Progress()
		if err := p.Validate(); err != nil {
			t.Fatal("invalid runtime WriteProgress", p, err)
		}
		if p.AcceptedBytes == accepted {
			return p
		}
		if p.AcceptedBytes > accepted || p.Phase == protocolv4.V4WritePhaseTerminal || time.Now().After(until) {
			t.Fatal("unexpected original request progress", p, accepted)
		}
		runtime.Gosched()
	}
}

func awaitWriteTerminal(t *testing.T, op *WriteOperation) protocolv4.V4WriteProgress {
	t.Helper()
	select {
	case <-op.done:
	case <-time.After(3 * time.Second):
		t.Fatal("operation did not finish without a Wait owner")
	}
	p := op.Progress()
	if err := p.Validate(); err != nil {
		t.Fatal(p, err)
	}
	return p
}

func TestWriteOperationPrepareCopiesBeforeStartAndUsesOriginalFIFO(t *testing.T) {
	f := newServiceFixtureQueue(t, 1, [3]uint32{1}, 64, 4)
	w := &serviceTestWriter{frames: make(chan []byte, 32)}
	q, peer := f.open(t, BusinessStream, 64, w)
	runWriteService(t, f)
	input := []byte("immutable")
	op := prepareWrite(t, f, q, input, 3000)
	clear(input)
	if p := op.Progress(); p.Phase != protocolv4.V4WritePhasePrepared || p.AcceptedBytes != 0 {
		t.Fatal(p)
	}
	if n, err := q.Write(context.Background(), []byte("first")); n != 5 || err != nil {
		t.Fatal(n, err)
	}
	if err := op.Start(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	p, err := op.Wait(ctx)
	if err != nil || p.AcceptedBytes != 9 || p.TerminalReason != protocolv4.V4WriteTerminalReasonComplete {
		t.Fatal(p, err)
	}
	if err := op.Start(); err != nil {
		t.Fatal(err)
	}
	op.Cancel()
	if op.queue.Load() != nil || op.CleanupStatus().Status != protocolv4.V4CleanupStateComplete {
		t.Fatal("terminal handle retained transport ownership")
	}
	q.Seal()
	var got []byte
	for {
		r, err := f.peer.receiver.Receive(ctx, nextServiceFrame(t, w))
		if err != nil {
			t.Fatal(err)
		}
		frame, _ := r.Body()
		fin, _ := frame.Field("fin").Bool()
		if err := peer.Apply(r); err != nil {
			t.Fatal(err)
		}
		r.Release()
		var data [64]byte
		n, _, err := peer.receive.TryRead(data[:])
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, data[:n]...)
		if fin {
			break
		}
	}
	if string(got) != "firstimmutable" {
		t.Fatal("input reuse or repeated Start changed publication", string(got))
	}
}

func TestWriteOperationCancelSealsOnlyItsAcceptedPrefix(t *testing.T) {
	f := newServiceFixtureQueue(t, 1, [3]uint32{1}, 64, 4)
	w := &serviceTestWriter{frames: make(chan []byte, 32)}
	q, _ := f.open(t, BusinessStream, 0, w)
	runWriteService(t, f)
	if n, err := q.Write(context.Background(), bytes.Repeat([]byte{'a'}, 60)); n != 60 || err != nil {
		t.Fatal(n, err)
	}
	op := prepareWrite(t, f, q, []byte("ABCDEFGH"), 3000)
	if err := op.Start(); err != nil {
		t.Fatal(err)
	}
	waitWriteProgress(t, op, 4)
	op.Cancel()
	p, err := op.Wait(context.Background())
	if !errors.Is(err, context.Canceled) || p.AcceptedBytes != 4 || p.TerminalReason != protocolv4.V4WriteTerminalReasonCanceled {
		t.Fatal(p, err)
	}
	if err := op.Start(); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled owner regained Start", err)
	}
	q.mu.Lock()
	got := append([]byte(nil), q.storage...)
	q.mu.Unlock()
	if string(got[60:]) != "ABCD" {
		t.Fatal("cancel removed accepted bytes", string(got[60:]))
	}
	if accepted, _, pending, sealed, _, _, _ := q.Snapshot(); accepted != 64 || pending != 64 || sealed {
		t.Fatal(accepted, pending, sealed)
	}
	// Cancel affected neither the direction nor the original publisher. Grant
	// test credit on the original flow and verify the retained prefix is sent.
	if err := q.flow.ApplyCredit(0, 64); err != nil {
		t.Fatal(err)
	}
	for range 16 {
		nextServiceFrame(t, w)
	}
	if p := op.Progress(); p.AcceptedBytes != 4 {
		t.Fatal("late publication changed terminal n", p)
	}
}

func TestWriteOperationWaitCancellationDoesNotCancelOrRenewRequest(t *testing.T) {
	f := newServiceFixtureQueue(t, 1, [3]uint32{1}, 64, 4)
	w := &serviceTestWriter{frames: make(chan []byte, 32)}
	q, _ := f.open(t, BusinessStream, 0, w)
	runWriteService(t, f)
	if _, err := q.Write(context.Background(), make([]byte, 64)); err != nil {
		t.Fatal(err)
	}
	op := prepareWrite(t, f, q, []byte("later"), 250)
	if err := op.Start(); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		p, err := op.Wait(ctx)
		cancel()
		if !errors.Is(err, context.DeadlineExceeded) || p.Phase != protocolv4.V4WritePhaseRunning || p.AcceptedBytes != 0 {
			t.Fatal(p, err)
		}
	}
	p := awaitWriteTerminal(t, op)
	if p.TerminalReason != protocolv4.V4WriteTerminalReasonDeadlineExceeded || p.AcceptedBytes != 0 {
		t.Fatal(p)
	}
	if _, err := op.Wait(context.Background()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	if accepted, _, pending, _, _, _, _ := q.Snapshot(); accepted != 64 || pending != 64 {
		t.Fatal("expired suffix changed previous input", accepted, pending)
	}
}

func TestWriteOperationPreparedExpiryRunsBehindBlockedProvider(t *testing.T) {
	f := newServiceFixtureQueue(t, 1, [3]uint32{1}, 64, 4)
	w := &serviceTestWriter{frames: make(chan []byte, 32), entered: make(chan struct{}), release: make(chan struct{})}
	defer close(w.release)
	q, _ := f.open(t, BusinessStream, 64, w)
	runWriteService(t, f)
	if _, err := q.Write(context.Background(), []byte("held")); err != nil {
		t.Fatal(err)
	}
	<-w.entered
	op := prepareWrite(t, f, q, []byte("never-started"), 100)
	before := f.root.Snapshot().Charged
	p := awaitWriteTerminal(t, op)
	if p.AcceptedBytes != 0 || p.TerminalReason != protocolv4.V4WriteTerminalReasonDeadlineExceeded || p.CleanupStatus.Status != protocolv4.V4CleanupStateComplete {
		t.Fatal(p)
	}
	if f.root.Snapshot().Charged != before {
		t.Fatal("operation expiry refunded shared staging or provider tail")
	}
	if err := op.Start(); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	if err := f.local.engine.CheckApplicationAuthorization(); err != nil {
		t.Fatal("local expiry closed healthy Session", err)
	}
}

func TestWriteOperationObserverDetachThenSuccessfulWait(t *testing.T) {
	f := newServiceFixtureQueue(t, 1, [3]uint32{1}, 64, 4)
	w := &serviceTestWriter{frames: make(chan []byte, 32)}
	q, _ := f.open(t, BusinessStream, 0, w)
	runWriteService(t, f)
	q.Write(context.Background(), make([]byte, 64))
	op := prepareWrite(t, f, q, []byte("next"), 3000)
	if err := op.Start(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := op.Wait(ctx); done <- err }()
	until := time.Now().Add(3 * time.Second)
	for op.Progress().CleanupStatus.PendingCallbacks != 1 {
		if time.Now().After(until) {
			t.Fatal("observer did not acquire original bounded slot")
		}
		runtime.Gosched()
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := q.flow.ApplyCredit(0, 64); err != nil {
		t.Fatal(err)
	}
	ctx, cancel = context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	p, err := op.Wait(ctx)
	if err != nil || p.AcceptedBytes != 4 || p.TerminalReason != protocolv4.V4WriteTerminalReasonComplete {
		t.Fatal(p, err)
	}
}

func TestWriteOperationFiniteAdmissionAndEarlierHardDeadline(t *testing.T) {
	if _, err := SendQueueCharge(math.MaxInt, math.MaxUint32); err == nil {
		t.Fatal("overflowing staging charge accepted")
	}
	f := newServiceFixtureQueue(t, 1, [3]uint32{1}, 64, 2)
	w := &serviceTestWriter{frames: make(chan []byte, 32)}
	q, _ := f.open(t, BusinessStream, 0, w)
	options := WriteOptions{TimeoutMS: 3000, HardDeadline: streamTestDeadline(t, f.local.engine)}
	if _, err := q.PrepareWrite(nil, options); !errors.Is(err, cryptov4.ErrConfiguration) {
		t.Fatal("unserviced owner admitted", err)
	}
	runWriteService(t, f)
	if _, err := q.PrepareWrite(make([]byte, 65), options); !errors.Is(err, ErrWriteOperationInput) {
		t.Fatal(err)
	}
	if q.waiters != 0 {
		t.Fatal("failed admission consumed a slot")
	}
	a := prepareWrite(t, f, q, nil, 3000)
	b := prepareWrite(t, f, q, nil, 3000)
	if _, err := q.PrepareWrite(nil, options); !errors.Is(err, cryptov4.ErrCapacity) {
		t.Fatal("unbounded prepared owner", err)
	}
	if _, err := a.Wait(context.Background()); !errors.Is(err, cryptov4.ErrCapacity) {
		t.Fatal("observer bypassed aggregate slab cap", err)
	}
	a.Cancel()
	b.Cancel()
	d, err := timev4.NewAge(f.local.engine.Clock(), 100, math.MaxUint64)
	if err != nil {
		t.Fatal(err)
	}
	op, err := q.PrepareWrite(nil, WriteOptions{TimeoutMS: 3000, HardDeadline: d})
	if err != nil {
		t.Fatal(err)
	}
	if p := awaitWriteTerminal(t, op); p.TerminalReason != protocolv4.V4WriteTerminalReasonDeadlineExceeded {
		t.Fatal(p)
	}
	zero := prepareWrite(t, f, q, nil, 3000)
	if err := zero.Start(); err != nil {
		t.Fatal(err)
	}
	if p := awaitWriteTerminal(t, zero); p.AcceptedBytes != 0 || p.TerminalReason != protocolv4.V4WriteTerminalReasonComplete {
		t.Fatal(p)
	}
}

func TestWriteOperationConcurrentCancelStartAndCloseHaveStableCounts(t *testing.T) {
	for range 30 {
		f := newServiceFixtureQueue(t, 1, [3]uint32{1}, 64, 4)
		w := &serviceTestWriter{frames: make(chan []byte, 32)}
		q, _ := f.open(t, BusinessStream, 0, w)
		runWriteService(t, f)
		op := prepareWrite(t, f, q, bytes.Repeat([]byte{'x'}, 64), 3000)
		var group sync.WaitGroup
		group.Add(3)
		go func() { defer group.Done(); op.Start() }()
		go func() { defer group.Done(); op.Cancel() }()
		go func() { defer group.Done(); q.Seal() }()
		group.Wait()
		p := awaitWriteTerminal(t, op)
		accepted, _, pending, _, _, _, _ := q.Snapshot()
		if p.AcceptedBytes != accepted || uint64(pending) != accepted {
			t.Fatal("terminal request count diverged from original gate", p, accepted, pending)
		}
		if p2 := op.Progress(); p2 != p {
			t.Fatal("terminal observation changed", p, p2)
		}
		f.local.admission.Close()
	}
}

func TestWriteOperationResourceRevocationCannotAcceptPreparedInput(t *testing.T) {
	f := newServiceFixtureQueue(t, 1, [3]uint32{1}, 64, 4)
	w := &serviceTestWriter{frames: make(chan []byte, 32)}
	q, _ := f.open(t, BusinessStream, 0, w)
	runWriteService(t, f)
	op := prepareWrite(t, f, q, []byte("revoked"), 3000)
	f.root.Close()
	if err := op.Start(); err == nil {
		t.Fatal("revoked root accepted an operation")
	}
	if p := awaitWriteTerminal(t, op); p.AcceptedBytes != 0 {
		t.Fatal(p)
	}
	if _, err := q.Write(context.Background(), nil); !errors.Is(err, resourcev4.ErrClosed) {
		t.Fatal(err)
	}
}

type writeGateAuthorization struct {
	testAuthorization
	calls atomic.Uint32
	after atomic.Uint32
	fatal atomic.Bool
}

func (a *writeGateAuthorization) Check() error {
	n := a.calls.Add(1)
	if after := a.after.Load(); after != 0 && n >= after {
		if a.fatal.Load() {
			return errAuthorizationRejected
		}
		return timev4.ErrPending
	}
	return nil
}

func TestWriteOperationFinalAcceptanceGateSchedulesPauseAndSettlesFailure(t *testing.T) {
	for _, fatal := range []bool{false, true} {
		t.Run(map[bool]string{false: "pause", true: "failure"}[fatal], func(t *testing.T) {
			authority := &writeGateAuthorization{}
			f := newServiceFixtureAuthorization(t, 1, [3]uint32{1}, 64, 4, authority)
			w := &serviceTestWriter{frames: make(chan []byte, 32)}
			q, _ := f.open(t, BusinessStream, 0, w)
			runWriteService(t, f)
			op := prepareWrite(t, f, q, []byte("original"), 3000)
			// Park the real coordinator so the test can deterministically change
			// authority between this pass's slab scan and final copy gate.
			f.service.mu.Lock()
			if err := op.Start(); err != nil {
				f.service.mu.Unlock()
				t.Fatal(err)
			}
			authority.calls.Store(0)
			authority.fatal.Store(fatal)
			authority.after.Store(2)
			q.mu.Lock()
			remaining, active := q.serviceOperationsLocked()
			q.mu.Unlock()
			p := op.Progress()
			authority.after.Store(0)
			f.service.mu.Unlock()
			if fatal {
				if p.Phase != protocolv4.V4WritePhaseTerminal || p.TerminalReason != protocolv4.V4WriteTerminalReasonStreamTerminated {
					t.Fatal("terminal authority loss parked until operation timeout", p)
				}
			} else {
				if !active || remaining > 10 || p.AcceptedBytes != 0 || p.Phase != protocolv4.V4WritePhaseRunning {
					t.Fatal("final gate pause lost bounded recovery wake", remaining, active, p)
				}
				if p := awaitWriteTerminal(t, op); p.TerminalReason != protocolv4.V4WriteTerminalReasonComplete {
					t.Fatal("recovered authority lost the original input", p)
				}
			}
		})
	}
}

func TestWriteOperationAuthorizationRecoveryWithoutSendEvent(t *testing.T) {
	authority := &writeGateAuthorization{}
	f := newServiceFixtureAuthorization(t, 1, [3]uint32{1}, 64, 4, authority)
	w := &serviceTestWriter{frames: make(chan []byte, 32)}
	q, _ := f.open(t, BusinessStream, 0, w)
	runWriteService(t, f)
	op := prepareWrite(t, f, q, []byte("resumed"), 3000)
	f.service.mu.Lock()
	if err := op.Start(); err != nil {
		f.service.mu.Unlock()
		t.Fatal(err)
	}
	authority.calls.Store(0)
	authority.after.Store(1)
	f.service.mu.Unlock()
	until := time.Now().Add(2 * time.Second)
	for authority.calls.Load() < 4 {
		if time.Now().After(until) {
			t.Fatal("paused acceptance did not retain a bounded recovery check")
		}
		runtime.Gosched()
	}
	authority.after.Store(0) // Deliberately no crypto-slot or queue notification.
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	p, err := op.Wait(ctx)
	if err != nil || p.AcceptedBytes != 7 || p.TerminalReason != protocolv4.V4WriteTerminalReasonComplete {
		t.Fatal("healthy operation clock hid authorization recovery", p, err)
	}
}
