package sessionv4

import (
	"context"
	"errors"
	"fmt"
	"math"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/diagnosticv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

type diagnosticFixture struct {
	*executorFixture
	sink    *DiagnosticSink
	seconds atomic.Int64
}

func diagnosticReceive[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(5 * time.Second):
		t.Fatal("diagnostic delivery did not arrive")
	}
	var zero T
	return zero
}

func diagnosticUntil(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("diagnostic task did not reach expected state")
		}
		runtime.Gosched()
	}
}

func newDiagnosticFixture(t *testing.T, c DiagnosticSinkConfig, callback func(context.Context, diagnosticv4.Event), sample func(uint16) bool) *diagnosticFixture {
	t.Helper()
	f := &diagnosticFixture{executorFixture: &executorFixture{config: ApplicationExecutorConfig{Diagnostics: true, Running: 1, CompletionRunning: 1, CompletionReserved: 1, RuntimeBytes: 4096, RuntimeBytesPerTask: 64 * 1024}}}
	f.seconds.Store(1800)
	config := resourcev4.Config{ProfileRevision: [32]byte{1}, AccountSlots: 8, ReservationSlots: 64, ReferenceSlots: 128, Limit: resourcev4.Vector{resourcev4.SDKBytes: 16 * 1024 * 1024, resourcev4.Items: 20000, resourcev4.Tasks: 32, resourcev4.WorkSlots: 32, resourcev4.Timers: 8}}
	var err error
	f.root, err = resourcev4.NewRoot(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		f.root.Close()
		if got := f.root.Snapshot(); !got.CleanupComplete {
			t.Error("diagnostic root leaked", got)
		}
	})
	executorCharge, err := ApplicationExecutorCharge(f.config)
	if err != nil {
		t.Fatal(err)
	}
	f.executor, err = NewApplicationExecutor(f.config, f.reserve(t, 1, executorCharge))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		f.executor.Close()
		diagnosticUntil(t, func() bool { return f.executor.Snapshot().CleanupComplete })
	})
	if callback != nil {
		if c.RuntimeBytes == 0 {
			c.RuntimeBytes = 16384
		}
		if c.RuntimeBytesPerTask == 0 {
			c.RuntimeBytesPerTask = 64 * 1024
		}
		charge, err := DiagnosticSinkCharge(c)
		if err != nil {
			t.Fatal(err)
		}
		if sample == nil {
			sample = func(uint16) bool { return true }
		}
		f.sink, err = newDiagnosticSink(c, f.executor, f.reserve(t, 2, charge), callback, func() time.Time { return time.Unix(f.seconds.Load(), 0) }, sample)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			f.sink.Close()
			diagnosticUntil(t, func() bool { return f.sink.CleanupStatus().Status == protocolv4.V4CleanupStateComplete })
		})
	}
	return f
}

func (f *diagnosticFixture) begin(t *testing.T) (operation *DiagnosticOperation) {
	t.Helper()
	diagnosticUntil(t, func() bool { operation = f.sink.Begin(); return operation != nil })
	t.Cleanup(operation.Close)
	return
}

func diagnosticEmit(t *testing.T, op *DiagnosticOperation, fields diagnosticv4.Fields) {
	t.Helper()
	diagnosticUntil(t, func() bool { return op.Emit(fields) })
}

func TestDiagnosticLaneIndependentCapacityTransferAndRealTails(t *testing.T) {
	f := newDiagnosticFixture(t, DiagnosticSinkConfig{}, nil, nil)
	ordinaryCharge, input := f.job(t, 2)
	ordinary, err := f.executor.TryAcquire(ApplicationShort, ordinaryCharge, input)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ordinary.Close)
	completion, err := f.executor.ReserveCompletion(f.reserve(t, 2, f.executor.CompletionCharge()), input)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(completion.Close)
	backing := f.reserve(t, 2, resourcev4.Vector{resourcev4.SDKBytes: 1024, resourcev4.Items: 1})
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	var queuedCalled atomic.Uint32
	var jobs [6]*diagnosticTask
	for i := range jobs {
		borrow, err := backing.Borrow()
		if err != nil {
			t.Fatal(err)
		}
		before := f.root.Snapshot()
		jobs[i], err = f.executor.enqueueDiagnostic(context.Background(), borrow, func(ctx context.Context) {
			if i >= 2 {
				queuedCalled.Add(1)
				return
			}
			defer func() { <-release }()
			entered <- struct{}{}
			<-ctx.Done()
		}, nil)
		if err != nil || borrow.CheckRetained() == nil || f.root.Snapshot() != before {
			t.Fatal("event charge was copied or lost", err)
		}
		if i < 2 {
			<-entered
		}
	}
	if snapshot := f.executor.Snapshot(); snapshot.DiagnosticRunning != 2 || snapshot.DiagnosticReady != 4 || snapshot.Running != 1 || snapshot.CompletionReserved != 1 {
		t.Fatal(snapshot)
	}
	refused, _ := backing.Borrow()
	if _, err := f.executor.enqueueDiagnostic(context.Background(), refused, func(context.Context) {}, nil); !errors.Is(err, cryptov4.ErrCapacity) || refused.Check() != nil {
		t.Fatal("capacity refusal consumed backing", err)
	}
	refused.Release()
	before := f.root.Snapshot().Charged
	f.executor.Close()
	if snapshot := f.executor.Snapshot(); snapshot.DiagnosticRunning != 2 || snapshot.DiagnosticReady != 0 || snapshot.CleanupComplete {
		t.Fatal("cancellation returned actual running capacity", snapshot)
	}
	// Executor Close releases an unstarted ordinary permit, but diagnostic
	// callback defers and the original diagnostic backing remain charged.
	if got := f.root.Snapshot().Charged; got[resourcev4.Tasks] != before[resourcev4.Tasks]-1 {
		t.Fatal("running diagnostic stacks refunded", before, got)
	}
	for i := 2; i < len(jobs); i++ {
		select {
		case <-jobs[i].done:
		default:
			t.Fatal("ready callback survived close")
		}
	}
	for i := range 2 {
		select {
		case <-jobs[i].done:
			t.Fatal("callback defer treated as exited")
		default:
		}
	}
	once.Do(func() { close(release) })
	for _, job := range jobs {
		<-job.done
	}
	if queuedCalled.Load() != 0 {
		t.Fatal("queued callback entered after close")
	}
}

func TestDiagnosticLaneStaleHandlePanicGoexitAndOverflow(t *testing.T) {
	f := newDiagnosticFixture(t, DiagnosticSinkConfig{}, nil, nil)
	backing := f.reserve(t, 2, resourcev4.Vector{resourcev4.SDKBytes: 1024, resourcev4.Items: 1})
	var stale *diagnosticTask
	for _, work := range []func(context.Context){func(context.Context) { panic("private callback panic") }, func(context.Context) { runtime.Goexit() }} {
		borrow, _ := backing.Borrow()
		h, err := f.executor.enqueueDiagnostic(context.Background(), borrow, work, nil)
		if err != nil {
			t.Fatal(err)
		}
		<-h.done
		if h.executor.Load() != nil {
			t.Fatal("completed alias retained executor")
		}
		stale = h
	}
	entered, release := make(chan context.Context, 1), make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	borrow, _ := backing.Borrow()
	h, err := f.executor.enqueueDiagnostic(context.Background(), borrow, func(ctx context.Context) { entered <- ctx; <-release }, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := <-entered
	stale.cancel(context.Canceled)
	if ctx.Err() != nil {
		t.Fatal("stale handle cancelled a replacement")
	}
	once.Do(func() { close(release) })
	<-h.done
	for _, c := range []ApplicationExecutorConfig{
		{Diagnostics: true, RuntimeBytes: math.MaxUint64, RuntimeBytesPerTask: 1},
		{Diagnostics: true, RuntimeBytes: 1, RuntimeBytesPerTask: math.MaxUint64 / 2},
	} {
		if _, err := diagnosticLaneCharge(c); err == nil {
			t.Fatal("diagnostic byte charge overflow accepted")
		}
	}
	if _, err := f.executor.enqueueDiagnostic(context.Background(), backing, func(context.Context) {}, nil); !errors.Is(err, resourcev4.ErrOwner) || backing.Check() != nil {
		t.Fatal("primary owner accepted as moved borrow", err)
	}
}

func TestDiagnosticSinkRotationPurgesQueueAndCancelsReadyCallbacks(t *testing.T) {
	type delivery struct {
		event diagnosticv4.Event
		ctx   context.Context
	}
	entered := make(chan delivery, 8)
	release := make(chan struct{})
	var once sync.Once
	f := newDiagnosticFixture(t, DiagnosticSinkConfig{OperationSlots: 4, QueueEvents: 16}, func(ctx context.Context, event diagnosticv4.Event) {
		entered <- delivery{event, ctx}
		<-ctx.Done()
		<-release
	}, nil)
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	op := f.begin(t)
	for range 2 {
		diagnosticEmit(t, op, diagnosticv4.Fields{Phase: diagnosticv4.PhasePrepare})
	}
	first, second := diagnosticReceive(t, entered), diagnosticReceive(t, entered)
	if first.event.CorrelationID() != second.event.CorrelationID() {
		t.Fatal("one operation changed ID inside bucket")
	}
	for range 4 {
		diagnosticEmit(t, op, diagnosticv4.Fields{Phase: diagnosticv4.PhaseSpend})
	}
	diagnosticUntil(t, func() bool { return f.executor.Snapshot().DiagnosticReady == 4 })
	f.seconds.Add(900)
	f.sink.wakePump()
	diagnosticUntil(t, func() bool {
		f.sink.mu.Lock()
		defer f.sink.mu.Unlock()
		return f.sink.bucket == 3 && f.sink.queued == 0 && f.executor.Snapshot().DiagnosticReady == 0
	})
	if first.ctx.Err() == nil || second.ctx.Err() == nil {
		t.Fatal("previous bucket callback not cancelled")
	}
	f.sink.mu.Lock()
	newID := f.sink.operations[op.index].id
	for i := range f.sink.deliveries {
		if f.sink.deliveries[i].event != (diagnosticv4.Event{}) {
			t.Error("expired SDK event retained")
		}
	}
	f.sink.mu.Unlock()
	if newID == first.event.CorrelationID() {
		t.Fatal("live operation kept cross-bucket ID")
	}
	if got := f.sink.Counters(diagnosticv4.MetricDiagnosticDrop).Total; got < 4 {
		t.Fatal("expired ready entries not counted", got)
	}
	once.Do(func() { close(release) })
	diagnosticUntil(t, func() bool { return f.executor.Snapshot().DiagnosticRunning == 0 })
	diagnosticEmit(t, op, diagnosticv4.Fields{Phase: diagnosticv4.PhaseActivate})
	third := diagnosticReceive(t, entered)
	if third.event.CorrelationID() != newID || third.event.Fields().Phase != diagnosticv4.PhaseActivate {
		t.Fatal(third.event)
	}
	// A backwards wall-clock change also rotates; it cannot resurrect an ID.
	f.seconds.Add(-900)
	f.sink.wakePump()
	diagnosticUntil(t, func() bool { f.sink.mu.Lock(); defer f.sink.mu.Unlock(); return f.sink.bucket == 2 })
	f.sink.mu.Lock()
	rollbackID := f.sink.operations[op.index].id
	f.sink.mu.Unlock()
	if rollbackID == first.event.CorrelationID() || rollbackID == newID {
		t.Fatal("clock rollback resurrected correlation")
	}
}

func TestDiagnosticSinkCloseRetainsRealTailAndDetachesOperations(t *testing.T) {
	entered, release := make(chan context.Context, 1), make(chan struct{})
	var once sync.Once
	f := newDiagnosticFixture(t, DiagnosticSinkConfig{OperationSlots: 2, QueueEvents: 4}, func(ctx context.Context, _ diagnosticv4.Event) {
		defer func() { <-release }()
		entered <- ctx
		<-ctx.Done()
	}, nil)
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	op := f.begin(t)
	diagnosticEmit(t, op, diagnosticv4.Fields{})
	ctx := diagnosticReceive(t, entered)
	before := f.root.Snapshot().Charged
	status := f.sink.Close()
	if ctx.Err() == nil || status.Status != protocolv4.V4CleanupStateCleanupIncomplete || status.PendingCallbacks != 1 || f.root.Snapshot().Charged != before {
		t.Fatal("logical close refunded a real tail", status)
	}
	if op.sink.Load() != nil || op.Emit(diagnosticv4.Fields{}) || f.sink.Begin() != nil {
		t.Fatal("sink continued after close")
	}
	timeout, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	status, err := f.sink.WaitCleanup(timeout)
	if !errors.Is(err, ErrDiagnosticCleanupIncomplete) || status.Status != protocolv4.V4CleanupStateCleanupIncomplete || status.Validate() != nil {
		t.Fatal(status, err)
	}
	if f.sink.Counters(diagnosticv4.MetricCleanupTimeout).Total != 1 {
		t.Fatal("cleanup timeout not counted")
	}
	once.Do(func() { close(release) })
	status, err = f.sink.WaitCleanup(context.Background())
	if err != nil || status.Status != protocolv4.V4CleanupStateComplete || status.PendingCallbacks != 0 || status.Validate() != nil {
		t.Fatal(status, err)
	}
	if fmt.Sprintf("%#v %+v", f.sink, op) != "DiagnosticSink DiagnosticOperation" {
		t.Fatal("debug exposed owner graph")
	}
}

func TestDiagnosticSinkCapsSamplingAndNoProducerWait(t *testing.T) {
	f := newDiagnosticFixture(t, DiagnosticSinkConfig{OperationSlots: 2, QueueEvents: 4}, func(context.Context, diagnosticv4.Event) {}, func(uint16) bool { return false })
	op := f.begin(t)
	f.sink.mu.Lock()
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		if op.Emit(diagnosticv4.Fields{}) || f.sink.Begin() != nil {
			t.Error("producer entered a busy sink")
		}
	}()
	select {
	case <-finished:
	case <-time.After(time.Second):
		f.sink.mu.Unlock()
		t.Fatal("diagnostic gate blocked producer")
	}
	f.sink.mu.Unlock()
	diagnosticEmit(t, op, diagnosticv4.Fields{})
	diagnosticUntil(t, func() bool { f.sink.mu.Lock(); defer f.sink.mu.Unlock(); return f.sink.queued == 0 })
	if f.executor.Snapshot().DiagnosticRunning != 0 {
		t.Fatal("unsampled event entered callback service")
	}
	if f.sink.policy.sample != 100 {
		t.Fatal("default sampling must be 1%")
	}
	zero := uint16(0)
	quiet := newDiagnosticFixture(t, DiagnosticSinkConfig{SampleBasisPoints: &zero, OperationSlots: 2, QueueEvents: 4}, func(context.Context, diagnosticv4.Event) { t.Error("zero sampling delivered") }, nil)
	quietOp := quiet.begin(t)
	if quietOp.Emit(diagnosticv4.Fields{}) {
		t.Fatal("zero sampling queued an event")
	}
	quiet.sink.counters.Observe(diagnosticv4.MetricConnectionAttempt, diagnosticv4.Fields{})
	if quiet.sink.Counters(diagnosticv4.MetricConnectionAttempt).Total != 1 {
		t.Fatal("aggregate counter was sampled")
	}
	aboveLimit := uint16(101)
	for _, c := range []DiagnosticSinkConfig{
		{SampleBasisPoints: &aboveLimit, RuntimeBytes: 1, RuntimeBytesPerTask: 1},
		{OperationSlots: 1025, RuntimeBytes: 1, RuntimeBytesPerTask: 1},
		{QueueEvents: 4097, RuntimeBytes: 1, RuntimeBytesPerTask: 1},
		{RuntimeBytes: math.MaxUint64, RuntimeBytesPerTask: 1},
	} {
		if _, err := DiagnosticSinkCharge(c); err == nil {
			t.Fatal("invalid cap accepted", c)
		}
	}
}

func TestDiagnosticSinkPerBucketIDAndEventCeilings(t *testing.T) {
	f := newDiagnosticFixture(t, DiagnosticSinkConfig{OperationSlots: 2, QueueEvents: 16}, func(context.Context, diagnosticv4.Event) {}, nil)
	ids := make(map[[16]byte]bool)
	for range diagnosticMaxIDs {
		op := f.begin(t)
		f.sink.mu.Lock()
		id := f.sink.operations[op.index].id
		f.sink.mu.Unlock()
		if id == ([16]byte{}) || ids[id] {
			t.Fatal("random correlation reused")
		}
		ids[id] = true
		op.Close()
	}
	if f.sink.Begin() != nil {
		t.Fatal("per-bucket ID cap recycled after operation close")
	}
	f.seconds.Add(900)
	f.sink.wakePump()
	diagnosticUntil(t, func() bool { f.sink.mu.Lock(); defer f.sink.mu.Unlock(); return f.sink.bucket == 3 })
	op := f.begin(t)
	deadline := time.Now().Add(10 * time.Second)
	for {
		f.sink.mu.Lock()
		atLimit := f.sink.events == diagnosticMaxEvents
		if f.sink.queueBytes > diagnosticMaxQueueBytes {
			t.Error("queue byte cap")
		}
		f.sink.mu.Unlock()
		if atLimit {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("event cap was not reached")
		}
		op.Emit(diagnosticv4.Fields{})
		runtime.Gosched()
	}
	if op.Emit(diagnosticv4.Fields{}) {
		t.Fatal("per-bucket event ceiling exceeded")
	}
}

func TestDiagnosticSinkRootShutdownAndDisabledLane(t *testing.T) {
	f := newDiagnosticFixture(t, DiagnosticSinkConfig{OperationSlots: 2, QueueEvents: 4}, func(context.Context, diagnosticv4.Event) {}, nil)
	f.executor.Close()
	diagnosticUntil(t, func() bool { return f.sink.CleanupStatus().Status == protocolv4.V4CleanupStateComplete })
	disabled := newExecutorFixture(t, 1, 0)
	ref := disabled.reserve(t, 2, resourcev4.Vector{resourcev4.SDKBytes: 1024, resourcev4.Items: 1})
	if _, err := NewDiagnosticSink(DiagnosticSinkConfig{RuntimeBytes: 1, RuntimeBytesPerTask: 1}, disabled.executor, ref, func(context.Context, diagnosticv4.Event) {}); !errors.Is(err, resourcev4.ErrClosed) || ref.Check() != nil {
		t.Fatal("enabled diagnostics after original executor admission", err)
	}
}
