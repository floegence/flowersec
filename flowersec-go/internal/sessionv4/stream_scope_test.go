package sessionv4

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

type scopeFixture struct {
	*serviceFixture
	executor *ApplicationExecutor
	options  StreamScopeOptions
	h        OpenHandle
	peerFlow *StreamFlow
	writer   *serviceTestWriter
	queue    *SendQueue
	scope    *StreamScope
}

func newScopeFixture(t *testing.T, timeout uint64) *scopeFixture {
	return newScopeFixtureResources(t, timeout)
}

func newScopeFixtureResources(t *testing.T, timeout uint64, extra ...resourcev4.Vector) *scopeFixture {
	t.Helper()
	f := &scopeFixture{options: StreamScopeOptions{TimeoutMS: timeout, CleanupTimeoutMS: 40, RuntimeBytes: 256 * 1024}}
	config := ApplicationExecutorConfig{Running: 2, ResidentRunning: 1, RuntimeBytes: 4096, RuntimeBytesPerTask: 64 * 1024}
	e := &ApplicationExecutor{config: config}
	scopeCharge, _ := StreamScopeCharge(f.options)
	executorCharge, _ := ApplicationExecutorCharge(config)
	// One additional reference position admits the executor's input borrow;
	// the existing reservation is charged only once.
	extra = append(extra, scopeCharge, executorCharge, StreamOwnershipCharge(), e.TaskCharge(), resourcev4.Vector{}, resourcev4.Vector{})
	f.serviceFixture = newServiceFixtureResources(t, 1, [3]uint32{1}, 8, 2, testAuthorization{}, true, extra)
	var err error
	f.executor, err = NewApplicationExecutor(config, f.reserve(t, executorCharge))
	if err != nil {
		t.Fatal(err)
	}
	f.writer = &serviceTestWriter{frames: make(chan []byte, 16)}
	f.queue, f.peerFlow = f.open(t, BusinessStream, 64, f.writer)
	f.h = OpenHandle{f.local.admission, f.flows[0].receive.scope}
	f.options.HardDeadline = streamTestDeadline(t, f.local.engine)
	t.Cleanup(func() {
		f.local.admission.Close()
		if f.scope != nil {
			select {
			case <-f.scope.Done():
			case <-time.After(3 * time.Second):
				t.Error("scope retained actual cleanup owner")
			}
		}
		f.executor.Close()
		select {
		case <-f.executor.Done():
		case <-time.After(3 * time.Second):
			t.Error("callback did not exit")
		}
	})
	return f
}

func (f *scopeFixture) start(t *testing.T, ctx context.Context, callback func(context.Context, *ScopeStream) error) *StreamScope {
	t.Helper()
	charge, _ := StreamScopeCharge(f.options)
	var err error
	f.scope, err = f.local.admission.StartStreamScope(ctx, f.h, f.options, f.executor, ApplicationResident, f.reserve(t, charge), f.reserve(t, StreamOwnershipCharge()), f.reserve(t, f.executor.TaskCharge()), callback)
	if err != nil {
		t.Fatal(err)
	}
	return f.scope
}

func waitScope(t *testing.T, scope *StreamScope) (ScopeResult, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	r, err := scope.Wait(ctx)
	if errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("scope did not publish its fixed result", r)
	}
	return r, err
}

func TestStreamScopeRequiresDeliveredEOFIncludingEmptyFIN(t *testing.T) {
	for _, input := range []string{"", "unread"} {
		t.Run(input, func(t *testing.T) {
			f := newScopeFixture(t, 1000)
			deliverOwnedInput(t, f.serviceFixture, f.peerFlow, input, true)
			var escaped *ScopeStream
			s := f.start(t, context.Background(), func(_ context.Context, stream *ScopeStream) error {
				escaped = stream
				return nil
			})
			r, err := waitScope(t, s)
			if !errors.Is(err, ErrScopeExchangeIncomplete) || r.Normal || r.Close.CleanupStatus.Status != protocolv4.V4CleanupStateCleanupIncomplete {
				t.Fatal("unobserved EOF became normal scope completion", r, err)
			}
			if _, err := escaped.Write(context.Background(), []byte("late")); !errors.Is(err, ErrStreamOwned) {
				t.Fatal("escaped callback reopened I/O", err)
			}
			f.local.admission.mu.Lock()
			slot, err := f.local.admission.slot(f.h)
			cancelled := err == nil && slot.cancelled
			f.local.admission.mu.Unlock()
			if !cancelled {
				t.Fatal("incomplete exchange omitted original Reset")
			}
		})
	}
}

func TestStreamScopeNormalRequestHalfCloseResponseEOFAndAuthenticatedDrain(t *testing.T) {
	for _, cursor := range []bool{false, true} {
		scopeNormalRoundTrip(t, cursor)
	}
}

func scopeNormalRoundTrip(t *testing.T, cursorRead bool) {
	t.Helper()
	charge, _ := ScopeReaderCursorCharge(5)
	f := newScopeFixtureResources(t, 3000, charge)
	ref := f.reserve(t, charge)
	t.Cleanup(ref.Release)
	f.options.CleanupTimeoutMS = 500
	f.run(t)
	s := f.start(t, context.Background(), func(ctx context.Context, stream *ScopeStream) error {
		if n, err := stream.WriteAll(ctx, []byte("request")); err != nil || n != 7 {
			return errors.New("request acceptance failed")
		}
		if err := stream.CloseWrite(ctx); err != nil {
			return err
		}
		if cursorRead {
			target, _ := exactCursorTarget(5, 5)
			cursor := attachScopeTestCursor(t, stream, target, ref)
			r, err := cursor.ReadExactly(ctx)
			if err == nil && (string(r.Data) != "reply" || r.StreamStatus != protocolv4.V4StreamStatusEof) {
				return errors.New("cursor response handoff failed")
			}
			return err
		}
		var input [8]byte
		r, err := stream.ReadInto(ctx, input[:])
		if err == nil && (r.Progress.Filled != 5 || string(input[:5]) != "reply" || r.ReadTerminal != protocolv4.V4ReadTerminalEof) {
			return errors.New("response handoff failed")
		}
		return err
	})
	for {
		r, err := f.peer.receiver.Receive(context.Background(), nextServiceFrame(t, f.writer))
		if err != nil {
			t.Fatal(err)
		}
		frame, _ := r.Body()
		fin, _ := frame.Field("fin").Bool()
		err = f.peerFlow.Apply(r)
		r.Release()
		if err != nil {
			t.Fatal(err)
		}
		if fin {
			break
		}
	}
	deliverOwnedInput(t, f.serviceFixture, f.peerFlow, "reply", true)
	// Local FIN and callback return alone are not peer-authenticated drainage.
	select {
	case <-s.ready:
		t.Fatal("scope completed before authenticated peer proof")
	default:
	}
	if _, err := f.peer.admission.PublishDrained(context.Background(), OpenHandle{f.peer.admission, f.h.scope}, f.peer.maintenance); err != nil {
		t.Fatal(err)
	}
	applyTerminalWire(t, f.local, f.peer.control.Bytes())
	if _, err := f.local.admission.PublishDrained(context.Background(), f.h, f.local.maintenance); err != nil {
		t.Fatal(err)
	}
	applyTerminalWire(t, f.peer, f.local.control.Bytes())
	r, err := waitScope(t, s)
	if err != nil || !r.Normal || r.AcceptedBytes != 7 || !r.Close.SendDrained || r.Close.ReadTerminal != protocolv4.V4ReadTerminalEof || r.Close.CleanupStatus.Status != protocolv4.V4CleanupStateComplete {
		t.Fatal(r, err)
	}
	<-s.Done()
	if s.owner != nil || s.view != nil || s.task != nil || s.deadline != nil || s.reservation != (resourcev4.Reference{}) {
		t.Fatal("completed scope retained original transport/executor graph")
	}
}

func TestStreamScopeErrorKeepsStableAcceptanceAndLateCallbackCharge(t *testing.T) {
	f := newScopeFixture(t, 1000)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	var escaped *ScopeStream
	s := f.start(t, ctx, func(_ context.Context, stream *ScopeStream) error {
		escaped = stream
		if _, err := stream.Write(context.Background(), []byte("prefix")); err != nil {
			return err
		}
		defer func() { close(entered); <-release }()
		return nil
	})
	<-entered
	before := f.root.Snapshot().Charged
	cancel()
	r, err := waitScope(t, s)
	if !errors.Is(err, context.Canceled) || r.AcceptedBytes != 6 || r.Normal || r.Close.CleanupStatus.PendingCallbacks != 1 || f.executor.Snapshot().ResidentRunning != 1 {
		t.Fatal(r, err, f.executor.Snapshot())
	}
	if after := f.root.Snapshot().Charged; after[resourcev4.Tasks] != before[resourcev4.Tasks] {
		t.Fatal("timeout refunded callback or lifecycle tasks", before, after)
	}
	if _, err := escaped.Write(context.Background(), []byte("late")); !errors.Is(err, ErrStreamOwned) {
		t.Fatal(err)
	}
	f.local.admission.Close()
	select {
	case <-s.Done():
		t.Fatal("Session close manufactured actual callback exit")
	default:
	}
	once.Do(func() { close(release) })
	<-s.Done()
	r, err = s.Result()
	if !errors.Is(err, context.Canceled) || r.AcceptedBytes != 6 || r.Close.CleanupStatus.Status != protocolv4.V4CleanupStateComplete || r.Close.CleanupStatus.PendingCallbacks != 0 {
		t.Fatal("late exit changed original outcome", r, err)
	}
}

func TestStreamScopePreservesApplicationErrorAndGoexitCleanup(t *testing.T) {
	for _, goexit := range []bool{false, true} {
		f := newScopeFixture(t, 1000)
		cause := errors.New("application failure")
		s := f.start(t, context.Background(), func(context.Context, *ScopeStream) error {
			if goexit {
				runtime.Goexit()
			}
			return cause
		})
		_, err := waitScope(t, s)
		if goexit && !errors.Is(err, ErrScopeCallbackExit) || !goexit && err != cause {
			t.Fatal("cleanup replaced the first callback cause", err)
		}
		f.local.admission.Close()
		<-s.Done()
	}
}

func TestStreamScopeWaitCancellationDoesNotCancelOriginalOperation(t *testing.T) {
	f := newScopeFixture(t, 1000)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	s := f.start(t, context.Background(), func(context.Context, *ScopeStream) error {
		close(entered)
		<-release
		return nil
	})
	<-entered
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Wait(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if s.owner.revoked.Load() || s.failure() != nil || f.executor.Snapshot().Running != 1 {
		t.Fatal("Wait cancellation terminated original scope")
	}
	once.Do(func() { close(release) })
	if _, err := waitScope(t, s); !errors.Is(err, ErrScopeExchangeIncomplete) {
		t.Fatal(err)
	}
}

func TestStreamScopeDeadlineRetainsNoncooperativeCallback(t *testing.T) {
	f := newScopeFixture(t, 60)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	s := f.start(t, context.Background(), func(context.Context, *ScopeStream) error {
		close(entered)
		<-release
		return nil
	})
	<-entered
	r, err := waitScope(t, s)
	if !errors.Is(err, timev4.ErrExpired) || r.Normal || r.Close.CleanupStatus.PendingCallbacks != 1 {
		t.Fatal(r, err)
	}
	once.Do(func() { close(release) })
	f.local.admission.Close()
	<-s.Done()
}

func TestStreamScopeSessionCloseCancelsOriginalCallback(t *testing.T) {
	f := newScopeFixture(t, 30000)
	entered := make(chan struct{})
	s := f.start(t, context.Background(), func(ctx context.Context, stream *ScopeStream) error {
		close(entered)
		<-ctx.Done()
		return ctx.Err()
	})
	<-entered
	f.local.admission.Close()
	r, err := waitScope(t, s)
	if !errors.Is(err, cryptov4.ErrClosed) || r.Normal || r.Close.CleanupStatus.Status != protocolv4.V4CleanupStateComplete {
		t.Fatal("Session shutdown did not promptly end its scope", r, err)
	}
}

func TestStreamScopeDetachedWaitKeepsOriginalTaskReservation(t *testing.T) {
	f := newScopeFixture(t, 30000)
	releaseCallback := make(chan struct{})
	cause := errors.New("application failed")
	s := f.start(t, context.Background(), func(context.Context, *ScopeStream) error { <-releaseCallback; return cause })
	ctx := &cursorHeldWaitContext{Context: context.Background(), entered: make(chan struct{}), release: make(chan struct{})}
	var release sync.Once
	t.Cleanup(func() { release.Do(func() { close(ctx.release) }) })
	returned := make(chan error, 1)
	go func() { _, err := s.Wait(ctx); returned <- err }()
	<-ctx.entered
	close(releaseCallback)
	<-s.task.Done()
	f.local.admission.Close()
	<-s.Done()
	before := f.root.Snapshot()
	charge, _ := StreamScopeCharge(f.options)
	if before.Charged[resourcev4.Tasks] < charge[resourcev4.Tasks] || s.owner != nil || s.deadline != nil {
		t.Fatal("detached observer lost charge or kept transport authority", before)
	}
	release.Do(func() { close(ctx.release) })
	if err := <-returned; err != cause {
		t.Fatal(err)
	}
	after := f.root.Snapshot()
	if before.Reservations-after.Reservations != 1 || before.Charged[resourcev4.Tasks]-after.Charged[resourcev4.Tasks] != charge[resourcev4.Tasks] {
		t.Fatal("real observer return did not release its original alias", before, after)
	}
}

// The mechanics seam supplies the same synthetic authorization as the core
// cursor tests. Production construction still requires DeliveryAuthorization;
// this helper isolates scope settlement from credential fixture setup.
func attachScopeTestCursor(t *testing.T, v *ScopeStream, target cursorTarget, ref resourcev4.Reference) *ScopeReaderCursor {
	t.Helper()
	charge, _ := ScopeReaderCursorCharge(target.limit)
	owned, err := ref.Take(charge)
	if err != nil {
		t.Fatal(err)
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	f := v.owner.flow.receive
	f.pool.mu.Lock()
	c := newReaderCursorLocked(f, target, owned, testAuthorization{})
	c.owner, c.scopeDeadline = v.owner, v.owner.deadline
	c.scopeContext = v.owner.operationContext
	f.pool.mu.Unlock()
	v.cursor = &ScopeReaderCursor{view: v, cursor: c}
	return v.cursor
}

func TestStreamScopeClosesDormantAndUndeliveredCursor(t *testing.T) {
	for _, detached := range []bool{false, true} {
		charge, _ := ScopeReaderCursorCharge(4)
		f := newScopeFixtureResources(t, 1000, charge)
		ref := f.reserve(t, charge)
		deliverOwnedInput(t, f.serviceFixture, f.peerFlow, "data", true)
		var cursor *ScopeReaderCursor
		s := f.start(t, context.Background(), func(_ context.Context, v *ScopeStream) error {
			target, _ := exactCursorTarget(4, 4)
			cursor = attachScopeTestCursor(t, v, target, ref)
			if detached {
				cursor.cursor.mu.Lock()
				_, err := cursor.cursor.advanceLocked(true)
				cursor.cursor.mu.Unlock()
				if err != nil {
					return err
				}
			}
			return nil
		})
		r, err := waitScope(t, s)
		if !errors.Is(err, ErrScopeExchangeIncomplete) || r.Normal || !cursor.Progress().Closed || cursor.Progress().Delivered {
			t.Fatal("scope silently accepted undelivered cursor responsibility", detached, r, err, cursor.Progress())
		}
		f.local.admission.Close()
		<-s.Done()
		if cursor.cursor.scopeDeadline != nil || cursor.cursor.flow != nil || cursor.cursor.reservation != (resourcev4.Reference{}) {
			t.Fatal("scope cursor kept original graph or charge")
		}
	}
}

func TestStreamScopeLateCursorTailWakesActualCleanup(t *testing.T) {
	charge, _ := ScopeReaderCursorCharge(4)
	f := newScopeFixtureResources(t, 1000, charge)
	ref := f.reserve(t, charge)
	opCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	held := &cursorHeldWaitContext{Context: context.Background(), entered: make(chan struct{}), release: make(chan struct{})}
	var release sync.Once
	t.Cleanup(func() { release.Do(func() { close(held.release) }) })
	readerDone := make(chan error, 1)
	s := f.start(t, opCtx, func(_ context.Context, v *ScopeStream) error {
		target, _ := exactCursorTarget(4, 4)
		cursor := attachScopeTestCursor(t, v, target, ref)
		go func() { _, err := cursor.ReadExactly(held); readerDone <- err }()
		<-held.entered
		return nil
	})
	<-held.entered
	_, err := waitScope(t, s)
	if !errors.Is(err, ErrScopeExchangeIncomplete) {
		t.Fatal(err)
	}
	f.local.admission.Close()
	if err := f.service.WaitCleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-s.Done():
		t.Fatal("held cursor return tail was refunded")
	default:
	}
	release.Do(func() { close(held.release) })
	if err := <-readerDone; err == nil {
		t.Fatal("closed cursor delivered a new result")
	}
	select {
	case <-s.Done():
	case <-time.After(time.Second):
		t.Fatal("actual cursor exit failed to wake original cleanup owner")
	}
}

func TestStreamScopeDeadlineIsCheckedAtOriginalDataGates(t *testing.T) {
	f, _, peer, h, ref := ownedFixture(t, 8)
	deadline := streamTestDeadline(t, f.local.engine)
	o, err := f.local.admission.ownStream(h, ref, deadline)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { o.Revoke(); _ = o.Release() })
	deliverOwnedInput(t, f, peer, "input", false)
	// No supervisor or timer exists in this mechanics test. Expiration alone
	// must deny both actual copying gates, even with context.Background().
	_ = deadline.Tighten(0)
	if n, err := o.Write(context.Background(), []byte("late")); n != 0 || !errors.Is(err, timev4.ErrExpired) {
		t.Fatal(n, err)
	}
	if n, _, err := o.TryRead(make([]byte, 8)); n != 0 || !errors.Is(err, timev4.ErrExpired) {
		t.Fatal(n, err)
	}
	if o.AcceptedBytes() != 0 || f.flows[0].receive.delivered != 0 {
		t.Fatal("expired gate accepted or delivered application bytes")
	}
}

func TestStreamScopeCancellationIsCheckedWithoutSupervisor(t *testing.T) {
	f, _, peer, h, ref := ownedFixture(t, 8)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	o, err := f.local.admission.ownStreamContext(h, ref, streamTestDeadline(t, f.local.engine), ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { o.Revoke(); _ = o.Release() })
	deliverOwnedInput(t, f, peer, "input", false)
	cancel()
	if n, err := o.Write(context.Background(), []byte("late")); n != 0 || !errors.Is(err, context.Canceled) {
		t.Fatal(n, err)
	}
	if n, _, err := o.TryRead(make([]byte, 8)); n != 0 || !errors.Is(err, context.Canceled) {
		t.Fatal(n, err)
	}
	if err := o.enterCallback(); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled operation acquired a new callback invocation", err)
	}
	if o.AcceptedBytes() != 0 || f.flows[0].receive.delivered != 0 {
		t.Fatal("cancellation required a supervisor to fence actual bytes")
	}
}

func TestStreamScopePreparedWriteMustSettleBeforeCallbackSuccess(t *testing.T) {
	f := newScopeFixture(t, 1000)
	runWriteService(t, f.serviceFixture)
	deliverOwnedInput(t, f.serviceFixture, f.peerFlow, "", true)
	var operation *WriteOperation
	s := f.start(t, context.Background(), func(ctx context.Context, v *ScopeStream) error {
		if _, err := v.ReadInto(ctx, make([]byte, 1)); err != nil {
			return err
		}
		var err error
		operation, err = v.PrepareWrite([]byte("pending"), WriteOptions{TimeoutMS: 30000, HardDeadline: f.options.HardDeadline})
		return err
	})
	r, err := waitScope(t, s)
	if !errors.Is(err, ErrScopeExchangeIncomplete) || r.Normal || r.AcceptedBytes != 0 {
		t.Fatal("scope silently discarded a prepared write and claimed success", r, err)
	}
	if err := operation.Start(); err == nil || operation.Progress().AcceptedBytes != 0 {
		t.Fatal("escaped prepared operation regained callback submission rights", err)
	}
}

func TestStreamScopePreservesFirstCallbackCauseWhileSealingWaits(t *testing.T) {
	f := newScopeFixture(t, 1000)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered, returnNow := make(chan struct{}), make(chan struct{})
	cause := errors.New("first application failure")
	s := f.start(t, ctx, func(context.Context, *ScopeStream) error {
		close(entered)
		<-returnNow
		return cause
	})
	<-entered
	f.queue.mu.Lock()
	close(returnNow)
	until := time.Now().Add(time.Second)
	for s.failure() == nil && time.Now().Before(until) {
		runtime.Gosched()
	}
	first := s.failure()
	cancel()
	f.queue.mu.Unlock()
	if first != cause {
		t.Fatal("sealing delayed the original callback outcome", first)
	}
	if _, err := waitScope(t, s); err != cause {
		t.Fatal("cleanup cancellation replaced original application cause", err)
	}
}

func TestStreamScopeProviderTailSurvivesIncompleteResult(t *testing.T) {
	f := newScopeFixture(t, 1000)
	f.writer.entered, f.writer.release = make(chan struct{}), make(chan struct{})
	var release sync.Once
	t.Cleanup(func() { release.Do(func() { close(f.writer.release) }) })
	f.run(t)
	deliverOwnedInput(t, f.serviceFixture, f.peerFlow, "", true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := f.start(t, ctx, func(ctx context.Context, v *ScopeStream) error {
		if _, err := v.ReadInto(ctx, make([]byte, 1)); err != nil {
			return err
		}
		_, err := v.WriteAll(ctx, []byte("tail"))
		return err
	})
	<-f.writer.entered
	cancel()
	r, err := waitScope(t, s)
	if !errors.Is(err, context.Canceled) || r.AcceptedBytes != 4 || r.Close.CleanupStatus.CoreCleanup != protocolv4.V4CoreCleanupPending {
		t.Fatal(r, err)
	}
	f.local.admission.Close()
	f.queue.mu.Lock()
	retained := f.queue.storage != nil && f.queue.pumping
	f.queue.mu.Unlock()
	if !retained {
		t.Fatal("incomplete provider write lost original owned backing")
	}
	release.Do(func() { close(f.writer.release) })
	select {
	case <-s.Done():
	case <-time.After(time.Second):
		t.Fatal("late provider return did not finish original scope cleanup")
	}
	r, err = s.Result()
	if !errors.Is(err, context.Canceled) || r.AcceptedBytes != 4 || r.Close.CleanupStatus.Status != protocolv4.V4CleanupStateComplete || r.Normal {
		t.Fatal(r, err)
	}
}

func TestScopeCursorRejectsInvalidConstructionBeforeReadClaim(t *testing.T) {
	charge, _ := ScopeReaderCursorCharge(8)
	f := newScopeFixtureResources(t, 1000, charge)
	ref := f.reserve(t, charge)
	t.Cleanup(ref.Release)
	cause := errors.New("end fixture")
	s := f.start(t, context.Background(), func(_ context.Context, v *ScopeStream) error {
		if _, err := v.ExactReaderCursor(9, 8, ref, nil); !errors.Is(err, ErrCursorTarget) {
			return errors.New("invalid exact target accepted")
		}
		if _, err := v.UntilReaderCursor(nil, 8, 8, ref, nil); !errors.Is(err, ErrCursorTarget) {
			return errors.New("invalid delimiter accepted")
		}
		if _, err := v.ExactReaderCursor(8, 8, ref, nil); !errors.Is(err, ErrCursorTarget) || ref.Check() != nil {
			return errors.New("missing authority consumed original reservation")
		}
		if _, err := v.UntilReaderCursor([]byte("\n"), 8, 8, ref, &protocolv4.DeliveryAuthorization{}); err == nil {
			return errors.New("invalid original authority acquired reader")
		}
		if _, _, err := v.TryRead(make([]byte, 1)); err != nil {
			return errors.New("failed cursor constructor retained read claim")
		}
		return cause
	})
	if _, err := waitScope(t, s); err != cause {
		t.Fatal(err)
	}
}

func TestStreamScopeApplicationPanicRemainsStreamLocal(t *testing.T) {
	f := newScopeFixture(t, 1000)
	s := f.start(t, context.Background(), func(ctx context.Context, stream *ScopeStream) error {
		if _, err := stream.Write(ctx, []byte("known")); err != nil {
			return err
		}
		panic(struct{ private string }{private: "not a diagnostic"})
	})
	r, err := waitScope(t, s)
	if !errors.Is(err, ErrScopeCallbackExit) || r.AcceptedBytes != 5 || r.Normal || f.executor.Snapshot().Running != 0 {
		t.Fatal(r, err)
	}
	if err := f.local.engine.CheckApplicationAuthorization(); err != nil {
		t.Fatal("application panic closed unrelated Session work", err)
	}
	f.local.admission.Close()
	<-s.Done()
}
