package sessionv4

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

func readyExecutorFixture(t *testing.T, ready, residentReady uint32) *executorFixture {
	return newExecutorConfigFixture(t, ApplicationExecutorConfig{Running: 2, ResidentRunning: 1, Ready: ready, ResidentReady: residentReady, CompletionRunning: 1, CompletionReserved: 2, RuntimeBytes: 4096, RuntimeBytesPerTask: 65536})
}
func holdOrdinaryPermit(t *testing.T, f *executorFixture) *ApplicationPermit {
	t.Helper()
	task, input := f.job(t, 1)
	permit, err := f.executor.TryAcquire(ApplicationShort, task, input)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(permit.Close)
	return permit
}
func readyGroup(t *testing.T, e *ApplicationExecutor) *applicationGroup {
	t.Helper()
	g, err := e.newApplicationGroup()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.cancelApplicationGroup(g) })
	return g
}
func enqueueTestApplication(t *testing.T, f *executorFixture, g *applicationGroup, class ApplicationWorkClass, work func()) *QueuedApplicationTask {
	t.Helper()
	task, input := f.job(t, 1)
	q, err := f.executor.queueApplication(g, class, task, input, work)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { q.Cancel() })
	return q
}
func awaitApplicationTask(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("original task did not finish")
	}
}

func TestApplicationReadyRejectsFullAndResidentFloorBeforeTakingReferences(t *testing.T) {
	f := readyExecutorFixture(t, 3, 1)
	holdOrdinaryPermit(t, f)
	holdOrdinaryPermit(t, f)
	g := readyGroup(t, f.executor)
	enqueueTestApplication(t, f, g, ApplicationResident, func() { t.Error("queued resident ran") })
	task, input := f.job(t, 1)
	before := f.root.Snapshot()
	if _, err := f.executor.queueApplication(g, ApplicationResident, task, input, func() {}); !errors.Is(err, cryptov4.ErrCapacity) {
		t.Fatal(err)
	}
	if task.Check() != nil || input.Check() != nil || f.root.Snapshot() != before {
		t.Fatal("resident rejection moved original references")
	}
	enqueueTestApplication(t, f, g, ApplicationShort, func() { t.Error("queued short ran") })
	enqueueTestApplication(t, f, g, ApplicationShort, func() { t.Error("queued short ran") })
	before = f.root.Snapshot()
	if _, err := f.executor.queueApplication(g, ApplicationShort, task, input, func() {}); !errors.Is(err, cryptov4.ErrCapacity) {
		t.Fatal(err)
	}
	if task.Check() != nil || f.root.Snapshot() != before {
		t.Fatal("full queue rejection moved original references")
	}
	if s := f.executor.Snapshot(); s.Ready != 3 || s.ResidentReady != 1 || s.Running != 2 {
		t.Fatal(s)
	}
}

func TestApplicationReadyAlternatesClassesAndSessionGroupsWithFIFOWithinGroup(t *testing.T) {
	f := readyExecutorFixture(t, 8, 4)
	first := holdOrdinaryPermit(t, f)
	second := holdOrdinaryPermit(t, f)
	a, b := readyGroup(t, f.executor), readyGroup(t, f.executor)
	entered := make(chan string, 6)
	release := make(chan struct{})
	var once sync.Once
	defer func() { once.Do(func() { close(release) }); second.Close(); waitExecutorIdle(t, f.executor) }()
	add := func(g *applicationGroup, class ApplicationWorkClass, name string) {
		enqueueTestApplication(t, f, g, class, func() { entered <- name; <-release })
	}
	add(a, ApplicationResident, "resident-a1")
	add(a, ApplicationShort, "short-a1")
	add(a, ApplicationShort, "short-a2")
	add(a, ApplicationResident, "resident-a2")
	add(b, ApplicationResident, "resident-b")
	add(b, ApplicationShort, "short-b")
	first.Close()
	for _, want := range []string{"short-a1", "resident-a1", "short-b", "resident-b", "short-a2", "resident-a2"} {
		select {
		case got := <-entered:
			if got != want {
				t.Fatalf("dispatch %q, want %q", got, want)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("fair queue stalled")
		}
		release <- struct{}{}
	}
}

func TestApplicationReadyStaleCancellationCannotTouchReusedSlot(t *testing.T) {
	f := readyExecutorFixture(t, 2, 1)
	holdOrdinaryPermit(t, f)
	holdOrdinaryPermit(t, f)
	g := readyGroup(t, f.executor)
	old := enqueueTestApplication(t, f, g, ApplicationShort, func() { t.Error("canceled callback ran") })
	if !old.Cancel() || !old.Canceled() || old.Started() {
		t.Fatal("failed original cancel")
	}
	awaitApplicationTask(t, old.Done())
	next := enqueueTestApplication(t, f, g, ApplicationShort, func() { t.Error("replacement callback ran") })
	if old.index != next.index {
		t.Fatal("fixture did not reuse slot")
	}
	if old.Cancel() || next.Canceled() || f.executor.Snapshot().Ready != 1 {
		t.Fatal("stale handle canceled replacement")
	}
	f.executor.Close()
	awaitApplicationTask(t, next.Done())
	if !next.Canceled() || next.Started() || next.executor.Load() != nil {
		t.Fatal("root close left queued application attached")
	}
}

func TestApplicationReadyChecksOriginalTenantAtDispatch(t *testing.T) {
	f := readyExecutorFixture(t, 2, 1)
	first := holdOrdinaryPermit(t, f)
	holdOrdinaryPermit(t, f)
	g := readyGroup(t, f.executor)
	tenant, err := f.root.Account(resourcev4.AccountKey{Kind: resourcev4.TenantAccount, ID: [16]byte{7}}, resourcev4.Vector{resourcev4.SDKBytes: 1024 * 1024, resourcev4.Items: 10, resourcev4.Tasks: 2, resourcev4.WorkSlots: 2})
	if err != nil {
		t.Fatal(err)
	}
	task := f.reserve(t, 1, f.executor.TaskCharge(), tenant)
	input := f.reserve(t, 1, resourcev4.Vector{resourcev4.SDKBytes: 128, resourcev4.Items: 1}, tenant)
	var entered atomic.Bool
	q, err := f.executor.queueApplication(g, ApplicationShort, task, input, func() { entered.Store(true) })
	if err != nil {
		t.Fatal(err)
	}
	input.Release()
	tenant.Close()
	first.Close()
	awaitApplicationTask(t, q.Done())
	if entered.Load() || q.Started() || !q.Canceled() {
		t.Fatal("closed original tenant entered callback")
	}
	if used, _ := tenant.Usage(); used != (resourcev4.Vector{}) {
		t.Fatal("failed dispatch retained original input", used)
	}
}

func TestApplicationReadySessionCloseKeepsActualCallbackDefers(t *testing.T) {
	f := readyExecutorFixture(t, 3, 1)
	p := applicationTestPlan(t, f, SessionPlanConfig{RuntimeBytes: 4096, AuthorizeApplication: func(context.Context, AuthenticatedRequestContext) (AuthorizeApplicationResult, error) {
		return AuthorizeApplicationResult{}, nil
	}})
	entered, tail, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	running := enqueueTestApplication(t, f, p.applicationGroup, ApplicationResident, func() { defer func() { close(tail); <-release }(); close(entered); runtime.Goexit() })
	awaitApplicationTask(t, entered)
	awaitApplicationTask(t, tail)
	holdOrdinaryPermit(t, f)
	queued := enqueueTestApplication(t, f, p.applicationGroup, ApplicationShort, func() { t.Error("closed Session dispatched") })
	p.Close()
	awaitApplicationTask(t, queued.Done())
	if !queued.Canceled() || running.Cancel() || !running.Started() {
		t.Fatal("close confused queued and running ownership")
	}
	if err := p.Retire(); !errors.Is(err, cryptov4.ErrCapacity) {
		t.Fatal("retired actual callback tail", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := p.releaseAfterCleanup(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("cleanup skipped actual callback tail", err)
	}
	select {
	case <-running.Done():
		t.Fatal("Goexit defer reported complete early")
	default:
	}
	once.Do(func() { close(release) })
	awaitApplicationTask(t, running.Done())
	if err := p.releaseAfterCleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := p.Retire(); err != nil {
		t.Fatal(err)
	}
}

func TestApplicationReadyGroupIdentityCannotCrossRootsOrReopen(t *testing.T) {
	f, other := readyExecutorFixture(t, 2, 1), readyExecutorFixture(t, 2, 1)
	g := readyGroup(t, other.executor)
	task, input := f.job(t, 1)
	before := f.root.Snapshot()
	if _, err := f.executor.queueApplication(g, ApplicationShort, task, input, func() {}); !errors.Is(err, cryptov4.ErrConfiguration) {
		t.Fatal(err)
	}
	if f.root.Snapshot() != before || task.Check() != nil {
		t.Fatal("foreign group moved resources")
	}
	own := readyGroup(t, f.executor)
	f.executor.cancelApplicationGroup(own)
	if _, err := f.executor.queueApplication(own, ApplicationShort, task, input, func() {}); !errors.Is(err, cryptov4.ErrConfiguration) {
		t.Fatal("closed group reopened", err)
	}
}

func TestApplicationReadyNewSessionsCannotOvertakeExistingTurn(t *testing.T) {
	f := readyExecutorFixture(t, 6, 2)
	first, second := holdOrdinaryPermit(t, f), holdOrdinaryPermit(t, f)
	a, b := readyGroup(t, f.executor), readyGroup(t, f.executor)
	entered := make(chan string, 4)
	release := make(chan struct{})
	defer func() { close(release); second.Close(); waitExecutorIdle(t, f.executor) }()
	add := func(g *applicationGroup, name string) {
		enqueueTestApplication(t, f, g, ApplicationShort, func() { entered <- name; <-release })
	}
	add(a, "a1")
	add(a, "a2")
	add(b, "b")
	first.Close()
	if got := <-entered; got != "a1" {
		t.Fatal(got)
	}
	add(readyGroup(t, f.executor), "new-session")
	for _, want := range []string{"b", "a2", "new-session"} {
		release <- struct{}{}
		select {
		case got := <-entered:
			if got != want {
				t.Fatalf("got %s, want %s", got, want)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("fair queue stalled")
		}
	}
}

func TestApplicationReadyCancelRacingDispatchHasExactlyOneOutcome(t *testing.T) {
	f := readyExecutorFixture(t, 2, 1)
	second := holdOrdinaryPermit(t, f)
	g := readyGroup(t, f.executor)
	for range 32 {
		permitTask, permitInput := f.job(t, 1)
		permit, err := f.executor.TryAcquire(ApplicationShort, permitTask, permitInput)
		if err != nil {
			t.Fatal(err)
		}
		task, input := f.job(t, 1)
		var called atomic.Uint32
		q, err := f.executor.queueApplication(g, ApplicationShort, task, input, func() { called.Add(1) })
		if err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); <-start; permit.Close() }()
		go func() { defer wg.Done(); <-start; q.Cancel() }()
		close(start)
		wg.Wait()
		awaitApplicationTask(t, q.Done())
		if q.Canceled() == q.Started() || q.Started() != (called.Load() == 1) || called.Load() > 1 {
			t.Fatal("cancel/start double outcome", q.Canceled(), q.Started(), called.Load())
		}
		permitInput.Release()
		input.Release()
	}
	second.Close()
}

func TestSessionApplicationQueuedAuthorizationUsesOriginalCaller(t *testing.T) {
	f := readyExecutorFixture(t, 2, 1)
	first, second := holdOrdinaryPermit(t, f), holdOrdinaryPermit(t, f)
	var calls atomic.Uint32
	p := applicationTestPlan(t, f, SessionPlanConfig{RuntimeBytes: 4096, AuthorizeApplication: func(_ context.Context, c AuthenticatedRequestContext) (AuthorizeApplicationResult, error) {
		calls.Add(1)
		lease, err := c.ReserveLease(c.Binding(), nil, func(context.Context) error { return nil })
		return AuthorizeApplicationResult{Lease: lease}, err
	}})
	p.claimed = true
	result := make(chan error, 1)
	go func() { result <- p.authorize(context.Background(), ApplicationBinding{}, func() error { return nil }) }()
	waitAuthorizationReady(t, f.executor)
	if calls.Load() != 0 {
		t.Fatal("ready authorization entered without ordinary position")
	}
	first.Close()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("authorization queue stalled")
	}
	if calls.Load() != 1 {
		t.Fatal("authorization dispatched more than once", calls.Load())
	}
	second.Close()
}
func waitAuthorizationReady(t *testing.T, e *ApplicationExecutor) {
	t.Helper()
	until := time.Now().Add(3 * time.Second)
	for e.Snapshot().Ready != 1 {
		if time.Now().After(until) {
			t.Fatal("authorization did not become ready", e.Snapshot())
		}
		runtime.Gosched()
	}
}
func TestSessionApplicationQueuedAuthorizationCancellationDetachesCapability(t *testing.T) {
	for _, closePlan := range []bool{false, true} {
		t.Run(map[bool]string{false: "context", true: "session"}[closePlan], func(t *testing.T) {
			f := readyExecutorFixture(t, 2, 1)
			first, second := holdOrdinaryPermit(t, f), holdOrdinaryPermit(t, f)
			var calls atomic.Uint32
			p := applicationTestPlan(t, f, SessionPlanConfig{RuntimeBytes: 4096, AuthorizeApplication: func(context.Context, AuthenticatedRequestContext) (AuthorizeApplicationResult, error) {
				calls.Add(1)
				return AuthorizeApplicationResult{}, nil
			}})
			p.claimed = true
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := make(chan error, 1)
			go func() { result <- p.authorize(ctx, ApplicationBinding{}, func() error { return nil }) }()
			waitAuthorizationReady(t, f.executor)
			if closePlan {
				p.Close()
			} else {
				cancel()
			}
			select {
			case err := <-result:
				if !errors.Is(err, cryptov4.ErrClosed) {
					t.Fatal("canceled authorization outcome", err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("canceled ready authorization retained caller")
			}
			p.invocation.mu.Lock()
			detached := p.invocation.lease == nil && p.invocation.ctx == nil
			p.invocation.mu.Unlock()
			if !detached || calls.Load() != 0 || f.executor.Snapshot().Ready != 0 {
				t.Fatal("canceled ready authorization entered callback or retained capability")
			}
			first.Close()
			second.Close()
		})
	}
}

func TestApplicationReadyPreparedPositionHasNoDispatchRightAndClosesWithGroup(t *testing.T) {
	f := readyExecutorFixture(t, 2, 1)
	group, err := f.executor.newApplicationGroup()
	if err != nil {
		t.Fatal(err)
	}
	backing := f.reserve(t, 1, resourcev4.Vector{resourcev4.SDKBytes: 512, resourcev4.Items: 1})
	task := f.reserve(t, 1, f.executor.TaskCharge())
	q, err := f.executor.prepareApplication(group, ApplicationShort, task, backing)
	if err != nil {
		t.Fatal(err)
	}
	if q.Started() || f.executor.Snapshot().Ready != 1 || f.executor.Snapshot().Running != 0 {
		t.Fatal("private reservation dispatched")
	}
	f.executor.cancelApplicationGroup(group)
	awaitApplicationTask(t, q.Done())
	if err := q.startPrepared(func() { t.Error("closed reservation ran") }); err == nil {
		t.Fatal("closed position reopened")
	}
	if f.executor.Snapshot().Ready != 0 {
		t.Fatal("closed group retained private position")
	}
}
