package sessionv4

import (
	"errors"
	"math"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

type executorFixture struct {
	root     *resourcev4.Root
	executor *ApplicationExecutor
	config   ApplicationExecutorConfig
	serial   byte
}

func newExecutorFixture(t *testing.T, running, resident uint32, completion ...uint32) *executorFixture {
	t.Helper()
	f := &executorFixture{config: ApplicationExecutorConfig{Running: running, ResidentRunning: resident, RuntimeBytes: 4096, RuntimeBytesPerTask: 64 * 1024}}
	if len(completion) == 2 {
		f.config.CompletionRunning, f.config.CompletionReserved = completion[0], completion[1]
	}
	return newExecutorConfigFixture(t, f.config)
}

func newExecutorConfigFixture(t *testing.T, c ApplicationExecutorConfig) *executorFixture {
	t.Helper()
	f := &executorFixture{config: c}
	charge, err := ApplicationExecutorCharge(f.config)
	if err != nil {
		t.Fatal(err)
	}
	config := resourcev4.Config{ProfileRevision: [32]byte{1}, AccountSlots: 8, ReservationSlots: 32, ReferenceSlots: 64, Limit: resourcev4.Vector{resourcev4.SDKBytes: 4 * 1024 * 1024, resourcev4.Items: 128, resourcev4.Tasks: 32, resourcev4.WorkSlots: 32, resourcev4.Timers: charge[resourcev4.Timers]}}
	metadata, err := resourcev4.BackingBytes(config)
	if err != nil {
		t.Fatal(err)
	}
	config.Limit[resourcev4.SDKBytes] += metadata
	f.root, err = resourcev4.NewRoot(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		f.root.Close()
		if s := f.root.Snapshot(); !s.CleanupComplete {
			t.Error("executor leaked original task/backing", s)
		}
	})
	f.executor, err = NewApplicationExecutor(f.config, f.reserve(t, 1, charge))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		f.executor.Close()
		select {
		case <-f.executor.Done():
		case <-time.After(3 * time.Second):
			t.Error("callback never returned")
		}
	})
	return f
}

func (f *executorFixture) reserve(t *testing.T, environment byte, charge resourcev4.Vector, accounts ...resourcev4.Account) resourcev4.Reference {
	t.Helper()
	return f.reserveOwner(t, environment, charge, false, accounts...)
}
func (f *executorFixture) reserveOwner(t *testing.T, environment byte, charge resourcev4.Vector, result bool, accounts ...resourcev4.Account) resourcev4.Reference {
	t.Helper()
	f.serial++
	reserve := f.root.Reserve
	if result {
		reserve = f.root.ReserveResult
	}
	ref, err := reserve(resourcev4.OwnerKey{ProfileRevision: [32]byte{1}, Environment: [16]byte{environment}, Instance: [16]byte{f.serial}, Backing: [16]byte{f.serial}, Kind: 1}, charge, accounts...)
	if err != nil {
		t.Fatal(err, "charge", charge, "root", f.root.Snapshot())
	}
	t.Cleanup(ref.Release)
	return ref
}

func (f *executorFixture) job(t *testing.T, environment byte) (resourcev4.Reference, resourcev4.Reference) {
	return f.reserve(t, environment, f.executor.TaskCharge()), f.reserve(t, environment, resourcev4.Vector{resourcev4.SDKBytes: 128, resourcev4.Items: 1})
}

func waitExecutorIdle(t *testing.T, e *ApplicationExecutor) {
	t.Helper()
	end := time.Now().Add(3 * time.Second)
	for e.Snapshot().Running != 0 {
		if time.Now().After(end) {
			t.Fatal("actual callback tail retained", e.Snapshot())
		}
		runtime.Gosched()
	}
}

func TestApplicationExecutorResidentFloorSharesActualRootAcrossEnvironments(t *testing.T) {
	f := newExecutorFixture(t, 3, 2)
	release := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }); waitExecutorIdle(t, f.executor) })
	entered := make(chan struct{}, 3)
	work := func() { entered <- struct{}{}; <-release }
	for _, env := range []byte{1, 2} {
		task, input := f.job(t, env)
		if _, err := f.executor.TrySubmit(ApplicationResident, task, input, work); err != nil {
			t.Fatal(err)
		}
		<-entered
	}
	task, input := f.job(t, 3)
	before := f.root.Snapshot()
	if _, err := f.executor.TrySubmit(ApplicationResident, task, input, work); !errors.Is(err, cryptov4.ErrCapacity) {
		t.Fatal("another Environment bypassed resident cap", err)
	}
	if task.Check() != nil || f.root.Snapshot() != before {
		t.Fatal("failed try-now admission changed ownership")
	}
	if _, err := f.executor.TrySubmit(ApplicationShort, task, input, work); err != nil {
		t.Fatal("resident work consumed short floor", err)
	}
	<-entered
	if s := f.executor.Snapshot(); s.Running != 3 || s.ResidentRunning != 2 {
		t.Fatal(s)
	}
	lastTask, lastInput := f.job(t, 1)
	if _, err := f.executor.TrySubmit(ApplicationShort, lastTask, lastInput, work); !errors.Is(err, cryptov4.ErrCapacity) {
		t.Fatal(err)
	}
	releaseOnce.Do(func() { close(release) })
	waitExecutorIdle(t, f.executor)
	if _, err := f.executor.TrySubmit(ApplicationResident, lastTask, lastInput, func() {}); err != nil {
		t.Fatal("actual callback exit failed to return original permit", err)
	}
	waitExecutorIdle(t, f.executor)
}

func TestApplicationExecutorCloseKeepsTaskAndInputUntilActualCallbackDefersExit(t *testing.T) {
	f := newExecutorFixture(t, 2, 1)
	task, input := f.job(t, 1)
	entered, exiting, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }); waitExecutorIdle(t, f.executor) })
	job, err := f.executor.TrySubmit(ApplicationResident, task, input, func() {
		defer func() { close(exiting); <-release }()
		close(entered)
	})
	if err != nil {
		t.Fatal(err)
	}
	<-entered
	<-exiting
	input.Release()
	before := f.root.Snapshot()
	f.executor.Close()
	if s := f.executor.Snapshot(); s.CleanupComplete || s.Running != 1 || s.ResidentRunning != 1 || f.root.Snapshot().Charged != before.Charged {
		t.Fatal("logical close refunded a live callback defer or input alias", s, before, f.root.Snapshot())
	}
	select {
	case <-f.executor.Done():
		t.Fatal("cancel was reported as physical cleanup")
	default:
	}
	select {
	case <-job.Done():
		t.Fatal("callback result preceded actual defer exit")
	default:
	}
	once.Do(func() { close(release) })
	<-job.Done()
	<-f.executor.Done()
	if s := f.root.Snapshot(); s.Reservations != 0 || s.References != 0 {
		t.Fatal("late actual exit leaked original reservations", s)
	}
}

func TestApplicationExecutorRejectsSecondPhysicalPoolAndRetiredReplacement(t *testing.T) {
	f := newExecutorFixture(t, 2, 1)
	charge, _ := ApplicationExecutorCharge(f.config)
	for _, closed := range []bool{false, true} {
		if closed {
			f.executor.Close()
			<-f.executor.Done()
		}
		ref := f.reserve(t, 2, charge)
		if _, err := NewApplicationExecutor(f.config, ref); !errors.Is(err, resourcev4.ErrOwner) {
			t.Fatal("root acquired a second ordinary allowance", err)
		}
	}
}

func TestApplicationExecutorRejectsPrivateRootsAndMismatchedInvocationEnvironment(t *testing.T) {
	f, foreign := newExecutorFixture(t, 2, 1), newExecutorFixture(t, 2, 1)
	foreignTask, foreignInput := foreign.job(t, 1)
	called := atomic.Bool{}
	work := func() { called.Store(true) }
	if _, err := f.executor.TrySubmit(ApplicationShort, foreignTask, foreignInput, work); !errors.Is(err, resourcev4.ErrOwner) {
		t.Fatal(err)
	}
	task, _ := f.job(t, 1)
	_, input := f.job(t, 2)
	if _, err := f.executor.TrySubmit(ApplicationShort, task, input, work); !errors.Is(err, resourcev4.ErrOwner) {
		t.Fatal(err)
	}
	if called.Load() || task.Check() != nil || foreignTask.Check() != nil {
		t.Fatal("rejected invocation started or consumed original owner")
	}
}

func TestApplicationExecutorTaskReservationCannotStartTwoPhysicalJobs(t *testing.T) {
	f := newExecutorFixture(t, 3, 2)
	task, input := f.job(t, 1)
	release := make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }); waitExecutorIdle(t, f.executor) })
	if _, err := f.executor.TrySubmit(ApplicationShort, task, input, func() { <-release }); err != nil {
		t.Fatal(err)
	}
	before := f.root.Snapshot()
	if _, err := f.executor.TrySubmit(ApplicationShort, task, input, func() { t.Error("stale task executed") }); !errors.Is(err, resourcev4.ErrOwner) {
		t.Fatal(err)
	}
	if f.root.Snapshot() != before {
		t.Fatal("stale admission leaked input borrow")
	}
	once.Do(func() { close(release) })
	waitExecutorIdle(t, f.executor)
}

func TestApplicationExecutorEnvironmentCloseCannotRefundItsRunningCallback(t *testing.T) {
	f := newExecutorFixture(t, 2, 1)
	limit := resourcev4.Vector{resourcev4.SDKBytes: 1024 * 1024, resourcev4.Items: 8, resourcev4.Tasks: 2, resourcev4.WorkSlots: 2}
	env, err := f.root.Account(resourcev4.AccountKey{Kind: resourcev4.EnvironmentAccount, ID: [16]byte{1}}, limit)
	if err != nil {
		t.Fatal(err)
	}
	task := f.reserve(t, 1, f.executor.TaskCharge(), env)
	input := f.reserve(t, 1, resourcev4.Vector{resourcev4.SDKBytes: 128, resourcev4.Items: 1}, env)
	release := make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }); waitExecutorIdle(t, f.executor) })
	if _, err := f.executor.TrySubmit(ApplicationResident, task, input, func() { <-release }); err != nil {
		t.Fatal(err)
	}
	used, _ := env.Usage()
	env.Close()
	if after, _ := env.Usage(); after != used || f.executor.Snapshot().ResidentRunning != 1 {
		t.Fatal("Environment closure refunded callback")
	}
	otherTask, otherInput := f.job(t, 2)
	if _, err := f.executor.TrySubmit(ApplicationShort, otherTask, otherInput, func() {}); err != nil {
		t.Fatal("borrower close stopped shared service", err)
	}
	once.Do(func() { close(release) })
	waitExecutorIdle(t, f.executor)
}

func TestApplicationExecutorChargesSharedRuntimeAndRejectsOverflow(t *testing.T) {
	config := ApplicationExecutorConfig{Running: 2, ResidentRunning: 1, RuntimeBytes: 4096, RuntimeBytesPerTask: 65536}
	base, err := ApplicationExecutorCharge(config)
	if err != nil {
		t.Fatal(err)
	}
	config.RuntimeBytes++
	next, err := ApplicationExecutorCharge(config)
	if err != nil || next[resourcev4.SDKBytes] != base[resourcev4.SDKBytes]+1 {
		t.Fatal("shared runtime allowance not charged", next, err)
	}
	for _, runtimeBytes := range []uint64{0, math.MaxUint64} {
		config.RuntimeBytes = runtimeBytes
		if _, err := ApplicationExecutorCharge(config); !errors.Is(err, cryptov4.ErrConfiguration) {
			t.Fatal("invalid runtime allowance accepted", runtimeBytes, err)
		}
	}
}

func TestApplicationExecutorFailedTaskTakeRollsBackOriginalInputBorrow(t *testing.T) {
	f := newExecutorFixture(t, 2, 1)
	charge := f.executor.TaskCharge()
	charge[resourcev4.SDKBytes]--
	task := f.reserve(t, 1, charge)
	input := f.reserve(t, 1, resourcev4.Vector{resourcev4.SDKBytes: 128, resourcev4.Items: 1})
	before := f.root.Snapshot()
	if _, err := f.executor.TrySubmit(ApplicationShort, task, input, func() { t.Error("underfunded task ran") }); err == nil {
		t.Fatal("undersized task reservation accepted")
	}
	if f.root.Snapshot() != before || task.Check() != nil || input.Check() != nil || f.executor.Snapshot().Running != 0 {
		t.Fatal("failed task Take changed original input ownership")
	}
}

func TestApplicationExecutorConcurrentResidentAdmissionKeepsShortFloor(t *testing.T) {
	f := newExecutorFixture(t, 3, 2)
	const count = 10
	var jobs [count][2]resourcev4.Reference
	for i := range jobs {
		jobs[i][0], jobs[i][1] = f.job(t, byte(i+1))
	}
	start, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }); waitExecutorIdle(t, f.executor) })
	var wg sync.WaitGroup
	var admitted atomic.Uint32
	for i := range jobs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, err := f.executor.TrySubmit(ApplicationResident, jobs[i][0], jobs[i][1], func() { <-release })
			if err == nil {
				admitted.Add(1)
			} else if !errors.Is(err, cryptov4.ErrCapacity) {
				t.Error(err)
			}
		}(i)
	}
	close(start)
	wg.Wait()
	if admitted.Load() != 2 || f.executor.Snapshot().Running != 2 {
		t.Fatal("concurrent resident admission bypassed cap", admitted.Load(), f.executor.Snapshot())
	}
	task, input := f.job(t, 1)
	if _, err := f.executor.TrySubmit(ApplicationShort, task, input, func() { <-release }); err != nil {
		t.Fatal("resident contenders consumed short floor", err)
	}
	if s := f.executor.Snapshot(); s.Running != 3 || s.ResidentRunning != 2 {
		t.Fatal(s)
	}
	once.Do(func() { close(release) })
	waitExecutorIdle(t, f.executor)
}

func TestApplicationExecutorConcurrentCloseAndSubmission(t *testing.T) {
	f := newExecutorFixture(t, 3, 2)
	const count = 10
	var jobs [count][2]resourcev4.Reference
	var results [count]*ApplicationTask
	for i := range jobs {
		jobs[i][0], jobs[i][1] = f.job(t, 1)
	}
	start, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }); waitExecutorIdle(t, f.executor) })
	var wg sync.WaitGroup
	for i := range jobs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			var err error
			results[i], err = f.executor.TrySubmit(ApplicationShort, jobs[i][0], jobs[i][1], func() { <-release })
			if err != nil && !errors.Is(err, cryptov4.ErrCapacity) && !errors.Is(err, resourcev4.ErrClosed) {
				t.Error(err)
			}
		}(i)
	}
	wg.Add(1)
	go func() { defer wg.Done(); <-start; f.executor.Close() }()
	close(start)
	wg.Wait()
	if s := f.executor.Snapshot(); !s.Closed || s.Running > 3 {
		t.Fatal(s)
	}
	once.Do(func() { close(release) })
	<-f.executor.Done()
	for _, task := range results {
		if task != nil {
			select {
			case <-task.Done():
			default:
				t.Fatal("executor cleanup preceded task completion")
			}
		}
	}
}

func TestApplicationExecutorReentrantCallbackAndGoexit(t *testing.T) {
	f := newExecutorFixture(t, 2, 1)
	task, input := f.job(t, 1)
	nestedTask, nestedInput := f.job(t, 1)
	nestedResult := make(chan *ApplicationTask, 1)
	deferred := make(chan struct{})
	job, err := f.executor.TrySubmit(ApplicationResident, task, input, func() {
		defer close(deferred)
		if s := f.executor.Snapshot(); s.Running != 1 || s.ResidentRunning != 1 {
			t.Error(s)
		}
		nested, err := f.executor.TrySubmit(ApplicationShort, nestedTask, nestedInput, func() {})
		if err != nil {
			t.Error(err)
		}
		nestedResult <- nested
		f.executor.Close()
		runtime.Goexit()
	})
	if err != nil {
		t.Fatal(err)
	}
	<-job.Done()
	<-deferred
	if nested := <-nestedResult; nested != nil {
		<-nested.Done()
	}
	<-f.executor.Done()
	if s := f.executor.Snapshot(); !s.CleanupComplete || s.Running != 0 || s.ResidentRunning != 0 {
		t.Fatal("Goexit bypassed actual cleanup", s)
	}
}
