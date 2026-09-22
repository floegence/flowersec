package sessionv4

import (
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

// Synthetic SDK steps exist only in this package's tests. Production exposes
// no callback adapter for the sealed fixed-query service.
type testSDKQueryWork struct {
	step  func() (bool, error)
	close func()
}

func (w *testSDKQueryWork) queryStep() (bool, error) { return w.step() }
func (w *testSDKQueryWork) queryClose() {
	if w.close != nil {
		w.close()
	}
}

func queryExecutorFixture(t *testing.T, count uint32) *executorFixture {
	return newExecutorConfigFixture(t, ApplicationExecutorConfig{Running: 2, ResidentRunning: 1, CompletionRunning: 1, CompletionReserved: 2, QueryOwners: count, RuntimeBytes: 4096, RuntimeBytesPerTask: 65536})
}

func registerTestQuery(t *testing.T, f *executorFixture, group *sdkQueryGroup, direction uint8, work *testSDKQueryWork) *sdkQueryRegistration {
	t.Helper()
	backing := f.reserve(t, 1, resourcev4.Vector{resourcev4.SDKBytes: 512, resourcev4.Items: 1})
	borrow, err := backing.Borrow()
	if err != nil {
		t.Fatal(err)
	}
	r, err := f.executor.registerSDKQuery(group, direction, work, borrow)
	borrow.Release()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Close)
	return r
}

func awaitQuery(t *testing.T, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(3 * time.Second):
		t.Fatal("fixed query owner did not progress")
	}
}

// TestApplicationQueriesProtectedRootLane implements v4.go_contract_query.root_lane.
func TestApplicationQueriesProtectedRootLane(t *testing.T) {
	f := queryExecutorFixture(t, 12)
	release := make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	entered := make(chan struct{}, 3)
	for range 2 {
		task, backing := f.job(t, 1)
		if _, err := f.executor.TrySubmit(ApplicationShort, task, backing, func() { entered <- struct{}{}; <-release }); err != nil {
			t.Fatal(err)
		}
	}
	completion, err := f.executor.ReserveCompletion(f.reserve(t, 1, f.executor.CompletionCharge()), f.reserve(t, 1, resourcev4.Vector{resourcev4.SDKBytes: 128}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := completion.Submit(func() error { entered <- struct{}{}; <-release; return nil }); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		awaitQuery(t, entered)
	}
	first, advance := make(chan struct{}), make(chan struct{})
	var advanceOnce sync.Once
	t.Cleanup(func() { advanceOnce.Do(func() { close(advance) }) })
	progress := make(chan int, 36)
	var refs [12]*sdkQueryRegistration
	var active, peak atomic.Int32
	for i := range refs {
		steps := 0
		refs[i] = registerTestQuery(t, f, &sdkQueryGroup{}, uint8(i%2), &testSDKQueryWork{step: func() (bool, error) {
			n := active.Add(1)
			defer active.Add(-1)
			for old := peak.Load(); n > old && !peak.CompareAndSwap(old, n); old = peak.Load() {
			}
			if i == 0 && steps == 0 {
				close(first)
				<-advance
			}
			steps++
			progress <- i
			return steps < 3, nil
		}})
	}
	refs[0].Wake()
	awaitQuery(t, first)
	for _, r := range refs[1:] {
		r.Wake()
	}
	if s := f.executor.Snapshot(); s.QueryOwners != 12 || s.QueryReady != 4 || s.QueryRunning != 1 || s.Running != 2 || s.CompletionRunning != 1 {
		t.Fatal("fixed service borrowed another lane or lost finite ready bounds", s)
	}
	extra := f.reserve(t, 1, resourcev4.Vector{resourcev4.SDKBytes: 128})
	borrow, err := extra.Borrow()
	if err != nil {
		t.Fatal(err)
	}
	before := f.root.Snapshot()
	if _, err := f.executor.registerSDKQuery(&sdkQueryGroup{}, 0, &testSDKQueryWork{}, borrow); !errors.Is(err, cryptov4.ErrCapacity) || f.root.Snapshot() != before || borrow.Check() != nil {
		t.Fatal("full finite index created a waiter or consumed rejected ownership", err)
	}
	borrow.Release()
	advanceOnce.Do(func() { close(advance) })
	counts := [12]int{}
	for range 36 {
		select {
		case i := <-progress:
			counts[i]++
		case <-time.After(3 * time.Second):
			t.Fatal("ordinary saturation blocked fixed query progress", counts)
		}
	}
	for _, count := range counts {
		if count != 3 {
			t.Fatal("eligible original owner lost", counts)
		}
	}
	if peak.Load() != 1 {
		t.Fatal("more than one physical fixed SDK step", peak.Load())
	}
	for _, r := range refs {
		r.Close()
		awaitQuery(t, r.done)
	}
	once.Do(func() { close(release) })
}

// TestApplicationQueriesRotateOriginalOwners implements v4.go_contract_query.root_fairness.
func TestApplicationQueriesRotateOriginalOwners(t *testing.T) {
	f := queryExecutorFixture(t, 7)
	groups := [3]sdkQueryGroup{}
	groupOf := [7]int{0, 0, 0, 0, 1, 1, 2}
	direction := [7]uint8{0, 0, 1, 1, 0, 1, 0}
	trace := make(chan int, 700)
	var refs [7]*sdkQueryRegistration
	for i := range refs {
		steps := 0
		refs[i] = registerTestQuery(t, f, &groups[groupOf[i]], direction[i], &testSDKQueryWork{step: func() (bool, error) {
			steps++
			trace <- i
			return steps < 100, nil
		}})
	}
	// All seven original owners become eligible in the same gate. There are
	// still only four real ready entries and one original physical worker.
	f.executor.mu.Lock()
	for i := range f.executor.queries.slots {
		f.executor.queries.slots[i].pending = true
	}
	f.executor.wakeSDKQueriesLocked()
	f.executor.mu.Unlock()
	lastOwner, lastGroup := [7]int{}, [3]int{}
	for step := range 100 {
		var owner int
		select {
		case owner = <-trace:
		case <-time.After(3 * time.Second):
			t.Fatal("eligible owners stalled")
		}
		lastOwner[owner], lastGroup[groupOf[owner]] = step, step
		if step > 20 {
			for i, last := range lastOwner {
				if step-last > 16 {
					t.Fatal("query owner starved behind another direction or Session", i, step, last)
				}
			}
			for i, last := range lastGroup {
				if step-last > 7 {
					t.Fatal("Session with more queries monopolized the lane", i, step, last)
				}
			}
		}
	}
}

// TestApplicationQueriesCloseAndWakePreserveActualStep implements v4.go_contract_query.root_tail.
func TestApplicationQueriesCloseAndWakePreserveActualStep(t *testing.T) {
	for _, closeRoot := range []bool{false, true} {
		t.Run(map[bool]string{false: "wake", true: "close"}[closeRoot], func(t *testing.T) {
			f := queryExecutorFixture(t, 1)
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			t.Cleanup(func() { once.Do(func() { close(release) }) })
			var steps, cleaned atomic.Int32
			second := make(chan struct{})
			r := registerTestQuery(t, f, &sdkQueryGroup{}, 0, &testSDKQueryWork{step: func() (bool, error) {
				if steps.Add(1) == 1 {
					close(entered)
					<-release
				} else {
					close(second)
				}
				return false, nil
			}, close: func() { cleaned.Add(1) }})
			r.Wake()
			awaitQuery(t, entered)
			before := f.root.Snapshot()
			if closeRoot {
				f.executor.Close()
				if f.root.Snapshot() != before || f.executor.Snapshot().QueryRunning != 1 {
					t.Fatal("logical Close refunded physical step")
				}
				select {
				case <-f.executor.Done():
					t.Fatal("cleanup completed before original step exited")
				default:
				}
			} else {
				for range 1000 {
					r.Wake()
				}
			}
			once.Do(func() { close(release) })
			if !closeRoot {
				awaitQuery(t, second)
				r.Close()
			}
			awaitQuery(t, r.done)
			if cleaned.Load() != 1 || steps.Load() != map[bool]int32{false: 2, true: 1}[closeRoot] {
				t.Fatal("lost wake, duplicated step or physical cleanup", steps.Load(), cleaned.Load())
			}
		})
	}
}

func TestApplicationQueriesAbnormalExitDoesNotReplaceWorker(t *testing.T) {
	for _, goexit := range []bool{false, true} {
		t.Run(map[bool]string{false: "panic", true: "goexit"}[goexit], func(t *testing.T) {
			f := queryExecutorFixture(t, 2)
			var cleaned atomic.Int32
			bad := registerTestQuery(t, f, &sdkQueryGroup{}, 0, &testSDKQueryWork{step: func() (bool, error) {
				if goexit {
					runtime.Goexit()
				}
				panic("fixed codec fault")
			}, close: func() { cleaned.Add(1) }})
			goodStep := make(chan struct{}, 1)
			good := registerTestQuery(t, f, &sdkQueryGroup{}, 0, &testSDKQueryWork{step: func() (bool, error) { goodStep <- struct{}{}; return false, nil }, close: func() { cleaned.Add(1) }})
			bad.Wake()
			awaitQuery(t, bad.done)
			if !errors.Is(bad.err, ErrCompletionCallbackExit) {
				t.Fatal("lost source failure", bad.err)
			}
			good.Wake()
			if goexit {
				awaitQuery(t, good.done)
				if !f.executor.Snapshot().QueryFailed {
					t.Fatal("Goexit created a replacement worker")
				}
				select {
				case <-goodStep:
					t.Fatal("failed lane resumed fixed dispatch")
				default:
				}
			} else {
				awaitQuery(t, goodStep)
				good.Close()
				awaitQuery(t, good.done)
			}
			if cleaned.Load() != 2 {
				t.Fatal("actual original source cleanup lost", cleaned.Load())
			}
		})
	}
}

func TestApplicationQueriesChargeIncludesActualWorker(t *testing.T) {
	c := ApplicationExecutorConfig{Running: 26, ResidentRunning: 18, RuntimeBytes: 4096, RuntimeBytesPerTask: 65536}
	base, err := ApplicationExecutorCharge(c)
	if err != nil {
		t.Fatal(err)
	}
	c.QueryOwners = 12
	with, err := ApplicationExecutorCharge(c)
	if err != nil || with[resourcev4.Tasks] != base[resourcev4.Tasks]+1 || with[resourcev4.WorkSlots] != base[resourcev4.WorkSlots]+1 || with[resourcev4.Timers] != base[resourcev4.Timers]+1 || with[resourcev4.SDKBytes] < base[resourcev4.SDKBytes]+c.RuntimeBytesPerTask {
		t.Fatal("query worker or original index was free", base, with, err)
	}
	c.RuntimeBytesPerTask = 256 * 1024
	if _, err := ApplicationExecutorCharge(c); err == nil {
		t.Fatal("fixed lane admitted metadata plus stack beyond its own cap")
	}
}
