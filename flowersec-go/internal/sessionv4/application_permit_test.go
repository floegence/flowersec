package sessionv4

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

func waitApplicationPermitTask(t *testing.T, task *ApplicationTask) {
	t.Helper()
	select {
	case <-task.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("original application task did not return")
	}
}

func TestApplicationPermitAcceptanceOrdersExecutorClose(t *testing.T) {
	for _, acceptedFirst := range []bool{false, true} {
		t.Run(fmt.Sprint(acceptedFirst), func(t *testing.T) {
			f := newExecutorFixture(t, 2, 1)
			task, input := f.job(t, 1)
			permit, err := f.executor.TryAcquire(ApplicationResident, task, input)
			if err != nil {
				t.Fatal(err)
			}
			defer permit.Close()
			before := f.root.Snapshot()
			if acceptedFirst {
				if err := permit.commitAcceptance(); err != nil {
					t.Fatal(err)
				}
				if err := permit.commitAcceptance(); !errors.Is(err, cryptov4.ErrTransition) {
					t.Fatal("acceptance was committed twice", err)
				}
			}
			f.executor.Close()
			if acceptedFirst {
				if f.root.Snapshot() != before || f.executor.Snapshot().Running != 1 {
					t.Fatal("executor close refunded accepted responsibility")
				}
			} else if err := permit.commitAcceptance(); !errors.Is(err, resourcev4.ErrClosed) {
				t.Fatal("closed executor accepted an OPEN", err)
			}
			if task, err := permit.Start(func() { t.Error("closed executor started a new callback") }); task != nil || !errors.Is(err, resourcev4.ErrClosed) {
				t.Fatal(err)
			}
			permit.Close()
			select {
			case <-f.executor.Done():
			case <-time.After(time.Second):
				t.Fatal("released acceptance retained executor")
			}
		})
	}
}

func TestApplicationPermitPreadmissionKeepsResidentFloorAndRejectsBeforeTake(t *testing.T) {
	f := newExecutorFixture(t, 2, 1)
	task, input := f.job(t, 1)
	resident, err := f.executor.TryAcquire(ApplicationResident, task, input)
	if err != nil {
		t.Fatal(err)
	}
	defer resident.Close()
	nextTask, nextInput := f.job(t, 2)
	nextBorrow, err := nextInput.Borrow()
	if err != nil {
		t.Fatal(err)
	}
	defer nextBorrow.Release()
	before := f.root.Snapshot()
	for _, acquire := range []func() (*ApplicationPermit, error){
		func() (*ApplicationPermit, error) {
			return f.executor.TryAcquire(ApplicationResident, nextTask, nextInput)
		},
		func() (*ApplicationPermit, error) {
			return f.executor.TryAcquireWithBackingBorrow(ApplicationResident, nextTask, nextBorrow)
		},
	} {
		if p, err := acquire(); p != nil || !errors.Is(err, cryptov4.ErrCapacity) {
			t.Fatal("unstarted resident permit failed to preserve the short floor", err)
		}
		if f.root.Snapshot() != before || nextTask.Check() != nil || nextBorrow.Check() != nil {
			t.Fatal("rejected permit consumed an original task or backing reference")
		}
	}
	short, err := f.executor.TryAcquireWithBackingBorrow(ApplicationShort, nextTask, nextBorrow)
	if err != nil {
		t.Fatal("reserved resident work consumed the short floor", err)
	}
	defer short.Close()
	if snapshot := f.executor.Snapshot(); snapshot.Running != 2 || snapshot.ResidentRunning != 1 {
		t.Fatal(snapshot)
	}
	input.Release()
	nextInput.Release()
	resident.Close()
	resident.Close()
	if snapshot := f.executor.Snapshot(); snapshot.Running != 1 || snapshot.ResidentRunning != 0 || f.root.Snapshot().Reservations != 3 {
		t.Fatal("unused permit did not return exactly its original task and backing", snapshot, f.root.Snapshot())
	}
	short.Close()
	if snapshot := f.root.Snapshot(); snapshot.Reservations != 1 {
		t.Fatal("unused short permit retained invocation resources", snapshot)
	}
}

func TestApplicationPermitPreborrowStartsWithFullReferenceSlab(t *testing.T) {
	f := newExecutorFixture(t, 2, 1)
	task, input := f.job(t, 1)
	backing, err := input.Borrow()
	if err != nil {
		t.Fatal(err)
	}
	defer backing.Release()
	var fill []resourcev4.Reference
	defer func() {
		for _, ref := range fill {
			ref.Release()
		}
	}()
	for {
		ref, err := input.Borrow()
		if errors.Is(err, resourcev4.ErrCapacity) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		fill = append(fill, ref)
	}
	before := f.root.Snapshot()
	if p, err := f.executor.TryAcquire(ApplicationShort, task, input); p != nil || !errors.Is(err, resourcev4.ErrCapacity) {
		t.Fatal("test did not exhaust original reference capacity", err)
	}
	if f.root.Snapshot() != before || task.Check() != nil {
		t.Fatal("failed backing borrow consumed task admission")
	}
	p, err := f.executor.TryAcquireWithBackingBorrow(ApplicationShort, task, backing)
	if err != nil {
		t.Fatal("pre-admitted reference required a new slot", err)
	}
	defer p.Close()
	if f.root.Snapshot() != before || !errors.Is(backing.Check(), resourcev4.ErrOwner) {
		t.Fatal("pre-admitted borrow was duplicated instead of moved")
	}
	backing.Release() // A retained caller alias cannot release the moved owner.
	release := make(chan struct{})
	stop := sync.OnceFunc(func() { close(release) })
	defer stop()
	job, err := p.Start(func() { <-release })
	if err != nil {
		t.Fatal("accepted permit required another quota or reference slot", err)
	}
	if f.root.Snapshot() != before {
		t.Fatal("Start changed the complete original resource admission")
	}
	stop()
	waitApplicationPermitTask(t, job)
}

func TestApplicationPermitStartsOnceAndStaleAliasesCannotUseRecycledSlot(t *testing.T) {
	f := newExecutorFixture(t, 1, 0)
	task, input := f.job(t, 1)
	old, err := f.executor.TryAcquire(ApplicationShort, task, input)
	if err != nil {
		t.Fatal(err)
	}
	old.Close()
	task, input = f.job(t, 1)
	p, err := f.executor.TryAcquire(ApplicationShort, task, input)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if old.index != p.index {
		t.Fatal("test did not reuse the fixed execution slot")
	}
	old.Close()
	// Copy the public value's routing fields without copying an atomic value
	// after first use. Identity in the original slot still belongs only to p.
	copied := &ApplicationPermit{index: p.index}
	copied.executor.Store(p.executor.Load())
	for _, alias := range []*ApplicationPermit{old, copied} {
		alias.Close()
		if job, err := alias.Start(func() { t.Error("stale permit invoked work") }); job != nil || !errors.Is(err, resourcev4.ErrClosed) {
			t.Fatal("stale permit acted on a recycled execution position", err)
		}
	}
	if job, err := p.Start(nil); job != nil || !errors.Is(err, cryptov4.ErrConfiguration) {
		t.Fatal("nil work consumed the original permit", err)
	}
	release := make(chan struct{})
	stop := sync.OnceFunc(func() { close(release) })
	defer stop()
	var calls atomic.Uint32
	var wg sync.WaitGroup
	results := make(chan *ApplicationTask, 12)
	for range cap(results) {
		wg.Go(func() {
			job, err := p.Start(func() { calls.Add(1); <-release })
			if err == nil {
				results <- job
			} else if !errors.Is(err, resourcev4.ErrClosed) {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if len(results) != 1 || p.executor.Load() != nil {
		t.Fatal("one permit admitted multiple callbacks or retained its executor", len(results))
	}
	p.Close()
	if snapshot := f.executor.Snapshot(); snapshot.Running != 1 {
		t.Fatal("consumed permit Close revoked an actual callback", snapshot)
	}
	stop()
	waitApplicationPermitTask(t, <-results)
	if calls.Load() != 1 {
		t.Fatal("callback was not invoked exactly once", calls.Load())
	}
}

func TestApplicationPermitExecutorCloseRevokesOnlyUnstartedWork(t *testing.T) {
	f := newExecutorFixture(t, 2, 1)
	var permits [2]*ApplicationPermit
	var inputs [2]resourcev4.Reference
	for i := range permits {
		task, backing := f.job(t, byte(i+1))
		p, err := f.executor.TryAcquire(ApplicationWorkClass(i), task, backing)
		if err != nil {
			t.Fatal(err)
		}
		permits[i] = p
		inputs[i] = backing
		defer p.Close()
	}
	exiting, release := make(chan struct{}), make(chan struct{})
	stop := sync.OnceFunc(func() { close(release) })
	defer stop()
	job, err := permits[1].Start(func() {
		defer func() { close(exiting); <-release }()
		_ = f.executor.Snapshot() // Callback entry must be outside its gate.
	})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-exiting:
	case <-time.After(3 * time.Second):
		t.Fatal("callback could not reenter the original execution gate")
	}
	for _, input := range inputs {
		input.Release()
	}
	f.executor.Close()
	if snapshot := f.executor.Snapshot(); snapshot.Running != 1 || snapshot.ResidentRunning != 1 || snapshot.CleanupComplete || f.root.Snapshot().Reservations != 3 {
		t.Fatal("executor close confused an unstarted permit with a live callback", snapshot, f.root.Snapshot())
	}
	if task, err := permits[0].Start(func() { t.Error("revoked callback ran") }); task != nil || !errors.Is(err, resourcev4.ErrClosed) {
		t.Fatal("executor close left an unstarted permit usable", err)
	}
	select {
	case <-job.Done():
		t.Fatal("held application defer was reported complete")
	default:
	}
	stop()
	waitApplicationPermitTask(t, job)
	if snapshot := f.root.Snapshot(); snapshot.Reservations != 0 || snapshot.References != 0 {
		t.Fatal("completed callback retained original executor resources", snapshot)
	}
}

func TestApplicationPermitStartRacesPermitAndExecutorClose(t *testing.T) {
	for _, executorClose := range []bool{false, true} {
		for iteration := range 16 {
			t.Run(fmt.Sprintf("executor=%v/iteration=%d", executorClose, iteration), func(t *testing.T) {
				f := newExecutorFixture(t, 1, 0)
				task, input := f.job(t, 1)
				p, err := f.executor.TryAcquire(ApplicationShort, task, input)
				if err != nil {
					t.Fatal(err)
				}
				defer p.Close()
				begin, release := make(chan struct{}), make(chan struct{})
				stop := sync.OnceFunc(func() { close(release) })
				defer stop()
				var calls atomic.Uint32
				var job *ApplicationTask
				var startErr error
				var wg sync.WaitGroup
				wg.Go(func() {
					<-begin
					job, startErr = p.Start(func() { calls.Add(1); <-release })
				})
				wg.Go(func() {
					<-begin
					if executorClose {
						f.executor.Close()
					} else {
						p.Close()
					}
				})
				close(begin)
				wg.Wait()
				input.Release()
				if job == nil {
					if !errors.Is(startErr, resourcev4.ErrClosed) || calls.Load() != 0 || f.executor.Snapshot().Running != 0 {
						t.Fatal("revocation lost its original admission race", startErr, calls.Load())
					}
				} else {
					if startErr != nil || f.executor.Snapshot().Running != 1 || f.root.Snapshot().Reservations != 3 {
						t.Fatal("racing close refunded a committed callback", startErr, f.root.Snapshot())
					}
					stop()
					waitApplicationPermitTask(t, job)
					if calls.Load() != 1 {
						t.Fatal("committed callback did not run exactly once", calls.Load())
					}
				}
				f.executor.Close()
				if snapshot := f.root.Snapshot(); snapshot.Reservations != 0 {
					t.Fatal("race retained original task or backing", snapshot)
				}
			})
		}
	}
}

func TestApplicationPermitRespectsOriginalTenantFenceAtStart(t *testing.T) {
	f := newExecutorFixture(t, 2, 1)
	tenant, err := f.root.Account(resourcev4.AccountKey{Kind: resourcev4.TenantAccount, ID: [16]byte{1}}, resourcev4.Vector{resourcev4.SDKBytes: 1 << 20, resourcev4.Items: 8, resourcev4.Tasks: 2, resourcev4.WorkSlots: 2})
	if err != nil {
		t.Fatal(err)
	}
	task := f.reserve(t, 1, f.executor.TaskCharge(), tenant)
	backing := f.reserve(t, 1, resourcev4.Vector{resourcev4.SDKBytes: 128, resourcev4.Items: 1}, tenant)
	p, err := f.executor.TryAcquire(ApplicationResident, task, backing)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	before, err := tenant.Usage()
	if err != nil {
		t.Fatal(err)
	}
	tenant.Close()
	if after, _ := tenant.Usage(); after != before {
		t.Fatal("tenant closure refunded its still-owned permit")
	}
	if job, err := p.Start(func() { t.Error("closed tenant started a callback") }); job != nil || !errors.Is(err, resourcev4.ErrClosed) {
		t.Fatal("Start lost the original tenant fence", err)
	}
	backing.Release()
	if after, _ := tenant.Usage(); after != (resourcev4.Vector{}) || f.executor.Snapshot().Running != 0 {
		t.Fatal("revoked unstarted permit retained original tenant resources", after)
	}
	otherTask, otherInput := f.job(t, 2)
	job, err := f.executor.TrySubmit(ApplicationShort, otherTask, otherInput, func() {})
	if err != nil {
		t.Fatal("tenant closure stopped the shared executor", err)
	}
	waitApplicationPermitTask(t, job)
}
