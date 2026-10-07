package sessionv4

import (
	"context"
	"errors"
	"math"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

var ErrCompletionCallbackExit = errors.New("sessionv4: completion callback exited without returning")
var errCompletionNotEligible = errors.New("sessionv4: original completion is not eligible")

type completionSlot struct {
	dependency                  *completionDependency
	claimed                     bool
	floor                       *CompletionFloor
	reservation                 *CompletionReservation
	task                        *CompletionTask
	backing, charge             resourcev4.Reference
	service                     resourcev4.Reference
	work                        func() error
	order                       uint64
	active, submitted, running  bool
	retained, closing           bool
	resultBound, resultDetached bool
}

// CompletionReservation holds one original future cleanup/delivery position.
// It is admitted before accepting the responsibility that needs it. Ordinary
// and resident callbacks cannot consume these positions or running capacity.
// It grants no business, wire, durable or application authorization.
type CompletionReservation struct {
	executor atomic.Pointer[ApplicationExecutor]
	index    int
}

// CompletionTask retains only a result, never an executor, input or Session.
// Canceling Wait detaches the observer; actual callback exit ends its charge.
type CompletionTask struct {
	mu   sync.Mutex
	done chan struct{}
	err  error
}

func (t *CompletionTask) Wait(ctx context.Context) error {
	if t == nil || ctx == nil {
		return cryptov4.ErrConfiguration
	}
	select {
	case <-t.done:
		t.mu.Lock()
		defer t.mu.Unlock()
		return t.err
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (t *CompletionTask) Done() <-chan struct{} { return t.done }

func (e *ApplicationExecutor) CompletionCharge() resourcev4.Vector {
	// The root executor already owns every possible running Completion stack.
	// Dormant owners reserve bounded descriptor/wake metadata and their own
	// payload, without pretending to run a task or taking a ready worker.
	overhead := e.config.RuntimeBytes
	if e.config.Profile != ApplicationProfileCustom {
		// Two actual descriptor/wake channels plus fixed allocator metadata;
		// the running stack is already owned by the shared Completion reserve.
		overhead = 192
	}
	return resourcev4.Vector{resourcev4.SDKBytes: overhead + uint64(unsafe.Sizeof(CompletionReservation{})) + uint64(unsafe.Sizeof(CompletionTask{})), resourcev4.Items: 2}
}

func (e *ApplicationExecutor) ReserveCompletion(reservation, backing resourcev4.Reference) (*CompletionReservation, error) {
	return e.reserveCompletion(reservation, backing, false)
}

func (e *ApplicationExecutor) reserveCompletion(reservation, backing resourcev4.Reference, floor bool) (*CompletionReservation, error) {
	if e == nil || reservation == backing {
		return nil, cryptov4.ErrConfiguration
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return nil, cryptov4.ErrClosed
	}
	if err := e.reservation.CheckSameRoot(backing); err != nil {
		return nil, err
	}
	if err := reservation.CheckSameEnvironment(backing); err != nil {
		return nil, err
	}
	if e.completionCount == uint32(len(e.completions)) || e.completionOrder == math.MaxUint64 {
		return nil, cryptov4.ErrCapacity
	}
	borrow, err := backing.Borrow()
	if err != nil {
		return nil, err
	}
	minimum := e.CompletionCharge()
	if floor {
		minimum = e.CompletionFloorCharge()
	}
	var service resourcev4.Reference
	if e.config.Profile != ApplicationProfileCustom {
		service, err = e.reservation.BorrowApplicationService(backing)
		if err != nil {
			borrow.Release()
			return nil, err
		}
	}
	charge, err := reservation.Take(minimum)
	if err != nil {
		service.Release()
		borrow.Release()
		return nil, err
	}
	index := 0
	for e.completions[index].active {
		index++
	}
	p := &CompletionReservation{index: index}
	e.completionOrder++
	e.completions[index] = completionSlot{order: e.completionOrder, reservation: p, task: &CompletionTask{done: make(chan struct{})}, backing: borrow, charge: charge, service: service, active: true}
	e.completionCount++
	p.executor.Store(e)
	return p, nil
}

// Submit consumes the reserved original cleanup exactly once. Executor.Close
// stops new reservations but preserves these already accepted responsibilities.
// The original caller must freeze cleanup inputs and close their business gate
// before submission; no fresh decoder/operation may be smuggled into this lane.
func (p *CompletionReservation) Submit(work func() error) (*CompletionTask, error) {
	return p.submit(work, false)
}

// offer keeps the original dormant reservation if a trusted SDK trampoline
// loses all consumers before application entry. Only errCompletionNotEligible
// can restore it; application errors are normalized by that trampoline.
func (p *CompletionReservation) offer(work func() error) (*CompletionTask, error) {
	return p.submit(work, true)
}

func (p *CompletionReservation) submit(work func() error, retained bool) (*CompletionTask, error) {
	if p == nil || work == nil {
		return nil, cryptov4.ErrConfiguration
	}
	e := p.executor.Load()
	if e == nil {
		return nil, cryptov4.ErrClosed
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if p.executor.Load() != e || p.index >= len(e.completions) {
		return nil, cryptov4.ErrClosed
	}
	s := &e.completions[p.index]
	if s.reservation != p || s.submitted {
		return nil, cryptov4.ErrTransition
	}
	// Ordering was fixed at reservation, before accepting the responsibility;
	// submission cannot encounter a new counter/capacity exhaustion boundary.
	s.work, s.submitted, s.retained = work, true, retained
	if !retained {
		s.reservation = nil
		p.executor.Store(nil)
	}
	task := s.task
	e.dispatchCompletionsLocked()
	return task, nil
}

func (p *CompletionReservation) Close() {
	if p == nil {
		return
	}
	e := p.executor.Load()
	if e == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if p.executor.Load() != e || p.index >= len(e.completions) || e.completions[p.index].reservation != p {
		return
	}
	if e.completions[p.index].running {
		e.completions[p.index].closing = true
		return
	}
	if task := e.completions[p.index].task; e.completions[p.index].submitted && task != nil {
		task.mu.Lock()
		task.err = cryptov4.ErrClosed
		close(task.done)
		task.mu.Unlock()
	}
	e.releaseCompletionLocked(p.index)
	e.dispatchCompletionsLocked()
	e.cleanupLocked()
}

func (e *ApplicationExecutor) releaseCompletionLocked(index int) {
	defer e.refillCompletionReadyLocked()
	s := &e.completions[index]
	if s.claimed {
		e.completionClaims--
		s.claimed = false
	}
	if s.dependency != nil {
		s.dependency.executor.Store(nil)
		s.dependency = nil
	}
	if s.reservation != nil {
		s.reservation.executor.Store(nil)
	}
	if s.floor != nil && s.floor.use != nil {
		// An item finishing does not finish the accepted stream. Keep the same
		// result backing and future descriptor between its actual item reads.
		if s.running {
			e.completionRunning--
		}
		s.retained, s.closing = false, false
		s.reservation, s.task, s.work = nil, nil, nil
		s.submitted, s.running = false, false
		return
	}
	if s.floor != nil && !s.floor.closed {
		// Return only after the actual callback exit (or an unsubmitted cancel).
		// The original task charge, backing alias and future position stay held.
		if s.running {
			e.completionRunning--
		}
		if s.resultBound {
			s.backing.Release()
			s.backing = s.floor.backing
			_ = s.charge.RestoreOriginalScopes(s.floor.anchor)
		}
		s.resultBound, s.resultDetached, s.retained, s.closing = false, false, false, false
		s.reservation, s.task, s.work = nil, nil, nil
		s.submitted, s.running = false, false
		return
	}
	if s.floor != nil {
		if s.resultBound {
			s.floor.backing.Release()
		}
		s.floor.anchor.Release()
		s.floor.backing, s.floor.anchor = resourcev4.Reference{}, resourcev4.Reference{}
		s.floor.executor.Store(nil)
	}
	s.backing.Release()
	s.charge.Release()
	s.service.Release()
	if s.running {
		e.completionRunning--
	}
	*s = completionSlot{}
	e.completionCount--
}

// refillCompletionReadyLocked scans the existing finite owner index. At most
// four original eligible owners enter real ready positions; the rest hold no
// queued worker or separate polling job. Explicit ancestor claims retain their
// promised next permit and take precedence over unclaimed ready owners.
func (e *ApplicationExecutor) refillCompletionReadyLocked() {
	e.completionReadyCount = 0
	for i := range e.completions {
		s := &e.completions[i]
		if !s.active || !s.submitted || s.running {
			continue
		}
		position := e.completionReadyCount
		for j := uint32(0); j < e.completionReadyCount; j++ {
			current := &e.completions[e.completionReady[j]]
			if s.claimed && !current.claimed || s.claimed == current.claimed && s.order < current.order {
				position = j
				break
			}
		}
		if position >= uint32(len(e.completionReady)) {
			continue
		}
		last := min(e.completionReadyCount, uint32(len(e.completionReady)-1))
		for j := last; j > position; j-- {
			e.completionReady[j] = e.completionReady[j-1]
		}
		e.completionReady[position] = i
		if e.completionReadyCount < uint32(len(e.completionReady)) {
			e.completionReadyCount++
		}
	}
}

func (e *ApplicationExecutor) dispatchCompletionsLocked() {
	e.refillCompletionReadyLocked()
	for e.completionRunning < e.config.CompletionRunning {
		index := -1
		for _, candidate := range e.completionReady[:e.completionReadyCount] {
			s := &e.completions[candidate]
			if s.claimed || e.completionRunning+e.completionClaims < e.config.CompletionRunning {
				index = candidate
				break
			}
		}
		if index < 0 {
			return
		}
		s := &e.completions[index]
		if s.claimed {
			e.completionClaims--
			s.claimed = false
		}
		if s.dependency != nil {
			s.dependency.executor.Store(nil)
		}
		s.running = true
		e.completionRunning++
		work, task := s.work, s.task
		s.work = nil
		e.refillCompletionReadyLocked()
		go e.runCompletion(index, work, task)
	}
}

func (e *ApplicationExecutor) runCompletion(index int, work func() error, task *CompletionTask) {
	err := ErrCompletionCallbackExit
	returned := false
	defer func() {
		if recover() != nil || !returned {
			err = ErrCompletionCallbackExit
		}
		work = nil
		e.mu.Lock()
		s := &e.completions[index]
		if err == errCompletionNotEligible && s.retained && !s.closing {
			// A scheduled SDK trampoline is not application delivery. Preserve
			// the same reservation and first dependency deadline for a later
			// real consumer, without a second result or request owner.
			e.completionRunning--
			s.running, s.submitted, s.retained = false, false, false
			s.task = &CompletionTask{done: make(chan struct{})}
		} else {
			e.releaseCompletionLocked(index)
		}
		task.mu.Lock()
		task.err = err
		close(task.done)
		task.mu.Unlock()
		e.dispatchCompletionsLocked()
		e.cleanupLocked()
		e.mu.Unlock()
	}()
	err = work()
	returned = true
}
