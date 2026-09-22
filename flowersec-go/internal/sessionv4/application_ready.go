package sessionv4

import (
	"sync/atomic"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

// A ready invocation retains its original complete task/input reservation.
// This conservative charge is distinct from evidence of an actual running Go
// worker; only dispatch below creates one, under the original running limit.
// The final deployment profile must qualify all simultaneous ready/run costs.
type applicationReadySlot struct {
	handle         *QueuedApplicationTask
	group          *applicationGroup
	previous, next int
	class          ApplicationWorkClass
	task, backing  resourcev4.Reference
	work           func()
	prepared       bool
	cleanup        bool
}

// QueuedApplicationTask permits cancellation only before original dispatch.
// After dispatch, the original invocation context governs the actual callback;
// Cancel never refunds a running task or manufactures its exit notification.
// Retained terminal handles contain no executor, callback, input or Session.
type QueuedApplicationTask struct {
	executor atomic.Pointer[ApplicationExecutor]
	index    int
	started  atomic.Bool
	canceled atomic.Bool
	result   *ApplicationTask
}

func (q *QueuedApplicationTask) Done() <-chan struct{} { return q.result.Done() }
func (q *QueuedApplicationTask) Started() bool         { return q != nil && q.started.Load() }
func (q *QueuedApplicationTask) Canceled() bool        { return q != nil && q.canceled.Load() }
func (q *QueuedApplicationTask) Cancel() bool {
	if q == nil {
		return false
	}
	e := q.executor.Load()
	if e == nil {
		return false
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if q.executor.Load() != e || q.index >= len(e.ready) || e.ready[q.index].handle != q {
		return false
	}
	e.cancelReadyLocked(q.index)
	e.cleanupLocked()
	return true
}

// A group is issued only by this root for an original local SessionPlan.
// Retained handles cannot follow a new group's identity after cleanup.
func (e *ApplicationExecutor) newApplicationGroup() (*applicationGroup, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return nil, resourcev4.ErrClosed
	}
	return &applicationGroup{executor: e, head: [2]int{-1, -1}, tail: [2]int{-1, -1}, done: make(chan struct{})}, nil
}

// queueApplication is the explicit SDK queue admission, not an implicit retry
// of TryAcquire. A full ready/class vector rejects before moving any reference.
// Source authorization, message deadlines and complete result/output admission
// remain obligations of the original SDK invocation, including inside work.
func (e *ApplicationExecutor) queueApplication(group *applicationGroup, class ApplicationWorkClass, taskReservation, backing resourcev4.Reference, work func()) (*QueuedApplicationTask, error) {
	if e == nil || work == nil {
		return nil, cryptov4.ErrConfiguration
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	q, err := e.prepareApplicationLocked(group, class, taskReservation, backing)
	if err != nil {
		return nil, err
	}
	if err = e.startPreparedLocked(q, work); err != nil {
		e.cancelReadyLocked(q.index)
		return nil, err
	}
	return q, nil
}

// prepareApplication acquires a real ready position without dispatch rights.
// History registration commits only after this finite reservation succeeds;
// the original owner must then start or cancel the same prepared position.
func (e *ApplicationExecutor) prepareApplication(group *applicationGroup, class ApplicationWorkClass, taskReservation, backing resourcev4.Reference) (*QueuedApplicationTask, error) {
	if e == nil {
		return nil, cryptov4.ErrConfiguration
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.prepareApplicationLocked(group, class, taskReservation, backing)
}
func (e *ApplicationExecutor) prepareApplicationLocked(group *applicationGroup, class ApplicationWorkClass, taskReservation, backing resourcev4.Reference) (*QueuedApplicationTask, error) {
	return e.prepareApplicationBorrowLocked(group, class, taskReservation, backing, resourcev4.Reference{})
}

func (e *ApplicationExecutor) prepareApplicationWithBorrow(group *applicationGroup, class ApplicationWorkClass, task, backing, borrow resourcev4.Reference) (*QueuedApplicationTask, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.prepareApplicationBorrowLocked(group, class, task, backing, borrow)
}

func (e *ApplicationExecutor) prepareApplicationBorrowLocked(group *applicationGroup, class ApplicationWorkClass, taskReservation, backing, originalBorrow resourcev4.Reference) (*QueuedApplicationTask, error) {
	if class > ApplicationResident || taskReservation == backing {
		return nil, cryptov4.ErrConfiguration
	}
	if e.closed {
		return nil, resourcev4.ErrClosed
	}
	if group == nil || group.executor != e || group.closed {
		return nil, cryptov4.ErrConfiguration
	}
	if e.readyCount == e.config.Ready || class == ApplicationResident && e.residentReady == e.config.ResidentReady {
		return nil, cryptov4.ErrCapacity
	}
	if err := e.reservation.CheckSameRoot(backing); err != nil {
		return nil, err
	}
	if err := taskReservation.CheckSameEnvironment(backing); err != nil {
		return nil, err
	}
	var borrow resourcev4.Reference
	var err error
	if originalBorrow == (resourcev4.Reference{}) {
		borrow, err = backing.Borrow()
	} else if err = originalBorrow.CheckSameEnvironment(backing); err == nil {
		borrow, err = originalBorrow.TakeBorrow()
	}
	if err != nil {
		return nil, err
	}
	task, err := taskReservation.Take(e.TaskCharge())
	if err != nil {
		borrow.Release()
		return nil, err
	}
	index := 0
	for e.ready[index].handle != nil {
		index++
	}
	q := &QueuedApplicationTask{index: index, result: &ApplicationTask{done: make(chan struct{})}}
	e.ready[index] = applicationReadySlot{handle: q, group: group, previous: -1, next: -1, class: class, task: task, backing: borrow, prepared: true}
	group.active++
	e.readyCount++
	if class == ApplicationResident {
		e.residentReady++
	}
	q.executor.Store(e)
	return q, nil
}
func (q *QueuedApplicationTask) startPrepared(work func()) error {
	if q == nil || work == nil {
		return cryptov4.ErrConfiguration
	}
	e := q.executor.Load()
	if e == nil {
		return resourcev4.ErrClosed
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.startPreparedLocked(q, work)
}

// checkPrepared is the original acceptance gate for a future application
// stage. Reserving this descriptor does not occupy a running executor slot.
func (q *QueuedApplicationTask) checkPrepared() error {
	if q == nil {
		return cryptov4.ErrConfiguration
	}
	e := q.executor.Load()
	if e == nil {
		return resourcev4.ErrClosed
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if q.executor.Load() != e || q.index >= len(e.ready) || e.ready[q.index].handle != q || e.closed {
		return resourcev4.ErrClosed
	}
	s := &e.ready[q.index]
	if !s.prepared || s.group.closed {
		return cryptov4.ErrTransition
	}
	if err := s.task.Check(); err != nil {
		return err
	}
	return s.backing.Check()
}
func (e *ApplicationExecutor) startPreparedLocked(q *QueuedApplicationTask, work func()) error {
	if q.executor.Load() != e || q.index >= len(e.ready) || e.ready[q.index].handle != q {
		return resourcev4.ErrClosed
	}
	s := &e.ready[q.index]
	if e.closed && !s.cleanup {
		return resourcev4.ErrClosed
	}
	if !s.prepared || s.group.closed && !s.cleanup {
		return cryptov4.ErrTransition
	}
	checkTask, checkBacking := s.task.Check, s.backing.Check
	if s.cleanup {
		checkTask, checkBacking = s.task.CheckRetained, s.backing.CheckRetained
	}
	if err := checkTask(); err != nil {
		return err
	}
	if err := checkBacking(); err != nil {
		return err
	}
	s.prepared, s.work = false, work
	s.previous = s.group.tail[s.class]
	if s.previous >= 0 {
		e.ready[s.previous].next = q.index
	} else {
		s.group.head[s.class] = q.index
		e.appendReadyGroupLocked(s.group, s.class)
	}
	s.group.tail[s.class] = q.index
	e.dispatchQueuedLocked()
	return nil
}

func (e *ApplicationExecutor) nextReadyLocked(class ApplicationWorkClass) int {
	if g := e.readyGroups[class]; g != nil {
		return g.head[class]
	}
	return -1
}

// Only groups with actual ready jobs occupy this finite class list. Serving
// one job moves its remaining group to the tail in constant time; newly ready
// Sessions cannot overtake old groups or reset their waiting position.
func (e *ApplicationExecutor) appendReadyGroupLocked(g *applicationGroup, class ApplicationWorkClass) {
	g.previous[class], g.next[class] = e.readyGroupTails[class], nil
	if tail := e.readyGroupTails[class]; tail != nil {
		tail.next[class] = g
	} else {
		e.readyGroups[class] = g
	}
	e.readyGroupTails[class] = g
}
func (e *ApplicationExecutor) unlinkReadyGroupLocked(g *applicationGroup, class ApplicationWorkClass) {
	if previous := g.previous[class]; previous != nil {
		previous.next[class] = g.next[class]
	} else {
		e.readyGroups[class] = g.next[class]
	}
	if next := g.next[class]; next != nil {
		next.previous[class] = g.previous[class]
	} else {
		e.readyGroupTails[class] = g.previous[class]
	}
	g.previous[class], g.next[class] = nil, nil
}
func (e *ApplicationExecutor) rotateReadyGroupLocked(g *applicationGroup, class ApplicationWorkClass) {
	if g.head[class] < 0 || e.readyGroupTails[class] == g {
		return
	}
	e.unlinkReadyGroupLocked(g, class)
	e.appendReadyGroupLocked(g, class)
}
func (e *ApplicationExecutor) removeReadyLocked(index int) applicationReadySlot {
	s := e.ready[index]
	if !s.prepared {
		if s.previous >= 0 {
			e.ready[s.previous].next = s.next
		} else {
			s.group.head[s.class] = s.next
		}
		if s.next >= 0 {
			e.ready[s.next].previous = s.previous
		} else {
			s.group.tail[s.class] = s.previous
		}
		if s.group.head[s.class] < 0 {
			e.unlinkReadyGroupLocked(s.group, s.class)
		}
	}
	e.ready[index] = applicationReadySlot{}
	e.readyCount--
	e.notifyAvailabilityLocked()
	if s.class == ApplicationResident {
		e.residentReady--
	}
	s.handle.executor.Store(nil)
	return s
}
func (e *ApplicationExecutor) cancelReadyLocked(index int) {
	s := e.removeReadyLocked(index)
	s.handle.canceled.Store(true)
	s.work = nil
	s.backing.Release()
	s.task.Release()
	e.releaseApplicationGroupLocked(s.group)
	close(s.handle.result.done)
}
func (e *ApplicationExecutor) dispatchQueuedLocked() {
	for e.running < e.config.Running && e.readyCount != 0 {
		index := -1
		for turn := 0; turn < 2; turn++ {
			class := ApplicationWorkClass((uint8(e.queueClass) + uint8(turn)) % 2)
			if class == ApplicationResident && e.resident == e.config.ResidentRunning {
				continue
			}
			if index = e.nextReadyLocked(class); index >= 0 {
				break
			}
		}
		if index < 0 {
			return
		}
		s := &e.ready[index]
		checkTask, checkBacking := s.task.Check, s.backing.Check
		if s.cleanup {
			checkTask, checkBacking = s.task.CheckRetained, s.backing.CheckRetained
		}
		if e.closed && !s.cleanup || checkTask() != nil || checkBacking() != nil {
			e.cancelReadyLocked(index)
			continue
		}
		slot := 0
		for e.slots[slot].active {
			slot++
		}
		original := e.removeReadyLocked(index)
		original.handle.started.Store(true)
		e.rotateReadyGroupLocked(original.group, original.class)
		e.queueClass = 1 - original.class
		e.slots[slot] = applicationTaskSlot{active: true, started: true, committed: true, class: original.class, group: original.group, result: original.handle.result, backing: original.backing, task: original.task}
		e.running++
		if original.class == ApplicationResident {
			e.resident++
		}
		go e.run(slot, original.work, original.handle.result)
	}
}
func (e *ApplicationExecutor) cancelApplicationGroup(group *applicationGroup) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if group == nil || group.executor != e || group.closed {
		return
	}
	group.closed = true
	for index := range e.ready {
		if e.ready[index].handle != nil && e.ready[index].group == group && !e.ready[index].cleanup {
			e.cancelReadyLocked(index)
		}
	}
	e.finishApplicationGroupLocked(group)
	e.cleanupLocked()
}

// applicationGroup is original SessionPlan metadata, never a global Session
// registry. The root holds it only through actual queued/running tasks. Its
// detached notification permits cleanup to wait without creating another job.
type applicationGroup struct {
	head, tail     [2]int
	previous, next [2]*applicationGroup
	executor       *ApplicationExecutor
	active         uint64
	closed         bool
	done           chan struct{}
}

func (e *ApplicationExecutor) releaseApplicationGroupLocked(g *applicationGroup) {
	if g != nil {
		g.active--
		e.finishApplicationGroupLocked(g)
	}
}
func (e *ApplicationExecutor) finishApplicationGroupLocked(g *applicationGroup) {
	if g.closed && g.active == 0 && g.executor != nil {
		g.executor = nil
		close(g.done)
	}
}

// prepareOrdinaryCleanup reserves a real descriptor from the SAME bounded
// ordinary ready service before subscription responsibility can be acquired.
// It creates no worker while dormant and is not an extra scheduler or lane.
// Closing a business group cannot erase its already accepted cleanup duty.
func (e *ApplicationExecutor) prepareOrdinaryCleanup(group *applicationGroup, class ApplicationWorkClass, task, backing resourcev4.Reference) (*QueuedApplicationTask, error) {
	if e == nil {
		return nil, cryptov4.ErrConfiguration
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	q, err := e.prepareApplicationLocked(group, class, task, backing)
	if err != nil {
		return nil, err
	}
	e.ready[q.index].cleanup = true
	return q, nil
}
