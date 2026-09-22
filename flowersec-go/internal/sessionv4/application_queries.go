package sessionv4

import (
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

// sdkQueryWork is sealed to this package. Only original fixed SDK query owners
// may use this lane: it accepts no application callback, codec or authorization
// hook. A step performs at most one bounded target read or 4 KiB of fixed codec
// work. External I/O must remain in its separately admitted source owner.
type sdkQueryWork interface {
	queryStep() (again bool, err error)
	queryClose()
}

// One group identifies an actual Session, not a wire priority or peer claim.
// The original Session owns the group and its complete query backing. Its
// scheduler cursors are accessed only under the root executor gate.
type sdkQueryGroup struct {
	direction uint8
	cursor    [2]int
}

type sdkQuerySlot struct {
	registration                    *sdkQueryRegistration
	group                           *sdkQueryGroup
	work                            sdkQueryWork
	backing                         resourcev4.Reference
	direction                       uint8
	pending, ready, active, closing bool
	cleanupFailed                   bool
	err                             error
}

type sdkQueryLane struct {
	slots                 []sdkQuerySlot
	wake                  chan struct{}
	sourceWake            chan struct{}
	ready                 [4]int
	readyHead, readyCount uint8
	count, running        uint32
	lastGroup             int
	worker, failed        bool
}

// A retained registration becomes detached when its original source exits.
// The pointer identity fences reuse of the bounded slot without a wrapping
// generation counter. Repeated wakes coalesce in that same original slot.
type sdkQueryRegistration struct {
	executor atomic.Pointer[ApplicationExecutor]
	index    int
	done     chan struct{}
	mu       sync.Mutex
	err      error
}

func sdkQueryLaneCharge(c ApplicationExecutorConfig) (resourcev4.Vector, error) {
	if c.QueryOwners == 0 {
		return resourcev4.Vector{}, nil
	}
	// The finite index is not another ready queue. Larger qualified profiles
	// must still fit this actual metadata and worker in the fixed lane's cap.
	if c.QueryOwners > 128 {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	fixed := uint64(unsafe.Sizeof(sdkQueryLane{})) + uint64(unsafe.Sizeof(time.Timer{})) + uint64(c.QueryOwners)*(uint64(unsafe.Sizeof(sdkQuerySlot{}))+uint64(unsafe.Sizeof(sdkQueryRegistration{}))+uint64(unsafe.Sizeof(sdkQueryGroup{})))
	charge, err := (resourcev4.Vector{resourcev4.SDKBytes: fixed, resourcev4.Items: uint64(c.QueryOwners) + 5, resourcev4.Tasks: 1, resourcev4.WorkSlots: 1, resourcev4.Timers: 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: c.RuntimeBytesPerTask})
	if err != nil || charge[resourcev4.SDKBytes] > 256*1024 {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	return charge, nil
}

// registerSDKQuery moves an already admitted backing reference, without a new
// root allocation. This reserves only a finite index; Wake makes it eligible
// for one of four actual ready entries. No ordinary/Completion permit is taken.
func (e *ApplicationExecutor) registerSDKQuery(group *sdkQueryGroup, direction uint8, work sdkQueryWork, backingBorrow resourcev4.Reference) (*sdkQueryRegistration, error) {
	if e == nil || group == nil || direction > 1 || work == nil {
		return nil, cryptov4.ErrConfiguration
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	q := e.queries
	if e.closed || q == nil || q.failed || !q.worker {
		return nil, cryptov4.ErrClosed
	}
	if err := e.reservation.CheckSameRoot(backingBorrow); err != nil {
		return nil, err
	}
	if q.count == uint32(len(q.slots)) {
		return nil, cryptov4.ErrCapacity
	}
	backing, err := backingBorrow.TakeBorrow()
	if err != nil {
		return nil, err
	}
	index := 0
	for q.slots[index].registration != nil {
		index++
	}
	r := &sdkQueryRegistration{index: index, done: make(chan struct{})}
	q.slots[index] = sdkQuerySlot{registration: r, group: group, direction: direction, work: work, backing: backing}
	q.count++
	r.executor.Store(e)
	return r, nil
}

func (r *sdkQueryRegistration) Wake() {
	if r == nil {
		return
	}
	e := r.executor.Load()
	if e == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if r.executor.Load() != e || e.queries.slots[r.index].registration != r {
		return
	}
	s := &e.queries.slots[r.index]
	if !s.closing && !e.closed && !e.queries.failed {
		s.pending = true
		e.fillSDKQueryReadyLocked()
		e.wakeSDKQueriesLocked()
	}
}

func (r *sdkQueryRegistration) Close() {
	if r == nil {
		return
	}
	e := r.executor.Load()
	if e == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if r.executor.Load() != e || e.queries.slots[r.index].registration != r {
		return
	}
	e.queries.slots[r.index].closing = true
	e.fillSDKQueryReadyLocked()
	e.wakeSDKQueriesLocked()
}

func (e *ApplicationExecutor) wakeSDKQueriesLocked() {
	select {
	case e.queries.wake <- struct{}{}:
	default:
	}
}

func (e *ApplicationExecutor) fillSDKQueryReadyLocked() {
	q := e.queries
	for q.readyCount < uint8(len(q.ready)) {
		index := q.choose()
		if index < 0 {
			return
		}
		q.slots[index].ready = true
		q.ready[(q.readyHead+q.readyCount)%uint8(len(q.ready))] = index
		q.readyCount++
	}
}

// choose rotates Session, direction, then original owner. Only a group's first
// live slot participates in the outer rotation, so a Session with more owners
// cannot purchase more scheduling turns. Already queued entries keep their
// order; a newly eligible owner sees at most four previously selected entries.
func (q *sdkQueryLane) choose() int {
	for step := 1; step <= len(q.slots); step++ {
		anchor := (q.lastGroup + step) % len(q.slots)
		group := q.slots[anchor].group
		if group == nil {
			continue
		}
		first := true
		for i := 0; i < anchor; i++ {
			if q.slots[i].group == group {
				first = false
				break
			}
		}
		if !first {
			continue
		}
		for d := uint8(1); d <= 2; d++ {
			direction := (group.direction + d) % 2
			for offset := 1; offset <= len(q.slots); offset++ {
				index := (group.cursor[direction] + offset) % len(q.slots)
				s := &q.slots[index]
				if s.group == group && s.direction == direction && !s.ready && !s.active && (s.pending || s.closing) {
					group.direction, group.cursor[direction] = direction, index
					q.lastGroup = anchor
					return index
				}
			}
		}
	}
	return -1
}

func runSDKQueryStep(work sdkQueryWork, closing bool) (again bool, err error) {
	defer func() {
		if recover() != nil {
			again, err = false, ErrCompletionCallbackExit
		}
	}()
	if closing {
		work.queryClose()
		return false, nil
	}
	return work.queryStep()
}

func (e *ApplicationExecutor) runSDKQueries() {
	// A fixed SDK step must not Goexit. If it does, permanently fence this
	// original lane and drain its finite owners on this same worker's defers.
	// No replacement goroutine or second running responsibility is created.
	defer e.exitSDKQueryWorker()
	timer := time.NewTimer(25 * time.Millisecond)
	defer timer.Stop()
	for {
		e.mu.Lock()
		q := e.queries
		select {
		case <-q.sourceWake:
			q.wakeSources()
		default:
		}
		select {
		case <-timer.C:
			q.wakeDeadlines()
			timer.Reset(25 * time.Millisecond)
		default:
		}
		e.fillSDKQueryReadyLocked()
		if q.readyCount == 0 {
			closed, wake := e.closed, q.wake
			e.mu.Unlock()
			if closed {
				return
			}
			select {
			case <-timer.C:
				e.mu.Lock()
				q.wakeDeadlines()
				e.mu.Unlock()
				timer.Reset(25 * time.Millisecond)
			case <-wake:
			case <-q.sourceWake:
				e.mu.Lock()
				q.wakeSources()
				e.mu.Unlock()
			}
			continue
		}
		index := q.ready[q.readyHead]
		q.readyHead = (q.readyHead + 1) % uint8(len(q.ready))
		q.readyCount--
		s := &q.slots[index]
		s.ready, s.active, s.pending = false, true, false
		q.running = 1
		work, closing := s.work, s.closing
		e.fillSDKQueryReadyLocked()
		e.mu.Unlock()

		again, err := runSDKQueryStep(work, closing)
		work = nil
		e.mu.Lock()
		q.running, s.active = 0, false
		if closing {
			if err != nil {
				// Cleanup did not return normally. Keep the actual owner and
				// its backing, permanently fence the lane, and do not retry.
				q.failed = true
				s.err, s.cleanupFailed = err, true
				e.mu.Unlock()
				return
			}
			e.releaseSDKQueryLocked(index)
		} else if err != nil {
			s.closing, s.err = true, err
		} else {
			s.pending = s.pending || again
		}
		e.mu.Unlock()
	}
}

// A source signals only this coalesced root channel. The already admitted
// finite owner index absorbs the wake; it does not allocate a message job or
// a watcher per Session. Each concrete SDK owner checks its original input.
func (q *sdkQueryLane) wakeSources() {
	for i := range q.slots {
		if q.slots[i].registration != nil && !q.slots[i].closing {
			q.slots[i].pending = true
		}
	}
}

// Only original incoming sources need this timer opportunity when both full
// output vectors are held by old provider tails. Pending expiry can still use
// the original small ReplySlot. This creates no per-Session watcher or timer.
func (q *sdkQueryLane) wakeDeadlines() {
	for i := range q.slots {
		s := &q.slots[i]
		if _, ok := s.work.(*incomingSDKQuery); ok && !s.closing {
			s.pending = true
		}
	}
}

func (e *ApplicationExecutor) releaseSDKQueryLocked(index int) {
	q := e.queries
	s := &q.slots[index]
	r := s.registration
	r.mu.Lock()
	r.err = s.err
	r.executor.Store(nil)
	s.backing.Release()
	*s = sdkQuerySlot{}
	q.count--
	close(r.done)
	r.mu.Unlock()
}

func (e *ApplicationExecutor) exitSDKQueryWorker() {
	defer func() {
		e.mu.Lock()
		q := e.queries
		q.running, q.worker = 0, false
		for i := range q.slots {
			q.slots[i].active = false
		}
		e.cleanupLocked()
		e.mu.Unlock()
	}()
	e.mu.Lock()
	q := e.queries
	if !e.closed || q.count != 0 {
		q.failed = true
	}
	q.readyCount = 0
	for i := range q.slots {
		s := &q.slots[i]
		if s.registration == nil {
			continue
		}
		s.ready = false
		if s.cleanupFailed {
			// A failed cleanup has no evidence of physical release.
			continue
		}
		if s.err == nil {
			s.err = ErrCompletionCallbackExit
		}
		s.closing, s.active = true, true
		q.running = 1
		work := s.work
		e.mu.Unlock()
		_, err := runSDKQueryStep(work, true)
		work = nil
		e.mu.Lock()
		s.active = false
		if err == nil {
			e.releaseSDKQueryLocked(i)
		}
	}
	e.mu.Unlock()
}
