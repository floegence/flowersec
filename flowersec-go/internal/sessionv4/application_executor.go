package sessionv4

import (
	"math"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

// ApplicationWorkClass is fixed by trusted local registration. Peer metadata,
// the payload and callback suspension cannot change a job's original class.
type ApplicationWorkClass uint8

const (
	ApplicationShort ApplicationWorkClass = iota
	ApplicationResident
)

// ApplicationExecutorConfig describes the ordinary execution service. Resident
// work shares its original running slots and leaves a strict short-work floor.
// RuntimeBytes covers qualified shared and per-descriptor channel/allocator
// overhead. Completion stacks belong to the shared running service, not every
// dormant future descriptor.
// RuntimeBytesPerTask is the qualified host's stack/scheduler allowance, not a
// restriction on arbitrary application allocation. Payload/codec/input owners
// have their own original full reservations and are never folded into it.
type ApplicationExecutorConfig struct {
	Running, ResidentRunning              uint32
	Ready, ResidentReady                  uint32
	CompletionRunning, CompletionReserved uint32
	// QueryOwners is the finite original query index, including idle sources.
	// Zero disables the fixed SDK lane. Its one worker and four ready entries
	// are shared by the whole root, independently of ordinary/Completion work.
	QueryOwners         uint32
	RuntimeBytes        uint64
	RuntimeBytesPerTask uint64
}

type applicationTaskSlot struct {
	active    bool
	started   bool
	committed bool
	class     ApplicationWorkClass
	group     *applicationGroup
	permit    *ApplicationPermit
	result    *ApplicationTask
	backing   resourcev4.Reference
	task      resourcev4.Reference
}

// ApplicationExecutor is the one root-scoped ordinary execution gate shared by
// participating Environments/Sessions. Try-now admission requires an actual
// running slot; explicitly queued SDK invocations use the same finite ordinary
// service and preserve their original complete backing. Go schedules only
// already admitted running tasks. Completion has separate protected
// reservation/running capacity in this same root executor. Management, diagnostics
// and protocol maintenance never borrow the ordinary or Completion positions.
type ApplicationExecutor struct {
	availability                       chan struct{}
	ready                              []applicationReadySlot
	readyCount, residentReady          uint32
	readyGroups, readyGroupTails       [2]*applicationGroup
	queueClass                         ApplicationWorkClass
	queries                            *sdkQueryLane
	completions                        []completionSlot
	completionCount, completionRunning uint32
	completionClaims                   uint32
	completionOrder                    uint64
	mu                                 sync.Mutex
	config                             ApplicationExecutorConfig
	reservation                        resourcev4.Reference
	slots                              []applicationTaskSlot
	running                            uint32
	resident                           uint32
	closed                             bool
	cleaned                            bool
	done                               chan struct{}
}

func ApplicationExecutorCharge(config ApplicationExecutorConfig) (resourcev4.Vector, error) {
	metadata := max(max(uint64(unsafe.Sizeof(ApplicationPermit{})), uint64(unsafe.Sizeof(QueuedApplicationTask{})))+uint64(unsafe.Sizeof(ApplicationTask{})), uint64(unsafe.Sizeof(CompletionReservation{}))+uint64(unsafe.Sizeof(CompletionTask{}))+uint64(unsafe.Sizeof(CompletionFloor{})))
	if config.Ready > 65536 || config.Ready == 0 && config.ResidentReady != 0 || config.Ready != 0 && config.ResidentReady >= config.Ready {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	if (config.CompletionRunning == 0) != (config.CompletionReserved == 0) || config.CompletionRunning > config.CompletionReserved || config.CompletionReserved > 65536 {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	if config.Running == 0 || config.ResidentRunning >= config.Running || config.RuntimeBytes == 0 || config.RuntimeBytesPerTask == 0 || config.RuntimeBytesPerTask > math.MaxUint64-metadata {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	fixed, slot := uint64(unsafe.Sizeof(ApplicationExecutor{})), uint64(unsafe.Sizeof(applicationTaskSlot{}))
	if config.RuntimeBytes > math.MaxUint64-fixed {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	fixed += config.RuntimeBytes
	if uint64(config.Running) > (math.MaxUint64-fixed)/slot || uint64(config.Running) > uint64(math.MaxInt)/slot {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	charge, err := (resourcev4.Vector{resourcev4.SDKBytes: fixed + uint64(config.Running)*slot, resourcev4.Items: uint64(config.Running) + 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: uint64(config.CompletionReserved) * uint64(unsafe.Sizeof(completionSlot{})), resourcev4.Items: uint64(config.CompletionReserved)})
	if err != nil {
		return resourcev4.Vector{}, err
	}
	if config.CompletionRunning != 0 && config.RuntimeBytesPerTask > math.MaxUint64/uint64(config.CompletionRunning) {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	charge, err = charge.Add(resourcev4.Vector{resourcev4.SDKBytes: uint64(config.CompletionRunning) * config.RuntimeBytesPerTask, resourcev4.Tasks: uint64(config.CompletionRunning), resourcev4.WorkSlots: uint64(config.CompletionRunning)})
	if err != nil {
		return resourcev4.Vector{}, err
	}
	charge, err = charge.Add(resourcev4.Vector{resourcev4.SDKBytes: uint64(config.Ready) * uint64(unsafe.Sizeof(applicationReadySlot{})), resourcev4.Items: uint64(config.Ready)})
	if err != nil {
		return resourcev4.Vector{}, err
	}
	query, err := sdkQueryLaneCharge(config)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	return charge.Add(query)
}

// TaskCharge is acquired by the original invocation's complete admission in
// its own tenant/Environment/Session accounts. No idle executor goroutine exists;
// these actual task/stack resources must not be counted twice in its metadata.
// An unstarted permit holds the same complete charge before OPEN acceptance.
func (e *ApplicationExecutor) TaskCharge() resourcev4.Vector {
	return resourcev4.Vector{resourcev4.SDKBytes: e.config.RuntimeBytesPerTask + max(uint64(unsafe.Sizeof(ApplicationPermit{})), uint64(unsafe.Sizeof(QueuedApplicationTask{}))) + uint64(unsafe.Sizeof(ApplicationTask{})), resourcev4.Items: 2, resourcev4.Tasks: 1, resourcev4.WorkSlots: 1}
}

// ApplicationPermit owns one already charged ordinary execution position.
// Start consumes it once after the original invocation's acceptance gates.
// Close returns only unstarted ownership; it never cancels a running callback.
// The executor pointer is cleared at either outcome so retained permit aliases
// do not keep the executor, input or other callbacks alive after consumption.
type ApplicationPermit struct {
	executor atomic.Pointer[ApplicationExecutor]
	index    int
}

// ApplicationTask is a detached notification of one original callback task's
// actual exit, including its defers and input/resource handoff. It contains no
// executor, callback, input, Session or reservation reference.
type ApplicationTask struct{ done chan struct{} }

func (task *ApplicationTask) Done() <-chan struct{} { return task.done }

// NewApplicationExecutor belongs to the trusted root factory. The same object
// must be supplied to every borrower. A second constructor cannot obtain a new
// allowance even after the first executor has closed or completed its cleanup.
func NewApplicationExecutor(config ApplicationExecutorConfig, reservation resourcev4.Reference) (*ApplicationExecutor, error) {
	charge, err := ApplicationExecutorCharge(config)
	if err != nil {
		return nil, err
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		return nil, err
	}
	if err := owned.ClaimApplicationExecutor(); err != nil {
		owned.Release()
		return nil, err
	}
	e := &ApplicationExecutor{availability: make(chan struct{}), config: config, reservation: owned, slots: make([]applicationTaskSlot, int(config.Running)), ready: make([]applicationReadySlot, config.Ready), completions: make([]completionSlot, config.CompletionReserved), done: make(chan struct{})}
	if config.QueryOwners != 0 {
		e.queries = &sdkQueryLane{slots: make([]sdkQuerySlot, config.QueryOwners), wake: make(chan struct{}, 1), sourceWake: make(chan struct{}, 1), worker: true, lastGroup: -1}
		go e.runSDKQueries()
	}
	return e, nil
}

// TrySubmit fixes one actual running responsibility before creating its Go task.
// backing is the original invocation's already admitted metadata/input owner;
// the task borrows that exact charge until callback exit, including cancellation
// or timeout. The caller must provide its original invocation authorization gate
// inside work: this executor grants resources, never protocol/business authority.
func (e *ApplicationExecutor) TrySubmit(class ApplicationWorkClass, taskReservation, backing resourcev4.Reference, work func()) (*ApplicationTask, error) {
	if work == nil {
		return nil, cryptov4.ErrConfiguration
	}
	e.mu.Lock()
	permit, err := e.acquireLocked(class, taskReservation, backing, false)
	if err != nil {
		e.mu.Unlock()
		return nil, err
	}
	result, err := e.startLocked(permit)
	e.mu.Unlock()
	if err != nil {
		return nil, err
	}
	go e.run(permit.index, work, result)
	return result, nil
}

// trySubmitJoined keeps the original task and input backing charged through a
// finite SDK join. callbackExited proves all application defers have returned;
// the public task Done remains closed only after that join and slot release.
// join is internal cleanup and must never enter application code or wait on it.
func (e *ApplicationExecutor) trySubmitJoined(class ApplicationWorkClass, taskReservation, backing resourcev4.Reference, work, join func()) (<-chan struct{}, error) {
	if work == nil || join == nil {
		return nil, cryptov4.ErrConfiguration
	}
	e.mu.Lock()
	permit, err := e.acquireLocked(class, taskReservation, backing, false)
	if err != nil {
		e.mu.Unlock()
		return nil, err
	}
	result, err := e.startLocked(permit)
	e.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return e.launchJoined(permit, result, work, join), nil
}

// startJoined consumes an already admitted ordinary/resident permit. Durable
// registration can therefore own the real executor position before its write.
func (p *ApplicationPermit) startJoined(work, join func()) (<-chan struct{}, error) {
	if p == nil || work == nil || join == nil {
		return nil, cryptov4.ErrConfiguration
	}
	e := p.executor.Load()
	if e == nil {
		return nil, resourcev4.ErrClosed
	}
	e.mu.Lock()
	result, err := e.startLocked(p)
	e.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return e.launchJoined(p, result, work, join), nil
}

func (e *ApplicationExecutor) launchJoined(permit *ApplicationPermit, result *ApplicationTask, work, join func()) <-chan struct{} {
	callbackExited := make(chan struct{})
	go func() {
		defer func() {
			// Resource retirement is guaranteed even if an internal join fails.
			defer func() {
				e.mu.Lock()
				e.releaseLocked(permit.index)
				close(result.done)
				e.cleanupLocked()
				e.mu.Unlock()
			}()
			work = nil
			close(callbackExited)
			join()
			join = nil
		}()
		work()
	}()
	return callbackExited
}

// TryAcquire reserves an actual execution position before a protocol owner
// accepts work. It has no queue, worker or callback. Capacity, root and original
// Environment checks precede Take, so a rejected request keeps its reservation.
func (e *ApplicationExecutor) TryAcquire(class ApplicationWorkClass, taskReservation, backing resourcev4.Reference) (*ApplicationPermit, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.acquireLocked(class, taskReservation, backing, false)
}

// TryAcquireWithBackingBorrow moves the original invocation's already admitted
// backing borrow without taking another reference slot. Rejection before that
// move preserves both handles. A later task Take failure releases the moved
// borrow; the caller must supply the complete original TaskCharge.
func (e *ApplicationExecutor) TryAcquireWithBackingBorrow(class ApplicationWorkClass, taskReservation, backingBorrow resourcev4.Reference) (*ApplicationPermit, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.acquireLocked(class, taskReservation, backingBorrow, true)
}

func (e *ApplicationExecutor) acquireLocked(class ApplicationWorkClass, taskReservation, backing resourcev4.Reference, moveBorrow bool) (*ApplicationPermit, error) {
	if class > ApplicationResident || taskReservation == backing {
		return nil, cryptov4.ErrConfiguration
	}
	if e.closed {
		return nil, resourcev4.ErrClosed
	}
	if err := e.reservation.CheckSameRoot(backing); err != nil {
		return nil, err
	}
	if err := taskReservation.CheckSameEnvironment(backing); err != nil {
		return nil, err
	}
	if e.running == e.config.Running || class == ApplicationResident && e.resident == e.config.ResidentRunning {
		return nil, cryptov4.ErrCapacity
	}
	var borrow resourcev4.Reference
	var err error
	if moveBorrow {
		borrow, err = backing.TakeBorrow()
	} else {
		borrow, err = backing.Borrow()
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
	for e.slots[index].active {
		index++
	}
	permit := &ApplicationPermit{index: index}
	result := &ApplicationTask{done: make(chan struct{})}
	e.slots[index] = applicationTaskSlot{active: true, class: class, permit: permit, result: result, backing: borrow, task: task}
	e.running++
	if class == ApplicationResident {
		e.resident++
	}
	permit.executor.Store(e)
	return permit, nil
}

// Start admits at most one callback, outside every executor gate. A racing
// Close either revokes this still-unstarted permit or leaves the committed
// callback charged through its actual exit. Resource admission does not replace
// the original invocation's authorization checks inside work.
func (p *ApplicationPermit) Start(work func()) (*ApplicationTask, error) {
	if p == nil || work == nil {
		return nil, cryptov4.ErrConfiguration
	}
	e := p.executor.Load()
	if e == nil {
		return nil, resourcev4.ErrClosed
	}
	e.mu.Lock()
	result, err := e.startLocked(p)
	e.mu.Unlock()
	if err != nil {
		return nil, err
	}
	go e.run(p.index, work, result)
	return result, nil
}

// commitAcceptance is the SDK's OPEN commit gate. A shutdown that won first
// rejects acceptance. Once this gate wins, shutdown retains the still-unstarted
// responsibility until the original caller starts or explicitly releases it.
// Closing the executor still prevents later callback entry through Start.
func (p *ApplicationPermit) commitAcceptance() error {
	if p == nil {
		return resourcev4.ErrClosed
	}
	e := p.executor.Load()
	if e == nil {
		return resourcev4.ErrClosed
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || p.executor.Load() != e || p.index >= len(e.slots) || e.slots[p.index].permit != p {
		return resourcev4.ErrClosed
	}
	s := &e.slots[p.index]
	if err := s.task.Check(); err != nil {
		return err
	}
	if err := s.backing.Check(); err != nil {
		return err
	}
	if s.committed {
		return cryptov4.ErrTransition
	}
	s.committed = true
	return nil
}

func (e *ApplicationExecutor) startLocked(p *ApplicationPermit) (*ApplicationTask, error) {
	if e.closed || p.executor.Load() != e || p.index >= len(e.slots) || e.slots[p.index].permit != p {
		return nil, resourcev4.ErrClosed
	}
	s := &e.slots[p.index]
	err := s.task.Check()
	if err == nil {
		err = s.backing.Check()
	}
	if err != nil {
		e.releaseLocked(p.index)
		e.cleanupLocked()
		return nil, err
	}
	s.started, s.permit = true, nil
	p.executor.Store(nil)
	return s.result, nil
}

func (p *ApplicationPermit) Close() {
	if p == nil {
		return
	}
	e := p.executor.Load()
	if e == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if p.executor.Load() != e || p.index >= len(e.slots) || e.slots[p.index].permit != p {
		return
	}
	e.releaseLocked(p.index)
	e.cleanupLocked()
}

func (e *ApplicationExecutor) releaseLocked(index int) {
	s := &e.slots[index]
	if s.permit != nil {
		s.permit.executor.Store(nil)
	}
	if s.class == ApplicationResident {
		e.resident--
	}
	s.backing.Release()
	s.task.Release()
	e.releaseApplicationGroupLocked(s.group)
	*s = applicationTaskSlot{}
	e.running--
	e.dispatchQueuedLocked()
}

func (e *ApplicationExecutor) run(index int, work func(), result *ApplicationTask) {
	defer func() {
		// The application has truly returned, including all of its defers.
		// No callback pointer, input or user code is retained in the slot.
		work = nil
		e.mu.Lock()
		e.releaseLocked(index)
		close(result.done)
		e.cleanupLocked()
		e.mu.Unlock()
	}()
	work()
}

// Close is root-owned shutdown, never an individual Session/Environment close.
// It revokes unstarted permits while noncooperative callbacks keep their real
// positions, input aliases and the original complete executor backing charged.
func (e *ApplicationExecutor) Close() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.closed = true
	e.notifyAvailabilityLocked()
	for i := range e.ready {
		if e.ready[i].handle != nil && !e.ready[i].cleanup {
			e.cancelReadyLocked(i)
		}
	}
	if e.queries != nil {
		for i := range e.queries.slots {
			if e.queries.slots[i].registration != nil {
				e.queries.slots[i].closing = true
			}
		}
		e.wakeSDKQueriesLocked()
	}
	for i := range e.slots {
		if e.slots[i].active && !e.slots[i].started && !e.slots[i].committed {
			e.releaseLocked(i)
		}
	}
	e.cleanupLocked()
}

func (e *ApplicationExecutor) cleanupLocked() {
	if !e.closed || e.cleaned || e.running != 0 || e.readyCount != 0 || e.completionCount != 0 || e.queries != nil && (e.queries.worker || e.queries.count != 0) {
		return
	}
	e.cleaned = true
	e.slots = nil
	e.ready = nil
	e.completions = nil
	if e.queries != nil {
		e.queries.slots = nil
	}
	e.reservation.Release()
	e.reservation = resourcev4.Reference{}
	close(e.done)
}

// Done reports actual cleanup, not cancellation or a request to close. A wait
// needs only this detached notification channel and never acquires another job.
func (e *ApplicationExecutor) Done() <-chan struct{} { return e.done }

// Running counts occupied positions, including preadmitted unstarted permits.
// Those permits consume the same resident bound and strict short-work floor.
type ApplicationExecutorSnapshot struct {
	QueryOwners, QueryReady, QueryRunning                   uint32
	QueryFailed                                             bool
	CompletionReserved, CompletionRunning, CompletionClaims uint32
	Running, ResidentRunning                                uint32
	Ready, ResidentReady                                    uint32
	Closed, CleanupComplete                                 bool
}

func (e *ApplicationExecutor) Snapshot() ApplicationExecutorSnapshot {
	e.mu.Lock()
	defer e.mu.Unlock()
	s := ApplicationExecutorSnapshot{CompletionClaims: e.completionClaims, CompletionReserved: e.completionCount, CompletionRunning: e.completionRunning, Running: e.running, ResidentRunning: e.resident, Ready: e.readyCount, ResidentReady: e.residentReady, Closed: e.closed, CleanupComplete: e.cleaned}
	if q := e.queries; q != nil {
		s.QueryOwners, s.QueryReady, s.QueryRunning, s.QueryFailed = q.count, uint32(q.readyCount), q.running, q.failed
	}
	return s
}

// Original SDK pumps wait on this bounded shared generation. Capacity changes
// wake all existing owners without a per-event polling task or private queue.
func (e *ApplicationExecutor) availabilitySnapshot() <-chan struct{} {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.availability
}
func (e *ApplicationExecutor) notifyAvailabilityLocked() {
	if e.availability != nil {
		close(e.availability)
	}
	e.availability = make(chan struct{})
}
