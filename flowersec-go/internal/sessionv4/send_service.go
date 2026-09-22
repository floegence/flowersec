package sessionv4

import (
	"context"
	"math"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

type sendServiceSignal struct {
	ready atomic.Bool
	wake  chan struct{}
}

func (s *sendServiceSignal) notify() {
	s.ready.Store(true)
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

type sendServiceSlot struct {
	queue  *SendQueue
	scope  uint64
	class  StreamClass
	busy   bool
	signal *sendServiceSignal
}

// SendService gives accepted DATA owners fixed Session publication workers.
// Each trusted StreamClass has its own declared share within the total; no
// application tag, new goroutine per Write or unbounded ready queue exists.
// This does not replace maintenance scheduling or provider flow-control
// reservations. Those retain their independent original service/byte owners.
type SendService struct {
	mu                        sync.Mutex
	admission                 *OpenAdmission
	reservation               resourcev4.Reference
	slots                     []sendServiceSlot
	workers                   [3]uint32
	cursor                    [3]int
	wake                      [3]chan struct{}
	stop, done                chan struct{}
	started, closed, stopping bool
	activeWorkers             uint32
	coordinatorActive         bool
	cleaned                   bool
	running                   atomic.Bool
	operationWake             chan struct{}
	bootstrapWake             chan struct{}
}

func SendServiceCharge(streams uint32, workers [3]uint32) (resourcev4.Vector, error) {
	count := uint64(workers[0]) + uint64(workers[1]) + uint64(workers[2])
	if streams == 0 || uint64(streams) > uint64(math.MaxInt) || count == 0 || count > 128 {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	bytes := uint64(unsafe.Sizeof(SendService{})) + uint64(streams)*uint64(unsafe.Sizeof(sendServiceSlot{}))
	return resourcev4.Vector{resourcev4.SDKBytes: bytes, resourcev4.Items: uint64(streams) + 1, resourcev4.Tasks: count + 1, resourcev4.WorkSlots: count + 1, resourcev4.Timers: 1}, nil
}

// NewSendService installs the one Session DATA scheduler before any OPEN or
// bootstrap flow is constructed. Fixed slots cover the original active bound;
// each enabled class has at least one publication worker. Host stacks/channels
// and provider/crypto costs remain part of the admitted complete profile.
func NewSendService(a *OpenAdmission, workers [3]uint32, reservation resourcev4.Reference) (*SendService, error) {
	if a == nil {
		return nil, cryptov4.ErrConfiguration
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed || a.runtime != nil || a.sendService != nil || a.active != 0 || a.pending != 0 || a.positiveProofs != 0 || a.rejectionProofs != 0 || a.bootstrap != nil {
		return nil, cryptov4.ErrConfiguration
	}
	count := uint64(0)
	for class, cap := range a.limits.PerClass {
		if cap != 0 && workers[class] == 0 || cap == 0 && workers[class] != 0 {
			return nil, cryptov4.ErrConfiguration
		}
		count += uint64(workers[class])
	}
	if count > uint64(a.engine.OrdinaryWorkSlots()) {
		return nil, cryptov4.ErrConfiguration
	}
	charge, err := SendServiceCharge(a.limits.Active, workers)
	if err != nil {
		return nil, err
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		return nil, err
	}
	s := &SendService{admission: a, reservation: owned, slots: make([]sendServiceSlot, int(a.limits.Active)), workers: workers, operationWake: make(chan struct{}, 1), bootstrapWake: make(chan struct{}, 1), stop: make(chan struct{}), done: make(chan struct{})}
	for class, n := range workers {
		s.wake[class] = make(chan struct{}, int(n))
	}
	a.sendService = s
	return s, nil
}

// attach is called only by original OPEN/bootstrap preparation with its trusted
// class, before the accepted outcome. The queue already owns its full backing.
func (s *SendService) attach(scope uint64, class StreamClass, q *SendQueue) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || class > ManagementStream || s.workers[class] == 0 {
		return cryptov4.ErrClosed
	}
	if err := s.reservation.CheckSameEnvironment(q.reservation); err != nil {
		return err
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.service != nil || q.pumping || q.closed || q.finComplete {
		return cryptov4.ErrConfiguration
	}
	for i := range s.slots {
		if s.slots[i].queue != nil && s.slots[i].scope == scope {
			return cryptov4.ErrConfiguration
		}
	}
	for i := range s.slots {
		slot := &s.slots[i]
		if slot.queue != nil {
			continue
		}
		slot.queue, slot.scope, slot.class = q, scope, class
		q.serviceNotify.wake = s.wake[class]
		slot.signal = &q.serviceNotify
		q.service = s
		q.serviceSignal.Store(slot.signal)
		if q.size != 0 || q.sealed {
			slot.signal.notify()
		}
		return nil
	}
	return cryptov4.ErrCapacity
}

func (s *SendService) pick(class StreamClass) (int, *SendQueue) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return -1, nil
	}
	for scanned := range len(s.slots) {
		i := (s.cursor[class] + scanned) % len(s.slots)
		slot := &s.slots[i]
		if slot.queue == nil || slot.class != class || slot.busy || !slot.signal.ready.Swap(false) {
			continue
		}
		// Crypto-availability broadcasts also reach private, empty OPEN
		// candidates. They own no send work and must not create worker tails
		// before acceptance. Their synchronous rollback can then detach the
		// same untouched queue without abandoning a physical worker alias.
		slot.queue.mu.Lock()
		work := !slot.queue.closed && (slot.queue.size != 0 || slot.queue.sealed)
		slot.queue.mu.Unlock()
		if !work {
			continue
		}
		slot.busy = true
		s.cursor[class] = (i + 1) % len(s.slots)
		return i, slot.queue
	}
	return -1, nil
}

func (s *SendService) detachLocked(slot *sendServiceSlot) {
	q := slot.queue
	q.serviceSignal.Store(nil)
	q.service = nil
	slot.queue = nil
	slot.signal.ready.Store(false)
	slot.signal = nil
}

func (s *SendService) detachStopped(q *SendQueue) {
	s.mu.Lock()
	defer s.mu.Unlock()
	q.mu.Lock()
	defer q.mu.Unlock()
	if !q.closed && !q.finComplete {
		return
	}
	for i := range s.slots {
		slot := &s.slots[i]
		if slot.queue == q && !slot.busy {
			s.detachLocked(slot)
			return
		}
	}
}

func (s *SendService) returned(index int, q *SendQueue, complete bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	slot := &s.slots[index]
	slot.busy = false
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed || q.finComplete {
		s.detachLocked(slot)
	} else if complete && (q.size != 0 || q.sealed) {
		slot.signal.notify()
	}
	// An event arriving during publication kept ready set while busy. Give
	// another original worker a chance without restarting a failed attempt.
	if slot.queue != nil && slot.signal.ready.Load() {
		select {
		case s.wake[slot.class] <- struct{}{}:
		default:
		}
	}
}

func (s *SendService) worker(ctx context.Context, class StreamClass) {
	defer func() {
		s.mu.Lock()
		s.activeWorkers--
		s.cleanupLocked()
		s.mu.Unlock()
	}()
	for {
		if ctx.Err() != nil {
			return
		}
		index, q := s.pick(class)
		if q != nil {
			result, _, err := q.pump(ctx, s)
			if err != nil && !sendQueueBackpressure(err) {
				q.Stop(err)
			}
			s.returned(index, q, result.Complete)
			s.admission.Collect()
			continue
		}
		select {
		case <-s.stop:
			return
		case <-ctx.Done():
			return
		case <-s.wake[class]:
		}
	}
}

// Run belongs to the admitted Session lifetime. One coordinator receives
// ordinary crypto-slot availability; it never consumes the idle watchdog's
// signal. Cancellation closes the original Session promptly while blocked
// provider workers keep their original resources until actual return.
func (s *SendService) Run(ctx context.Context) (err error) {
	if ctx == nil {
		return cryptov4.ErrConfiguration
	}
	s.mu.Lock()
	if s.started || s.closed {
		s.mu.Unlock()
		return cryptov4.ErrClosed
	}
	if err := s.reservation.Check(); err != nil {
		s.mu.Unlock()
		return err
	}
	s.started = true
	s.running.Store(true)
	s.coordinatorActive = true
	for class, n := range s.workers {
		for range n {
			s.activeWorkers++
			go s.worker(ctx, StreamClass(class))
		}
	}
	s.mu.Unlock()
	defer func() {
		s.running.Store(false)
		s.admission.closeWithCause(err)
		s.mu.Lock()
		s.coordinatorActive = false
		s.cleanupLocked()
		s.mu.Unlock()
	}()
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	defer timer.Stop()
	for {
		remaining, active := s.serviceOperations()
		var tick <-chan time.Time
		if active {
			timer.Reset(idleTimerChunk(max(remaining, 1)))
			tick = timer.C
		}
		select {
		case <-s.operationWake:
		case <-tick:
		case <-ctx.Done():
			return ctx.Err()
		case <-s.stop:
			return cryptov4.ErrClosed
		case <-s.admission.engine.Done():
			return cryptov4.ErrClosed
		case <-s.admission.engine.SendWake():
			// The original initializer observes its own bounded hint. It must
			// never compete with this sole consumer of Engine availability.
			select {
			case s.bootstrapWake <- struct{}{}:
			default:
			}
			s.mu.Lock()
			for i := range s.slots {
				if s.slots[i].queue != nil {
					s.slots[i].signal.notify()
				}
			}
			s.mu.Unlock()
		}
		timer.Stop()
	}
}

func (s *SendService) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed, s.stopping = true, true
	s.running.Store(false)
	close(s.stop)
	s.mu.Unlock()
	// Closed forbids slot reuse. No service gate is held across original flow
	// Stop, and workers remain responsible for their already-started provider.
	for i := range s.slots {
		s.mu.Lock()
		q := s.slots[i].queue
		s.mu.Unlock()
		if q != nil {
			q.Stop(cryptov4.ErrClosed)
		}
	}
	s.mu.Lock()
	s.stopping = false
	s.cleanupLocked()
	s.mu.Unlock()
}

func (s *SendService) cleanupLocked() {
	if !s.closed || s.stopping || s.activeWorkers != 0 || s.coordinatorActive || s.cleaned {
		return
	}
	for i := range s.slots {
		slot := &s.slots[i]
		if slot.queue != nil {
			q := slot.queue
			q.mu.Lock()
			s.detachLocked(slot)
			q.mu.Unlock()
		}
	}
	s.cleaned = true
	close(s.done)
}

func (s *SendService) WaitCleanup(ctx context.Context) error {
	if ctx == nil {
		return cryptov4.ErrConfiguration
	}
	select {
	case <-s.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *SendService) retire() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.cleaned {
		return cryptov4.ErrCapacity
	}
	s.slots = nil
	s.admission = nil
	s.reservation.Release()
	return nil
}

// Provider workers never own this pass. Original request deadlines therefore
// remain observable even when every publication worker is blocked in host I/O.
func (s *SendService) serviceOperations() (uint64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	next, active := uint64(math.MaxUint64), false
	if s.closed {
		return next, false
	}
	for i := range s.slots {
		if q := s.slots[i].queue; q != nil {
			q.mu.Lock()
			remaining, live := q.serviceOperationsLocked()
			q.cleanupLocked()
			q.mu.Unlock()
			if live {
				next, active = min(next, remaining), true
			}
		}
	}
	return next, active
}
