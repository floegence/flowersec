package sessionv4

import (
	"context"
	"math"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// The source dispatcher already owns the original authenticated fanout gate.
// This copy goes directly into the single root queue, with a full input/task
// vector in the source's scopes and an actual scoped alias to the root.
func (source *controllerNotificationSource) enqueueLocked(deadline *timev4.Deadline, payload []byte, sample timev4.Sample, digest [32]byte) error {
	n, d := source.root, source.dispatch
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed || source.closed || source.detached || digest != source.digest {
		return rpcv4.ErrClosed
	}
	index, pending := -1, 0
	var old *controllerNotificationDelivery
	for i, j := range n.jobs {
		if j == nil {
			if index < 0 {
				index = i
			}
			continue
		}
		if !j.entered {
			pending++
		}
		if !j.entered && !j.canceled {
			old = j
		}
	}
	if index < 0 || pending >= 16 || n.serial == math.MaxUint64 {
		return rpcv4.ErrCapacity
	}
	if n.options.Pending == NotificationLatestPending && old != nil && old.source.eligible && !source.eligible {
		return rpcv4.ErrCapacity
	}
	metadata, err := (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(controllerNotificationDelivery{})) + applicationContextBytes() + uint64(unsafe.Sizeof(notificationInvocation{})) + uint64(unsafe.Sizeof(timev4.Deadline{})) + uint64(len(payload)), resourcev4.Items: 2}).Add(resourcev4.Vector{resourcev4.SDKBytes: n.options.RuntimeBytes})
	if err != nil {
		return err
	}
	var refs [2]resourcev4.Reference
	if err := d.reserveLocked([]resourcev4.Vector{metadata, n.executor.TaskCharge()}, refs[:]); err != nil {
		return err
	}
	keep := false
	defer func() {
		if !keep {
			for _, ref := range refs {
				ref.Release()
			}
		}
	}()
	copyDeadline, err := deadline.ForkAt(deadline.Cap(), sample)
	if err != nil {
		return err
	}
	tail, err := n.reservation.BorrowInScopesOf(refs[0])
	if err != nil {
		return err
	}
	n.serial++
	ctx, cancel := context.WithCancelCause(context.Background())
	ctx = context.WithValue(ctx, notificationInvocationKey{}, &notificationInvocation{root: n})
	job := &controllerNotificationDelivery{root: n, source: source, serial: n.serial, payload: append([]byte(nil), payload...), deadline: copyDeadline, ctx: ctx, cancel: cancel, reservation: refs[0], taskReservation: refs[1], rootTail: tail}
	if n.options.Pending == NotificationLatestPending && old != nil {
		old.canceled = true
		old.cancel(rpcv4.ErrClosed)
		if old.queued != nil {
			old.queued.Cancel()
		}
		n.recordGapLocked(old.source.generation, source.generation, NotificationGapCoalesced, 1, false)
	}
	source.jobs++
	n.jobs[index] = job
	keep = true
	n.updateStatusLocked()
	return nil
}

func (n *controllerNotificationRoot) reapDeliveriesLocked(sample timev4.Sample, sampleErr error) {
	for index, job := range n.jobs {
		if job == nil {
			continue
		}
		if !job.canceled && (n.closed || job.source.closed || sampleErr != nil || job.deadline.CheckAt(sample) != nil) {
			job.canceled = true
			job.cancel(rpcv4.ErrClosed)
			if job.queued != nil {
				job.queued.Cancel()
			}
			if !job.entered {
				n.recordGapLocked(job.source.generation, job.source.generation, NotificationGapExpired, 1, true)
			}
		}
		if !controllerNotificationJobDone(job) {
			continue
		}
		if n.active == job {
			n.active = nil
		}
		job.source.jobs--
		releaseControllerNotificationJob(job)
		n.jobs[index] = nil
	}
	if job := n.active; job != nil && job.isGap && controllerNotificationJobDone(job) {
		releaseControllerNotificationJob(job)
		n.active = nil
	}
}

func controllerNotificationJobDone(job *controllerNotificationDelivery) bool {
	if job.queued == nil {
		return job.canceled
	}
	select {
	case <-job.queued.Done():
		return true
	default:
		return false
	}
}

func releaseControllerNotificationJob(job *controllerNotificationDelivery) {
	job.cancel(rpcv4.ErrClosed)
	clear(job.payload)
	job.payload = nil
	job.rootTail.Release()
	job.reservation.Release()
	job.taskReservation.Release()
	job.services.releaseInvocation()
	job.services = nil
	job.rootTail, job.reservation, job.taskReservation = resourcev4.Reference{}, resourcev4.Reference{}, resourcev4.Reference{}
	job.ctx, job.cancel, job.deadline, job.queued, job.source, job.root = nil, nil, nil, nil, nil, nil
}

// Only the original coordinator submits application work. Unpublished inputs
// may be skipped, preserving FIFO among eligible entries from every source.
func (n *controllerNotificationRoot) queueNextLocked(dataReady bool) {
	if n.closed || n.active != nil {
		return
	}
	var next *controllerNotificationDelivery
	for _, job := range n.jobs {
		if dataReady && job != nil && !job.canceled && job.source.eligible && !job.source.closed && (next == nil || job.serial < next.serial) {
			next = job
		}
	}
	if n.gapDirty && (next == nil || !n.lastWasGap) {
		backing, err := n.gapBacking.Checkout()
		if err != nil {
			return
		}
		task, err := n.gapTask.Checkout()
		if err != nil {
			backing.Release()
			return
		}
		ctx, cancel := context.WithCancelCause(context.Background())
		ctx = context.WithValue(ctx, notificationInvocationKey{}, &notificationInvocation{root: n})
		next = &controllerNotificationDelivery{root: n, isGap: true, gap: n.gapPending, ctx: ctx, cancel: cancel, reservation: backing, taskReservation: task}
	}
	if next == nil {
		return
	}
	class := ApplicationShort
	if !next.isGap {
		class = next.source.token.method.method.WorkClass
		if err := n.services.retainRegistration(); err != nil {
			return
		}
		next.services = n.services
	}
	queued, err := n.executor.queueApplication(n.group, class, next.taskReservation, next.reservation, next.run)
	if err != nil {
		if next.isGap {
			releaseControllerNotificationJob(next)
		} else {
			next.canceled = true
			next.cancel(err)
			n.recordGapLocked(next.source.generation, next.source.generation, NotificationGapCapacity, 1, false)
		}
		return
	}
	next.queued, n.active = queued, next
	n.lastWasGap = next.isGap
	if next.isGap {
		n.gapDirty = false
		n.gapPending = ControllerNotificationGap{}
	}
}

func (job *controllerNotificationDelivery) dataGate(enter bool) (string, error) {
	n, source := job.root, job.source
	phase := ""
	err := source.dispatch.withAuthoritySample(source.token.method.method.Method, func(_ notificationMethod, sample timev4.Sample) error {
		n.mu.Lock()
		defer n.mu.Unlock()
		if n.closed || source.closed || !source.eligible || job.canceled || job.ctx.Err() != nil || n.active != job {
			return rpcv4.ErrClosed
		}
		if err := job.deadline.CheckAt(sample); err != nil {
			return err
		}
		phase = source.phase
		if enter {
			job.entered = true
			n.updateStatusLocked()
		}
		return nil
	})
	return phase, err
}

func (job *controllerNotificationDelivery) run() {
	n := job.root
	reason := NotificationGapHandler
	returned := false
	defer func() {
		if recover() != nil || !returned {
			reason = NotificationGapHandler
		}
		if reason != 0 {
			n.mu.Lock()
			generation := uint64(0)
			if job.source != nil {
				generation = job.source.generation
			}
			// A failed gap callback remains visible in the compact status and
			// never queues itself again into an unbounded callback-error loop.
			if job.isGap {
				s := n.subscription
				s.mu.Lock()
				mergeNotificationGap(&s.observation.Gap, 0, 0, reason, 0, false)
				s.mu.Unlock()
			} else {
				n.recordGapLocked(generation, generation, reason, 0, true)
			}
			n.mu.Unlock()
		}
	}()
	class := ApplicationShort
	if job.isGap {
		n.mu.Lock()
		if n.closed || job.canceled || n.active != job {
			n.mu.Unlock()
			reason, returned = 0, true
			return
		}
		job.entered = true
		n.updateStatusLocked()
		n.mu.Unlock()
	} else {
		if _, err := job.dataGate(true); err != nil {
			reason, returned = NotificationGapSourceClosed, true
			return
		}
		class = job.source.token.method.method.WorkClass
	}
	callCtx, exit, err := enterApplicationContext(job.ctx, n.executor, ordinaryApplicationLane, class, job.reservation, nil)
	if err != nil {
		reason, returned = NotificationGapSourceClosed, true
		return
	}
	defer exit()
	if job.isGap {
		// Local gap delivery needs no surviving Session or payload authority.
		if err = n.observer.Handle(callCtx, ControllerNotificationEvent{Kind: "observation_gap", Gap: job.gap}); err == nil {
			reason = 0
		}
		returned = true
		return
	}
	if err = attachInvocationServices(callCtx, job.services); err != nil {
		reason, returned = NotificationGapSourceClosed, true
		return
	}
	value, err := n.observer.Decode(callCtx, job.payload)
	if err != nil {
		reason, returned = NotificationGapInvalidPayload, true
		return
	}
	phase, err := job.dataGate(false)
	if err != nil {
		reason, returned = NotificationGapSourceClosed, true
		return
	}
	if err = n.observer.Handle(callCtx, ControllerNotificationEvent{Kind: "notification", Value: value, SourceGeneration: job.source.generation, SourcePhase: phase}); err == nil {
		reason = 0
	}
	returned = true
}
