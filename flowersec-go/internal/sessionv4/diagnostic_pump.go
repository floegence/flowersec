package sessionv4

import (
	"context"
	"math"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/diagnosticv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

func (s *DiagnosticSink) run() {
	timer := time.NewTimer(diagnosticBucket)
	defer timer.Stop()
	closing := s.executorClosing
	for {
		// A continuously nonempty producer queue must not starve root Close.
		select {
		case <-closing:
			s.mu.Lock()
			s.closeLocked()
			s.mu.Unlock()
			closing = nil
		default:
		}
		s.rotate()
		s.mu.Lock()
		s.reapLocked()
		if s.reservation.Check() != nil {
			s.closeLocked()
		}
		if s.closed && s.idleLocked() {
			s.operations, s.queue, s.ids = nil, nil, nil
			s.executor, s.callback, s.ctx, s.cancel, s.executorClosing = nil, nil, nil, nil, nil
			s.now, s.sample = nil, nil
			s.reservation.Release()
			s.reservation = resourcev4.Reference{}
			s.cleaned = true
			close(s.done)
			s.mu.Unlock()
			return
		}
		more := !s.closed && s.queued != 0
		s.mu.Unlock()
		if more {
			s.dispatch()
			continue
		}
		now := s.now()
		seconds := now.UTC().Unix() % int64(diagnosticBucket/time.Second)
		if seconds < 0 {
			seconds += int64(diagnosticBucket / time.Second)
		}
		delay := diagnosticBucket - time.Duration(seconds)*time.Second - time.Duration(now.Nanosecond())
		// UTC determines privacy buckets, never protocol authorization. A
		// wall-clock change cannot resurrect an earlier ID or queue entry.
		if delay <= 0 || delay > diagnosticBucket {
			delay = diagnosticBucket
		}
		timer.Reset(delay)
		select {
		case <-s.wake:
		case <-timer.C:
		case <-closing:
			s.mu.Lock()
			s.closeLocked()
			s.mu.Unlock()
			closing = nil
		}
	}
}

func (s *DiagnosticSink) idleLocked() bool {
	for i := range s.deliveries {
		if s.deliveries[i].task != nil {
			return false
		}
	}
	return true
}

func (s *DiagnosticSink) reapLocked() {
	for i := range s.deliveries {
		d := &s.deliveries[i]
		if d.task == nil {
			continue
		}
		select {
		case <-d.task.done:
			if d.pending {
				s.drop()
			}
			*d = diagnosticDelivery{}
		default:
		}
	}
}

func (s *DiagnosticSink) rotate() {
	s.mu.Lock()
	needed := !s.closed && s.bucket != utcDiagnosticBucket(s.now())
	s.mu.Unlock()
	if !needed {
		return
	}
	// Random draws are outside the producer gate and transport call chain.
	// This scratch array is part of the admitted SDK pump stack allowance.
	var ids [diagnosticMaxIDs][16]byte
	fillDiagnosticIDs(ids[:])
	s.mu.Lock()
	defer s.mu.Unlock()
	defer clear(ids[:])
	if s.closed {
		return
	}
	if s.generation == math.MaxUint64 {
		s.closeLocked()
		return
	}
	s.generation++
	s.bucket = utcDiagnosticBucket(s.now())
	s.discardQueueLocked()
	copy(s.ids, ids[:])
	s.nextID, s.events = 0, 0
	for i := range s.operations {
		o := &s.operations[i]
		if o.handle == nil {
			continue
		}
		o.id = s.ids[s.nextID]
		clear(s.ids[s.nextID][:])
		s.nextID++
	}
	for i := range s.deliveries {
		d := &s.deliveries[i]
		if d.pending {
			s.drop()
		}
		d.pending = false
		d.event = diagnosticv4.Event{}
		if d.task != nil {
			d.task.cancel(context.Canceled)
		}
	}
}

func (s *DiagnosticSink) dispatch() {
	// Sampling may involve the OS CSPRNG; only this original admitted task
	// performs it. A concurrent rotation/Close is checked before publication.
	sampled := s.sample(s.policy.sample)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.queued == 0 {
		return
	}
	q := s.queue[s.first]
	s.queue[s.first] = diagnosticQueuedEvent{}
	s.first = (s.first + 1) % s.policy.queue
	s.queued--
	s.queueBytes -= uint32(q.length)
	if !sampled {
		return
	}
	if s.bucket != utcDiagnosticBucket(s.now()) || s.events == diagnosticMaxEvents {
		s.drop()
		return
	}
	s.events++
	index := -1
	for i := range s.deliveries {
		if s.deliveries[i].task == nil {
			index = i
			break
		}
	}
	if index < 0 {
		s.drop()
		return
	}
	borrow, err := s.reservation.Borrow()
	if err != nil {
		s.drop()
		return
	}
	s.deliveries[index] = diagnosticDelivery{event: q.event, generation: s.generation, pending: true}
	task, err := s.executor.enqueueDiagnostic(s.ctx, borrow, func(ctx context.Context) { s.deliver(index, ctx) }, s.wake)
	if err != nil {
		borrow.Release()
		s.deliveries[index] = diagnosticDelivery{}
		s.drop()
		return
	}
	s.deliveries[index].task = task
}

func (s *DiagnosticSink) deliver(index int, ctx context.Context) {
	s.mu.Lock()
	d := &s.deliveries[index]
	allowed := !s.closed && d.pending && ctx.Err() == nil && d.generation == s.generation && s.bucket == utcDiagnosticBucket(s.now())
	dropped := d.pending && !allowed
	event, callback := d.event, s.callback
	// After delivery the SDK keeps no event/ID copy in the slot. Application
	// callback copies are external values whose retention it must declare.
	d.event = diagnosticv4.Event{}
	d.pending = false
	s.mu.Unlock()
	if allowed {
		callback(ctx, event)
	} else if dropped {
		s.drop()
	}
}
