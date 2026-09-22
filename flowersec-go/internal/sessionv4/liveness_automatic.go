package sessionv4

import (
	"context"
	"errors"
	"math"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

// AutomaticLivenessPolicy is an explicit immutable deployment choice. There
// are no implicit defaults. Its submission budget is part of the original
// total deadline; publication never starts a fresh response work window.
type AutomaticLivenessPolicy struct {
	IntervalMS, SubmissionMS, ResponseMS uint64
	MissThreshold                        uint32
}

type automaticLiveness struct {
	policy                        AutomaticLivenessPolicy
	next                          *timev4.Delay
	misses                        uint32
	started                       bool
	schedulerExited, workerExited bool
	cleanup                       chan struct{}
}

func NewLivenessWithPolicy(a *OpenAdmission, writer *RecordWriter, slots []ProbeSlot, policy AutomaticLivenessPolicy, reservation resourcev4.Reference) (*Liveness, error) {
	if policy.IntervalMS == 0 || policy.SubmissionMS == 0 || policy.ResponseMS == 0 || policy.MissThreshold == 0 || policy.SubmissionMS > math.MaxUint64-policy.ResponseMS {
		return nil, cryptov4.ErrConfiguration
	}
	if a == nil {
		return nil, cryptov4.ErrConfiguration
	}
	// Reject an unrepresentable interval before installing the original owner.
	if _, err := timev4.NewDelay(a.engine.Clock(), policy.IntervalMS); err != nil {
		return nil, err
	}
	if _, err := timev4.NewWindow(a.engine.Clock(), policy.SubmissionMS+policy.ResponseMS); err != nil {
		return nil, err
	}
	return newLiveness(a, writer, slots, &automaticLiveness{policy: policy}, reservation)
}

// LocalStallKind has one original active owner per local subsystem. A stale
// completion cannot clear a newer stall or restore an invalidated sample.
type LocalStallKind uint8

const (
	LocalReadStall LocalStallKind = iota
	LocalWriteStall
	LocalResourceStall
)

type LivenessStall struct {
	pool *Liveness
	kind LocalStallKind
}

func (p *Liveness) stalled() bool {
	return p.stalls[0] != nil || p.stalls[1] != nil || p.stalls[2] != nil
}

func (p *Liveness) BeginLocalStall(kind LocalStallKind) (*LivenessStall, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if kind > LocalResourceStall {
		return nil, cryptov4.ErrConfiguration
	}
	if p.closed {
		return nil, cryptov4.ErrClosed
	}
	if err := p.reservation.Check(); err != nil {
		return nil, err
	}
	if p.stalls[kind] != nil {
		return nil, cryptov4.ErrCapacity
	}
	o := &LivenessStall{pool: p, kind: kind}
	p.stalls[kind] = o
	if p.automatic != nil {
		if sample := p.slots[len(p.slots)-1].owner; sample != nil {
			now, _ := p.admission.engine.Clock().Monotonic()
			sample.finish(ErrProbeLocalStall, now)
		}
	}
	p.signal()
	return o, nil
}

func (o *LivenessStall) End() {
	p := o.pool
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.stalls[o.kind] == o {
		p.stalls[o.kind] = nil
		p.signal()
	}
}

func (p *Liveness) signal() {
	select {
	case p.wake <- struct{}{}:
	default:
	}
}

// published is invoked only by the original complete successful write. Taking
// the clock sample inside this gate is conservative if accounting was delayed:
// it can invalidate a miss, never manufacture extra response time.
func (o *Probe) published() {
	p := o.pool
	p.mu.Lock()
	defer p.mu.Unlock()
	o.result.Complete = true
	if !o.automatic || o.terminal || p.closed || p.intent != nil || p.exchange != nil || p.stalled() {
		return
	}
	now, err := o.check()
	if err != nil {
		return
	}
	_, elapsed, err := p.admission.engine.Clock().Profile().Rate.Elapsed(now.Milliseconds - o.start.Milliseconds)
	if err == nil && elapsed <= p.automatic.policy.SubmissionMS {
		o.eligible, o.handoff = true, now
	}
}

// automaticOutcome runs exactly once, under the same gate as PONG, rekey,
// local stalls and expiry. A minimum response interval must actually elapse;
// outward clock rounding cannot turn an early work-window expiry into a miss.
func (o *Probe) automaticOutcome(cause error, now timev4.Mark) {
	if !o.automatic {
		return
	}
	p, a := o.pool, o.pool.automatic
	a.next = nil
	if p.closed {
		return
	}
	if cause == nil {
		a.misses = 0
		return
	}
	if !errors.Is(cause, timev4.ErrExpired) || !o.eligible || p.intent != nil || p.exchange != nil || p.stalled() || !now.SameEra(o.handoff) || now.Milliseconds < o.handoff.Milliseconds {
		return
	}
	lower, _, err := p.admission.engine.Clock().Profile().Rate.Elapsed(now.Milliseconds - o.handoff.Milliseconds)
	if err != nil || lower < a.policy.ResponseMS {
		return
	}
	a.misses++ // Cannot overflow: the finite threshold closes at or before max.
	if a.misses >= a.policy.MissThreshold {
		p.failure = ErrLivenessPathUnresponsive
		p.closeLocked()
	}
}

// AutomaticStatus exposes finite policy facts, never a nonce or an assertion
// about peer process/business health. Disabled policy has zero misses.
func (p *Liveness) AutomaticStatus() (enabled bool, misses uint32, cause error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.automatic == nil {
		return false, 0, p.failure
	}
	return true, p.automatic.misses, p.failure
}

// automaticStep belongs to the sole automatic scheduler. Zero remaining means
// wait for an owner event, not poll. Real publication tails retain the protected
// slot and cannot be replaced by another sample after their waiter times out.
func (p *Liveness) automaticStep() (probe *Probe, remaining uint64, err error) {
	p.mu.Lock()
	if p.automatic == nil {
		p.mu.Unlock()
		return nil, 0, cryptov4.ErrConfiguration
	}
	defer func() {
		if errors.Is(err, ErrLivenessPathUnresponsive) {
			p.admission.closeWithCause(err)
		}
	}()
	if o := p.slots[len(p.slots)-1].owner; o != nil {
		_, _ = o.check()
		if o.terminal {
			o.released = true
			o.collect()
		} else {
			remaining, err = o.window.RemainingMS()
			if err != nil {
				now, _ := p.admission.engine.Clock().Monotonic()
				o.finish(err, now)
				p.mu.Unlock()
				return nil, 1, nil
			}
			if !o.publishing && !o.attempted {
				probe = o
			}
			p.mu.Unlock()
			return probe, remaining, nil
		}
	}
	if p.closed {
		err = p.failure
		if err == nil {
			err = cryptov4.ErrClosed
		}
		p.mu.Unlock()
		return nil, 0, err
	}
	if p.slots[len(p.slots)-1].owner != nil || p.intent != nil || p.exchange != nil || p.stalled() {
		p.mu.Unlock()
		return nil, 0, nil
	}
	if p.automatic.next == nil {
		p.automatic.next, err = timev4.NewDelay(p.admission.engine.Clock(), p.automatic.policy.IntervalMS)
		if err != nil {
			p.mu.Unlock()
			return nil, 0, err
		}
	}
	remaining, err = p.automatic.next.RemainingMS()
	if errors.Is(err, timev4.ErrPending) {
		p.mu.Unlock()
		return nil, remaining, nil
	}
	policy := p.automatic.policy
	p.mu.Unlock()
	if err != nil {
		return nil, 0, err
	}
	probe, err = p.begin(policy.SubmissionMS+policy.ResponseMS, true)
	if errors.Is(err, ErrProbeRekey) || errors.Is(err, ErrProbeLocalStall) {
		return nil, 0, nil
	}
	return probe, policy.SubmissionMS + policy.ResponseMS, err
}

// RunAutomatic uses one scheduler/timer and one reserved publication worker.
// The Session owns ctx. Cancellation ends only the automatic policy/sample;
// an irreversible provider call keeps its original slot until it really exits.
// Restart is forbidden, including while that tail is still returning.
func (p *Liveness) RunAutomatic(ctx context.Context) error {
	if ctx == nil {
		return cryptov4.ErrConfiguration
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return cryptov4.ErrClosed
	}
	if err := p.reservation.Check(); err != nil {
		p.mu.Unlock()
		return err
	}
	if p.automatic == nil || p.automatic.started {
		p.mu.Unlock()
		return cryptov4.ErrConfiguration
	}
	p.automatic.started = true
	p.automatic.cleanup = make(chan struct{})
	p.mu.Unlock()
	defer p.automaticExited(true)
	jobs := make(chan *Probe)
	completed := make(chan struct{}, 1)
	go func() {
		defer p.automaticExited(false)
		timer := time.NewTimer(time.Hour)
		timer.Stop()
		defer timer.Stop()
		for o := range jobs {
			// Workspace contention may outlive the writer's own busy flag. One
			// bounded worker backs off within the same original sample deadline.
			for backoff := time.Millisecond; ; backoff = min(backoff*2, 32*time.Millisecond) {
				result, err := o.Publish(ctx)
				if result.Submitted || !errors.Is(err, cryptov4.ErrCapacity) {
					break
				}
				timer.Reset(backoff)
				select {
				case <-timer.C:
				case <-o.done:
				case <-p.done:
				case <-ctx.Done():
				}
				timer.Stop()
			}
			completed <- struct{}{}
		}
	}()
	defer close(jobs)
	defer func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		if o := p.slots[len(p.slots)-1].owner; o != nil {
			now, _ := p.admission.engine.Clock().Monotonic()
			o.finish(context.Canceled, now)
			o.released = true
			o.collect()
		}
	}()
	var timer *time.Timer
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	busy := false
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		probe, remaining, err := p.automaticStep()
		if err != nil {
			return err
		}
		var submit chan<- *Probe
		var writerReady <-chan struct{}
		if probe != nil && !busy {
			p.writer.mu.Lock()
			if p.writer.active {
				writerReady = p.writer.idle
			} else {
				submit = jobs
			}
			p.writer.mu.Unlock()
		}
		var tick <-chan time.Time
		if remaining != 0 {
			if timer == nil {
				timer = time.NewTimer(idleTimerChunk(remaining))
			} else {
				timer.Reset(idleTimerChunk(remaining))
			}
			tick = timer.C
		}
		select {
		case submit <- probe:
			busy = true
		case <-completed:
			busy = false
		case <-writerReady:
		case <-tick:
		case <-p.wake:
		case <-ctx.Done():
			return ctx.Err()
		case <-p.done:
		case <-p.admission.engine.Done():
			p.Close()
		}
		if timer != nil {
			timer.Stop()
		}
	}
}

func (p *Liveness) automaticExited(scheduler bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	a := p.automatic
	if scheduler {
		a.schedulerExited = true
	} else {
		a.workerExited = true
	}
	if a.schedulerExited && a.workerExited {
		close(a.cleanup)
	}
}

// WaitAutomaticCleanup observes both real worker exits. Caller cancellation
// cancels only this wait; it never detaches a provider tail or clears its slot.
func (p *Liveness) WaitAutomaticCleanup(ctx context.Context) error {
	p.mu.Lock()
	if p.automatic == nil || !p.automatic.started {
		p.mu.Unlock()
		return nil
	}
	done := p.automatic.cleanup
	p.mu.Unlock()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
