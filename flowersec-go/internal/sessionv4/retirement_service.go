package sessionv4

import (
	"context"
	"errors"
	"math"
	"sync"
	"time"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

// RetirementService drives the original fixed inbound/outbound retirement
// positions. Its independent deadline task retains blocked publication tails.
type RetirementService struct {
	mu                                            sync.Mutex
	retirement                                    *Retirement
	reservation                                   resourcev4.Reference
	timeoutMS                                     uint64
	outDeadline, publication                      *timev4.Deadline
	wake, stop, done                              chan struct{}
	started, closed, coordinator, worker, cleaned bool
}

func RetirementServiceCharge() (resourcev4.Vector, error) {
	count, err := protocolv4.FieldItemLimit("STREAM_ACK_RETIRE_BATCH", "scope_ids")
	if err != nil {
		return resourcev4.Vector{}, err
	}
	maximum, err := protocolv4.SchemaByteLimit("STREAM_ACK_RETIRE_BATCH")
	if err != nil {
		return resourcev4.Vector{}, err
	}
	return resourcev4.Vector{
		resourcev4.SDKBytes: uint64(unsafe.Sizeof(RetirementService{})) + uint64(unsafe.Sizeof(Retirement{})) + uint64(3*count*8+2*maximum) + 4*uint64(unsafe.Sizeof(timev4.Deadline{})),
		resourcev4.Items:    8, resourcev4.Tasks: 2, resourcev4.WorkSlots: 2, resourcev4.Timers: 1,
	}, nil
}

func NewRetirementService(r *Retirement, timeoutMS uint64, reservation resourcev4.Reference) (*RetirementService, error) {
	if r == nil || timeoutMS == 0 {
		return nil, cryptov4.ErrConfiguration
	}
	a := r.admission
	if _, err := timev4.NewAge(a.engine.Clock(), timeoutMS, math.MaxUint64); err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed || a.runtime != nil || a.retirement != r || a.retirementService != nil || a.active != 0 || a.pending != 0 {
		return nil, cryptov4.ErrConfiguration
	}
	charge, err := RetirementServiceCharge()
	if err != nil {
		return nil, err
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		return nil, err
	}
	p := &RetirementService{retirement: r, reservation: owned, timeoutMS: timeoutMS, wake: make(chan struct{}, 1), stop: make(chan struct{}), done: make(chan struct{})}
	a.retirementService = p
	r.wake = p.wake
	return p, nil
}

func (p *RetirementService) notify() {
	select {
	case p.wake <- struct{}{}:
	default:
	}
}
func (r *Retirement) notify() {
	select {
	case r.wake <- struct{}{}:
	default:
	}
}

func (p *RetirementService) step(ctx context.Context) error {
	r := p.retirement
	a := r.admission
	a.mu.Lock()
	ack := r.ackReadyLocked()
	var deadline *timev4.Deadline
	if ack {
		for i := range r.in {
			if r.in[i].live && !r.in[i].done {
				deadline = r.in[i].deadline
				break
			}
		}
	}
	a.mu.Unlock()
	p.mu.Lock()
	if deadline == nil {
		deadline = p.outDeadline
	}
	if deadline == nil {
		var err error
		deadline, err = timev4.NewAge(a.engine.Clock(), p.timeoutMS, math.MaxUint64)
		if err != nil {
			p.mu.Unlock()
			return err
		}
		if !ack {
			p.outDeadline = deadline
		}
	}
	p.publication = deadline
	p.mu.Unlock()
	// The coordinator may already be waiting without a timer. Publish this
	// original deadline before entering a provider that can remain blocked.
	p.notify()
	defer func() { p.mu.Lock(); p.publication = nil; p.mu.Unlock() }()
	var result RecordWriteResult
	var err error
	if ack {
		result, err = r.Acknowledge(ctx)
	} else {
		result, err = r.Start(ctx, len(r.out.ids), deadline)
	}
	if !ack && result.Submitted {
		p.mu.Lock()
		p.outDeadline = nil
		p.mu.Unlock()
	}
	if !result.Submitted && (errors.Is(err, ErrOpenPending) || errors.Is(err, cryptov4.ErrCapacity) || errors.Is(err, cryptov4.ErrTransition) || errors.Is(err, cryptov4.ErrNotReady)) {
		return nil
	}
	return err
}

func (p *RetirementService) status() (ready bool, remaining uint64, err error) {
	r := p.retirement
	a := r.admission
	remaining = math.MaxUint64
	include := func(d *timev4.Deadline) {
		if d == nil || err != nil {
			return
		}
		var n uint64
		n, err = d.RemainingMS()
		remaining = min(remaining, n)
	}
	p.mu.Lock()
	include(p.outDeadline)
	include(p.publication)
	p.mu.Unlock()
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return false, 0, cryptov4.ErrClosed
	}
	ready = r.ackReadyLocked()
	for _, b := range []*retirementBatch{&r.out, &r.in[0], &r.in[1]} {
		if b.live && (!b.done || b.writing) {
			include(b.deadline)
		}
	}
	if !r.out.live {
		for i := range a.slots {
			s := &a.slots[i]
			if s.local && s.phase == openRecent && s.barrierUnpublished == 0 {
				ready = true
				break
			}
		}
	}
	return ready, remaining, err
}

func (p *RetirementService) Run(ctx context.Context) (err error) {
	if ctx == nil {
		return cryptov4.ErrConfiguration
	}
	p.mu.Lock()
	if p.started || p.closed {
		p.mu.Unlock()
		return cryptov4.ErrClosed
	}
	if err := p.reservation.Check(); err != nil {
		p.mu.Unlock()
		return err
	}
	p.started, p.coordinator, p.worker = true, true, true
	p.mu.Unlock()
	jobs, results := make(chan struct{}), make(chan error, 1)
	go func() {
		defer func() { p.mu.Lock(); p.worker = false; p.cleanupLocked(); p.mu.Unlock() }()
		for range jobs {
			results <- p.step(ctx)
		}
	}()
	defer close(jobs)
	defer func() {
		p.retirement.admission.closeWithCause(err)
		p.mu.Lock()
		p.coordinator = false
		p.cleanupLocked()
		p.mu.Unlock()
	}()
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	defer timer.Stop()
	busy, retry := false, false
	for {
		ready, remaining, err := p.status()
		if err != nil {
			return err
		}
		var submit chan<- struct{}
		if ready && !busy && !retry {
			submit = jobs
		}
		if retry {
			remaining = min(remaining, uint64(10))
		}
		var tick <-chan time.Time
		if remaining != math.MaxUint64 {
			timer.Reset(idleTimerChunk(remaining))
			tick = timer.C
		}
		select {
		case submit <- struct{}{}:
			busy = true
		case err := <-results:
			busy, retry = false, true
			if err != nil {
				return err
			}
		case <-p.wake:
			retry = false
		case <-tick:
			retry = false
		case <-ctx.Done():
			return ctx.Err()
		case <-p.stop:
			return cryptov4.ErrClosed
		case <-p.retirement.admission.engine.Done():
			return cryptov4.ErrClosed
		}
		timer.Stop()
	}
}
func (p *RetirementService) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.closed {
		p.closed = true
		p.reservation.Seal()
		close(p.stop)
	}
	p.cleanupLocked()
}
func (p *RetirementService) cleanupLocked() {
	if p.closed && !p.cleaned && !p.worker && !p.coordinator {
		p.cleaned = true
		close(p.done)
	}
}
func (p *RetirementService) WaitCleanup(ctx context.Context) error {
	if ctx == nil {
		return cryptov4.ErrConfiguration
	}
	select {
	case <-p.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (p *RetirementService) retire() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.cleaned {
		return cryptov4.ErrCapacity
	}
	p.reservation.Release()
	return nil
}
