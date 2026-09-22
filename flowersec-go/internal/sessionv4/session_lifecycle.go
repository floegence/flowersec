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

var (
	ErrSessionDraining = errors.New("sessionv4: Session admission is draining")
	ErrGoAwayConflict  = errors.New("sessionv4: conflicting GOAWAY boundary")
	ErrDrainDeadline   = errors.New("sessionv4: original drain deadline exceeded")
	ErrPeerClosed      = errors.New("sessionv4: peer closed Session")
)

// Engine ticket guards cannot take admission.mu: other admission methods call
// Engine under that lock. This leaf gate orders only new OPEN tickets with
// GOAWAY/Drain. A ticket that won before closure remains an in-flight opening.
type localOpenGate struct {
	mu     sync.Mutex
	closed bool
}

func (g *localOpenGate) close() { g.mu.Lock(); g.closed = true; g.mu.Unlock() }
func (g *localOpenGate) LockTicket() error {
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return cryptov4.ErrClosed
	}
	return nil
}
func (g *localOpenGate) UnlockTicket(bool) { g.mu.Unlock() }

type goAwayBoundary struct {
	set             bool
	ceiling, reason uint64
}

type DrainOutcome uint8

const (
	DrainPending DrainOutcome = iota
	Drained
	DrainDeadlineAborted
	DrainFailed
)

type DrainResult struct {
	Outcome DrainOutcome
	Cause   error
}

// DrainOperation is the original immutable process. Wait cancellation only
// detaches that observer. Physical cleanup is observed on the Session owner.
type DrainOperation struct {
	mu     sync.Mutex
	done   chan struct{}
	result DrainResult
}

func (o *DrainOperation) Result() DrainResult {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.result
}

func (o *DrainOperation) Wait(ctx context.Context) (DrainResult, error) {
	if o == nil || ctx == nil {
		return DrainResult{}, cryptov4.ErrConfiguration
	}
	select {
	case <-o.done:
		return o.Result(), nil
	case <-ctx.Done():
		return DrainResult{}, ctx.Err()
	}
}

func (o *DrainOperation) finish(outcome DrainOutcome, cause error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.result.Outcome == DrainPending {
		o.result = DrainResult{outcome, cause}
		close(o.done)
	}
}

// SessionLifecycle owns two finite tasks: the original deadline coordinator
// and one control publisher. A blocked provider retains that publisher and
// its reservation after logical termination, until WaitCleanup succeeds.
// All mutable protocol fields use the original admission gate.
type SessionLifecycle struct {
	admission                                         *OpenAdmission
	writer                                            *RecordWriter
	reservation                                       resourcev4.Reference
	timeoutMS                                         uint64
	deadline                                          *timev4.Deadline
	boundary                                          goAwayBoundary
	operation                                         *DrainOperation
	publicationGate                                   localOpenGate
	goAwaySent, closeSent                             bool
	started, running, worker, active, closed, cleaned bool
	wake, stop, cleanup                               chan struct{}
}

func SessionLifecycleCharge() resourcev4.Vector {
	return resourcev4.Vector{
		resourcev4.SDKBytes: uint64(unsafe.Sizeof(SessionLifecycle{})) + uint64(unsafe.Sizeof(DrainOperation{})) + uint64(unsafe.Sizeof(timev4.Deadline{})),
		resourcev4.Items:    3, resourcev4.Tasks: 2, resourcev4.WorkSlots: 2, resourcev4.Timers: 1,
	}
}

func NewSessionLifecycle(a *OpenAdmission, writer *RecordWriter, timeoutMS uint64, reservation resourcev4.Reference) (*SessionLifecycle, error) {
	if a == nil || writer == nil || writer.engine != a.engine || writer.scope != 0 || timeoutMS == 0 {
		return nil, cryptov4.ErrConfiguration
	}
	if _, err := timev4.NewAge(a.engine.Clock(), timeoutMS, math.MaxUint64); err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed || a.draining || a.runtime != nil || a.lifecycle != nil {
		return nil, cryptov4.ErrTransition
	}
	if a.reservation != (resourcev4.Reference{}) {
		if err := reservation.CheckSameEnvironment(a.reservation); err != nil {
			return nil, err
		}
	}
	owned, err := reservation.Take(SessionLifecycleCharge())
	if err != nil {
		return nil, err
	}
	l := &SessionLifecycle{admission: a, writer: writer, timeoutMS: timeoutMS, reservation: owned,
		operation: &DrainOperation{done: make(chan struct{})}, wake: make(chan struct{}, 1), stop: make(chan struct{}), cleanup: make(chan struct{})}
	a.lifecycle = l
	return l, nil
}

// Drain freezes the accepted boundary and original deadline in one admission
// gate. A zero timeout selects the preadmitted deployment policy; a nonzero
// absolute cap supports Serve's original group deadline. Repeats change neither.
func (l *SessionLifecycle) Drain(timeoutMS, absoluteCap uint64, reason string) (*DrainOperation, error) {
	if l == nil {
		return nil, cryptov4.ErrConfiguration
	}
	a := l.admission
	a.mu.Lock()
	defer a.mu.Unlock()
	if l.boundary.set {
		return l.operation, nil
	}
	if a.closed || l.closed {
		return nil, cryptov4.ErrClosed
	}
	if err := l.reservation.Check(); err != nil {
		return nil, err
	}
	code, err := protocolv4.EnumValue("GOAWAY", "reason", reason)
	if err != nil {
		return nil, err
	}
	if timeoutMS == 0 {
		timeoutMS = l.timeoutMS
	}
	if absoluteCap == 0 {
		absoluteCap = math.MaxUint64
	}
	if cap := a.engine.SessionParameters().SessionNotAfterMS; cap != 0 {
		absoluteCap = min(absoluteCap, cap)
	}
	deadline, err := timev4.NewAge(a.engine.Clock(), min(timeoutMS, l.timeoutMS), absoluteCap)
	if err != nil {
		return nil, err
	}
	l.deadline = deadline
	l.boundary = goAwayBoundary{true, a.highestAccepted[1-a.direction], code}
	a.drainLocked()
	l.notify()
	return l.operation, nil
}

func (l *SessionLifecycle) notify() { notifyOpenWait(l.wake) }

// Communication completion uses actual terminal proofs. Recent/held proof or
// callback/provider cleanup may outlive it; neither is an active communication.
func (a *OpenAdmission) communicationDrainedLocked() bool {
	for i := range a.slots {
		s := &a.slots[i]
		if s.phase != openFree && s.phase != openRecent && s.phase != openHeld {
			return false
		}
		if s.deciding || s.terminalPublishing {
			return false
		}
		if s.flow != nil {
			r := s.flow.receive
			r.pool.mu.Lock()
			unread := r.size != 0 || r.readPending
			r.pool.mu.Unlock()
			if unread {
				return false
			}
		}
	}
	return true
}

func (l *SessionLifecycle) closeLocked(cause error) {
	if !l.closed {
		l.closed = true
		l.publicationGate.close()
		l.reservation.Seal()
		close(l.stop)
		if cause == nil {
			cause = cryptov4.ErrClosed
		}
		if l.boundary.set {
			l.operation.finish(DrainFailed, cause)
		}
	}
	l.cleanupLocked()
}

func (l *SessionLifecycle) cleanupLocked() {
	if l.closed && !l.running && !l.worker && !l.active && !l.cleaned {
		l.cleaned = true
		close(l.cleanup)
	}
}

type lifecycleTicket struct {
	lifecycle *SessionLifecycle
}

func (g lifecycleTicket) LockTicket() error {
	l := g.lifecycle
	if err := l.publicationGate.LockTicket(); err != nil {
		return err
	}
	err := l.reservation.Check()
	if err == nil {
		err = l.deadline.Check()
	}
	if err != nil {
		l.publicationGate.UnlockTicket(false)
	}
	return err
}
func (g lifecycleTicket) UnlockTicket(submitted bool) {
	g.lifecycle.publicationGate.UnlockTicket(submitted)
}

func (l *SessionLifecycle) progress(ctx context.Context) (ready bool, err error) {
	a := l.admission
	a.mu.Lock()
	if a.closed || l.closed {
		a.mu.Unlock()
		return false, cryptov4.ErrClosed
	}
	if !l.boundary.set || l.active || l.closeSent || l.goAwaySent && !a.communicationDrainedLocked() {
		a.mu.Unlock()
		return false, nil
	}
	if err = l.deadline.Check(); err != nil {
		a.mu.Unlock()
		return false, err
	}
	closing, boundary := l.goAwaySent, l.boundary
	if closing {
		// The original terminal proofs and consumed input establish drained.
		// CLOSE is physical teardown, not another communication receipt: the
		// peer may receive it and close its carrier before Write returns here.
		// Freeze the result before that response can race with local teardown.
		l.operation.finish(Drained, nil)
	}
	l.active = true
	a.mu.Unlock()
	frame := protocolv4.FrameGoAway
	if closing {
		frame = protocolv4.FrameClose
	}
	result, err := l.writer.WriteBuildGuard(ctx, frame, 32, func(_ protocolv4.RecordHeader, dst []byte) (int, error) {
		schema := "GOAWAY"
		fields := [2]protocolv4.Field{{Name: "accept_ceiling", Number: boundary.ceiling}, {Name: "reason", Number: boundary.reason}}
		if closing {
			schema = "CLOSE"
			fields = [2]protocolv4.Field{{Name: "reason", Number: boundary.reason}, {Name: "target_scope", Number: 0}}
		}
		wire, err := protocolv4.EncodeMap(dst, schema, fields[:])
		return len(wire), err
	}, nil, lifecycleTicket{l})
	retry := !result.Submitted && (errors.Is(err, cryptov4.ErrCapacity) || errors.Is(err, cryptov4.ErrTransition) || errors.Is(err, cryptov4.ErrNotReady))
	a.mu.Lock()
	l.active = false
	if err == nil {
		if closing {
			l.closeSent = true
		} else {
			l.goAwaySent = true
		}
	}
	l.cleanupLocked()
	a.mu.Unlock()
	if retry {
		return false, nil
	}
	return err == nil, err
}

func (l *SessionLifecycle) Run(ctx context.Context) (err error) {
	if ctx == nil {
		return cryptov4.ErrConfiguration
	}
	a := l.admission
	a.mu.Lock()
	if l.started || l.closed {
		a.mu.Unlock()
		return cryptov4.ErrClosed
	}
	if err := l.reservation.Check(); err != nil {
		a.mu.Unlock()
		return err
	}
	l.started, l.running, l.worker = true, true, true
	a.mu.Unlock()
	type completion struct {
		ready bool
		err   error
	}
	jobs, results := make(chan struct{}), make(chan completion, 1)
	go func() {
		defer func() { a.mu.Lock(); l.worker = false; l.cleanupLocked(); a.mu.Unlock() }()
		for range jobs {
			ready, err := l.progress(ctx)
			results <- completion{ready, err}
		}
	}()
	defer close(jobs)
	defer func() {
		if errors.Is(err, timev4.ErrExpired) {
			err = ErrDrainDeadline
			l.operation.finish(DrainDeadlineAborted, err)
		}
		a.closeWithCause(err)
		a.mu.Lock()
		l.running = false
		l.cleanupLocked()
		a.mu.Unlock()
	}()
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	defer timer.Stop()
	busy, retry := false, false
	for {
		a.mu.Lock()
		if l.closed {
			a.mu.Unlock()
			return cryptov4.ErrClosed
		}
		var submit chan<- struct{}
		remaining := uint64(0)
		if l.boundary.set {
			if l.closeSent && l.operation.Result().Outcome == Drained {
				a.mu.Unlock()
				return nil
			}
			remaining, err = l.deadline.RemainingMS()
			if errors.Is(err, timev4.ErrExpired) {
				err = ErrDrainDeadline
				l.operation.finish(DrainDeadlineAborted, err)
			} else if errors.Is(err, timev4.ErrUnavailable) {
				remaining, err = 25, nil
			} else if err == nil && l.closeSent {
				l.operation.finish(Drained, nil)
				a.mu.Unlock()
				return nil
			} else if err == nil && !busy && !retry && (!l.goAwaySent || a.communicationDrainedLocked()) {
				submit = jobs
			}
		}
		a.mu.Unlock()
		if err != nil {
			return err
		}
		var tick <-chan time.Time
		if remaining != 0 {
			// Terminal proof changes and clock uncertainty share this finite
			// wakeup; blocked publication never blocks deadline enforcement.
			timer.Reset(time.Duration(min(remaining, 10)) * time.Millisecond)
			tick = timer.C
		}
		select {
		case submit <- struct{}{}:
			busy = true
		case c := <-results:
			busy, retry = false, !c.ready
			if c.err != nil {
				return c.err
			}
		case <-ctx.Done():
			return ctx.Err()
		case <-l.stop:
			return cryptov4.ErrClosed
		case <-a.engine.Done():
			return cryptov4.ErrClosed
		case <-l.wake:
		case <-tick:
			retry = false
		}
		timer.Stop()
	}
}

func (l *SessionLifecycle) WaitCleanup(ctx context.Context) error {
	if ctx == nil {
		return cryptov4.ErrConfiguration
	}
	select {
	case <-l.cleanup:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (l *SessionLifecycle) retire() error {
	// Called by the original admission retirement after every method tail.
	select {
	case <-l.cleanup:
	default:
		return cryptov4.ErrCapacity
	}
	l.reservation.Release()
	return nil
}
