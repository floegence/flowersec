package sessionv4

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

var ErrEnvironmentTaskExit = errors.New("sessionv4: original Environment task exited without returning")

// EnvironmentSession is the original dual-READY Session and its physical
// cleanup owner. It contains no independent engine, carrier, nonce or quota.
// Connect cancellation ends at successful delivery; Close remains available
// independently of the shared Environment and any caller's cleanup wait.
type EnvironmentSession struct {
	application                               *SessionPlan
	mu                                        sync.Mutex
	environment                               *Environment
	position                                  int
	establishment                             *SessionEstablishment
	admission                                 *SessionAdmissionReservation
	entrance                                  *AcceptedEntrance
	core                                      *SessionCore
	context                                   sessionRuntimeContext
	preparationDeadline                       *timev4.Deadline
	staticMaterial                            *ConnectionMaterial
	source                                    *sourcePreparation
	intake                                    *acceptedIntake
	ingress                                   *acceptedIngress
	preparationOwner, preparationDependencies resourcev4.Reference
	ready, published, stop, watchDone, done   chan struct{}
	delivered, closed, cleaned                bool
	result, cleanupError                      error
	drain                                     *DrainOperation
	info                                      protocolv4.V4SessionInfo
	serve                                     ServeIngress
}

func newEnvironmentSession(e *Environment, slot int, ctx context.Context) *EnvironmentSession {
	return &EnvironmentSession{environment: e, position: slot,
		context: sessionRuntimeContext{parent: ctx, done: make(chan struct{})}, ready: make(chan struct{}), published: make(chan struct{}), stop: make(chan struct{}), watchDone: make(chan struct{}), done: make(chan struct{})}
}

func (s *EnvironmentSession) deliver(ctx context.Context) (*EnvironmentSession, error) {
	select {
	case <-s.ready:
	case <-ctx.Done():
		s.closeWith(ctx.Err())
		return nil, ctx.Err()
	case <-s.stop:
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		s.closeLocked(err)
		return nil, err
	}
	if s.closed || s.core == nil {
		if s.result != nil {
			return nil, s.result
		}
		return nil, cryptov4.ErrClosed
	}
	if s.delivered {
		return nil, cryptov4.ErrTransition
	}
	if s.preparationDeadline != nil {
		if err := s.preparationDeadline.Check(); err != nil {
			s.closeLocked(err)
			return nil, err
		}
	}
	if err := s.core.Engine().CheckApplicationAuthorization(); err != nil {
		s.closeLocked(err)
		return nil, err
	}
	if s.admission == nil || s.admission.prepared == nil {
		s.closeLocked(cryptov4.ErrConfiguration)
		return nil, cryptov4.ErrConfiguration
	}
	if err := s.admission.config.Requirements.Check(s.info.Guarantees); err != nil {
		s.closeLocked(err)
		return nil, err
	}
	s.admission.prepared.mu.Lock()
	guaranteeErr := s.admission.prepared.checkGuaranteesLocked()
	s.admission.prepared.mu.Unlock()
	if guaranteeErr != nil {
		s.closeLocked(guaranteeErr)
		return nil, guaranteeErr
	}
	// This detach changes only the local Connect cancellation lifetime. The
	// signed deadlines, trust subscriptions and original READY facts stay fixed.
	s.context.mu.Lock()
	err := s.context.err
	if err == nil {
		err = ctx.Err()
	}
	if err == nil {
		if s.serve.group != nil {
			err = s.serve.publish()
		}
	}
	if err == nil {
		s.context.parent = nil
		s.delivered = true
	}
	s.context.mu.Unlock()
	if err != nil {
		s.closeLocked(err)
		return nil, err
	}
	close(s.published)
	s.environment.signalMaterials()
	return s, nil
}

func (s *EnvironmentSession) watch(parent context.Context) {
	defer func() {
		if recover() != nil {
			s.closeWith(ErrEnvironmentTaskExit)
		}
		close(s.watchDone)
	}()
	parentDone := parent.Done()
	// One existing cancellation position also drives acquisition/preparation
	// expiry. It must keep progressing while an issuer or provider is blocked.
	var timer *time.Timer
	var deadlineWake <-chan time.Time
	if s.preparationDeadline != nil {
		timer = time.NewTimer(0)
		deadlineWake = timer.C
		defer timer.Stop()
	}
	for {
		select {
		case <-deadlineWake:
			s.mu.Lock()
			if s.delivered || s.closed {
				deadlineWake = nil
			} else {
				remaining, err := s.preparationDeadline.RemainingMS()
				if err == nil || errors.Is(err, timev4.ErrUnavailable) {
					if resourceErr := s.preparationOwner.Check(); resourceErr != nil {
						err = resourceErr
					} else if resourceErr = s.preparationDependencies.Check(); resourceErr != nil {
						err = resourceErr
					} else if s.staticMaterial != nil {
						if materialErr := s.staticMaterial.checkPreparationOpen(); materialErr != nil {
							err = materialErr
						}
					}
				}
				if err != nil && !errors.Is(err, timev4.ErrUnavailable) {
					s.closeLocked(err)
				} else {
					// Recheck recoverable clock state and revocation without
					// extending the original absolute/monotonic deadline.
					if err != nil {
						remaining = 25
					}
					timer.Reset(time.Duration(min(max(remaining, 1), 100)) * time.Millisecond)
				}
			}
			s.mu.Unlock()
		case <-parentDone:
			s.mu.Lock()
			if !s.delivered {
				s.closeLocked(parent.Err())
			}
			s.mu.Unlock()
			parentDone = nil
		case <-s.stop:
			s.mu.Lock()
			p, a, entrance := s.establishment, s.admission, s.entrance
			s.mu.Unlock()
			// Close may itself have a real provider tail. The original watcher
			// keeps its position until that call returns; no waiter replaces it.
			p.Close()
			if a != nil {
				a.Close()
			}
			if entrance != nil {
				entrance.Close()
			}
			return
		}
	}
}

func (s *EnvironmentSession) run(input environmentEstablishment) {
	source := input.source
	intake := input.intake
	ingress := input.ingress
	var a *SessionAdmissionReservation
	var core *SessionCore
	err := ErrEnvironmentTaskExit
	returned := false
	defer func() {
		if recover() != nil || !returned {
			err = ErrEnvironmentTaskExit
		}
		s.closeWith(err)
		s.finish(input, a, source, intake, ingress)
	}()
	err = s.context.Err()
	if err == nil && ingress != nil {
		input, err = ingress.prepare(s)
		intake = input.intake
	}
	if err == nil && source != nil {
		input, err = source.prepare(s)
	}
	if err == nil && intake != nil {
		input, err = intake.prepare(s)
	}
	p := s.establishment
	a = s.admission
	if err == nil {
		switch input.kind {
		case 1:
			i := input.pool
			core, err = p.connectPool(a, i.Store, i.Authority, i.Consume, s)
		case 2:
			i := input.live
			core, err = p.connectLiveSQLite(a, i.Store, i.Authority, i.Issuance, i.Owner, i.Guard, i.Policy, i.Buffers, i.Invocation, s)
		case 3:
			i := input.accepted
			a, core, err = p.accept(&s.context, i.Entrance, i.Config, i.Subscriptions, i.Root, i.ResourceOwner, i.Environment, i.Preauth, i.Scope, i.Store, i.Authority, i.Owner, i.Buffers, i.Invocation, s)
		}
	}
	if err == nil {
		err = core.Runtime().bindApplicationPublication(s.published)
	}
	s.mu.Lock()
	s.admission = a
	if err == nil && !s.closed {
		s.core = core
		s.info = a.info
	} else {
		if err == nil {
			err = cryptov4.ErrClosed
		}
		s.closeLocked(err)
	}
	close(s.ready)
	s.mu.Unlock()
	if err == nil {
		err = core.Runtime().Run(&s.context)
	}
	returned = true
}

// Info remains a detached immutable value after physical Session retirement.
// It owns no endpoint, credential, provider, stable digest or result observer.
func (s *EnvironmentSession) Info() protocolv4.V4SessionInfo {
	if s == nil {
		return protocolv4.V4SessionInfo{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.info
}

func (s *EnvironmentSession) finish(input environmentEstablishment, a *SessionAdmissionReservation, source *sourcePreparation, intake *acceptedIntake, ingress *acceptedIngress) {
	<-s.watchDone
	if intake == nil {
		intake = s.intake
	}
	p := s.establishment
	if a == nil && p != nil {
		p.mu.Lock()
		a = p.admission
		p.mu.Unlock()
	}
	var err error
	// An accepted admission can attach after the watcher took its snapshot.
	// Its original constructor already sees the canceled context; close/join it
	// here as well, after establishment and the original provider Close return.
	if a != nil {
		a.Close()
		err = a.WaitCleanup(context.Background())
		if err == nil {
			err = a.Retire()
		}
	} else if s.entrance != nil {
		s.entrance.Close()
		err = s.entrance.WaitCleanup(context.Background())
		if err == nil {
			err = s.entrance.Retire()
		}
	}
	if err == nil && p != nil {
		p.mu.Lock()
		attached := p.admission != nil
		p.mu.Unlock()
		if !attached {
			err = p.Retire()
		}
	}
	if err == nil && source != nil {
		err = source.cleanup()
	}
	if err == nil && intake != nil {
		err = intake.cleanup()
	}
	if err == nil && ingress != nil {
		err = ingress.cleanup()
	}
	if err == nil {
		err = s.application.retireUnclaimed()
	}
	if err != nil {
		// An invariant failure cannot turn into a physical-cleanup assertion.
		// Keep the same Environment position and resource owner for diagnosis.
		s.mu.Lock()
		s.cleanupError = err
		s.mu.Unlock()
		return
	}
	// Any workspace not adopted by its durable adapter still belongs to this
	// original assembly. Adopted handles are stale and Release is a no-op.
	switch input.kind {
	case 1:
		input.pool.Consume.Release()
	case 2:
		input.live.Buffers.Release()
		input.live.Invocation.Release()
	case 3:
		input.accepted.Buffers.Release()
		input.accepted.Invocation.Release()
		if a == nil && input.accepted.Subscriptions != nil {
			input.accepted.Subscriptions.Close()
		}
	}
	input = environmentEstablishment{}
	s.mu.Lock()
	e, slot := s.environment, s.position
	s.establishment, s.admission, s.entrance, s.core = nil, nil, nil, nil
	s.context.mu.Lock()
	s.context.parent = nil
	s.context.mu.Unlock()
	s.preparationDeadline = nil
	s.staticMaterial = nil
	s.source = nil
	s.intake = nil
	s.ingress = nil
	s.application = nil
	s.preparationOwner, s.preparationDependencies = resourcev4.Reference{}, resourcev4.Reference{}
	s.cleaned = true
	s.environment = nil
	serve := s.serve
	s.serve = ServeIngress{}
	result := DrainResult{DrainFailed, s.result}
	if s.drain != nil {
		result = s.drain.Result()
	}
	close(s.done)
	s.mu.Unlock()
	if serve.group != nil {
		serve.finish(result)
	}
	e.mu.Lock()
	e.positions[slot] = nil
	e.active--
	e.completeLocked()
	e.mu.Unlock()
}

func (s *EnvironmentSession) closeLocked(cause error) {
	if s.closed {
		return
	}
	s.closed = true
	s.result = cause
	s.context.cancel()
	close(s.stop)
}

func (s *EnvironmentSession) closeWith(cause error) {
	s.mu.Lock()
	s.closeLocked(cause)
	s.mu.Unlock()
}

func (s *EnvironmentSession) Close() {
	if s != nil {
		s.closeWith(cryptov4.ErrClosed)
	}
}

func (s *EnvironmentSession) Drain(timeoutMS, absoluteCap uint64) (*DrainOperation, error) {
	if s == nil {
		return nil, cryptov4.ErrConfiguration
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.drain != nil {
		return s.drain, nil
	}
	if !s.delivered || s.closed || s.core == nil {
		return nil, cryptov4.ErrClosed
	}
	op, err := s.core.Drain(timeoutMS, absoluteCap)
	if err == nil {
		s.drain = op
	}
	return op, err
}

// Only the owning Serve may tighten an already running child Drain. Ordinary
// repeated Drain calls retain the original operation and deadline unchanged.
func (s *EnvironmentSession) drainForGroup(cap uint64) (*DrainOperation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.core == nil {
		if s.drain != nil {
			return s.drain, nil
		}
		return nil, cryptov4.ErrClosed
	}
	p := s.core.plan
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.admission == nil || p.admission.lifecycle == nil {
		return nil, cryptov4.ErrClosed
	}
	l := p.admission.lifecycle
	op, err := l.Drain(0, cap, "normal")
	if err != nil {
		return nil, err
	}
	p.drain, s.drain = op, op
	a := l.admission
	a.mu.Lock()
	if cap < l.deadline.Cap() {
		err = l.deadline.Tighten(cap)
	}
	l.notify()
	a.mu.Unlock()
	if err != nil && !errors.Is(err, timev4.ErrUnavailable) {
		outcome := DrainFailed
		if errors.Is(err, timev4.ErrExpired) {
			outcome, err = DrainDeadlineAborted, ErrDrainDeadline
		}
		op.finish(outcome, err)
		s.closeLocked(err)
	}
	return op, nil
}

// CleanupStatus reports physical exit independently of the drain result.
func (s *EnvironmentSession) CleanupStatus() (complete bool, err error) {
	if s == nil {
		return false, cryptov4.ErrConfiguration
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cleaned, s.cleanupError
}

func (s *EnvironmentSession) WaitTermination(ctx context.Context) error {
	if s == nil || ctx == nil {
		return cryptov4.ErrConfiguration
	}
	select {
	case <-s.stop:
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.result
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *EnvironmentSession) WaitCleanup(ctx context.Context) error {
	if s == nil || ctx == nil {
		return cryptov4.ErrConfiguration
	}
	select {
	case <-s.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Core is private SDK composition, never a public carrier/key escape hatch.
// Its methods retain their original graph pins through actual method return.
func (s *EnvironmentSession) Core() (*SessionCore, error) {
	if s == nil {
		return nil, cryptov4.ErrConfiguration
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.delivered || s.closed || s.core == nil {
		return nil, cryptov4.ErrClosed
	}
	return s.core, nil
}

func (s *EnvironmentSession) abortFromGroup(result DrainResult) DrainResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	if result.Outcome == DrainPending {
		result = DrainResult{DrainFailed, cryptov4.ErrClosed}
	}
	if s.drain != nil {
		s.drain.finish(result.Outcome, result.Cause)
		result = s.drain.Result()
	}
	s.closeLocked(result.Cause)
	return result
}
