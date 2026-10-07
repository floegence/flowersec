package sessionv4

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/diagnosticv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

var ErrEnvironmentTaskExit = errors.New("sessionv4: original Environment task exited without returning")
var ErrSessionCleanupIncomplete = errors.New("sessionv4: session cleanup_incomplete")

const sessionCleanupTimeout = 5 * time.Second

// EnvironmentSession is the original dual-READY Session and its physical
// cleanup owner. It contains no independent engine, carrier, nonce or quota.
// Connect cancellation ends at successful delivery; Close remains available
// independently of the shared Environment and any caller's cleanup wait.
type EnvironmentSession struct {
	notificationController                            *ConnectionController
	publicView                                        any
	diagnosticStarted                                 time.Time
	diagnosticPhase                                   diagnosticv4.Phase
	diagnosticOperation                               *DiagnosticOperation
	diagnosticAttempt                                 uint64
	cleanupTimeoutObserved                            bool
	cleanupDeadline                                   time.Time
	cleanupObserved, physicalDone, cleanupWatchDone   chan struct{}
	application                                       *SessionPlan
	spendObservation                                  *ledgerv4.PoolSpendObservation
	diagnosticSourceProfile                           string
	admissionState                                    string
	controllerManaged, controllerApplicationPublished bool
	controllerDiagnosticAttempt                       uint64
	diagnosticNetworkReady                            bool
	mu                                                sync.Mutex
	environment                                       *Environment
	position                                          int
	establishment                                     *SessionEstablishment
	admission                                         *SessionAdmissionReservation
	entrance                                          *AcceptedEntrance
	core                                              *SessionCore
	context                                           sessionRuntimeContext
	preparationDeadline                               *timev4.Deadline
	staticMaterial                                    *ConnectionMaterial
	source                                            *sourcePreparation
	intake                                            *acceptedIntake
	ingress                                           *acceptedIngress
	preparationOwner, preparationDependencies         resourcev4.Reference
	ready, published, stop, watchDone, done           chan struct{}
	delivered, closed, cleaned                        bool
	result, cleanupError                              error
	drain                                             *DrainOperation
	controllerRetention                               *timev4.Deadline
	controllerSourceFailure                           *ControllerSourceError
	controllerTransportFailure                        bool
	info                                              protocolv4.V4SessionInfo
	serve                                             ServeIngress
}

// PublicView memoizes only the SDK's opaque facade for this original owner.
// The factory is SDK-local allocation, with no I/O, callbacks or owner reads.
// It prevents delayed observers from manufacturing a second public identity.
func (s *EnvironmentSession) PublicView(factory func() any) any {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.publicView == nil {
		s.publicView = factory()
	}
	return s.publicView
}

func newEnvironmentSession(e *Environment, slot int, ctx context.Context) *EnvironmentSession {
	return &EnvironmentSession{environment: e, position: slot,
		cleanupObserved: make(chan struct{}), physicalDone: make(chan struct{}), cleanupWatchDone: make(chan struct{}),
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
		// Connect/Accept publishes a usable application owner. A caller may
		// subscribe immediately, before the Environment coordinator wakes.
		if s.application != nil {
			s.application.mu.Lock()
			dispatch, notifications := s.application.services, s.application.notifications
			s.application.mu.Unlock()
			if notifications != nil {
				notifications.activate()
			}
			if dispatch != nil {
				dispatch.activate()
			}
		}
		s.diagnosticPhase = diagnosticv4.PhaseApplication
		if s.diagnosticOperation != nil {
			s.diagnosticOperation.Emit(diagnosticv4.Fields{State: diagnosticv4.StateReady, Phase: s.diagnosticPhase, Code: diagnosticv4.CodeOK, AttemptBucket: diagnosticv4.Attempt(s.diagnosticAttempt), DurationBucket: diagnosticv4.Duration(time.Since(s.diagnosticStarted))})
		}
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
	// Its fixed observation position was admitted with the Environment. The
	// provider Close below may block independently of the original run task.
	go s.watchCleanup()
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
	// Ingress may hand the same original deadline to intake while this watcher
	// starts. Read the presence bit under the same gate as that handoff.
	s.mu.Lock()
	hasPreparationDeadline := s.preparationDeadline != nil
	s.mu.Unlock()
	if hasPreparationDeadline {
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
		s.setDiagnosticPhase(diagnosticv4.PhasePrepare)
		input, err = ingress.prepare(s)
		intake = input.intake
	}
	if err == nil && source != nil {
		s.setDiagnosticPhase(diagnosticv4.PhaseMaterial)
		input, err = source.prepare(s)
	}
	if err == nil && intake != nil {
		s.setDiagnosticPhase(diagnosticv4.PhaseActivate)
		input, err = intake.prepare(s)
	}
	p := s.establishment
	a = s.admission
	if err == nil {
		s.setDiagnosticPhase(diagnosticv4.PhaseSpend)
		switch input.kind {
		case 1:
			i := input.pool
			core, err = p.connectPool(a, i.Store, i.Authority, i.Consume, s, i.Observation, i.ServerAllow)
		case 2:
			i := input.live
			if i.Control.Provider != nil {
				core, err = p.connectLiveControl(a, i.Control, i.Buffers, s)
			} else {
				core, err = p.connectLiveSQLite(a, i.Store, i.Authority, i.Issuance, i.Owner, i.Guard, i.Policy, i.Buffers, i.Invocation, s, i.ServerPublication)
			}
		case 3:
			i := input.accepted
			a, core, err = p.accept(&s.context, i.Entrance, i.Config, i.Subscriptions, i.Root, i.ResourceOwner, i.Environment, i.Preauth, i.Scope, i.Store, i.Authority, i.Owner, i.Buffers, i.Invocation, s)
		}
	}
	if err == nil {
		err = core.Runtime().bindApplicationPublication(s.published)
	}
	var initialTransportFailure bool
	if err != nil && a != nil {
		a.mu.Lock()
		initial := a.initial
		a.mu.Unlock()
		if initial != nil {
			initial.mu.Lock()
			initialTransportFailure = initial.transportFailure && controllerNetworkRetry(err) && initial.terminal == err
			initial.mu.Unlock()
		}
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
		s.closeLockedSource(err, initialTransportFailure)
	}
	close(s.ready)
	s.mu.Unlock()
	if err == nil {
		err = core.Runtime().Run(&s.context)
		runtime := core.Runtime()
		runtime.mu.Lock()
		transportFailure := runtime.transportFailure
		runtime.mu.Unlock()
		s.closeWithSource(err, transportFailure)
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
		if relay := input.live.ServerPublication.Relay; relay != nil {
			relay.Reservation.Release()
		}
	case 3:
		input.accepted.Buffers.Release()
		input.accepted.Invocation.Release()
		if a == nil && input.accepted.Subscriptions != nil {
			input.accepted.Subscriptions.Close()
		}
	}
	input = environmentEstablishment{}
	close(s.physicalDone)
	<-s.cleanupWatchDone
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
	s.notificationController = nil
	s.preparationOwner, s.preparationDependencies = resourcev4.Reference{}, resourcev4.Reference{}
	s.cleaned = true
	if s.diagnosticOperation != nil {
		s.diagnosticOperation.Close()
		s.diagnosticOperation = nil
	}
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
	s.closeLockedSource(cause, false)
}

func (s *EnvironmentSession) closeLockedSource(cause error, transport bool) {
	if s.closed {
		return
	}
	s.observeClosure(cause)
	s.closed = true
	s.cleanupDeadline = time.Now().Add(sessionCleanupTimeout)
	s.result = cause
	s.controllerTransportFailure = transport && controllerNetworkRetry(cause)
	s.context.cancel()
	close(s.stop)
}

func (s *EnvironmentSession) closeWith(cause error) {
	s.closeWithSource(cause, false)
}

func (s *EnvironmentSession) closeWithSource(cause error, transport bool) {
	s.mu.Lock()
	s.closeLockedSource(cause, transport)
	s.mu.Unlock()
}

func (s *EnvironmentSession) Close() {
	if s != nil {
		// An explicit local Close is a successful terminal request. Peer and
		// transport failures still publish their own authoritative causes via
		// closeWithSource, while WaitTermination remains nil for this local
		// lifecycle action.
		s.closeWith(nil)
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
	if s.controllerRetention != nil {
		if err := s.controllerRetention.Check(); err != nil {
			s.closeLocked(err)
			return nil, err
		}
		if absoluteCap == 0 || s.controllerRetention.Cap() < absoluteCap {
			absoluteCap = s.controllerRetention.Cap()
		}
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

// watchCleanup publishes one fixed observation without replacing any real
// cleanup work. No observer can extend the deadline or refund its owner.
func (s *EnvironmentSession) watchCleanup() {
	defer close(s.cleanupWatchDone)
	<-s.stop
	s.mu.Lock()
	deadline := s.cleanupDeadline
	s.mu.Unlock()
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case <-s.physicalDone:
	case <-timer.C:
		select {
		case <-s.physicalDone:
			return
		default:
		}
		s.observeCleanupTimeout(context.DeadlineExceeded)
		close(s.cleanupObserved)
	}
}

// CleanupStatus is a passive, finite observation of the original owner. The
// transport core and its attributable application callbacks remain distinct.
func (s *EnvironmentSession) CleanupStatus() protocolv4.V4CleanupStatus {
	status := protocolv4.V4CleanupStatus{Status: protocolv4.V4CleanupStatePending, CoreCleanup: protocolv4.V4CoreCleanupPending}
	if s == nil {
		return status
	}
	s.mu.Lock()
	if s.cleaned {
		s.mu.Unlock()
		status.Status, status.CoreCleanup = protocolv4.V4CleanupStateComplete, protocolv4.V4CoreCleanupComplete
		return status
	}
	if s.cleanupError != nil || s.closed && !time.Now().Before(s.cleanupDeadline) {
		status.Status = protocolv4.V4CleanupStateCleanupIncomplete
	}
	a, application := s.admission, s.application
	s.mu.Unlock()
	var scope resourcev4.Account
	if a != nil {
		a.mu.Lock()
		core, prepared, accepted, retired := a.core, a.prepared, a.accepted, a.retired
		scope = a.scope.Session
		if application == nil {
			application = a.application
		}
		a.mu.Unlock()
		coreDone := retired
		if core != nil {
			core.mu.Lock()
			coreDone = core.cleaned
			core.mu.Unlock()
		}
		providerDone := retired
		if accepted != nil {
			accepted.mu.Lock()
			providerDone = accepted.cleaned
			accepted.mu.Unlock()
		} else if prepared != nil && prepared.preparedCarrier != nil {
			prepared.mu.Lock()
			providerDone = prepared.complete
			prepared.mu.Unlock()
		}
		if coreDone && providerDone {
			select {
			case <-s.watchDone:
				status.CoreCleanup = protocolv4.V4CoreCleanupComplete
			default:
			}
		}
	}
	if application != nil {
		application.mu.Lock()
		executor, backing := application.executor, application.reservation
		application.mu.Unlock()
		if executor != nil {
			executor.mu.Lock()
			for _, slot := range executor.slots {
				if slot.active && slot.started && slot.backing.RetainsCleanupScope(scope, backing) {
					status.PendingCallbacks++
				}
			}
			for _, slot := range executor.completions {
				if slot.active && slot.running && slot.backing.RetainsCleanupScope(scope, backing) {
					status.PendingCallbacks++
				}
			}
			executor.mu.Unlock()
		}
	}
	return status
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
	case <-s.cleanupObserved:
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.cleaned {
			return nil
		}
		if s.cleanupError != nil {
			return s.cleanupError
		}
		return ErrSessionCleanupIncomplete
	case <-ctx.Done():
		s.observeCleanupTimeout(ctx.Err())
		return ctx.Err()
	}
}

// WaitPhysicalCleanup joins an owning SDK aggregate to the actual retirement
// notification. Public observers use WaitCleanup's fixed finite result.
func (s *EnvironmentSession) WaitPhysicalCleanup(ctx context.Context) error {
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

// OpenStream is the public-adapter seam for an already delivered v4 session.
// It deliberately delegates to the original SessionCore so OPEN admission,
// stream limits, READY authorization and owner cleanup remain on the same
// state machine.  It does not create a carrier or a second session graph.
func (s *EnvironmentSession) OpenStream(ctx context.Context, kind string, metadata []byte, deadline *timev4.Deadline) (*StreamOwnership, error) {
	if s == nil || ctx == nil {
		return nil, cryptov4.ErrConfiguration
	}
	core, err := s.Core()
	if err != nil {
		return nil, err
	}
	if deadline == nil {
		// The public facade does not accept a detached trusted-time handle.
		// Its OPEN uses the original local dispatch window and signed Session
		// cap; cancellation still belongs to this same caller's operation.
		deadline, err = timev4.NewAge(core.plan.config.Clock, core.plan.config.DispatchTimeoutMS, core.plan.config.Session.SessionNotAfterMS)
		if err != nil {
			return nil, err
		}
	}
	return core.OpenStream(ctx, kind, metadata, deadline)
}

// OpenMessageStream retains the same delivered Session and original dispatch
// deadline as OpenStream. The typed candidate and reserved metadata wrapper
// are prepared by SessionCore before the native OPEN ordinal is allocated.
func (s *EnvironmentSession) OpenMessageStream(ctx context.Context, config TypedMessageConfig, metadata []byte) (*TypedMessageStream, error) {
	if s == nil || ctx == nil {
		return nil, cryptov4.ErrConfiguration
	}
	core, err := s.Core()
	if err != nil {
		return nil, err
	}
	deadline, err := timev4.NewAge(core.plan.config.Clock, core.plan.config.DispatchTimeoutMS, core.plan.config.Session.SessionNotAfterMS)
	if err != nil {
		return nil, err
	}
	return core.OpenMessageStream(ctx, config, metadata, deadline)
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
