package sessionv4

import (
	"context"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

type controllerInitializerKey struct{}
type controllerInitializerContext struct {
	context.Context
	identity *controllerIdentity
	plan     *controllerInitializerToken
}

func (c controllerInitializerContext) Value(key any) any {
	if _, ok := key.(controllerInitializerPlanKey); ok {
		if c.plan == nil {
			return nil
		}
		return c.plan.plan.Load()
	}
	if _, ok := key.(controllerInitializerKey); ok {
		return c.identity
	}
	return c.Context.Value(key)
}

func (a *controllerAttempt) initializerContext(c *ConnectionController) context.Context {
	return controllerInitializerContext{Context: a.ctx, identity: c.identity, plan: a.initialization.contextToken()}
}

// CaptureSession performs no acquisition, OPEN, application call or polling.
// The snapshot is checked again at the publication gate; a racing replacement
// cannot make a previously captured pointer become the new current Session.
func (c *ConnectionController) CaptureSession() (*EnvironmentSession, error) {
	if c == nil {
		return nil, cryptov4.ErrConfiguration
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, cryptov4.ErrClosed
	}
	if c.blocked {
		c.mu.Unlock()
		return nil, ErrControllerInitialization
	}
	s := c.current
	required := c.config.RequiredContracts
	c.mu.Unlock()
	if s == nil {
		return nil, cryptov4.ErrNotReady
	}
	now, err := s.controllerSample()
	if err != nil {
		return nil, err
	}
	err = s.withControllerAccepting(required, now, func(uint64) error {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.closed {
			return cryptov4.ErrClosed
		}
		if c.blocked {
			return ErrControllerInitialization
		}
		if c.current != s {
			return cryptov4.ErrNotReady
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return s, nil
}

// WaitForSession only observes publication. Its cancellation never calls
// Close, starts a connection or changes any candidate's original deadline.
func (c *ConnectionController) WaitForSession(ctx context.Context) (*EnvironmentSession, error) {
	if c == nil || ctx == nil {
		return nil, cryptov4.ErrConfiguration
	}
	if ctx.Value(controllerInitializerKey{}) == c.identity {
		return nil, ErrApplicationDependency
	}
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		c.mu.Lock()
		changed := c.changed
		c.mu.Unlock()
		s, err := c.CaptureSession()
		if err == nil {
			return s, err
		}
		c.mu.Lock()
		initializing := c.attempt != nil && c.attempt.entered && !c.attempt.finished
		closed := c.closed
		willRetry := c.retryWindow != nil || c.retryPending
		if a := c.attempt; a != nil && a.automatic && a.finished && !a.entered && (a.sourceFailure != nil || a.transportFailure) && !c.blocked &&
			c.retryContext != nil && c.retryContext.Err() == nil && (c.config.MaximumAttempts == 0 || c.cycleAttempts < c.config.MaximumAttempts) {
			willRetry = true
		}
		failed := (c.attempt == nil || c.attempt.finished) && c.lastError != nil && !willRetry
		failure := c.lastError
		settled := c.attempt == nil
		c.mu.Unlock()
		if closed {
			return nil, cryptov4.ErrClosed
		}
		if err == ErrControllerInitialization && !initializing && settled {
			return nil, err
		}
		if failed && settled {
			return nil, failure
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-changed:
		}
	}
}

func controllerSessionDone(s *EnvironmentSession) bool {
	if s == nil {
		return true
	}
	select {
	case <-s.done:
		return true
	default:
		return false
	}
}

// A single charged coordinator advances the fixed three links. Close is local
// and nonblocking; providers are closed by each Session's existing watcher.
// No per-Session shutdown waiter is created and no timeout refunds a tail.
func (c *ConnectionController) run() {
	timer := time.NewTimer(0)
	defer timer.Stop()
	lifetime := c.lifetime.Done()
	for {
		c.mu.Lock()
		var candidateStop <-chan struct{}
		if a := c.attempt; a != nil && !a.finished && a.candidate != nil {
			candidateStop = a.candidate.stop
		}
		c.mu.Unlock()
		select {
		case <-lifetime:
			c.Close()
			lifetime = nil
		case <-c.wake:
		case <-candidateStop:
		case <-timer.C:
		}
		c.advanceDispatches()
		c.advanceNotifications()
		c.mu.Lock()
		closed, current, retired, a := c.closed, c.current, c.retired, c.attempt
		pending := a != nil && !a.finished
		retention, retirement := c.retention, c.retirement
		startRetirement := retired != nil && !c.retirementStarted
		if startRetirement {
			c.retirementStarted = true
		}
		c.mu.Unlock()
		if pending {
			err := c.checkAttempt(a)
			if err != nil {
				c.captureAttemptFailure(a, err)
				c.mu.Lock()
				a.cancel(err)
				c.finishLocked(a, err)
				c.mu.Unlock()
			}
		}
		if closed {
			if current != nil {
				current.Close()
			}
			if retired != nil {
				retired.Close()
			}
		}
		if a != nil {
			c.mu.Lock()
			candidate, failed := a.candidate, a.finished && !a.result.CurrentSwitched
			c.mu.Unlock()
			if candidate != nil && (failed || closed) {
				candidate.Close()
			}
		}
		if retired != nil && !closed {
			if retention != nil && retention.Check() != nil {
				retired.Close()
			} else if startRetirement && retirement == ControllerDrain {
				if _, err := retired.Drain(c.config.DrainTimeoutMS, 0); err != nil {
					retired.Close()
				}
			}
		}
		currentDone := controllerSessionDone(current)
		var currentFailure error
		var currentTransport bool
		var currentDiagnostic ConnectionDiagnostic
		if current != nil && currentDone {
			currentDiagnostic = current.ConnectionDiagnostic()
			current.mu.Lock()
			currentFailure = current.result
			currentTransport = current.controllerTransportFailure && controllerNetworkRetry(currentFailure)
			current.mu.Unlock()
		}
		c.mu.Lock()
		var failedCandidate *EnvironmentSession
		if a != nil && c.attempt == a && a.exited && !a.result.CurrentSwitched {
			failedCandidate = a.candidate
		}
		c.mu.Unlock()
		var candidateDiagnostic ConnectionDiagnostic
		if failedCandidate != nil {
			candidateDiagnostic = failedCandidate.ConnectionDiagnostic()
		}
		c.mu.Lock()
		retry, notBefore := false, uint64(0)
		if c.retired != nil && controllerSessionDone(c.retired) {
			c.retired = nil
			c.retention = nil
			c.signalLocked()
		}
		if a != nil && c.attempt == a && a.exited && a.unused == nil && (a.result.CurrentSwitched || controllerSessionDone(a.candidate)) {
			if !a.result.CurrentSwitched && a.automatic && !a.entered && (a.sourceFailure != nil || a.transportFailure) {
				retry = true
				if a.sourceFailure != nil {
					notBefore = a.sourceFailure.notBeforeMS
				}
			}
			if !a.result.CurrentSwitched && failedCandidate != nil && a.candidate == failedCandidate {
				c.lastDiagnostic, c.hasLastDiagnostic = candidateDiagnostic, true
			}
			c.attempt = nil
			c.signalLocked()
		}
		// A published current can finish before its successful attempt exits.
		// Keep that original Session and failure until its same attempt tail is
		// removed above; otherwise the only network retry source would be lost.
		publicationTail := c.attempt != nil && c.attempt.result.CurrentSwitched && c.attempt.result.Current == current
		if current != nil && c.current == current && currentDone && !publicationTail {
			c.current = nil
			// An older current Session may finish while a later replacement is
			// establishing or has failed. Retiring it cannot overwrite the newer
			// attempt's failure or its spend/publication facts.
			if currentDiagnostic.Attempt == c.serial {
				c.lastError = currentFailure
				c.lastDiagnostic, c.hasLastDiagnostic = currentDiagnostic, true
			}
			// A new acquisition uses the configured Source after original cleanup;
			// the consumed material and its spend facts remain terminal.
			if currentDiagnostic.Attempt == c.serial && c.attempt == nil && c.retryWindow == nil && !c.retryPending && currentTransport {
				retry = true
			}
			c.signalLocked()
		}
		serial := c.serial
		c.retryPending = retry && c.retryEligibleLocked(serial)
		ready := c.closed && c.current == nil && c.retired == nil && c.attempt == nil && c.dispatches == 0 && c.notificationsCleanedLocked()
		if ready {
			if c.task != nil {
				c.task.Close()
			}
			if c.completion != nil {
				c.completion.Close()
			}
			ready = (c.task == nil || c.task.CleanupComplete()) && (c.completion == nil || c.completion.CleanupComplete())
		}
		if ready {
			services := c.initializeServices
			c.initializeServices = nil
			c.mu.Unlock()
			services.close()
			c.mu.Lock()
			c.config = ControllerConfig{}
			c.lifetime = nil
			c.retryContext = nil
			c.shared.Release()
			c.shared = resourcev4.Reference{}
			c.reservation.Release()
			c.reservation = resourcev4.Reference{}
			c.cleaned = true
			c.signalLocked()
			e, position := c.environment, c.position
			c.environment = nil
			c.mu.Unlock()
			e.mu.Lock()
			e.controllers[position] = nil
			e.controllersActive--
			e.completeLocked()
			e.mu.Unlock()
			close(c.done)
			return
		}
		// Dependency readiness and physical cleanup share this bounded wake. A
		// fixed timer never restarts the attempt or retained absolute deadline.
		c.changedLocked()
		c.mu.Unlock()
		if retry {
			c.scheduleRetry(serial, notBefore)
		}
		c.advanceRetry()
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(25 * time.Millisecond)
	}
}
