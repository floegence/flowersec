package sessionv4

import (
	"context"
	"math"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

func (c *ConnectionController) Start(ctx context.Context) error {
	if c == nil || ctx == nil {
		return cryptov4.ErrConfiguration
	}
	c.mu.Lock()
	started, closed := c.started, c.closed
	c.mu.Unlock()
	if closed {
		return cryptov4.ErrClosed
	}
	if started {
		return nil
	}
	_, err := c.begin(ctx, ControllerReplaceOptions{}, true, nil)
	return err
}

// ReplaceSession is an active attempt. Cancellation before publication revokes
// that attempt; after publication it only ends this call's result observation.
func (c *ConnectionController) ReplaceSession(ctx context.Context, options ControllerReplaceOptions) (ControllerReplaceResult, error) {
	a, err := c.begin(ctx, options, false, nil)
	if err != nil {
		return ControllerReplaceResult{}, err
	}
	select {
	case <-a.done:
	case <-ctx.Done():
	}
	c.mu.Lock()
	if !a.finished {
		a.cancel(ctx.Err())
		c.finishLocked(a, ctx.Err())
	}
	result, err := a.result, a.err
	c.mu.Unlock()
	return result, err
}

// RetryNow only wakes an existing retry. It cannot acquire in parallel, bypass
// an authoritative not-before, or restart failed application initialization.
func (c *ConnectionController) RetryNow(ctx context.Context) error {
	if c == nil || ctx == nil {
		return cryptov4.ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return cryptov4.ErrClosed
	}
	if c.blocked {
		c.mu.Unlock()
		return ErrControllerInitialization
	}
	if c.attempt != nil || c.retryPending {
		c.mu.Unlock()
		return ErrControllerBusy
	}
	w, clock, notBefore := c.retryWindow, c.config.Clock, c.retryNotBefore
	c.mu.Unlock()
	if w == nil {
		return cryptov4.ErrTransition
	}
	if notBefore != 0 {
		now, err := clock.Sample()
		if err != nil {
			return err
		}
		if now.LowerMS < notBefore {
			return timev4.ErrPending
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.retryWindow != w || !c.retryEligibleLocked(c.serial) {
		return cryptov4.ErrTransition
	}
	c.retryRequested = true
	c.signalLocked()
	return nil
}

func (c *ConnectionController) begin(ctx context.Context, options ControllerReplaceOptions, ordinary bool, retry *timev4.Window) (*controllerAttempt, error) {
	if c == nil || ctx == nil {
		return nil, cryptov4.ErrConfiguration
	}
	if options.Retirement > ControllerRetain || options.Retirement == ControllerDrain && options.RetainUntilMS != 0 || options.Retirement == ControllerRetain && options.RetainUntilMS == 0 {
		return nil, cryptov4.ErrConfiguration
	}
	if application, err := checkApplicationContext(ctx); err != nil {
		return nil, err
	} else if application {
		return nil, ErrApplicationDependency
	}
	// Sample the trusted clock before entering the local publication gate.
	// Its adapter must never run while another Controller action is locked out.
	c.mu.Lock()
	clock, timeout := c.config.Clock, c.config.AttemptTimeoutMS
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return nil, cryptov4.ErrClosed
	}
	deadline, err := timev4.NewAge(clock, timeout, math.MaxUint64)
	if err != nil {
		return nil, err
	}
	var retention *timev4.Deadline
	if options.Retirement == ControllerRetain {
		retention, err = timev4.NewDeadline(clock, options.RetainUntilMS)
		if err != nil {
			return nil, err
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.lifetime.Err() != nil {
		return nil, cryptov4.ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if ordinary && c.blocked {
		return nil, ErrControllerInitialization
	}
	if retry != nil && (c.retryWindow != retry || !c.retryEligibleLocked(c.serial)) {
		return nil, cryptov4.ErrTransition
	}
	if ordinary && retry == nil && c.started {
		return nil, cryptov4.ErrTransition
	}
	if c.attempt != nil {
		return nil, ErrControllerBusy
	}
	if c.retired != nil {
		return nil, ErrRetirementCapacity
	}
	if ordinary && c.current != nil {
		return nil, cryptov4.ErrTransition
	}
	if c.serial == math.MaxUint64 {
		return nil, cryptov4.ErrCapacity
	}
	if err := c.reservation.Check(); err != nil {
		return nil, err
	}
	var task resourcev4.Reference
	var completion *CompletionReservation
	var initializer *ApplicationPermit
	if c.task != nil {
		task, err = c.task.Checkout()
		if err == nil {
			completion, err = c.completion.Checkout()
		}
		if err == nil {
			// Reserve the actual executor position before source work. READY
			// and dependency preparation cannot turn this original promise
			// into a new competition for running or resident capacity.
			initializer, err = c.config.Executor.TryAcquire(c.config.InitializeClass, task, c.reservation)
		}
		if err != nil {
			completion.Close()
			task.Release()
			return nil, err
		}
	}
	attemptCtx, cancel := context.WithCancelCause(ctx)
	c.serial++
	if c.cycleAttempts < math.MaxUint64 {
		c.cycleAttempts++
	}
	if ordinary {
		c.automatic, c.retryContext = true, ctx
	}
	c.retryWindow, c.retryNotBefore, c.retryRequested, c.retryPending = nil, 0, false, false
	a := &controllerAttempt{serial: c.serial, automatic: ordinary, ctx: attemptCtx, cancel: cancel, deadline: deadline, retention: retention, options: options, previous: c.current, done: make(chan struct{}), initializer: initializer, completion: completion}
	c.started = true
	c.lastError = nil
	c.lastDiagnostic, c.hasLastDiagnostic = unknownAttemptDiagnostic(a.serial), true
	c.attempt = a
	c.signalLocked()
	go c.establish(a)
	return a, nil
}

// This callback is invoked under the Environment admission gate, before any
// source/provider task starts. It records the original physical cleanup owner
// even when Connect later returns only an error.
func (c *ConnectionController) attach(a *controllerAttempt, s *EnvironmentSession) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.attempt != a || a.finished || a.candidate != nil || a.ctx.Err() != nil {
		return cryptov4.ErrClosed
	}
	a.candidate = s
	c.signalLocked()
	return nil
}

func (c *ConnectionController) checkAttempt(a *controllerAttempt) error {
	c.mu.Lock()
	if c.closed || c.attempt != a || a.finished {
		c.mu.Unlock()
		return cryptov4.ErrClosed
	}
	candidate := a.candidate
	c.mu.Unlock()
	if err := a.ctx.Err(); err != nil {
		return err
	}
	if err := c.lifetime.Err(); err != nil {
		return err
	}
	if err := c.reservation.Check(); err != nil {
		return err
	}
	if err := a.deadline.Check(); err != nil {
		return err
	}
	if candidate != nil {
		return candidate.controllerAttemptValid()
	}
	return nil
}

func (c *ConnectionController) finishLocked(a *controllerAttempt, err error) {
	if a.finished {
		return
	}
	a.finished = true
	a.err = err
	a.transportFailure = a.transportFailure && controllerNetworkRetry(err)
	if a.sourceFailure != nil && err != a.sourceFailure {
		a.sourceFailure = nil
	}
	if err != nil {
		c.lastError = err
		if a.entered {
			c.blocked = true
		}
	}
	close(a.done)
	c.signalLocked()
}

// Copy only the candidate's first original failure. Both the establishing
// worker and coordinator may observe it; neither may relabel a prior local
// cancellation or a callback error. No Controller lock is held at Session gates.
func (c *ConnectionController) captureAttemptFailure(a *controllerAttempt, err error) {
	c.mu.Lock()
	candidate := a.candidate
	c.mu.Unlock()
	if candidate == nil || err == nil {
		return
	}
	candidate.mu.Lock()
	cause, transport, source := candidate.result, candidate.controllerTransportFailure, candidate.controllerSourceFailure
	candidate.mu.Unlock()
	// Network errors accepted here have comparable concrete sentinel/pointer
	// types. Source identity is also an exact pointer, never an error hook.
	transport = transport && controllerNetworkRetry(err) && cause == err
	sourceMatches := source != nil && err == source && cause == source
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.attempt == a && !a.finished && !a.entered {
		a.transportFailure = a.transportFailure || transport
		if sourceMatches {
			a.sourceFailure = source
		}
	}
}

func (c *ConnectionController) establish(a *controllerAttempt) {
	var preparation *ControllerPreparation
	adopted := false
	err := ErrEnvironmentTaskExit
	defer func() {
		if recover() != nil {
			err = ErrEnvironmentTaskExit
		}
		c.captureAttemptFailure(a, err)
		c.mu.Lock()
		c.finishLocked(a, err)
		candidate, switched := a.candidate, a.result.CurrentSwitched
		c.mu.Unlock()
		if candidate != nil && !switched {
			candidate.Close()
		}
		if !adopted && preparation != nil {
			for {
				cleanupErr := preparation.releaseUnused()
				c.mu.Lock()
				a.cleanupError, a.unused = cleanupErr, preparation
				if cleanupErr == nil {
					a.unused = nil
				}
				// The existing coordinator timer supplies the next cleanup wake.
				// Signalling its work queue here would turn failed retirement
				// into a self-sustaining worker/coordinator busy loop.
				c.changedLocked()
				changed := c.changed
				c.mu.Unlock()
				if cleanupErr == nil {
					break
				}
				// Retain the original worker and graph until actual retirement.
				<-changed
			}
		}
		a.initializer.Close()
		a.initialization.close()
		a.workloads.close(candidate)
		if a.completion != nil {
			a.completion.Close()
		}
		a.cancel(err)
		c.mu.Lock()
		a.exited = true
		c.signalLocked()
		c.mu.Unlock()
	}()
	if err = c.checkAttempt(a); err != nil {
		return
	}
	// A retained Session is validated before PrepareConnection can acquire a
	// lease. Its original signed hard cap is never widened by the local cap.
	if a.retention != nil && a.previous != nil {
		var cap uint64
		cap, err = a.previous.controllerAccepting(nil)
		if err != nil {
			return
		}
		if a.retention.Cap() > cap {
			err = timev4.ErrExpired
			return
		}
	}
	preparation, err = c.config.Source.PrepareConnection(a.ctx, ControllerRequest{Attempt: a.serial, SourceIncarnation: c.config.SourceIncarnation, Deadline: a.deadline})
	if err != nil {
		c.mu.Lock()
		if !a.finished {
			a.sourceFailure = controllerSourceFailure(err)
		}
		c.mu.Unlock()
		return
	}
	if preparation == nil {
		err = cryptov4.ErrConfiguration
		return
	}
	if err = c.checkAttempt(a); err != nil {
		return
	}
	config := preparation.Config
	if config.Admission.Core.Clock != c.config.Clock ||
		config.Admission.Initial.Deadline == nil || !config.Admission.Initial.Deadline.BelongsTo(c.config.Clock) ||
		config.controller != nil || config.controllerOwner != nil {
		err = cryptov4.ErrConfiguration
		return
	}
	if preparation.PoolSource != nil {
		source := preparation.PoolSource
		source.mu.Lock()
		pool := source.pool
		valid := !source.closed && pool != nil
		source.mu.Unlock()
		if valid {
			pool.mu.Lock()
			valid = !pool.closed && pool.environment == c.environment && pool.generation.Source == c.config.SourceIncarnation
			pool.mu.Unlock()
		}
		if !valid || preparation.Pool == nil || preparation.Live != nil || config.Generation != (MaterialGeneration{}) || config.poolSource != nil {
			err = cryptov4.ErrConfiguration
			return
		}
		config.poolSource = source
	} else if config.Generation.Source != c.config.SourceIncarnation || config.poolSource != nil {
		err = cryptov4.ErrConfiguration
		return
	}
	if err = config.Admission.Initial.Deadline.TightenFrom(a.deadline); err != nil {
		return
	}
	if err = a.deadline.TightenFrom(config.Admission.Initial.Deadline); err != nil {
		return
	}
	config.controller, config.controllerOwner = a, c
	if err = c.prepareWorkloadPlan(a, &config); err != nil {
		return
	}
	if err = c.prepareInitializerPlan(a, config); err != nil {
		return
	}
	if config.Admission.headroom != nil {
		err = cryptov4.ErrConfiguration
		return
	}
	config.Admission.headroom, err = reserveSessionHeadroom(config, c.environment)
	if err != nil {
		return
	}
	defer func() {
		if !adopted {
			config.Admission.headroom.close()
		}
	}()
	if err = c.waitVerification(a, config); err != nil {
		return
	}
	if err = a.workloads.check(); err != nil {
		return
	}
	var session *EnvironmentSession
	session, adopted, err = c.environment.ConnectPrepared(a.ctx, config, nil, preparation.Pool, preparation.Live)
	if err != nil {
		return
	}
	if session == nil {
		err = cryptov4.ErrConfiguration
		return
	}
	defer c.finishCandidateContracts(a)
	if err = c.waitDependencies(a, session); err != nil {
		return
	}
	if c.config.InitializeSession != nil {
		if err = c.initialize(a, session); err != nil {
			return
		}
		if a.initialization != nil {
			// A successful initializer may have consumed its prepared Stream.
			// Replenish only that same admitted path outside application work,
			// under the original attempt deadline, before final publication.
			if err = c.waitDependencies(a, session); err != nil {
				return
			}
		}
	}
	if err = c.checkAttempt(a); err != nil {
		return
	}
	now, sampleErr := c.config.Clock.Sample()
	if sampleErr != nil {
		err = sampleErr
		return
	}
	finishRenewal, renewalErr := c.prepareRenewalCurrent(session, now)
	if renewalErr != nil {
		err = renewalErr
		return
	}
	publishedCurrent := false
	defer func() { finishRenewal(publishedCurrent) }()
	finishDependencies, dependencyErr := c.qualifyDeclaredDependencies(a.initializerContext(c), session)
	if dependencyErr != nil {
		err = dependencyErr
		return
	}
	defer finishDependencies()
	if err = a.workloads.checkRevisionLocked(); err != nil {
		return
	}
	err = session.withControllerAccepting(c.config.RequiredContracts, now, func(uint64) error {
		publish := func(retained bool, retirementErr error) error {
			return a.initialization.withGenerations(func() error {
				c.mu.Lock()
				defer c.mu.Unlock()
				if c.closed || c.attempt != a || a.finished || a.ctx.Err() != nil || c.lifetime.Err() != nil {
					return cryptov4.ErrClosed
				}
				if c.config.InitializeSession != nil && !a.initialized {
					return ErrControllerInitialization
				}
				if err := a.deadline.CheckAt(now); err != nil {
					return err
				}
				c.publishNotificationsLocked(session, a.previous, a.options.Retirement)
				c.current = session
				// withControllerAccepting still holds this original Session gate.
				session.controllerApplicationPublished = true
				publishedCurrent = true
				c.retired = a.previous
				c.retention = a.retention
				c.retirement = a.options.Retirement
				c.retirementStarted = false
				c.blocked = false
				c.lastError = nil
				c.lastDiagnostic, c.hasLastDiagnostic = ConnectionDiagnostic{}, false
				c.cycleAttempts = 0
				a.result = ControllerReplaceResult{CurrentSwitched: true, Current: session, Previous: a.previous, Retirement: a.options.Retirement, RetainUntilMS: a.options.RetainUntilMS, PreviousRetained: retained, RetirementError: retirementErr}
				c.finishLocked(a, nil)
				return nil
			})
		}
		if a.retention != nil && a.previous != nil {
			called := false
			retirementErr := a.previous.withControllerRetention(a.retention, now, func() error { called = true; return publish(true, nil) })
			if called {
				return retirementErr
			}
			// The old path may have begun Drain or terminated while the candidate
			// was being established. Publish the qualified replacement and report
			// that fact, without pretending the old path was retained or reopened.
			return publish(false, retirementErr)
		}
		return publish(false, nil)
	})
}

func (p *ControllerPreparation) releaseUnused() error {
	// Trusted providers return exclusive preparation inputs, never an already
	// attached SessionPlan. Cleanup waits for actual callbacks before releasing
	// their referenced graph; failed cleanup cannot assert a refund.
	if p.Config.Admission.Application != nil {
		if err := p.Config.Admission.Application.retireUnclaimed(); err != nil {
			return err
		}
	}
	for _, ref := range [...]resourcev4.Reference{p.Config.Preparation, p.Config.Acquisition, p.Config.Material, p.Config.Establishment, p.Config.Subscriptions, p.Config.CarrierReservation, p.Config.LiveIssuance.Reservation} {
		ref.Release()
	}
	if p.Pool != nil {
		p.Pool.Consume.Release()
	}
	if p.Live != nil {
		p.Live.Buffers.Release()
		p.Live.Invocation.Release()
	}
	return nil
}

func (c *ConnectionController) waitDependencies(a *controllerAttempt, s *EnvironmentSession) error {
	for {
		c.mu.Lock()
		changed := c.changed
		c.mu.Unlock()
		if err := c.checkAttempt(a); err != nil {
			return err
		}
		if err := a.workloads.check(); err != nil {
			return err
		}
		_, err := s.controllerAccepting(c.config.RequiredContracts)
		if err == nil {
			err = c.prepareCandidateContracts(a, s)
		}
		if err == nil {
			err = c.prepareCandidateWorkloads(a, s)
		}
		if err == nil {
			err = c.prepareDeclaredDependencyPaths(a.ctx, s, a.deadline)
		}
		if err == nil {
			err = a.initialization.prepare(a.ctx, s)
		}
		if err == nil {
			var finish func()
			finish, err = c.qualifyDeclaredDependencies(a.initializerContext(c), s)
			if finish != nil {
				finish()
			}
		}
		if err == nil {
			err = c.initializeServices.requiredReady(a.initializerContext(c))
		}
		if err == nil || !dependencyPreparationPending(err) {
			return err
		}
		// One original attempt waits on the controller's bounded merged timer.
		select {
		case <-a.ctx.Done():
			return context.Cause(a.ctx)
		case <-changed:
		}
	}
}

func (c *ConnectionController) initialize(a *controllerAttempt, s *EnvironmentSession) error {
	cap, err := s.controllerAccepting(c.config.RequiredContracts)
	if err != nil {
		return err
	}
	if err := c.initializeServices.requiredReady(a.initializerContext(c)); err != nil {
		return err
	}
	if err = a.deadline.Tighten(min(a.deadline.Cap(), cap)); err != nil {
		return err
	}
	permit := a.initializer
	if permit == nil {
		return resourcev4.ErrOwner
	}
	defer permit.Close()
	callbackErr := ErrEnvironmentTaskExit
	task, err := permit.Start(func() {
		defer func() {
			if recover() != nil {
				callbackErr = ErrEnvironmentTaskExit
			}
			c.mu.Lock()
			a.callbackRunning = false
			c.signalLocked()
			c.mu.Unlock()
		}()
		if callbackErr = c.checkAttempt(a); callbackErr != nil {
			return
		}
		parent := a.initializerContext(c)
		ctx, exit, entryErr := enterApplicationContext(parent, c.config.Executor, ordinaryApplicationLane, c.config.InitializeClass, c.reservation, nil)
		if entryErr != nil {
			callbackErr = entryErr
			return
		}
		defer exit()
		if callbackErr = attachInvocationServices(ctx, c.initializeServices); callbackErr != nil {
			return
		}
		if callbackErr = a.initialization.attachReferences(ctx); callbackErr != nil {
			return
		}
		now, sampleErr := c.config.Clock.Sample()
		if sampleErr != nil {
			callbackErr = sampleErr
			return
		}
		finishDependencies, dependencyErr := c.qualifyDeclaredDependencies(parent, s)
		if dependencyErr != nil {
			callbackErr = dependencyErr
			return
		}
		callbackErr = s.withControllerAccepting(c.config.RequiredContracts, now, func(uint64) error {
			return a.initialization.withGenerations(func() error {
				c.mu.Lock()
				defer c.mu.Unlock()
				if c.closed || c.attempt != a || a.finished || a.ctx.Err() != nil {
					return cryptov4.ErrClosed
				}
				if err := a.deadline.CheckAt(now); err != nil {
					return err
				}
				a.entered, a.callbackRunning = true, true
				c.blocked = true
				c.signalLocked()
				return nil
			})
		})
		finishDependencies()
		if callbackErr != nil {
			return
		}
		callbackErr = ErrEnvironmentTaskExit
		callbackErr = c.config.InitializeSession(ctx, s)
	})
	if err != nil {
		return err
	}
	// Even after observer cancellation the existing attempt position remains
	// occupied until this original callback and all of its defers really exit.
	<-task.Done()
	// Deliver the original result through its already reserved Completion
	// position after the ordinary callback and permit have actually exited.
	completion, err := a.completion.Submit(func() error {
		c.mu.Lock()
		defer c.mu.Unlock()
		if !c.closed && c.attempt == a && !a.finished && a.ctx.Err() == nil && callbackErr == nil {
			a.initialized = true
		}
		return callbackErr
	})
	if err != nil {
		return err
	}
	return completion.Wait(context.Background())
}
