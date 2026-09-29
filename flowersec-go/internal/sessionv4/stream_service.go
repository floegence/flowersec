package sessionv4

import (
	"context"
	"net/http"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// DelegatedHTTPService fixes the complete native HTTP execution responsibility
// in the original kind registry. Setup runs once on an ordinary invocation,
// before acceptance, and must return the handler whose complete lifetime and
// allocations are covered by Options.ExternalRuntime and the registration's
// delegate backing. HTTP requests and upgrades then belong to that declared
// external service; they do not borrow ordinary or Completion permits.
// Setup's invocation context is never used as the service's future context.
// HardDeadline must be nil here; the original Session supplies its authority.
type DelegatedHTTPService struct {
	Options HTTPStreamOptions
	Setup   func(context.Context, any, []byte) (http.Handler, error)
}

type preparedStreamService struct {
	controlled  *ControlledHTTPService
	callback    *resourcev4.ProtectedReservation
	dispatcher  *sessionStreamDispatcher
	options     HTTPStreamOptions
	rawOptions  DelegatedStreamOptions
	http        bool
	serve       DelegatedStreamServe
	refs        [3]resourcev4.Reference
	deadline    *timev4.Deadline
	context     context.Context
	cancel      context.CancelFunc
	handler     http.Handler
	transferred bool
}

func (job *streamHandlerInvocation) prepareStreamService(registration RawStreamHandlerConfig) error {
	d := job.dispatcher
	d.mu.Lock()
	if d.closed || d.services == d.config.ServiceTarget {
		d.mu.Unlock()
		return cryptov4.ErrCapacity
	}
	d.services++
	d.mu.Unlock()
	s := &preparedStreamService{dispatcher: d, http: registration.HTTP != nil || registration.ControlledHTTP != nil, controlled: registration.ControlledHTTP}
	installed := false
	defer func() {
		if !installed {
			s.release()
		}
	}()
	var err error
	var connection StreamConnOptions
	if s.controlled != nil {
		s.options, err = normalizeHTTPStreamOptions(s.controlled.Options)
		connection = s.options.Connection
	} else if s.http {
		s.options, err = normalizeHTTPStreamOptions(registration.HTTP.Options)
		connection = s.options.Connection
	} else {
		s.rawOptions = registration.Delegated.Options
		_, err = DelegatedStreamCharge(s.rawOptions)
		connection = s.rawOptions.Connection
	}
	if err != nil {
		return err
	}
	_, err = StreamConnCharge(connection)
	if err != nil {
		return err
	}
	p := d.core.plan
	if connection.TimeoutMS == 0 {
		s.deadline, err = timev4.NewDeadline(p.engine.Clock(), p.engine.SessionParameters().SessionNotAfterMS)
	} else {
		// Fix an explicit service age on this original preparation. Delayed
		// setup or accepted publication cannot move its start or renew it.
		s.deadline, err = timev4.NewAge(p.engine.Clock(), connection.TimeoutMS, p.engine.SessionParameters().SessionNotAfterMS)
	}
	if err != nil {
		return err
	}
	s.options.Connection.HardDeadline = s.deadline
	s.rawOptions.Connection.HardDeadline = s.deadline
	s.options.Connection.TimeoutMS, s.rawOptions.Connection.TimeoutMS = 0, 0
	job.allocation.reservation.NormalTerminationMS = connection.FinishTimeoutMS

	if job.allocation.floor == nil {
		return cryptov4.ErrConfiguration
	}
	if s.controlled != nil {
		s.callback = job.allocation.floor.owners[streamServiceCallback]
		if s.callback == nil {
			return cryptov4.ErrConfiguration
		}
	}
	s.refs, job.allocation.serviceRefs = job.allocation.serviceRefs, [3]resourcev4.Reference{}
	for _, ref := range s.refs {
		if err := ref.Check(); err != nil {
			return err
		}
	}

	// This context borrows only the original Session dispatcher lifetime.
	// It contains neither the short setup invocation nor any of its permits.
	s.context, s.cancel = context.WithCancel(d.context)
	job.watchMu.Lock()
	defer job.watchMu.Unlock()
	if err := job.context.Err(); err != nil {
		return err
	}
	job.service = s
	installed = true
	return nil
}

func (s *preparedStreamService) setup(ctx context.Context, capture StreamHandlerCapture, metadata []byte) (err error) {
	p := capture.plan
	p.mu.Lock()
	slot, err := capture.slotLocked()
	if err == nil && (p.closed || slot.busy || !slot.authorized || slot.accepted || slot.setupCalled) {
		err = cryptov4.ErrTransition
	}
	if err == nil {
		err = p.checkResourcesLocked()
	}
	if err != nil {
		p.mu.Unlock()
		return err
	}
	slot.busy, slot.setupCalled = true, true
	registration, binding := p.registrations[slot.registration].config, p.binding
	p.mu.Unlock()
	err = ErrStreamHandlerCallbackExit
	defer func() {
		_ = recover()
		if err != nil {
			s.handler, s.serve = nil, nil
		}
		capture.finish(false, &err)
	}()
	if err = s.checkResources(); err != nil {
		return err
	}
	// A panic/Goexit leaves the fixed failure value and never formats payload.
	err = ErrStreamHandlerCallbackExit
	if s.controlled != nil {
		s.handler, err = registration.ControlledHTTP.Setup(ctx, binding, metadata)
	} else if s.http {
		s.handler, err = registration.HTTP.Setup(ctx, binding, metadata)
	} else {
		s.serve, err = registration.Delegated.Setup(ctx, binding, metadata)
	}
	if err == nil && s.handler == nil && s.serve == nil {
		err = cryptov4.ErrConfiguration
	}
	if err == nil {
		err = ctx.Err()
	}
	return err
}

func (s *preparedStreamService) checkResources() error {
	if err := s.context.Err(); err != nil {
		return err
	}
	if err := s.deadline.Check(); err != nil {
		return err
	}
	for _, ref := range s.refs {
		if err := ref.Check(); err != nil {
			return err
		}
	}
	return nil
}
func (s *preparedStreamService) check() error {
	if s.handler == nil && s.serve == nil {
		return cryptov4.ErrConfiguration
	}
	return s.checkResources()
}

func (job *streamHandlerInvocation) runStreamService(owner *StreamOwnership) {
	s, d := job.service, job.dispatcher
	// Cancellation and handoff use one original gate. Cancellation that wins
	// prevents construction; later cancellation belongs to the accepted service.
	job.watchMu.Lock()
	err := job.context.Err()
	if err == nil {
		err = job.deadline.Check()
	}
	if err == nil {
		err = s.check()
	}
	if err == nil {
		err = job.capture.claimService()
	}
	var conn *StreamConn
	if err == nil && s.http {
		var service *HTTPStream
		var controlled *controlledHTTPExecution
		if s.controlled != nil {
			controlled = &controlledHTTPExecution{executor: d.executor, task: s.callback, class: s.controlled.RequestClass, timeoutMS: s.controlled.RequestTimeoutMS, upgrade: s.controlled.Upgrade}
		}
		service, err = startHTTPStream(s.context, owner, s.handler, s.options, s.refs[0], s.refs[1], job.allocation.refs[streamFactoryInvocation], controlled)
		if err == nil {
			conn = service.conn
		}
	} else if err == nil {
		var service *DelegatedStream
		service, err = StartDelegatedStream(s.context, owner, s.serve, s.rawOptions, s.refs[0], s.refs[1], job.allocation.refs[streamFactoryInvocation])
		if err == nil {
			conn = service.conn
		}
	}
	if err == nil {
		s.transferred = true
	}
	job.watchMu.Unlock()
	if err != nil {
		owner.Revoke()
		_ = owner.Cancel()
		_ = owner.Release()
		return
	}
	s.handler, s.serve = nil, nil
	// Setup already physically returned before OPEN acceptance. Its ordinary
	// slot is free; retain only this original service, transport and close work.
	job.finishWatch()
	d.core.plan.mu.Lock()
	job.allocation.service = true
	d.core.plan.streamServices++
	d.core.plan.mu.Unlock()
	d.mu.Lock()
	d.active--
	d.mu.Unlock()
	// Even cleanup_incomplete cannot release this registration, input or task.
	// The compound close owner closes done only after all real workers exit.
	<-conn.done
}

func (s *preparedStreamService) release() {
	if s == nil {
		return
	}
	if s.cancel != nil {
		s.cancel()
	}
	s.handler, s.serve = nil, nil
	for _, ref := range s.refs {
		ref.Release()
	}
	s.refs = [3]resourcev4.Reference{}
	s.dispatcher.mu.Lock()
	s.dispatcher.services--
	s.dispatcher.cleanupLocked()
	s.dispatcher.mu.Unlock()
}

// Service handoff consumes the original registration once. Accepted work keeps
// its captured generation, while every actual resource and cancellation gate
// remains live; a retained capture cannot start a second external execution.
func (c StreamHandlerCapture) claimService() error {
	p := c.plan
	p.mu.Lock()
	defer p.mu.Unlock()
	s, err := c.slotLocked()
	if err != nil {
		return err
	}
	r := p.registrations[s.registration].config
	if s.busy || !s.accepted || !s.setupCalled || s.handlerCalled || r.HTTP == nil && r.Delegated == nil && r.ControlledHTTP == nil {
		return cryptov4.ErrTransition
	}
	if err := p.checkResourcesLocked(); err != nil {
		return err
	}
	s.handlerCalled = true
	return nil
}
