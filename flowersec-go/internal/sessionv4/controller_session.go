package sessionv4

import (
	"errors"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

func (s *EnvironmentSession) controllerAccepting(required [][32]byte) (cap uint64, err error) {
	now, err := s.controllerSample()
	if err != nil {
		return 0, err
	}
	err = s.withControllerAccepting(required, now, func(value uint64) error { cap = value; return nil })
	return
}

func (s *EnvironmentSession) controllerSample() (timev4.Sample, error) {
	if s == nil {
		return timev4.Sample{}, cryptov4.ErrNotReady
	}
	s.mu.Lock()
	if !s.delivered || s.closed || s.core == nil {
		s.mu.Unlock()
		return timev4.Sample{}, cryptov4.ErrClosed
	}
	p := s.core.plan
	p.mu.Lock()
	clock := p.config.Clock
	p.mu.Unlock()
	s.mu.Unlock()
	if clock == nil {
		return timev4.Sample{}, cryptov4.ErrClosed
	}
	return clock.Sample()
}

// A candidate's original terminal signal cancels its initializer even after
// Connect has detached the caller's context at dual READY.
func (s *EnvironmentSession) controllerAttemptValid() error {
	s.mu.Lock()
	closed, delivered, cause := s.closed, s.delivered, s.result
	s.mu.Unlock()
	if closed {
		if cause != nil {
			return cause
		}
		return cryptov4.ErrClosed
	}
	if delivered {
		_, err := s.controllerAccepting(nil)
		return err
	}
	return nil
}

// The action is SDK-only publication, with no I/O or application callbacks.
// Session/Open admission remains locked until current publication commits.
func (s *EnvironmentSession) withControllerAccepting(required [][32]byte, now timev4.Sample, action func(uint64) error) error {
	if s == nil {
		return cryptov4.ErrNotReady
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.delivered || s.closed || s.core == nil {
		return cryptov4.ErrClosed
	}
	p := s.core.plan
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.admission == nil || p.engine == nil {
		return cryptov4.ErrClosed
	}
	a := p.admission
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed || a.draining || a.peerGoAway.set {
		return ErrSessionDraining
	}
	if err := p.engine.CheckApplicationAuthorization(); err != nil {
		return err
	}
	var lease *ApplicationLease
	if p.application != nil {
		var err error
		lease, _, err = p.application.queryAuthorization()
		if err != nil {
			return err
		}
	}
	qualification := func() error {
		r := p.rpc
		if r == nil && len(required) != 0 {
			return cryptov4.ErrNotReady
		}
		if r != nil {
			r.mu.Lock()
			defer r.mu.Unlock()
			if r.closed || r.draining.Load() {
				return ErrSessionDraining
			}
		}
		if lease != nil {
			lease.mu.Lock()
			defer lease.mu.Unlock()
			if !lease.reserved || !lease.authorized || lease.revoked {
				return ErrApplicationAuthorization
			}
		}
		if len(required) != 0 {
			if r.rpcPublisherLocked() == nil {
				return cryptov4.ErrNotReady
			}
			err := r.routes.WithRequiredUnaryAt(required, now, func() error { return action(p.config.Session.SessionNotAfterMS) })
			if errors.Is(err, rpcv4.ErrMethod) {
				// A configured exact route or its Offer may still be installing.
				// Keep the original candidate/deadline; never acquire again.
				return cryptov4.ErrNotReady
			}
			return err
		}
		return action(p.config.Session.SessionNotAfterMS)
	}
	// Keep original endpoint authorization and the application lease through
	// current publication, using the same order as request-header acceptance.
	if s.admission == nil || s.admission.authorization == nil {
		return cryptov4.ErrNotReady
	}
	return s.admission.authorization.WithCurrentAuthorization(qualification)
}

// Installing retirement and switching current share one publication action.
// Failure leaves the previous Session's local limit untouched.
func (s *EnvironmentSession) withControllerRetention(deadline *timev4.Deadline, now timev4.Sample, action func() error) error {
	if s == nil || deadline == nil {
		return action()
	}
	return s.withControllerAccepting(nil, now, func(cap uint64) error {
		if s.controllerRetention != nil {
			return ErrRetirementCapacity
		}
		if deadline.Cap() > cap {
			return timev4.ErrExpired
		}
		if err := deadline.CheckAt(now); err != nil {
			return err
		}
		if err := action(); err != nil {
			return err
		}
		s.controllerRetention = deadline
		return nil
	})
}
