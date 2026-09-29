package sessionv4

import (
	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

// The attempt keeps its local recipe, original deadline and charged worker
// while verification catches up. This never reacquires a lease, performs a
// TopUp or starts a second namespace refresh owner.
func (c *ConnectionController) waitVerification(a *controllerAttempt, config SourceConnectConfig) error {
	defer func() {
		c.mu.Lock()
		a.verificationPending = false
		c.changedLocked()
		c.mu.Unlock()
	}()
	for {
		c.mu.Lock()
		changed := c.changed
		c.mu.Unlock()
		if err := c.checkAttempt(a); err != nil {
			return err
		}
		var pending bool
		var err error
		if config.poolSource != nil {
			if h := config.Admission.headroom; h != nil {
				if err := config.poolSource.checkPreparationOwner(c.environment); err != nil {
					return err
				}
				if h.source.poolOrigin != config.poolSource || h.source.verification.lease == nil {
					return resourcev4.ErrOwner
				}
				pending, err = c.environment.checkPreparationLease(h.source.verification)
			} else {
				pending, err = config.poolSource.controllerVerification(c.environment)
			}
		} else {
			var pin identityUse
			if h := config.Admission.headroom; h != nil {
				// This original attempt owns the headroom throughout the wait.
				// Source publication and its cleanup occur only after it returns.
				// Reuse the captured generation even if advertisement retires.
				pin = h.source.identity
				if pin.identity == nil || pin.identity != config.Identity {
					return resourcev4.ErrOwner
				}
			} else {
				var captureErr error
				pin, captureErr = config.Identity.capture(c.reservation)
				if captureErr != nil {
					return captureErr
				}
			}
			i := pin.identity
			pending, err = c.environment.checkPreparationCredential(i.validation, i.credential, pin.ref)
			if config.Admission.headroom == nil {
				pin.release()
			}
		}
		if err != nil || !pending {
			return err
		}
		c.mu.Lock()
		a.verificationPending = true
		c.mu.Unlock()
		select {
		case <-a.ctx.Done():
			return a.ctx.Err()
		case <-changed:
		}
	}
}

func (s *PreauthorizedPoolSource) controllerVerification(e *Environment) (bool, error) {
	if err := s.checkPreparationOwner(e); err != nil {
		return false, err
	}
	pin, err := s.capturePreparation(e.reservation)
	if err != nil {
		return false, err
	}
	defer pin.release()
	return e.checkPreparationLease(pin)
}

func (s *PreauthorizedPoolSource) checkPreparationOwner(e *Environment) error {
	if e == nil {
		return cryptov4.ErrConfiguration
	}
	if err := s.access(); err != nil {
		return err
	}
	s.mu.Lock()
	p, closed := s.pool, s.closed
	s.mu.Unlock()
	if p == nil || closed {
		return cryptov4.ErrClosed
	}
	p.mu.Lock()
	belongs := !p.closed && p.environment == e
	p.mu.Unlock()
	if !belongs {
		return cryptov4.ErrClosed
	}
	return nil
}

// The original attempt fixes one verification snapshot before waiting for
// freshness. Pool acquisition still validates the actual selected material;
// this pin supplies no claim, spend or replacement authority. Only ownership
// checks run here; the caller's access gate must run outside ownership locks.
func (s *PreauthorizedPoolSource) capturePreparation(environment resourcev4.Reference) (artifactLeaseUse, error) {
	s.mu.Lock()
	p, closed := s.pool, s.closed
	s.mu.Unlock()
	if closed || p == nil {
		return artifactLeaseUse{}, cryptov4.ErrClosed
	}
	p.mu.Lock()
	if p.closed || p.environment == nil {
		p.mu.Unlock()
		return artifactLeaseUse{}, cryptov4.ErrClosed
	}
	if err := p.reservation.CheckSameEnvironment(environment); err != nil {
		p.mu.Unlock()
		return artifactLeaseUse{}, err
	}
	var material *ConnectionMaterial
	for _, slot := range p.slots {
		if slot.ready && !slot.busy {
			material = slot.material
			break
		}
	}
	if material == nil {
		p.mu.Unlock()
		return artifactLeaseUse{}, poolError(protocolv4.V4TopUpErrorCodeSourceExhausted)
	}
	material.mu.Lock()
	if material.closed || material.cleaned {
		material.mu.Unlock()
		p.mu.Unlock()
		return artifactLeaseUse{}, cryptov4.ErrClosed
	}
	// The captured lease pins all signed credentials and their namespace graph.
	// Checks run outside pool/material locks and never invoke key providers.
	pin, err := material.lease.borrow(p.reservation)
	material.mu.Unlock()
	p.mu.Unlock()
	return pin, err
}

func (e *Environment) checkPreparationLease(pin artifactLeaseUse) (bool, error) {
	if pin.lease == nil {
		return false, resourcev4.ErrOwner
	}
	pending := false
	bindings := pin.lease.allCredentialBindings()
	credentials := pin.lease.allCredentials()
	if len(bindings) != len(credentials) {
		return false, resourcev4.ErrOwner
	}
	for i, binding := range bindings {
		if credentials[i] == nil && i >= 3 && (i-3)%2 == 0 {
			entry := &pin.lease.tunnels[(i-3)/2]
			if !entry.pendingGrant {
				return false, resourcev4.ErrOwner
			}
			e.mu.Lock()
			closed, registry := e.closed, e.verification
			e.mu.Unlock()
			if closed {
				return false, cryptov4.ErrClosed
			}
			if registry != nil {
				if err := registry.CheckNamespace(binding.Namespace); err != nil {
					return false, err
				}
			}
			wait, err := entry.liveGrant.CheckPreparation(pin.lease.session.SessionNotAfterMS, pin.ref)
			if err != nil {
				return false, err
			}
			pending = pending || wait
			continue
		}
		wait, err := e.checkPreparationCredential(binding, credentials[i], pin.ref)
		if err != nil {
			return false, err
		}
		pending = pending || wait
	}
	return pending, nil
}

func (e *Environment) checkPreparationCredential(binding protocolv4.CredentialValidation, credential *protocolv4.Credential, backing resourcev4.Reference) (bool, error) {
	e.mu.Lock()
	closed, registry := e.closed, e.verification
	e.mu.Unlock()
	if closed || credential == nil {
		return false, cryptov4.ErrClosed
	}
	if registry != nil {
		if err := registry.CheckNamespace(binding.Namespace); err != nil {
			return false, err
		}
	}
	return protocolv4.CheckMaterialPreparation(binding, credential, credential.Scope().ExpiresMS, backing)
}
