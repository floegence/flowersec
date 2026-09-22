package protocolv4

import "github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"

// MatchOriginal compares the retained original Artifact, profile, attempt and
// complete selected route. The Artifact digest covers the original signed
// Session parameters; activation may cap its end earlier without changing them.
func (b *ActivationBinding) MatchOriginal(session ArtifactSessionParameters, attempt [16]byte, winner PoolMember) error {
	if b == nil || !session.Contract.Valid() || b.artifactDigest != session.ArtifactDigest || b.profile != session.Profile || b.attempt != attempt || b.winner != winner {
		return CBORFailure("activation_parent_binding")
	}
	return nil
}

// MatchOriginal keeps authority attached to its original immutable activation.
func (a *ActivationAuthority) MatchOriginal(session ArtifactSessionParameters, attempt [16]byte, winner PoolMember) error {
	if a == nil {
		return CBORFailure("activation_parent_binding")
	}
	return a.binding.MatchOriginal(session, attempt, winner)
}

// MatchBinding requires the exact original proof and all detached activation
// facts. Equal parent/attempt/winner values alone do not bind proof deadlines,
// keys, delegation or the selected source policy.
func (a *ActivationAuthority) MatchBinding(binding *ActivationBinding) error {
	if a == nil || a.binding == nil || binding == nil || *a.binding != *binding {
		return CBORFailure("admission_proof_binding")
	}
	return nil
}

// MatchProofBytes binds the exact canonical proof carried in the original FSB
// before publication. It does not replace independent signature/trust checks.
func (a *ActivationAuthority) MatchProofBytes(proof []byte) error {
	if a == nil || a.binding == nil {
		return CBORFailure("admission_proof_binding")
	}
	digest, err := fullMapDigest("activation_digest", "ActivationAuthorization", proof)
	if err != nil {
		return err
	}
	if digest != a.binding.proofDigest {
		return CBORFailure("admission_proof_binding")
	}
	return nil
}

// CheckPreparationFor performs the original pre-spend validation under the
// same subscription lock as the Environment identity check.
func (s *CredentialSubscriptions) CheckPreparationFor(environment resourcev4.Reference) (CredentialValidity, error) {
	if s == nil {
		return CredentialValidity{}, CBORFailure("credential_authorization_owner")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.used || s.closed || s.prepared || s.closure == nil {
		return CredentialValidity{}, CBORFailure("credential_authorization_owner")
	}
	if err := s.reservation.CheckSameEnvironment(environment); err != nil {
		return CredentialValidity{}, err
	}
	result, err := s.checkPreparationLocked()
	if err != nil {
		s.closeLocked()
	}
	return result, err
}

// CheckOriginalFor additionally binds preparation to the original endpoint
// role, complete candidate route, and parent credential facts. The parent's
// digest covers the full signed Session. This neither manufactures trust nor
// adds an attempt to a credential closure that does not retain one.
func (s *CredentialSubscriptions) CheckOriginalFor(environment resourcev4.Reference, session ArtifactSessionParameters, role Direction, winner PoolMember) (CredentialValidity, error) {
	if s == nil {
		return CredentialValidity{}, CBORFailure("credential_authorization_owner")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.prepared {
		return CredentialValidity{}, CBORFailure("credential_authorization_owner")
	}
	return s.checkOriginalLocked(environment, session, role, winner)
}

func (s *CredentialSubscriptions) checkOriginalLocked(environment resourcev4.Reference, session ArtifactSessionParameters, role Direction, winner PoolMember) (CredentialValidity, error) {
	if s.used || s.closed || s.closure == nil {
		return CredentialValidity{}, CBORFailure("credential_authorization_owner")
	}
	e := s.closure
	parent := e.credentials[0]
	if !session.Contract.Valid() || role > ServerToClient || e.role != role || e.selection != winner || parent == nil || parent.facts.Digest != session.ArtifactDigest || parent.scope.Profile != session.Profile {
		return CredentialValidity{}, CBORFailure("credential_activation_binding")
	}
	if err := s.reservation.CheckSameEnvironment(environment); err != nil {
		return CredentialValidity{}, err
	}
	result, err := s.checkPreparationLocked()
	if err == nil {
		sample, sampleErr := s.bindings[0].Namespace.clock.Sample()
		err = sampleErr
		if err == nil {
			err = parent.CheckAdmission(sample.Interval)
		}
	}
	if err != nil {
		s.closeLocked()
	}
	return result, err
}

// CredentialPreparation is the original subscription's exclusive pre-spend
// owner. Its address is checked; copied or manufactured values cannot activate
// or close another admission's subscriptions.
type CredentialPreparation struct{ subscriptions *CredentialSubscriptions }

// AdoptPreparation commits bounded local graph adoption while holding the
// subscription gate. adopt must not do I/O, call application code or reenter
// these subscriptions. Failure leaves the original subscription caller-owned;
// success detaches the caller's preparation and Close entry points.
func (s *CredentialSubscriptions) AdoptPreparation(environment resourcev4.Reference, session ArtifactSessionParameters, role Direction, winner PoolMember, adopt func() error) (*CredentialPreparation, error) {
	if s == nil || adopt == nil {
		return nil, CBORFailure("credential_authorization_owner")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.prepared {
		return nil, CBORFailure("credential_authorization_owner")
	}
	if _, err := s.checkOriginalLocked(environment, session, role, winner); err != nil {
		return nil, err
	}
	if err := adopt(); err != nil {
		return nil, err
	}
	s.prepared = true
	s.preparation.subscriptions = s
	return &s.preparation, nil
}

func (p *CredentialPreparation) CheckOriginalFor(environment resourcev4.Reference, session ArtifactSessionParameters, role Direction, winner PoolMember) (CredentialValidity, error) {
	if p == nil || p.subscriptions == nil {
		return CredentialValidity{}, CBORFailure("credential_authorization_owner")
	}
	s := p.subscriptions
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.prepared || p != &s.preparation {
		return CredentialValidity{}, CBORFailure("credential_authorization_owner")
	}
	return s.checkOriginalLocked(environment, session, role, winner)
}

func (p *CredentialPreparation) Authorize(activation *ActivationAuthority) (*EndpointAuthorization, error) {
	if p == nil || p.subscriptions == nil {
		return nil, CBORFailure("credential_authorization_owner")
	}
	return newEndpointAuthorization(p.subscriptions, activation, p)
}

func (p *CredentialPreparation) Close() {
	if p == nil || p.subscriptions == nil {
		return
	}
	s := p.subscriptions
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.prepared && p == &s.preparation && s.bound == nil {
		s.closeLocked()
	}
}
