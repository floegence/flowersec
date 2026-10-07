package protocolv4

import (
	"strings"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// LiveGrantPreparation describes the future local Grant's independently
// configured issuer, namespace, policy and validity envelope. It contains no
// credential or signing capability. Its exact scope is checked again against
// the original TxB Grant before endpoint authorization becomes possible.
type LiveGrantPreparation struct {
	Scope      CredentialScope
	Validation CredentialValidation
}

func (p LiveGrantPreparation) valid() bool {
	s := p.Scope
	if s.Schema != "Grant" || s.Subject != "" || s.Profile != "" || s.Role != 5 && s.Role != 6 || s.ExpiresMS <= s.IssuedMS || s.CapacityDigest == ([32]byte{}) || s.Issuer == ([16]byte{}) || s.ParentIssuer == ([16]byte{}) || s.ParentCapacityDigest == ([32]byte{}) || s.Generation == 0 || s.ParentGeneration == 0 {
		return false
	}
	for _, text := range []string{s.Tenant, s.Authority, s.Audience, s.Service, s.ParentAuthority} {
		if len(text) == 0 || len(text) > 128 {
			return false
		}
	}
	return true
}

func (p LiveGrantPreparation) clone() *LiveGrantPreparation {
	for _, text := range []*string{&p.Scope.Schema, &p.Scope.Tenant, &p.Scope.Authority, &p.Scope.Audience, &p.Scope.Subject, &p.Scope.Profile, &p.Scope.Service, &p.Scope.ParentAuthority} {
		*text = strings.Clone(*text)
	}
	return &p
}

func (p LiveGrantPreparation) Check(hardEnd uint64, environment resourcev4.Reference) (uint64, error) {
	n := p.Validation.Namespace
	if !p.valid() || n == nil || p.Validation.Policy == nil {
		return 0, CBORFailure("credential_namespace_owner")
	}
	if err := n.reservation.CheckSameEnvironment(environment); err != nil {
		return 0, err
	}
	now, err := n.sampleCurrent()
	if err != nil {
		return 0, err
	}
	return p.checkAt(p.Validation, p.Validation.Policy.Requirements(), hardEnd, now)
}

// CheckPreparation suspends only for an SDK-proven freshness or lower-bound
// gap. It preserves this exact future scope and requests the already installed
// namespace worker. Adapter failures and known revocations remain failures.
func (p LiveGrantPreparation) CheckPreparation(hardEnd uint64, environment resourcev4.Reference) (bool, error) {
	n := p.Validation.Namespace
	if !p.valid() || n == nil || p.Validation.Policy == nil {
		return false, CBORFailure("credential_namespace_owner")
	}
	if err := n.reservation.CheckSameEnvironment(environment); err != nil {
		return false, err
	}
	now, err := n.sampleCurrent()
	if err != nil {
		return false, err
	}
	_, pending, err := p.checkScopeAt(p.Validation, p.Validation.Policy.Requirements(), hardEnd, now, true)
	return pending, err
}

func (p LiveGrantPreparation) checkAt(v CredentialValidation, requirement CredentialRequirements, end uint64, now timev4.Sample) (uint64, error) {
	deadline, _, err := p.checkScopeAt(v, requirement, end, now, false)
	return deadline, err
}

func (p LiveGrantPreparation) checkScopeAt(v CredentialValidation, requirement CredentialRequirements, end uint64, now timev4.Sample, allowPending bool) (deadline uint64, pending bool, err error) {
	scope, n := p.Scope, v.Namespace
	if !p.valid() || v != p.Validation || n == nil || v.Policy == nil || scope.Issuer != v.Issuer.Issuer || v.Issuer.Schema != "Grant" || v.Issuer.Key == ([32]byte{}) || scope.IssuedMS < v.Issuer.SigningStart || scope.IssuedMS >= v.Issuer.SigningEnd {
		return 0, false, CBORFailure("credential_grant_preparation")
	}
	n.mu.Lock()
	defer func() {
		refresh := n.refresh
		n.mu.Unlock()
		if pending && err == nil && refresh != nil {
			refresh.Request()
		}
	}()
	if err := n.checkAvailable(); err != nil {
		return 0, false, err
	}
	if current, err := n.clock.RefreshSample(now); err != nil {
		return 0, false, err
	} else {
		now = current
	}
	if err := n.continuityAvailable(); err != nil {
		return 0, false, err
	}
	if scope.Tenant != n.rules.tenant || scope.Authority != n.rules.authority || scope.CapacityDigest != n.rules.capacityDigest || scope.Generation != n.observed.generation {
		return 0, false, CBORFailure("credential_namespace_binding")
	}
	if scope.Cohort < n.observed.floors[1] {
		return 0, false, CBORFailure("revocation_floor_rejected")
	}
	if err := n.checkIssuerAt(v.Issuer, scope, now); err != nil {
		return 0, false, err
	}
	if err := n.checkPolicyAt(v.Policy, now); err != nil {
		return 0, false, err
	}
	if err := n.rules.CheckPublication(requirement); err != nil {
		return 0, false, err
	}
	state := n.active
	if state == nil {
		return 0, false, CBORFailure("revocation_state_owner")
	}
	// Independent trust callbacks precede temporal classification. A provider
	// returning a time sentinel cannot turn a failed trust lookup into a wait.
	if err := n.checkHeadTrustAt(state.head, now); err != nil {
		return 0, false, err
	}
	if err := func() error {
		w := state.workspace
		w.mu.Lock()
		defer w.mu.Unlock()
		if w.current != state {
			return CBORFailure("revocation_state_owner")
		}
		if err := w.reservation.Check(); err != nil {
			return err
		}
		cohort, err := state.cohort(1, scope.Cohort)
		if err != nil {
			return err
		}
		if scope.IssuedMS < cohort.start || scope.IssuedMS >= cohort.end || scope.ExpiresMS > cohort.impact {
			return CBORFailure("revocation_credential_impact")
		}
		if searchRevocation(state.document.Root().Named("RevocationState", "revoked_issuers"), "RevokedIssuerEntry", []string{"issuer_key_id"}, scope.Issuer[:]).valid() {
			return CBORFailure("revocation_issuer_rejected")
		}
		return nil
	}(); err != nil {
		return 0, false, err
	}
	end = min(end, scope.ExpiresMS)
	if !now.ValidBefore(end) {
		return 0, false, timev4.ErrExpired
	}
	if err := now.LowerBound(scope.IssuedMS, true); err != nil {
		if !allowPending || err != timev4.ErrPending {
			return 0, false, err
		}
		pending = true
	}
	deadline, err = state.head.Deadline(requirement.StalenessMS, requirement.SignerLifetimeMS, end, now.Interval)
	if err != nil {
		if !allowPending || err != timev4.ErrPending && err != timev4.ErrExpired {
			return 0, false, err
		}
		return 0, true, nil
	}
	return deadline, pending, nil
}

// BindLiveEndpointPreparation checks the signed candidate and all available
// local credentials. The missing Grant remains an explicit non-credential
// dependency; MatchActivation refuses this closure until it is completed.
func BindLiveEndpointPreparation(role Direction, artifact *SignedMap, index uint64, client, server, relay *SignedMap, grant LiveGrantPreparation) (*EndpointCredentials, error) {
	if !grant.valid() {
		return nil, CBORFailure("credential_grant_preparation")
	}
	return bindEndpointCredentials(role, artifact, index, client, server, nil, relay, nil, grant.clone())
}

// CompleteLiveGrant replaces only the missing local dependency on the original
// admission owner. All namespace slots and validation work were reserved before
// TxA; no new subscription or activation right is acquired here.
func (p *CredentialPreparation) CompleteLiveGrant(complete *EndpointCredentials) error {
	if p == nil || p.subscriptions == nil {
		return CBORFailure("credential_authorization_owner")
	}
	return p.subscriptions.completeLiveGrant(complete, p)
}

// CompleteLiveGrant also supports an original server recipient before its
// admission adoption. Once adopted, only CredentialPreparation may complete it.
func (s *CredentialSubscriptions) CompleteLiveGrant(complete *EndpointCredentials) error {
	return s.completeLiveGrant(complete, nil)
}

func (s *CredentialSubscriptions) completeLiveGrant(complete *EndpointCredentials, preparation *CredentialPreparation) error {
	if s == nil || complete == nil || complete.pendingGrant != nil {
		return CBORFailure("credential_authorization_owner")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.used || (s.prepared && preparation != &s.preparation || !s.prepared && preparation != nil) || s.sampling != 0 || s.closure == nil || s.closure.pendingGrant == nil {
		return CBORFailure("credential_authorization_owner")
	}
	original := s.closure
	if complete.count != 5 || !complete.tunnel || complete.role != original.role || complete.selection != original.selection || complete.credentials[3] == nil || complete.credentials[3].scope != original.pendingGrant.Scope || complete.credentials[3].key != s.bindings[3].Issuer.Key {
		return CBORFailure("credential_grant_preparation")
	}
	for _, i := range []int{0, 1, 2, 4} {
		if complete.credentials[i] == nil || *complete.credentials[i] != *original.credentials[i] {
			return CBORFailure("credential_grant_preparation")
		}
	}
	// Keep the sampling pin through external clock access and recheck identity
	// after reacquiring the original gate; Close may have won in the meantime.
	samples, err := s.sampleLocked()
	if err != nil {
		return err
	}
	if s.closed || s.used || s.closure != original || s.sampling != 0 || (s.prepared && preparation != &s.preparation || !s.prepared && preparation != nil) {
		return CBORFailure("credential_authorization_owner")
	}
	if _, err = complete.checkCurrentAt(s.bindings[:], s.hardEnd, samples); err != nil {
		return err
	}
	end := min(s.hardEnd, complete.hardEnd)
	if err = s.hard.TightenAt(end, samples[0]); err != nil {
		return err
	}
	// Result floors were reserved against this exact pending closure before
	// TxA. Retain its identity only after verifying the original Grant above;
	// delivery still checks the completed signed closure and original deadline.
	s.deliveryOrigin = original
	s.closure, s.hardEnd = complete, end
	return nil
}
