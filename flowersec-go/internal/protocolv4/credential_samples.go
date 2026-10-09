package protocolv4

import "github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"

// One closure has at most five original namespace dependencies. Sample each
// distinct Environment clock outside ownership gates, then reuse that actual
// envelope for its current trust, credential, activation and deadline checks.
type credentialSamples [5]timev4.Sample

// namespaceClosureRead exists only while a closure check retains n.mu. It locks
// the original State and concrete shared trust store in namespace -> State ->
// trust order. No check result survives this synchronous read. Custom trust
// adapters keep their existing independent read contract.
type namespaceClosureRead struct {
	namespace *LiveNamespace
	state     *NamespaceState
	store     *NamespaceTrustStore
}

func (n *LiveNamespace) lockClosureReadAt(sample timev4.Sample) (namespaceClosureRead, error) {
	read := namespaceClosureRead{namespace: n}
	store, concrete := n.trust.(*NamespaceTrustStore)
	if !concrete {
		return read, nil
	}
	state := n.active
	state.workspace.mu.Lock()
	if state.workspace.current != state || state.workspace.owner != n {
		state.workspace.mu.Unlock()
		return read, CBORFailure("revocation_state_owner")
	}
	if err := state.workspace.reservation.Check(); err != nil {
		state.workspace.mu.Unlock()
		return read, err
	}
	read.state = state
	store.mu.Lock()
	if err := store.checkCurrentLockedAt(sample); err != nil {
		store.mu.Unlock()
		state.workspace.mu.Unlock()
		return read, err
	}
	read.store = store
	return read, nil
}

func (r namespaceClosureRead) unlock() {
	if r.store != nil {
		r.store.mu.Unlock()
	}
	if r.state != nil {
		r.state.workspace.mu.Unlock()
	}
}

func (r namespaceClosureRead) credentialAt(credential *Credential, permission IssuerPermission, sample timev4.Sample) (CredentialStateFacts, error) {
	if r.state != nil {
		return r.state.checkCredentialContentsLocked(credential, sample.Interval, false)
	}
	return r.namespace.active.checkDetachedCredential(credential, permission, sample.Interval, false)
}

func (r namespaceClosureRead) checkActivationAt(a *ActivationAuthority, sample timev4.Sample) error {
	if r.state != nil {
		return r.state.checkActivationContentsLocked(a, sample.Interval)
	}
	return r.namespace.active.CheckActivation(a, sample.Interval)
}

func (r namespaceClosureRead) headAt(head *NamespaceHead, sample timev4.Sample) error {
	if r.store == nil {
		return r.namespace.checkHeadAt(head, sample)
	}
	binding, err := r.headTrustBinding(head)
	if err != nil {
		return err
	}
	if _, err = r.store.headCurrentLocked(binding, 0); err != nil {
		return err
	}
	return head.CheckTime(sample.Interval)
}

func (r namespaceClosureRead) headTrustAt(head *NamespaceHead, sample timev4.Sample) error {
	if r.store == nil {
		return r.namespace.checkHeadTrustAt(head, sample)
	}
	binding, err := r.headTrustBinding(head)
	if err != nil {
		return err
	}
	_, err = r.store.headCurrentLocked(binding, 0)
	return err
}

func (r namespaceClosureRead) headTrustBinding(head *NamespaceHead) (NamespaceHeadTrust, error) {
	n := r.namespace
	if head == nil || head.rules != n.rules || head.generation != n.observed.generation {
		return NamespaceHeadTrust{}, CBORFailure("revocation_namespace_binding")
	}
	return NamespaceHeadTrust{Tenant: n.rules.tenant, Authority: n.rules.authority, Capacity: n.rules.capacityDigest, Delegation: head.delegationDigest, Signer: head.signerID, Generation: head.generation, TrustIssuedMS: head.trustIssued, TrustNotAfterMS: head.trustEnd}, nil
}

func (r namespaceClosureRead) issuerAt(permission IssuerPermission, scope CredentialScope, sample timev4.Sample) error {
	if r.store != nil {
		return r.store.issuerCurrentLocked(permission, scope)
	}
	return r.namespace.checkIssuerAt(permission, scope, sample)
}

func (r namespaceClosureRead) policyAt(policy *CredentialPolicy, sample timev4.Sample) error {
	if r.store != nil {
		return r.store.policyCurrentLocked(policy)
	}
	return r.namespace.checkPolicyAt(policy, sample)
}

func (r namespaceClosureRead) activationAt(binding ActivationTrustBinding, sample timev4.Sample) error {
	if r.store != nil {
		return r.store.activationCurrentLocked(binding)
	}
	return r.namespace.checkActivationTrustAt(binding, sample)
}

func sampleCredentialBindings(bindings []CredentialValidation) (samples credentialSamples, err error) {
	return sampleCredentialBindingsAt(bindings, timev4.Sample{})
}

func sampleCredentialBindingsAt(bindings []CredentialValidation, adjacent timev4.Sample) (samples credentialSamples, err error) {
	if len(bindings) == 0 || len(bindings) > len(samples) {
		return samples, CBORFailure("credential_validation_count")
	}
	for i := range bindings {
		binding := &bindings[i]
		if binding.Namespace == nil || binding.Namespace.clock == nil {
			return samples, CBORFailure("credential_namespace_owner")
		}
		shared := false
		for j := 0; j < i; j++ {
			previous := &bindings[j]
			if previous.Namespace.clock == binding.Namespace.clock {
				samples[i], shared = samples[j], true
				break
			}
		}
		if !shared {
			if adjacent.BelongsTo(binding.Namespace.clock) {
				// Borrow only this synchronous gate's actual sample. Refresh
				// against current trust/continuity before any owner check.
				samples[i], err = binding.Namespace.clock.RefreshSample(adjacent)
			} else {
				samples[i], err = binding.Namespace.sampleCurrent()
			}
			if err != nil {
				return samples, err
			}
		}
	}
	return samples, nil
}

// Concrete shared trust stores consume the same validated envelope. Component
// trust adapters retain their existing contract of bounded local SDK reads.
func (n *LiveNamespace) checkHeadAtPending(head *NamespaceHead, sample timev4.Sample) (uint64, error) {
	var err error
	sample, err = n.clock.RefreshSample(sample)
	if err != nil {
		return 0, err
	}
	if head == nil || head.rules != n.rules || head.generation != n.observed.generation {
		return 0, CBORFailure("revocation_namespace_binding")
	}
	binding := NamespaceHeadTrust{Tenant: n.rules.tenant, Authority: n.rules.authority, Capacity: n.rules.capacityDigest, Delegation: head.delegationDigest, Signer: head.signerID, Generation: head.generation, TrustIssuedMS: head.trustIssued, TrustNotAfterMS: head.trustEnd}
	pending := uint64(0)
	if trust, ok := n.trust.(*NamespaceTrustStore); ok {
		pending, err = trust.headAtPending(binding, sample)
	} else {
		err = n.trust.Head(binding)
	}
	if err != nil {
		return 0, err
	}
	headPending, err := head.CheckTimePending(sample.Interval)
	if err != nil {
		return 0, err
	}
	return max(pending, headPending), nil
}

func (n *LiveNamespace) checkHeadAt(head *NamespaceHead, sample timev4.Sample) error {
	var err error
	sample, err = n.clock.RefreshSample(sample)
	if err != nil {
		return err
	}
	if err := n.checkHeadTrustCurrentAt(head, sample); err != nil {
		return err
	}
	return head.CheckTime(sample.Interval)
}

func (n *LiveNamespace) checkHeadTrustAt(head *NamespaceHead, sample timev4.Sample) error {
	if current, err := n.clock.RefreshSample(sample); err != nil {
		return err
	} else {
		sample = current
	}
	return n.checkHeadTrustCurrentAt(head, sample)
}

func (n *LiveNamespace) checkHeadTrustCurrentAt(head *NamespaceHead, sample timev4.Sample) error {
	if head == nil || head.rules != n.rules || head.generation != n.observed.generation {
		return CBORFailure("revocation_namespace_binding")
	}
	binding := NamespaceHeadTrust{Tenant: n.rules.tenant, Authority: n.rules.authority, Capacity: n.rules.capacityDigest, Delegation: head.delegationDigest, Signer: head.signerID, Generation: head.generation, TrustIssuedMS: head.trustIssued, TrustNotAfterMS: head.trustEnd}
	var err error
	if trust, ok := n.trust.(*NamespaceTrustStore); ok {
		err = trust.headAt(binding, sample)
	} else {
		err = n.trust.Head(binding)
	}
	if err != nil {
		return err
	}
	return nil
}

func (n *LiveNamespace) checkIssuerAt(permission IssuerPermission, scope CredentialScope, sample timev4.Sample) error {
	if trust, ok := n.trust.(*NamespaceTrustStore); ok {
		return trust.issuerAt(permission, scope, sample)
	}
	return n.trust.Issuer(permission, scope)
}

func (n *LiveNamespace) checkPolicyAt(policy *CredentialPolicy, sample timev4.Sample) error {
	if trust, ok := n.trust.(*NamespaceTrustStore); ok {
		return trust.policyAt(policy, sample)
	}
	return n.trust.Policy(policy)
}

func (n *LiveNamespace) checkActivationTrustAt(binding ActivationTrustBinding, sample timev4.Sample) error {
	if trust, ok := n.trust.(*NamespaceTrustStore); ok {
		return trust.activationAt(binding, sample)
	}
	return n.trust.Activation(binding)
}

func (n *LiveNamespace) checkStateHistoryAtPending(state *NamespaceState, sample timev4.Sample) (uint64, error) {
	if current, err := n.clock.RefreshSample(sample); err != nil {
		return 0, err
	} else {
		sample = current
	}
	if trust, ok := n.trust.(*NamespaceTrustStore); ok {
		return trust.stateHistoryAtPending(state, sample)
	}
	return 0, n.trust.StateHistory(state)
}

func (n *LiveNamespace) checkStateHistoryAt(state *NamespaceState, sample timev4.Sample) error {
	if current, err := n.clock.RefreshSample(sample); err != nil {
		return err
	} else {
		sample = current
	}
	if trust, ok := n.trust.(*NamespaceTrustStore); ok {
		return trust.stateHistoryAt(state, sample)
	}
	return n.trust.StateHistory(state)
}
