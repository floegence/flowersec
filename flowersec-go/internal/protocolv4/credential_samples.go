package protocolv4

import "github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"

// One closure has at most five original namespace dependencies. Sample each
// distinct Environment clock outside ownership gates, then reuse that actual
// envelope for its current trust, credential, activation and deadline checks.
type credentialSamples [5]timev4.Sample

func sampleCredentialBindings(bindings []CredentialValidation) (samples credentialSamples, err error) {
	if len(bindings) == 0 || len(bindings) > len(samples) {
		return samples, CBORFailure("credential_validation_count")
	}
	for i, binding := range bindings {
		if binding.Namespace == nil || binding.Namespace.clock == nil {
			return samples, CBORFailure("credential_namespace_owner")
		}
		shared := false
		for j, previous := range bindings[:i] {
			if previous.Namespace.clock == binding.Namespace.clock {
				samples[i], shared = samples[j], true
				break
			}
		}
		if !shared {
			samples[i], err = binding.Namespace.sampleCurrent()
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
	if err := n.checkHeadTrustAt(head, sample); err != nil {
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
