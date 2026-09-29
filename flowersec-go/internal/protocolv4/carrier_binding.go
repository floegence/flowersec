package protocolv4

import "crypto/subtle"

func validAcceptedBinding(policy HelloPolicy, registry *helloRegistry, tls13 bool) bool {
	return policy.BindingMode == registry.authenticated && len(policy.Exporter) == 0 ||
		tls13 && policy.BindingMode == registry.exporter && len(policy.Exporter) == 32
}

// CheckCarrierExporter compares a policy with the actual original provider
// derivation. It grants no authority to values supplied by material lookup.
func CheckCarrierExporter(policy HelloPolicy, actual [32]byte) error {
	r, err := runtimeHello()
	if err != nil {
		return err
	}
	if policy.BindingMode != r.exporter || len(policy.Exporter) != len(actual) || subtle.ConstantTimeCompare(policy.Exporter, actual[:]) != 1 {
		return CBORFailure("carrier_binding_invalid")
	}
	return nil
}

// CheckBindingMode rejects an impossible selection before the consumer spends
// a credential. Native capability and actual exporter derivation are separate
// checks owned by the prepared carrier, never inferred from this signed route.
func (m *SignedMap) CheckBindingMode(index, mode uint64) error {
	if m == nil || m.codec == nil {
		return CBORFailure("artifact_owner")
	}
	r, err := runtimeHello()
	if err != nil {
		return err
	}
	c := m.codec
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.current != m || c.schema != "Artifact" {
		return CBORFailure("artifact_owner")
	}
	candidates := m.document.Root().Named("Artifact", "candidates")
	if index >= uint64(candidates.Len()) {
		return CBORFailure("pool_index_membership")
	}
	if mode == r.authenticated {
		return nil
	}
	candidate := candidates.Index(int(index))
	path, _ := candidate.Named("Candidate", "path_kind").Uint()
	access, ok := candidate.Named("Candidate", "direct_leg").Named("Leg", "access_class").Uint()
	if mode != r.exporter || path != r.direct || !ok || access != 0 {
		return CBORFailure("hello_binding_selection")
	}
	return nil
}
