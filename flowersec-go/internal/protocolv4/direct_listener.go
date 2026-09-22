package protocolv4

// CheckDirectListenerCandidate excludes tunnel and reversed physical roles
// from a direct Acceptor. Endpoint, TLS, Origin and deployment validation still
// belong to the same accepted provider's independently configured policy.
func (m *SignedMap) CheckDirectListenerCandidate(index uint64) error {
	if m == nil || m.codec == nil {
		return CBORFailure("artifact_owner")
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
	candidate := candidates.Index(int(index))
	direct, err := EnumValue("Candidate", "path_kind", "direct")
	if err != nil {
		return err
	}
	path, ok := candidate.Named("Candidate", "path_kind").Uint()
	if !ok || path != direct {
		return CBORFailure("accepted_listener_binding")
	}
	leg := candidate.Named("Candidate", "direct_leg")
	for _, field := range []struct{ name, role string }{{"endpoint_role", "server"}, {"dialer_role", "client"}, {"listener_role", "server"}} {
		want, err := EnumValue("Leg", field.name, field.role)
		if err != nil {
			return err
		}
		got, ok := leg.Named("Leg", field.name).Uint()
		if !ok || got != want {
			return CBORFailure("accepted_listener_binding")
		}
	}
	return nil
}
