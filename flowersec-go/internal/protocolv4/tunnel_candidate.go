package protocolv4

// CheckTunnelCandidate validates the signed two-leg route before any carrier
// provider work.  Tunnel legs are checked as a pair; treating the route as a
// direct listener would silently discard the relay grant and permit a direct
// endpoint predicate to authorize the wrong physical role.
func (m *SignedMap) CheckTunnelCandidate(index uint64) error {
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
	tunnel, err := EnumValue("Candidate", "path_kind", "tunnel")
	if err != nil {
		return err
	}
	path, ok := candidate.Named("Candidate", "path_kind").Uint()
	if !ok || path != tunnel {
		return CBORFailure("tunnel_route_binding")
	}
	for _, name := range []string{"client_leg", "server_leg"} {
		leg := candidate.Named("Candidate", name)
		if len(leg.Encoded()) == 0 {
			return CBORFailure("tunnel_route_binding")
		}
		access, ok := leg.Named("Leg", "access_class").Uint()
		network, e := EnumValue("Leg", "access_class", "network")
		if e != nil || !ok || access != network {
			if e != nil {
				return e
			}
			return CBORFailure("tunnel_route_binding")
		}
		if _, ok := leg.Named("Leg", "carrier").Uint(); !ok {
			return CBORFailure("tunnel_route_binding")
		}
		for _, field := range []string{"endpoint_role", "dialer_role", "listener_role"} {
			if _, ok := leg.Named("Leg", field).Uint(); !ok {
				return CBORFailure("tunnel_route_binding")
			}
		}
	}
	clientID, ok := candidate.Named("Candidate", "client_leg").Named("Leg", "leg_id").ByteString()
	serverID, okServer := candidate.Named("Candidate", "server_leg").Named("Leg", "leg_id").ByteString()
	if !ok || !okServer || len(clientID) != 16 || len(serverID) != 16 || string(clientID) == string(serverID) {
		return CBORFailure("tunnel_route_binding")
	}
	return nil
}

// CheckCandidate applies the path-specific signed route predicate used by
// source preparation.  It keeps direct and relay admission rules separate.
func (m *SignedMap) CheckCandidate(index uint64) error {
	if m == nil {
		return CBORFailure("artifact_owner")
	}
	candidate := m.Field("candidates").Index(int(index))
	path, ok := candidate.Named("Candidate", "path_kind").Uint()
	if !ok {
		return CBORFailure("pool_index_membership")
	}
	direct, err := EnumValue("Candidate", "path_kind", "direct")
	if err != nil {
		return err
	}
	if path == direct {
		return m.CheckDirectListenerCandidate(index)
	}
	return m.CheckTunnelCandidate(index)
}
