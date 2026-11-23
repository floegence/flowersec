package protocolv4

import "net/netip"

// AcceptedWebSocketEndpoint contains immutable observations from the original
// HTTP upgrade. TLS13 means the actual connection completed TLS 1.3. The
// independently trusted deployment still checks the signed TLS policy, pins,
// application authentication and its supported consumer capability.
type AcceptedWebSocketEndpoint struct {
	Host, Path, Subprotocol, Origin string
	Port                            uint16
	OriginPresent, TLS13            bool
	Local, Remote                   netip.AddrPort
}

// CheckAcceptedWebSocket matches the actual observed entrance to the signed
// direct leg. This structural/carrier check is not TLS/pin or host-instance
// qualification. A provider must additionally run its original trusted policy.
func (m *SignedMap) CheckAcceptedWebSocket(index uint64, endpoint AcceptedWebSocketEndpoint, policy HelloPolicy) error {
	if err := m.CheckDirectListenerCandidate(index); err != nil {
		return err
	}
	registry, err := runtimeHello()
	if err != nil {
		return err
	}
	if policy.BindingMode != registry.authenticated || len(policy.Exporter) != 0 {
		return CBORFailure("accepted_listener_binding")
	}
	c := m.codec
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.current != m {
		return CBORFailure("artifact_owner")
	}
	leg := m.document.Root().Named("Artifact", "candidates").Index(int(index)).Named("Candidate", "direct_leg")
	get := func(name string) Value { return leg.Named("Leg", name) }
	carrier, _ := get("carrier").Uint()
	port, _ := get("port").Uint()
	if carrier != registry.websocket || port != uint64(endpoint.Port) {
		return CBORFailure("accepted_listener_binding")
	}
	for _, pair := range []struct{ name, want string }{{"host", endpoint.Host}, {"path", endpoint.Path}, {"subprotocol", endpoint.Subprotocol}} {
		actual, ok := get(pair.name).Text()
		if !ok || actual != pair.want {
			return CBORFailure("accepted_listener_binding")
		}
	}
	access, _ := get("access_class").Uint()
	network, err := EnumValue("Leg", "access_class", "network")
	if err != nil {
		return err
	}
	if access == network {
		if !endpoint.TLS13 {
			return CBORFailure("accepted_listener_binding")
		}
		originPolicy := get("origin_policy")
		// A absent policy permits only native non-Origin input. Browser input
		// always requires an explicit signed allowlist.
		if len(originPolicy.Encoded()) == 0 {
			if endpoint.OriginPresent {
				return CBORFailure("accepted_listener_binding")
			}
		} else if !endpoint.OriginPresent {
			allow, ok := originPolicy.Named("OriginPolicy", "allow_absent").Bool()
			if !ok || !allow {
				return CBORFailure("accepted_listener_binding")
			}
		} else {
			origins := originPolicy.Named("OriginPolicy", "origins")
			found := false
			for i := 0; i < origins.Len(); i++ {
				value, _ := origins.Index(i).Text()
				found = found || value == endpoint.Origin
			}
			if !found {
				return CBORFailure("accepted_listener_binding")
			}
		}
	} else {
		local, err := EnumValue("Leg", "access_class", "local_loopback")
		if err != nil {
			return err
		}
		host, err := netip.ParseAddr(endpoint.Host)
		origin, ok := get("origin").Text()
		if access != local || err != nil || !host.IsLoopback() || endpoint.TLS13 || !endpoint.Local.IsValid() || !endpoint.Remote.IsValid() || !endpoint.Local.Addr().IsLoopback() || !endpoint.Remote.Addr().IsLoopback() || endpoint.Local.Addr().Unmap() != host.Unmap() || endpoint.Local.Port() != endpoint.Port || !ok || !endpoint.OriginPresent || endpoint.Origin != origin {
			return CBORFailure("accepted_listener_binding")
		}
	}
	return nil
}
