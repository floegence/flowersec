package protocolv4

import "net/netip"

// AcceptedWebTransportEndpoint binds the original CONNECT, TLS and UDP tuple.
type AcceptedWebTransportEndpoint struct {
	Local, Remote                        netip.AddrPort
	ServerName, ALPN, Host, Path, Origin string
	TLS13, OriginPresent                 bool
}

// LegAllowsOrigin applies only the original signed allowlist. Missing policy
// permits native non-Origin requests; browser requests require explicit policy.
func LegAllowsOrigin(leg Value, origin string, present bool) bool {
	policy := leg.Named("Leg", "origin_policy")
	if policy.Encoded() == nil {
		return !present && origin == ""
	}
	if !present {
		allow, ok := policy.Named("OriginPolicy", "allow_absent").Bool()
		return origin == "" && ok && allow
	}
	if origin == "" {
		return false
	}
	origins := policy.Named("OriginPolicy", "origins")
	for i := range origins.Len() {
		value, ok := origins.Index(i).Text()
		if ok && value == origin {
			return true
		}
	}
	return false
}

func (m *SignedMap) CheckAcceptedWebTransport(index uint64, endpoint AcceptedWebTransportEndpoint, policy HelloPolicy) error {
	if err := m.CheckDirectListenerCandidate(index); err != nil {
		return err
	}
	registry, err := runtimeHello()
	if err != nil {
		return err
	}
	if !validAcceptedBinding(policy, registry, endpoint.TLS13) || !endpoint.TLS13 || endpoint.ALPN != "h3" ||
		!endpoint.Local.IsValid() || !endpoint.Remote.IsValid() || endpoint.Local.Port() == 0 || endpoint.Remote.Port() == 0 ||
		endpoint.Local.Addr().Zone() != "" || endpoint.Remote.Addr().Zone() != "" {
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
	access, _ := get("access_class").Uint()
	port, _ := get("port").Uint()
	alpn, _ := get("alpn").Text()
	host, _ := get("host").Text()
	path, _ := get("path").Text()
	subprotocol, _ := get("subprotocol").Text()
	if carrier != 2 || access != 0 || port != uint64(endpoint.Local.Port()) || alpn != endpoint.ALPN || host != endpoint.Host ||
		path != endpoint.Path || path != "/flowersec/webtransport/v4/direct" || subprotocol != "" || !LegAllowsOrigin(leg, endpoint.Origin, endpoint.OriginPresent) {
		return CBORFailure("accepted_listener_binding")
	}
	if address, parseErr := netip.ParseAddr(host); parseErr == nil {
		if address != endpoint.Local.Addr() || endpoint.ServerName != "" {
			return CBORFailure("accepted_listener_binding")
		}
	} else if host == "" || endpoint.ServerName != host {
		return CBORFailure("accepted_listener_binding")
	}
	return nil
}
