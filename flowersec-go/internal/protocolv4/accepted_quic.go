package protocolv4

import "net/netip"

// AcceptedQUICEndpoint contains actual TLS and UDP observations. The original
// listener must additionally check its immutable route and local certificate
// policy; this value does not provide those authorities by itself.
type AcceptedQUICEndpoint struct {
	Local, Remote    netip.AddrPort
	ServerName, ALPN string
	TLS13            bool
}

// CheckAcceptedQUIC binds one direct native entrance to its signed candidate.
// The original provider must separately derive any direct exporter. Matching
// this structural policy alone never establishes its connection authority.
func (m *SignedMap) CheckAcceptedQUIC(index uint64, endpoint AcceptedQUICEndpoint, policy HelloPolicy) error {
	if err := m.CheckDirectListenerCandidate(index); err != nil {
		return err
	}
	registry, err := runtimeHello()
	if err != nil {
		return err
	}
	quic, err := EnumValue("Leg", "carrier", "raw_quic")
	if err != nil {
		return err
	}
	network, err := EnumValue("Leg", "access_class", "network")
	if err != nil {
		return err
	}
	if !validAcceptedBinding(policy, registry, endpoint.TLS13) || !endpoint.TLS13 ||
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
	if carrier != quic || access != network || port != uint64(endpoint.Local.Port()) || alpn != endpoint.ALPN ||
		path != "" || subprotocol != "" || get("origin_policy").Encoded() != nil {
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
