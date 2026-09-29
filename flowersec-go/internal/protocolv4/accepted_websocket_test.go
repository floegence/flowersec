package protocolv4

import (
	"net/netip"
	"testing"
)

func TestAcceptedLocalWebSocketPreservesSignedIPFamily(t *testing.T) {
	seed := oracleSeed(t, "artifact_local_fields")
	artifact := signRuntimeFixture(t, "Artifact", oracleBytes(t, seed.Hex), DecodeContext{})
	leg := artifact.Field("candidates").Index(0).Named("Candidate", "direct_leg")
	get := func(name string) Value { return leg.Named("Leg", name) }
	host, _ := get("host").Text()
	path, _ := get("path").Text()
	subprotocol, _ := get("subprotocol").Text()
	origin, _ := get("origin").Text()
	port, _ := get("port").Uint()
	ip, err := netip.ParseAddr(host)
	if err != nil || !ip.Is4() {
		t.Fatal("fixture must exercise a signed IPv4 loopback", host, err)
	}
	registry, err := runtimeHello()
	if err != nil {
		t.Fatal(err)
	}
	endpoint := AcceptedWebSocketEndpoint{Host: host, Path: path, Subprotocol: subprotocol, Origin: origin, OriginPresent: true, Port: uint16(port), Local: netip.AddrPortFrom(ip, uint16(port)), Remote: netip.AddrPortFrom(ip, 32000)}
	policy := HelloPolicy{BindingMode: registry.authenticated}
	if err = artifact.CheckAcceptedWebSocket(0, endpoint, policy); err != nil {
		t.Fatal("exact signed endpoint rejected", err)
	}
	mapped := netip.AddrFrom16(ip.As16())
	if !mapped.Is4In6() {
		t.Fatal("fixture did not preserve mapped family")
	}
	endpoint.Local = netip.AddrPortFrom(mapped, uint16(port))
	if err = artifact.CheckAcceptedWebSocket(0, endpoint, policy); err == nil {
		t.Fatal("mapped local address substituted for signed IPv4")
	}
}
