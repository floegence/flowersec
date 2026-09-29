package protocolv4

import (
	"net/netip"
	"testing"
)

func TestAcceptedQUICBindsActualTLSAndSignedEndpoint(t *testing.T) {
	r := newCBORTextReference(t)
	seed := oracleSeed(t, "artifact_pool_sixteen_fields")
	root, _, err := r.decode(oracleBytes(t, seed.Hex), "Artifact", nil, 1<<16)
	if err != nil {
		t.Fatal(err)
	}
	// Keep all signed Artifact relationships; replace only the direct leg's
	// carrier tuple with the registered QUIC tuple before signing the fixture.
	candidate := oracleField(t, r.cborReference, "Artifact", root, "candidates").items[0]
	leg := oracleField(t, r.cborReference, "Candidate", candidate, "direct_leg")
	oracleField(t, r.cborReference, "Leg", leg, "carrier").n = 0
	oracleField(t, r.cborReference, "Leg", leg, "path").data = nil
	oracleField(t, r.cborReference, "Leg", leg, "subprotocol").data = nil
	oracleField(t, r.cborReference, "Leg", leg, "alpn").data = []byte("flowersec-direct/4")
	pairs := leg.pairs[:0]
	for _, pair := range leg.pairs {
		if pair[0].n != 12 { // Origin policy is forbidden for raw QUIC.
			pairs = append(pairs, pair)
		}
	}
	leg.pairs = pairs
	registry, err := runtimeHello()
	if err != nil {
		t.Fatal(err)
	}
	policy := HelloPolicy{BindingMode: registry.authenticated}
	for _, host := range []string{"example.com", "127.0.0.1"} {
		t.Run(host, func(t *testing.T) {
			oracleField(t, r.cborReference, "Leg", leg, "host").data = []byte(host)
			artifact := signRuntimeFixture(t, "Artifact", root.encode(nil), DecodeContext{})
			port := uint16(oracleField(t, r.cborReference, "Leg", leg, "port").n)
			endpoint := AcceptedQUICEndpoint{Local: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port),
				Remote: netip.MustParseAddrPort("127.0.0.1:32000"), ALPN: "flowersec-direct/4", TLS13: true}
			if host == "example.com" {
				endpoint.ServerName = host
			}
			if err := artifact.CheckAcceptedQUIC(0, endpoint, policy); err != nil {
				t.Fatal("exact native tuple rejected", err)
			}
			for _, mutation := range []string{"alpn", "port", "sni", "tls", "remote", "exporter", "family"} {
				changed, p := endpoint, policy
				switch mutation {
				case "alpn":
					changed.ALPN = "flowersec-tunnel/4"
				case "port":
					changed.Local = netip.AddrPortFrom(changed.Local.Addr(), port+1)
				case "sni":
					changed.ServerName = "other.example"
				case "tls":
					changed.TLS13 = false
				case "remote":
					changed.Remote = netip.AddrPort{}
				case "exporter":
					p.Exporter = []byte{1}
				case "family":
					if host != "127.0.0.1" {
						continue
					}
					changed.Local = netip.AddrPortFrom(netip.AddrFrom16(changed.Local.Addr().As16()), port)
				}
				if err := artifact.CheckAcceptedQUIC(0, changed, p); err == nil {
					t.Fatal("changed accepted endpoint was trusted", mutation)
				}
			}
		})
	}
}
