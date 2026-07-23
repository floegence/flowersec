package endpointsetv2

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/session"
)

var testNow = time.Unix(2_000_000_000, 0)

func TestEndpointSetStrictJSONRoundTrip(t *testing.T) {
	set := validEndpointSet()
	raw, err := MarshalJSON(set, testNow)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeJSON(bytes.NewReader(raw), testNow)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Version != 2 || decoded.Profile != Profile || len(decoded.Listeners) != 3 {
		t.Fatalf("unexpected decoded endpoint set: %+v", decoded)
	}

	for _, mutation := range []struct {
		name string
		old  string
		new  string
	}{
		{name: "unknown field", old: `"v":2`, new: `"v":2,"tenant_id":"tenant-1"`},
		{name: "duplicate field", old: `"profile":"flowersec-tunnel-endpoint-set/2"`, new: `"profile":"flowersec-tunnel-endpoint-set/2","profile":"flowersec-tunnel-endpoint-set/2"`},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			changed := bytes.Replace(raw, []byte(mutation.old), []byte(mutation.new), 1)
			if _, err := DecodeJSON(bytes.NewReader(changed), testNow); err == nil {
				t.Fatalf("DecodeJSON accepted %s", changed)
			}
		})
	}
}

func TestEndpointSetRejectsInvalidTuples(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*EndpointSet)
	}{
		{name: "duplicate", mutate: func(s *EndpointSet) { s.Listeners[1] = s.Listeners[0] }},
		{name: "noncanonical order", mutate: func(s *EndpointSet) { s.Listeners[0], s.Listeners[1] = s.Listeners[1], s.Listeners[0] }},
		{name: "cross path", mutate: func(s *EndpointSet) { s.Listeners[1].Path = carrier.PathDirect }},
		{name: "cross path profile", mutate: func(s *EndpointSet) { s.Listeners[1].WireProfile = "flowersec-direct/2" }},
		{name: "cross path url", mutate: func(s *EndpointSet) { s.Listeners[1].URL = "wss://tunnel.example/flowersec/v2/direct" }},
		{name: "noncanonical url", mutate: func(s *EndpointSet) { s.Listeners[1].URL = "WSS://TUNNEL.example:443/flowersec/v2/tunnel" }},
		{name: "dial with bind", mutate: func(s *EndpointSet) { s.Listeners[1].BindEndpoint = "tcp://0.0.0.0:443" }},
		{name: "listen with dial url", mutate: func(s *EndpointSet) { s.Listeners[0].URL = "quic://tunnel.example:443" }},
		{name: "listen missing advertised url", mutate: func(s *EndpointSet) { s.Listeners[0].AdvertisedURL = "" }},
		{name: "listen cross path advertised url", mutate: func(s *EndpointSet) { s.Listeners[0].AdvertisedURL = "quic://tunnel.example:443/flowersec/v2/direct" }},
		{name: "wrong bind scheme", mutate: func(s *EndpointSet) { s.Listeners[0].BindEndpoint = "tcp://0.0.0.0:443" }},
		{name: "invalid listen role", mutate: func(s *EndpointSet) { s.Listeners[0].SessionRole = "relay" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			set := validEndpointSet()
			tt.mutate(&set)
			if err := Validate(set, testNow); !errors.Is(err, ErrInvalidEndpointSet) {
				t.Fatalf("Validate error = %v, want ErrInvalidEndpointSet", err)
			}
		})
	}
}

func TestEndpointSetUsesUDPForQUICNativeListeners(t *testing.T) {
	for _, testCase := range []struct {
		name         string
		carrier      carrier.Kind
		advertised   string
		bindEndpoint string
	}{
		{name: "raw QUIC", carrier: carrier.KindQUIC, advertised: "quic://tunnel.example", bindEndpoint: "udp://0.0.0.0:443"},
		{name: "WebTransport", carrier: carrier.KindWebTransport, advertised: "https://tunnel.example/flowersec/webtransport/v2/tunnel", bindEndpoint: "udp://0.0.0.0:443"},
		{name: "WebSocket", carrier: carrier.KindWebSocket, advertised: "wss://tunnel.example/flowersec/v2/tunnel", bindEndpoint: "tcp://0.0.0.0:443"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			set := validEndpointSet()
			set.Listeners = []ListenerTuple{{
				Carrier: testCase.carrier, NetworkMode: session.NetworkListen,
				Path: carrier.PathTunnel, SessionRole: session.RoleServer,
				AdvertisedURL: testCase.advertised, BindEndpoint: testCase.bindEndpoint,
				WireProfile: TunnelWireProfile,
			}}
			if err := Validate(set, testNow); err != nil {
				t.Fatalf("Validate: %v", err)
			}
		})
	}

	set := validEndpointSet()
	set.Listeners = []ListenerTuple{{
		Carrier: carrier.KindWebTransport, NetworkMode: session.NetworkListen,
		Path: carrier.PathTunnel, SessionRole: session.RoleServer,
		AdvertisedURL: "https://tunnel.example/flowersec/webtransport/v2/tunnel",
		BindEndpoint:  "tcp://0.0.0.0:443", WireProfile: TunnelWireProfile,
	}}
	if err := Validate(set, testNow); !errors.Is(err, ErrInvalidEndpointSet) {
		t.Fatalf("Validate accepted TCP WebTransport bind: %v", err)
	}
}

func TestEndpointSetCompatibleListenersFailsClosedOnEmptyIntersection(t *testing.T) {
	set := validEndpointSet()
	compatible, err := CompatibleListeners(set, testNow, session.GoCapabilities())
	if err != nil {
		t.Fatal(err)
	}
	if len(compatible) != len(set.Listeners) {
		t.Fatalf("compatible listeners = %d, want %d", len(compatible), len(set.Listeners))
	}

	noMatch := session.CapabilityDescriptor{
		Language: "test", Runtime: "minimal", SchemaVersion: 2,
		Tuples: []session.CapabilityTuple{{
			Carrier: carrier.KindWebSocket, NetworkMode: session.NetworkDial,
			Path: session.PathDirect, SessionRole: session.RoleClient,
		}},
		Unsupported: []session.UnsupportedCapability{
			{Carrier: carrier.KindQUIC, Reason: "not_supported"},
			{Carrier: carrier.KindWebTransport, Reason: "not_supported"},
		},
	}
	if _, err := CompatibleListeners(set, testNow, noMatch); !errors.Is(err, ErrNoCompatibleListener) {
		t.Fatalf("empty intersection error = %v, want ErrNoCompatibleListener", err)
	}
}

func TestEndpointSetListenTuplesPreserveAcceptedSessionRole(t *testing.T) {
	set := validEndpointSet()
	set.Listeners = []ListenerTuple{
		{
			Carrier: carrier.KindQUIC, NetworkMode: session.NetworkListen,
			Path: carrier.PathTunnel, SessionRole: session.RoleClient,
			AdvertisedURL: "quic://tunnel.example", BindEndpoint: "udp://0.0.0.0:443",
			WireProfile: TunnelWireProfile,
		},
		{
			Carrier: carrier.KindQUIC, NetworkMode: session.NetworkListen,
			Path: carrier.PathTunnel, SessionRole: session.RoleServer,
			AdvertisedURL: "quic://tunnel.example", BindEndpoint: "udp://0.0.0.0:443",
			WireProfile: TunnelWireProfile,
		},
	}
	if err := Validate(set, testNow); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	for _, role := range []session.SessionRole{session.RoleClient, session.RoleServer} {
		requester := session.CapabilityDescriptor{
			Language: "test", Runtime: "role_only", SchemaVersion: 2,
			Tuples: []session.CapabilityTuple{{
				Carrier: carrier.KindQUIC, NetworkMode: session.NetworkDial,
				Path: session.PathTunnel, SessionRole: role,
			}},
			Unsupported: []session.UnsupportedCapability{
				{Carrier: carrier.KindWebSocket, Reason: "not_supported"},
				{Carrier: carrier.KindWebTransport, Reason: "not_supported"},
			},
		}
		compatible, err := CompatibleListeners(set, testNow, requester)
		if err != nil {
			t.Fatalf("CompatibleListeners(%s): %v", role, err)
		}
		if len(compatible) != 1 || compatible[0].SessionRole != role {
			t.Fatalf("CompatibleListeners(%s) = %+v, want exactly that accepted role", role, compatible)
		}
	}
}

func TestEndpointSetRejectsStaleOrUnreadyRegistration(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*EndpointSet)
	}{
		{name: "expired", mutate: func(s *EndpointSet) { s.Freshness.ExpiresAtUnixSeconds = testNow.Unix() }},
		{name: "issued in future", mutate: func(s *EndpointSet) { s.Freshness.IssuedAtUnixSeconds = testNow.Unix() + 1 }},
		{name: "stale", mutate: func(s *EndpointSet) { s.Freshness.IssuedAtUnixSeconds = testNow.Unix() - 301 }},
		{name: "certificate not ready", mutate: func(s *EndpointSet) { s.Certificate.Ready = false }},
		{name: "certificate expires first", mutate: func(s *EndpointSet) { s.Certificate.NotAfterUnixSeconds = s.Freshness.ExpiresAtUnixSeconds - 1 }},
		{name: "missing verified server name", mutate: func(s *EndpointSet) { s.Certificate.VerifiedServerNames = []string{"other.example"} }},
		{name: "audience not ready", mutate: func(s *EndpointSet) { s.Audience.Ready = false }},
		{name: "invalid audience", mutate: func(s *EndpointSet) { s.Audience.ListenerAudience = "" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			set := validEndpointSet()
			tt.mutate(&set)
			if err := Validate(set, testNow); !errors.Is(err, ErrInvalidEndpointSet) {
				t.Fatalf("Validate error = %v, want ErrInvalidEndpointSet", err)
			}
		})
	}
}

func validEndpointSet() EndpointSet {
	return EndpointSet{
		Version:            2,
		Profile:            Profile,
		RendezvousGroupID:  "group-1",
		EndpointInstanceID: "tunnel-1",
		Listeners: []ListenerTuple{
			{Carrier: carrier.KindQUIC, NetworkMode: session.NetworkListen, Path: carrier.PathTunnel, SessionRole: session.RoleServer, AdvertisedURL: "quic://tunnel.example", BindEndpoint: "udp://0.0.0.0:443", WireProfile: TunnelWireProfile},
			{Carrier: carrier.KindWebSocket, NetworkMode: session.NetworkDial, Path: carrier.PathTunnel, SessionRole: session.RoleClient, URL: "wss://tunnel.example/flowersec/v2/tunnel", WireProfile: TunnelWireProfile},
			{Carrier: carrier.KindWebTransport, NetworkMode: session.NetworkDial, Path: carrier.PathTunnel, SessionRole: session.RoleServer, URL: "https://tunnel.example/flowersec/webtransport/v2/tunnel", WireProfile: TunnelWireProfile},
		},
		Certificate: CertificateReadiness{Ready: true, NotAfterUnixSeconds: testNow.Unix() + 7200, VerifiedServerNames: []string{"tunnel.example"}},
		Audience:    AudienceReadiness{Ready: true, ListenerAudience: "listener-1"},
		Freshness:   Freshness{IssuedAtUnixSeconds: testNow.Unix() - 60, ExpiresAtUnixSeconds: testNow.Unix() + 3600},
	}
}
