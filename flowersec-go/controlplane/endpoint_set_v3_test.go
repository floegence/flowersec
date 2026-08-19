package controlplane

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v3/internal/artifactv3"
)

func TestEndpointSetReportsTypedRedactedErrors(t *testing.T) {
	tests := []struct {
		name  string
		build func() error
		code  ControlPlaneErrorCode
		field string
	}{
		{"zero-endpoints", func() error { _, err := NewEndpointSet(); return err }, InvalidEndpointCount, "endpoints"},
		{"too-many-endpoints", func() error {
			configs := make([]EndpointConfig, 5)
			for index := range configs {
				configs[index] = caEndpoint(fmt.Sprintf("endpoint-%d", index), fmt.Sprintf("wss://edge-%d.example/flowersec/v3/direct", index))
			}
			_, err := NewEndpointSet(configs...)
			return err
		}, InvalidEndpointCount, "endpoints"},
		{"zero-policy", func() error {
			_, err := NewEndpointSet(EndpointConfig{ID: "edge", URL: "wss://edge.example/flowersec/v3/direct"})
			return err
		}, InvalidTLSPolicy, "endpoints[0].tls"},
		{"unknown-policy", func() error {
			_, err := NewEndpointSet(EndpointConfig{ID: "edge", URL: "wss://edge.example/flowersec/v3/direct", TLS: TLSPolicy{tag: 99}})
			return err
		}, InvalidTLSPolicy, "endpoints[0].tls"},
		{"plain-websocket", func() error {
			_, err := NewEndpointSet(caEndpoint("edge", "ws://127.0.0.1/flowersec/v3/direct"))
			return err
		}, InvalidEndpointURL, "endpoints[0].url"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.build()
			var typed *ControlPlaneError
			if !errors.As(err, &typed) || !errors.Is(err, ErrInvalidControlPlaneInput) {
				t.Fatalf("error = %#v, want typed control-plane error", err)
			}
			if typed.Code() != test.code || typed.FieldPath() != test.field || typed.Error() != "flowersec control-plane input is invalid" {
				t.Fatalf("error = code %q field %q text %q", typed.Code(), typed.FieldPath(), typed.Error())
			}
			if strings.Contains(fmt.Sprintf("%+v", err), "edge.example") {
				t.Fatal("typed error exposed endpoint URL")
			}
		})
	}
}

func TestPinPolicySortsCanonicalBase64URLAndRejectsInvalidPins(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	var lowRaw, highRaw [32]byte
	highRaw[0] = 0xf8
	policy, err := PinPolicy(
		CertificatePin{SHA256: lowRaw, NotAfter: now.Add(2 * time.Minute)},
		CertificatePin{SHA256: highRaw, NotAfter: now.Add(time.Minute)},
	)
	if err != nil {
		t.Fatal(err)
	}
	wire := toArtifactTLSPolicy(policy)
	if got, want := wire.Pins[0].ValueBase64URL, base64.RawURLEncoding.EncodeToString(highRaw[:]); got != want {
		t.Fatalf("first canonical pin = %q, want ASCII-first %q", got, want)
	}
	if bytes.Compare(lowRaw[:], highRaw[:]) >= 0 {
		t.Fatal("test pins do not establish reverse raw/ASCII ordering")
	}

	for _, test := range []struct {
		name string
		pins []CertificatePin
	}{
		{"empty", nil},
		{"duplicate", []CertificatePin{{SHA256: lowRaw, NotAfter: now}, {SHA256: lowRaw, NotAfter: now.Add(time.Second)}}},
		{"subsecond", []CertificatePin{{SHA256: lowRaw, NotAfter: now.Add(time.Nanosecond)}}},
		{"zero-time", []CertificatePin{{SHA256: lowRaw}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := PinPolicy(test.pins...)
			var typed *ControlPlaneError
			if !errors.As(err, &typed) || typed.Code() != InvalidPin {
				t.Fatalf("PinPolicy error = %#v, want invalid_pin", err)
			}
		})
	}
}

func TestIssuerRevalidatesActivePinsAtOneFixedIssuanceTime(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	var hash [32]byte
	hash[0] = 7
	policy, err := PinPolicy(CertificatePin{SHA256: hash, NotAfter: now})
	if err != nil {
		t.Fatal(err)
	}
	set, err := NewEndpointSet(EndpointConfig{
		ID: "pinned", URL: "wss://edge.example/flowersec/v3/direct", TLS: policy,
	})
	if err != nil {
		t.Fatal(err)
	}
	issuer := newIssuerForTest(bytes.NewReader(bytes.Repeat([]byte{9}, 128)), now)
	_, err = issuer.IssueDirect(DirectIssueOptions{
		Session:   SessionOptions{ChannelID: "channel", ExpiresAt: now.Add(time.Minute)},
		Endpoints: set, RendezvousGroupID: "group", ListenerAudience: "listener", UpstreamAddress: "127.0.0.1:9000",
	})
	var typed *ControlPlaneError
	if !errors.As(err, &typed) || typed.Code() != InvalidTLSPolicy || typed.FieldPath() != "endpoints[0].tls" {
		t.Fatalf("expired policy error = %#v", err)
	}

	policy, err = PinPolicy(CertificatePin{SHA256: hash, NotAfter: now.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	set, err = NewEndpointSet(EndpointConfig{ID: "pinned", URL: "wss://edge.example/flowersec/v3/direct", TLS: policy})
	if err != nil {
		t.Fatal(err)
	}
	issued, err := issuer.IssueDirect(DirectIssueOptions{
		Session:   SessionOptions{ChannelID: "channel", ExpiresAt: now.Add(time.Minute)},
		Endpoints: set, RendezvousGroupID: "group", ListenerAudience: "listener", UpstreamAddress: "127.0.0.1:9000",
	})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := artifactv3.DecodeArtifactJSON(bytes.NewReader(issued.ArtifactJSON()))
	if err != nil || artifact.Path.Candidates[0].TLS.Mode != artifactv3.TLSModePin {
		t.Fatalf("issued pin artifact = %#v, %v", artifact, err)
	}
}

func TestIssuerRejectsNormalizedDuplicateEndpointAcrossPolicies(t *testing.T) {
	var hash [32]byte
	hash[0] = 1
	pin, err := PinPolicy(CertificatePin{SHA256: hash, NotAfter: time.Unix(2_000_000_000, 0)})
	if err != nil {
		t.Fatal(err)
	}
	set, err := NewEndpointSet(
		caEndpoint("ca", "WSS://EXAMPLE.com:443/flowersec/v3/direct"),
		EndpointConfig{ID: "pin", URL: "wss://example.com/flowersec/v3/direct", TLS: pin},
	)
	if err != nil {
		t.Fatal(err)
	}
	_, err = newIssuerForTest(bytes.NewReader(bytes.Repeat([]byte{3}, 128)), time.Unix(1_900_000_000, 0)).IssueDirect(DirectIssueOptions{
		Session:   SessionOptions{ChannelID: "channel", ExpiresAt: time.Unix(1_900_000_060, 0)},
		Endpoints: set, RendezvousGroupID: "group", ListenerAudience: "listener", UpstreamAddress: "127.0.0.1:9000",
	})
	var typed *ControlPlaneError
	if !errors.As(err, &typed) || typed.Code() != DuplicateEndpoint || typed.FieldPath() != "endpoints[1]" {
		t.Fatalf("duplicate endpoint error = %#v", err)
	}
}
