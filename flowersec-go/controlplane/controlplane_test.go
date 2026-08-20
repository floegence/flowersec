package controlplane

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v3/internal/artifactv3"
)

func TestIssuerCreatesOpaqueDirectArtifactAndBoundRuntimeAuthorization(t *testing.T) {
	issuer := newIssuerForTest(bytes.NewReader(bytes.Repeat([]byte{0x42}, 128)), time.Unix(1_800_000_000, 0))
	endpoints, err := NewEndpointSet(
		caEndpoint("websocket", "wss://edge.example/flowersec/v3/direct"),
		caEndpoint("raw-quic", "quic://edge.example"),
		caEndpoint("webtransport", "https://edge.example/flowersec/webtransport/v3/direct"),
	)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := issuer.IssueDirect(DirectIssueOptions{
		Session:   SessionOptions{ChannelID: "channel-direct", ExpiresAt: time.Unix(1_800_000_060, 0)},
		Endpoints: endpoints, RendezvousGroupID: "group-direct", ListenerAudience: "audience-direct",
		UpstreamAddress: "127.0.0.1:9000",
		Metadata: ArtifactMetadata{
			Scopes:          []Scope{{Name: "redeven.proxy", Version: 1, Critical: true, Payload: json.RawMessage(`{"mode":"service_worker"}`)}},
			CorrelationTags: map[string]string{"trace": "trace-123"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := artifactv3.DecodeArtifactJSON(bytes.NewReader(issued.ArtifactJSON())); err != nil {
		t.Fatalf("public artifact parse failed: %v", err)
	}
	encodedRecord, err := issued.AuthorizationRecord().Encode()
	if err != nil {
		t.Fatal(err)
	}
	record, err := ParseAuthorizationRecord(encodedRecord)
	if err != nil {
		t.Fatal(err)
	}

	request := runtimeRequestForCandidate(t, record, "websocket")
	if request.LookupKey() != issued.LookupKey() {
		t.Fatalf("request lookup key = %q, want issued key %q", request.LookupKey(), issued.LookupKey())
	}
	response, err := AuthorizeRuntime(request, record, "lease-direct")
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err := json.Unmarshal(response.JSON(), &wire); err != nil {
		t.Fatal(err)
	}
	if wire["decision"] != "allow" || wire["credential_id"] != issued.LookupKey() || wire["lease_id"] != "lease-direct" {
		t.Fatalf("unexpected authorization response: %#v", wire)
	}
	if _, present := wire["artifact"]; present || strings.Contains(string(response.JSON()), "e2ee_psk_b64u") {
		t.Fatalf("authorization response leaked artifact fields: %s", response.JSON())
	}
}

func TestRuntimeAuthorizationReturnsExactRetryAtArtifactExpiry(t *testing.T) {
	issuedAt := time.Unix(1_800_000_000, 0).UTC()
	expiresAt := issuedAt.Add(time.Minute)
	issuer := newIssuerForTest(bytes.NewReader(bytes.Repeat([]byte{0x5a}, 512)), issuedAt)
	directEndpoints, err := NewEndpointSet(caEndpoint("websocket", "wss://edge.example/flowersec/v3/direct"))
	if err != nil {
		t.Fatal(err)
	}
	direct, err := issuer.IssueDirect(DirectIssueOptions{
		Session: SessionOptions{ChannelID: "expired-direct", ExpiresAt: expiresAt}, Endpoints: directEndpoints,
		RendezvousGroupID: "expired-direct-group", ListenerAudience: "expired-direct-audience",
		UpstreamAddress: "127.0.0.1:9000",
	})
	if err != nil {
		t.Fatal(err)
	}
	tunnelEndpoints, err := NewEndpointSet(caEndpoint("websocket", "wss://edge.example/flowersec/v3/tunnel"))
	if err != nil {
		t.Fatal(err)
	}
	pair, err := issuer.IssueTunnelPair(TunnelIssueOptions{
		Session: SessionOptions{ChannelID: "expired-tunnel", ExpiresAt: expiresAt}, Endpoints: tunnelEndpoints,
		RendezvousGroupID: "expired-tunnel-group", ListenerAudience: "expired-tunnel-audience",
		FirstEndpointID: "expired-endpoint-a", SecondEndpointID: "expired-endpoint-b",
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name      string
		issued    IssuedArtifact
		want      string
		authorize func(RuntimeAuthorizationRequest, AuthorizationRecord) ([]byte, error)
	}{
		{
			name: "direct", issued: direct,
			want: `{"decision":"retry","reason":"expired_artifact","credential_id":"","lease_id":"","expires_at":"0001-01-01T00:00:00Z","direct":null}`,
			authorize: func(request RuntimeAuthorizationRequest, record AuthorizationRecord) ([]byte, error) {
				response, err := authorizeRuntimeAt(request, record, "lease-expired-direct", expiresAt)
				return response.JSON(), err
			},
		},
		{
			name: "tunnel", issued: pair.First,
			want: `{"decision":"retry","reason":"expired_artifact","credential_id":"","lease_id":"","expires_at":"0001-01-01T00:00:00Z","expected_peer_endpoint_instance_id":"","allow_replacement":false}`,
			authorize: func(request RuntimeAuthorizationRequest, record AuthorizationRecord) ([]byte, error) {
				response, err := authorizeTunnelRuntimeAt(request, record, "lease-expired-tunnel", expiresAt)
				return response.JSON(), err
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			encodedRecord, err := test.issued.AuthorizationRecord().Encode()
			if err != nil {
				t.Fatal(err)
			}
			record, err := ParseAuthorizationRecord(encodedRecord)
			if err != nil {
				t.Fatal(err)
			}
			requestBody := runtimeRequestBody(t, record, "websocket", "")
			request, err := ParseRuntimeAuthorizationRequest(requestBody)
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := test.authorize(request, record)
			if err != nil {
				t.Fatalf("expired artifact returned an input error: %v", err)
			}
			if string(encoded) != test.want {
				t.Fatalf("expired artifact response = %s, want %s", encoded, test.want)
			}
		})
	}
}

func TestProductionIssuerMatchesSharedAdmissionHashVector(t *testing.T) {
	var fixture struct {
		ArtifactJSON              string `json:"artifact_json"`
		ChosenCandidateID         string `json:"chosen_candidate_id"`
		FSB3Hex                   string `json:"fsb3_hex"`
		AdmissionBindingHex       string `json:"admission_binding_hex"`
		AcceptorAdmissionsHashHex string `json:"acceptor_admissions_hash_hex"`
	}
	raw, err := os.ReadFile("../../testdata/transport_v3/go_issuer_admission_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0).UTC()
	endpoints, err := NewEndpointSet(caEndpoint("issuer-ws", "wss://issuer.example/flowersec/v3/direct"))
	if err != nil {
		t.Fatal(err)
	}
	issued, err := newIssuerForTest(bytes.NewReader(bytes.Repeat([]byte{0x42}, 128)), now).IssueDirect(DirectIssueOptions{
		Session:   SessionOptions{ChannelID: "issuer-shared", ExpiresAt: now.Add(time.Minute)},
		Endpoints: endpoints, RendezvousGroupID: "issuer-group", ListenerAudience: "issuer-audience",
		UpstreamAddress: "127.0.0.1:9000",
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(issued.ArtifactJSON()) != fixture.ArtifactJSON {
		t.Fatal("Go production issuer artifact differs from shared fixture")
	}
	artifact, err := artifactv3.DecodeArtifactJSON(bytes.NewReader(issued.ArtifactJSON()))
	if err != nil {
		t.Fatal(err)
	}
	request, err := artifactv3.BuildRequest(*artifact, fixture.ChosenCandidateID)
	if err != nil {
		t.Fatal(err)
	}
	frame, err := artifactv3.MarshalRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	actualHex := hex.EncodeToString(frame)
	if actualHex != fixture.FSB3Hex {
		t.Fatalf("Go production FSB3 differs: got %d hex chars want %d", len(actualHex), len(fixture.FSB3Hex))
	}
	binding := artifactv3.AdmissionBinding(frame)
	if hex.EncodeToString(binding[:]) != fixture.AdmissionBindingHex {
		t.Fatal("Go admission binding differs from shared fixture")
	}
	acceptor, err := artifactv3.AcceptorAdmissionsHash([][]byte{frame})
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(acceptor[:]) != fixture.AcceptorAdmissionsHashHex {
		t.Fatal("Go acceptor admissions hash differs from shared fixture")
	}
}

func TestIssuerRoundsSubsecondExpiryUpToWireSecond(t *testing.T) {
	now := time.Unix(1_800_000_000, 500_000_000)
	issuer := newIssuerForTest(bytes.NewReader(bytes.Repeat([]byte{0x61}, 128)), now)
	endpoints, err := NewEndpointSet(caEndpoint("websocket", "wss://edge.example/flowersec/v3/direct"))
	if err != nil {
		t.Fatal(err)
	}
	issued, err := issuer.IssueDirect(DirectIssueOptions{
		Session:   SessionOptions{ChannelID: "subsecond", ExpiresAt: now.Add(100 * time.Millisecond)},
		Endpoints: endpoints, RendezvousGroupID: "group", ListenerAudience: "audience",
		UpstreamAddress: "127.0.0.1:9000",
	})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := artifactv3.DecodeArtifactJSON(bytes.NewReader(issued.ArtifactJSON()))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := artifact.Session.InitExpireAtUnixSeconds, now.Unix()+1; got != want {
		t.Fatalf("wire expiry = %d, want rounded-up second %d", got, want)
	}
}

func TestEndpointSetRejectsPlainWebSocketIncludingLoopback(t *testing.T) {
	for _, rawURL := range []string{
		"ws://127.0.0.1:23998/flowersec/v3/direct",
		"ws://edge.example:23998/flowersec/v3/direct",
	} {
		_, err := NewEndpointSet(caEndpoint("websocket", rawURL))
		var controlErr *ControlPlaneError
		if !errors.As(err, &controlErr) || controlErr.Code() != InvalidEndpointURL || controlErr.FieldPath() != "endpoints[0].url" {
			t.Fatalf("plain WebSocket error = %#v, want invalid_endpoint_url", err)
		}
	}
}

func TestControlPlaneBoundariesFailClosedAndRedactOpaqueValues(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	issuer := newIssuerForTest(bytes.NewReader(bytes.Repeat([]byte{0x31}, 128)), now)
	directEndpoints, err := NewEndpointSet(caEndpoint("websocket", "wss://edge.example/flowersec/v3/direct"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := issuer.IssueDirect(DirectIssueOptions{
		Session: SessionOptions{ChannelID: "expired", ExpiresAt: now}, Endpoints: directEndpoints,
		RendezvousGroupID: "group", ListenerAudience: "audience", UpstreamAddress: "127.0.0.1:9000",
	}); err == nil {
		t.Fatal("expired issuance unexpectedly succeeded")
	}
	if _, err := issuer.IssueDirect(DirectIssueOptions{
		Session: SessionOptions{ChannelID: "bad-upstream", ExpiresAt: now.Add(time.Minute)}, Endpoints: directEndpoints,
		RendezvousGroupID: "group", ListenerAudience: "audience", UpstreamAddress: "missing-port",
	}); err == nil {
		t.Fatal("invalid direct upstream unexpectedly succeeded")
	}

	issued, err := issuer.IssueDirect(DirectIssueOptions{
		Session: SessionOptions{ChannelID: "redacted", ExpiresAt: now.Add(time.Minute)}, Endpoints: directEndpoints,
		RendezvousGroupID: "group", ListenerAudience: "audience", UpstreamAddress: "127.0.0.1:9000",
	})
	if err != nil {
		t.Fatal(err)
	}
	record := issued.AuthorizationRecord()
	request := runtimeRequestForCandidate(t, record, "websocket")
	response, err := AuthorizeRuntime(request, record, "lease-redacted")
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]any{
		"issued": issued, "record": record, "request": request, "response": response,
	} {
		encoded, err := json.Marshal(value)
		if err != nil || string(encoded) != "{}" {
			t.Fatalf("%s generic JSON = %s, %v", name, encoded, err)
		}
		formatted := fmt.Sprintf("%+v", value)
		if strings.Contains(formatted, "edge.example") || strings.Contains(formatted, "127.0.0.1") || strings.Contains(formatted, "channel") {
			t.Fatalf("%s formatting leaked sensitive data: %s", name, formatted)
		}
	}

	encodedRecord, err := record.Encode()
	if err != nil {
		t.Fatal(err)
	}
	var recordWire map[string]any
	if err := json.Unmarshal(encodedRecord, &recordWire); err != nil {
		t.Fatal(err)
	}
	recordWire["lookup_key"] = strings.Repeat("a", 43)
	tampered, _ := json.Marshal(recordWire)
	if _, err := ParseAuthorizationRecord(tampered); err == nil {
		t.Fatal("tampered record lookup key unexpectedly succeeded")
	}

	requestBody := runtimeRequestBody(t, record, "websocket", "websocket")
	var requestWire map[string]any
	if err := json.Unmarshal(requestBody, &requestWire); err != nil {
		t.Fatal(err)
	}
	requestWire["unknown"] = true
	unknown, _ := json.Marshal(requestWire)
	if _, err := ParseRuntimeAuthorizationRequest(unknown); err == nil {
		t.Fatal("unknown runtime request field unexpectedly succeeded")
	}
	requestWire = map[string]any{}
	if err := json.Unmarshal(requestBody, &requestWire); err != nil {
		t.Fatal(err)
	}
	requestWire["carrier"] = "raw_quic"
	drifted, _ := json.Marshal(requestWire)
	if _, err := ParseRuntimeAuthorizationRequest(drifted); err == nil {
		t.Fatal("runtime carrier drift unexpectedly succeeded")
	}
}

func TestIssuerRedactsRandomSourceFailure(t *testing.T) {
	issuer := newIssuerForTest(errorReader{}, time.Unix(1_800_000_000, 0))
	endpoints, err := NewEndpointSet(caEndpoint("websocket", "wss://edge.example/flowersec/v3/direct"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = issuer.IssueDirect(DirectIssueOptions{
		Session:   SessionOptions{ChannelID: "channel", ExpiresAt: time.Unix(1_800_000_060, 0)},
		Endpoints: endpoints, RendezvousGroupID: "group", ListenerAudience: "audience",
		UpstreamAddress: "127.0.0.1:9000",
	})
	if !errors.Is(err, ErrIssuanceFailed) || err.Error() != ErrIssuanceFailed.Error() {
		t.Fatalf("random source error = %v, want stable redacted issuance failure", err)
	}
}

func TestIssuerRedactsClockAndProviderFailures(t *testing.T) {
	for _, test := range []struct {
		name   string
		issuer *Issuer
	}{
		{name: "missing clock", issuer: &Issuer{random: bytes.NewReader(make([]byte, 64))}},
		{name: "zero clock", issuer: &Issuer{
			random: bytes.NewReader(make([]byte, 64)),
			now:    func() time.Time { return time.Time{} },
		}},
		{name: "missing random provider", issuer: &Issuer{now: time.Now}},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := test.issuer.IssueDirect(DirectIssueOptions{})
			if !errors.Is(err, ErrIssuanceFailed) || errors.Is(err, ErrInvalidControlPlaneInput) ||
				err.Error() != ErrIssuanceFailed.Error() {
				t.Fatalf("provider failure = %v, want stable redacted issuance failure", err)
			}
		})
	}
}

func TestRejectRuntimeBuildsOnlyValidatedRejectAndRetryResponses(t *testing.T) {
	for _, test := range []struct {
		retryable bool
		decision  string
	}{{false, "reject"}, {true, "retry"}} {
		response, err := RejectRuntime("permission_denied", test.retryable)
		if err != nil {
			t.Fatal(err)
		}
		var wire map[string]any
		if err := json.Unmarshal(response.JSON(), &wire); err != nil {
			t.Fatal(err)
		}
		if wire["decision"] != test.decision || wire["reason"] != "permission_denied" {
			t.Fatalf("rejection response = %#v", wire)
		}
	}
	if _, err := RejectRuntime("Secret Detail", false); err == nil {
		t.Fatal("invalid rejection reason unexpectedly succeeded")
	}
	if _, err := RejectRuntime(artifactv3.ReasonExpiredArtifact, false); !errors.Is(err, ErrInvalidControlPlaneInput) {
		t.Fatalf("expired artifact reject error = %v, want invalid control-plane input", err)
	}
	if _, err := RejectTunnelRuntime(artifactv3.ReasonExpiredArtifact, false); !errors.Is(err, ErrInvalidControlPlaneInput) {
		t.Fatalf("expired tunnel artifact reject error = %v, want invalid control-plane input", err)
	}
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, errors.New("secret provider detail") }

func TestIssuerCreatesTunnelPairAndRejectsCrossRecordAuthorization(t *testing.T) {
	issuer := newIssuerForTest(bytes.NewReader(bytes.Repeat([]byte{0x24}, 256)), time.Unix(1_800_000_000, 0))
	endpoints, err := NewEndpointSet(
		caEndpoint("websocket", "wss://tunnel.example/flowersec/v3/tunnel"),
		caEndpoint("raw-quic", "quic://tunnel.example"),
		caEndpoint("webtransport", "https://tunnel.example/flowersec/webtransport/v3/tunnel"),
	)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := issuer.IssueTunnelPair(TunnelIssueOptions{
		Session:   SessionOptions{ChannelID: "channel-tunnel", ExpiresAt: time.Unix(1_800_000_060, 0)},
		Endpoints: endpoints, RendezvousGroupID: "group-tunnel", ListenerAudience: "audience-tunnel",
		FirstEndpointID: "endpoint-a", SecondEndpointID: "endpoint-b", AllowReplacement: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	firstRecord := pair.First.AuthorizationRecord()
	secondRecord := pair.Second.AuthorizationRecord()
	firstRequest := runtimeRequestForCandidate(t, firstRecord, "raw-quic")
	if _, err := AuthorizeRuntime(firstRequest, secondRecord, "lease-cross"); err == nil {
		t.Fatal("cross-record authorization unexpectedly succeeded")
	}
	if _, err := AuthorizeRuntime(firstRequest, firstRecord, "lease-first"); err == nil {
		t.Fatal("direct runtime authorization accepted a tunnel request")
	}
}

func TestTunnelRuntimeAuthorizationNeverContainsSessionSecrets(t *testing.T) {
	issuer := newIssuerForTest(bytes.NewReader(bytes.Repeat([]byte{0x25}, 256)), time.Unix(1_800_000_000, 0))
	endpoints, err := NewEndpointSet(caEndpoint("websocket", "wss://tunnel.example/flowersec/v3/tunnel"))
	if err != nil {
		t.Fatal(err)
	}
	pair, err := issuer.IssueTunnelPair(TunnelIssueOptions{
		Session:   SessionOptions{ChannelID: "opaque-relay", ExpiresAt: time.Unix(1_800_000_060, 0)},
		Endpoints: endpoints, RendezvousGroupID: "opaque-group", ListenerAudience: "opaque-audience",
		FirstEndpointID: "endpoint-a", SecondEndpointID: "endpoint-b",
	})
	if err != nil {
		t.Fatal(err)
	}
	record := pair.First.AuthorizationRecord()
	request := runtimeRequestForCandidate(t, record, "websocket")
	response, err := AuthorizeTunnelRuntime(request, record, "lease-opaque")
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err := json.Unmarshal(response.JSON(), &wire); err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"session", "direct", "e2ee_psk_base64url", "allowed_suites", "default_suite"} {
		if _, exists := wire[forbidden]; exists {
			t.Fatalf("tunnel runtime authorization exposes forbidden field %q", forbidden)
		}
		if bytes.Contains(response.JSON(), []byte(forbidden)) {
			t.Fatalf("tunnel runtime authorization contains forbidden token %q", forbidden)
		}
	}
}

func TestAllowTunnelRuntimeBuildsSecretFreeResponseAfterExternalAuthorization(t *testing.T) {
	issuer := newIssuerForTest(bytes.NewReader(bytes.Repeat([]byte{0x26}, 256)), time.Unix(1_800_000_000, 0))
	endpoints, err := NewEndpointSet(caEndpoint("websocket", "wss://tunnel.example/flowersec/v3/tunnel"))
	if err != nil {
		t.Fatal(err)
	}
	pair, err := issuer.IssueTunnelPair(TunnelIssueOptions{
		Session:   SessionOptions{ChannelID: "external-authorization", ExpiresAt: time.Unix(1_800_000_060, 0)},
		Endpoints: endpoints, RendezvousGroupID: "external-group", ListenerAudience: "external-audience",
		FirstEndpointID: "endpoint-a", SecondEndpointID: "endpoint-b", AllowReplacement: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := runtimeRequestForCandidate(t, pair.First.AuthorizationRecord(), "websocket")
	response, err := AllowTunnelRuntime(request, "lease-external", time.Now().Add(time.Minute), "endpoint-b", true)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err := json.Unmarshal(response.JSON(), &wire); err != nil {
		t.Fatal(err)
	}
	if wire["decision"] != "allow" || wire["credential_id"] != request.LookupKey() || wire["expected_peer_endpoint_instance_id"] != "endpoint-b" {
		t.Fatalf("unexpected tunnel authorization response: %#v", wire)
	}
	for _, forbidden := range []string{"session", "artifact", "psk", "secret"} {
		if bytes.Contains(bytes.ToLower(response.JSON()), []byte(forbidden)) {
			t.Fatalf("secret-free response contains forbidden token %q", forbidden)
		}
	}

	direct, err := issuer.IssueDirect(DirectIssueOptions{
		Session:   SessionOptions{ChannelID: "direct-external", ExpiresAt: time.Unix(1_800_000_060, 0)},
		Endpoints: endpoints, RendezvousGroupID: "direct-group", ListenerAudience: "direct-audience",
		UpstreamAddress: "127.0.0.1:9000",
	})
	if err == nil {
		directRequest := runtimeRequestForCandidate(t, direct.AuthorizationRecord(), "websocket")
		if _, allowErr := AllowTunnelRuntime(directRequest, "lease-direct", time.Now().Add(time.Minute), "endpoint-b", false); allowErr == nil {
			t.Fatal("secret-free tunnel allow accepted a direct request")
		}
	}
	if _, err := AllowTunnelRuntime(request, "lease-external", time.Now().Add(-time.Second), "endpoint-b", false); err == nil {
		t.Fatal("secret-free tunnel allow accepted an expired lease")
	}
}

func runtimeRequestForCandidate(t *testing.T, record AuthorizationRecord, candidateID string) RuntimeAuthorizationRequest {
	t.Helper()
	body := runtimeRequestBody(t, record, candidateID, "")
	parsed, err := ParseRuntimeAuthorizationRequest(body)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func runtimeRequestBody(t *testing.T, record AuthorizationRecord, candidateID string, observedCarrier string) []byte {
	t.Helper()
	request, err := artifactv3.BuildRequest(*record.artifact, candidateID)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := artifactv3.MarshalRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	carrier := ""
	for _, candidate := range request.Candidates {
		if candidate.ID == candidateID {
			carrier = string(candidate.Carrier)
		}
	}
	if observedCarrier != "" {
		carrier = observedCarrier
	}
	body, err := json.Marshal(map[string]string{
		"fsb3_base64url": base64.RawURLEncoding.EncodeToString(raw),
		"carrier":        carrier,
		"remote_address": "198.51.100.10:50000",
	})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func caEndpoint(id, rawURL string) EndpointConfig {
	return EndpointConfig{ID: id, URL: rawURL, TLS: CAPolicy()}
}
