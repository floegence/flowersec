package controlplane

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/artifactv2"
)

func TestIssuerCreatesOpaqueDirectArtifactAndBoundRuntimeAuthorization(t *testing.T) {
	issuer := newIssuerForTest(bytes.NewReader(bytes.Repeat([]byte{0x42}, 128)), time.Unix(1_800_000_000, 0))
	endpoints, err := NewEndpointSet(
		"wss://edge.example/flowersec/v2/direct",
		"quic://edge.example",
		"https://edge.example/flowersec/webtransport/v2/direct",
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
	if _, err := artifactv2.DecodeArtifactJSON(bytes.NewReader(issued.ArtifactJSON())); err != nil {
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

func TestIssuerAcceptsLoopbackPlainWebSocketOnlyForDirectArtifacts(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	issuer := newIssuerForTest(bytes.NewReader(bytes.Repeat([]byte{0x52}, 128)), now)
	loopback, err := NewEndpointSet("ws://127.0.0.1:23998/flowersec/v2/direct")
	if err != nil {
		t.Fatalf("NewEndpointSet loopback ws: %v", err)
	}
	if _, err := issuer.IssueDirect(DirectIssueOptions{
		Session:   SessionOptions{ChannelID: "loopback", ExpiresAt: now.Add(time.Minute)},
		Endpoints: loopback, RendezvousGroupID: "group", ListenerAudience: "audience",
		UpstreamAddress: "127.0.0.1:23998",
	}); err != nil {
		t.Fatalf("loopback ws direct issuance: %v", err)
	}
	nonLoopback, err := NewEndpointSet("ws://edge.example:23998/flowersec/v2/direct")
	if err != nil {
		t.Fatalf("NewEndpointSet non-loopback ws: %v", err)
	}
	if _, err := issuer.IssueDirect(DirectIssueOptions{
		Session:   SessionOptions{ChannelID: "non-loopback", ExpiresAt: now.Add(time.Minute)},
		Endpoints: nonLoopback, RendezvousGroupID: "group", ListenerAudience: "audience",
		UpstreamAddress: "127.0.0.1:23998",
	}); err == nil {
		t.Fatal("non-loopback plain ws direct issuance unexpectedly succeeded")
	}
}

func TestControlPlaneBoundariesFailClosedAndRedactOpaqueValues(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	issuer := newIssuerForTest(bytes.NewReader(bytes.Repeat([]byte{0x31}, 128)), now)
	directEndpoints, err := NewEndpointSet("wss://edge.example/flowersec/v2/direct")
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
	endpoints, err := NewEndpointSet("wss://edge.example/flowersec/v2/direct")
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
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, errors.New("secret provider detail") }

func TestIssuerCreatesTunnelPairAndRejectsCrossRecordAuthorization(t *testing.T) {
	issuer := newIssuerForTest(bytes.NewReader(bytes.Repeat([]byte{0x24}, 256)), time.Unix(1_800_000_000, 0))
	endpoints, err := NewEndpointSet(
		"wss://tunnel.example/flowersec/v2/tunnel",
		"quic://tunnel.example",
		"https://tunnel.example/flowersec/webtransport/v2/tunnel",
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
	endpoints, err := NewEndpointSet("wss://tunnel.example/flowersec/v2/tunnel")
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
	endpoints, err := NewEndpointSet("wss://tunnel.example/flowersec/v2/tunnel")
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
	request, err := artifactv2.BuildRequest(*record.artifact, candidateID)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := artifactv2.MarshalRequest(request)
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
		"fsb2_base64url": base64.RawURLEncoding.EncodeToString(raw),
		"carrier":        carrier,
		"remote_address": "198.51.100.10:50000",
	})
	if err != nil {
		t.Fatal(err)
	}
	return body
}
