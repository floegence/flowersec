package interopprotocol

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	controlv1 "github.com/floegence/flowersec/flowersec-go/v2/gen/flowersec/controlplane/v1"
	directv1 "github.com/floegence/flowersec/flowersec-go/v2/gen/flowersec/direct/v1"
)

func TestDecodeRejectsUnknownFields(t *testing.T) {
	var hello Hello
	err := Decode(strings.NewReader(`{"v":1,"event":"hello","language":"rust","roles":["client","server"],"cases":[],"extra":true}`), &hello)
	if err == nil {
		t.Fatal("unknown fields must be rejected")
	}
}

func TestDecodeRejectsMalformedJSON(t *testing.T) {
	var hello Hello
	if err := Decode(strings.NewReader(`{"v":1,"event":`), &hello); err == nil {
		t.Fatal("malformed JSON must be rejected")
	}
}

func TestEncodeCommandIncludesCompleteWorkloadShape(t *testing.T) {
	var encoded bytes.Buffer
	if err := Encode(&encoded, Command{Workload: validWorkload()}); err != nil {
		t.Fatal(err)
	}
	var command map[string]json.RawMessage
	if err := json.Unmarshal(encoded.Bytes(), &command); err != nil {
		t.Fatal(err)
	}
	workload := requiredTestObject(t, command, "workload")
	assertTestJSONFields(t, workload, []string{
		"streams", "rekey", "liveness_probes", "rpc", "proxy", "reconnect_cycles", "limit_checks",
	})
	assertTestJSONFields(t, requiredTestObject(t, workload, "streams"), []string{
		"concurrent", "bytes_per_stream", "chunk_bytes", "slow_readers", "churn", "fin", "reset",
		"mixed_concurrent", "mixed_bytes_per_stream",
	})
	assertTestJSONFields(t, requiredTestObject(t, workload, "rekey"), []string{
		"client", "server", "concurrent",
	})
	assertTestJSONFields(t, requiredTestObject(t, workload, "rpc"), []string{
		"calls", "notifications", "cancellations", "timeouts", "saturation_active", "saturation_queued", "saturation_rejected",
	})
	assertTestJSONFields(t, requiredTestObject(t, workload, "proxy"), []string{
		"http_requests", "http_body_bytes", "streaming_http_body_bytes", "websocket_frames", "websocket_frame_bytes",
	})
}

func requiredTestObject(t *testing.T, parent map[string]json.RawMessage, key string) map[string]json.RawMessage {
	t.Helper()
	raw, ok := parent[key]
	if !ok {
		t.Fatalf("missing object %q", key)
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		t.Fatalf("decode object %q: %v", key, err)
	}
	return object
}

func assertTestJSONFields(t *testing.T, object map[string]json.RawMessage, expected []string) {
	t.Helper()
	if len(object) != len(expected) {
		t.Fatalf("JSON fields = %v, want %v", object, expected)
	}
	for _, key := range expected {
		if _, ok := object[key]; !ok {
			t.Errorf("missing JSON field %q", key)
		}
	}
}

func TestDiagnosticExpectationsMustMatchCanonicalOrder(t *testing.T) {
	valid := append([]DiagnosticExpectation(nil), DiagnosticExpectations...)
	if err := ValidateDiagnosticExpectations(valid, len(valid)); err != nil {
		t.Fatal(err)
	}
	valid[0], valid[1] = valid[1], valid[0]
	if err := ValidateDiagnosticExpectations(valid, len(valid)); err == nil {
		t.Fatal("out-of-order diagnostic expectations must fail")
	}
}

func TestValidateHelloRequiresCompleteContract(t *testing.T) {
	hello := Hello{V: Version, Event: "hello", Language: "rust", Roles: []string{"server", "client"}, Cases: append([]string(nil), Cases...)}
	if err := ValidateHello(hello, "rust"); err != nil {
		t.Fatalf("valid hello rejected: %v", err)
	}
	hello.Cases = hello.Cases[:len(hello.Cases)-1]
	if err := ValidateHello(hello, "rust"); err == nil {
		t.Fatal("incomplete case declaration must be rejected")
	}
}

func TestCommandRejectsAmbiguousTransportInputs(t *testing.T) {
	command := Command{
		V: 1, Event: "run_client", RequestID: "request-1", Profile: "smoke",
		Transport: "direct", Suite: "x25519", DeadlineMS: 1000,
		Origin: "https://interop.flowersec.test", UpstreamURL: "http://127.0.0.1",
		DirectInfo: &directInfoFixture, TunnelGrant: &tunnelGrantFixture,
		Workload: validWorkload(), ReconnectArtifacts: []ClientArtifact{{DirectInfo: &directv1.DirectConnectInfo{}}},
	}
	if err := command.Validate(); err == nil {
		t.Fatal("ambiguous direct/tunnel input must be rejected")
	}
}

var directInfoFixture = directv1.DirectConnectInfo{}
var tunnelGrantFixture = controlv1.ChannelInitGrant{}

func validWorkload() Workload {
	return Workload{
		Streams: StreamWorkload{Concurrent: 1, BytesPerStream: 1, ChunkBytes: 1, SlowReaders: 1, Churn: 1, FIN: 1, Reset: 1},
		Rekey:   RekeyWorkload{Client: 1, Server: 1}, LivenessProbes: 1,
		RPC:             RPCWorkload{Calls: 1, Notifications: 1, Cancellations: 1, Timeouts: 1, SaturationActive: 1, SaturationQueued: 1, SaturationRejected: 1},
		Proxy:           ProxyWorkload{HTTPRequests: 1, HTTPBodyBytes: 1, WebSocketFrames: 1, WebSocketFrameBytes: 1},
		ReconnectCycles: 1, LimitChecks: 1,
	}
}

func TestWorkloadValidatesExplicitStressSettingsAsOneContract(t *testing.T) {
	workload := validWorkload()
	if err := workload.Validate(); err != nil {
		t.Fatalf("explicit zero-valued stress settings were rejected: %v", err)
	}
	workload.Streams.MixedConcurrent = 8
	if err := workload.Validate(); err == nil {
		t.Fatal("mixed concurrency without a transfer size must fail")
	}
	workload.Streams.MixedBytesPerStream = 2 * 1024 * 1024
	workload.Proxy.StreamingHTTPBodyBytes = 16 * 1024 * 1024
	if err := workload.Validate(); err != nil {
		t.Fatalf("valid stress settings were rejected: %v", err)
	}
	if got := workload.Streams.MixedTransferCount(); got != 4 {
		t.Fatalf("mixed transfer count got %d, want 4", got)
	}
	if got := workload.Streams.MixedRPCCallCount(); got != 4 {
		t.Fatalf("mixed RPC count got %d, want 4", got)
	}
}
