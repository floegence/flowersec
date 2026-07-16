package interopprotocol

import (
	"strings"
	"testing"

	controlv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/controlplane/v1"
	directv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/direct/v1"
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
