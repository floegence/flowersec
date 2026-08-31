package rpc

import (
	"encoding/json"
	"os"
	"testing"
)

func TestVersionIsolationRPCUsesProductionEnvelopeCodec(t *testing.T) {
	raw, err := os.ReadFile("../../../testdata/transport_v3/version_isolation_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Application struct {
			RPC struct {
				Envelope string `json:"envelope_json"`
			} `json:"rpc"`
		} `json:"application_codecs"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	envelope, err := decodeEnvelope([]byte(fixture.Application.RPC.Envelope))
	if err != nil {
		t.Fatal(err)
	}
	if envelope.TypeId != 7 || envelope.RequestId != 1 || envelope.ResponseTo != 0 {
		t.Fatalf("unexpected RPC envelope: %+v", envelope)
	}
	var payload struct {
		Ratio float64 `json:"ratio"`
	}
	if err := json.Unmarshal(envelope.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Ratio != 1.5 {
		t.Fatalf("RPC float payload = %v", payload.Ratio)
	}
}
