package protocolv2

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/artifactv2"
)

type securityNegativeFixture struct {
	Version int    `json:"version"`
	Profile string `json:"profile"`
	Vectors []struct {
		ID    string `json:"id"`
		Kind  string `json:"kind"`
		Value string `json:"value"`
	} `json:"vectors"`
}

func TestSharedSecurityNegativeVectorsRejectMalformedInputs(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "transport_v2", "security_negative_vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture securityNegativeFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Version != 1 || fixture.Profile != "flowersec/2" {
		t.Fatalf("security fixture metadata = %+v", fixture)
	}
	for _, vector := range fixture.Vectors {
		value, err := hex.DecodeString(vector.Value)
		if vector.Kind == "artifact_json" {
			value = []byte(vector.Value)
		} else if err != nil {
			t.Fatalf("%s hex: %v", vector.ID, err)
		}
		var parseErr error
		switch vector.Kind {
		case "artifact_json":
			_, parseErr = artifactv2.DecodeArtifactJSON(bytes.NewReader(value))
		case "fsa2_hex":
			_, parseErr = artifactv2.ParseClientResponse(value)
		case "fsr2_hex":
			_, parseErr = ParseRecordHeader(value)
		case "open_hex":
			_, parseErr = ParseOpenPayload(value)
		default:
			t.Fatalf("unknown security vector kind %q", vector.Kind)
		}
		if parseErr == nil {
			t.Fatalf("%s accepted malformed input", vector.ID)
		}
	}
}
