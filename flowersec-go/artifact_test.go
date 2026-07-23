package flowersec_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	flowersec "github.com/floegence/flowersec/flowersec-go/v2"
)

func TestOpaqueArtifactAndLease(t *testing.T) {
	artifact := parseFixtureArtifact(t)
	if got := fmt.Sprintf("%v %#v", artifact, artifact); got != "Flowersec.Artifact flowersec.Artifact" {
		t.Fatalf("artifact formatting leaked implementation: %q", got)
	}
	encoded, err := json.Marshal(artifact)
	if err != nil || string(encoded) != "{}" {
		t.Fatalf("artifact JSON = %q, %v", encoded, err)
	}
	lease, err := flowersec.NewArtifactLease(artifact, func(context.Context) error { return nil })
	if err != nil {
		t.Fatalf("NewArtifactLease: %v", err)
	}
	encoded, err = json.Marshal(lease)
	if err != nil || string(encoded) != "{}" {
		t.Fatalf("lease JSON = %q, %v", encoded, err)
	}
}

func TestOpaqueArtifactRejectsMalformedAndForgedValues(t *testing.T) {
	if _, err := flowersec.ParseArtifact([]byte(`{"version":2,"version":2}`)); !errors.Is(err, flowersec.ErrInvalidArtifact) {
		t.Fatalf("duplicate field error = %v", err)
	}
	if _, err := flowersec.NewArtifactLease(flowersec.Artifact{}, func(context.Context) error { return nil }); !errors.Is(err, flowersec.ErrInvalidArtifact) {
		t.Fatalf("forged artifact error = %v", err)
	}
	if _, err := flowersec.NewArtifactLease(parseFixtureArtifact(t), nil); !errors.Is(err, flowersec.ErrInvalidArtifact) {
		t.Fatalf("nil commit callback error = %v", err)
	}
}

func parseFixtureArtifact(t *testing.T) flowersec.Artifact {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "testdata", "transport_v2", "artifact_vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixtures struct {
		Positive []struct {
			ArtifactJSON string `json:"artifact_json"`
		} `json:"positive"`
	}
	if err := json.Unmarshal(raw, &fixtures); err != nil {
		t.Fatal(err)
	}
	artifact, err := flowersec.ParseArtifact([]byte(fixtures.Positive[0].ArtifactJSON))
	if err != nil {
		t.Fatalf("ParseArtifact: %v", err)
	}
	return artifact
}
