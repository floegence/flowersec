package flowersec_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	flowersec "github.com/floegence/flowersec/flowersec-go/v7"
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
	if got := fmt.Sprintf("%v %#v", lease, lease); got != "Flowersec.ArtifactLease flowersec.ArtifactLease" {
		t.Fatalf("lease formatting leaked implementation: %q", got)
	}
}

func TestOpaqueArtifactRejectsMalformedAndForgedValues(t *testing.T) {
	valid := fixtureArtifactJSON(t)
	duplicate := append([]byte(`{"version":5,`), valid[1:]...)
	if _, err := flowersec.ParseArtifact(duplicate); !errors.Is(err, flowersec.ErrInvalidArtifact) {
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
	artifact, err := flowersec.ParseArtifact(fixtureArtifactJSON(t))
	if err != nil {
		t.Fatalf("ParseArtifact: %v", err)
	}
	return artifact
}

func fixtureArtifactJSON(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "testdata", "transport_v5", "artifact_vectors.json"))
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
	if len(fixtures.Positive) == 0 || len(fixtures.Positive[0].ArtifactJSON) == 0 || fixtures.Positive[0].ArtifactJSON[0] != '{' {
		t.Fatal("missing positive artifact object")
	}
	return []byte(fixtures.Positive[0].ArtifactJSON)
}
