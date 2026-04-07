package protocolio

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type artifactFixtureManifest struct {
	Version int                   `json:"version"`
	Cases   []artifactFixtureCase `json:"cases"`
}

type artifactFixtureCase struct {
	ID            string `json:"id"`
	Input         string `json:"input"`
	OK            bool   `json:"ok"`
	Normalized    string `json:"normalized"`
	ErrorContains string `json:"error_contains"`
}

func TestDecodeConnectArtifactJSON_SharedFixtures(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "connect_artifact_cases")
	manifestBytes, err := os.ReadFile(filepath.Join(root, "manifest.json"))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var manifest artifactFixtureManifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatalf("parse manifest: %v", err)
	}
	for _, tc := range manifest.Cases {
		t.Run(tc.ID, func(t *testing.T) {
			input, err := os.ReadFile(filepath.Join(root, tc.Input))
			if err != nil {
				t.Fatalf("read input: %v", err)
			}
			artifact, err := DecodeConnectArtifactJSON(bytes.NewReader(input))
			if !tc.OK {
				if err == nil {
					t.Fatalf("expected decode failure")
				}
				if tc.ErrorContains != "" && !strings.Contains(err.Error(), tc.ErrorContains) {
					t.Fatalf("expected error containing %q, got %v", tc.ErrorContains, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("DecodeConnectArtifactJSON: %v", err)
			}
			if tc.Normalized == "" {
				return
			}
			got, err := normalizedGenericJSON(artifact)
			if err != nil {
				t.Fatalf("normalize actual: %v", err)
			}
			wantBytes, err := os.ReadFile(filepath.Join(root, tc.Normalized))
			if err != nil {
				t.Fatalf("read expected: %v", err)
			}
			want, err := normalizedGenericJSON(json.RawMessage(wantBytes))
			if err != nil {
				t.Fatalf("normalize expected: %v", err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("normalized mismatch\n got: %#v\nwant: %#v", got, want)
			}
		})
	}
}

func normalizedGenericJSON(v any) (any, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return out, nil
}
