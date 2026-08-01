package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCapabilityManifestRequiresPortableContractsAndSharedFixtures(t *testing.T) {
	repoRoot, err := repoRootFromWD()
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := loadCapabilityManifest(repoRoot)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("portable capability", func(t *testing.T) {
		copy := cloneCapabilityManifest(t, manifest)
		copy.PortableCapabilities = copy.PortableCapabilities[1:]
		_, err := loadCapabilityManifest(writeCapabilityManifest(t, &copy))
		if err == nil || !strings.Contains(err.Error(), "missing required portable capability") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("shared fixture", func(t *testing.T) {
		copy := cloneCapabilityManifest(t, manifest)
		copy.SharedFixtures = copy.SharedFixtures[1:]
		_, err := loadCapabilityManifest(writeCapabilityManifest(t, &copy))
		if err == nil || !strings.Contains(err.Error(), "missing required shared fixture") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestInteropMatrixContainsOnlyV2Evidence(t *testing.T) {
	repoRoot, err := repoRootFromWD()
	if err != nil {
		t.Fatal(err)
	}
	capabilities, err := loadCapabilityManifest(repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyInteropMatrix(repoRoot, capabilities); err != nil {
		t.Fatal(err)
	}
}

func TestPublicErrorClassificationContractIsCanonical(t *testing.T) {
	repoRoot, err := repoRootFromWD()
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyPublicErrorClassification(repoRoot); err != nil {
		t.Fatal(err)
	}
}

func TestPublicErrorClassificationRejectsInvalidContracts(t *testing.T) {
	repoRoot, err := repoRootFromWD()
	if err != nil {
		t.Fatal(err)
	}
	var contract publicErrorClassificationContract
	if err := decodeStrictJSONFile(filepath.Join(repoRoot, publicErrorClassificationPath), &contract); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		edit func(*publicErrorClassificationContract)
		want string
	}{
		{
			name: "invalid action",
			edit: func(contract *publicErrorClassificationContract) {
				decision := contract.Decisions["retry"]
				decision.Action = "wait"
				contract.Decisions["retry"] = decision
			},
			want: "unsupported action",
		},
		{
			name: "inconsistent retryable flag",
			edit: func(contract *publicErrorClassificationContract) {
				decision := contract.Decisions["stop"]
				decision.Retryable = true
				contract.Decisions["stop"] = decision
			},
			want: "retryable must match action",
		},
		{
			name: "missing language",
			edit: func(contract *publicErrorClassificationContract) {
				delete(contract.Connect[0].Codes, "rust")
			},
			want: "must contain exactly",
		},
		{
			name: "duplicate domain code",
			edit: func(contract *publicErrorClassificationContract) {
				contract.Session[1].Codes["go"] = append(contract.Session[1].Codes["go"], "canceled")
			},
			want: "duplicate code",
		},
		{
			name: "unknown decision",
			edit: func(contract *publicErrorClassificationContract) {
				contract.Connect[0].Decision = "unknown"
			},
			want: "references unknown decision",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			copy := clonePublicErrorClassificationContract(t, contract)
			tt.edit(&copy)
			err := validatePublicErrorClassification(copy)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func clonePublicErrorClassificationContract(t *testing.T, contract publicErrorClassificationContract) publicErrorClassificationContract {
	t.Helper()
	data, err := json.Marshal(contract)
	if err != nil {
		t.Fatal(err)
	}
	var copy publicErrorClassificationContract
	if err := json.Unmarshal(data, &copy); err != nil {
		t.Fatal(err)
	}
	return copy
}

func cloneCapabilityManifest(t *testing.T, manifest *capabilityManifest) capabilityManifest {
	t.Helper()
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	var copy capabilityManifest
	if err := json.Unmarshal(data, &copy); err != nil {
		t.Fatal(err)
	}
	return copy
}

func writeCapabilityManifest(t *testing.T, manifest *capabilityManifest) string {
	t.Helper()
	root := t.TempDir()
	path := filepath.Join(root, capabilityManifestPath)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}
