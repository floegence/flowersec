package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestLanguageCapabilitiesDeclareContractLayers(t *testing.T) {
	repoRoot, err := repoRootFromWD()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(repoRoot, capabilityManifestPath))
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		CapabilityLayers     []string `json:"capability_layers"`
		PortableCapabilities []struct {
			ID    string `json:"id"`
			Layer string `json:"layer"`
		} `json:"portable_capabilities"`
		RuntimeSpecificCapabilities []struct {
			ID    string `json:"id"`
			Layer string `json:"layer"`
		} `json:"runtime_specific_capabilities"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	want := []string{"portable_core", "server_integration", "control_plane", "sdk_profile", "language_convenience"}
	if !slices.Equal(document.CapabilityLayers, want) {
		t.Fatalf("capability_layers = %v, want %v", document.CapabilityLayers, want)
	}
	allowedLayers := map[string]bool{"portable_core": true, "server_integration": true, "control_plane": true}
	for _, capability := range document.PortableCapabilities {
		if !allowedLayers[capability.Layer] {
			t.Errorf("public capability %s has invalid layer %q", capability.ID, capability.Layer)
		}
	}
	allowedProfiles := map[string]bool{"server_integration": true, "control_plane": true, "sdk_profile": true, "language_convenience": true}
	for _, capability := range document.RuntimeSpecificCapabilities {
		if !allowedProfiles[capability.Layer] {
			t.Errorf("runtime capability %s has invalid layer %q", capability.ID, capability.Layer)
		}
	}
}

func TestServerParityContractIsGranularAndExecutable(t *testing.T) {
	repoRoot, err := repoRootFromWD()
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := loadCapabilityManifest(repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateServerParityContract(manifest.ServerParityContract); err != nil {
		t.Fatal(err)
	}
}

func TestSDKReadmesDescribePublicCapabilities(t *testing.T) {
	repoRoot, err := repoRootFromWD()
	if err != nil {
		t.Fatal(err)
	}
	documents := map[string][]string{
		"README.md": {
			"What Your App Can Do",
			"Long-lived connection recovery",
			"Server-side session acceptance",
		},
		"flowersec-go/README.md": {
			"flowersec.Connect",
			"NewConnectionController",
			"Supported Connections",
		},
		"flowersec-ts/README.md": {
			"connect(...)",
			"ConnectionController",
			"Supported Connections",
		},
		"flowersec-swift/README.md": {
			"connect(lease:options:)",
			"ConnectionController",
			"Supported Connections",
		},
		"flowersec-rust/README.md": {
			"connect(...)",
			"ConnectionController",
			"Supported Connections",
		},
	}
	for path, tokens := range documents {
		assertDocumentContains(t, repoRoot, path, tokens)
	}
}

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

	t.Run("session handler fixture", func(t *testing.T) {
		copy := cloneCapabilityManifest(t, manifest)
		copy.SharedFixtures = slices.DeleteFunc(copy.SharedFixtures, func(fixture sharedFixture) bool {
			return fixture.ID == "session_handlers_v2"
		})
		_, err := loadCapabilityManifest(writeCapabilityManifest(t, &copy))
		if err == nil || !strings.Contains(err.Error(), "missing required shared fixture session_handlers_v2") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestCapabilityManifestRejectsRetiredProductionCarrierCapabilities(t *testing.T) {
	repoRoot, err := repoRootFromWD()
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := loadCapabilityManifest(repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	copy := cloneCapabilityManifest(t, manifest)
	copy.RuntimeSpecificCapabilities[0].ID = "node_webtransport"
	_, err = loadCapabilityManifest(writeCapabilityManifest(t, &copy))
	if err == nil || !strings.Contains(err.Error(), "retired production carrier capability") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCapabilityManifestRejectsUnverifiableServerClaims(t *testing.T) {
	repoRoot, err := repoRootFromWD()
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := loadCapabilityManifest(repoRoot)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("supported server capability without entrypoint", func(t *testing.T) {
		copy := cloneCapabilityManifest(t, manifest)
		implementation := copy.PortableCapabilities[6].Implementations["go"]
		implementation.Entrypoint = ""
		copy.PortableCapabilities[6].Implementations["go"] = implementation
		_, err := loadCapabilityManifest(writeCapabilityManifest(t, &copy))
		if err == nil || !strings.Contains(err.Error(), "requires an entrypoint") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("supported server capability rejects the wrong owner", func(t *testing.T) {
		copy := cloneCapabilityManifest(t, manifest)
		for index := range copy.PortableCapabilities {
			if copy.PortableCapabilities[index].ID != "server_admission_paths" {
				continue
			}
			implementation := copy.PortableCapabilities[index].Implementations["go"]
			implementation.Entrypoint = "flowersec.NewTunnelRuntime"
			copy.PortableCapabilities[index].Implementations["go"] = implementation
		}
		_, err := loadCapabilityManifest(writeCapabilityManifest(t, &copy))
		if err == nil || !strings.Contains(err.Error(), "production entrypoint") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("unsupported server capability needs only a stable reason", func(t *testing.T) {
		copy := cloneCapabilityManifest(t, manifest)
		implementation := copy.PortableCapabilities[6].Implementations["swift"]
		implementation.Entrypoint = ""
		implementation.TestIDs = nil
		copy.PortableCapabilities[6].Implementations["swift"] = implementation
		_, err := loadCapabilityManifest(writeCapabilityManifest(t, &copy))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestServerParityContractUsesSupportedAndUnsupportedBinary(t *testing.T) {
	repoRoot, err := repoRootFromWD()
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := loadCapabilityManifest(repoRoot)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("supported requires exactly one test id", func(t *testing.T) {
		copy := cloneCapabilityManifest(t, manifest)
		copy.ServerParityContract.Units[0].TestIDs = []string{"carrier/go-direct", "protocol/go"}
		err := validateServerParityContract(copy.ServerParityContract)
		if err == nil || !strings.Contains(err.Error(), "exactly one test_id") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("supported rejects an incorrect non-empty production entrypoint", func(t *testing.T) {
		copy := cloneCapabilityManifest(t, manifest)
		unit := &copy.ServerParityContract.Units[0]
		unit.Entrypoint = "flowersec.NewAcceptor"
		err := validateServerParityContract(copy.ServerParityContract)
		if err == nil || !strings.Contains(err.Error(), "production entrypoint") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("unsupported rejects executable metadata", func(t *testing.T) {
		copy := cloneCapabilityManifest(t, manifest)
		unit := &copy.ServerParityContract.Units[0]
		unit.Status = "unsupported"
		unit.Reason = "This production profile is unavailable."
		err := validateServerParityContract(copy.ServerParityContract)
		if err == nil || !strings.Contains(err.Error(), "must not declare an entrypoint or test_ids") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("unsupported requires stable English reason", func(t *testing.T) {
		copy := cloneCapabilityManifest(t, manifest)
		unit := &copy.ServerParityContract.Units[0]
		unit.Status = "unsupported"
		unit.Entrypoint = ""
		unit.TestIDs = nil
		unit.Reason = "temporary"
		err := validateServerParityContract(copy.ServerParityContract)
		if err == nil || !strings.Contains(err.Error(), "stable English reason") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("supported test id must exist in registry", func(t *testing.T) {
		copy := cloneCapabilityManifest(t, manifest)
		copy.ServerParityContract.Units[0].TestIDs = []string{"missing/test-id"}
		err := validateServerParityRegistry(copy.ServerParityContract, map[string]struct{}{"carrier/go-direct": {}})
		if err == nil || !strings.Contains(err.Error(), "unknown registry test_id") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestInteropUnsupportedTuplesCarryOnlyAReason(t *testing.T) {
	repoRoot, err := repoRootFromWD()
	if err != nil {
		t.Fatal(err)
	}
	var matrix interopMatrix
	if err := decodeStrictJSONFile(filepath.Join(repoRoot, interopMatrixPath), &matrix); err != nil {
		t.Fatal(err)
	}
	cell := &matrix.DirectCells[0]
	cell.Status = "unsupported"
	cell.Reason = "This runtime does not expose the required production carrier."
	if err := validateDirectInteropCells(matrix, map[string]struct{}{"interop/server-parity/direct-matrix": {}}); err == nil || !strings.Contains(err.Error(), "must not declare test_ids") {
		t.Fatalf("unexpected error: %v", err)
	}
	cell.TestIDs = nil
	if err := validateDirectInteropCells(matrix, map[string]struct{}{"interop/server-parity/direct-matrix": {}}); err != nil {
		t.Fatal(err)
	}
	cell.Status = "supported"
	cell.Reason = ""
	cell.TestIDs = []string{"missing/test-id"}
	if err := validateDirectInteropCells(matrix, map[string]struct{}{"interop/server-parity/direct-matrix": {}}); err == nil || !strings.Contains(err.Error(), "unknown registry test_id") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestInteropMatrixContainsOnlyStableTestIDs(t *testing.T) {
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

func TestConnectionControllerRecoveryContractIsCanonical(t *testing.T) {
	repoRoot, err := repoRootFromWD()
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyConnectionControllerRecovery(repoRoot); err != nil {
		t.Fatal(err)
	}
}

func TestConnectionControllerRecoveryRejectsInvalidContracts(t *testing.T) {
	repoRoot, err := repoRootFromWD()
	if err != nil {
		t.Fatal(err)
	}
	var contract connectionControllerRecoveryContract
	if err := decodeStrictJSONFile(filepath.Join(repoRoot, connectionControllerRecoveryPath), &contract); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		edit func(*connectionControllerRecoveryContract)
		want string
	}{
		{
			name: "invalid disposition",
			edit: func(contract *connectionControllerRecoveryContract) {
				decision := contract.Decisions["retryable"]
				decision.Disposition = "wait"
				contract.Decisions["retryable"] = decision
			},
			want: "unsupported disposition",
		},
		{
			name: "missing language",
			edit: func(contract *connectionControllerRecoveryContract) {
				delete(contract.Connect[0].Codes, "rust")
			},
			want: "must contain exactly",
		},
		{
			name: "duplicate domain code",
			edit: func(contract *connectionControllerRecoveryContract) {
				contract.Session[1].Codes["go"] = append(contract.Session[1].Codes["go"], "canceled")
			},
			want: "duplicate code",
		},
		{
			name: "unknown decision",
			edit: func(contract *connectionControllerRecoveryContract) {
				contract.Connect[0].Decision = "unknown"
			},
			want: "references unknown decision",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			copy := cloneConnectionControllerRecoveryContract(t, contract)
			tt.edit(&copy)
			err := validateConnectionControllerRecovery(copy)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func cloneConnectionControllerRecoveryContract(t *testing.T, contract connectionControllerRecoveryContract) connectionControllerRecoveryContract {
	t.Helper()
	data, err := json.Marshal(contract)
	if err != nil {
		t.Fatal(err)
	}
	var copy connectionControllerRecoveryContract
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
