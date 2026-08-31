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

func TestLanguageCapabilitiesDeclareNamedDeploymentProfiles(t *testing.T) {
	repoRoot, err := repoRootFromWD()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(repoRoot, capabilityManifestPath))
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		DeploymentProfiles struct {
			ApplicationWire string `json:"application_wire"`
			Profiles        []struct {
				ID                    string              `json:"id"`
				ClaimedRuntimes       []string            `json:"claimed_runtimes"`
				RequiredRoles         []string            `json:"required_roles"`
				RequiredCarriers      []string            `json:"required_carriers"`
				RequiredTupleCount    int                 `json:"required_tuple_count"`
				RequiredPathUnitCount int                 `json:"required_path_unit_count"`
				RequiredPaths         map[string][]string `json:"required_paths"`
			} `json:"profiles"`
		} `json:"deployment_profiles"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	if document.DeploymentProfiles.ApplicationWire != "flowersec/3" {
		t.Fatalf("deployment profile application wire = %q", document.DeploymentProfiles.ApplicationWire)
	}
	wantProfiles := []string{"native-server-core", "browser-client", "apple-client", "webtransport-server"}
	gotProfiles := make([]string, 0, len(document.DeploymentProfiles.Profiles))
	for _, profile := range document.DeploymentProfiles.Profiles {
		gotProfiles = append(gotProfiles, profile.ID)
	}
	if !slices.Equal(gotProfiles, wantProfiles) {
		t.Fatalf("deployment profiles = %v, want %v", gotProfiles, wantProfiles)
	}
	native := document.DeploymentProfiles.Profiles[0]
	if !slices.Equal(native.ClaimedRuntimes, []string{"go", "rust", "node-typescript"}) ||
		!slices.Equal(native.RequiredRoles, []string{"endpoint-client", "direct-server", "tunnel-runtime"}) ||
		!slices.Equal(native.RequiredCarriers, []string{"websocket", "raw-quic"}) || native.RequiredTupleCount != 18 || native.RequiredPathUnitCount != 24 {
		t.Fatalf("native-server-core profile does not declare the exact 18 tuples and 24 path units: %+v", native)
	}
	manifest, err := loadCapabilityManifest(repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	mutated := manifest.DeploymentProfiles
	mutated.Profiles = slices.Clone(mutated.Profiles)
	mutated.Profiles[0].RequiredTupleCount++
	if err := validateDeploymentProfiles(mutated, manifest.ServerParityContract); err == nil || !strings.Contains(err.Error(), "canonical capability contract") {
		t.Fatalf("mutated native profile validation error = %v", err)
	}
	capabilityMutation := manifest.DeploymentProfiles
	capabilityMutation.Profiles = slices.Clone(capabilityMutation.Profiles)
	capabilityMutation.Profiles[0].RequiredCapabilityIDs = slices.Clone(capabilityMutation.Profiles[0].RequiredCapabilityIDs)
	capabilityMutation.Profiles[0].RequiredCapabilityIDs[0] = "missing_capability"
	if err := validateDeploymentProfileCapabilityBindings(capabilityMutation, manifest.PortableCapabilities); err == nil || !strings.Contains(err.Error(), "unknown required capability") {
		t.Fatalf("mutated profile capability validation error = %v", err)
	}
	invalidWire := manifest.DeploymentProfiles
	invalidWire.ApplicationWire = "runtime_private_wire"
	if err := validateDeploymentProfileTransportBindings(invalidWire, manifest.ServerParityContract); err == nil || !strings.Contains(err.Error(), "flowersec/3") {
		t.Fatalf("mutated profile wire validation error = %v", err)
	}
}

func TestDeploymentProfileTransportBindingsRequireCurrentRuntimeAndRolePathUnits(t *testing.T) {
	repoRoot, err := repoRootFromWD()
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := loadCapabilityManifest(repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	invalidRuntime := manifest.DeploymentProfiles
	invalidRuntime.Profiles = slices.Clone(invalidRuntime.Profiles)
	invalidRuntime.Profiles[0].TransportRuntimeIDs = slices.Clone(invalidRuntime.Profiles[0].TransportRuntimeIDs)
	invalidRuntime.Profiles[0].TransportRuntimeIDs[0] = "go/legacy"
	if err := validateDeploymentProfileTransportBindings(invalidRuntime, manifest.ServerParityContract); err == nil || !strings.Contains(err.Error(), "go/legacy") {
		t.Fatalf("unknown current runtime error = %v", err)
	}

	parity := *manifest.ServerParityContract
	parity.Units = slices.DeleteFunc(slices.Clone(parity.Units), func(unit serverParityUnit) bool {
		return unit.Runtime == "rust" && unit.Role == "tunnel-runtime" && unit.Carrier == "websocket" && unit.Path == "tunnel"
	})
	if err := validateDeploymentProfileTransportBindings(manifest.DeploymentProfiles, &parity); err == nil || !strings.Contains(err.Error(), "tunnel-runtime") {
		t.Fatalf("missing opaque tunnel production unit error = %v", err)
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
		t.Fatalf("valid supported/unsupported server parity contract failed: %v", err)
	}
	incomplete := *manifest.ServerParityContract
	incomplete.Units = slices.Clone(incomplete.Units[1:])
	if err := validateServerParityContract(&incomplete); err == nil || !strings.Contains(err.Error(), "missing required server parity unit") {
		t.Fatalf("missing required server parity unit error = %v", err)
	}
}

func TestServerParityCompletionObjectiveRejectsUnsupportedRequiredUnit(t *testing.T) {
	repoRoot, err := repoRootFromWD()
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := loadCapabilityManifest(repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	contract := *manifest.ServerParityContract
	contract.Units = slices.Clone(contract.Units)
	unit := &contract.Units[0]
	unit.Status = "unsupported"
	unit.Entrypoint = ""
	unit.TestIDs = nil
	unit.Reason = "No production driver satisfies the required contract."

	err = validateRequiredServerParityComplete(&contract)
	if err == nil || !strings.Contains(err.Error(), "required server parity unit") {
		t.Fatalf("unsupported required unit error = %v", err)
	}
}

func TestServerParityCompletionObjectiveLocksGoWebTransportTunnelToProductionEvidence(t *testing.T) {
	repoRoot, err := repoRootFromWD()
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := loadCapabilityManifest(repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateRequiredServerParityComplete(manifest.ServerParityContract); err != nil {
		t.Fatalf("optional WebTransport blocked required server parity: %v", err)
	}
	for _, role := range []string{"endpoint-client", "tunnel-runtime"} {
		unit := slices.IndexFunc(manifest.ServerParityContract.Units, func(unit serverParityUnit) bool {
			return unit.Runtime == "go" && unit.Role == role && unit.Carrier == "webtransport" && unit.Path == "tunnel"
		})
		if unit < 0 {
			t.Fatalf("Go H4 %s WebTransport tunnel unit is missing", role)
		}
		entry := manifest.ServerParityContract.Units[unit]
		if entry.Status != "supported" || !slices.Equal(entry.TestIDs, []string{"carrier/go-webtransport-tunnel"}) || entry.Reason != "" {
			t.Fatalf("Go H4 %s WebTransport tunnel unit is not locked to production broker evidence", role)
		}
	}
}

func TestServerParityCompletionObjectiveAllowsUnsupportedNonGoControlPlane(t *testing.T) {
	repoRoot, err := repoRootFromWD()
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := loadCapabilityManifest(repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateRequiredServerParityComplete(manifest.ServerParityContract); err != nil {
		t.Fatalf("design-approved control-plane exclusions blocked server parity: %v", err)
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
			return fixture.ID == "session_handlers_v3"
		})
		_, err := loadCapabilityManifest(writeCapabilityManifest(t, &copy))
		if err == nil || !strings.Contains(err.Error(), "missing required shared fixture session_handlers_v3") {
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
		capability := portableCapabilityByID(t, &copy, "server_acceptor_session")
		implementation := capability.Implementations["go"]
		implementation.Entrypoint = ""
		capability.Implementations["go"] = implementation
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
		capability := portableCapabilityByID(t, &copy, "server_acceptor_session")
		implementation := capability.Implementations["swift"]
		implementation.Entrypoint = ""
		implementation.TestIDs = nil
		capability.Implementations["swift"] = implementation
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

	t.Run("completion rejects a supported test id missing from the registry", func(t *testing.T) {
		copy := cloneCapabilityManifest(t, manifest)
		copy.ServerParityContract.Units[0].TestIDs = []string{"missing/test-id"}
		err := validateRequiredServerParityCompletionContract(copy.ServerParityContract, map[string]struct{}{"carrier/go-direct": {}})
		if err == nil || !strings.Contains(err.Error(), "unknown registry test_id") {
			t.Fatalf("unexpected completion error: %v", err)
		}
	})
}

func TestInteropCellsRequireTruthfulSupportedAndUnsupportedMetadata(t *testing.T) {
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
	cell.TestIDs = []string{"carrier/go-direct"}
	if err := validateDirectInteropCells(matrix, map[string]struct{}{"carrier/go-direct": {}}); err == nil || !strings.Contains(err.Error(), "must not declare test_ids") {
		t.Fatalf("unexpected error: %v", err)
	}
	cell.TestIDs = nil
	if err := validateDirectInteropCells(matrix, matrixRegistryIDs(matrix)); err != nil {
		t.Fatalf("truthful unsupported direct cell error = %v", err)
	}
	cell.Status = "supported"
	cell.Reason = ""
	registryIDs := matrixRegistryIDs(matrix)
	cell.TestIDs = []string{"missing/test-id"}
	if err := validateDirectInteropCells(matrix, registryIDs); err == nil || !strings.Contains(err.Error(), "unknown registry test_id") {
		t.Fatalf("unexpected error: %v", err)
	}

	topology := &matrix.TunnelTopologies[0]
	topology.Status = "unsupported"
	topology.TestIDs = nil
	topology.Reason = "This runtime does not expose the required production carrier."
	if err := validateTunnelInteropTopologies(matrix, matrixRegistryIDs(matrix)); err != nil {
		t.Fatalf("truthful unsupported tunnel topology error = %v", err)
	}
}

func TestTunnelInteropRequiresGeneratedPairwiseCoveringSet(t *testing.T) {
	repoRoot, err := repoRootFromWD()
	if err != nil {
		t.Fatal(err)
	}
	var matrix interopMatrix
	if err := decodeStrictJSONFile(filepath.Join(repoRoot, interopMatrixPath), &matrix); err != nil {
		t.Fatal(err)
	}
	for index := range matrix.TunnelTopologies {
		if matrix.TunnelTopologies[index].ID == "go_via_go_to_go_websocket_tunnel" {
			matrix.TunnelTopologies[index].TunnelRuntime = "rust"
			break
		}
	}
	err = validateTunnelInteropTopologies(matrix, matrixRegistryIDs(matrix))
	if err == nil || !strings.Contains(err.Error(), "generated pairwise covering set") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func matrixRegistryIDs(matrix interopMatrix) map[string]struct{} {
	ids := make(map[string]struct{})
	for _, cell := range matrix.DirectCells {
		for _, id := range cell.TestIDs {
			ids[id] = struct{}{}
		}
	}
	for _, topology := range matrix.TunnelTopologies {
		for _, id := range topology.TestIDs {
			ids[id] = struct{}{}
		}
	}
	return ids
}

func TestRequiredInteropMatrixContainsOnlyWebSocketAndRawQUIC(t *testing.T) {
	repoRoot, err := repoRootFromWD()
	if err != nil {
		t.Fatal(err)
	}
	var matrix interopMatrix
	if err := decodeStrictJSONFile(filepath.Join(repoRoot, interopMatrixPath), &matrix); err != nil {
		t.Fatal(err)
	}
	if len(matrix.DirectCells) != 18 || len(matrix.TunnelTopologies) != 18 {
		t.Fatalf("required matrix dimensions = direct:%d tunnel:%d, want 18/18", len(matrix.DirectCells), len(matrix.TunnelTopologies))
	}
	for _, cell := range matrix.DirectCells {
		if cell.Carrier == "webtransport" {
			t.Fatalf("optional WebTransport direct cell %s entered the required matrix", cell.ID)
		}
	}
	for _, topology := range matrix.TunnelTopologies {
		if topology.IngressCarrierA == "webtransport" || topology.IngressCarrierB == "webtransport" {
			t.Fatalf("optional WebTransport tunnel topology %s entered the required matrix", topology.ID)
		}
	}
}

func TestInteropMatrixPublishesOnlyCompleteGoBaselineEvidence(t *testing.T) {
	repoRoot, err := repoRootFromWD()
	if err != nil {
		t.Fatal(err)
	}
	var matrix interopMatrix
	if err := decodeStrictJSONFile(filepath.Join(repoRoot, interopMatrixPath), &matrix); err != nil {
		t.Fatal(err)
	}
	directSupported, directUnsupported := 0, 0
	for _, cell := range matrix.DirectCells {
		switch cell.Status {
		case "supported":
			directSupported++
			if cell.Client != "go" && cell.Server != "go" {
				t.Fatalf("direct cell %s claims support without the Go baseline", cell.ID)
			}
			if len(cell.TestIDs) != 1 || cell.TestIDs[0] != "interop/v3/native/direct/go-baseline" || cell.Reason != "" {
				t.Fatalf("direct cell %s does not use the complete parameterized release gate", cell.ID)
			}
		case "unsupported":
			directUnsupported++
			if len(cell.TestIDs) != 0 || cell.Reason != "No release-gating v3 interoperability test exercises the complete executable case set for this cell." {
				t.Fatalf("direct cell %s has an invalid unverified declaration", cell.ID)
			}
		}
	}
	if directSupported != 10 || directUnsupported != 8 {
		t.Fatalf("direct evidence = supported:%d unsupported:%d, want 10/8", directSupported, directUnsupported)
	}

	tunnelSupported, tunnelUnsupported := 0, 0
	for _, topology := range matrix.TunnelTopologies {
		switch topology.Status {
		case "supported":
			tunnelSupported++
			if topology.EndpointA != "go" && topology.TunnelRuntime != "go" && topology.EndpointB != "go" {
				t.Fatalf("tunnel topology %s claims support without the Go baseline", topology.ID)
			}
			if len(topology.TestIDs) != 1 || topology.TestIDs[0] != "interop/v3/native/tunnel/go-baseline" || topology.Reason != "" {
				t.Fatalf("tunnel topology %s does not use the complete parameterized release gate", topology.ID)
			}
		case "unsupported":
			tunnelUnsupported++
			if len(topology.TestIDs) != 0 || topology.Reason != "No release-gating v3 interoperability test exercises the complete executable case set for this topology." {
				t.Fatalf("tunnel topology %s has an invalid unverified declaration", topology.ID)
			}
		}
	}
	if tunnelSupported != 14 || tunnelUnsupported != 4 {
		t.Fatalf("tunnel evidence = supported:%d unsupported:%d, want 14/4", tunnelSupported, tunnelUnsupported)
	}

	if len(matrix.ClientProfiles) != 4 {
		t.Fatalf("client profile evidence = %d, want 4", len(matrix.ClientProfiles))
	}
	for _, profile := range matrix.ClientProfiles {
		if profile.Status != "supported" || profile.Server != "go" || profile.Carrier != "websocket" ||
			(profile.Client != "swift" && profile.Client != "typescript-browser") {
			t.Fatalf("client profile %s is outside the exact Swift/browser-to-Go WSS gate", profile.ID)
		}
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

func portableCapabilityByID(t *testing.T, manifest *capabilityManifest, id string) *portableCapability {
	t.Helper()
	for index := range manifest.PortableCapabilities {
		if manifest.PortableCapabilities[index].ID == id {
			return &manifest.PortableCapabilities[index]
		}
	}
	t.Fatalf("portable capability %q not found", id)
	return nil
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
