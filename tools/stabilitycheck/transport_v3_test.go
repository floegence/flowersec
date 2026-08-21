package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTransportV3RegistryAndSourceConsumers(t *testing.T) {
	repoRoot, err := repoRootFromWD()
	if err != nil {
		t.Fatal(err)
	}
	registry, err := loadTransportV3Registry(repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	if registry.Version != 3 || len(registry.WireFixtures) != 15 {
		t.Fatal("unexpected transport v3 registry summary")
	}
}

func TestTransportV3SourceOwnershipCoversCamelCaseAndSharedDefaultFiles(t *testing.T) {
	repoRoot, err := repoRootFromWD()
	if err != nil {
		t.Fatal(err)
	}
	registry, err := loadTransportV3Registry(repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	owned := transportV3OwnedSourceFiles(repoRoot, registry)
	for path := range owned {
		if !isTransportV3SourcePath(path, true) {
			t.Fatalf("registered v3 source ownership omitted %s", path)
		}
	}
	for _, path := range []string{
		"flowersec-ts/src/node/acceptorV3.ts",
		"flowersec-ts/src/node/tunnelRuntimeV3.ts",
		"flowersec-swift/Sources/Flowersec/TransportV3Crypto.swift",
		"flowersec-go/connection_controller.go",
		"flowersec-swift/Sources/Flowersec/ConnectionController.swift",
	} {
		if !isTransportV3SourcePath(path, owned[path]) {
			t.Fatalf("v3 source ownership omitted %s", path)
		}
	}
	for _, path := range []string{
		"flowersec-go/internal/protocolv2/codec.go",
		"flowersec-ts/src/v2/protocol.ts",
		"flowersec-swift/Sources/Flowersec/TransportV2Crypto.swift",
	} {
		if isTransportV3SourcePath(path, owned[path]) {
			t.Fatalf("v2 source was misclassified as v3: %s", path)
		}
	}
}

func TestTransportV3ForbiddenDomainRecognizesEveryIsolationFamily(t *testing.T) {
	for _, value := range []string{
		"FSB2",
		"flowersec/2",
		"flowersec-direct/2",
		"/flowersec/v2/direct",
		"/flowersec/webtransport/v2/tunnel",
		"flowersec.direct.v2",
		"flowersec v2 server finished",
		"flowersec v2 record key",
		"flowersec-v2-handshake",
		"flowersec-v2-record",
	} {
		if !transportV3ForbiddenDomain.MatchString(value) {
			t.Fatalf("v2 isolation family was not recognized: %q", value)
		}
	}
}

func TestTransportV3RegistryRejectsUnknownTopLevelField(t *testing.T) {
	repoRoot, err := repoRootFromWD()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(repoRoot, transportV3ContractPath))
	if err != nil {
		t.Fatal(err)
	}
	temporary := t.TempDir()
	mutated := append([]byte{}, raw[:len(raw)-2]...)
	mutated = append(mutated, []byte(",\n  \"invented\": true\n}\n")...)
	if err := os.MkdirAll(filepath.Join(temporary, "stability"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(temporary, transportV3ContractPath), mutated, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadTransportV3Registry(temporary); err == nil {
		t.Fatal("registry with unknown top-level field was accepted")
	}
}

func TestTransportV3ConsumerEvidenceRejectsSourceMutations(t *testing.T) {
	repoRoot, err := repoRootFromWD()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		fixture  string
		language string
		paths    []string
		token    string
	}{
		{"artifact_admission", "go", []string{"flowersec-go/internal/artifactv3/vectors_test.go", "flowersec-go/internal/transportsecurity/policy_test.go"}, "SnapshotPolicy"},
		{"artifact_admission", "typescript", []string{"flowersec-ts/src/v3/artifact.test.ts"}, "snapshotTransportSecurityPolicyV3"},
		{"artifact_admission", "rust", []string{"flowersec-rust/src/artifact_v3.rs"}, "active_pin_snapshots"},
		{"artifact_admission", "swift", []string{"flowersec-swift/Tests/FlowersecTests/TransportV3Tests.swift"}, "session_contract_hash_b64u"},
		{"capability", "rust", []string{"flowersec-rust/src/transport_v3.rs"}, "typescript-browser-ca-only"},
		{"capability", "swift", []string{"flowersec-swift/Tests/FlowersecTests/TransportV3Tests.swift"}, "go-native"},
		{"idna", "go", []string{"flowersec-go/internal/artifactv3/vectors_test.go", "flowersec-go/internal/idna15/idna_test.go"}, "idna15.LookupASCII"},
		{"idna", "typescript", []string{"flowersec-ts/src/v3/artifact.test.ts"}, "urlFixture.positive"},
		{"session_handlers", "swift", []string{"flowersec-swift/Tests/FlowersecTests/TransportV3SessionTests.swift"}, "duplicate_type_id"},
	}
	for _, test := range tests {
		t.Run(test.fixture+"-"+test.language+"-"+test.token, func(t *testing.T) {
			bodies := make([]string, 0, len(test.paths))
			for _, path := range test.paths {
				body, err := os.ReadFile(filepath.Join(repoRoot, path))
				if err != nil {
					t.Fatal(err)
				}
				bodies = append(bodies, string(body))
			}
			body := strings.Join(bodies, "\n")
			if err := validateTransportV3ConsumerEvidence(test.fixture, test.language, body); err != nil {
				t.Fatalf("unmodified consumer evidence failed: %v", err)
			}
			mutated := strings.ReplaceAll(body, test.token, "")
			if err := validateTransportV3ConsumerEvidence(test.fixture, test.language, mutated); err == nil {
				t.Fatal("consumer mutation unexpectedly retained evidence")
			}
		})
	}
}
