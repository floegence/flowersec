package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/transportrelease"
)

func TestWeaknetFullCaseRunsProduceMeasuredEvidence(t *testing.T) {
	tests := []struct {
		id  string
		run func(context.Context) (weaknetCaseRun, error)
	}{
		{id: "WF-BYTE-FULL", run: runWeaknetByteFull},
		{id: "WF-CLEANUP-FULL", run: runWeaknetCleanupFull},
		{id: "WF-UDP-FULL", run: runWeaknetUDPFull},
		{id: "WF-UDP-RANDOM-LOSS", run: runWeaknetRandomLoss},
	}
	for _, test := range tests {
		t.Run(test.id, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			result, err := test.run(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if result.completed < 1 || len(result.metrics) == 0 || len(result.config) == 0 || len(result.trace) == 0 {
				t.Fatalf("incomplete result: %+v", result)
			}
		})
	}
}

func TestRegisteredCaseDefinitionsAreExactAndOrdered(t *testing.T) {
	tests := []struct {
		owner string
		count int
	}{
		{owner: conformanceSmokeOwner, count: 6},
		{owner: conformanceFullOwner, count: 8},
		{owner: weaknetFullOwner, count: 4},
		{owner: quicNativeSmokeOwner, count: 4},
		{owner: quicNativeProofOwner, count: 7},
	}
	for _, test := range tests {
		definitions, err := registeredCasesForOwner(test.owner, "normal")
		if err != nil {
			t.Fatal(err)
		}
		if len(definitions) != test.count {
			t.Fatalf("%s definitions = %d, want %d", test.owner, len(definitions), test.count)
		}
		if err := validateReleaseCaseDefinitions(definitions); err != nil {
			t.Fatalf("%s: %v", test.owner, err)
		}
	}
	if _, err := registeredCasesForOwner(weaknetFullOwner, "race"); err == nil {
		t.Fatal("weaknet-full accepted race mode")
	}
	raceDefinitions, err := registeredCasesForOwner(quicNativeRaceOwner, "race")
	if err != nil {
		t.Fatal(err)
	}
	if len(raceDefinitions) != 4 || raceDefinitions[0].ID != "BN-N5" || raceDefinitions[1].ID != "NP-REBIND" ||
		raceDefinitions[2].ID != "NS-N2" || raceDefinitions[3].ID != "NS-N3" {
		t.Fatalf("native race definitions = %+v", raceDefinitions)
	}
	if err := validateReleaseCaseDefinitions(raceDefinitions); err != nil {
		t.Fatal(err)
	}
}

func TestRegisteredCaseSelectorBindsExactOwnerAndMode(t *testing.T) {
	definitions, err := registeredCasesForOwnerAndID(capacityOwner, "normal", "CAP-DIRECT-WSS-1000")
	if err != nil {
		t.Fatal(err)
	}
	if len(definitions) != 1 || definitions[0].ID != "CAP-DIRECT-WSS-1000" {
		t.Fatalf("selected definitions = %+v", definitions)
	}
	for _, test := range []struct {
		owner  string
		mode   string
		caseID string
	}{
		{owner: capacityOwner, mode: "normal", caseID: "CS-C1"},
		{owner: quicNativeRaceOwner, mode: "race", caseID: "CAP-DIRECT-WSS-1000"},
		{owner: capacityOwner, mode: "normal", caseID: "missing"},
	} {
		if _, err := registeredCasesForOwnerAndID(test.owner, test.mode, test.caseID); err == nil {
			t.Fatalf("accepted case %q for owner %q mode %q", test.caseID, test.owner, test.mode)
		}
	}
}

func TestNativeSmokeCasesExerciseProductionQUICAndTunnel(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	artifacts := filepath.Join(root, "artifacts")
	if err := os.Mkdir(artifacts, 0o700); err != nil {
		t.Fatal(err)
	}
	destination, err := newArtifactDestination(artifacts, filepath.Join(root, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer destination.Close()
	for _, definition := range nativeSmokeCases {
		t.Run(definition.ID, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			result, err := runNativeSmokeCase(ctx, destination, definition, "normal")
			if err != nil {
				t.Fatal(err)
			}
			if result.CompletedOperations < 1 || len(result.Artifacts) != len(nativeCaseArtifactKinds(definition.ID)) {
				t.Fatalf("case result = %+v", result)
			}
			assertNativeArtifactsUseRawQLOG(t, root, result)
		})
	}
}

func TestNativeProofCoreCasesExerciseFrozenQUICBoundaries(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	artifacts := filepath.Join(root, "artifacts")
	if err := os.Mkdir(artifacts, 0o700); err != nil {
		t.Fatal(err)
	}
	destination, err := newArtifactDestination(artifacts, filepath.Join(root, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer destination.Close()
	for _, definition := range nativeProofCoreCases {
		t.Run(definition.ID, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			result, err := runNativeProofCoreCase(ctx, destination, definition, "normal")
			if err != nil {
				t.Fatal(err)
			}
			if result.CompletedOperations < 1 || len(result.Artifacts) != 4 {
				t.Fatalf("case result = %+v", result)
			}
			assertNativeArtifactsUseRawQLOG(t, root, result)
		})
	}
}

func assertNativeArtifactsUseRawQLOG(t *testing.T, reportDirectory string, result releaseCaseResult) {
	t.Helper()
	if len(result.RawSources) != 1 || result.RawSources[0].ID != "qlog-001" || result.RawSources[0].Kind != "qlog" {
		t.Fatalf("native raw source inventory = %+v", result.RawSources)
	}
	artifacts := make(map[string]releaseArtifact, len(result.Artifacts))
	for _, artifact := range result.Artifacts {
		artifacts[artifact.Kind] = artifact
	}
	qlog, err := os.ReadFile(filepath.Join(reportDirectory, filepath.FromSlash(result.RawSources[0].Path)))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(qlog, []byte{0x1e}) || bytes.Contains(qlog, []byte("application:")) {
		t.Fatal("native qlog is not raw transport-only quic-go JSON-SEQ")
	}
	for _, frame := range requiredRawQLOGFrames(result.ID) {
		if !bytes.Contains(qlog, []byte(`"frame_type":"`+frame+`"`)) {
			t.Fatalf("raw qlog for %s is missing %s", result.ID, frame)
		}
	}
	connectionID, _, err := inspectNativeQLOG(qlog)
	if err != nil {
		t.Fatal(err)
	}
	traceData, err := os.ReadFile(filepath.Join(reportDirectory, filepath.FromSlash(artifacts["trace"].Path)))
	if err != nil {
		t.Fatal(err)
	}
	var trace rawTraceArtifact
	if err := json.Unmarshal(traceData, &trace); err != nil {
		t.Fatal(err)
	}
	if len(trace.Records) < 2 || trace.Records[len(trace.Records)-1].Event != "completed" {
		t.Fatal("native application trace is missing observations or completion")
	}
	for _, record := range trace.Records {
		if record.ConnectionID != connectionID {
			t.Fatalf("trace connection ID = %q, want raw qlog group %q", record.ConnectionID, connectionID)
		}
	}
	configData, err := os.ReadFile(filepath.Join(reportDirectory, filepath.FromSlash(artifacts["config"].Path)))
	if err != nil {
		t.Fatal(err)
	}
	var config rawConfigArtifact
	if err := json.Unmarshal(configData, &config); err != nil {
		t.Fatal(err)
	}
	values := make(map[string]string, len(config.Records))
	for _, record := range config.Records {
		values[record.Key] = record.Value
	}
	if values["qlog_source"] != "quic-go-json-seq-v0.3" || values["qlog_sha256"] != artifacts["qlog"].SHA256 || values["qlog_connection_id"] != connectionID {
		t.Fatalf("native config does not bind raw qlog: %+v", values)
	}
}

func requiredRawQLOGFrames(id string) []string {
	switch id {
	case "NS-N2", "NS-N4", "NP-FLOW-FULL":
		return []string{"stream_data_blocked"}
	case "NS-N3", "NP-RESET-FIN":
		return []string{"reset_stream", "stop_sending"}
	case "NP-MAXDATA":
		return []string{"data_blocked"}
	case "NP-STREAM-LIMIT":
		return []string{"streams_blocked"}
	default:
		return nil
	}
}

func nativeCaseArtifactKinds(id string) []string {
	if id == "NS-N1" {
		return []string{"trace", "qlog", "config"}
	}
	return []string{"trace", "qlog", "metrics", "config"}
}

func TestConformanceFullCasesUseProductionCarriers(t *testing.T) {
	for _, definition := range conformanceFullCases {
		t.Run(definition.ID, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			result, err := runConformanceSmokeCase(ctx, definition)
			if err != nil {
				t.Fatal(err)
			}
			if result.CompletedOperations != 1 || result.NegotiatedSuite != definition.Suite {
				t.Fatalf("case result = %+v", result)
			}
		})
	}
}

func TestCaseSuitePublishesExactWeaknetAndConformanceFullResults(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the release case report records the native Linux kernel")
	}
	for _, owner := range []string{weaknetFullOwner, conformanceFullOwner, quicNativeSmokeOwner} {
		t.Run(owner, func(t *testing.T) {
			root, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			artifacts := filepath.Join(root, "artifacts")
			if err := os.Mkdir(artifacts, 0o700); err != nil {
				t.Fatal(err)
			}
			reportPath := filepath.Join(root, "report.json")
			destination, err := newArtifactDestination(artifacts, reportPath)
			if err != nil {
				t.Fatal(err)
			}
			defer destination.Close()
			manifest := transportrelease.ManifestBinding{Digest: transportrelease.FrozenPerformanceManifestDigest}
			if err := runCaseSuite(reportPath, destination, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "", owner, "normal", "", "", transportrelease.ReleasePlan{}, manifest); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(reportPath)
			if err != nil {
				t.Fatal(err)
			}
			var report caseSuiteReport
			if err := json.Unmarshal(data, &report); err != nil {
				t.Fatal(err)
			}
			definitions, err := registeredCasesForOwner(owner, "normal")
			if err != nil {
				t.Fatal(err)
			}
			if len(report.Results) != len(definitions) {
				t.Fatalf("results = %d, want %d", len(report.Results), len(definitions))
			}
			for index, result := range report.Results {
				if result.ID != definitions[index].ID || result.Status != "pass" || result.CompletedOperations < 1 {
					t.Fatalf("result %d = %+v", index, result)
				}
			}
		})
	}
}
