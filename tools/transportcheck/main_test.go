package main

import (
	"bytes"
	"cmp"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

var cachedCompleteReport struct {
	sync.Once
	report *EvidenceReport
}

func TestMain(m *testing.M) {
	code := m.Run()
	if cachedCompleteReport.report != nil {
		_ = os.RemoveAll(cachedCompleteReport.report.baseDir)
	}
	os.Exit(code)
}

func TestCheckedInManifestAndRegistryAreValid(t *testing.T) {
	manifest := loadFixtureManifest(t)
	if err := validateManifest(manifest); err != nil {
		t.Fatalf("validate manifest: %v", err)
	}
	registry := loadFixtureRegistry(t)
	if err := validateCaseRegistry(registry); err != nil {
		t.Fatalf("validate registry: %v", err)
	}
}

func TestCheckedInRegistryOwnersHaveMakeRecipes(t *testing.T) {
	registry := loadFixtureRegistry(t)
	makefile := filepath.Join(filepath.Dir(fixturePath(t, "case_registry.json")), "..", "..", "Makefile")
	if err := validateCaseOwnerRecipes(registry, makefile); err != nil {
		t.Fatalf("validate checked-in owner recipes: %v", err)
	}
}

func TestCaseOwnerRecipeValidationRejectsAllowlistedTargetWithoutRecipe(t *testing.T) {
	registry := &CaseRegistry{
		SchemaVersion: 1,
		Cases: []CaseDefinition{{ID: "CAP-SOAK-HOURLY", Owner: "bench-transport-soak", Mode: "normal", Required: true, Profile: "soak", EvidenceFields: []string{"trace"}}},
	}
	makefile := filepath.Join(t.TempDir(), "Makefile")
	if err := os.WriteFile(makefile, []byte(".PHONY: bench-transport-soak\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := validateCaseOwnerRecipes(registry, makefile); err == nil || !strings.Contains(err.Error(), "bench-transport-soak") {
		t.Fatalf("validateCaseOwnerRecipes() error = %v, want missing recipe", err)
	}
}

func TestCaseOwnerRecipeValidationAcceptsMultiTargetRecipeAndRaceOwner(t *testing.T) {
	registry := &CaseRegistry{
		SchemaVersion: 1,
		Cases: []CaseDefinition{{ID: "CAP-SOAK-HOURLY", Owner: "bench-transport-soak", RaceOwner: "quic-native-race", Mode: "normal", Required: true, Profile: "soak", EvidenceFields: []string{"trace"}}},
	}
	makefile := filepath.Join(t.TempDir(), "Makefile")
	contents := "bench-transport-soak quic-native-race:\n\t@true\n"
	if err := os.WriteFile(makefile, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := validateCaseOwnerRecipes(registry, makefile); err != nil {
		t.Fatalf("validateCaseOwnerRecipes() error = %v", err)
	}
}

func TestCheckedInEvidenceTrustPolicyPinsExactRunner(t *testing.T) {
	policy, err := loadEvidenceTrustPolicy(fixturePath(t, "evidence_trust_policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	if policy.Runner.KernelRelease != signedRunnerKernelRelease || policy.Runner.EffectiveConfigSHA256 != signedRunnerConfigDigest {
		t.Fatalf("checked-in runner policy = %+v, want exact audited kernel/config", policy.Runner)
	}
	storePath := fixturePath(t, "evidence_trust_store.json")
	store, err := loadEvidenceTrustStore(storePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateTrustStoreAgainstPolicy(storePath, store, policy); err != nil {
		t.Fatal(err)
	}
}

func TestManifestRejectsInvalidFrozenContract(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*PerformanceManifest)
		wantErr string
	}{
		{
			name: "run count",
			mutate: func(manifest *PerformanceManifest) {
				manifest.RunCount = 14
			},
			wantErr: "run_count",
		},
		{
			name: "ratio formula version",
			mutate: func(manifest *PerformanceManifest) {
				manifest.RatioFormulaVersion = "mutable"
			},
			wantErr: "ratio_formula_version",
		},
		{
			name: "bootstrap resamples",
			mutate: func(manifest *PerformanceManifest) {
				manifest.Bootstrap.Resamples = 9999
			},
			wantErr: "bootstrap resamples",
		},
		{
			name: "bootstrap seed",
			mutate: func(manifest *PerformanceManifest) {
				manifest.Bootstrap.Seed++
			},
			wantErr: "bootstrap seed",
		},
		{
			name: "bootstrap cluster",
			mutate: func(manifest *PerformanceManifest) {
				manifest.Bootstrap.Cluster = "sample"
			},
			wantErr: "run-cluster",
		},
		{
			name: "cold operations",
			mutate: func(manifest *PerformanceManifest) {
				profileByID(t, manifest, "clean-v1").Cold.Operations--
			},
			wantErr: "cold operations",
		},
		{
			name: "cold inflight",
			mutate: func(manifest *PerformanceManifest) {
				profileByID(t, manifest, "mobile-v1").Cold.MaxInflight++
			},
			wantErr: "max_inflight",
		},
		{
			name: "cold retry",
			mutate: func(manifest *PerformanceManifest) {
				profileByID(t, manifest, "edge-v1").Cold.Retries = 1
			},
			wantErr: "cold retries",
		},
		{
			name: "clean start rate",
			mutate: func(manifest *PerformanceManifest) {
				profileByID(t, manifest, "clean-v1").Cold.StartRatePerSecond--
			},
			wantErr: "start_rate_per_second",
		},
		{
			name: "mobile start rate",
			mutate: func(manifest *PerformanceManifest) {
				profileByID(t, manifest, "mobile-v1").Cold.StartRatePerSecond--
			},
			wantErr: "start_rate_per_second",
		},
		{
			name: "edge start rate",
			mutate: func(manifest *PerformanceManifest) {
				profileByID(t, manifest, "edge-v1").Cold.StartRatePerSecond--
			},
			wantErr: "start_rate_per_second",
		},
		{
			name: "RPC operations",
			mutate: func(manifest *PerformanceManifest) {
				profileByID(t, manifest, "clean-v1").RPC.Operations++
			},
			wantErr: "RPC operations",
		},
		{
			name: "RPC request bytes",
			mutate: func(manifest *PerformanceManifest) {
				profileByID(t, manifest, "mobile-v1").RPC.RequestBytes++
			},
			wantErr: "request_bytes",
		},
		{
			name: "RPC response bytes",
			mutate: func(manifest *PerformanceManifest) {
				profileByID(t, manifest, "mobile-v1").RPC.ResponseBytes++
			},
			wantErr: "response_bytes",
		},
		{
			name: "RPC workers",
			mutate: func(manifest *PerformanceManifest) {
				profileByID(t, manifest, "edge-v1").RPC.Workers--
			},
			wantErr: "workers",
		},
		{
			name: "clean bulk bytes",
			mutate: func(manifest *PerformanceManifest) {
				profileByID(t, manifest, "clean-v1").Bulk.ScoreBytesPerDirection--
			},
			wantErr: "bulk bytes",
		},
		{
			name: "mobile bulk bytes",
			mutate: func(manifest *PerformanceManifest) {
				profileByID(t, manifest, "mobile-v1").Bulk.WarmupBytesPerDirection--
			},
			wantErr: "bulk bytes",
		},
		{
			name: "edge bulk bytes",
			mutate: func(manifest *PerformanceManifest) {
				profileByID(t, manifest, "edge-v1").Bulk.ScoreBytesPerDirection--
			},
			wantErr: "bulk bytes",
		},
		{
			name: "operation deadline",
			mutate: func(manifest *PerformanceManifest) {
				profileByID(t, manifest, "edge-v1").Cold.OperationDeadlineSeconds--
			},
			wantErr: "operation deadline",
		},
		{
			name: "phase deadline",
			mutate: func(manifest *PerformanceManifest) {
				profileByID(t, manifest, "mobile-v1").RPC.PhaseDeadlineSeconds--
			},
			wantErr: "phase deadline",
		},
		{
			name: "cell watchdog",
			mutate: func(manifest *PerformanceManifest) {
				profileByID(t, manifest, "clean-v1").CellWatchdogMinutes++
			},
			wantErr: "cell watchdog",
		},
		{
			name: "adaptive RPC present",
			mutate: func(manifest *PerformanceManifest) {
				profileByID(t, manifest, "adaptive-selection-v1").RPC = &RPCWorkload{Operations: 2000}
			},
			wantErr: "adaptive profile must not define RPC or bulk",
		},
		{
			name: "adaptive stage missing",
			mutate: func(manifest *PerformanceManifest) {
				profile := profileByID(t, manifest, "adaptive-selection-v1")
				profile.AdaptiveStages = profile.AdaptiveStages[:1]
			},
			wantErr: "adaptive stages",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manifest := loadFixtureManifest(t)
			test.mutate(manifest)
			refreshManifestDigest(t, manifest)
			err := validateManifest(manifest)
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("validateManifest() error = %v, want containing %q", err, test.wantErr)
			}
		})
	}
}

func TestManifestDigestIsCanonicalAndTamperEvident(t *testing.T) {
	manifest := loadFixtureManifest(t)
	originalDigest := manifest.Digest
	manifest.RunCount--
	if err := validateManifest(manifest); err == nil || !strings.Contains(err.Error(), "digest") {
		t.Fatalf("tampered manifest error = %v, want digest mismatch", err)
	}

	manifest = loadFixtureManifest(t)
	data, err := canonicalManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	var reformatted PerformanceManifest
	if err := json.Unmarshal(data, &reformatted); err != nil {
		t.Fatal(err)
	}
	reformatted.Digest = originalDigest
	if err := validateManifestDigest(&reformatted); err != nil {
		t.Fatalf("canonical digest changed after reformatting: %v", err)
	}
}

func TestBootstrapMeanConstantDistributionIsExact(t *testing.T) {
	manifest := loadFixtureManifest(t)
	values := make([]float64, manifest.RunCount)
	for index := range values {
		values[index] = 42.5
	}
	estimate, lower, upper := bootstrapMean(values, manifest.Bootstrap, "constant-cell", "constant-metric")
	if estimate != 42.5 || lower != 42.5 || upper != 42.5 {
		t.Fatalf("constant bootstrap = %g [%g, %g], want 42.5 [42.5, 42.5]", estimate, lower, upper)
	}
}

func TestManifestRejectsInconsistentBudgetsAndLPTOverflow(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*PerformanceManifest)
		wantErr string
	}{
		{
			name: "cold cap cannot cover schedule tail",
			mutate: func(manifest *PerformanceManifest) {
				profileByID(t, manifest, "clean-v1").Cold.PhaseDeadlineSeconds = 29
			},
			wantErr: "cold phase cannot cover",
		},
		{
			name: "cell duration differs from profile watchdog",
			mutate: func(manifest *PerformanceManifest) {
				manifest.Cells[0].DurationMinutes++
			},
			wantErr: "does not match profile",
		},
		{
			name: "cell watchdog cannot cover phases",
			mutate: func(manifest *PerformanceManifest) {
				profileByID(t, manifest, "mobile-v1").CellWatchdogMinutes--
				for index := range manifest.Cells {
					if manifest.Cells[index].ProfileID == "mobile-v1" {
						manifest.Cells[index].DurationMinutes--
					}
				}
			},
			wantErr: "cannot cover phase deadlines",
		},
		{
			name: "insufficient global watchdog",
			mutate: func(manifest *PerformanceManifest) {
				manifest.GlobalWatchdogMinutes--
			},
			wantErr: "global watchdog",
		},
		{
			name: "global watchdog cannot be loosened",
			mutate: func(manifest *PerformanceManifest) {
				manifest.GlobalWatchdogMinutes++
			},
			wantErr: "must equal recomputed",
		},
		{
			name: "job set exceeds preregistered limit",
			mutate: func(manifest *PerformanceManifest) {
				cell := manifest.Cells[len(manifest.Cells)-1]
				cell.ID = "clean-11"
				manifest.Cells = append(manifest.Cells, cell)
			},
			wantErr: "exceeds preregistered limit",
		},
		{
			name: "actual eligible lanes overflow limit",
			mutate: func(manifest *PerformanceManifest) {
				manifest.EligibleLaneCount = 3
				manifest.GlobalWatchdogMinutes = manifest.MaximumLaneMinutes
			},
			wantErr: "480 minutes",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manifest := loadFixtureManifest(t)
			test.mutate(manifest)
			refreshManifestDigest(t, manifest)
			err := validateManifest(manifest)
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("validateManifest() error = %v, want containing %q", err, test.wantErr)
			}
		})
	}
}

func TestReferenceManifestRecomputesSignedLPTLoads(t *testing.T) {
	manifest := loadFixtureManifest(t)
	loads, err := allocateLPT(manifest.Cells, manifest.EligibleLaneCount)
	if err != nil {
		t.Fatal(err)
	}
	want := []int{405, 405, 410, 415, 415, 415}
	if !equalInts(loads, want) {
		t.Fatalf("LPT loads = %v, want %v", loads, want)
	}
}

func TestReferenceManifestGivesWebTransportEqualForcedAndAdaptiveCoverage(t *testing.T) {
	manifest := loadFixtureManifest(t)
	want := map[string]map[string]bool{
		"clean-v1": {
			"browser_webtransport": true, "browser_tunnel_wt_wss": true, "browser_tunnel_wt_quic": true,
		},
		"mobile-v1": {
			"browser_webtransport": true, "browser_tunnel_wt_wss": true, "browser_tunnel_wt_quic": true,
		},
		"edge-v1": {
			"browser_webtransport": true, "browser_tunnel_wt_wss": true, "browser_tunnel_wt_quic": true,
		},
		"adaptive-selection-v1": {"adaptive_native": true, "adaptive_web": true},
	}
	for _, cell := range manifest.Cells {
		delete(want[cell.ProfileID], cell.Topology)
	}
	for profileID, missing := range want {
		if len(missing) != 0 {
			t.Fatalf("profile %s is missing equal WebTransport coverage: %v", profileID, missing)
		}
	}
	web := manifestCellByID(t, manifest, "adaptive-selection-02")
	if web.Policy != "Adaptive" || !sameStringSet(web.SupportedCandidates, []string{"runtime-wss", "runtime-webtransport"}) {
		t.Fatalf("web adaptive cell = %+v, want equal WSS/WebTransport candidate race", web)
	}
}

func TestManifestRejectsNetworkProfileAndCellCoverageDrift(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*PerformanceManifest)
		wantErr string
	}{
		{
			name: "mobile delay",
			mutate: func(manifest *PerformanceManifest) {
				profileByID(t, manifest, "mobile-v1").Network.OneWayDelayMilliseconds++
			},
			wantErr: "mobile-v1 network profile",
		},
		{
			name: "edge jitter",
			mutate: func(manifest *PerformanceManifest) {
				profileByID(t, manifest, "edge-v1").Network.JitterMilliseconds[1]++
			},
			wantErr: "edge-v1 network profile",
		},
		{
			name: "clean must be explicitly unshaped",
			mutate: func(manifest *PerformanceManifest) {
				profileByID(t, manifest, "clean-v1").Network.Shape = &NetworkShape{}
			},
			wantErr: "clean-v1 network profile",
		},
		{
			name: "clean network field omitted",
			mutate: func(manifest *PerformanceManifest) {
				profileByID(t, manifest, "clean-v1").networkPresent = false
			},
			wantErr: "explicitly include network",
		},
		{
			name: "clean shape field omitted",
			mutate: func(manifest *PerformanceManifest) {
				profileByID(t, manifest, "clean-v1").Network.shapePresent = false
			},
			wantErr: "explicitly include network and shape",
		},
		{
			name: "adaptive network field omitted",
			mutate: func(manifest *PerformanceManifest) {
				profileByID(t, manifest, "adaptive-selection-v1").networkPresent = false
			},
			wantErr: "explicitly declare network",
		},
		{
			name: "missing tunnel topology",
			mutate: func(manifest *PerformanceManifest) {
				for index := range manifest.Cells {
					if manifest.Cells[index].ProfileID == "clean-v1" && manifest.Cells[index].Topology == "qw" {
						manifest.Cells[index].Topology = "direct_quic"
						break
					}
				}
			},
			wantErr: "missing required topology qw",
		},
		{
			name: "missing browser cell",
			mutate: func(manifest *PerformanceManifest) {
				for index := range manifest.Cells {
					if manifest.Cells[index].Topology == "browser_webtransport" {
						manifest.Cells[index].Topology = "direct_quic"
						break
					}
				}
			},
			wantErr: "missing required topology browser_webtransport",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manifest := loadFixtureManifest(t)
			test.mutate(manifest)
			refreshManifestDigest(t, manifest)
			err := validateManifest(manifest)
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("validateManifest() error = %v, want containing %q", err, test.wantErr)
			}
		})
	}
}

func TestEvidenceRequiresFifteenMetricSamplesAndAdverseCI(t *testing.T) {
	tests := []struct {
		name       string
		mutate     func(*PerformanceManifest, *EvidenceReport)
		wantStatus checkStatus
		wantIssue  string
	}{
		{
			name: "missing metric",
			mutate: func(manifest *PerformanceManifest, report *EvidenceReport) {
				cell := &report.Cells[0]
				delete(cell.Metrics, manifestCellByID(t, manifest, cell.CellID).RequiredMetrics[0])
			},
			wantStatus: statusInconclusive,
			wantIssue:  "missing metric",
		},
		{
			name: "metric samples below 15",
			mutate: func(manifest *PerformanceManifest, report *EvidenceReport) {
				cell := &report.Cells[0]
				id := manifestCellByID(t, manifest, cell.CellID).RequiredMetrics[0]
				metric := cell.Metrics[id]
				metric.Samples = 14
				cell.Metrics[id] = metric
			},
			wantStatus: statusInconclusive,
			wantIssue:  "exactly 15 run-cluster samples",
		},
		{
			name: "upper CI crosses threshold",
			mutate: func(manifest *PerformanceManifest, report *EvidenceReport) {
				cell := evidenceCellByID(t, report, "mobile-02")
				contract := metricContractByID(t, manifest, "mobile_migration_first_rpc_ms")
				setMetricSamples(t, manifest, report, cell, contract.ID, *contract.Threshold+0.01)
			},
			wantStatus: statusInconclusive,
			wantIssue:  "upper CI",
		},
		{
			name: "lower CI crosses threshold",
			mutate: func(manifest *PerformanceManifest, report *EvidenceReport) {
				cell := evidenceCellByID(t, report, "clean-01")
				contract := metricContractByID(t, manifest, "clean_revision_throughput_ratio")
				setMetricSamples(t, manifest, report, cell, contract.ID, *contract.Threshold-0.01)
			},
			wantStatus: statusInconclusive,
			wantIssue:  "lower CI",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manifest := loadFixtureManifest(t)
			registry := loadFixtureRegistry(t)
			report := completeReport(t, manifest, registry)
			test.mutate(manifest, report)
			result := checkEvidence(manifest, registry, report, report.baseDir)
			assertResult(t, result, test.wantStatus, test.wantIssue)
		})
	}
}

func metricContractByID(t *testing.T, manifest *PerformanceManifest, id string) MetricContract {
	t.Helper()
	for _, contract := range manifest.MetricContracts {
		if contract.ID == id {
			return contract
		}
	}
	t.Fatalf("metric contract %s not found", id)
	return MetricContract{}
}

func TestCaseRegistryRejectsInvalidOwnership(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*CaseRegistry)
		wantErr string
	}{
		{
			name: "duplicate normal ID",
			mutate: func(registry *CaseRegistry) {
				registry.Cases = append(registry.Cases, registry.Cases[0])
			},
			wantErr: "duplicate case ID",
		},
		{
			name: "missing owner",
			mutate: func(registry *CaseRegistry) {
				registry.Cases[0].Owner = ""
			},
			wantErr: "exactly one owner",
		},
		{
			name: "missing evidence field",
			mutate: func(registry *CaseRegistry) {
				registry.Cases[0].EvidenceFields = nil
			},
			wantErr: "evidence_fields",
		},
		{
			name: "unregistered owner target",
			mutate: func(registry *CaseRegistry) {
				registry.Cases[0].Owner = "unknown-smoke-target"
			},
			wantErr: "is not registered",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			registry := loadFixtureRegistry(t)
			test.mutate(registry)
			err := validateCaseRegistry(registry)
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("validateCaseRegistry() error = %v, want containing %q", err, test.wantErr)
			}
		})
	}
}

func TestEvidenceAcceptsCompleteSyntheticUnitEvidence(t *testing.T) {
	manifest := loadFixtureManifest(t)
	registry := loadFixtureRegistry(t)
	report := completeReport(t, manifest, registry)
	result := checkEvidence(manifest, registry, report, report.baseDir)
	if result.Status != statusPass || len(result.Issues) != 0 {
		t.Fatalf("result = %#v, want pass", result)
	}
}

func TestPhaseFaultMetricUnitsAreSemantic(t *testing.T) {
	if got := phaseFaultMetricUnit("fault_outage_duration_ns"); got != "nanoseconds" {
		t.Fatalf("phaseFaultMetricUnit(fault_outage_duration_ns) = %q, want nanoseconds", got)
	}
	if got := phaseFaultMetricUnit("fault_outage_events"); got != "count" {
		t.Fatalf("phaseFaultMetricUnit(fault_outage_events) = %q, want count", got)
	}
}

func TestTraceArtifactsRequireStrictlyIncreasingTimestamps(t *testing.T) {
	context := "strict trace timestamps"
	data, err := json.Marshal(TraceArtifact{
		SchemaVersion: 1, Kind: "transport_trace", Context: context,
		Records: []TraceRecord{
			{Sequence: 1, AtNS: 2, Event: "second", Digest: strings.Repeat("a", 64)},
			{Sequence: 2, AtNS: 1, Event: "first", Digest: strings.Repeat("b", 64)},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := validateTypedStructuredArtifact(context, "trace", data); err == nil {
		t.Fatal("validateTypedStructuredArtifact() accepted non-monotonic trace timestamps")
	}
}

func TestRequiredCaseIdentityBindsCaseArtifacts(t *testing.T) {
	manifest := loadFixtureManifest(t)
	registry := loadFixtureRegistry(t)
	report := completeReport(t, manifest, registry)
	evidence := caseEvidenceByID(t, report, "CS-C1")
	rewriteOrAddCaseConfigValue(t, report, evidence, "case_id", "CS-C2")
	result := checkEvidence(manifest, registry, report, report.baseDir)
	assertResult(t, result, statusFail, "case identity")
}

func TestRaceCaseRequiresExecutionAttestation(t *testing.T) {
	manifest := loadFixtureManifest(t)
	registry := loadFixtureRegistry(t)
	report := completeReport(t, manifest, registry)
	evidence := caseEvidenceByModeAndID(t, report, "race", "NS-N2")
	evidence.Execution = nil
	result := checkEvidence(manifest, registry, report, report.baseDir)
	assertResult(t, result, statusFail, "execution attestation")
}

func TestTDDEvidenceRequiresRawStageOutput(t *testing.T) {
	manifest := loadFixtureManifest(t)
	registry := loadFixtureRegistry(t)
	report := completeReport(t, manifest, registry)
	report.TDD[0].Red.OutputArtifact = EvidenceArtifact{}
	result := checkEvidence(manifest, registry, report, report.baseDir)
	assertResult(t, result, statusFail, "TDD slice "+report.TDD[0].Slice+" red stage output")
}

func TestOutageMetricRequiresSameRunFaultBinding(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*MetricFaultBinding)
	}{
		{name: "missing binding", mutate: func(binding *MetricFaultBinding) { *binding = MetricFaultBinding{} }},
		{name: "carrier identity", mutate: func(binding *MetricFaultBinding) { binding.Carrier = "raw_quic" }},
		{name: "reorder matrix", mutate: func(binding *MetricFaultBinding) { binding.ReorderPercent++ }},
		{name: "schedule", mutate: func(binding *MetricFaultBinding) { binding.RecoveryAtNS++ }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manifest := loadFixtureManifest(t)
			registry := loadFixtureRegistry(t)
			report := completeReport(t, manifest, registry)
			cell := evidenceCellByID(t, report, "mobile-01")
			rewriteMetricSamplesArtifact(t, report, cell, "mobile_outage_recovery_overhead_ms", func(samples *MetricSamplesArtifact) {
				if samples.Runs[0].FaultBinding == nil {
					t.Fatal("fixture fault binding is missing")
				}
				test.mutate(samples.Runs[0].FaultBinding)
			})
			result := checkEvidence(manifest, registry, report, report.baseDir)
			assertResult(t, result, statusFail, "fault binding")
		})
	}
}

func TestFaultMetricQlogBindingMatchesPhaseArtifacts(t *testing.T) {
	tests := []struct {
		name   string
		cellID string
		mutate func(*MetricFaultBinding)
	}{
		{name: "required qlog omitted", cellID: "mobile-02", mutate: func(binding *MetricFaultBinding) { binding.QlogSHA256 = "" }},
		{name: "unexpected qlog on WebSocket", cellID: "mobile-01", mutate: func(binding *MetricFaultBinding) { binding.QlogSHA256 = strings.Repeat("a", 64) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manifest := loadFixtureManifest(t)
			registry := loadFixtureRegistry(t)
			report := completeReport(t, manifest, registry)
			cell := evidenceCellByID(t, report, test.cellID)
			rewriteMetricSamplesArtifact(t, report, cell, "mobile_outage_recovery_overhead_ms", func(samples *MetricSamplesArtifact) {
				if samples.Runs[0].FaultBinding == nil {
					t.Fatal("fixture fault binding is missing")
				}
				test.mutate(samples.Runs[0].FaultBinding)
			})
			assertResult(t, checkEvidence(manifest, registry, report, report.baseDir), statusFail, "fault binding qlog")
		})
	}
}

func TestMigrationMetricRejectsOutageEventSubstitution(t *testing.T) {
	manifest := loadFixtureManifest(t)
	registry := loadFixtureRegistry(t)
	report := completeReport(t, manifest, registry)
	cell := evidenceCellByID(t, report, "mobile-02")
	rewriteMetricSamplesArtifact(t, report, cell, "mobile_migration_first_rpc_ms", func(samples *MetricSamplesArtifact) {
		binding := samples.Runs[0].FaultBinding
		if binding == nil {
			t.Fatal("fixture fault binding is missing")
		}
		binding.Event = "outage_started"
		binding.RecoveryEvent = "outage_recovered"
		binding.StartAtNS = 1e9
	})
	assertResult(t, checkEvidence(manifest, registry, report, report.baseDir), statusFail, "fault binding event contract")
}

func TestFaultMetricRejectsUnboundFirstRPCDuration(t *testing.T) {
	manifest := loadFixtureManifest(t)
	registry := loadFixtureRegistry(t)
	report := completeReport(t, manifest, registry)
	cell := evidenceCellByID(t, report, "mobile-02")
	rewriteMetricSamplesArtifact(t, report, cell, "mobile_migration_first_rpc_ms", func(samples *MetricSamplesArtifact) {
		binding := samples.Runs[0].FaultBinding
		if binding == nil {
			t.Fatal("fixture fault binding is missing")
		}
		binding.FirstRPCAtNS++
	})
	assertResult(t, checkEvidence(manifest, registry, report, report.baseDir), statusFail, "post-recovery RPC")
}

func TestMigrationMetricRequiresPostValidationRPCTrace(t *testing.T) {
	manifest := loadFixtureManifest(t)
	registry := loadFixtureRegistry(t)
	report := completeReport(t, manifest, registry)
	cell := evidenceCellByID(t, report, "mobile-02")
	rewritePerformanceFaultTrace(t, report, cell, 1, func(trace *TraceArtifact) {
		trace.Records = slices.DeleteFunc(trace.Records, func(record TraceRecord) bool {
			return record.Event == "rpc_completed" && record.MetricID == "mobile_migration_first_rpc_ms"
		})
	})
	assertResult(t, checkEvidence(manifest, registry, report, report.baseDir), statusFail, "fault trace contains")
}

func TestMigrationMetricRequiresSharedRequestIdentity(t *testing.T) {
	manifest := loadFixtureManifest(t)
	registry := loadFixtureRegistry(t)
	report := completeReport(t, manifest, registry)
	cell := evidenceCellByID(t, report, "mobile-02")
	rewriteMetricSamplesArtifact(t, report, cell, "mobile_migration_first_rpc_ms", func(samples *MetricSamplesArtifact) {
		binding := samples.Runs[0].FaultBinding
		if binding == nil {
			t.Fatal("fixture fault binding is missing")
		}
		binding.RequestID = "different-request"
	})
	assertResult(t, checkEvidence(manifest, registry, report, report.baseDir), statusFail, "request identity")
}

func TestMigrationMetricRequiresSharedQlogRPCTimestamp(t *testing.T) {
	manifest := loadFixtureManifest(t)
	registry := loadFixtureRegistry(t)
	report := completeReport(t, manifest, registry)
	cell := evidenceCellByID(t, report, "mobile-02")
	rewritePerformanceMigrationQlog(t, report, cell, 1, func(fields []any) {
		fields[0] = fields[0].(float64) + 1
	})
	assertResult(t, checkEvidence(manifest, registry, report, report.baseDir), statusFail, "migration qlog does not prove")
}

func TestEvidenceRejectsSyntheticStatusOnlyReleaseEvidence(t *testing.T) {
	manifest := loadFixtureManifest(t)
	registry := loadFixtureRegistry(t)
	report := completeReport(t, manifest, registry)
	phase := &report.Cells[0].Runs[0].Phases[0]
	data := []byte(fmt.Sprintf(`{"schema_version":1,"kind":"transport_trace","context":%q,"records":[{"status":"pass"}]}`, "cell edge-01 run 1 phase edge-v1/cold"))
	phase.Artifacts["trace"] = rewriteEvidenceArtifact(t, report.baseDir, phase.Artifacts["trace"], data)
	result := checkEvidence(manifest, registry, report, report.baseDir)
	assertResult(t, result, statusFail, "typed operation records")
}

func TestEvidenceRejectsArtifactReuseAcrossContexts(t *testing.T) {
	manifest := loadFixtureManifest(t)
	registry := loadFixtureRegistry(t)
	report := completeReport(t, manifest, registry)
	first := report.Cells[0].Runs[0].Phases[0].Artifacts["pcap"]
	report.Cells[0].Runs[0].Phases[1].Artifacts["pcap"] = first
	result := checkEvidence(manifest, registry, report, report.baseDir)
	assertResult(t, result, statusFail, "reuses artifact path across report")
}

func TestEvidenceRejectsArtifactDigestReuseAcrossContexts(t *testing.T) {
	manifest := loadFixtureManifest(t)
	registry := loadFixtureRegistry(t)
	report := completeReport(t, manifest, registry)
	cell := &report.Cells[0]
	run := &cell.Runs[0]
	first := run.Phases[0].Artifacts["pcap"]
	data, err := os.ReadFile(filepath.Join(report.baseDir, first.Path))
	if err != nil {
		t.Fatal(err)
	}
	second := &run.Phases[1]
	context := fmt.Sprintf("cell %s run %d phase %s/%s", cell.CellID, run.RunNumber, second.ProfileID, second.Phase)
	second.Artifacts["pcap"] = writeEvidenceArtifact(t, report.baseDir, context, "pcap", ".pcap", data)

	result := checkEvidence(manifest, registry, report, report.baseDir)
	assertResult(t, result, statusFail, "reuses artifact digest across report")
}

func TestMetricProvenanceCannotBindAnotherCellInTheSameRun(t *testing.T) {
	manifest := loadFixtureManifest(t)
	registry := loadFixtureRegistry(t)
	report := completeReport(t, manifest, registry)
	cell := evidenceCellByID(t, report, "edge-01")
	other := evidenceCellByID(t, report, "edge-02")
	metric := cell.Metrics["connect_p50_ms"]
	data, err := os.ReadFile(filepath.Join(report.baseDir, metric.RawSamples.Path))
	if err != nil {
		t.Fatal(err)
	}
	var samples MetricSamplesArtifact
	if err := decodeStrictJSON(data, &samples); err != nil {
		t.Fatal(err)
	}
	samples.Runs[0].Sources[0] = metricSourcesForRun(t, other.CellID, "connect_p50_ms", &other.Runs[0])[0]
	data, err = json.Marshal(samples)
	if err != nil {
		t.Fatal(err)
	}
	metric.RawSamples = rewriteEvidenceArtifact(t, report.baseDir, metric.RawSamples, data)
	cell.Metrics["connect_p50_ms"] = metric
	result := checkEvidence(manifest, registry, report, report.baseDir)
	assertResult(t, result, statusFail, "same cell")
}

func TestMetricProvenanceRejectsTamperedResourceValuesAndBindings(t *testing.T) {
	t.Run("ratio value differs from bound resource", func(t *testing.T) {
		manifest := loadFixtureManifest(t)
		registry := loadFixtureRegistry(t)
		report := completeReport(t, manifest, registry)
		cell, metricID := cellMetricByDerivation(t, report, "ratio")
		rewriteMetricSamplesArtifact(t, report, cell, metricID, func(samples *MetricSamplesArtifact) {
			*samples.Runs[0].Numerator++
		})

		result := checkEvidence(manifest, registry, report, report.baseDir)
		assertResult(t, result, statusFail, "not recomputed from the frozen operand graph")
	})

	t.Run("ratio source digest differs from exact run resource", func(t *testing.T) {
		manifest := loadFixtureManifest(t)
		registry := loadFixtureRegistry(t)
		report := completeReport(t, manifest, registry)
		cell, metricID := cellMetricByDerivation(t, report, "ratio")
		rewriteMetricSamplesArtifact(t, report, cell, metricID, func(samples *MetricSamplesArtifact) {
			samples.Runs[0].OperandGraph[0].Source.ArtifactSHA256 = strings.Repeat("0", 64)
		})

		result := checkEvidence(manifest, registry, report, report.baseDir)
		assertResult(t, result, statusFail, "resource source does not bind exact field")
	})

	t.Run("resource measurement scope differs from exact variant", func(t *testing.T) {
		manifest := loadFixtureManifest(t)
		registry := loadFixtureRegistry(t)
		report := completeReport(t, manifest, registry)
		cell := evidenceCellByID(t, report, "clean-01")
		run := &cell.Runs[0]
		old := run.Resource
		data, err := os.ReadFile(filepath.Join(report.baseDir, old.Path))
		if err != nil {
			t.Fatal(err)
		}
		var resource ResourceArtifact
		if err := decodeStrictJSON(data, &resource); err != nil {
			t.Fatal(err)
		}
		for index := range resource.Measurements {
			if resource.Measurements[index].Name == "variant.candidate.cpu_nanoseconds" {
				resource.Measurements[index].VariantID = "base"
			}
		}
		data, err = json.Marshal(resource)
		if err != nil {
			t.Fatal(err)
		}
		run.Resource = rewriteEvidenceArtifact(t, report.baseDir, old, data)
		rebindMetricArtifactDigest(t, report, old.SHA256, run.Resource.SHA256)

		result := checkEvidence(manifest, registry, report, report.baseDir)
		assertResult(t, result, statusFail, "run resource field variant.candidate.cpu_nanoseconds is missing")
	})
}

func TestMetricProvenanceRejectsWrongOperationFieldOrPhase(t *testing.T) {
	tests := []struct {
		name       string
		derivation string
		mutate     func(*MetricSourceRef)
		wantIssue  string
	}{
		{
			name: "percentile field", derivation: "p50",
			mutate:    func(source *MetricSourceRef) { source.Field = "score_goodput" },
			wantIssue: "percentile source must use",
		},
		{
			name: "goodput phase", derivation: "goodput_mbps",
			mutate:    func(source *MetricSourceRef) { source.Phase = "cold" },
			wantIssue: "goodput must bind one bulk",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manifest := loadFixtureManifest(t)
			registry := loadFixtureRegistry(t)
			report := completeReport(t, manifest, registry)
			cell, metricID := cellMetricByDerivation(t, report, test.derivation)
			rewriteMetricSamplesArtifact(t, report, cell, metricID, func(samples *MetricSamplesArtifact) {
				test.mutate(&samples.Runs[0].Sources[0])
			})

			result := checkEvidence(manifest, registry, report, report.baseDir)
			assertResult(t, result, statusFail, test.wantIssue)
		})
	}
}

func TestPerformancePhaseConfigMustExactlyMatchFrozenNetwork(t *testing.T) {
	tests := []struct {
		name  string
		key   string
		value string
	}{
		{name: "manifest", key: "performance_manifest_digest", value: "sha256:" + strings.Repeat("0", 64)},
		{name: "profile", key: "effective_profile_id", value: "clean-v1"},
		{name: "phase", key: "phase", value: "rpc"},
		{name: "network JSON", key: "effective_network_json", value: `{}`},
		{name: "network digest", key: "effective_network_sha256", value: strings.Repeat("0", 64)},
		{name: "tc digest", key: "effective_tc_config_sha256", value: strings.Repeat("0", 64)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manifest := loadFixtureManifest(t)
			registry := loadFixtureRegistry(t)
			report := completeReport(t, manifest, registry)
			phase := &evidenceCellByID(t, report, "edge-01").Runs[0].Phases[0]
			data, err := os.ReadFile(filepath.Join(report.baseDir, phase.Artifacts["config"].Path))
			if err != nil {
				t.Fatal(err)
			}
			var artifact ConfigArtifact
			if err := decodeStrictJSON(data, &artifact); err != nil {
				t.Fatal(err)
			}
			for index := range artifact.Records {
				if artifact.Records[index].Key == test.key {
					artifact.Records[index].Value = test.value
				}
			}
			data, err = json.Marshal(artifact)
			if err != nil {
				t.Fatal(err)
			}
			phase.Artifacts["config"] = rewriteEvidenceArtifact(t, report.baseDir, phase.Artifacts["config"], data)

			result := checkEvidence(manifest, registry, report, report.baseDir)
			assertResult(t, result, statusFail, "effective network config does not match the frozen manifest")
		})
	}
}

func TestEveryPerformancePhaseBindsAndExercisesItsFrozenFaults(t *testing.T) {
	tests := []struct {
		name, cellID, counter, wantIssue string
		value                            float64
		bindDigest                       bool
	}{
		{name: "configured mobile loss unhit", cellID: "mobile-07", counter: "fault_periodic_loss_packets", value: 0, bindDigest: true, wantIssue: "configured phase fault"},
		{name: "configured edge burst unhit", cellID: "edge-08", counter: "fault_burst_loss_packets", value: 0, bindDigest: true, wantIssue: "configured phase fault"},
		{name: "clean profile injected fault", cellID: "clean-08", counter: "fault_delay_packets", value: 1, bindDigest: true, wantIssue: "outside the frozen network profile"},
		{name: "same-run metrics digest changed", cellID: "mobile-09", counter: "fault_delay_packets", value: 2, bindDigest: false, wantIssue: "effective network config"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manifest := loadFixtureManifest(t)
			registry := loadFixtureRegistry(t)
			report := completeReport(t, manifest, registry)
			phase := &evidenceCellByID(t, report, test.cellID).Runs[0].Phases[0]
			rewritePhaseMetricCounter(t, report, phase, test.counter, test.value, test.bindDigest)
			assertResult(t, checkEvidence(manifest, registry, report, report.baseDir), statusFail, test.wantIssue)
		})
	}
}

func TestRatioFormulaRejectsEveryScopeAndFormulaDrift(t *testing.T) {
	tests := []struct {
		name     string
		cellID   string
		metricID string
		mutate   func(*MetricRunSample)
		issue    string
	}{
		{name: "formula", cellID: "clean-03", metricID: "clean_quic_cold_p95_ratio", mutate: func(run *MetricRunSample) { run.Formula = "denominator/numerator" }, issue: "formula or operand graph shape"},
		{name: "cell", cellID: "clean-03", metricID: "clean_quic_cold_p95_ratio", mutate: func(run *MetricRunSample) { run.OperandGraph[1].Source.CellID = "clean-03" }, issue: "frozen cell/run/variant/profile/phase"},
		{name: "run", cellID: "clean-03", metricID: "clean_quic_cold_p95_ratio", mutate: func(run *MetricRunSample) { run.OperandGraph[0].Source.RunNumber++ }, issue: "frozen cell/run/variant/profile/phase"},
		{name: "variant", cellID: "clean-01", metricID: "clean_revision_cold_p95_ratio", mutate: func(run *MetricRunSample) { run.OperandGraph[0].Source.VariantID = "base" }, issue: "frozen cell/run/variant/profile/phase"},
		{name: "profile", cellID: "adaptive-selection-01", metricID: "adaptive_cold_formula_ratio", mutate: func(run *MetricRunSample) { run.OperandGraph[0].Source.ProfileID = "clean-v1" }, issue: "frozen cell/run/variant/profile/phase"},
		{name: "phase", cellID: "mobile-02", metricID: "mobile_native_interactive_vs_idle_ratio", mutate: func(run *MetricRunSample) { run.OperandGraph[0].Source.Phase = "cold" }, issue: "frozen cell/run/variant/profile/phase"},
		{name: "digest", cellID: "edge-01", metricID: "edge_cpu_per_delivered_byte_vs_clean_ratio", mutate: func(run *MetricRunSample) { run.OperandGraph[0].Source.ArtifactSHA256 = strings.Repeat("0", 64) }, issue: "resource source does not bind exact field"},
		{name: "operand", cellID: "adaptive-selection-01", metricID: "adaptive_cpu_connect_formula_ratio", mutate: func(run *MetricRunSample) { run.OperandGraph[0].Name = "denominator" }, issue: "frozen cell/run/variant/profile/phase"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manifest := loadFixtureManifest(t)
			registry := loadFixtureRegistry(t)
			report := completeReport(t, manifest, registry)
			cell := evidenceCellByID(t, report, test.cellID)
			rewriteMetricSamplesArtifact(t, report, cell, test.metricID, func(samples *MetricSamplesArtifact) {
				test.mutate(&samples.Runs[0])
			})
			result := checkEvidence(manifest, registry, report, report.baseDir)
			assertResult(t, result, statusFail, test.issue)
		})
	}
}

func TestPCAPPathAndPMTUDSemanticsAreConnectionCorrelated(t *testing.T) {
	t.Run("same IP port rebind", func(t *testing.T) {
		packets := [][]byte{
			syntheticIPPacketWithTuple(t, 4, 17, 1200, 1, 1001, 4433),
			syntheticIPPacketWithTuple(t, 4, 17, 1200, 1, 2001, 4433),
		}
		oldPath, newPath, remote, err := pcapUDPPathTransition(mustParsePCAP(t, encodeClassicPCAP(packets)), nil)
		if err != nil || oldPath.String() != "192.0.2.1:1001" || newPath.String() != "192.0.2.1:2001" || remote.String() != "198.51.100.1:4433" {
			t.Fatalf("transition = %s -> %s remote %s, error=%v", oldPath, newPath, remote, err)
		}
	})
	t.Run("unrelated UDP flow", func(t *testing.T) {
		packets := [][]byte{
			syntheticIPPacketWithTuple(t, 4, 17, 1200, 1, 1001, 4433),
			syntheticIPPacketWithTuple(t, 4, 17, 1200, 2, 2001, 8443),
		}
		if _, _, _, err := pcapUDPPathTransition(mustParsePCAP(t, encodeClassicPCAP(packets)), nil); err == nil {
			t.Fatal("unrelated UDP flow was accepted as migration")
		}
	})
	t.Run("PMTUD must be ordered on one tuple", func(t *testing.T) {
		packets := [][]byte{
			syntheticIPPacketWithTuple(t, 4, 17, 1200, 1, 1001, 4433),
			syntheticIPPacketWithTuple(t, 4, 17, 1301, 1, 1001, 4433),
		}
		if err := validateQUICPMTUDCapture(encodeClassicPCAP(packets), 4); err == nil {
			t.Fatal("reversed PMTUD sequence was accepted")
		}
	})
}

func TestPMTUDQuotedTupleAcceptsTheMinimumTransportHeaderQuote(t *testing.T) {
	for _, version := range []int{4, 6} {
		t.Run(fmt.Sprintf("IPv%d", version), func(t *testing.T) {
			oversized := syntheticIPPacketWithTuple(t, version, 17, 1301, 1, 1001, 4433)
			ptb := minimumICMPPTBQuote(t, version, oversized)
			constrained := syntheticIPPacketWithTuple(t, version, 17, 1200, 1, 1001, 4433)
			if err := validateQUICPMTUDCaptureForConnection(encodeClassicPCAP([][]byte{oversized, ptb, constrained}), version, true, "8394c8f03e515708"); err != nil {
				t.Fatalf("minimum IPv%d quoted tuple rejected: %v", version, err)
			}
		})
	}
}

func TestTypedRebindAndQUICPMTUDCasesRejectFalseEvidence(t *testing.T) {
	t.Run("unrelated rebind flow", func(t *testing.T) {
		manifest := loadFixtureManifest(t)
		registry := loadFixtureRegistry(t)
		report := completeReport(t, manifest, registry)
		evidence := caseEvidenceByID(t, report, "NP-REBIND")
		pcap := encodeClassicPCAP([][]byte{
			syntheticIPPacketWithTuple(t, 4, 17, 1200, 1, 1001, 4433),
			syntheticIPPacketWithTuple(t, 4, 17, 1200, 2, 2001, 8443),
		})
		evidence.Evidence["pcap"] = rewriteEvidenceArtifact(t, report.baseDir, evidence.Evidence["pcap"], pcap)
		assertResult(t, checkEvidence(manifest, registry, report, report.baseDir), statusFail, "ordered local AddrPort change")
	})

	t.Run("PMTUD reverse order", func(t *testing.T) {
		manifest := loadFixtureManifest(t)
		registry := loadFixtureRegistry(t)
		report := completeReport(t, manifest, registry)
		evidence := caseEvidenceByID(t, report, "NP-PMTUD-STATE")
		pcap := encodeClassicPCAP([][]byte{
			syntheticIPPacketWithTuple(t, 4, 17, 1200, 1, 1001, 4433),
			syntheticIPPacketWithTuple(t, 4, 17, 1301, 1, 1001, 4433),
		})
		evidence.Evidence["pcap"] = rewriteEvidenceArtifact(t, report.baseDir, evidence.Evidence["pcap"], pcap)
		assertResult(t, checkEvidence(manifest, registry, report, report.baseDir), statusFail, "oversized UDP")
	})

	t.Run("IPv6 PMTUD cannot use IPv4 capture", func(t *testing.T) {
		manifest := loadFixtureManifest(t)
		registry := loadFixtureRegistry(t)
		report := completeReport(t, manifest, registry)
		evidence := caseEvidenceByID(t, report, "SYS-PMTUD-QUIC-IPV6")
		pcap := encodeClassicPCAP([][]byte{
			syntheticIPPacketWithTuple(t, 4, 17, 1301, 1, 1001, 4433),
			syntheticIPPacketWithTuple(t, 4, 17, 1200, 1, 1001, 4433),
		})
		evidence.Evidence["pcap"] = rewriteEvidenceArtifact(t, report.baseDir, evidence.Evidence["pcap"], pcap)
		assertResult(t, checkEvidence(manifest, registry, report, report.baseDir), statusFail, "missing IPv6 UDP packet")
	})

	t.Run("kernel PMTUD requires PTB counter", func(t *testing.T) {
		manifest := loadFixtureManifest(t)
		registry := loadFixtureRegistry(t)
		report := completeReport(t, manifest, registry)
		evidence := caseEvidenceByID(t, report, "SYS-PMTUD-QUIC-IPV4")
		data, err := os.ReadFile(filepath.Join(report.baseDir, evidence.Evidence["metrics"].Path))
		if err != nil {
			t.Fatal(err)
		}
		var metrics MetricsArtifact
		if err := decodeStrictJSON(data, &metrics); err != nil {
			t.Fatal(err)
		}
		for index := range metrics.Records {
			if metrics.Records[index].Name == "icmp_ptb_received" {
				metrics.Records[index].Value = 0
			}
		}
		data, err = json.Marshal(metrics)
		if err != nil {
			t.Fatal(err)
		}
		evidence.Evidence["metrics"] = rewriteEvidenceArtifact(t, report.baseDir, evidence.Evidence["metrics"], data)
		assertResult(t, checkEvidence(manifest, registry, report, report.baseDir), statusFail, "ICMP PTB reception")
	})
}

func TestMigrationRequiresTheValidatedUpdatedPathAndPostValidationRPCIdentity(t *testing.T) {
	for _, test := range []struct {
		name, event, field, value string
	}{
		{name: "validated local path", event: "connectivity:path_validated", field: "new_path", value: "192.0.2.1:3001"},
		{name: "validated remote path", event: "connectivity:path_validated", field: "remote_path", value: "198.51.100.2:4433"},
		{name: "post-validation RPC identity", event: "application:rpc_completed", field: "connection_id", value: "different-connection"},
	} {
		t.Run(test.name, func(t *testing.T) {
			manifest := loadFixtureManifest(t)
			registry := loadFixtureRegistry(t)
			report := completeReport(t, manifest, registry)
			evidence := caseEvidenceByID(t, report, "SYS-MIGRATION-REBIND")
			rewriteCaseQlogEventField(t, report, evidence, test.event, test.field, test.value)
			assertResult(t, checkEvidence(manifest, registry, report, report.baseDir), statusFail, "migration identity/order mismatch")
		})
	}
}

func TestWSSPMTUDRequiresCorrelatedPTBAndTCPInfoTimeWindow(t *testing.T) {
	for _, version := range []int{4, 6} {
		t.Run(fmt.Sprintf("IPv%d", version), func(t *testing.T) {
			manifest := loadFixtureManifest(t)
			registry := loadFixtureRegistry(t)
			report := completeReport(t, manifest, registry)
			caseID := fmt.Sprintf("SYS-PMTUD-WSS-RECOVER-IPV%d", version)
			evidence := caseEvidenceByID(t, report, caseID)
			oversized := syntheticIPPacketWithTuple(t, version, 6, 1301, 1, 1001, 4433)
			unrelated := syntheticIPPacketWithTuple(t, version, 6, 1301, 2, 2001, 8443)
			pcap := encodeClassicPCAP([][]byte{oversized, syntheticICMPPTB(t, version, unrelated)})
			evidence.Evidence["pcap"] = rewriteEvidenceArtifact(t, report.baseDir, evidence.Evidence["pcap"], pcap)
			assertResult(t, checkEvidence(manifest, registry, report, report.baseDir), statusFail, "quoted TCP tuple")
		})
	}
}

func TestResourceMeasurementsEnforceFrozenUnitsAndNumericDomains(t *testing.T) {
	for _, test := range []struct {
		name        string
		measurement ScopedResourceMeasurement
	}{
		{name: "CPU unit", measurement: ScopedResourceMeasurement{Name: "cpu_nanoseconds", Value: 1, Unit: "bytes"}},
		{name: "byte integer", measurement: ScopedResourceMeasurement{Name: "delivered_bytes", Value: 1.5, Unit: "bytes"}},
		{name: "delivered positive", measurement: ScopedResourceMeasurement{Name: "delivered_bytes", Value: 0, Unit: "bytes"}},
		{name: "unknown field", measurement: ScopedResourceMeasurement{Name: "cpu_seconds", Value: 1, Unit: "seconds"}},
		{name: "incomplete scope", measurement: ScopedResourceMeasurement{Name: "cpu_nanoseconds", Value: 1, Unit: "nanoseconds", ProfileID: "clean-v1"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := validateResourceMeasurement(test.measurement); err == nil {
				t.Fatalf("validateResourceMeasurement(%+v) succeeded", test.measurement)
			}
		})
	}
}

func TestRequiredSeededRandomLossEvidenceCannotClaimAnotherSequence(t *testing.T) {
	manifest := loadFixtureManifest(t)
	registry := loadFixtureRegistry(t)
	report := completeReport(t, manifest, registry)
	evidence := caseEvidenceByID(t, report, "WF-UDP-RANDOM-LOSS")
	data, err := os.ReadFile(filepath.Join(report.baseDir, evidence.Evidence["metrics"].Path))
	if err != nil {
		t.Fatal(err)
	}
	var metrics MetricsArtifact
	if err := decodeStrictJSON(data, &metrics); err != nil {
		t.Fatal(err)
	}
	for index := range metrics.Records {
		if metrics.Records[index].Name == "actual_random_loss_units" {
			metrics.Records[index].Value++
		}
	}
	data, err = json.Marshal(metrics)
	if err != nil {
		t.Fatal(err)
	}
	evidence.Evidence["metrics"] = rewriteEvidenceArtifact(t, report.baseDir, evidence.Evidence["metrics"], data)
	assertResult(t, checkEvidence(manifest, registry, report, report.baseDir), statusFail, "seeded random-loss counters")
}

func TestCapacityEvidenceRejectsGenericStatusArtifacts(t *testing.T) {
	manifest := loadFixtureManifest(t)
	registry := loadFixtureRegistry(t)
	report := completeReport(t, manifest, registry)
	evidence := caseEvidenceByID(t, report, "CAP-DIRECT-WSS-1000")
	context := "case " + evidence.ID
	generic := MetricsArtifact{SchemaVersion: 1, Kind: "transport_metrics", Context: context,
		Records: []MetricCounterRecord{{Name: "completed_operations", Value: 1, Unit: "count"}}}
	data, err := json.Marshal(generic)
	if err != nil {
		t.Fatal(err)
	}
	evidence.Evidence["metrics"] = rewriteEvidenceArtifact(t, report.baseDir, evidence.Evidence["metrics"], data)

	result := checkEvidence(manifest, registry, report, report.baseDir)
	assertResult(t, result, statusFail, "capacity")
}

func TestRequiredWeakNetworkCasesRejectMissingRawSemantics(t *testing.T) {
	for _, test := range []struct {
		name, caseID, wantIssue string
	}{
		{name: "random loss byte conservation", caseID: "WF-UDP-RANDOM-LOSS", wantIssue: "random-loss byte"},
		{name: "kernel outage schedule", caseID: "SYS-COMMON-KERNEL", wantIssue: "outage trace"},
		{name: "native rebind schedule", caseID: "NP-REBIND", wantIssue: "rebind trace"},
		{name: "kernel rebind schedule", caseID: "SYS-MIGRATION-REBIND", wantIssue: "rebind trace"},
		{name: "QUIC PMTUD post-recovery RPC", caseID: "NP-PMTUD-STATE", wantIssue: "post-recovery RPC"},
	} {
		t.Run(test.name, func(t *testing.T) {
			manifest := loadFixtureManifest(t)
			registry := loadFixtureRegistry(t)
			report := completeReport(t, manifest, registry)
			evidence := caseEvidenceByID(t, report, test.caseID)
			switch test.caseID {
			case "WF-UDP-RANDOM-LOSS":
				data, err := os.ReadFile(filepath.Join(report.baseDir, evidence.Evidence["metrics"].Path))
				if err != nil {
					t.Fatal(err)
				}
				var metrics MetricsArtifact
				if err := decodeStrictJSON(data, &metrics); err != nil {
					t.Fatal(err)
				}
				for index := range metrics.Records {
					if metrics.Records[index].Name == "expected_output_bytes" || metrics.Records[index].Name == "actual_output_bytes" {
						metrics.Records[index].Value += 1200
					}
				}
				data, err = json.Marshal(metrics)
				if err != nil {
					t.Fatal(err)
				}
				evidence.Evidence["metrics"] = rewriteEvidenceArtifact(t, report.baseDir, evidence.Evidence["metrics"], data)
			case "SYS-COMMON-KERNEL", "NP-REBIND", "SYS-MIGRATION-REBIND":
				context := "case " + test.caseID
				trace := TraceArtifact{SchemaVersion: 1, Kind: "transport_trace", Context: context, Records: []TraceRecord{{
					Sequence: 1, AtNS: 1, Event: fixtureCaseTraceEvent(context), Digest: strings.Repeat("a", 64), ConnectionID: evidenceConnectionID,
				}}}
				data, err := json.Marshal(trace)
				if err != nil {
					t.Fatal(err)
				}
				evidence.Evidence["trace"] = rewriteEvidenceArtifact(t, report.baseDir, evidence.Evidence["trace"], data)
			case "NP-PMTUD-STATE":
				rewriteCaseQlogEventField(t, report, evidence, "application:rpc_completed", "connection_id", "different-connection")
			}

			result := checkEvidence(manifest, registry, report, report.baseDir)
			assertResult(t, result, statusFail, test.wantIssue)
		})
	}
}

func TestExpectedActualCounterUnitsAreSemantic(t *testing.T) {
	artifact := MetricsArtifact{Records: []MetricCounterRecord{
		{Name: "expected_input_bytes", Value: 1200, Unit: "count"},
		{Name: "actual_input_bytes", Value: 1200, Unit: "count"},
	}}
	if _, err := expectedActualCounters(artifact, []string{"input_bytes"}); err == nil || !strings.Contains(err.Error(), "unit") {
		t.Fatalf("expectedActualCounters() error = %v, want unit mismatch", err)
	}
}

func TestManifestFreezesEveryCapacityLimit(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*CapacityContract)
	}{
		{name: "sessions", mutate: func(value *CapacityContract) { value.Sessions-- }},
		{name: "ramp", mutate: func(value *CapacityContract) { value.RampDurationNS-- }},
		{name: "hold", mutate: func(value *CapacityContract) { value.HoldDurationNS-- }},
		{name: "cleanup", mutate: func(value *CapacityContract) { value.CleanupDurationNS-- }},
		{name: "watchdog", mutate: func(value *CapacityContract) { value.WatchdogDurationNS-- }},
		{name: "RSS", mutate: func(value *CapacityContract) { value.MaxRSSBytes-- }},
		{name: "CPU", mutate: func(value *CapacityContract) { value.MaxCPUNanoseconds-- }},
		{name: "file descriptors", mutate: func(value *CapacityContract) { value.MaxOpenFDs-- }},
		{name: "goroutines", mutate: func(value *CapacityContract) { value.MaxGoroutines-- }},
		{name: "tasks", mutate: func(value *CapacityContract) { value.MaxTasks-- }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manifest := loadFixtureManifest(t)
			test.mutate(&manifest.Capacity)
			refreshManifestDigest(t, manifest)
			if err := validateManifest(manifest); err == nil || !strings.Contains(err.Error(), "capacity contract") {
				t.Fatalf("validateManifest() error = %v, want capacity contract rejection", err)
			}
		})
	}
}

func TestManifestFreezesEverySoakLimit(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*SoakContract)
	}{
		{name: "duration", mutate: func(value *SoakContract) { value.DurationNS-- }},
		{name: "fault period", mutate: func(value *SoakContract) { value.FaultCyclePeriodNS-- }},
		{name: "fault cycles", mutate: func(value *SoakContract) { value.FaultCycleCount-- }},
		{name: "reconnects", mutate: func(value *SoakContract) { value.ReconnectCount-- }},
		{name: "migrations", mutate: func(value *SoakContract) { value.MigrationCount-- }},
		{name: "RSS slope", mutate: func(value *SoakContract) { value.MaxRSSGrowthBytesPerHour-- }},
		{name: "goroutine slope", mutate: func(value *SoakContract) { value.MaxGoroutineGrowthPerHour-- }},
		{name: "fd slope", mutate: func(value *SoakContract) { value.MaxOpenFDGrowthPerHour-- }},
		{name: "task slope", mutate: func(value *SoakContract) { value.MaxTaskGrowthPerHour-- }},
		{name: "residual sessions", mutate: func(value *SoakContract) { value.ResidualSessions = 1 }},
		{name: "residual goroutines", mutate: func(value *SoakContract) { value.ResidualGoroutines = 1 }},
		{name: "residual fds", mutate: func(value *SoakContract) { value.ResidualOpenFDs = 1 }},
		{name: "residual tasks", mutate: func(value *SoakContract) { value.ResidualTasks = 1 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manifest := loadFixtureManifest(t)
			test.mutate(&manifest.Soak)
			refreshManifestDigest(t, manifest)
			if err := validateManifest(manifest); err == nil || !strings.Contains(err.Error(), "soak contract") {
				t.Fatalf("validateManifest() error = %v, want soak contract rejection", err)
			}
		})
	}
}

func TestSoakEvidenceRejectsEveryFrozenContractDrift(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, *EvidenceReport, *CaseEvidence)
	}{
		{name: "duration metric", mutate: func(t *testing.T, report *EvidenceReport, evidence *CaseEvidence) {
			rewriteCaseMetricCounter(t, report, evidence, "duration_ns", float64(signedSoakContract.DurationNS-1))
		}},
		{name: "cycle metric", mutate: func(t *testing.T, report *EvidenceReport, evidence *CaseEvidence) {
			rewriteCaseMetricCounter(t, report, evidence, "fault_cycle_count", float64(signedSoakContract.FaultCycleCount-1))
		}},
		{name: "trace schedule", mutate: func(t *testing.T, report *EvidenceReport, evidence *CaseEvidence) {
			rewriteCaseTrace(t, report, evidence, func(trace *TraceArtifact) { trace.Records[1].AtNS++ })
		}},
		{name: "resource slope", mutate: func(t *testing.T, report *EvidenceReport, evidence *CaseEvidence) {
			rewriteCaseResource(t, report, evidence, func(resource *ResourceArtifact) {
				resource.Records[1].RSSBytes += signedSoakContract.MaxRSSGrowthBytesPerHour + 1
			})
		}},
		{name: "config identity", mutate: func(t *testing.T, report *EvidenceReport, evidence *CaseEvidence) {
			rewriteCaseConfigValue(t, report, evidence, "fault_cycle_period_ns", "1")
		}},
		{name: "residual", mutate: func(t *testing.T, report *EvidenceReport, evidence *CaseEvidence) {
			rewriteCaseMetricCounter(t, report, evidence, "residual_tasks", 1)
		}},
		{name: "resource residual sessions", mutate: func(t *testing.T, report *EvidenceReport, evidence *CaseEvidence) {
			rewriteCaseResource(t, report, evidence, func(resource *ResourceArtifact) { resource.Records[1].ResidualSessions = intPointer(1) })
		}},
		{name: "resource residual goroutines", mutate: func(t *testing.T, report *EvidenceReport, evidence *CaseEvidence) {
			rewriteCaseResource(t, report, evidence, func(resource *ResourceArtifact) { resource.Records[1].ResidualGoroutines = intPointer(1) })
		}},
		{name: "resource residual fds", mutate: func(t *testing.T, report *EvidenceReport, evidence *CaseEvidence) {
			rewriteCaseResource(t, report, evidence, func(resource *ResourceArtifact) { resource.Records[1].ResidualOpenFDs = intPointer(1) })
		}},
		{name: "resource residual tasks", mutate: func(t *testing.T, report *EvidenceReport, evidence *CaseEvidence) {
			rewriteCaseResource(t, report, evidence, func(resource *ResourceArtifact) { resource.Records[1].ResidualTasks = intPointer(1) })
		}},
		{name: "resource residual attestation missing", mutate: func(t *testing.T, report *EvidenceReport, evidence *CaseEvidence) {
			rewriteCaseResource(t, report, evidence, func(resource *ResourceArtifact) { resource.Records[1].ResidualTasks = nil })
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manifest := loadFixtureManifest(t)
			registry := loadFixtureRegistry(t)
			report := completeReport(t, manifest, registry)
			evidence := caseEvidenceByID(t, report, "CAP-SOAK-HOURLY")
			test.mutate(t, report, evidence)
			assertResult(t, checkEvidence(manifest, registry, report, report.baseDir), statusFail, "soak")
		})
	}
}

func TestCapacityEvidenceRejectsCounterAndTraceDrift(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(*testing.T, *EvidenceReport, *CaseEvidence)
		wantIssue string
	}{
		{name: "attempted equation", wantIssue: "capacity counters", mutate: func(t *testing.T, report *EvidenceReport, evidence *CaseEvidence) {
			rewriteCaseMetricCounter(t, report, evidence, "attempted_sessions", 999)
		}},
		{name: "unique active peak", wantIssue: "capacity counters", mutate: func(t *testing.T, report *EvidenceReport, evidence *CaseEvidence) {
			rewriteCaseMetricCounter(t, report, evidence, "unique_active_peak", 999)
		}},
		{name: "hold duration", wantIssue: "capacity counters", mutate: func(t *testing.T, report *EvidenceReport, evidence *CaseEvidence) {
			rewriteCaseMetricCounter(t, report, evidence, "hold_duration_ns", 60e9-1)
		}},
		{name: "hold disconnect", wantIssue: "capacity counters", mutate: func(t *testing.T, report *EvidenceReport, evidence *CaseEvidence) {
			rewriteCaseMetricCounter(t, report, evidence, "hold_disconnects", 1)
		}},
		{name: "watchdog", wantIssue: "capacity counters", mutate: func(t *testing.T, report *EvidenceReport, evidence *CaseEvidence) {
			rewriteCaseMetricCounter(t, report, evidence, "watchdog_timeouts", 1)
		}},
		{name: "cleanup residual", wantIssue: "capacity counters", mutate: func(t *testing.T, report *EvidenceReport, evidence *CaseEvidence) {
			rewriteCaseMetricCounter(t, report, evidence, "cleanup_residual_sessions", 1)
		}},
		{name: "trace hold disconnect", wantIssue: "intact hold interval", mutate: func(t *testing.T, report *EvidenceReport, evidence *CaseEvidence) {
			rewriteCaseTrace(t, report, evidence, func(trace *TraceArtifact) { trace.Records[1].Disconnects = 1 })
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manifest := loadFixtureManifest(t)
			registry := loadFixtureRegistry(t)
			report := completeReport(t, manifest, registry)
			evidence := caseEvidenceByID(t, report, "CAP-DIRECT-WSS-1000")
			test.mutate(t, report, evidence)
			assertResult(t, checkEvidence(manifest, registry, report, report.baseDir), statusFail, test.wantIssue)
		})
	}
}

func TestCapacityResourceTimelineRejectsEveryLimitAndPhaseDrift(t *testing.T) {
	contract := signedCapacityContract
	times := []int64{contract.RampDurationNS, contract.RampDurationNS + contract.HoldDurationNS, contract.WatchdogDurationNS}
	valid := fixtureCaseResource("case CAP-DIRECT-WSS-1000")
	tests := []struct {
		name   string
		mutate func(*[]ResourceRecord)
	}{
		{name: "missing phase", mutate: func(records *[]ResourceRecord) { *records = (*records)[:2] }},
		{name: "phase name", mutate: func(records *[]ResourceRecord) { (*records)[1].Phase = "steady" }},
		{name: "RSS", mutate: func(records *[]ResourceRecord) { (*records)[1].RSSBytes = contract.MaxRSSBytes + 1 }},
		{name: "CPU", mutate: func(records *[]ResourceRecord) { (*records)[1].CPUNanoseconds = contract.MaxCPUNanoseconds + 1 }},
		{name: "file descriptors", mutate: func(records *[]ResourceRecord) { (*records)[1].OpenFDs = contract.MaxOpenFDs + 1 }},
		{name: "goroutines", mutate: func(records *[]ResourceRecord) { (*records)[1].Goroutines = contract.MaxGoroutines + 1 }},
		{name: "tasks", mutate: func(records *[]ResourceRecord) { (*records)[1].Tasks = contract.MaxTasks + 1 }},
		{name: "cleanup active", mutate: func(records *[]ResourceRecord) { (*records)[2].ActiveSessions = 1 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			records := append([]ResourceRecord(nil), valid...)
			test.mutate(&records)
			artifact := ResourceArtifact{Records: records}
			if err := validateCapacityResourceTimeline(artifact, contract, times); err == nil {
				t.Fatal("validateCapacityResourceTimeline() succeeded for drifted evidence")
			}
		})
	}
}

func TestOutageAndRebindEvidenceRejectsScheduleIdentityOrderAndCounterDrift(t *testing.T) {
	tests := []struct {
		name, caseID, wantIssue string
		mutate                  func(*testing.T, *EvidenceReport, *CaseEvidence)
	}{
		{name: "outage config schedule", caseID: "SYS-COMMON-KERNEL", wantIssue: "effective config outage_start_ns", mutate: func(t *testing.T, report *EvidenceReport, evidence *CaseEvidence) {
			rewriteCaseConfigValue(t, report, evidence, "outage_start_ns", "1000000001")
		}},
		{name: "outage raw duration", caseID: "SYS-COMMON-KERNEL", wantIssue: "outage trace", mutate: func(t *testing.T, report *EvidenceReport, evidence *CaseEvidence) {
			rewriteCaseTrace(t, report, evidence, func(trace *TraceArtifact) { trace.Records[1].AtNS++ })
		}},
		{name: "outage connection identity", caseID: "SYS-COMMON-KERNEL", wantIssue: "outage trace", mutate: func(t *testing.T, report *EvidenceReport, evidence *CaseEvidence) {
			rewriteCaseTrace(t, report, evidence, func(trace *TraceArtifact) { trace.Records[0].ConnectionID = "different-connection" })
		}},
		{name: "outage derived duration", caseID: "SYS-COMMON-KERNEL", wantIssue: "outage trace", mutate: func(t *testing.T, report *EvidenceReport, evidence *CaseEvidence) {
			rewriteCaseMetricCounter(t, report, evidence, "expected_outage_duration_ns", 1)
			rewriteCaseMetricCounter(t, report, evidence, "actual_outage_duration_ns", 1)
		}},
		{name: "rebind config schedule", caseID: "NP-REBIND", wantIssue: "effective config rebind_at_ns", mutate: func(t *testing.T, report *EvidenceReport, evidence *CaseEvidence) {
			rewriteCaseConfigValue(t, report, evidence, "rebind_at_ns", "2000000001")
		}},
		{name: "rebind event order", caseID: "NP-REBIND", wantIssue: "rebind trace", mutate: func(t *testing.T, report *EvidenceReport, evidence *CaseEvidence) {
			rewriteCaseTrace(t, report, evidence, func(trace *TraceArtifact) {
				trace.Records[2].Event, trace.Records[3].Event = trace.Records[3].Event, trace.Records[2].Event
			})
		}},
		{name: "rebind connection identity", caseID: "NP-REBIND", wantIssue: "rebind trace", mutate: func(t *testing.T, report *EvidenceReport, evidence *CaseEvidence) {
			rewriteCaseTrace(t, report, evidence, func(trace *TraceArtifact) { trace.Records[3].ConnectionID = "different-connection" })
		}},
		{name: "rebind derived counter", caseID: "NP-REBIND", wantIssue: "rebind metrics", mutate: func(t *testing.T, report *EvidenceReport, evidence *CaseEvidence) {
			rewriteCaseMetricCounter(t, report, evidence, "path_updates", 2)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manifest := loadFixtureManifest(t)
			registry := loadFixtureRegistry(t)
			report := completeReport(t, manifest, registry)
			evidence := caseEvidenceByID(t, report, test.caseID)
			test.mutate(t, report, evidence)
			assertResult(t, checkEvidence(manifest, registry, report, report.baseDir), statusFail, test.wantIssue)
		})
	}
}

func TestQUICPMTUDQlogRequiresSameConnectionAndStrictRecoveryOrder(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, *EvidenceReport, *CaseEvidence)
	}{
		{name: "packet-too-large CID", mutate: func(t *testing.T, report *EvidenceReport, evidence *CaseEvidence) {
			rewriteCaseQlogEventField(t, report, evidence, "transport:packet_too_large", "connection_id", "different-connection")
		}},
		{name: "recovery CID", mutate: func(t *testing.T, report *EvidenceReport, evidence *CaseEvidence) {
			rewriteCaseQlogEventField(t, report, evidence, "transport:metrics_updated", "connection_id", "different-connection")
		}},
		{name: "post-recovery RPC CID", mutate: func(t *testing.T, report *EvidenceReport, evidence *CaseEvidence) {
			rewriteCaseQlogEventField(t, report, evidence, "application:rpc_completed", "connection_id", "different-connection")
		}},
		{name: "RPC before recovery", mutate: func(t *testing.T, report *EvidenceReport, evidence *CaseEvidence) {
			swapCaseQlogEvents(t, report, evidence, "transport:metrics_updated", "application:rpc_completed")
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manifest := loadFixtureManifest(t)
			registry := loadFixtureRegistry(t)
			report := completeReport(t, manifest, registry)
			evidence := caseEvidenceByID(t, report, "SYS-PMTUD-QUIC-IPV4")
			test.mutate(t, report, evidence)
			assertResult(t, checkEvidence(manifest, registry, report, report.baseDir), statusFail, "post-recovery RPC")
		})
	}
}

func mustParsePCAP(t *testing.T, data []byte) []packetObservation {
	t.Helper()
	packets, err := parseClassicPCAP(data)
	if err != nil {
		t.Fatal(err)
	}
	return packets
}

func TestPerformanceCellWatchdogIsFailClosed(t *testing.T) {
	manifest := loadFixtureManifest(t)
	registry := loadFixtureRegistry(t)
	report := completeReport(t, manifest, registry)
	cell := &report.Cells[0]
	contract := manifestCellByID(t, manifest, cell.CellID)
	cell.ElapsedNanoseconds = int64Pointer(int64(contract.DurationMinutes)*60*1e9 + 1)

	result := checkEvidence(manifest, registry, report, report.baseDir)
	assertResult(t, result, statusFail, "wall-clock elapsed time exceeds")
}

func TestCleanupMetricIsAHardProfileDeadline(t *testing.T) {
	manifest := loadFixtureManifest(t)
	registry := loadFixtureRegistry(t)
	report := completeReport(t, manifest, registry)
	cell := evidenceCellByID(t, report, "clean-02")
	setMetricSamples(t, manifest, report, cell, "cleanup_latency_ms", 5001)
	result := checkEvidence(manifest, registry, report, report.baseDir)
	assertResult(t, result, statusFail, "cleanup deadline")
}

func TestForcedProfilesRequireCleanupPhaseEvidence(t *testing.T) {
	manifest := loadFixtureManifest(t)
	profile := profileByID(t, manifest, "clean-v1")
	phases := expectedPhases(*profile)
	if !slices.ContainsFunc(phases, func(phase expectedPhase) bool { return phase.phase == "cleanup" }) {
		t.Fatal("forced profile has no cleanup evidence phase")
	}
}

func TestWeaknetFullRejectsGenericStatusLikeMetrics(t *testing.T) {
	manifest := loadFixtureManifest(t)
	registry := loadFixtureRegistry(t)
	report := completeReport(t, manifest, registry)
	for index := range report.Cases {
		if report.Cases[index].ID != "WF-UDP-FULL" || report.Cases[index].Mode != "normal" {
			continue
		}
		context := "case WF-UDP-FULL"
		generic := MetricsArtifact{SchemaVersion: 1, Kind: "transport_metrics", Context: context,
			Records: []MetricCounterRecord{{Name: "completed_operations", Value: 1, Unit: "count"}}}
		data, err := json.Marshal(generic)
		if err != nil {
			t.Fatal(err)
		}
		artifact := report.Cases[index].Evidence["metrics"]
		report.Cases[index].Evidence["metrics"] = rewriteEvidenceArtifact(t, report.baseDir, artifact, data)
		break
	}
	result := checkEvidence(manifest, registry, report, report.baseDir)
	assertResult(t, result, statusFail, "expected/actual counters")
}

func TestKernelWeaknetEvidenceRejectsGenericMetricsAndConfig(t *testing.T) {
	tests := []struct {
		name      string
		kind      string
		value     any
		wantIssue string
	}{
		{
			name: "generic metrics", kind: "metrics",
			value: MetricsArtifact{SchemaVersion: 1, Kind: "transport_metrics",
				Records: []MetricCounterRecord{{Name: "completed_operations", Value: 1, Unit: "count"}}},
			wantIssue: "expected/actual counters",
		},
		{
			name: "generic config", kind: "config",
			value: ConfigArtifact{SchemaVersion: 1, Kind: "transport_config",
				Records: []ConfigRecord{{Key: "watchdog", Value: "completed"}}},
			wantIssue: "effective config",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manifest := loadFixtureManifest(t)
			registry := loadFixtureRegistry(t)
			report := completeReport(t, manifest, registry)
			caseEvidence := caseEvidenceByID(t, report, "SYS-COMMON-KERNEL")
			context := "case SYS-COMMON-KERNEL"
			switch value := test.value.(type) {
			case MetricsArtifact:
				value.Context = context
				test.value = value
			case ConfigArtifact:
				value.Context = context
				test.value = value
			}
			data, err := json.Marshal(test.value)
			if err != nil {
				t.Fatal(err)
			}
			caseEvidence.Evidence[test.kind] = rewriteEvidenceArtifact(t, report.baseDir, caseEvidence.Evidence[test.kind], data)

			result := checkEvidence(manifest, registry, report, report.baseDir)
			assertResult(t, result, statusFail, test.wantIssue)
		})
	}
}

func TestWSSPMTUDEvidenceCannotImpersonateOppositeTerminal(t *testing.T) {
	tests := []struct {
		name      string
		caseID    string
		recovered bool
		wantIssue string
	}{
		{name: "recover impersonates timeout", caseID: "SYS-PMTUD-WSS-TIMEOUT-IPV4", recovered: true, wantIssue: "effective config"},
		{name: "timeout impersonates recover", caseID: "SYS-PMTUD-WSS-RECOVER-IPV4", recovered: false, wantIssue: "effective config"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manifest := loadFixtureManifest(t)
			registry := loadFixtureRegistry(t)
			report := completeReport(t, manifest, registry)
			writeWSSPMTUDTerminalEvidence(t, report, caseEvidenceByID(t, report, test.caseID), test.recovered)

			result := checkEvidence(manifest, registry, report, report.baseDir)
			assertResult(t, result, statusFail, test.wantIssue)
		})
	}
}

func TestReleaseEvidenceRequiresRegisteredRaceAndWeaknetFullResults(t *testing.T) {
	manifest := loadFixtureManifest(t)
	registry := loadFixtureRegistry(t)
	report := completeReport(t, manifest, registry)
	kept := report.Cases[:0]
	for _, evidence := range report.Cases {
		if evidence.Mode != "race" {
			kept = append(kept, evidence)
		}
	}
	report.Cases = kept
	result := checkEvidence(manifest, registry, report, report.baseDir)
	assertResult(t, result, statusFail, "missing race evidence")

	foundWeaknetFull := false
	for _, definition := range registry.Cases {
		if definition.Owner == "weaknet-full" && definition.Required {
			foundWeaknetFull = true
			break
		}
	}
	if !foundWeaknetFull {
		t.Fatal("case registry is missing required weaknet-full evidence")
	}
}

func TestEvidenceRejectsArtifactImpersonationAndTampering(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(*EvidenceReport)
		wantIssue string
	}{
		{
			name: "plain text impersonates structured trace",
			mutate: func(report *EvidenceReport) {
				phase := &report.Cells[0].Runs[0].Phases[0]
				phase.Artifacts["trace"] = rewriteEvidenceArtifact(t, report.baseDir, phase.Artifacts["trace"], []byte("pass\n"))
			},
			wantIssue: "not a bound structured evidence envelope",
		},
		{
			name: "one path impersonates two kinds",
			mutate: func(report *EvidenceReport) {
				phase := &report.Cells[0].Runs[0].Phases[0]
				phase.Artifacts["metrics"] = phase.Artifacts["trace"]
			},
			wantIssue: "reuses artifact path",
		},
		{
			name: "artifact context differs",
			mutate: func(report *EvidenceReport) {
				phase := &report.Cells[0].Runs[0].Phases[0]
				phase.Artifacts["trace"] = writeStructuredArtifact(t, report.baseDir, "another context", "trace")
			},
			wantIssue: "metadata does not bind exact context",
		},
		{
			name: "empty pcap header impersonates capture",
			mutate: func(report *EvidenceReport) {
				phase := &report.Cells[0].Runs[0].Phases[0]
				emptyCapture := make([]byte, 24)
				copy(emptyCapture, []byte{0xa1, 0xb2, 0xc3, 0xd4, 0, 2, 0, 4})
				phase.Artifacts["pcap"] = rewriteEvidenceArtifact(t, report.baseDir, phase.Artifacts["pcap"], emptyCapture)
			},
			wantIssue: "no valid pcap/pcapng header and non-empty packet record",
		},
		{
			name: "reported confidence interval differs",
			mutate: func(report *EvidenceReport) {
				cell := &report.Cells[0]
				for metricID, metric := range cell.Metrics {
					*metric.UpperCI++
					cell.Metrics[metricID] = metric
					break
				}
			},
			wantIssue: "reported statistics do not match deterministic bootstrap",
		},
		{
			name: "raw values changed without digest",
			mutate: func(report *EvidenceReport) {
				cell := &report.Cells[0]
				for metricID, metric := range cell.Metrics {
					data, err := json.Marshal(MetricSamplesArtifact{
						SchemaVersion: 1,
						CellID:        cell.CellID,
						MetricID:      metricID,
						Runs:          make([]MetricRunSample, 15),
					})
					if err != nil {
						t.Fatal(err)
					}
					name := "tampered-" + filepath.Base(metric.RawSamples.Path)
					if err := os.WriteFile(filepath.Join(report.baseDir, name), data, 0o600); err != nil {
						t.Fatal(err)
					}
					metric.RawSamples.Path = name
					cell.Metrics[metricID] = metric
					break
				}
			},
			wantIssue: "digest mismatch",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manifest := loadFixtureManifest(t)
			registry := loadFixtureRegistry(t)
			report := completeReport(t, manifest, registry)
			test.mutate(report)
			result := checkEvidence(manifest, registry, report, report.baseDir)
			assertResult(t, result, statusFail, test.wantIssue)
		})
	}
}

func TestEvidenceRejectsCaseSpecificQlogAndPCAPImpersonation(t *testing.T) {
	t.Run("flow isolation qlog has no blocking or RPC proof", func(t *testing.T) {
		manifest := loadFixtureManifest(t)
		registry := loadFixtureRegistry(t)
		report := completeReport(t, manifest, registry)
		for index := range report.Cases {
			if report.Cases[index].ID == "NS-N2" && report.Cases[index].Mode == "normal" {
				context := "case NS-N2"
				report.Cases[index].Evidence["qlog"] = writeQlogArtifactWithEvents(t, report.baseDir, context, []string{"transport:unit"}, 0)
				break
			}
		}
		result := checkEvidence(manifest, registry, report, report.baseDir)
		assertResult(t, result, statusFail, "STREAM_DATA_BLOCKED")
	})

	t.Run("IPv6 WSS PMTUD pcap contains no IPv6 TCP oversized packet", func(t *testing.T) {
		manifest := loadFixtureManifest(t)
		registry := loadFixtureRegistry(t)
		report := completeReport(t, manifest, registry)
		for index := range report.Cases {
			if report.Cases[index].ID == "SYS-PMTUD-WSS-RECOVER-IPV6" && report.Cases[index].Mode == "normal" {
				artifact := report.Cases[index].Evidence["pcap"]
				data := encodeClassicPCAP([][]byte{syntheticIPPacket(t, 4, 17, 1301, 1)})
				report.Cases[index].Evidence["pcap"] = rewriteEvidenceArtifact(t, report.baseDir, artifact, data)
				break
			}
		}
		result := checkEvidence(manifest, registry, report, report.baseDir)
		assertResult(t, result, statusFail, "IPv6 TCP packet larger than 1280 bytes")
	})
}

func TestEvidenceAttestationRequiresTrustedEd25519Signature(t *testing.T) {
	manifest := loadFixtureManifest(t)
	registry := loadFixtureRegistry(t)
	report := completeReport(t, manifest, registry)
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x5a}, ed25519.SeedSize))
	trustStore := EvidenceTrustStore{
		SchemaVersion: 1,
		Keys: []TrustedEvidenceKey{{
			KeyID:     "release-lab-2026",
			PublicKey: base64.StdEncoding.EncodeToString(privateKey.Public().(ed25519.PublicKey)),
		}},
	}
	signEvidenceReportForTest(t, report, "release-lab-2026", privateKey)
	if err := verifyEvidenceAttestation(report, &trustStore); err != nil {
		t.Fatalf("verify trusted evidence: %v", err)
	}

	t.Run("missing signature", func(t *testing.T) {
		unsigned := *report
		unsigned.Attestation = EvidenceAttestation{}
		if err := verifyEvidenceAttestation(&unsigned, &trustStore); err == nil || !strings.Contains(err.Error(), "attestation") {
			t.Fatalf("verifyEvidenceAttestation() error = %v, want attestation error", err)
		}
	})

	t.Run("untrusted key", func(t *testing.T) {
		otherPrivateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x6b}, ed25519.SeedSize))
		otherTrustStore := &EvidenceTrustStore{
			SchemaVersion: 1,
			Keys: []TrustedEvidenceKey{{
				KeyID:     "another-lab",
				PublicKey: base64.StdEncoding.EncodeToString(otherPrivateKey.Public().(ed25519.PublicKey)),
			}},
		}
		if err := verifyEvidenceAttestation(report, otherTrustStore); err == nil || !strings.Contains(err.Error(), "not trusted") {
			t.Fatalf("verifyEvidenceAttestation() error = %v, want untrusted key", err)
		}
	})

	t.Run("report tampering", func(t *testing.T) {
		tampered := *report
		tampered.Cells = append([]CellEvidence(nil), report.Cells...)
		tampered.Cells[0].Policy = "tampered"
		if err := verifyEvidenceAttestation(&tampered, &trustStore); err == nil || !strings.Contains(err.Error(), "signature") {
			t.Fatalf("verifyEvidenceAttestation() error = %v, want signature error", err)
		}
	})

	t.Run("zero public key and signature", func(t *testing.T) {
		weakStore := &EvidenceTrustStore{
			SchemaVersion: 1,
			Keys: []TrustedEvidenceKey{{
				KeyID:     "weak-zero-key",
				PublicKey: base64.StdEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize)),
			}},
		}
		forged := *report
		forged.Attestation = EvidenceAttestation{
			Scheme:    "ed25519",
			KeyID:     "weak-zero-key",
			Signature: base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize)),
		}
		if err := verifyEvidenceAttestation(&forged, weakStore); err == nil || !strings.Contains(err.Error(), "weak Ed25519 public key") {
			t.Fatalf("verifyEvidenceAttestation() error = %v, want weak public key error", err)
		}
	})

	t.Run("nonzero low-order public key", func(t *testing.T) {
		lowOrder, err := hex.DecodeString("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85")
		if err != nil {
			t.Fatal(err)
		}
		weakStore := &EvidenceTrustStore{
			SchemaVersion: 1,
			Keys: []TrustedEvidenceKey{{
				KeyID:     "weak-low-order-key",
				PublicKey: base64.StdEncoding.EncodeToString(lowOrder),
			}},
		}
		if err := validateEvidenceTrustStore(weakStore); err == nil || !strings.Contains(err.Error(), "weak Ed25519 public key") {
			t.Fatalf("validateEvidenceTrustStore() error = %v, want weak public key error", err)
		}
	})
}

func TestRepositoryTrustPolicyRejectsSignerReplacement(t *testing.T) {
	publicKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x2a}, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	store := EvidenceTrustStore{SchemaVersion: 1, Keys: []TrustedEvidenceKey{{
		KeyID: "release-lab-2026", PublicKey: base64.StdEncoding.EncodeToString(publicKey),
	}}}
	storePath := filepath.Join(t.TempDir(), "trust-store.json")
	writeJSON(t, storePath, store)
	storeData, err := os.ReadFile(storePath)
	if err != nil {
		t.Fatal(err)
	}
	storeDigest := sha256.Sum256(storeData)
	publicDigest := sha256.Sum256(publicKey)
	policy := EvidenceTrustPolicy{
		SchemaVersion: 1, TrustStoreSHA256: hex.EncodeToString(storeDigest[:]),
		KeyID: "release-lab-2026", PublicKeySHA256: hex.EncodeToString(publicDigest[:]),
		Runner: EvidenceRunnerPolicy{
			ID: "flowersec-linux-release-v1", OS: "linux", Architecture: "amd64", KernelRelease: "6.12.1",
			Namespace: "isolated", TrafficControl: "tc-netem-v1", PacketCounters: "ebpf-v1", EffectiveConfigSHA256: signedRunnerConfigDigest,
			ExecutableSHA256: signedRunnerExecutableSHA, SourceSHA256: signedRunnerSourceSHA, ArgvSHA256: signedRunnerArgvSHA,
			EffectiveConfigPath: signedRunnerConfigPath,
		},
	}
	if err := validateTrustStoreAgainstPolicy(storePath, &store, &policy); err != nil {
		t.Fatalf("valid audited trust store: %v", err)
	}

	t.Run("trust store digest", func(t *testing.T) {
		mutated := policy
		mutated.TrustStoreSHA256 = strings.Repeat("0", 64)
		if err := validateTrustStoreAgainstPolicy(storePath, &store, &mutated); err == nil || !strings.Contains(err.Error(), "audited digest") {
			t.Fatalf("validateTrustStoreAgainstPolicy() error = %v, want audited digest rejection", err)
		}
	})

	t.Run("public key", func(t *testing.T) {
		mutatedStore := store
		mutatedStore.Keys = append([]TrustedEvidenceKey(nil), store.Keys...)
		mutatedStore.Keys[0].PublicKey = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x3b}, ed25519.PublicKeySize))
		mutatedPath := filepath.Join(t.TempDir(), "trust-store.json")
		writeJSON(t, mutatedPath, mutatedStore)
		data, err := os.ReadFile(mutatedPath)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(data)
		mutatedPolicy := policy
		mutatedPolicy.TrustStoreSHA256 = hex.EncodeToString(digest[:])
		if err := validateTrustStoreAgainstPolicy(mutatedPath, &mutatedStore, &mutatedPolicy); err == nil || !strings.Contains(err.Error(), "public key") {
			t.Fatalf("validateTrustStoreAgainstPolicy() error = %v, want public key rejection", err)
		}
	})

	t.Run("key ID", func(t *testing.T) {
		mutatedStore := store
		mutatedStore.Keys = append([]TrustedEvidenceKey(nil), store.Keys...)
		mutatedStore.Keys[0].KeyID = "replacement-lab"
		mutatedPath := filepath.Join(t.TempDir(), "trust-store.json")
		writeJSON(t, mutatedPath, mutatedStore)
		data, err := os.ReadFile(mutatedPath)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(data)
		mutatedPolicy := policy
		mutatedPolicy.TrustStoreSHA256 = hex.EncodeToString(digest[:])
		if err := validateTrustStoreAgainstPolicy(mutatedPath, &mutatedStore, &mutatedPolicy); err == nil || !strings.Contains(err.Error(), "key ID") {
			t.Fatalf("validateTrustStoreAgainstPolicy() error = %v, want key ID rejection", err)
		}
	})
}

func TestRepositoryTrustPolicyRejectsRunnerIdentityTampering(t *testing.T) {
	policy := &EvidenceTrustPolicy{
		SchemaVersion: 1, TrustStoreSHA256: strings.Repeat("1", 64),
		KeyID: "release-lab-2026", PublicKeySHA256: strings.Repeat("2", 64),
		Runner: EvidenceRunnerPolicy{
			ID: "flowersec-linux-release-v1", OS: "linux", Architecture: "amd64", KernelRelease: "6.12.1",
			Namespace: "isolated", TrafficControl: "tc-netem-v1", PacketCounters: "ebpf-v1", EffectiveConfigSHA256: signedRunnerConfigDigest,
			ExecutableSHA256: signedRunnerExecutableSHA, SourceSHA256: signedRunnerSourceSHA, ArgvSHA256: signedRunnerArgvSHA,
			EffectiveConfigPath: signedRunnerConfigPath,
		},
	}
	valid := EvidenceRunner{
		ID: "flowersec-linux-release-v1", OS: "linux", Architecture: "amd64", KernelRelease: "6.12.1",
		Namespace: "isolated", TrafficControl: "tc-netem-v1", PacketCounters: "ebpf-v1", EffectiveConfigSHA256: signedRunnerConfigDigest,
		ExecutableSHA256: signedRunnerExecutableSHA, SourceSHA256: signedRunnerSourceSHA, ArgvSHA256: signedRunnerArgvSHA,
	}
	for _, test := range []struct {
		name   string
		mutate func(*EvidenceRunner)
	}{
		{name: "runner ID", mutate: func(runner *EvidenceRunner) { runner.ID = "other-runner" }},
		{name: "OS", mutate: func(runner *EvidenceRunner) { runner.OS = "darwin" }},
		{name: "architecture", mutate: func(runner *EvidenceRunner) { runner.Architecture = "arm64" }},
		{name: "exact kernel", mutate: func(runner *EvidenceRunner) { runner.KernelRelease = "6.12.2" }},
		{name: "namespace", mutate: func(runner *EvidenceRunner) { runner.Namespace = "host" }},
		{name: "traffic control", mutate: func(runner *EvidenceRunner) { runner.TrafficControl = "disabled" }},
		{name: "packet counters", mutate: func(runner *EvidenceRunner) { runner.PacketCounters = "userspace" }},
		{name: "effective config", mutate: func(runner *EvidenceRunner) { runner.EffectiveConfigSHA256 = strings.Repeat("0", 64) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			mutated := valid
			test.mutate(&mutated)
			if err := validateRunnerAgainstPolicy(mutated, policy); err == nil || !strings.Contains(err.Error(), "runner identity") {
				t.Fatalf("validateRunnerAgainstPolicy() error = %v, want runner identity rejection", err)
			}
		})
	}
}

func TestEvidenceRequiresSignedSourceAndTDDEvidence(t *testing.T) {
	tests := []struct {
		name       string
		mutate     func(*EvidenceReport)
		wantStatus checkStatus
		wantIssue  string
	}{
		{name: "local smoke classification", mutate: func(report *EvidenceReport) { report.Classification = "local_smoke" }, wantStatus: statusFail, wantIssue: "classification"},
		{name: "invalid base SHA", mutate: func(report *EvidenceReport) { report.Source.BaseSHA = "base" }, wantStatus: statusInconclusive, wantIssue: "base_sha"},
		{name: "invalid final SHA", mutate: func(report *EvidenceReport) { report.Source.FinalSHA = "final" }, wantStatus: statusInconclusive, wantIssue: "final_sha"},
		{name: "same base and final", mutate: func(report *EvidenceReport) { report.Source.BaseSHA = report.Source.FinalSHA }, wantStatus: statusFail, wantIssue: "must differ"},
		{name: "dirty source", mutate: func(report *EvidenceReport) { report.Source.Dirty = boolPointer(true) }, wantStatus: statusFail, wantIssue: "dirty=false"},
		{name: "untracked source", mutate: func(report *EvidenceReport) { report.Source.UntrackedFileCount = intPointer(1) }, wantStatus: statusFail, wantIssue: "untracked_file_count"},
		{name: "missing TDD record", mutate: func(report *EvidenceReport) { report.TDD = nil }, wantStatus: statusInconclusive, wantIssue: "TDD evidence"},
		{name: "red unexpectedly passed", mutate: func(report *EvidenceReport) { report.TDD[0].Red.ExitCode = intPointer(0) }, wantStatus: statusFail, wantIssue: "red stage"},
		{name: "green failed", mutate: func(report *EvidenceReport) { report.TDD[0].Green.ExitCode = intPointer(1) }, wantStatus: statusFail, wantIssue: "green stage"},
		{name: "refactor log missing", mutate: func(report *EvidenceReport) { report.TDD[0].Refactor.Artifact = EvidenceArtifact{} }, wantStatus: statusInconclusive, wantIssue: "refactor stage artifact"},
		{
			name: "plain text TDD trace",
			mutate: func(report *EvidenceReport) {
				report.TDD[0].Green.Artifact = rewriteEvidenceArtifact(t, report.baseDir, report.TDD[0].Green.Artifact, []byte("go test passed\n"))
			},
			wantStatus: statusFail,
			wantIssue:  "not a bound structured evidence envelope",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manifest := loadFixtureManifest(t)
			registry := loadFixtureRegistry(t)
			report := completeReport(t, manifest, registry)
			test.mutate(report)
			result := checkEvidence(manifest, registry, report, report.baseDir)
			assertResult(t, result, test.wantStatus, test.wantIssue)
		})
	}
}

func TestEvidenceRequiresEveryFrozenTDDSlice(t *testing.T) {
	manifest := loadFixtureManifest(t)
	registry := loadFixtureRegistry(t)
	report := completeReport(t, manifest, registry)
	report.TDD = report.TDD[:len(report.TDD)-1]
	result := checkEvidence(manifest, registry, report, report.baseDir)
	assertResult(t, result, statusFail, "missing TDD evidence slice")
}

func TestEvidenceMatchesAuditedRepositoryState(t *testing.T) {
	manifest := loadFixtureManifest(t)
	registry := loadFixtureRegistry(t)
	report := completeReport(t, manifest, registry)
	expected := RepositoryState{
		BaseSHA: report.Source.BaseSHA, FinalSHA: report.Source.FinalSHA,
		Dirty: false, UntrackedFileCount: 0, BaseIsAncestor: true,
	}
	result := checkEvidenceAgainstRepository(manifest, registry, report, report.baseDir, expected)
	if result.Status != statusPass {
		t.Fatalf("matching repository state result = %#v", result)
	}
	expected.FinalSHA = strings.Repeat("c", 40)
	result = checkEvidenceAgainstRepository(manifest, registry, report, report.baseDir, expected)
	assertResult(t, result, statusFail, "repository HEAD")
	expected.FinalSHA = report.Source.FinalSHA
	expected.BaseSHA = strings.Repeat("c", 40)
	result = checkEvidenceAgainstRepository(manifest, registry, report, report.baseDir, expected)
	assertResult(t, result, statusFail, "repository base")
	expected.BaseSHA = report.Source.BaseSHA
	expected.Dirty = true
	result = checkEvidenceAgainstRepository(manifest, registry, report, report.baseDir, expected)
	assertResult(t, result, statusFail, "repository is not clean")
}

func TestEvidenceMetaSchemaAndGateClassifications(t *testing.T) {
	meta, err := loadEvidenceMetaSchema(fixturePath(t, "evidence_meta_schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := validateEvidenceMetaSchema(meta); err != nil {
		t.Fatalf("validate meta-schema: %v", err)
	}
	for _, test := range []struct {
		target         string
		classification string
		wantErr        string
	}{
		{target: "transport-v2-unit", classification: "contract_only"},
		{target: "transport-conformance-smoke", classification: "local_smoke"},
		{target: "transport-browser-smoke", classification: "local_smoke"},
		{target: "transport-interop-smoke", classification: "local_smoke"},
		{target: "weaknet-smoke", classification: "local_smoke"},
		{target: "quic-native-smoke", classification: "local_smoke"},
		{target: "quic-native-race-smoke", classification: "local_smoke"},
		{target: "weaknet-smoke", classification: "signed_transport_evidence", wantErr: "does not permit"},
		{target: "transport-v2-unit", classification: "local_smoke", wantErr: "does not permit"},
	} {
		err := validateGateDeclaration(meta, test.target, test.classification)
		if test.wantErr == "" && err != nil {
			t.Fatalf("valid gate %s/%s: %v", test.target, test.classification, err)
		}
		if test.wantErr != "" && (err == nil || !strings.Contains(err.Error(), test.wantErr)) {
			t.Fatalf("gate %s/%s error = %v", test.target, test.classification, err)
		}
	}
	mutated := *meta
	mutated.Gates = append([]EvidenceGateContract(nil), meta.Gates...)
	mutated.Gates[1].AllowedClassifications = []string{"local_smoke", "signed_transport_evidence"}
	if err := validateEvidenceMetaSchema(&mutated); err == nil || !strings.Contains(err.Error(), "frozen classification") {
		t.Fatalf("weakened meta-schema error = %v", err)
	}
}

func TestGateReportMustMatchDeclaredLocalClassification(t *testing.T) {
	meta, err := loadEvidenceMetaSchema(fixturePath(t, "evidence_meta_schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "smoke.json")
	writeJSON(t, path, map[string]any{"schema_version": 1, "classification": "local_smoke", "cases": []any{}})
	if err := validateGateReport(meta, "weaknet-smoke", "local_smoke", path); err != nil {
		t.Fatalf("valid local smoke report: %v", err)
	}
	if err := validateGateReport(meta, "weaknet-smoke", "local_smoke", ""); err == nil || !strings.Contains(err.Error(), "requires a report") {
		t.Fatalf("missing report error = %v", err)
	}
	writeJSON(t, path, map[string]any{"schema_version": 1, "classification": "signed_transport_evidence"})
	if err := validateGateReport(meta, "weaknet-smoke", "local_smoke", path); err == nil || !strings.Contains(err.Error(), "classification") {
		t.Fatalf("mismatched report error = %v", err)
	}
}

func TestMakeTargetsUseEvidenceClassificationGate(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	makefile := string(data)
	for _, required := range []string{
		"gate -meta ../../testdata/transport_v2/evidence_meta_schema.json -target transport-v2-unit -classification contract_only",
		"gate -meta ../../testdata/transport_v2/evidence_meta_schema.json -target transport-conformance-smoke -classification local_smoke",
		"gate -meta ../../testdata/transport_v2/evidence_meta_schema.json -target transport-browser-smoke -classification local_smoke",
		"gate -meta ../../testdata/transport_v2/evidence_meta_schema.json -target transport-interop-smoke -classification local_smoke",
		"gate -meta ../../testdata/transport_v2/evidence_meta_schema.json -target weaknet-smoke -classification local_smoke",
		"gate -meta ../../testdata/transport_v2/evidence_meta_schema.json -target quic-native-smoke -classification local_smoke",
		"gate -meta ../../testdata/transport_v2/evidence_meta_schema.json -target quic-native-race-smoke -classification local_smoke",
	} {
		if !strings.Contains(makefile, required) {
			t.Errorf("Makefile is missing evidence declaration gate %q", required)
		}
	}
	for _, required := range []string{
		"check: security-makefile-check security-dependency-check\n\t$(MAKE) release-policy-check",
		"\t$(MAKE) transport-v2-unit",
		"\t$(MAKE) weaknet-smoke",
		"\t$(MAKE) quic-native-smoke",
		"release-check:\n\t$(MAKE) check",
		"\t$(MAKE) transport-v2-signed-evidence-check",
		"override TRANSPORT_V2_TRUST_STORE := $(CURDIR)/testdata/transport_v2/evidence_trust_store.json",
		"override TRANSPORT_V2_TRUST_POLICY := $(CURDIR)/testdata/transport_v2/evidence_trust_policy.json",
		`./scripts/check-transport-v2-evidence.sh "$(TRANSPORT_V2_EVIDENCE_REPORT)" "$(TRANSPORT_V2_BASE_SHA)"`,
	} {
		if !strings.Contains(makefile, required) {
			t.Errorf("Makefile is missing Transport v2 gate wiring %q", required)
		}
	}
	for _, target := range []string{
		"transport-conformance-smoke",
		"transport-browser-smoke",
		"transport-interop-smoke",
		"transport-conformance-full",
		"quic-native-proof",
		"quic-native-race",
		"quic-native-race-smoke",
		"weaknet-full",
		"weaknet-system",
		"bench-transport-capacity",
		"bench-transport-ab",
	} {
		command := exec.Command("make", "-n", target)
		command.Dir = filepath.Join("..", "..")
		if output, err := command.CombinedOutput(); err != nil {
			t.Errorf("Make target %s is unavailable: %v: %s", target, err, output)
		}
	}
}

func TestExternalReleaseEvidenceTargetsFailClosedWithoutRunner(t *testing.T) {
	for _, target := range []string{
		"transport-conformance-full",
		"quic-native-proof",
		"quic-native-race",
		"weaknet-full",
		"weaknet-system",
		"bench-transport-capacity",
		"bench-transport-ab",
	} {
		t.Run(target, func(t *testing.T) {
			command := exec.Command(
				"make", "--no-print-directory", target,
				"TRANSPORT_V2_RELEASE_RUNNER=", "TRANSPORT_V2_EVIDENCE_REPORT=",
				"TRANSPORT_V2_BASE_SHA=", "TRANSPORT_V2_TRUST_STORE=",
			)
			command.Dir = filepath.Join("..", "..")
			output, err := command.CombinedOutput()
			if err == nil || !strings.Contains(string(output), "requires TRANSPORT_V2_RELEASE_RUNNER") {
				t.Fatalf("make %s error = %v output = %s, want fail-closed runner requirement", target, err, output)
			}
		})
	}
}

func TestReleaseCheckRunsOneFailClosedAllEvidenceRunner(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	makefile := string(data)
	for _, required := range []string{
		"transport-v2-release-evidence:",
		`"$(TRANSPORT_V2_RELEASE_RUNNER)" --target all --report "$(TRANSPORT_V2_EVIDENCE_REPORT)"`,
		"\t$(MAKE) transport-v2-release-evidence",
	} {
		if !strings.Contains(makefile, required) {
			t.Errorf("Makefile is missing all-evidence release runner wiring %q", required)
		}
	}
	command := exec.Command(
		"make", "--no-print-directory", "transport-v2-release-evidence",
		"TRANSPORT_V2_RELEASE_RUNNER=", "TRANSPORT_V2_EVIDENCE_REPORT=",
		"TRANSPORT_V2_BASE_SHA=", "TRANSPORT_V2_TRUST_STORE=",
	)
	command.Dir = filepath.Join("..", "..")
	output, err := command.CombinedOutput()
	if err == nil || !strings.Contains(string(output), "requires TRANSPORT_V2_RELEASE_RUNNER") {
		t.Fatalf("all-evidence release target error = %v output = %s, want fail-closed runner requirement", err, output)
	}
}

func TestReleaseCheckUsesRepositoryAuditedTrustPolicy(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	makefile := string(data)
	if strings.Contains(makefile, "TRANSPORT_V2_TRUST_STORE ?=") {
		t.Fatal("release gate permits a caller-selected trust store")
	}
	for _, required := range []string{"TRANSPORT_V2_TRUST_POLICY :=", "TRANSPORT_V2_TRUST_STORE :="} {
		if !strings.Contains(makefile, required) {
			t.Fatalf("Makefile is missing repository-audited trust wiring %q", required)
		}
	}
}

func TestEvidenceRejectsIncompleteOrInvalidPerformanceEvidence(t *testing.T) {
	tests := []struct {
		name       string
		mutate     func(*EvidenceReport)
		wantStatus checkStatus
		wantIssue  string
	}{
		{
			name: "missing run",
			mutate: func(report *EvidenceReport) {
				report.Cells[0].Runs = report.Cells[0].Runs[:14]
			},
			wantStatus: statusFail,
			wantIssue:  "exactly 15 independent runs",
		},
		{
			name: "missing sample",
			mutate: func(report *EvidenceReport) {
				report.Cells[0].Runs[0].Phases[0].SampleCount = nil
			},
			wantStatus: statusInconclusive,
			wantIssue:  "sample_count",
		},
		{
			name: "insufficient samples",
			mutate: func(report *EvidenceReport) {
				report.Cells[0].Runs[0].Phases[0].SampleCount = intPointer(1999)
			},
			wantStatus: statusInconclusive,
			wantIssue:  "sample_count",
		},
		{
			name: "missing failure count",
			mutate: func(report *EvidenceReport) {
				report.Cells[0].Runs[0].Phases[0].FailureCount = nil
			},
			wantStatus: statusInconclusive,
			wantIssue:  "missing failure_count",
		},
		{
			name: "missing retry count",
			mutate: func(report *EvidenceReport) {
				report.Cells[0].Runs[0].Phases[0].RetryCount = nil
			},
			wantStatus: statusInconclusive,
			wantIssue:  "missing retry_count",
		},
		{
			name: "failure sample",
			mutate: func(report *EvidenceReport) {
				report.Cells[0].Runs[0].Phases[0].FailureCount = intPointer(1)
			},
			wantStatus: statusFail,
			wantIssue:  "failure_count",
		},
		{
			name: "retry",
			mutate: func(report *EvidenceReport) {
				report.Cells[0].Runs[0].Phases[0].RetryCount = intPointer(1)
			},
			wantStatus: statusFail,
			wantIssue:  "retry_count",
		},
		{
			name: "missing metric",
			mutate: func(report *EvidenceReport) {
				delete(report.Cells[0].Runs[0].Phases[0].Artifacts, "metrics")
			},
			wantStatus: statusInconclusive,
			wantIssue:  "metrics artifact",
		},
		{
			name: "missing trace",
			mutate: func(report *EvidenceReport) {
				delete(report.Cells[0].Runs[0].Phases[0].Artifacts, "trace")
			},
			wantStatus: statusInconclusive,
			wantIssue:  "trace artifact",
		},
		{
			name: "missing pcap",
			mutate: func(report *EvidenceReport) {
				delete(report.Cells[0].Runs[0].Phases[0].Artifacts, "pcap")
			},
			wantStatus: statusInconclusive,
			wantIssue:  "pcap artifact",
		},
		{
			name: "missing config",
			mutate: func(report *EvidenceReport) {
				delete(report.Cells[0].Runs[0].Phases[0].Artifacts, "config")
			},
			wantStatus: statusInconclusive,
			wantIssue:  "config artifact",
		},
		{
			name: "artifact digest mismatch",
			mutate: func(report *EvidenceReport) {
				artifact := report.Cells[0].Runs[0].Phases[0].Artifacts["samples"]
				artifact.SHA256 = strings.Repeat("0", 64)
				report.Cells[0].Runs[0].Phases[0].Artifacts["samples"] = artifact
			},
			wantStatus: statusFail,
			wantIssue:  "digest mismatch",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manifest := loadFixtureManifest(t)
			registry := loadFixtureRegistry(t)
			report := completeReport(t, manifest, registry)
			test.mutate(report)
			result := checkEvidence(manifest, registry, report, report.baseDir)
			assertResult(t, result, test.wantStatus, test.wantIssue)
		})
	}
}

func TestEvidenceRequiresQlogOnlyForQUICFamilyTopologies(t *testing.T) {
	tests := []struct {
		name       string
		cellID     string
		wantStatus checkStatus
		wantIssue  string
	}{
		{name: "WSS only", cellID: "edge-01", wantStatus: statusPass},
		{name: "QUIC only", cellID: "edge-02", wantStatus: statusInconclusive, wantIssue: "qlog artifact"},
		{name: "mixed WSS QUIC", cellID: "edge-05", wantStatus: statusInconclusive, wantIssue: "qlog artifact"},
		{name: "browser WebTransport", cellID: "clean-08", wantStatus: statusInconclusive, wantIssue: "qlog artifact"},
		{name: "adaptive", cellID: "adaptive-selection-01", wantStatus: statusInconclusive, wantIssue: "qlog artifact"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manifest := loadFixtureManifest(t)
			registry := loadFixtureRegistry(t)
			report := completeReport(t, manifest, registry)
			cell := evidenceCellByID(t, report, test.cellID)
			delete(cell.Runs[0].Phases[0].Artifacts, "qlog")
			result := checkEvidence(manifest, registry, report, report.baseDir)
			if test.wantStatus == statusPass {
				if result.Status != statusPass || len(result.Issues) != 0 {
					t.Fatalf("result = %#v, want pass", result)
				}
			} else {
				assertResult(t, result, test.wantStatus, test.wantIssue)
			}
		})
	}
}

func TestEvidenceRequiresEveryDeclaredVariantInEveryRun(t *testing.T) {
	manifest := loadFixtureManifest(t)
	registry := loadFixtureRegistry(t)
	report := completeReport(t, manifest, registry)
	cell := evidenceCellByID(t, report, "clean-01")
	cell.Runs[0].Variants = cell.Runs[0].Variants[:1]
	result := checkEvidence(manifest, registry, report, report.baseDir)
	assertResult(t, result, statusInconclusive, "missing variant candidate")
}

func TestEvidenceEnforcesForcedAndAdaptiveSelection(t *testing.T) {
	tests := []struct {
		name       string
		cell       string
		mutate     func(*SelectionEvidence)
		wantStatus checkStatus
		wantIssue  string
	}{
		{
			name: "forced starts second candidate",
			cell: "clean-01",
			mutate: func(selection *SelectionEvidence) {
				selection.StartedCandidates["unexpected"] = 1
			},
			wantStatus: statusFail,
			wantIssue:  "forced candidate set",
		},
		{
			name: "forced misses operation start",
			cell: "clean-01",
			mutate: func(selection *SelectionEvidence) {
				for candidate := range selection.StartedCandidates {
					selection.StartedCandidates[candidate]--
				}
			},
			wantStatus: statusInconclusive,
			wantIssue:  "started count",
		},
		{
			name: "adaptive omits supported candidate",
			cell: "adaptive-selection-01",
			mutate: func(selection *SelectionEvidence) {
				for candidate := range selection.StartedCandidates {
					delete(selection.StartedCandidates, candidate)
					break
				}
			},
			wantStatus: statusInconclusive,
			wantIssue:  "adaptive candidate set",
		},
		{
			name: "adaptive does not use one barrier",
			cell: "adaptive-selection-01",
			mutate: func(selection *SelectionEvidence) {
				selection.SingleBarrierOperations--
			},
			wantStatus: statusFail,
			wantIssue:  "single barrier",
		},
		{
			name: "adaptive commits twice",
			cell: "adaptive-selection-01",
			mutate: func(selection *SelectionEvidence) {
				selection.CommitCount++
			},
			wantStatus: statusFail,
			wantIssue:  "commit_count",
		},
		{
			name: "adaptive writes credentials twice",
			cell: "adaptive-selection-01",
			mutate: func(selection *SelectionEvidence) {
				selection.CredentialWriteCount++
			},
			wantStatus: statusFail,
			wantIssue:  "credential_write_count",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manifest := loadFixtureManifest(t)
			registry := loadFixtureRegistry(t)
			report := completeReport(t, manifest, registry)
			cell := evidenceCellByID(t, report, test.cell)
			phases := cell.Runs[0].Phases
			if len(cell.Runs[0].Variants) != 0 {
				phases = cell.Runs[0].Variants[0].Phases
			}
			test.mutate(&phases[0].Selection)
			result := checkEvidence(manifest, registry, report, report.baseDir)
			assertResult(t, result, test.wantStatus, test.wantIssue)
		})
	}
}

func TestEvidenceRejectsUnknownDuplicateMissingAndWrongOwnerCases(t *testing.T) {
	tests := []struct {
		name       string
		mutate     func(*EvidenceReport)
		wantStatus checkStatus
		wantIssue  string
	}{
		{
			name: "unknown case ID",
			mutate: func(report *EvidenceReport) {
				report.Cases[0].ID = "UNKNOWN"
			},
			wantStatus: statusFail,
			wantIssue:  "unknown case ID",
		},
		{
			name: "duplicate case ID",
			mutate: func(report *EvidenceReport) {
				report.Cases = append(report.Cases, report.Cases[0])
			},
			wantStatus: statusFail,
			wantIssue:  "duplicate normal evidence",
		},
		{
			name: "missing case ID",
			mutate: func(report *EvidenceReport) {
				report.Cases = report.Cases[1:]
			},
			wantStatus: statusFail,
			wantIssue:  "missing normal evidence",
		},
		{
			name: "wrong owner",
			mutate: func(report *EvidenceReport) {
				report.Cases[0].Owner = "another-target"
			},
			wantStatus: statusFail,
			wantIssue:  "owner",
		},
		{
			name: "race presented as normal",
			mutate: func(report *EvidenceReport) {
				report.Cases[0].Mode = "race"
			},
			wantStatus: statusFail,
			wantIssue:  "mode",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manifest := loadFixtureManifest(t)
			registry := loadFixtureRegistry(t)
			report := completeReport(t, manifest, registry)
			test.mutate(report)
			result := checkEvidence(manifest, registry, report, report.baseDir)
			assertResult(t, result, test.wantStatus, test.wantIssue)
		})
	}
}

func TestStrictJSONRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "manifest.json")
	data := []byte(`{"schema_version":1,"digest":"x","unknown":true}`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadPerformanceManifest(path); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("loadPerformanceManifest() error = %v, want unknown field", err)
	}
}

func TestEvidenceCLIUsesNonzeroErrorForFailAndInconclusive(t *testing.T) {
	manifestPath := fixturePath(t, "performance_manifest.json")
	registryPath := fixturePath(t, "case_registry.json")
	manifest := loadFixtureManifest(t)
	registry := loadFixtureRegistry(t)
	repositoryPath, baseSHA, finalSHA := newCleanTestRepository(t)
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x7c}, ed25519.SeedSize))
	trustStorePath := filepath.Join(t.TempDir(), "trust-store.json")
	writeJSON(t, trustStorePath, EvidenceTrustStore{
		SchemaVersion: 1,
		Keys: []TrustedEvidenceKey{{
			KeyID:     "release-cli-test",
			PublicKey: base64.StdEncoding.EncodeToString(privateKey.Public().(ed25519.PublicKey)),
		}},
	})
	trustStoreData, err := os.ReadFile(trustStorePath)
	if err != nil {
		t.Fatal(err)
	}
	trustStoreDigest := sha256.Sum256(trustStoreData)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	publicKeyDigest := sha256.Sum256(publicKey)
	trustPolicyDir := t.TempDir()
	trustPolicyPath := filepath.Join(trustPolicyDir, "trust-policy.json")
	runnerConfig, err := os.ReadFile(fixturePath(t, signedRunnerConfigPath))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(trustPolicyDir, signedRunnerConfigPath), runnerConfig, 0o600); err != nil {
		t.Fatal(err)
	}
	writeJSON(t, trustPolicyPath, EvidenceTrustPolicy{
		SchemaVersion: 1, TrustStoreSHA256: hex.EncodeToString(trustStoreDigest[:]),
		KeyID: "release-cli-test", PublicKeySHA256: hex.EncodeToString(publicKeyDigest[:]),
		Runner: EvidenceRunnerPolicy{
			ID: "flowersec-linux-release-v1", OS: "linux", Architecture: "amd64", KernelRelease: "6.12.1",
			Namespace: "isolated", TrafficControl: "tc-netem-v1", PacketCounters: "ebpf-v1", EffectiveConfigSHA256: signedRunnerConfigDigest,
			ExecutableSHA256: signedRunnerExecutableSHA, SourceSHA256: signedRunnerSourceSHA, ArgvSHA256: signedRunnerArgvSHA,
			EffectiveConfigPath: signedRunnerConfigPath,
		},
	})

	for _, test := range []struct {
		name   string
		mutate func(*EvidenceReport)
		want   string
	}{
		{
			name: "fail",
			mutate: func(report *EvidenceReport) {
				report.Cells[0].Runs[0].Phases[0].FailureCount = intPointer(1)
			},
			want: "fail",
		},
		{
			name: "missing run is fail-closed",
			mutate: func(report *EvidenceReport) {
				report.Cells[0].Runs = report.Cells[0].Runs[:14]
			},
			want: "fail",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			report := completeReport(t, manifest, registry)
			report.Source.BaseSHA = baseSHA
			report.Source.FinalSHA = finalSHA
			test.mutate(report)
			signEvidenceReportForTest(t, report, "release-cli-test", privateKey)
			reportPath := filepath.Join(report.baseDir, "report.json")
			writeJSON(t, reportPath, report)
			var output bytes.Buffer
			err := run([]string{
				"evidence", "-manifest", manifestPath, "-registry", registryPath, "-report", reportPath,
				"-repo", repositoryPath, "-base-sha", baseSHA, "-trust-store", trustStorePath, "-trust-policy", trustPolicyPath,
			}, &output)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("run() error = %v, want nonzero %s", err, test.want)
			}
		})
	}

	t.Run("pass", func(t *testing.T) {
		report := completeReport(t, manifest, registry)
		report.Source.BaseSHA = baseSHA
		report.Source.FinalSHA = finalSHA
		signEvidenceReportForTest(t, report, "release-cli-test", privateKey)
		reportPath := filepath.Join(report.baseDir, "report.json")
		writeJSON(t, reportPath, report)
		var output bytes.Buffer
		err := run([]string{
			"evidence", "-manifest", manifestPath, "-registry", registryPath, "-report", reportPath,
			"-repo", repositoryPath, "-base-sha", baseSHA, "-trust-store", trustStorePath, "-trust-policy", trustPolicyPath,
		}, &output)
		if err != nil || !strings.Contains(output.String(), "evidence pass") {
			t.Fatalf("run() error = %v output = %q, want pass", err, output.String())
		}
	})

	t.Run("missing trust store", func(t *testing.T) {
		var output bytes.Buffer
		err := run([]string{
			"evidence", "-manifest", manifestPath, "-registry", registryPath, "-report", "report.json",
			"-repo", repositoryPath, "-base-sha", baseSHA,
		}, &output)
		if err == nil || !strings.Contains(err.Error(), "trust-store") {
			t.Fatalf("run() error = %v, want trust-store requirement", err)
		}
	})
}

func TestNewCleanTestRepositoryIgnoresOuterGitEnvironment(t *testing.T) {
	outerGitDir := filepath.Join(t.TempDir(), "outer.git")
	t.Setenv("GIT_DIR", outerGitDir)
	t.Setenv("GIT_WORK_TREE", t.TempDir())
	t.Setenv("GIT_INDEX_FILE", filepath.Join(t.TempDir(), "outer.index"))

	repositoryPath, baseSHA, finalSHA := newCleanTestRepository(t)
	if repositoryPath == "" || baseSHA == "" || finalSHA == "" {
		t.Fatal("newCleanTestRepository() returned an incomplete repository")
	}
	if baseSHA == finalSHA {
		t.Fatal("newCleanTestRepository() returned identical base and final commits")
	}
}

func newCleanTestRepository(t *testing.T) (string, string, string) {
	t.Helper()
	directory := t.TempDir()
	runGitTestCommand(t, directory, "init", "-q")
	path := filepath.Join(directory, "evidence.txt")
	if err := os.WriteFile(path, []byte("base\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runGitTestCommand(t, directory, "add", "evidence.txt")
	runGitTestCommand(t, directory, "-c", "user.name=Transport Check", "-c", "user.email=transport@example.invalid", "commit", "-qm", "base")
	baseSHA := gitTestOutput(t, directory, "rev-parse", "HEAD")
	if err := os.WriteFile(path, []byte("final\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runGitTestCommand(t, directory, "add", "evidence.txt")
	runGitTestCommand(t, directory, "-c", "user.name=Transport Check", "-c", "user.email=transport@example.invalid", "commit", "-qm", "final")
	return directory, baseSHA, gitTestOutput(t, directory, "rev-parse", "HEAD")
}

func runGitTestCommand(t *testing.T, directory string, args ...string) {
	t.Helper()
	command := exec.Command("git", append([]string{"-C", directory}, args...)...)
	command.Env = repositoryGitEnvironment()
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v: %s", args, err, output)
	}
}

func gitTestOutput(t *testing.T, directory string, args ...string) string {
	t.Helper()
	command := exec.Command("git", append([]string{"-C", directory}, args...)...)
	command.Env = repositoryGitEnvironment()
	output, err := command.Output()
	if err != nil {
		t.Fatalf("git %v: %v", args, err)
	}
	return strings.TrimSpace(string(output))
}

func loadFixtureManifest(t *testing.T) *PerformanceManifest {
	t.Helper()
	manifest, err := loadPerformanceManifest(fixturePath(t, "performance_manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	return manifest
}

func loadFixtureRegistry(t *testing.T) *CaseRegistry {
	t.Helper()
	registry, err := loadCaseRegistry(fixturePath(t, "case_registry.json"))
	if err != nil {
		t.Fatal(err)
	}
	return registry
}

func fixturePath(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join("..", "..", "testdata", "transport_v2", name)
}

func profileByID(t *testing.T, manifest *PerformanceManifest, id string) *PerformanceProfile {
	t.Helper()
	for index := range manifest.Profiles {
		if manifest.Profiles[index].ID == id {
			return &manifest.Profiles[index]
		}
	}
	t.Fatalf("profile %q not found", id)
	return nil
}

func evidenceCellByID(t *testing.T, report *EvidenceReport, id string) *CellEvidence {
	t.Helper()
	for index := range report.Cells {
		if report.Cells[index].CellID == id {
			return &report.Cells[index]
		}
	}
	t.Fatalf("cell %q not found", id)
	return nil
}

func caseEvidenceByID(t *testing.T, report *EvidenceReport, id string) *CaseEvidence {
	t.Helper()
	for index := range report.Cases {
		if report.Cases[index].ID == id && report.Cases[index].Mode == "normal" {
			return &report.Cases[index]
		}
	}
	t.Fatalf("normal case %q not found", id)
	return nil
}

func caseEvidenceByModeAndID(t *testing.T, report *EvidenceReport, mode, id string) *CaseEvidence {
	t.Helper()
	for index := range report.Cases {
		if report.Cases[index].ID == id && report.Cases[index].Mode == mode {
			return &report.Cases[index]
		}
	}
	t.Fatalf("%s case %q not found", mode, id)
	return nil
}

func cellMetricByDerivation(t *testing.T, report *EvidenceReport, derivation string) (*CellEvidence, string) {
	t.Helper()
	for cellIndex := range report.Cells {
		cell := &report.Cells[cellIndex]
		for metricID := range cell.Metrics {
			if requiredMetricDerivation(metricID) == derivation {
				return cell, metricID
			}
		}
	}
	t.Fatalf("metric derivation %q not found", derivation)
	return nil, ""
}

func rewriteMetricSamplesArtifact(t *testing.T, report *EvidenceReport, cell *CellEvidence, metricID string, mutate func(*MetricSamplesArtifact)) {
	t.Helper()
	metric := cell.Metrics[metricID]
	data, err := os.ReadFile(filepath.Join(report.baseDir, metric.RawSamples.Path))
	if err != nil {
		t.Fatal(err)
	}
	var samples MetricSamplesArtifact
	if err := decodeStrictJSON(data, &samples); err != nil {
		t.Fatal(err)
	}
	mutate(&samples)
	data, err = json.Marshal(samples)
	if err != nil {
		t.Fatal(err)
	}
	metric.RawSamples = rewriteEvidenceArtifact(t, report.baseDir, metric.RawSamples, data)
	cell.Metrics[metricID] = metric
}

func rewritePerformanceFaultTrace(t *testing.T, report *EvidenceReport, cell *CellEvidence, runNumber int, mutate func(*TraceArtifact)) {
	t.Helper()
	run := &cell.Runs[runNumber-1]
	phase := &run.Phases[slices.IndexFunc(run.Phases, func(phase PhaseEvidence) bool { return phase.Phase == "rpc" })]
	old := phase.Artifacts["trace"]
	data, err := os.ReadFile(filepath.Join(report.baseDir, old.Path))
	if err != nil {
		t.Fatal(err)
	}
	var trace TraceArtifact
	if err := decodeStrictJSON(data, &trace); err != nil {
		t.Fatal(err)
	}
	mutate(&trace)
	slices.SortStableFunc(trace.Records, func(left, right TraceRecord) int { return cmp.Compare(left.AtNS, right.AtNS) })
	for index := range trace.Records {
		trace.Records[index].Sequence = uint64(index + 1)
	}
	data, err = json.Marshal(trace)
	if err != nil {
		t.Fatal(err)
	}
	phase.Artifacts["trace"] = rewriteEvidenceArtifact(t, report.baseDir, old, data)
	for metricID := range cell.Metrics {
		if !requiresMetricFaultBinding(metricID) {
			continue
		}
		rewriteMetricSamplesArtifact(t, report, cell, metricID, func(samples *MetricSamplesArtifact) {
			binding := samples.Runs[runNumber-1].FaultBinding
			if binding != nil && binding.TraceSHA256 == old.SHA256 {
				binding.TraceSHA256 = phase.Artifacts["trace"].SHA256
			}
		})
	}
}

func rewritePerformanceMigrationQlog(t *testing.T, report *EvidenceReport, cell *CellEvidence, runNumber int, mutate func([]any)) {
	t.Helper()
	run := &cell.Runs[runNumber-1]
	phase := &run.Phases[slices.IndexFunc(run.Phases, func(phase PhaseEvidence) bool { return phase.Phase == "rpc" })]
	old := phase.Artifacts["qlog"]
	data, err := os.ReadFile(filepath.Join(report.baseDir, old.Path))
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	traces := document["traces"].([]any)
	events := traces[0].(map[string]any)["events"].([]any)
	for _, raw := range events {
		fields := raw.([]any)
		if fields[1] == "application" && fields[2] == "rpc_completed" {
			mutate(fields)
		}
	}
	data, err = json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	phase.Artifacts["qlog"] = rewriteEvidenceArtifact(t, report.baseDir, old, data)
	configRef := phase.Artifacts["config"]
	configData, err := os.ReadFile(filepath.Join(report.baseDir, configRef.Path))
	if err != nil {
		t.Fatal(err)
	}
	var config ConfigArtifact
	if err := decodeStrictJSON(configData, &config); err != nil {
		t.Fatal(err)
	}
	for index := range config.Records {
		if config.Records[index].Key == "qlog_sha256" {
			config.Records[index].Value = phase.Artifacts["qlog"].SHA256
		}
	}
	configData, err = json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	phase.Artifacts["config"] = rewriteEvidenceArtifact(t, report.baseDir, configRef, configData)
	for metricID := range cell.Metrics {
		if !requiresMetricFaultBinding(metricID) {
			continue
		}
		rewriteMetricSamplesArtifact(t, report, cell, metricID, func(samples *MetricSamplesArtifact) {
			binding := samples.Runs[runNumber-1].FaultBinding
			if binding != nil && binding.QlogSHA256 == old.SHA256 {
				binding.QlogSHA256 = phase.Artifacts["qlog"].SHA256
			}
		})
	}
}

func rebindResourceDigest(t *testing.T, report *EvidenceReport, cell *CellEvidence, runNumber int, oldDigest, newDigest string) {
	t.Helper()
	for metricID := range cell.Metrics {
		rewriteMetricSamplesArtifact(t, report, cell, metricID, func(samples *MetricSamplesArtifact) {
			for runIndex := range samples.Runs {
				run := &samples.Runs[runIndex]
				if run.RunNumber != runNumber {
					continue
				}
				for sourceIndex := range run.Sources {
					source := &run.Sources[sourceIndex]
					if source.Kind == "resource" && source.ArtifactSHA256 == oldDigest {
						source.ArtifactSHA256 = newDigest
					}
				}
			}
		})
	}
}

func writeWSSPMTUDTerminalEvidence(t *testing.T, report *EvidenceReport, evidence *CaseEvidence, recovered bool) {
	t.Helper()
	context := "case " + evidence.ID
	terminal, firewall, event := "timed_out", "drop-icmp-ptb", "pmtud_timed_out"
	metrics := []MetricCounterRecord{
		{Name: "watchdog_timeouts", Value: 0, Unit: "count"},
		{Name: "rpc_completed", Value: 0, Unit: "count"},
		{Name: "timeout_observed", Value: 1, Unit: "count"},
	}
	tcpInfo := []TCPInfoRecord{fixtureTCPInfoRecordForContext(context, 500_000_000, 1500, 0), fixtureTCPInfoRecordForContext(context, 2_000_000_000, 1500, 10)}
	if recovered {
		terminal, firewall, event = "recovered", "allow-icmp-ptb", "pmtud_recovered"
		metrics = []MetricCounterRecord{
			{Name: "watchdog_timeouts", Value: 0, Unit: "count"},
			{Name: "rpc_completed", Value: 1, Unit: "count"},
			{Name: "timeout_observed", Value: 0, Unit: "count"},
		}
		tcpInfo = []TCPInfoRecord{fixtureTCPInfoRecordForContext(context, 500_000_000, 1500, 0), fixtureTCPInfoRecordForContext(context, 2_000_000_000, 1200, 1)}
	}
	digest := sha256.Sum256([]byte(context + "\x00opposite-terminal"))
	values := map[string]any{
		"metrics": MetricsArtifact{SchemaVersion: 1, Kind: "transport_metrics", Context: context, Records: metrics},
		"config": ConfigArtifact{SchemaVersion: 1, Kind: "transport_config", Context: context, Records: []ConfigRecord{
			{Key: "actual_terminal", Value: terminal}, {Key: "expected_terminal", Value: terminal},
			{Key: "firewall", Value: firewall}, {Key: "namespace", Value: "isolated"},
			{Key: "os", Value: "linux"}, {Key: "watchdog", Value: "completed"},
		}},
		"trace": TraceArtifact{SchemaVersion: 1, Kind: "transport_trace", Context: context, Records: []TraceRecord{{
			Sequence: 1, AtNS: 1, Event: event, Digest: hex.EncodeToString(digest[:]),
		}}},
		"tcp_info": TCPInfoArtifact{SchemaVersion: 1, Kind: "transport_tcp_info", Context: context, Records: tcpInfo},
	}
	for kind, value := range values {
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		evidence.Evidence[kind] = rewriteEvidenceArtifact(t, report.baseDir, evidence.Evidence[kind], data)
	}
}

func manifestCellByID(t *testing.T, manifest *PerformanceManifest, id string) *PerformanceCell {
	t.Helper()
	for index := range manifest.Cells {
		if manifest.Cells[index].ID == id {
			return &manifest.Cells[index]
		}
	}
	t.Fatalf("manifest cell %q not found", id)
	return nil
}

func cellWithDecisionMetric(t *testing.T, manifest *PerformanceManifest, report *EvidenceReport, decision string) (*CellEvidence, MetricContract) {
	t.Helper()
	contracts := make(map[string]MetricContract, len(manifest.MetricContracts))
	for _, contract := range manifest.MetricContracts {
		contracts[contract.ID] = contract
	}
	for index := range report.Cells {
		cell := &report.Cells[index]
		for metricID := range cell.Metrics {
			contract := contracts[metricID]
			if contract.Decision == decision && requiredMetricDerivation(metricID) != "ratio" {
				return cell, contract
			}
		}
	}
	for index := range report.Cells {
		cell := &report.Cells[index]
		for metricID := range cell.Metrics {
			contract := contracts[metricID]
			if contract.Decision == decision {
				return cell, contract
			}
		}
	}
	t.Fatalf("decision metric %q not found", decision)
	return nil, MetricContract{}
}

func refreshManifestDigest(t *testing.T, manifest *PerformanceManifest) {
	t.Helper()
	digest, err := manifestDigest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifest.Digest = digest
}

func rewritePhaseMetricCounter(t *testing.T, report *EvidenceReport, phase *PhaseEvidence, name string, value float64, bindDigest bool) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(report.baseDir, phase.Artifacts["metrics"].Path))
	if err != nil {
		t.Fatal(err)
	}
	var metrics MetricsArtifact
	if err := decodeStrictJSON(data, &metrics); err != nil {
		t.Fatal(err)
	}
	found := false
	for index := range metrics.Records {
		if metrics.Records[index].Name == name {
			metrics.Records[index].Value = value
			found = true
		}
	}
	if !found {
		t.Fatalf("phase metric %s is missing", name)
	}
	data, err = json.Marshal(metrics)
	if err != nil {
		t.Fatal(err)
	}
	phase.Artifacts["metrics"] = rewriteEvidenceArtifact(t, report.baseDir, phase.Artifacts["metrics"], data)
	if !bindDigest {
		return
	}
	configData, err := os.ReadFile(filepath.Join(report.baseDir, phase.Artifacts["config"].Path))
	if err != nil {
		t.Fatal(err)
	}
	var config ConfigArtifact
	if err := decodeStrictJSON(configData, &config); err != nil {
		t.Fatal(err)
	}
	for index := range config.Records {
		if config.Records[index].Key == "ebpf_metrics_sha256" {
			config.Records[index].Value = phase.Artifacts["metrics"].SHA256
		}
	}
	configData, err = json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	phase.Artifacts["config"] = rewriteEvidenceArtifact(t, report.baseDir, phase.Artifacts["config"], configData)
}

func rewriteCaseMetricCounter(t *testing.T, report *EvidenceReport, evidence *CaseEvidence, name string, value float64) {
	t.Helper()
	ref := evidence.Evidence["metrics"]
	data, err := os.ReadFile(filepath.Join(report.baseDir, ref.Path))
	if err != nil {
		t.Fatal(err)
	}
	var metrics MetricsArtifact
	if err := decodeStrictJSON(data, &metrics); err != nil {
		t.Fatal(err)
	}
	found := false
	for index := range metrics.Records {
		if metrics.Records[index].Name == name {
			metrics.Records[index].Value = value
			found = true
		}
	}
	if !found {
		t.Fatalf("case metric %s is missing", name)
	}
	data, err = json.Marshal(metrics)
	if err != nil {
		t.Fatal(err)
	}
	evidence.Evidence["metrics"] = rewriteEvidenceArtifact(t, report.baseDir, ref, data)
}

func rewriteCaseTrace(t *testing.T, report *EvidenceReport, evidence *CaseEvidence, mutate func(*TraceArtifact)) {
	t.Helper()
	ref := evidence.Evidence["trace"]
	data, err := os.ReadFile(filepath.Join(report.baseDir, ref.Path))
	if err != nil {
		t.Fatal(err)
	}
	var trace TraceArtifact
	if err := decodeStrictJSON(data, &trace); err != nil {
		t.Fatal(err)
	}
	mutate(&trace)
	data, err = json.Marshal(trace)
	if err != nil {
		t.Fatal(err)
	}
	evidence.Evidence["trace"] = rewriteEvidenceArtifact(t, report.baseDir, ref, data)
}

func rewriteCaseResource(t *testing.T, report *EvidenceReport, evidence *CaseEvidence, mutate func(*ResourceArtifact)) {
	t.Helper()
	ref := evidence.Evidence["resource"]
	data, err := os.ReadFile(filepath.Join(report.baseDir, ref.Path))
	if err != nil {
		t.Fatal(err)
	}
	var resource ResourceArtifact
	if err := decodeStrictJSON(data, &resource); err != nil {
		t.Fatal(err)
	}
	mutate(&resource)
	data, err = json.Marshal(resource)
	if err != nil {
		t.Fatal(err)
	}
	evidence.Evidence["resource"] = rewriteEvidenceArtifact(t, report.baseDir, ref, data)
}

func rewriteCaseConfigValue(t *testing.T, report *EvidenceReport, evidence *CaseEvidence, key, value string) {
	t.Helper()
	ref := evidence.Evidence["config"]
	data, err := os.ReadFile(filepath.Join(report.baseDir, ref.Path))
	if err != nil {
		t.Fatal(err)
	}
	var config ConfigArtifact
	if err := decodeStrictJSON(data, &config); err != nil {
		t.Fatal(err)
	}
	found := false
	for index := range config.Records {
		if config.Records[index].Key == key {
			config.Records[index].Value = value
			found = true
		}
	}
	if !found {
		t.Fatalf("case config %s is missing", key)
	}
	data, err = json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	evidence.Evidence["config"] = rewriteEvidenceArtifact(t, report.baseDir, ref, data)
}

func rewriteOrAddCaseConfigValue(t *testing.T, report *EvidenceReport, evidence *CaseEvidence, key, value string) {
	t.Helper()
	ref := evidence.Evidence["config"]
	data, err := os.ReadFile(filepath.Join(report.baseDir, ref.Path))
	if err != nil {
		t.Fatal(err)
	}
	var config ConfigArtifact
	if err := decodeStrictJSON(data, &config); err != nil {
		t.Fatal(err)
	}
	found := false
	for index := range config.Records {
		if config.Records[index].Key == key {
			config.Records[index].Value = value
			found = true
		}
	}
	if !found {
		config.Records = append(config.Records, ConfigRecord{Key: key, Value: value})
	}
	data, err = json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	evidence.Evidence["config"] = rewriteEvidenceArtifact(t, report.baseDir, ref, data)
}

func rewriteCaseQlogEventField(t *testing.T, report *EvidenceReport, evidence *CaseEvidence, event, field string, value any) {
	t.Helper()
	ref := evidence.Evidence["qlog"]
	data, err := os.ReadFile(filepath.Join(report.baseDir, ref.Path))
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		QlogVersion string `json:"qlog_version"`
		Title       string `json:"title"`
		Traces      []struct {
			Events [][]json.RawMessage `json:"events"`
		} `json:"traces"`
	}
	if err := decodeStrictJSON(data, &document); err != nil {
		t.Fatal(err)
	}
	found := false
	for eventIndex := range document.Traces[0].Events {
		fields := document.Traces[0].Events[eventIndex]
		var category, name string
		if len(fields) != 4 || json.Unmarshal(fields[1], &category) != nil || json.Unmarshal(fields[2], &name) != nil || category+":"+name != event {
			continue
		}
		var eventData map[string]any
		if err := json.Unmarshal(fields[3], &eventData); err != nil {
			t.Fatal(err)
		}
		eventData[field] = value
		fields[3], err = json.Marshal(eventData)
		if err != nil {
			t.Fatal(err)
		}
		found = true
		break
	}
	if !found {
		t.Fatalf("qlog event %s is missing", event)
	}
	data, err = json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	evidence.Evidence["qlog"] = rewriteEvidenceArtifact(t, report.baseDir, ref, data)
}

func swapCaseQlogEvents(t *testing.T, report *EvidenceReport, evidence *CaseEvidence, first, second string) {
	t.Helper()
	ref := evidence.Evidence["qlog"]
	data, err := os.ReadFile(filepath.Join(report.baseDir, ref.Path))
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		QlogVersion string `json:"qlog_version"`
		Title       string `json:"title"`
		Traces      []struct {
			Events [][]json.RawMessage `json:"events"`
		} `json:"traces"`
	}
	if err := decodeStrictJSON(data, &document); err != nil {
		t.Fatal(err)
	}
	positions := map[string]int{first: -1, second: -1}
	for eventIndex, fields := range document.Traces[0].Events {
		var category, name string
		if len(fields) == 4 && json.Unmarshal(fields[1], &category) == nil && json.Unmarshal(fields[2], &name) == nil {
			if _, exists := positions[category+":"+name]; exists {
				positions[category+":"+name] = eventIndex
			}
		}
	}
	if positions[first] < 0 || positions[second] < 0 {
		t.Fatalf("cannot swap missing qlog events %s and %s", first, second)
	}
	document.Traces[0].Events[positions[first]], document.Traces[0].Events[positions[second]] =
		document.Traces[0].Events[positions[second]], document.Traces[0].Events[positions[first]]
	data, err = json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	evidence.Evidence["qlog"] = rewriteEvidenceArtifact(t, report.baseDir, ref, data)
}

func completeReport(t *testing.T, manifest *PerformanceManifest, registry *CaseRegistry) *EvidenceReport {
	t.Helper()
	cachedCompleteReport.Do(func() {
		cachedCompleteReport.report = buildCompleteReport(t, manifest, registry)
	})
	return cloneEvidenceReport(cachedCompleteReport.report)
}

// cloneEvidenceReport keeps the large synthetic evidence fixture shared while
// giving each mutation test an isolated object graph. Reflection is used here
// only in tests so production evidence validation never pays this cost.
func cloneEvidenceReport(source *EvidenceReport) *EvidenceReport {
	cloned := *source
	cloned.TDD = cloneTDDEvidence(source.TDD)
	cloned.Cells = cloneCellEvidence(source.Cells)
	cloned.Cases = cloneCaseEvidence(source.Cases)
	return &cloned
}

func cloneTDDEvidence(source []TDDEvidenceRecord) []TDDEvidenceRecord {
	if source == nil {
		return nil
	}
	cloned := make([]TDDEvidenceRecord, len(source))
	for index, record := range source {
		cloned[index] = record
		cloned[index].Red = cloneTDDStage(record.Red)
		cloned[index].Green = cloneTDDStage(record.Green)
		cloned[index].Refactor = cloneTDDStage(record.Refactor)
	}
	return cloned
}

func cloneTDDStage(source TDDStageEvidence) TDDStageEvidence {
	cloned := source
	cloned.ExitCode = cloneInt(source.ExitCode)
	return cloned
}

func cloneCellEvidence(source []CellEvidence) []CellEvidence {
	if source == nil {
		return nil
	}
	cloned := make([]CellEvidence, len(source))
	for index, cell := range source {
		cloned[index] = cell
		cloned[index].SupportedCandidates = append([]string(nil), cell.SupportedCandidates...)
		cloned[index].ElapsedNanoseconds = cloneInt64(cell.ElapsedNanoseconds)
		cloned[index].Runs = cloneRunEvidence(cell.Runs)
		if cell.Metrics != nil {
			cloned[index].Metrics = make(map[string]MetricEvidence, len(cell.Metrics))
			for metricID, metric := range cell.Metrics {
				metric.Estimate = cloneFloat64(metric.Estimate)
				metric.LowerCI = cloneFloat64(metric.LowerCI)
				metric.UpperCI = cloneFloat64(metric.UpperCI)
				cloned[index].Metrics[metricID] = metric
			}
		}
	}
	return cloned
}

func cloneRunEvidence(source []RunEvidence) []RunEvidence {
	if source == nil {
		return nil
	}
	cloned := make([]RunEvidence, len(source))
	for index, run := range source {
		cloned[index] = run
		cloned[index].Phases = clonePhaseEvidence(run.Phases)
		cloned[index].Variants = cloneVariantEvidence(run.Variants)
	}
	return cloned
}

func cloneVariantEvidence(source []VariantEvidence) []VariantEvidence {
	if source == nil {
		return nil
	}
	cloned := make([]VariantEvidence, len(source))
	for index, variant := range source {
		cloned[index] = variant
		cloned[index].Phases = clonePhaseEvidence(variant.Phases)
	}
	return cloned
}

func clonePhaseEvidence(source []PhaseEvidence) []PhaseEvidence {
	if source == nil {
		return nil
	}
	cloned := make([]PhaseEvidence, len(source))
	for index, phase := range source {
		cloned[index] = phase
		cloned[index].SampleCount = cloneInt(phase.SampleCount)
		cloned[index].FailureCount = cloneInt(phase.FailureCount)
		cloned[index].RetryCount = cloneInt(phase.RetryCount)
		if phase.Selection.StartedCandidates != nil {
			cloned[index].Selection.StartedCandidates = make(map[string]int, len(phase.Selection.StartedCandidates))
			for candidate, count := range phase.Selection.StartedCandidates {
				cloned[index].Selection.StartedCandidates[candidate] = count
			}
		}
		if phase.Artifacts != nil {
			cloned[index].Artifacts = make(map[string]EvidenceArtifact, len(phase.Artifacts))
			for kind, artifact := range phase.Artifacts {
				cloned[index].Artifacts[kind] = artifact
			}
		}
	}
	return cloned
}

func cloneCaseEvidence(source []CaseEvidence) []CaseEvidence {
	if source == nil {
		return nil
	}
	cloned := make([]CaseEvidence, len(source))
	for index, evidence := range source {
		cloned[index] = evidence
		if evidence.Evidence != nil {
			cloned[index].Evidence = make(map[string]EvidenceArtifact, len(evidence.Evidence))
			for kind, artifact := range evidence.Evidence {
				cloned[index].Evidence[kind] = artifact
			}
		}
	}
	return cloned
}

func cloneInt(source *int) *int {
	if source == nil {
		return nil
	}
	cloned := *source
	return &cloned
}

func cloneInt64(source *int64) *int64 {
	if source == nil {
		return nil
	}
	cloned := *source
	return &cloned
}

func cloneFloat64(source *float64) *float64 {
	if source == nil {
		return nil
	}
	cloned := *source
	return &cloned
}

func buildCompleteReport(t *testing.T, manifest *PerformanceManifest, registry *CaseRegistry) *EvidenceReport {
	t.Helper()
	directory, err := os.MkdirTemp("", "flowersec-transportcheck-")
	if err != nil {
		t.Fatal(err)
	}

	report := &EvidenceReport{
		SchemaVersion:  1,
		Classification: "signed_transport_evidence",
		ManifestDigest: manifest.Digest,
		Source: EvidenceSource{
			BaseSHA: strings.Repeat("b", 40), FinalSHA: strings.Repeat("a", 40),
			Dirty: boolPointer(false), UntrackedFileCount: intPointer(0),
		},
		Runner: EvidenceRunner{
			ID: "flowersec-linux-release-v1", OS: "linux", Architecture: "amd64", KernelRelease: "6.12.1",
			Namespace: "isolated", TrafficControl: "tc-netem-v1", PacketCounters: "ebpf-v1", EffectiveConfigSHA256: signedRunnerConfigDigest,
			ExecutableSHA256: signedRunnerExecutableSHA, SourceSHA256: signedRunnerSourceSHA, ArgvSHA256: signedRunnerArgvSHA,
		},
		baseDir: directory,
	}
	for _, slice := range frozenTDDSlices {
		report.TDD = append(report.TDD, TDDEvidenceRecord{
			Slice:    slice,
			Red:      fixtureTDDStage(t, directory, slice, "red"),
			Green:    fixtureTDDStage(t, directory, slice, "green"),
			Refactor: fixtureTDDStage(t, directory, slice, "refactor"),
		})
	}
	for _, cell := range manifest.Cells {
		profile := profileByID(t, manifest, cell.ProfileID)
		cellEvidence := CellEvidence{
			CellID:              cell.ID,
			Policy:              cell.Policy,
			SupportedCandidates: append([]string(nil), cell.SupportedCandidates...),
			ElapsedNanoseconds:  int64Pointer(int64(cell.DurationMinutes-1) * 60 * 1e9),
			Metrics:             make(map[string]MetricEvidence, len(cell.RequiredMetrics)),
		}
		contracts := make(map[string]MetricContract, len(manifest.MetricContracts))
		for _, contract := range manifest.MetricContracts {
			contracts[contract.ID] = contract
		}
		for runNumber := 1; runNumber <= manifest.RunCount; runNumber++ {
			run := RunEvidence{RunNumber: runNumber}
			if len(cell.Variants) == 0 {
				run.Phases = completePhases(t, directory, manifest.Digest, profile, cell, runNumber, "")
			}
			for _, variant := range cell.Variants {
				run.Variants = append(run.Variants, VariantEvidence{
					ID:     variant,
					Phases: completePhases(t, directory, manifest.Digest, profile, cell, runNumber, " variant "+variant),
				})
			}
			run.Resource = writeRunResourceArtifact(t, directory, cell, runNumber, contracts)
			cellEvidence.Runs = append(cellEvidence.Runs, run)
		}
		report.Cells = append(report.Cells, cellEvidence)
	}
	for cellIndex, cell := range manifest.Cells {
		cellEvidence := &report.Cells[cellIndex]
		contracts := make(map[string]MetricContract, len(manifest.MetricContracts))
		for _, contract := range manifest.MetricContracts {
			contracts[contract.ID] = contract
		}
		for _, metricID := range cell.RequiredMetrics {
			contract := contracts[metricID]
			value := fixtureMetricValue(cell, metricID, contract)
			values := make([]float64, manifest.RunCount)
			for index := range values {
				values[index] = value
			}
			estimate, lower, upper := bootstrapMean(values, manifest.Bootstrap, cell.ID, metricID)
			cellEvidence.Metrics[metricID] = MetricEvidence{
				Samples: manifest.RunCount, Estimate: floatPointer(estimate),
				LowerCI: floatPointer(lower), UpperCI: floatPointer(upper),
				RawSamples: writeMetricSamples(t, report, cellEvidence, metricID, values),
			}
		}
	}
	for _, entry := range registry.Cases {
		context := "case " + entry.ID
		evidence := writeArtifactSet(t, directory, context, entry.EvidenceFields, entry.Profile)
		report.Cases = append(report.Cases, CaseEvidence{
			ID:       entry.ID,
			Owner:    entry.Owner,
			Mode:     entry.Mode,
			Profile:  entry.Profile,
			Status:   "pass",
			Evidence: evidence,
		})
		if entry.RaceOwner != "" {
			raceContext := "race case " + entry.ID
			report.Cases = append(report.Cases, CaseEvidence{
				ID: entry.ID, Owner: entry.RaceOwner, Mode: "race", Profile: entry.Profile, Status: "pass",
				Evidence:  writeArtifactSet(t, directory, raceContext, entry.EvidenceFields, entry.Profile),
				Execution: fixtureRaceExecution(t, directory, entry.ID),
			})
		}
	}
	return report
}

func fixtureMetricValue(cell PerformanceCell, metricID string, contract MetricContract) float64 {
	if requiredMetricDerivation(metricID) == "ratio" {
		if metricID == "retransmit_amplification_ratio" || strings.Contains(metricID, "_retransmit_amplification_ratio") {
			switch cell.ProfileID {
			case "mobile-v1":
				return 0.25
			case "edge-v1":
				return 0.5
			default:
				return 0.1
			}
		}
		return 1
	}
	if strings.Contains(metricID, "p50") || strings.Contains(metricID, "p95") || strings.Contains(metricID, "p99") {
		return 1
	}
	if strings.Contains(metricID, "goodput_mbps") {
		switch cell.ProfileID {
		case "clean-v1":
			return 100
		case "mobile-v1":
			return 5
		case "edge-v1":
			return 1
		}
	}
	value := 1.0
	if contract.Threshold != nil {
		if contract.Decision == "upper" {
			value = *contract.Threshold * 0.9
		} else {
			value = *contract.Threshold * 1.1
		}
	}
	return value
}

func completePhases(t *testing.T, directory, manifestDigest string, profile *PerformanceProfile, cell PerformanceCell, runNumber int, scope string) []PhaseEvidence {
	t.Helper()
	var phases []PhaseEvidence
	if profile.Mode == "adaptive" {
		for _, stage := range profile.AdaptiveStages {
			context := fmt.Sprintf("cell %s run %d%s phase %s/cold", cell.ID, runNumber, scope, stage.ProfileID)
			phases = append(phases, completePhase(t, directory, manifestDigest, stage.ProfileID, "cold", stage.Cold.Operations, cell, runNumber, context))
			cleanupContext := fmt.Sprintf("cell %s run %d%s phase %s/cleanup", cell.ID, runNumber, scope, stage.ProfileID)
			phases = append(phases, completePhase(t, directory, manifestDigest, stage.ProfileID, "cleanup", 1, cell, runNumber, cleanupContext))
		}
		return phases
	}
	for _, phase := range []struct {
		name        string
		sampleCount int
	}{{"cold", profile.Cold.Operations}, {"rpc", profile.RPC.Operations}, {"bulk", 2}, {"cleanup", 1}} {
		context := fmt.Sprintf("cell %s run %d%s phase %s/%s", cell.ID, runNumber, scope, profile.ID, phase.name)
		phases = append(phases, completePhase(t, directory, manifestDigest, profile.ID, phase.name, phase.sampleCount, cell, runNumber, context))
	}
	return phases
}

func writeArtifactSet(t *testing.T, directory, context string, kinds []string, caseProfile ...string) map[string]EvidenceArtifact {
	t.Helper()
	artifacts := make(map[string]EvidenceArtifact, len(kinds))
	for _, kind := range kinds {
		switch kind {
		case "samples":
			continue
		case "pcap":
			artifacts[kind] = writePCAPArtifact(t, directory, context)
		case "qlog":
			artifacts[kind] = writeQlogArtifact(t, directory, context)
		default:
			artifacts[kind] = writeStructuredArtifact(t, directory, context, kind)
		}
	}
	if len(caseProfile) > 0 && caseProfile[0] != "" && strings.HasPrefix(context, "case ") || len(caseProfile) > 0 && caseProfile[0] != "" && strings.HasPrefix(context, "race case ") {
		bindCaseIdentityConfig(t, directory, context, caseProfile[0], artifacts)
	}
	return artifacts
}

func bindCaseIdentityConfig(t *testing.T, directory, context, profile string, artifacts map[string]EvidenceArtifact) {
	t.Helper()
	configRef, hasConfig := artifacts["config"]
	traceRef, hasTrace := artifacts["trace"]
	if !hasConfig || !hasTrace {
		return
	}
	data, err := os.ReadFile(filepath.Join(directory, configRef.Path))
	if err != nil {
		t.Fatal(err)
	}
	var config ConfigArtifact
	if err := decodeStrictJSON(data, &config); err != nil {
		t.Fatal(err)
	}
	values := map[string]string{
		"case_id":      strings.TrimPrefix(strings.TrimPrefix(context, "race case "), "case "),
		"case_profile": profile,
		"test_id":      caseExecutionID(context),
		"trace_sha256": traceRef.SHA256,
		"watchdog":     "completed",
	}
	if metricsRef, exists := artifacts["metrics"]; exists {
		values["metrics_sha256"] = metricsRef.SHA256
	}
	for key, value := range values {
		found := false
		for index := range config.Records {
			if config.Records[index].Key == key {
				config.Records[index].Value = value
				found = true
				break
			}
		}
		if !found {
			config.Records = append(config.Records, ConfigRecord{Key: key, Value: value})
		}
	}
	data, err = json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	artifacts["config"] = rewriteEvidenceArtifact(t, directory, configRef, data)
}

func writeStructuredArtifact(t *testing.T, directory, context, kind string) EvidenceArtifact {
	t.Helper()
	digest := sha256.Sum256([]byte(context + "\x00" + kind + "\x00record"))
	var value any
	switch kind {
	case "trace":
		value = TraceArtifact{SchemaVersion: 1, Kind: "transport_trace", Context: context,
			Records: fixtureCaseTrace(context, hex.EncodeToString(digest[:]))}
	case "metrics":
		records := fixtureCaseMetrics(context)
		if len(records) == 0 {
			records = []MetricCounterRecord{{Name: "completed_operations", Value: 1, Unit: "count"}}
		}
		value = MetricsArtifact{SchemaVersion: 1, Kind: "transport_metrics", Context: context,
			Records: records}
	case "config":
		records := fixtureCaseConfig(context)
		if len(records) == 0 {
			records = []ConfigRecord{{Key: "manifest_binding", Value: hex.EncodeToString(digest[:])}}
		}
		value = ConfigArtifact{SchemaVersion: 1, Kind: "transport_config", Context: context,
			Records: records}
	case "resource":
		value = ResourceArtifact{SchemaVersion: 1, Kind: "transport_resource", Context: context,
			Records: fixtureCaseResource(context)}
	case "tcp_info":
		records := fixtureTCPInfo(context)
		if len(records) == 0 {
			records = []TCPInfoRecord{fixtureTCPInfoRecordForContext(context, 1, 1200, 1)}
		}
		value = TCPInfoArtifact{SchemaVersion: 1, Kind: "transport_tcp_info", Context: context,
			Records: records}
	default:
		t.Fatalf("unsupported structured artifact kind %q", kind)
	}
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return writeEvidenceArtifact(t, directory, context, kind, ".json", data)
}

func fixtureCaseTrace(context, digest string) []TraceRecord {
	caseID := strings.TrimPrefix(strings.TrimPrefix(context, "race case "), "case ")
	records := func(events []string, times []int64, connectionID string) []TraceRecord {
		result := make([]TraceRecord, len(events))
		for index := range events {
			result[index] = TraceRecord{
				Sequence: uint64(index + 1), AtNS: times[index], Event: events[index], Digest: caseExecutionID(context), ConnectionID: connectionID,
			}
		}
		return result
	}
	if caseID == "CAP-SOAK-HOURLY" {
		result := make([]TraceRecord, 0, signedSoakContract.FaultCycleCount+2)
		result = append(result, TraceRecord{Sequence: 1, AtNS: 0, Event: "soak_started", Digest: caseExecutionID(context), ConnectionID: evidenceConnectionID})
		for index := 1; index <= signedSoakContract.FaultCycleCount; index++ {
			result = append(result, TraceRecord{Sequence: uint64(index + 1), AtNS: int64(index) * signedSoakContract.FaultCyclePeriodNS, Event: "fault_cycle_completed", Digest: caseExecutionID(context), ConnectionID: evidenceConnectionID})
		}
		result = append(result, TraceRecord{Sequence: uint64(len(result) + 1), AtNS: signedSoakContract.DurationNS, Event: "soak_completed", Digest: caseExecutionID(context), ConnectionID: evidenceConnectionID})
		return result
	}
	if strings.HasPrefix(caseID, "CAP-") {
		result := records(
			[]string{"capacity_ramp_completed", "capacity_hold_completed", "capacity_cleanup_completed"},
			[]int64{30e9, 90e9, 120e9}, "",
		)
		for index := range result {
			result[index].AttemptedSessions = 1000
			result[index].SucceededSessions = 1000
			result[index].UniqueActiveSessions = 1000
			result[index].ActiveSessions = 1000
		}
		result[2].ActiveSessions = 0
		result[2].Disconnects = 1000
		return result
	}
	switch caseID {
	case "SYS-COMMON-KERNEL":
		return records([]string{"outage_started", "outage_ended", "kernel_fault_matrix_completed"}, []int64{1e9, 3e9, 4e9}, evidenceConnectionID)
	case "NP-REBIND", "SYS-MIGRATION-REBIND":
		completion := "native_path_rebind_completed"
		if caseID == "SYS-MIGRATION-REBIND" {
			completion = "kernel_path_rebind_completed"
		}
		return records(
			[]string{"rpc_before_rebind", "rebind_scheduled", "path_updated", "path_validated", "rpc_after_rebind", completion},
			[]int64{1e9, 2e9, 3e9, 4e9, 5e9, 6e9}, evidenceConnectionID,
		)
	}
	event := fixtureCaseTraceEvent(context)
	connectionID := ""
	if caseID == "NP-PMTUD-STATE" || strings.HasPrefix(caseID, "SYS-PMTUD-QUIC-") {
		connectionID = evidenceConnectionID
	}
	return records([]string{event}, []int64{1}, connectionID)
}

func fixtureCaseResource(context string) []ResourceRecord {
	caseID := strings.TrimPrefix(strings.TrimPrefix(context, "race case "), "case ")
	if caseID == "CAP-SOAK-HOURLY" {
		return []ResourceRecord{
			{Phase: "soak_start", AtNS: 0, RSSBytes: 256 * 1024 * 1024, OpenFDs: 128, Goroutines: 256, Tasks: 256},
			{
				Phase: "soak_end", AtNS: signedSoakContract.DurationNS, RSSBytes: 288 * 1024 * 1024, OpenFDs: 136, Goroutines: 288, Tasks: 288,
				ResidualSessions: intPointer(0), ResidualGoroutines: intPointer(0), ResidualOpenFDs: intPointer(0), ResidualTasks: intPointer(0),
			},
		}
	}
	if !strings.HasPrefix(caseID, "CAP-") {
		return []ResourceRecord{{AtNS: 1, RSSBytes: 1, Goroutines: 1}}
	}
	return []ResourceRecord{
		{Phase: "ramp", AtNS: 30e9, ActiveSessions: 1000, UniqueActiveSessions: 1000, RSSBytes: 512 * 1024 * 1024, CPUNanoseconds: 20e9, OpenFDs: 4096, Goroutines: 4096, Tasks: 4096},
		{Phase: "hold", AtNS: 90e9, ActiveSessions: 1000, UniqueActiveSessions: 1000, RSSBytes: 768 * 1024 * 1024, CPUNanoseconds: 80e9, OpenFDs: 4096, Goroutines: 4096, Tasks: 4096},
		{Phase: "cleanup", AtNS: 120e9, ActiveSessions: 0, UniqueActiveSessions: 1000, RSSBytes: 256 * 1024 * 1024, CPUNanoseconds: 100e9, OpenFDs: 32, Goroutines: 32, Tasks: 32},
	}
}

func fixtureCaseTraceEvent(context string) string {
	caseID := strings.TrimPrefix(strings.TrimPrefix(context, "race case "), "case ")
	switch caseID {
	case "WF-UDP-FULL":
		return "weaknet_udp_fault_matrix_completed"
	case "WF-UDP-RANDOM-LOSS":
		return "weaknet_udp_seeded_random_loss_completed"
	case "WF-BYTE-FULL":
		return "weaknet_byte_fault_matrix_completed"
	case "WF-CLEANUP-FULL":
		return "weaknet_cleanup_completed"
	case "SYS-COMMON-KERNEL":
		return "kernel_fault_matrix_completed"
	case "NP-REBIND":
		return "native_path_rebind_completed"
	case "SYS-MIGRATION-REBIND":
		return "kernel_path_rebind_completed"
	case "NP-PMTUD-STATE":
		return "userspace_pmtud_state_converged"
	case "SYS-PMTUD-QUIC-IPV4", "SYS-PMTUD-QUIC-IPV6":
		return "kernel_quic_pmtud_recovered"
	}
	if strings.Contains(caseID, "PMTUD-WSS-RECOVER") {
		return "pmtud_recovered"
	}
	if strings.Contains(caseID, "PMTUD-WSS-TIMEOUT") {
		return "pmtud_timed_out"
	}
	return "completed"
}

func fixtureCaseMetrics(context string) []MetricCounterRecord {
	caseID := strings.TrimPrefix(strings.TrimPrefix(context, "race case "), "case ")
	pairs := func(values map[string]float64) []MetricCounterRecord {
		records := make([]MetricCounterRecord, 0, 2*len(values))
		keys := make([]string, 0, len(values))
		for key := range values {
			keys = append(keys, key)
		}
		slices.Sort(keys)
		for _, key := range keys {
			unit := counterUnit(key)
			records = append(records,
				MetricCounterRecord{Name: "expected_" + key, Value: values[key], Unit: unit},
				MetricCounterRecord{Name: "actual_" + key, Value: values[key], Unit: unit},
			)
		}
		return records
	}
	switch caseID {
	case "CAP-SOAK-HOURLY":
		return []MetricCounterRecord{
			{Name: "duration_ns", Value: float64(signedSoakContract.DurationNS), Unit: "nanoseconds"},
			{Name: "fault_cycle_count", Value: float64(signedSoakContract.FaultCycleCount), Unit: "count"},
			{Name: "reconnect_count", Value: float64(signedSoakContract.ReconnectCount), Unit: "count"},
			{Name: "migration_count", Value: float64(signedSoakContract.MigrationCount), Unit: "count"},
			{Name: "rss_growth_bytes", Value: 32 * 1024 * 1024, Unit: "bytes"},
			{Name: "goroutine_growth", Value: 32, Unit: "count"},
			{Name: "open_fd_growth", Value: 8, Unit: "count"},
			{Name: "task_growth", Value: 32, Unit: "count"},
			{Name: "residual_sessions", Value: 0, Unit: "count"},
			{Name: "residual_goroutines", Value: 0, Unit: "count"},
			{Name: "residual_open_fds", Value: 0, Unit: "count"},
			{Name: "residual_tasks", Value: 0, Unit: "count"},
			{Name: "watchdog_timeouts", Value: 0, Unit: "count"},
		}
	case "WF-UDP-FULL":
		return pairs(map[string]float64{
			"input_units": 10, "input_bytes": 100, "output_units": 5, "output_bytes": 50,
			"canceled_units": 1, "canceled_bytes": 10, "dropped_units": 5, "dropped_bytes": 50,
			"duplicate_units": 1, "duplicate_bytes": 10, "ordinal_loss_units": 1, "burst_loss_units": 1,
			"outage_units": 1, "mtu_drop_units": 1, "delay_units": 1, "jitter_units": 1,
			"reordered_units": 1, "rate_limited_units": 1, "nat_rebinds": 1, "queue_overflow_units": 1,
		})
	case "WF-UDP-RANDOM-LOSS":
		losses := float64(0)
		for ordinal := uint64(1); ordinal <= 10_000; ordinal++ {
			if seededEvidenceRandomLoss(20260720, ordinal, 100) {
				losses++
			}
		}
		return pairs(map[string]float64{
			"input_units": 10_000, "output_units": 10_000 - losses,
			"dropped_units": losses, "random_loss_units": losses,
			"input_bytes": 10_000 * 1200, "output_bytes": (10_000 - losses) * 1200,
			"dropped_bytes": losses * 1200, "random_loss_bytes": losses * 1200,
		})
	case "WF-BYTE-FULL":
		return pairs(map[string]float64{
			"input_bytes": 100, "output_bytes": 70, "canceled_bytes": 30, "delay_units": 1, "jitter_units": 1,
			"rate_limited_units": 1, "outage_units": 1, "fragment_units": 1, "coalesced_units": 1,
			"backpressure_units": 1, "half_closes": 1,
		})
	case "WF-CLEANUP-FULL":
		return pairs(map[string]float64{
			"input_bytes": 100, "output_bytes": 40, "canceled_bytes": 60, "pending_units": 0, "pending_bytes": 0,
		})
	case "SYS-COMMON-KERNEL":
		records := pairs(map[string]float64{
			"delay": 1, "jitter": 1, "periodic_loss": 1, "burst_loss": 1,
			"duplicate": 1, "reorder": 1, "rate_limit": 1, "outage": 1, "outage_duration_ns": 2e9,
		})
		records = append(records,
			MetricCounterRecord{Name: "ebpf_packets", Value: 100, Unit: "count"},
			MetricCounterRecord{Name: "ebpf_bytes", Value: 1000, Unit: "bytes"},
			MetricCounterRecord{Name: "watchdog_timeouts", Value: 0, Unit: "count"},
		)
		return bindMetricConnection(records, evidenceConnectionID)
	case "NP-REBIND", "SYS-MIGRATION-REBIND":
		return bindMetricConnection([]MetricCounterRecord{
			{Name: "path_updates", Value: 1, Unit: "count"},
			{Name: "path_validations", Value: 1, Unit: "count"},
			{Name: "rpc_before_rebind", Value: 1, Unit: "count"},
			{Name: "rpc_after_rebind", Value: 1, Unit: "count"},
			{Name: "watchdog_timeouts", Value: 0, Unit: "count"},
		}, evidenceConnectionID)
	case "NP-PMTUD-STATE":
		return bindMetricConnection([]MetricCounterRecord{
			{Name: "oversized_udp_packets", Value: 1, Unit: "count"},
			{Name: "constrained_udp_packets", Value: 1, Unit: "count"},
			{Name: "pmtud_recoveries", Value: 1, Unit: "count"},
			{Name: "rpc_completed", Value: 1, Unit: "count"},
			{Name: "watchdog_timeouts", Value: 0, Unit: "count"},
		}, evidenceConnectionID)
	case "SYS-PMTUD-QUIC-IPV4", "SYS-PMTUD-QUIC-IPV6":
		return bindMetricConnection([]MetricCounterRecord{
			{Name: "oversized_udp_packets", Value: 1, Unit: "count"},
			{Name: "constrained_udp_packets", Value: 1, Unit: "count"},
			{Name: "pmtud_recoveries", Value: 1, Unit: "count"},
			{Name: "icmp_ptb_received", Value: 1, Unit: "count"},
			{Name: "rpc_completed", Value: 1, Unit: "count"},
			{Name: "watchdog_timeouts", Value: 0, Unit: "count"},
		}, evidenceConnectionID)
	}
	if strings.HasPrefix(caseID, "CAP-") {
		return []MetricCounterRecord{
			{Name: "attempted_sessions", Value: 1000, Unit: "count"},
			{Name: "succeeded_sessions", Value: 1000, Unit: "count"},
			{Name: "failed_sessions", Value: 0, Unit: "count"},
			{Name: "unique_active_peak", Value: 1000, Unit: "count"},
			{Name: "hold_duration_ns", Value: 60e9, Unit: "nanoseconds"},
			{Name: "hold_disconnects", Value: 0, Unit: "count"},
			{Name: "cleanup_disconnects", Value: 1000, Unit: "count"},
			{Name: "watchdog_timeouts", Value: 0, Unit: "count"},
			{Name: "cleanup_residual_sessions", Value: 0, Unit: "count"},
		}
	}
	if strings.Contains(caseID, "PMTUD-WSS-RECOVER") {
		return []MetricCounterRecord{
			{Name: "watchdog_timeouts", Value: 0, Unit: "count"},
			{Name: "rpc_completed", Value: 1, Unit: "count"},
			{Name: "timeout_observed", Value: 0, Unit: "count"},
		}
	}
	if strings.Contains(caseID, "PMTUD-WSS-TIMEOUT") {
		return []MetricCounterRecord{
			{Name: "watchdog_timeouts", Value: 0, Unit: "count"},
			{Name: "rpc_completed", Value: 0, Unit: "count"},
			{Name: "timeout_observed", Value: 1, Unit: "count"},
		}
	}
	return nil
}

func bindMetricConnection(records []MetricCounterRecord, connectionID string) []MetricCounterRecord {
	for index := range records {
		records[index].ConnectionID = connectionID
	}
	return records
}

func fixtureCaseConfig(context string) []ConfigRecord {
	caseID := strings.TrimPrefix(strings.TrimPrefix(context, "race case "), "case ")
	fromMap := func(values map[string]string) []ConfigRecord {
		keys := make([]string, 0, len(values))
		for key := range values {
			keys = append(keys, key)
		}
		slices.Sort(keys)
		records := make([]ConfigRecord, 0, len(keys))
		for _, key := range keys {
			records = append(records, ConfigRecord{Key: key, Value: values[key]})
		}
		return records
	}
	switch caseID {
	case "CAP-SOAK-HOURLY":
		return fromMap(map[string]string{
			"profile": "hourly-weaknet-soak-v1", "duration_ns": strconv.FormatInt(signedSoakContract.DurationNS, 10),
			"fault_cycle_period_ns": strconv.FormatInt(signedSoakContract.FaultCyclePeriodNS, 10),
			"fault_cycle_count":     strconv.Itoa(signedSoakContract.FaultCycleCount),
			"reconnect_count":       strconv.Itoa(signedSoakContract.ReconnectCount),
			"migration_count":       strconv.Itoa(signedSoakContract.MigrationCount), "watchdog": "completed",
		})
	case "WF-UDP-FULL":
		return fromMap(map[string]string{"profile": "udp-full-v1", "clock": "virtual-deterministic", "pump": "net.PacketConn", "watchdog": "completed"})
	case "WF-UDP-RANDOM-LOSS":
		return fromMap(map[string]string{
			"profile": "udp-random-loss-v1", "sampler": "splitmix64-seed-ordinal-v1", "seed": "20260720",
			"draws": "10000", "loss_basis_points": "100", "datagram_bytes": "1200", "watchdog": "completed",
		})
	case "WF-BYTE-FULL":
		return fromMap(map[string]string{"profile": "byte-full-v1", "clock": "virtual-deterministic", "pump": "net.Conn", "watchdog": "completed"})
	case "WF-CLEANUP-FULL":
		return fromMap(map[string]string{"profile": "cleanup-full-v1", "pump": "real-socket", "watchdog": "completed"})
	case "SYS-COMMON-KERNEL":
		return fromMap(map[string]string{
			"os": "linux", "namespace": "isolated", "tc": "netem-v1", "ebpf": "enabled", "watchdog": "completed",
			"connection_id": evidenceConnectionID, "outage_start_ns": "1000000000", "outage_duration_ns": "2000000000",
		})
	case "NP-REBIND":
		return fromMap(map[string]string{
			"connection_id": evidenceConnectionID, "rebind_mode": "same-ip-port", "rebind_at_ns": "2000000000", "watchdog": "completed",
		})
	case "SYS-MIGRATION-REBIND":
		return fromMap(map[string]string{
			"connection_id": evidenceConnectionID, "rebind_mode": "same-ip-port", "rebind_at_ns": "2000000000", "watchdog": "completed",
			"os": "linux", "namespace": "isolated", "tc": "netem-v1",
		})
	case "NP-PMTUD-STATE":
		return fromMap(map[string]string{
			"pmtud": "userspace-state-machine-v1", "ip_family": "ipv4", "link_mtu": "1280",
			"connection_id":     "8394c8f03e515708",
			"expected_terminal": "recovered", "actual_terminal": "recovered", "watchdog": "completed",
		})
	case "SYS-PMTUD-QUIC-IPV4", "SYS-PMTUD-QUIC-IPV6":
		family := "ipv4"
		if strings.HasSuffix(caseID, "IPV6") {
			family = "ipv6"
		}
		return fromMap(map[string]string{
			"os": "linux", "namespace": "isolated", "firewall": "allow-icmp-ptb",
			"pmtud": "kernel-quic-v1", "ip_family": family, "link_mtu": "1280",
			"connection_id":     "8394c8f03e515708",
			"expected_terminal": "recovered", "actual_terminal": "recovered", "watchdog": "completed",
		})
	}
	if strings.HasPrefix(caseID, "CAP-") {
		return fromMap(map[string]string{
			"sessions": "1000", "ramp_duration_ns": "30000000000", "hold_duration_ns": "60000000000",
			"cleanup_duration_ns": "30000000000", "watchdog_duration_ns": "120000000000", "watchdog": "completed",
		})
	}
	if strings.Contains(caseID, "PMTUD-WSS-") {
		recovered := strings.Contains(caseID, "RECOVER")
		terminal, firewall := "timed_out", "drop-icmp-ptb"
		if recovered {
			terminal, firewall = "recovered", "allow-icmp-ptb"
		}
		return fromMap(map[string]string{
			"os": "linux", "namespace": "isolated", "firewall": firewall,
			"expected_terminal": terminal, "actual_terminal": terminal, "watchdog": "completed",
		})
	}
	return nil
}

func fixtureTCPInfo(context string) []TCPInfoRecord {
	caseID := strings.TrimPrefix(strings.TrimPrefix(context, "race case "), "case ")
	if strings.Contains(caseID, "PMTUD-WSS-RECOVER") {
		return []TCPInfoRecord{fixtureTCPInfoRecordForContext(context, 500_000_000, 1500, 0), fixtureTCPInfoRecordForContext(context, 3_000_000_000, 1200, 1)}
	}
	if strings.Contains(caseID, "PMTUD-WSS-TIMEOUT") {
		return []TCPInfoRecord{fixtureTCPInfoRecordForContext(context, 500_000_000, 1500, 0), fixtureTCPInfoRecordForContext(context, 2_000_000_000, 1500, 10)}
	}
	return nil
}

func fixtureTCPInfoRecord(atNS int64, mss uint32, retransmitted uint64) TCPInfoRecord {
	return TCPInfoRecord{
		AtNS: atNS, LocalAddress: "192.0.2.1", LocalPort: 1001,
		RemoteAddress: "198.51.100.1", RemotePort: 4433, SocketCookie: "socket-1",
		SendMSSBytes: mss, RetransmittedBytes: retransmitted,
	}
}

func fixtureTCPInfoRecordForContext(context string, atNS int64, mss uint32, retransmitted uint64) TCPInfoRecord {
	record := fixtureTCPInfoRecord(atNS, mss, retransmitted)
	if strings.Contains(context, "IPV6") {
		record.LocalAddress, record.RemoteAddress = "::1", "::1"
	}
	return record
}

func writeQlogArtifact(t *testing.T, directory, context string) EvidenceArtifact {
	t.Helper()
	required, streams, _ := qlogRequirements(context)
	return writeQlogArtifactWithEvents(t, directory, context, required, streams)
}

func writeQlogArtifactWithEvents(t *testing.T, directory, context string, names []string, streamCount int) EvidenceArtifact {
	t.Helper()
	events := make([]any, 0, len(names)+streamCount)
	for streamID := 0; streamID < streamCount; streamID++ {
		events = append(events, []any{len(events), "transport", "stream_opened", qlogTestEventData(context, "transport:stream_opened", streamID*4)})
	}
	for _, qualified := range names {
		parts := strings.SplitN(qualified, ":", 2)
		if len(parts) != 2 {
			t.Fatalf("invalid qlog event name %q", qualified)
		}
		if qualified == "transport:stream_opened" && streamCount > 0 {
			continue
		}
		events = append(events, []any{len(events), parts[0], parts[1], qlogTestEventData(context, qualified, 4)})
	}
	data, err := json.Marshal(map[string]any{
		"qlog_version": "0.3",
		"title":        context,
		"traces": []any{map[string]any{
			"events": events,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return writeEvidenceArtifact(t, directory, context, "qlog", ".qlog", data)
}

func qlogTestEventData(context, name string, streamID int) map[string]any {
	switch name {
	case "transport:stream_opened":
		return map[string]any{"stream_id": streamID, "stream_type": "bidirectional", "connection_id": "8394c8f03e515708"}
	case "transport:stream_data_blocked":
		return map[string]any{"stream_id": streamID, "limit": 65536, "connection_id": "8394c8f03e515708"}
	case "application:rpc_completed":
		return map[string]any{"request_id": "rpc-1", "status": "ok", "stream_id": 8, "connection_id": "8394c8f03e515708"}
	case "transport:reset_stream", "transport:stop_sending":
		return map[string]any{"stream_id": streamID, "error_code": 1, "connection_id": "8394c8f03e515708"}
	case "transport:data_blocked":
		return map[string]any{"limit": 98304, "connection_id": "8394c8f03e515708"}
	case "transport:streams_blocked":
		return map[string]any{"stream_limit": 8, "connection_id": "8394c8f03e515708"}
	case "connectivity:path_updated":
		return map[string]any{
			"old_path": "192.0.2.1:1001", "new_path": "192.0.2.1:2001",
			"remote_path": "198.51.100.1:4433", "connection_id": "8394c8f03e515708",
		}
	case "connectivity:path_validated":
		return map[string]any{"new_path": "192.0.2.1:2001", "remote_path": "198.51.100.1:4433", "connection_id": "8394c8f03e515708"}
	case "recovery:packet_lost":
		return map[string]any{"packet_number": 7, "connection_id": "8394c8f03e515708"}
	case "application:targeted_loss_released":
		return map[string]any{"stream_id": streamID, "missing_offset": 1024, "connection_id": "8394c8f03e515708"}
	case "transport:packet_too_large":
		return map[string]any{"packet_size": 1301, "connection_id": "8394c8f03e515708"}
	case "transport:metrics_updated":
		return map[string]any{"smoothed_rtt_ns": 1_000_000, "bytes_in_flight": 1200, "connection_id": "8394c8f03e515708"}
	case "transport:connection_started":
		return map[string]any{"connection_id": "connection-1"}
	case "application:capacity_completed":
		return map[string]any{"sessions": 1000, "connection_id": "connection-1"}
	default:
		return map[string]any{"status": "observed"}
	}
}

func writePCAPArtifact(t *testing.T, directory, context string) EvidenceArtifact {
	t.Helper()
	caseID := strings.TrimPrefix(strings.TrimPrefix(context, "race case "), "case ")
	version, protocol := 4, uint8(17)
	if strings.Contains(caseID, "IPV6") {
		version = 6
	}
	if strings.Contains(caseID, "PMTUD-WSS") {
		protocol = 6
	}
	oversized := syntheticIPPacketWithTuple(t, version, protocol, 1301, 1, 1001, 4433)
	packets := [][]byte{oversized}
	if caseID == "SYS-COMMON-KERNEL" {
		packets = append(packets, syntheticIPPacketWithTuple(t, 4, 6, 1301, 1, 1001, 443))
	}
	if caseID == "NP-REBIND" || caseID == "SYS-MIGRATION-REBIND" {
		packets = append(packets, syntheticIPPacketWithTuple(t, version, 17, 1301, 1, 2001, 4433))
	}
	if caseID == "NP-PMTUD-STATE" || strings.Contains(caseID, "SYS-PMTUD-QUIC") {
		if strings.Contains(caseID, "SYS-PMTUD-QUIC") {
			packets = append(packets, syntheticICMPPTB(t, version, oversized))
		}
		packets = append(packets, syntheticIPPacketWithTuple(t, version, 17, 1200, 1, 1001, 4433))
	}
	if strings.Contains(caseID, "PMTUD-WSS-RECOVER") {
		packets = append(packets, syntheticICMPPTB(t, version, oversized))
	}
	contextDigest := sha256.Sum256([]byte(context))
	copy(packets[0][len(packets[0])-8:], contextDigest[:8])
	data := encodeClassicPCAP(packets)
	return writeEvidenceArtifact(t, directory, context, "pcap", ".pcap", data)
}

func encodeClassicPCAP(packets [][]byte) []byte {
	data := make([]byte, 24)
	copy(data, []byte{
		0xa1, 0xb2, 0xc3, 0xd4, 0x00, 0x02, 0x00, 0x04,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x65, // LINKTYPE_RAW
	})
	for index, packet := range packets {
		record := make([]byte, 16)
		binary.BigEndian.PutUint32(record[0:4], uint32(index+1))
		binary.BigEndian.PutUint32(record[8:12], uint32(len(packet)))
		binary.BigEndian.PutUint32(record[12:16], uint32(len(packet)))
		data = append(data, record...)
		data = append(data, packet...)
	}
	return data
}

func syntheticIPPacket(t *testing.T, version int, protocol uint8, length, sourceID int) []byte {
	return syntheticIPPacketWithTuple(t, version, protocol, length, sourceID, uint16(1000+sourceID), 4433)
}

func syntheticIPPacketWithTuple(t *testing.T, version int, protocol uint8, length, sourceID int, sourcePort, destinationPort uint16) []byte {
	t.Helper()
	if length > 65535 || length < 48 {
		t.Fatalf("invalid synthetic packet length %d", length)
	}
	packet := make([]byte, length)
	switch version {
	case 4:
		packet[0] = 0x45
		binary.BigEndian.PutUint16(packet[2:4], uint16(length))
		packet[8], packet[9] = 64, protocol
		copy(packet[12:16], []byte{192, 0, 2, byte(sourceID)})
		copy(packet[16:20], []byte{198, 51, 100, 1})
		binary.BigEndian.PutUint16(packet[20:22], sourcePort)
		binary.BigEndian.PutUint16(packet[22:24], destinationPort)
		if protocol == 17 {
			binary.BigEndian.PutUint16(packet[24:26], uint16(length-20))
			setSyntheticQUICConnectionID(packet[28:])
		} else if protocol == 6 {
			packet[32] = 5 << 4
		}
	case 6:
		packet[0] = 0x60
		binary.BigEndian.PutUint16(packet[4:6], uint16(length-40))
		packet[6], packet[7] = protocol, 64
		packet[23] = byte(sourceID)
		packet[39] = 1
		binary.BigEndian.PutUint16(packet[40:42], sourcePort)
		binary.BigEndian.PutUint16(packet[42:44], destinationPort)
		if protocol == 17 {
			binary.BigEndian.PutUint16(packet[44:46], uint16(length-40))
			setSyntheticQUICConnectionID(packet[48:])
		} else if protocol == 6 {
			packet[52] = 5 << 4
		}
	default:
		t.Fatalf("invalid IP version %d", version)
	}
	return packet
}

func setSyntheticQUICConnectionID(payload []byte) {
	cid, _ := hex.DecodeString("8394c8f03e515708")
	if len(payload) < 1+len(cid) {
		return
	}
	payload[0] = 0x40
	copy(payload[1:], cid)
}

func syntheticICMPPTB(t *testing.T, version int, quoted []byte) []byte {
	t.Helper()
	header := 20
	protocol := uint8(1)
	if version == 6 {
		header, protocol = 40, 58
	}
	packet := make([]byte, header+8+len(quoted))
	if version == 4 {
		packet[0] = 0x45
		binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
		packet[8], packet[9] = 64, protocol
		copy(packet[12:16], []byte{198, 51, 100, 254})
		copy(packet[16:20], []byte{192, 0, 2, 1})
		packet[20], packet[21] = 3, 4
		binary.BigEndian.PutUint16(packet[26:28], 1280)
	} else {
		packet[0] = 0x60
		binary.BigEndian.PutUint16(packet[4:6], uint16(len(packet)-40))
		packet[6], packet[7] = protocol, 64
		packet[23], packet[39] = 254, 1
		packet[40] = 2
		binary.BigEndian.PutUint32(packet[44:48], 1280)
	}
	copy(packet[header+8:], quoted)
	return packet
}

func minimumICMPPTBQuote(t *testing.T, version int, quoted []byte) []byte {
	t.Helper()
	packet := syntheticICMPPTB(t, version, quoted)
	outerHeader, quotedHeader := 20, 20
	if version == 6 {
		outerHeader, quotedHeader = 40, 40
	}
	packet = packet[:outerHeader+8+quotedHeader+8]
	if version == 4 {
		binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	} else {
		binary.BigEndian.PutUint16(packet[4:6], uint16(len(packet)-40))
	}
	return packet
}

func writeEvidenceArtifact(t *testing.T, directory, context, kind, extension string, data []byte) EvidenceArtifact {
	t.Helper()
	sum := sha256.Sum256(data)
	nameHash := sha256.Sum256(append([]byte(context+"\x00"+kind+"\x00"), sum[:]...))
	name := kind + "-" + hex.EncodeToString(nameHash[:8]) + extension
	if err := os.WriteFile(filepath.Join(directory, name), data, 0o600); err != nil {
		t.Fatal(err)
	}
	artifact := EvidenceArtifact{Path: name, SHA256: hex.EncodeToString(sum[:])}
	metadata := ArtifactMetadata{
		SchemaVersion: 1, Context: context, Kind: kind, ArtifactPath: artifact.Path, ArtifactSHA256: artifact.SHA256,
	}
	metadataData, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	metadataName := name + ".meta.json"
	if err := os.WriteFile(filepath.Join(directory, metadataName), metadataData, 0o600); err != nil {
		t.Fatal(err)
	}
	metadataSum := sha256.Sum256(metadataData)
	artifact.MetaPath = metadataName
	artifact.MetaSHA256 = hex.EncodeToString(metadataSum[:])
	return artifact
}

func fixtureRaceExecution(t *testing.T, directory, caseID string) *CaseExecutionEvidence {
	t.Helper()
	testName := "TestTransportV2Case_" + strings.ReplaceAll(caseID, "-", "_")
	command := "go test"
	args := []string{"-race", "-count=1", "-run", testName, "."}
	testListContext := "race case " + caseID + " execution test-list"
	outputContext := "race case " + caseID + " execution output"
	testListData, err := json.Marshal(ExecutionLogArtifact{
		SchemaVersion: 1, Kind: "transport_execution_log", Context: testListContext, Role: "test_list",
		Command: command, Args: args, TestName: testName, ExitCode: 0, Tests: []string{testName},
	})
	if err != nil {
		t.Fatal(err)
	}
	outputData, err := json.Marshal(ExecutionLogArtifact{
		SchemaVersion: 1, Kind: "transport_execution_log", Context: outputContext, Role: "output",
		Command: command, Args: args, TestName: testName, ExitCode: 0, Output: "ok " + testName,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &CaseExecutionEvidence{
		Command: command, Args: args, TestName: testName,
		SourceSHA256: strings.Repeat("a", 64), BinarySHA256: strings.Repeat("b", 64),
		TestListArtifact: writeEvidenceArtifact(t, directory, testListContext, "execution_log", ".json", testListData),
		OutputArtifact:   writeEvidenceArtifact(t, directory, outputContext, "execution_log", ".json", outputData),
	}
}

func fixtureTDDStage(t *testing.T, directory, slice, stage string) TDDStageEvidence {
	t.Helper()
	testID := "TestTDD_" + strings.ReplaceAll(slice, "-", "_")
	args := []string{"-run", testID, "."}
	exitCode := 0
	if stage == "red" {
		exitCode = 1
	}
	startedAtNS, finishedAtNS := int64(1), int64(2)
	switch stage {
	case "green":
		startedAtNS, finishedAtNS = 3, 4
	case "refactor":
		startedAtNS, finishedAtNS = 5, 6
	}
	failureAssertion := ""
	output := "PASS " + testID
	if stage == "red" {
		failureAssertion = "expected failure assertion"
		output = "FAIL " + testID + ": " + failureAssertion
	}
	outputContext := fmt.Sprintf("TDD slice %s %s stage output", slice, stage)
	outputData, err := json.Marshal(ExecutionLogArtifact{
		SchemaVersion: 1, Kind: "transport_execution_log", Context: outputContext, Role: "tdd_output",
		Command: "go test", Args: args, TestName: testID, ExitCode: exitCode, Output: output,
	})
	if err != nil {
		t.Fatal(err)
	}
	sourceSum := sha256.Sum256([]byte(slice + "\x00" + stage + "\x00source"))
	binarySum := sha256.Sum256([]byte(slice + "\x00" + stage + "\x00binary"))
	return TDDStageEvidence{
		Command: "go test", Args: args, TestID: testID,
		SourceSHA256: hex.EncodeToString(sourceSum[:]), BinarySHA256: hex.EncodeToString(binarySum[:]),
		FailureAssertion: failureAssertion, StartedAtNS: startedAtNS, FinishedAtNS: finishedAtNS,
		ExitCode:       intPointer(exitCode),
		Artifact:       writeStructuredArtifact(t, directory, fmt.Sprintf("TDD slice %s %s stage", slice, stage), "trace"),
		OutputArtifact: writeEvidenceArtifact(t, directory, outputContext, "execution_log", ".json", outputData),
	}
}

func rewriteEvidenceArtifact(t *testing.T, directory string, artifact EvidenceArtifact, data []byte) EvidenceArtifact {
	t.Helper()
	sum := sha256.Sum256(data)
	pathDigest := sha256.Sum256([]byte(artifact.Path))
	name := "mutation-" + hex.EncodeToString(sum[:8]) + "-" + hex.EncodeToString(pathDigest[:4]) + filepath.Ext(artifact.Path)
	if err := os.WriteFile(filepath.Join(directory, name), data, 0o600); err != nil {
		t.Fatal(err)
	}
	artifact.Path = name
	artifact.SHA256 = hex.EncodeToString(sum[:])
	metadataData, err := os.ReadFile(filepath.Join(directory, artifact.MetaPath))
	if err != nil {
		t.Fatal(err)
	}
	var metadata ArtifactMetadata
	if err := decodeStrictJSON(metadataData, &metadata); err != nil {
		t.Fatal(err)
	}
	metadata.ArtifactPath = artifact.Path
	metadata.ArtifactSHA256 = artifact.SHA256
	metadataData, err = json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	metadataName := name + ".meta.json"
	if err := os.WriteFile(filepath.Join(directory, metadataName), metadataData, 0o600); err != nil {
		t.Fatal(err)
	}
	metadataSum := sha256.Sum256(metadataData)
	artifact.MetaPath = metadataName
	artifact.MetaSHA256 = hex.EncodeToString(metadataSum[:])
	return artifact
}

func signEvidenceReportForTest(t *testing.T, report *EvidenceReport, keyID string, privateKey ed25519.PrivateKey) {
	t.Helper()
	report.Attestation = EvidenceAttestation{Scheme: "ed25519", KeyID: keyID}
	message, err := evidenceSigningBytes(report)
	if err != nil {
		t.Fatal(err)
	}
	report.Attestation.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, message))
}

func writeMetricSamples(t *testing.T, report *EvidenceReport, cell *CellEvidence, metricID string, values []float64) EvidenceArtifact {
	t.Helper()
	runs := make([]MetricRunSample, len(values))
	for index, value := range values {
		runEvidence := &cell.Runs[index]
		run := MetricRunSample{
			RunNumber: index + 1, Derivation: requiredMetricDerivation(metricID),
		}
		if run.Derivation == "ratio" {
			var err error
			run.Formula, run.OperandGraph, err = ratioOperandGraph(report, cell.CellID, metricID, run.RunNumber)
			if err != nil {
				t.Fatal(err)
			}
		} else {
			run.Sources = metricSourcesForRun(t, cell.CellID, metricID, runEvidence)
		}
		if requiresMetricFaultBinding(metricID) {
			run.FaultBinding = fixtureMetricFaultBinding(t, cell, runEvidence, metricID, int64(math.Round(value*1e6)))
		}
		switch run.Derivation {
		case "p50", "p95", "p99", "max", "mean":
			count := 1
			if run.Derivation == "p50" || run.Derivation == "p95" || run.Derivation == "p99" {
				count = 2000
				if strings.HasPrefix(cell.CellID, "adaptive-") {
					count = 4000
				}
			}
			run.Observations = []FloatRunLength{{Count: count, Value: value}}
		case "ratio":
			numerator, denominator := fixtureFormulaInputs(t, report, run)
			run.Numerator, run.Denominator = floatPointer(numerator), floatPointer(denominator)
		case "duration_ms":
			duration := int64(math.Round(value * 1e6))
			run.DurationNanoseconds = &duration
		case "goodput_mbps":
			bytes := uint64(64 * 1024 * 1024)
			switch {
			case strings.HasPrefix(cell.CellID, "mobile-"):
				bytes = 16 * 1024 * 1024
			case strings.HasPrefix(cell.CellID, "edge-"):
				bytes = 2 * 1024 * 1024
			}
			duration := int64(math.Round(float64(bytes) * 8 * 1e3 / value))
			run.DurationNanoseconds, run.DeliveredBytes = &duration, &bytes
		default:
			t.Fatalf("unsupported metric derivation %q", run.Derivation)
		}
		runs[index] = run
	}
	data, err := json.Marshal(MetricSamplesArtifact{
		SchemaVersion: 1, CellID: cell.CellID, MetricID: metricID, Runs: runs,
	})
	if err != nil {
		t.Fatal(err)
	}
	context := fmt.Sprintf("cell %s metric %s raw samples", cell.CellID, metricID)
	return writeEvidenceArtifact(t, report.baseDir, context, "metric_samples", ".json", data)
}

func fixtureMetricFaultBinding(t *testing.T, cell *CellEvidence, run *RunEvidence, metricID string, durationNS int64) *MetricFaultBinding {
	t.Helper()
	var rpc *PhaseEvidence
	for index := range run.Phases {
		if run.Phases[index].Phase == "rpc" {
			rpc = &run.Phases[index]
			break
		}
	}
	if rpc == nil {
		t.Fatalf("rpc phase missing for fault metric %s", metricID)
	}
	binding := &MetricFaultBinding{
		Phase: "rpc", ProfileID: strings.TrimSuffix(strings.TrimPrefix(cell.CellID, "mobile-"), "-01"), TraceSHA256: rpc.Artifacts["trace"].SHA256, PCAPSHA256: rpc.Artifacts["pcap"].SHA256,
		ConnectionID: evidenceConnectionID, RequestID: fixtureFaultRequestID(cell.CellID, metricID, run.RunNumber), StartAtNS: 1e9, RecoveryAtNS: 3e9,
		Event: "outage_started", RecoveryEvent: "outage_recovered",
	}
	if strings.HasPrefix(cell.CellID, "mobile-") {
		binding.ProfileID = "mobile-v1"
	} else if strings.HasPrefix(cell.CellID, "edge-") {
		binding.ProfileID = "edge-v1"
	}
	carrier, err := carrierForTopology(cellTopologyForFixture(cell.CellID))
	if err != nil {
		t.Fatal(err)
	}
	binding.Carrier = carrier
	matrix := fixtureFaultMatrix(t, binding.ProfileID, carrier)
	binding.StartAtNS = matrix.OutageStartNS
	binding.RecoveryAtNS = matrix.OutageStartNS + matrix.OutageDurationNS
	if binding.ProfileID == "mobile-v1" {
		binding.ReorderPercent, binding.DuplicatePercent = 1, 1
	} else {
		binding.ReorderPercent, binding.DuplicatePercent = 2, 2
	}
	if qlog, exists := rpc.Artifacts["qlog"]; exists {
		binding.QlogSHA256 = qlog.SHA256
	}
	if strings.Contains(metricID, "migration_first_rpc") {
		binding.StartAtNS, binding.RecoveryAtNS = matrix.MigrationStartNS, matrix.MigrationValidatedNS
		binding.Event, binding.RecoveryEvent = "path_updated", "path_validated"
	}
	binding.FirstRPCAtNS = binding.RecoveryAtNS + durationNS
	return binding
}

func fixtureFaultMatrix(t *testing.T, profileID, carrier string) FaultMatrixContract {
	t.Helper()
	for _, matrix := range signedFaultMatrix {
		if matrix.ProfileID == profileID && matrix.Carrier == carrier {
			return matrix
		}
	}
	t.Fatalf("missing fault matrix for %s/%s", profileID, carrier)
	return FaultMatrixContract{}
}

func fixtureFaultRequestID(cellID, metricID string, runNumber int) string {
	return fmt.Sprintf("%s/%s/run-%d", cellID, metricID, runNumber)
}

func cellTopologyForFixture(cellID string) string {
	if strings.HasPrefix(cellID, "mobile-") || strings.HasPrefix(cellID, "edge-") {
		switch cellID[len(cellID)-2:] {
		case "01":
			return "direct_wss"
		case "02":
			return "direct_quic"
		case "03":
			return "ww"
		case "04":
			return "qq"
		case "05":
			return "wq"
		case "06":
			return "qw"
		case "07":
			return "browser_webtransport"
		case "08":
			return "browser_tunnel_wt_wss"
		case "09":
			return "browser_tunnel_wt_quic"
		}
	}
	return "direct_wss"
}

func fixtureFormulaInputs(t *testing.T, report *EvidenceReport, run MetricRunSample) (float64, float64) {
	t.Helper()
	values := make([]float64, len(run.OperandGraph))
	for index, operand := range run.OperandGraph {
		cell, sourceRun, err := metricEvidenceRun(report, operand.Source.CellID, operand.Source.RunNumber)
		if err != nil {
			t.Fatal(err)
		}
		switch operand.Source.Kind {
		case "resource":
			data, err := os.ReadFile(filepath.Join(report.baseDir, sourceRun.Resource.Path))
			if err != nil {
				t.Fatal(err)
			}
			var resource ResourceArtifact
			if err := decodeStrictJSON(data, &resource); err != nil {
				t.Fatal(err)
			}
			found := false
			for _, measurement := range resource.Measurements {
				if measurement.Name == operand.Source.Field {
					values[index], found = measurement.Value, true
				}
			}
			if !found {
				t.Fatalf("resource operand %s is missing from cell %s", operand.Source.Field, cell.CellID)
			}
		case "samples":
			phase, _, err := metricSourcePhase(cell.CellID, sourceRun, operand.Source)
			if err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(filepath.Join(report.baseDir, phase.Artifacts["samples"].Path))
			if err != nil {
				t.Fatal(err)
			}
			var artifact OperationSeriesArtifact
			if err := decodeStrictJSON(data, &artifact); err != nil {
				t.Fatal(err)
			}
			values[index], err = reduceOperationOperand(artifact.Records[0], operand.Reduction)
			if err != nil {
				t.Fatal(err)
			}
		default:
			t.Fatalf("unknown operand kind %s", operand.Source.Kind)
		}
	}
	switch run.Formula {
	case formulaDirect:
		return values[0], values[1]
	case formulaNormalized:
		return values[0] / values[1], values[2] / values[3]
	default:
		t.Fatalf("unknown fixture formula %s", run.Formula)
		return 0, 0
	}
}

func setMetricSamples(t *testing.T, manifest *PerformanceManifest, report *EvidenceReport, cell *CellEvidence, metricID string, value float64) {
	t.Helper()
	if metricID == "clean_revision_throughput_ratio" {
		for runIndex := range cell.Runs {
			run := &cell.Runs[runIndex]
			candidate := &run.Variants[slices.IndexFunc(run.Variants, func(variant VariantEvidence) bool { return variant.ID == "candidate" })]
			phase := &candidate.Phases[slices.IndexFunc(candidate.Phases, func(phase PhaseEvidence) bool { return phase.Phase == "bulk" })]
			old := phase.Artifacts["samples"]
			data, err := os.ReadFile(filepath.Join(report.baseDir, old.Path))
			if err != nil {
				t.Fatal(err)
			}
			var artifact OperationSeriesArtifact
			if err := decodeStrictJSON(data, &artifact); err != nil {
				t.Fatal(err)
			}
			goodput := value * 100
			record := &artifact.Records[0]
			scored, err := expandIntRuns(record.ScoredBytes, record.OperationCount, true)
			if err != nil {
				t.Fatal(err)
			}
			duration := int64(math.Round(float64(slices.Min(scored)) * 8 * 1e3 / goodput))
			record.ScoreDurationNS = []IntRunLength{{Count: record.OperationCount, Value: duration}}
			record.DurationNS = []IntRunLength{{Count: record.OperationCount, Value: duration + int64(time.Millisecond)}}
			data, err = json.Marshal(artifact)
			if err != nil {
				t.Fatal(err)
			}
			phase.Artifacts["samples"] = rewriteEvidenceArtifact(t, report.baseDir, old, data)
			rebindMetricArtifactDigest(t, report, old.SHA256, phase.Artifacts["samples"].SHA256)
		}
		updateMetricEvidence(t, manifest, report, cell, "bulk_goodput_mbps", value*100)
		updateMetricEvidence(t, manifest, report, cell, metricID, value)
		return
	}
	if requiredMetricDerivation(metricID) == "duration_ms" && metricID != "cleanup_latency_ms" {
		for runIndex := range cell.Runs {
			run := &cell.Runs[runIndex]
			old := run.Resource
			data, err := os.ReadFile(filepath.Join(report.baseDir, run.Resource.Path))
			if err != nil {
				t.Fatal(err)
			}
			var resource ResourceArtifact
			if err := decodeStrictJSON(data, &resource); err != nil {
				t.Fatal(err)
			}
			for measurementIndex := range resource.Measurements {
				measurement := &resource.Measurements[measurementIndex]
				if measurement.Name == metricID+".nanoseconds" {
					measurement.Value = value * 1e6
				}
			}
			resourceData, err := json.Marshal(resource)
			if err != nil {
				t.Fatal(err)
			}
			run.Resource = rewriteEvidenceArtifact(t, report.baseDir, run.Resource, resourceData)
			rebindMetricArtifactDigest(t, report, old.SHA256, run.Resource.SHA256)
		}
		if requiresMetricFaultBinding(metricID) {
			durationNS := int64(math.Round(value * 1e6))
			for runNumber := range cell.Runs {
				recoveryAtNS := int64(0)
				rewritePerformanceFaultTrace(t, report, cell, runNumber+1, func(trace *TraceArtifact) {
					contract, err := metricFaultContract(metricID)
					if err != nil {
						t.Fatal(err)
					}
					for _, record := range trace.Records {
						if record.Event == contract.recoveryEvent {
							recoveryAtNS = record.AtNS
						}
					}
					for recordIndex := range trace.Records {
						record := &trace.Records[recordIndex]
						if record.Event == "rpc_completed" && record.MetricID == metricID {
							record.AtNS = recoveryAtNS + durationNS
						}
					}
				})
				if strings.Contains(metricID, "migration_first_rpc") {
					rewritePerformanceMigrationQlog(t, report, cell, runNumber+1, func(fields []any) {
						fields[0] = float64(recoveryAtNS + durationNS)
					})
				}
			}
		}
	}
	updateMetricEvidence(t, manifest, report, cell, metricID, value)
}

func updateMetricEvidence(t *testing.T, manifest *PerformanceManifest, report *EvidenceReport, cell *CellEvidence, metricID string, value float64) {
	t.Helper()
	values := make([]float64, manifest.RunCount)
	for index := range values {
		values[index] = value
	}
	metric := cell.Metrics[metricID]
	metric.RawSamples = writeMetricSamples(t, report, cell, metricID, values)
	estimate, lower, upper := bootstrapMean(values, manifest.Bootstrap, cell.CellID, metricID)
	metric.Estimate = floatPointer(estimate)
	metric.LowerCI = floatPointer(lower)
	metric.UpperCI = floatPointer(upper)
	cell.Metrics[metricID] = metric
}

func rebindMetricArtifactDigest(t *testing.T, report *EvidenceReport, oldDigest, newDigest string) {
	t.Helper()
	for cellIndex := range report.Cells {
		cell := &report.Cells[cellIndex]
		for metricID, metric := range cell.Metrics {
			data, err := os.ReadFile(filepath.Join(report.baseDir, metric.RawSamples.Path))
			if err != nil {
				t.Fatal(err)
			}
			var artifact MetricSamplesArtifact
			if err := decodeStrictJSON(data, &artifact); err != nil {
				t.Fatal(err)
			}
			changed := false
			for runIndex := range artifact.Runs {
				for sourceIndex := range artifact.Runs[runIndex].Sources {
					source := &artifact.Runs[runIndex].Sources[sourceIndex]
					if source.ArtifactSHA256 == oldDigest {
						source.ArtifactSHA256, changed = newDigest, true
					}
				}
				for operandIndex := range artifact.Runs[runIndex].OperandGraph {
					source := &artifact.Runs[runIndex].OperandGraph[operandIndex].Source
					if source.ArtifactSHA256 == oldDigest {
						source.ArtifactSHA256, changed = newDigest, true
					}
				}
			}
			if changed {
				data, err = json.Marshal(artifact)
				if err != nil {
					t.Fatal(err)
				}
				metric.RawSamples = rewriteEvidenceArtifact(t, report.baseDir, metric.RawSamples, data)
				cell.Metrics[metricID] = metric
			}
		}
	}
}

func completePhase(t *testing.T, directory, manifestDigest, profileID, phase string, sampleCount int, cell PerformanceCell, runNumber int, context string) PhaseEvidence {
	t.Helper()
	var selection SelectionEvidence
	if phase == "cold" {
		started := make(map[string]int, len(cell.SupportedCandidates))
		for _, candidate := range cell.SupportedCandidates {
			started[candidate] = sampleCount
		}
		selection = SelectionEvidence{
			OperationCount:          sampleCount,
			StartedCandidates:       started,
			WinnerCount:             sampleCount,
			SingleBarrierOperations: sampleCount,
			CommitCount:             sampleCount,
			CredentialWriteCount:    sampleCount,
		}
	}
	artifacts := writeArtifactSet(t, directory, context, requiredArtifactsForCell(cell))
	if profileID == "mobile-v1" || profileID == "edge-v1" {
		artifacts["trace"] = writePerformanceFaultTrace(t, directory, context, profileID, phase, cell, runNumber)
		if phase == "rpc" && cell.Topology == "direct_quic" {
			artifacts["qlog"] = writePerformanceMigrationQlog(t, directory, context, profileID, cell, runNumber)
			artifacts["pcap"] = writePerformanceMigrationPCAP(t, directory, context)
		}
	}
	metricRecords := phaseFaultMetricRecords(profileID)
	metricsData, err := json.Marshal(MetricsArtifact{
		SchemaVersion: 1, Kind: "transport_metrics", Context: context, Records: metricRecords,
	})
	if err != nil {
		t.Fatal(err)
	}
	artifacts["metrics"] = writeEvidenceArtifact(t, directory, context, "metrics", ".json", metricsData)
	records, err := performanceNetworkConfigRecords(manifestDigest, profileID, phase)
	if err != nil {
		t.Fatal(err)
	}
	records = append(records,
		ConfigRecord{Key: "pcap_sha256", Value: artifacts["pcap"].SHA256},
		ConfigRecord{Key: "ebpf_metrics_sha256", Value: artifacts["metrics"].SHA256},
	)
	if qlog, exists := artifacts["qlog"]; exists {
		records = append(records, ConfigRecord{Key: "qlog_sha256", Value: qlog.SHA256})
	}
	configData, err := json.Marshal(ConfigArtifact{SchemaVersion: 1, Kind: "transport_config", Context: context, Records: records})
	if err != nil {
		t.Fatal(err)
	}
	artifacts["config"] = writeEvidenceArtifact(t, directory, context, "config", ".json", configData)
	artifacts["samples"] = writeOperationSeriesArtifact(t, directory, context, runNumber, profileID, phase, sampleCount)
	return PhaseEvidence{
		ProfileID:    profileID,
		Phase:        phase,
		SampleCount:  intPointer(sampleCount),
		FailureCount: intPointer(0),
		RetryCount:   intPointer(0),
		Selection:    selection,
		Artifacts:    artifacts,
	}
}

func writePerformanceFaultTrace(t *testing.T, directory, context, profileID, phase string, cell PerformanceCell, runNumber int) EvidenceArtifact {
	t.Helper()
	records := []TraceRecord{
		{Sequence: 1, AtNS: 1e9, Event: "outage_started", Digest: caseExecutionID(context), ConnectionID: evidenceConnectionID},
		{Sequence: 2, AtNS: 2e9, Event: "path_updated", Digest: caseExecutionID(context), ConnectionID: evidenceConnectionID},
		{Sequence: 3, AtNS: 2500 * 1e6, Event: "path_validated", Digest: caseExecutionID(context), ConnectionID: evidenceConnectionID},
		{Sequence: 4, AtNS: 3e9, Event: "outage_recovered", Digest: caseExecutionID(context), ConnectionID: evidenceConnectionID},
	}
	if cell.Topology != "direct_quic" {
		records = []TraceRecord{records[0], records[3]}
	}
	if phase == "rpc" {
		prefix := strings.TrimSuffix(profileID, "-v1")
		if cell.Topology == "direct_quic" {
			metricID := prefix + "_migration_first_rpc_ms"
			records = append(records, TraceRecord{
				AtNS: 2500*1e6 + faultMetricFixtureDurationNS(t, cell, metricID), Event: "rpc_completed", MetricID: metricID,
				RequestID: fixtureFaultRequestID(cell.ID, metricID, runNumber), Digest: caseExecutionID(context), ConnectionID: evidenceConnectionID,
			})
		}
		metricID := prefix + "_outage_recovery_overhead_ms"
		records = append(records, TraceRecord{
			AtNS: 3e9 + faultMetricFixtureDurationNS(t, cell, metricID), Event: "rpc_completed", MetricID: metricID,
			RequestID: fixtureFaultRequestID(cell.ID, metricID, runNumber), Digest: caseExecutionID(context), ConnectionID: evidenceConnectionID,
		})
	}
	completedAt := int64(6e9)
	records = append(records, TraceRecord{AtNS: completedAt, Event: "completed", Digest: caseExecutionID(context), ConnectionID: evidenceConnectionID})
	slices.SortStableFunc(records, func(left, right TraceRecord) int { return cmp.Compare(left.AtNS, right.AtNS) })
	for index := range records {
		records[index].Sequence = uint64(index + 1)
	}
	data, err := json.Marshal(TraceArtifact{SchemaVersion: 1, Kind: "transport_trace", Context: context, Records: records})
	if err != nil {
		t.Fatal(err)
	}
	return writeEvidenceArtifact(t, directory, context, "trace", ".json", data)
}

func faultMetricFixtureDurationNS(t *testing.T, cell PerformanceCell, metricID string) int64 {
	t.Helper()
	for _, contract := range signedMetricContracts {
		if contract.ID == metricID {
			return int64(math.Round(fixtureMetricValue(cell, metricID, contract) * 1e6))
		}
	}
	t.Fatalf("missing signed metric contract %s", metricID)
	return 0
}

func writePerformanceMigrationQlog(t *testing.T, directory, context, profileID string, cell PerformanceCell, runNumber int) EvidenceArtifact {
	t.Helper()
	metricID := strings.TrimSuffix(profileID, "-v1") + "_migration_first_rpc_ms"
	requestID := fixtureFaultRequestID(cell.ID, metricID, runNumber)
	rpcAtNS := int64(2500*1e6) + faultMetricFixtureDurationNS(t, cell, metricID)
	rpcData := qlogTestEventData(context, "application:rpc_completed", 4)
	rpcData["request_id"] = requestID
	events := []any{
		[]any{float64(2e9), "connectivity", "path_updated", qlogTestEventData(context, "connectivity:path_updated", 4)},
		[]any{float64(2500 * 1e6), "connectivity", "path_validated", qlogTestEventData(context, "connectivity:path_validated", 4)},
		[]any{float64(rpcAtNS), "application", "rpc_completed", rpcData},
		[]any{float64(5e9), "transport", "metrics_updated", qlogTestEventData(context, "transport:metrics_updated", 4)},
	}
	data, err := json.Marshal(map[string]any{
		"qlog_version": "0.3", "title": context, "traces": []any{map[string]any{"events": events}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return writeEvidenceArtifact(t, directory, context, "qlog", ".qlog", data)
}

func writePerformanceMigrationPCAP(t *testing.T, directory, context string) EvidenceArtifact {
	t.Helper()
	packets := [][]byte{
		syntheticIPPacketWithTuple(t, 4, 17, 1301, 1, 1001, 4433),
		syntheticIPPacketWithTuple(t, 4, 17, 1200, 1, 2001, 4433),
	}
	digest := sha256.Sum256([]byte(context))
	copy(packets[0][len(packets[0])-8:], digest[:8])
	return writeEvidenceArtifact(t, directory, context, "pcap", ".pcap", encodeClassicPCAP(packets))
}

func phaseFaultMetricRecords(profileID string) []MetricCounterRecord {
	hits := make(map[string]float64)
	switch profileID {
	case "mobile-v1":
		for _, name := range []string{"fault_delay_packets", "fault_jitter_packets", "fault_periodic_loss_packets", "fault_rate_limited_packets", "fault_mtu_drop_packets", "fault_queue_overflow_packets", "fault_reorder_packets", "fault_duplicate_packets", "fault_outage_events"} {
			hits[name] = 1
		}
		hits["fault_outage_duration_ns"] = 2e9
	case "edge-v1":
		for _, name := range []string{"fault_delay_packets", "fault_jitter_packets", "fault_burst_loss_packets", "fault_rate_limited_packets", "fault_mtu_drop_packets", "fault_queue_overflow_packets", "fault_reorder_packets", "fault_duplicate_packets", "fault_outage_events"} {
			hits[name] = 1
		}
		hits["fault_outage_duration_ns"] = 2e9
	}
	records := []MetricCounterRecord{{Name: "ebpf_packets", Value: 100, Unit: "count"}, {Name: "ebpf_bytes", Value: 10_000, Unit: "bytes"}}
	for _, name := range phaseFaultCounterNames {
		records = append(records, MetricCounterRecord{Name: name, Value: hits[name], Unit: phaseFaultMetricUnit(name)})
	}
	return records
}

func writeOperationSeriesArtifact(t *testing.T, directory, context string, runNumber int, profileID, phase string, sampleCount int) EvidenceArtifact {
	t.Helper()
	contract, err := signedOperationContract(profileID, phase)
	if err != nil {
		t.Fatal(err)
	}
	duration := int64(time.Millisecond)
	maximum := 1
	if phase == "bulk" {
		goodput := map[string]float64{"clean-v1": 100, "mobile-v1": 5, "edge-v1": 1}[profileID]
		scoreDuration := int64(math.Round(float64(contract.scoredBytes) * 8 * 1e3 / goodput))
		duration = scoreDuration + int64(time.Millisecond)
		maximum = 2
	}
	digest := sha256.Sum256([]byte(context + "\x00payload-hash-chain"))
	record := OperationSeriesRecord{
		RunNumber: runNumber, OperationCount: sampleCount,
		ScheduledFirstNS: 0, ScheduledIntervalNS: contract.scheduledIntervalNS,
		StartDelayNS: []IntRunLength{{Count: sampleCount, Value: 0}},
		DurationNS:   []IntRunLength{{Count: sampleCount, Value: duration}},
		RetryCounts:  []IntRunLength{{Count: sampleCount, Value: 0}},
		InputBytes:   []IntRunLength{{Count: sampleCount, Value: contract.inputBytes}},
		OutputBytes:  []IntRunLength{{Count: sampleCount, Value: contract.outputBytes}},
		ScoredBytes:  []IntRunLength{{Count: sampleCount, Value: contract.scoredBytes}},
		ScoreDurationNS: []IntRunLength{{
			Count: sampleCount,
			Value: map[bool]int64{true: duration - int64(time.Millisecond)}[contract.scoredBytes > 0],
		}},
		OperationDeadlineNS: contract.operationDeadlineNS, PhaseDeadlineNS: contract.phaseDeadlineNS,
		MaxInflightObserved:   maximum,
		ExpectedPayloadSHA256: hex.EncodeToString(digest[:]), ActualPayloadSHA256: hex.EncodeToString(digest[:]),
	}
	data, err := json.Marshal(OperationSeriesArtifact{
		SchemaVersion: 1, Kind: "transport_samples", Context: context, Records: []OperationSeriesRecord{record},
	})
	if err != nil {
		t.Fatal(err)
	}
	return writeEvidenceArtifact(t, directory, context, "samples", ".json", data)
}

func metricSourcesForRun(t *testing.T, cellID, metricID string, run *RunEvidence) []MetricSourceRef {
	t.Helper()
	derivation := requiredMetricDerivation(metricID)
	if derivation == "ratio" {
		t.Fatal("ratio sources must use the frozen operand graph")
	}
	if derivation == "max" {
		return []MetricSourceRef{{CellID: cellID, RunNumber: run.RunNumber, Kind: "resource", Field: metricID, ArtifactSHA256: run.Resource.SHA256}}
	}
	if derivation == "duration_ms" && metricID != "cleanup_latency_ms" {
		return []MetricSourceRef{{CellID: cellID, RunNumber: run.RunNumber, Kind: "resource", Field: metricID + ".nanoseconds", ArtifactSHA256: run.Resource.SHA256}}
	}
	phaseName, field := "cold", "duration_ns"
	if strings.Contains(metricID, "rpc") {
		phaseName = "rpc"
	}
	if derivation == "goodput_mbps" {
		phaseName, field = "bulk", "score_goodput"
	}
	if metricID == "cleanup_latency_ms" {
		phaseName = "cleanup"
	}
	var sources []MetricSourceRef
	appendPhases := func(variantID string, phases []PhaseEvidence) {
		for _, phase := range phases {
			if phase.Phase != phaseName {
				continue
			}
			sources = append(sources, MetricSourceRef{
				CellID: cellID, RunNumber: run.RunNumber, VariantID: variantID, ProfileID: phase.ProfileID,
				Phase: phase.Phase, Kind: "samples", Field: field,
				ArtifactSHA256: phase.Artifacts["samples"].SHA256,
			})
		}
	}
	if len(run.Variants) == 0 {
		appendPhases("", run.Phases)
	} else {
		chosen := &run.Variants[len(run.Variants)-1]
		for index := range run.Variants {
			if run.Variants[index].ID == "candidate" {
				chosen = &run.Variants[index]
				break
			}
		}
		appendPhases(chosen.ID, chosen.Phases)
	}
	if len(sources) == 0 {
		t.Fatalf("run %d has no %s source for metric %s", run.RunNumber, phaseName, metricID)
	}
	return sources
}

func writeRunResourceArtifact(t *testing.T, directory string, cell PerformanceCell, runNumber int, contracts map[string]MetricContract) EvidenceArtifact {
	t.Helper()
	retransmitRatio := 0.1
	if strings.HasPrefix(cell.ID, "mobile-") {
		retransmitRatio = 0.25
	} else if strings.HasPrefix(cell.ID, "edge-") {
		retransmitRatio = 0.5
	}
	measurements := []ScopedResourceMeasurement{
		{Name: "cpu_nanoseconds", Value: 100, Unit: "nanoseconds"},
		{Name: "delivered_bytes", Value: 100, Unit: "bytes"},
		{Name: "retransmitted_bytes", Value: retransmitRatio * 100, Unit: "bytes"},
		{Name: "variant.base.cpu_nanoseconds", Value: 100, Unit: "nanoseconds", VariantID: "base", ProfileID: "clean-v1", Phase: "bulk"},
		{Name: "variant.base.delivered_bytes", Value: 100, Unit: "bytes", VariantID: "base", ProfileID: "clean-v1", Phase: "bulk"},
		{Name: "variant.candidate.cpu_nanoseconds", Value: 100, Unit: "nanoseconds", VariantID: "candidate", ProfileID: "clean-v1", Phase: "bulk"},
		{Name: "variant.candidate.delivered_bytes", Value: 100, Unit: "bytes", VariantID: "candidate", ProfileID: "clean-v1", Phase: "bulk"},
		{Name: "variant.candidate.retransmitted_bytes", Value: retransmitRatio * 100, Unit: "bytes", VariantID: "candidate", ProfileID: "clean-v1", Phase: "bulk"},
		{Name: "profile.clean-v1.cpu_connect_nanoseconds", Value: 100, Unit: "nanoseconds", ProfileID: "clean-v1", Phase: "cold"},
		{Name: "profile.mobile-v1.cpu_connect_nanoseconds", Value: 100, Unit: "nanoseconds", ProfileID: "mobile-v1", Phase: "cold"},
		{Name: "interactive.rpc_p99_milliseconds", Value: 1, Unit: "milliseconds", ProfileID: "mobile-v1", Phase: "rpc"},
		{Name: "idle.rpc_p99_milliseconds", Value: 1, Unit: "milliseconds", ProfileID: "mobile-v1", Phase: "rpc"},
	}
	for _, metricID := range cell.RequiredMetrics {
		value := fixtureMetricValue(cell, metricID, contracts[metricID])
		switch requiredMetricDerivation(metricID) {
		case "ratio":
		case "max":
			unit := "bytes"
			if metricID == "active_streams" {
				unit = "count"
			}
			measurements = append(measurements, ScopedResourceMeasurement{Name: metricID, Value: value, Unit: unit})
		case "duration_ms":
			if metricID != "cleanup_latency_ms" {
				measurements = append(measurements, ScopedResourceMeasurement{Name: metricID + ".nanoseconds", Value: value * 1e6, Unit: "nanoseconds"})
			}
		}
	}
	context := fmt.Sprintf("cell %s run %d resource", cell.ID, runNumber)
	artifact := ResourceArtifact{
		SchemaVersion: 1, Kind: "transport_resource", Context: context,
		Records: []ResourceRecord{{AtNS: 1, RSSBytes: 1, Goroutines: 1}}, Measurements: measurements,
	}
	data, err := json.Marshal(artifact)
	if err != nil {
		t.Fatal(err)
	}
	return writeEvidenceArtifact(t, directory, context, "resource", ".json", data)
}

func intPointer(value int) *int {
	return &value
}

func int64Pointer(value int64) *int64 { return &value }

func boolPointer(value bool) *bool { return &value }

func floatPointer(value float64) *float64 { return &value }

func cloneArtifacts(source map[string]EvidenceArtifact) map[string]EvidenceArtifact {
	copy := make(map[string]EvidenceArtifact, len(source))
	for key, value := range source {
		copy[key] = value
	}
	return copy
}

func clonePhases(source []PhaseEvidence) []PhaseEvidence {
	copy := make([]PhaseEvidence, len(source))
	for index, phase := range source {
		copy[index] = phase
		copy[index].Artifacts = cloneArtifacts(phase.Artifacts)
	}
	return copy
}

func writeJSON(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func assertResult(t *testing.T, result CheckResult, wantStatus checkStatus, wantIssue string) {
	t.Helper()
	if result.Status != wantStatus {
		t.Fatalf("status = %q, want %q; issues=%v", result.Status, wantStatus, result.Issues)
	}
	for _, issue := range result.Issues {
		if strings.Contains(issue, wantIssue) {
			return
		}
	}
	t.Fatalf("issues = %v, want containing %q", result.Issues, wantIssue)
}

func equalInts(left, right []int) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
