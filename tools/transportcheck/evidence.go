package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
)

var requiredPerformanceArtifactKinds = []string{"samples", "metrics", "trace", "pcap", "config"}

var qlogTopologies = map[string]struct{}{
	"direct_quic":            {},
	"qq":                     {},
	"wq":                     {},
	"qw":                     {},
	"browser_webtransport":   {},
	"browser_tunnel_wt_wss":  {},
	"browser_tunnel_wt_quic": {},
	"adaptive_native":        {},
	"adaptive_web":           {},
}

var gitSHAPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

var frozenTDDSlices = []string{
	"slice-0-contract-baseline",
	"slice-1-wire-vectors",
	"slice-2-transport-model",
	"slice-3-websocket-v2",
	"slice-4-quic-native-direct",
	"slice-5-mixed-tunnel-broker",
	"slice-6-equal-selection-spend",
	"slice-7-portable-sdks",
	"slice-8-weaknet-performance",
	"slice-9-final-sync-review",
}

type resultBuilder struct {
	status        checkStatus
	issues        []string
	artifactPaths map[string]string
	artifactSHA   map[string][]string
}

func loadEvidenceReport(path string) (*EvidenceReport, error) {
	var report EvidenceReport
	if err := decodeStrictFile(path, &report); err != nil {
		return nil, err
	}
	report.baseDir = filepath.Dir(path)
	return &report, nil
}

func checkEvidence(manifest *PerformanceManifest, registry *CaseRegistry, report *EvidenceReport, baseDir string) CheckResult {
	return checkEvidenceInternal(manifest, registry, report, baseDir, nil)
}

func checkEvidenceAgainstRepository(manifest *PerformanceManifest, registry *CaseRegistry, report *EvidenceReport, baseDir string, repository RepositoryState) CheckResult {
	return checkEvidenceInternal(manifest, registry, report, baseDir, &repository)
}

func checkEvidenceInternal(manifest *PerformanceManifest, registry *CaseRegistry, report *EvidenceReport, baseDir string, repository *RepositoryState) CheckResult {
	builder := resultBuilder{
		status: statusPass, artifactPaths: make(map[string]string), artifactSHA: collectEvidenceArtifactSHA(report),
	}
	if err := validateManifest(manifest); err != nil {
		builder.fail("manifest: %v", err)
		return builder.result()
	}
	if err := validateCaseRegistry(registry); err != nil {
		builder.fail("case registry: %v", err)
		return builder.result()
	}
	if report == nil {
		builder.inconclusive("evidence report is missing")
		return builder.result()
	}
	checkArtifactDigestClaims(&builder)
	if report.SchemaVersion != 1 {
		builder.fail("report schema_version = %d, want 1", report.SchemaVersion)
	}
	if report.ManifestDigest != manifest.Digest {
		builder.fail("report manifest digest mismatch")
	}
	checkEvidenceMetadata(&builder, report, baseDir, repository)
	checkPerformanceCells(&builder, manifest, report, baseDir)
	checkCases(&builder, manifest, registry, report, baseDir)
	return builder.result()
}

func checkEvidenceMetadata(builder *resultBuilder, report *EvidenceReport, baseDir string, repository *RepositoryState) {
	if report.Classification != "signed_transport_evidence" {
		builder.fail("report classification = %q, want signed_transport_evidence", report.Classification)
	}
	if report.Runner.OS != "linux" || report.Runner.ID == "" || report.Runner.Architecture == "" || report.Runner.KernelRelease == "" ||
		report.Runner.Namespace != "isolated" || report.Runner.TrafficControl == "" || report.Runner.PacketCounters == "" ||
		!validSHA256(report.Runner.EffectiveConfigSHA256) || !validSHA256(report.Runner.ExecutableSHA256) ||
		!validSHA256(report.Runner.SourceSHA256) || !validSHA256(report.Runner.ArgvSHA256) {
		builder.fail("report runner must bind a complete isolated Linux kernel/netns/tc/packet-counter identity")
	}
	if !gitSHAPattern.MatchString(report.Source.BaseSHA) {
		builder.inconclusive("report base_sha must be a full lowercase Git SHA")
	}
	if !gitSHAPattern.MatchString(report.Source.FinalSHA) {
		builder.inconclusive("report final_sha must be a full lowercase Git SHA")
	}
	if report.Source.BaseSHA != "" && report.Source.BaseSHA == report.Source.FinalSHA {
		builder.fail("report base_sha and final_sha must differ")
	}
	if report.Source.Dirty == nil {
		builder.inconclusive("report source must explicitly record dirty=false")
	} else if *report.Source.Dirty {
		builder.fail("report source must record dirty=false")
	}
	if report.Source.UntrackedFileCount == nil {
		builder.inconclusive("report source is missing untracked_file_count")
	} else if *report.Source.UntrackedFileCount != 0 {
		builder.fail("report untracked_file_count = %d, want zero", *report.Source.UntrackedFileCount)
	}
	if repository != nil {
		if report.Source.FinalSHA != repository.FinalSHA {
			builder.fail("report final_sha does not match audited repository HEAD")
		}
		if report.Source.BaseSHA != repository.BaseSHA {
			builder.fail("report base_sha does not match the audited repository base")
		}
		if repository.Dirty || repository.UntrackedFileCount != 0 {
			builder.fail("audited repository is not clean: dirty=%t untracked_file_count=%d", repository.Dirty, repository.UntrackedFileCount)
		}
		if !repository.BaseIsAncestor {
			builder.fail("audited base_sha is not an ancestor of repository HEAD")
		}
	}
	checkTDDEvidence(builder, report.TDD, baseDir)
}

func checkTDDEvidence(builder *resultBuilder, records []TDDEvidenceRecord, baseDir string) {
	if len(records) == 0 {
		builder.inconclusive("report is missing TDD evidence records")
		return
	}
	seen := make(map[string]struct{}, len(records))
	for _, record := range records {
		if strings.TrimSpace(record.Slice) == "" {
			builder.inconclusive("TDD evidence slice must not be empty")
			continue
		}
		if _, duplicate := seen[record.Slice]; duplicate {
			builder.fail("duplicate TDD evidence slice %q", record.Slice)
			continue
		}
		seen[record.Slice] = struct{}{}
		checkTDDStage(builder, record.Slice, "red", record.Red, baseDir)
		checkTDDStage(builder, record.Slice, "green", record.Green, baseDir)
		checkTDDStage(builder, record.Slice, "refactor", record.Refactor, baseDir)
		validateTDDRecord(builder, record, baseDir)
	}
	for _, required := range frozenTDDSlices {
		if _, exists := seen[required]; !exists {
			builder.fail("missing TDD evidence slice %s", required)
		}
	}
}

func checkTDDStage(builder *resultBuilder, slice, name string, stage TDDStageEvidence, baseDir string) {
	context := fmt.Sprintf("TDD slice %s %s stage", slice, name)
	if strings.TrimSpace(stage.Command) == "" {
		builder.inconclusive("%s is missing command", context)
	}
	if stage.ExitCode == nil {
		builder.inconclusive("%s is missing exit_code", context)
	} else if name == "red" && *stage.ExitCode == 0 {
		builder.fail("%s must record a nonzero exit", context)
	} else if name != "red" && *stage.ExitCode != 0 {
		builder.fail("%s must record a zero exit", context)
	}
	if strings.TrimSpace(stage.Artifact.Path) == "" || strings.TrimSpace(stage.Artifact.SHA256) == "" {
		builder.inconclusive("%s artifact is missing", context)
		return
	}
	data, ok := readArtifact(builder, context, "trace", stage.Artifact, baseDir)
	if ok {
		checkArtifactSemantics(builder, context, "trace", data)
	}
}

func validateTDDRecord(builder *resultBuilder, record TDDEvidenceRecord, baseDir string) {
	stages := []struct {
		name  string
		value TDDStageEvidence
	}{
		{"red", record.Red}, {"green", record.Green}, {"refactor", record.Refactor},
	}
	if strings.TrimSpace(record.Red.TestID) == "" || record.Red.TestID != record.Green.TestID || record.Red.TestID != record.Refactor.TestID {
		builder.fail("TDD slice %s stages must bind one test_id", record.Slice)
		return
	}
	if strings.TrimSpace(record.Red.FailureAssertion) == "" {
		builder.fail("TDD slice %s red stage must record the expected failure assertion", record.Slice)
	}
	previousFinished := int64(-1)
	for _, stage := range stages {
		context := fmt.Sprintf("TDD slice %s %s stage", record.Slice, stage.name)
		if strings.TrimSpace(stage.value.Command) != "go test" || !slices.Contains(stage.value.Args, "-run") ||
			!slices.Contains(stage.value.Args, stage.value.TestID) || !validSHA256(stage.value.SourceSHA256) ||
			!validSHA256(stage.value.BinarySHA256) {
			builder.fail("%s execution identity is incomplete", context)
		}
		if stage.value.StartedAtNS < 0 || stage.value.FinishedAtNS <= stage.value.StartedAtNS || stage.value.StartedAtNS < previousFinished {
			builder.fail("%s timestamps are not a monotonic execution timeline", context)
		}
		previousFinished = stage.value.FinishedAtNS
		if stage.value.ExitCode == nil {
			continue
		}
		outputContext := context + " output"
		if strings.TrimSpace(stage.value.OutputArtifact.Path) == "" {
			builder.fail("%s output artifact is missing", context)
			continue
		}
		data, ok := readArtifact(builder, outputContext, "execution_log", stage.value.OutputArtifact, baseDir)
		if !ok {
			continue
		}
		var output ExecutionLogArtifact
		if err := decodeStrictJSON(data, &output); err != nil {
			builder.fail("%s output artifact is invalid: %v", context, err)
			continue
		}
		if output.SchemaVersion != 1 || output.Kind != "transport_execution_log" || output.Context != outputContext ||
			output.Role != "tdd_output" || output.Command != stage.value.Command || !slices.Equal(output.Args, stage.value.Args) ||
			output.TestName != stage.value.TestID || output.ExitCode != *stage.value.ExitCode || strings.TrimSpace(output.Output) == "" {
			builder.fail("%s output does not bind the declared test execution", context)
			continue
		}
		if stage.name == "red" && !strings.Contains(output.Output, stage.value.FailureAssertion) {
			builder.fail("%s output does not contain the expected failure assertion", context)
		}
	}
}

func checkPerformanceCells(builder *resultBuilder, manifest *PerformanceManifest, report *EvidenceReport, baseDir string) {
	manifestCells := make(map[string]PerformanceCell, len(manifest.Cells))
	profiles := make(map[string]PerformanceProfile, len(manifest.Profiles))
	for _, cell := range manifest.Cells {
		manifestCells[cell.ID] = cell
	}
	for _, profile := range manifest.Profiles {
		profiles[profile.ID] = profile
	}
	contracts := make(map[string]MetricContract, len(manifest.MetricContracts))
	for _, contract := range manifest.MetricContracts {
		contracts[contract.ID] = contract
	}
	seen := make(map[string]struct{}, len(report.Cells))
	for _, evidence := range report.Cells {
		cell, exists := manifestCells[evidence.CellID]
		if !exists {
			builder.fail("unknown performance cell %q", evidence.CellID)
			continue
		}
		if _, duplicate := seen[evidence.CellID]; duplicate {
			builder.fail("duplicate performance cell evidence %q", evidence.CellID)
			continue
		}
		seen[evidence.CellID] = struct{}{}
		if evidence.Policy != cell.Policy {
			builder.fail("cell %s policy mismatch", cell.ID)
		}
		if !sameStringSet(evidence.SupportedCandidates, cell.SupportedCandidates) {
			builder.fail("cell %s supported candidate set mismatch", cell.ID)
		}
		if evidence.ElapsedNanoseconds == nil {
			builder.inconclusive("cell %s is missing elapsed_nanoseconds", cell.ID)
		} else if *evidence.ElapsedNanoseconds < 0 || *evidence.ElapsedNanoseconds > int64(cell.DurationMinutes)*60*1e9 {
			builder.fail("cell %s wall-clock elapsed time exceeds its %d minute watchdog", cell.ID, cell.DurationMinutes)
		}
		checkRuns(builder, manifest, profiles[cell.ProfileID], cell, evidence, baseDir)
		checkMetrics(builder, manifest, report, cell, evidence.Metrics, contracts, baseDir)
	}
	for _, cell := range manifest.Cells {
		if _, exists := seen[cell.ID]; !exists {
			builder.inconclusive("cell %s is missing performance evidence", cell.ID)
		}
	}
}

func checkMetrics(builder *resultBuilder, manifest *PerformanceManifest, report *EvidenceReport, cell PerformanceCell, evidence map[string]MetricEvidence, contracts map[string]MetricContract, baseDir string) {
	required := make(map[string]struct{}, len(cell.RequiredMetrics))
	for _, metricID := range cell.RequiredMetrics {
		required[metricID] = struct{}{}
		metric, exists := evidence[metricID]
		if !exists {
			builder.inconclusive("cell %s is missing metric %s", cell.ID, metricID)
			continue
		}
		contract, exists := contracts[metricID]
		if !exists {
			builder.fail("cell %s metric %s has no registered contract", cell.ID, metricID)
			continue
		}
		context := fmt.Sprintf("cell %s metric %s", cell.ID, metricID)
		if metric.Samples != manifest.RunCount {
			builder.inconclusive("%s must contain exactly 15 run-cluster samples; got %d", context, metric.Samples)
		}
		if metric.Estimate == nil || metric.LowerCI == nil || metric.UpperCI == nil {
			builder.inconclusive("%s is missing estimate or confidence interval bounds", context)
			continue
		}
		estimate, lower, upper := *metric.Estimate, *metric.LowerCI, *metric.UpperCI
		if math.IsNaN(estimate) || math.IsNaN(lower) || math.IsNaN(upper) ||
			math.IsInf(estimate, 0) || math.IsInf(lower, 0) || math.IsInf(upper, 0) {
			builder.fail("%s contains a non-finite estimate or confidence interval", context)
			continue
		}
		if lower > estimate || estimate > upper {
			builder.fail("%s confidence interval does not contain its estimate", context)
			continue
		}
		computedEstimate, computedLower, computedUpper, ok := checkMetricRawSamples(builder, manifest, report, cell.ID, metricID, metric.RawSamples, baseDir)
		if !ok {
			continue
		}
		if !sameFloat(estimate, computedEstimate) || !sameFloat(lower, computedLower) || !sameFloat(upper, computedUpper) {
			builder.fail("%s reported statistics do not match deterministic bootstrap: got %.9g [%.9g, %.9g], want %.9g [%.9g, %.9g]",
				context, estimate, lower, upper, computedEstimate, computedLower, computedUpper)
		}
		estimate, lower, upper = computedEstimate, computedLower, computedUpper
		switch contract.Decision {
		case "observe":
		case "upper":
			if upper > *contract.Threshold {
				builder.inconclusive("%s upper CI %.6g exceeds threshold %.6g", context, upper, *contract.Threshold)
			}
		case "lower":
			if lower < *contract.Threshold {
				builder.inconclusive("%s lower CI %.6g is below threshold %.6g", context, lower, *contract.Threshold)
			}
		default:
			builder.fail("%s uses unknown decision %q", context, contract.Decision)
		}
	}
	for metricID := range evidence {
		if _, exists := required[metricID]; !exists {
			builder.fail("cell %s contains unregistered metric evidence %s", cell.ID, metricID)
		}
	}
}

func checkMetricRawSamples(builder *resultBuilder, manifest *PerformanceManifest, report *EvidenceReport, cellID, metricID string, artifact EvidenceArtifact, baseDir string) (float64, float64, float64, bool) {
	context := fmt.Sprintf("cell %s metric %s raw samples", cellID, metricID)
	data, ok := readArtifact(builder, context, "metric_samples", artifact, baseDir)
	if !ok {
		return 0, 0, 0, false
	}
	var samples MetricSamplesArtifact
	if err := decodeStrictJSON(data, &samples); err != nil {
		builder.fail("%s artifact is not strict metric samples JSON: %v", context, err)
		return 0, 0, 0, false
	}
	if samples.SchemaVersion != 1 || samples.CellID != cellID || samples.MetricID != metricID || len(samples.Runs) != manifest.RunCount {
		builder.fail("%s artifact metadata/count mismatch", context)
		return 0, 0, 0, false
	}
	values := make([]float64, manifest.RunCount)
	seenRuns := make(map[int]struct{}, manifest.RunCount)
	for _, run := range samples.Runs {
		if run.RunNumber < 1 || run.RunNumber > manifest.RunCount {
			builder.fail("%s artifact has invalid run_number %d", context, run.RunNumber)
			return 0, 0, 0, false
		}
		if _, duplicate := seenRuns[run.RunNumber]; duplicate {
			builder.fail("%s artifact has duplicate run_number %d", context, run.RunNumber)
			return 0, 0, 0, false
		}
		seenRuns[run.RunNumber] = struct{}{}
		if want := requiredMetricDerivation(metricID); run.Derivation != want {
			builder.fail("%s run %d derivation = %q, want %q", context, run.RunNumber, run.Derivation, want)
			return 0, 0, 0, false
		}
		if err := validateMetricRunContract(manifest, cellID, metricID, run); err != nil {
			builder.fail("%s run %d raw metric contract mismatch: %v", context, run.RunNumber, err)
			return 0, 0, 0, false
		}
		if err := validateAndDeriveMetricSources(builder, report, manifest, cellID, metricID, run, baseDir); err != nil {
			if errors.Is(err, errMetricSourceMissing) {
				builder.inconclusive("%s run %d provenance is incomplete: %v", context, run.RunNumber, err)
			} else {
				builder.fail("%s run %d provenance does not bind the exact same cell/variant/profile/phase raw source: %v", context, run.RunNumber, err)
			}
			return 0, 0, 0, false
		}
		value, err := deriveMetricRun(run)
		if err != nil || math.IsNaN(value) || math.IsInf(value, 0) {
			builder.fail("%s run %d cannot be derived from raw inputs: %v", context, run.RunNumber, err)
			return 0, 0, 0, false
		}
		values[run.RunNumber-1] = value
	}
	estimate, lower, upper := bootstrapMean(values, manifest.Bootstrap, cellID, metricID)
	return estimate, lower, upper, true
}

func collectEvidenceArtifactSHA(report *EvidenceReport) map[string][]string {
	index := make(map[string][]string)
	if report == nil {
		return index
	}
	add := func(context string, artifact EvidenceArtifact) {
		if artifact.SHA256 != "" {
			index[artifact.SHA256] = append(index[artifact.SHA256], context)
		}
	}
	for _, record := range report.TDD {
		add("TDD "+record.Slice+" red", record.Red.Artifact)
		add("TDD "+record.Slice+" green", record.Green.Artifact)
		add("TDD "+record.Slice+" refactor", record.Refactor.Artifact)
	}
	for _, cell := range report.Cells {
		for metricID, metric := range cell.Metrics {
			add(fmt.Sprintf("cell %s metric %s raw samples", cell.CellID, metricID), metric.RawSamples)
		}
		for _, run := range cell.Runs {
			add(fmt.Sprintf("cell %s run %d resource", cell.CellID, run.RunNumber), run.Resource)
			for _, phase := range run.Phases {
				for kind, artifact := range phase.Artifacts {
					add(fmt.Sprintf("cell %s run %d phase %s/%s %s", cell.CellID, run.RunNumber, phase.ProfileID, phase.Phase, kind), artifact)
				}
			}
			for _, variant := range run.Variants {
				for _, phase := range variant.Phases {
					for kind, artifact := range phase.Artifacts {
						add(fmt.Sprintf("cell %s run %d variant %s phase %s/%s %s", cell.CellID, run.RunNumber, variant.ID, phase.ProfileID, phase.Phase, kind), artifact)
					}
				}
			}
		}
	}
	for _, evidence := range report.Cases {
		for kind, artifact := range evidence.Evidence {
			add(fmt.Sprintf("case %s %s %s", evidence.ID, evidence.Mode, kind), artifact)
		}
	}
	return index
}

func checkArtifactDigestClaims(builder *resultBuilder) {
	digests := make([]string, 0, len(builder.artifactSHA))
	for digest, claims := range builder.artifactSHA {
		if len(claims) > 1 {
			digests = append(digests, digest)
		}
	}
	sort.Strings(digests)
	for _, digest := range digests {
		claims := append([]string(nil), builder.artifactSHA[digest]...)
		sort.Strings(claims)
		builder.fail("artifact SHA-256 %s reuses artifact digest across report claims: %s", digest, strings.Join(claims, "; "))
	}
}

func bootstrapMean(values []float64, contract BootstrapContract, cellID, metricID string) (float64, float64, float64) {
	estimate := mean(values)
	constant := true
	for _, value := range values[1:] {
		if value != values[0] {
			constant = false
			break
		}
	}
	if constant {
		return estimate, estimate, estimate
	}
	seedMaterial := sha256.Sum256([]byte(cellID + "\x00" + metricID))
	seed := int64(contract.Seed) ^ int64(binary.BigEndian.Uint64(seedMaterial[:8]))
	random := rand.New(rand.NewSource(seed))
	resampled := make([]float64, contract.Resamples)
	for index := range resampled {
		total := 0.0
		for range values {
			total += values[random.Intn(len(values))]
		}
		resampled[index] = total / float64(len(values))
	}
	sort.Float64s(resampled)
	alpha := (100 - float64(contract.ConfidencePercent)) / 200
	return estimate, quantile(resampled, alpha), quantile(resampled, 1-alpha)
}

func mean(values []float64) float64 {
	total := 0.0
	for _, value := range values {
		total += value
	}
	return total / float64(len(values))
}

func quantile(sorted []float64, probability float64) float64 {
	position := probability * float64(len(sorted)-1)
	lower := int(math.Floor(position))
	upper := int(math.Ceil(position))
	if lower == upper {
		return sorted[lower]
	}
	weight := position - float64(lower)
	return sorted[lower]*(1-weight) + sorted[upper]*weight
}

func sameFloat(left, right float64) bool {
	scale := math.Max(1, math.Max(math.Abs(left), math.Abs(right)))
	return math.Abs(left-right) <= 1e-9*scale
}

func checkRuns(builder *resultBuilder, manifest *PerformanceManifest, profile PerformanceProfile, cell PerformanceCell, evidence CellEvidence, baseDir string) {
	runCount := manifest.RunCount
	if len(evidence.Runs) != runCount {
		builder.inconclusive("cell %s must contain exactly 15 independent runs; got %d", cell.ID, len(evidence.Runs))
	}
	seenRuns := make(map[int]struct{}, len(evidence.Runs))
	for _, run := range evidence.Runs {
		if run.RunNumber < 1 || run.RunNumber > runCount {
			builder.fail("cell %s has invalid run_number %d", cell.ID, run.RunNumber)
			continue
		}
		if _, duplicate := seenRuns[run.RunNumber]; duplicate {
			builder.fail("cell %s has duplicate run_number %d", cell.ID, run.RunNumber)
			continue
		}
		seenRuns[run.RunNumber] = struct{}{}
		context := fmt.Sprintf("cell %s run %d resource", cell.ID, run.RunNumber)
		if strings.TrimSpace(run.Resource.Path) == "" || strings.TrimSpace(run.Resource.SHA256) == "" {
			builder.inconclusive("%s is missing", context)
		} else if data, ok := readArtifact(builder, context, "resource", run.Resource, baseDir); ok {
			checkArtifactSemantics(builder, context, "resource", data)
		}
		checkRunPhases(builder, manifest, profile, cell, run, baseDir)
	}
	for runNumber := 1; runNumber <= runCount; runNumber++ {
		if _, exists := seenRuns[runNumber]; !exists {
			builder.inconclusive("cell %s is missing run_number %d", cell.ID, runNumber)
		}
	}
}

type expectedPhase struct {
	profileID   string
	phase       string
	sampleCount int
	selection   bool
}

func checkRunPhases(builder *resultBuilder, manifest *PerformanceManifest, profile PerformanceProfile, cell PerformanceCell, run RunEvidence, baseDir string) {
	if len(cell.Variants) == 0 {
		if len(run.Variants) != 0 {
			builder.fail("cell %s run %d declares variants for a non-variant cell", cell.ID, run.RunNumber)
		}
		checkPhases(builder, manifest, profile, cell, run.RunNumber, "", run.Phases, baseDir)
		return
	}
	if len(run.Phases) != 0 {
		builder.fail("cell %s run %d must bind phases to declared variants", cell.ID, run.RunNumber)
	}
	seen := make(map[string]struct{}, len(run.Variants))
	for _, variant := range run.Variants {
		if !slices.Contains(cell.Variants, variant.ID) {
			builder.fail("cell %s run %d has unknown variant %s", cell.ID, run.RunNumber, variant.ID)
			continue
		}
		if _, duplicate := seen[variant.ID]; duplicate {
			builder.fail("cell %s run %d has duplicate variant %s", cell.ID, run.RunNumber, variant.ID)
			continue
		}
		seen[variant.ID] = struct{}{}
		checkPhases(builder, manifest, profile, cell, run.RunNumber, " variant "+variant.ID, variant.Phases, baseDir)
	}
	for _, variant := range cell.Variants {
		if _, exists := seen[variant]; !exists {
			builder.inconclusive("cell %s run %d is missing variant %s", cell.ID, run.RunNumber, variant)
		}
	}
}

func checkPhases(builder *resultBuilder, manifest *PerformanceManifest, profile PerformanceProfile, cell PerformanceCell, runNumber int, scope string, phases []PhaseEvidence, baseDir string) {
	expected := expectedPhases(profile)
	wanted := make(map[string]expectedPhase, len(expected))
	for _, phase := range expected {
		wanted[phase.profileID+"/"+phase.phase] = phase
	}
	seen := make(map[string]struct{}, len(phases))
	for _, evidence := range phases {
		key := evidence.ProfileID + "/" + evidence.Phase
		phase, exists := wanted[key]
		if !exists {
			builder.fail("cell %s run %d%s has unknown phase %s", cell.ID, runNumber, scope, key)
			continue
		}
		if _, duplicate := seen[key]; duplicate {
			builder.fail("cell %s run %d%s has duplicate phase %s", cell.ID, runNumber, scope, key)
			continue
		}
		seen[key] = struct{}{}
		context := fmt.Sprintf("cell %s run %d%s phase %s", cell.ID, runNumber, scope, key)
		if evidence.SampleCount == nil {
			builder.inconclusive("%s is missing sample_count", context)
		} else if *evidence.SampleCount != phase.sampleCount {
			builder.inconclusive("%s sample_count = %d, want %d", context, *evidence.SampleCount, phase.sampleCount)
		}
		if evidence.FailureCount == nil {
			builder.inconclusive("%s is missing failure_count", context)
		} else if *evidence.FailureCount != 0 {
			builder.fail("%s failure_count = %d, want zero", context, *evidence.FailureCount)
		}
		if evidence.RetryCount == nil {
			builder.inconclusive("%s is missing retry_count", context)
		} else if *evidence.RetryCount != 0 {
			builder.fail("%s retry_count = %d, want zero", context, *evidence.RetryCount)
		}
		if phase.selection {
			checkSelection(builder, context, profile.Mode, cell, evidence.Selection, phase.sampleCount)
		}
		checkRequiredArtifacts(builder, context, evidence.Artifacts, requiredArtifactsForCell(cell), baseDir)
		if config, exists := evidence.Artifacts["config"]; exists && strings.TrimSpace(config.Path) != "" && strings.TrimSpace(config.SHA256) != "" && hasBoundPhaseArtifacts(evidence.Artifacts, requiredArtifactsForCell(cell)) {
			if err := validatePerformanceNetworkConfig(builder, context, evidence, manifest, cell, evidence.Phase, baseDir); err != nil {
				builder.fail("%s effective network config does not match the frozen manifest: %v", context, err)
			}
		}
		checkPhaseOperationSeries(builder, context, runNumber, phase, evidence, baseDir)
	}
	for key := range wanted {
		if _, exists := seen[key]; !exists {
			builder.inconclusive("cell %s run %d%s is missing phase %s", cell.ID, runNumber, scope, key)
		}
	}
}

func hasBoundPhaseArtifacts(artifacts map[string]EvidenceArtifact, required []string) bool {
	for _, kind := range required {
		artifact, exists := artifacts[kind]
		if !exists || strings.TrimSpace(artifact.Path) == "" || !validSHA256(artifact.SHA256) {
			return false
		}
	}
	return true
}

func requiredArtifactsForCell(cell PerformanceCell) []string {
	required := append([]string(nil), requiredPerformanceArtifactKinds...)
	if _, needsQlog := qlogTopologies[cell.Topology]; needsQlog {
		required = append(required, "qlog")
	}
	return required
}

func expectedPhases(profile PerformanceProfile) []expectedPhase {
	if profile.Mode == "adaptive" {
		phases := make([]expectedPhase, 0, 2*len(profile.AdaptiveStages))
		for _, stage := range profile.AdaptiveStages {
			phases = append(phases, expectedPhase{profileID: stage.ProfileID, phase: "cold", sampleCount: stage.Cold.Operations, selection: true})
			phases = append(phases, expectedPhase{profileID: stage.ProfileID, phase: "cleanup", sampleCount: 1})
		}
		return phases
	}
	return []expectedPhase{
		{profileID: profile.ID, phase: "cold", sampleCount: profile.Cold.Operations, selection: true},
		{profileID: profile.ID, phase: "rpc", sampleCount: profile.RPC.Operations},
		{profileID: profile.ID, phase: "bulk", sampleCount: 2},
		{profileID: profile.ID, phase: "cleanup", sampleCount: 1},
	}
}

func checkSelection(builder *resultBuilder, context, mode string, cell PerformanceCell, selection SelectionEvidence, operations int) {
	if selection.OperationCount != operations {
		builder.inconclusive("%s selection operation_count = %d, want %d", context, selection.OperationCount, operations)
	}
	expectedCandidates := cell.SupportedCandidates
	actualCandidates := make([]string, 0, len(selection.StartedCandidates))
	for candidate := range selection.StartedCandidates {
		actualCandidates = append(actualCandidates, candidate)
	}
	if !sameStringSet(actualCandidates, expectedCandidates) {
		if mode == "forced" {
			builder.fail("%s forced candidate set differs from the single manifest candidate", context)
		} else {
			builder.inconclusive("%s adaptive candidate set omits or adds a manifest candidate", context)
		}
	}
	for _, candidate := range expectedCandidates {
		count, exists := selection.StartedCandidates[candidate]
		if !exists {
			continue
		}
		if count < operations {
			builder.inconclusive("%s candidate %s started count = %d, want %d", context, candidate, count, operations)
		} else if count > operations {
			builder.fail("%s candidate %s started count = %d, want %d", context, candidate, count, operations)
		}
	}
	if selection.WinnerCount != operations {
		builder.fail("%s winner_count = %d, want %d", context, selection.WinnerCount, operations)
	}
	if mode == "adaptive" && selection.SingleBarrierOperations != operations {
		builder.fail("%s adaptive selection must start all candidates on a single barrier for every operation", context)
	}
	if selection.CommitCount != operations {
		builder.fail("%s commit_count = %d, want exactly one per operation", context, selection.CommitCount)
	}
	if selection.CredentialWriteCount != operations {
		builder.fail("%s credential_write_count = %d, want exactly one per operation", context, selection.CredentialWriteCount)
	}
}

func checkCases(builder *resultBuilder, manifest *PerformanceManifest, registry *CaseRegistry, report *EvidenceReport, baseDir string) {
	definitions := make(map[string]CaseDefinition, len(registry.Cases))
	for _, entry := range registry.Cases {
		definitions[entry.ID] = entry
	}
	normalCounts := make(map[string]int, len(registry.Cases))
	raceCounts := make(map[string]int, len(registry.Cases))
	for _, evidence := range report.Cases {
		definition, exists := definitions[evidence.ID]
		if !exists {
			builder.fail("unknown case ID %q", evidence.ID)
			continue
		}
		if evidence.Mode == "race" {
			expectedOwner := definition.Owner
			if definition.Mode == "normal" {
				expectedOwner = definition.RaceOwner
			}
			raceRegistered := (definition.Mode == "normal" || definition.Mode == "race") && expectedOwner != ""
			if !raceRegistered || evidence.Owner != expectedOwner {
				builder.fail("case %s mode race is not registered for owner %q", evidence.ID, evidence.Owner)
			}
			raceCounts[evidence.ID]++
			if raceCounts[evidence.ID] > 1 {
				builder.fail("duplicate race evidence for case ID %s", evidence.ID)
				continue
			}
			if evidence.Profile != definition.Profile {
				builder.fail("race case %s profile = %q, want %q", evidence.ID, evidence.Profile, definition.Profile)
			}
			checkCaseStatus(builder, evidence)
			if err := validateRaceExecutionEvidence(builder, "race case "+evidence.ID, evidence, baseDir); err != nil {
				builder.fail("race case %s has invalid execution attestation: %v", evidence.ID, err)
			}
			checkRequiredArtifacts(builder, "race case "+evidence.ID, evidence.Evidence, definition.EvidenceFields, baseDir)
			if err := validateCaseEvidenceSemantics(builder, manifest, "race case "+evidence.ID, evidence, baseDir); err != nil {
				builder.fail("race case %s does not satisfy its frozen evidence semantics: %v", evidence.ID, err)
			}
			continue
		}
		if evidence.Mode != definition.Mode {
			builder.fail("case %s mode = %q, want %q", evidence.ID, evidence.Mode, definition.Mode)
			continue
		}
		normalCounts[evidence.ID]++
		if normalCounts[evidence.ID] > 1 {
			builder.fail("duplicate normal evidence for case ID %s", evidence.ID)
			continue
		}
		if evidence.Owner != definition.Owner {
			builder.fail("case %s owner = %q, want %q", evidence.ID, evidence.Owner, definition.Owner)
		}
		if evidence.Profile != definition.Profile {
			builder.fail("case %s profile = %q, want %q", evidence.ID, evidence.Profile, definition.Profile)
		}
		checkCaseStatus(builder, evidence)
		checkRequiredArtifacts(builder, "case "+evidence.ID, evidence.Evidence, definition.EvidenceFields, baseDir)
		if err := validateCaseEvidenceSemantics(builder, manifest, "case "+evidence.ID, evidence, baseDir); err != nil {
			builder.fail("case %s does not satisfy its frozen evidence semantics: %v", evidence.ID, err)
		}
	}
	for _, definition := range registry.Cases {
		if definition.Required && normalCounts[definition.ID] == 0 {
			builder.fail("missing normal evidence for required case ID %s", definition.ID)
		}
		if definition.RaceOwner != "" && raceCounts[definition.ID] == 0 {
			builder.fail("missing race evidence for case ID %s owned by %s", definition.ID, definition.RaceOwner)
		}
	}
}

func checkCaseStatus(builder *resultBuilder, evidence CaseEvidence) {
	switch evidence.Status {
	case "pass":
	case "fail":
		builder.fail("case %s reports failure", evidence.ID)
	case "inconclusive":
		builder.inconclusive("case %s reports inconclusive evidence", evidence.ID)
	default:
		builder.fail("case %s has unknown status %q", evidence.ID, evidence.Status)
	}
}

func validateRaceExecutionEvidence(builder *resultBuilder, context string, evidence CaseEvidence, baseDir string) error {
	execution := evidence.Execution
	if execution == nil {
		return errors.New("execution attestation is missing")
	}
	if strings.TrimSpace(execution.Command) != "go test" || strings.TrimSpace(execution.TestName) == "" ||
		!validSHA256(execution.SourceSHA256) || !validSHA256(execution.BinarySHA256) {
		return errors.New("execution attestation must bind go test, test name, source SHA, and test binary SHA")
	}
	for _, required := range []string{"-race", "-count=1", "-run"} {
		if !slices.Contains(execution.Args, required) {
			return fmt.Errorf("race command args are missing %s", required)
		}
	}
	if len(execution.Args) == 0 {
		return errors.New("race command args must not be empty")
	}
	testListContext := context + " execution test-list"
	testListData, ok := readArtifact(builder, testListContext, "execution_log", execution.TestListArtifact, baseDir)
	if !ok {
		return errors.New("race test-list artifact is invalid")
	}
	outputContext := context + " execution output"
	outputData, ok := readArtifact(builder, outputContext, "execution_log", execution.OutputArtifact, baseDir)
	if !ok {
		return errors.New("race output artifact is invalid")
	}
	var testList, output ExecutionLogArtifact
	if err := decodeStrictJSON(testListData, &testList); err != nil {
		return err
	}
	if err := decodeStrictJSON(outputData, &output); err != nil {
		return err
	}
	if testList.SchemaVersion != 1 || testList.Kind != "transport_execution_log" || testList.Context != testListContext ||
		testList.Role != "test_list" || testList.Command != execution.Command || !slices.Equal(testList.Args, execution.Args) ||
		!slices.Contains(testList.Tests, execution.TestName) || testList.ExitCode != 0 {
		return errors.New("race test-list artifact does not bind the declared command and test")
	}
	if output.SchemaVersion != 1 || output.Kind != "transport_execution_log" || output.Context != outputContext ||
		output.Role != "output" || output.Command != execution.Command || !slices.Equal(output.Args, execution.Args) ||
		output.TestName != execution.TestName || output.ExitCode != 0 || strings.TrimSpace(output.Output) == "" {
		return errors.New("race output artifact does not bind a successful declared command")
	}
	return nil
}

func checkRequiredArtifacts(builder *resultBuilder, context string, artifacts map[string]EvidenceArtifact, required []string, baseDir string) {
	seenPaths := make(map[string]string, len(required))
	for _, kind := range required {
		artifact, exists := artifacts[kind]
		if !exists || strings.TrimSpace(artifact.Path) == "" || strings.TrimSpace(artifact.SHA256) == "" {
			builder.inconclusive("%s is missing %s artifact", context, kind)
			continue
		}
		clean := filepath.Clean(artifact.Path)
		if previous, duplicate := seenPaths[clean]; duplicate {
			builder.fail("%s reuses artifact path %q for %s and %s", context, clean, previous, kind)
			continue
		}
		seenPaths[clean] = kind
		data, ok := readArtifact(builder, context, kind, artifact, baseDir)
		if ok {
			checkArtifactSemantics(builder, context, kind, data)
		}
	}
}

type structuredArtifactEnvelope struct {
	SchemaVersion int               `json:"schema_version"`
	Kind          string            `json:"kind"`
	Context       string            `json:"context"`
	Records       []json.RawMessage `json:"records"`
}

func checkArtifactSemantics(builder *resultBuilder, context, kind string, data []byte) {
	switch kind {
	case "pcap":
		if !validPCAP(data) {
			builder.fail("%s pcap artifact has no valid pcap/pcapng header and non-empty packet record", context)
		} else if err := validatePCAPEvidence(context, data); err != nil {
			builder.fail("%s pcap artifact does not prove required packet semantics: %v", context, err)
		}
	case "qlog":
		if err := validateQlogEvidence(context, data); err != nil {
			builder.fail("%s qlog artifact does not prove required events: %v", context, err)
		}
	case "samples", "metrics", "trace", "config", "resource", "tcp_info":
		if err := validateTypedStructuredArtifact(context, kind, data); err != nil {
			builder.fail("%s %s artifact is not a bound structured evidence envelope with typed operation records: %v", context, kind, err)
		}
	default:
		builder.fail("%s uses unknown evidence artifact kind %q", context, kind)
	}
}

func validPCAP(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	magic := binary.BigEndian.Uint32(data[:4])
	if magic == 0x0a0d0d0a {
		return validPCAPNG(data)
	}
	var order binary.ByteOrder
	switch magic {
	case 0xa1b2c3d4, 0xa1b23c4d:
		order = binary.BigEndian
	case 0xd4c3b2a1, 0x4d3cb2a1:
		order = binary.LittleEndian
	default:
		return false
	}
	if len(data) < 41 || order.Uint16(data[4:6]) != 2 || order.Uint16(data[6:8]) != 4 || order.Uint32(data[16:20]) == 0 {
		return false
	}
	captured := order.Uint32(data[32:36])
	original := order.Uint32(data[36:40])
	return captured > 0 && captured <= original && uint64(40)+uint64(captured) <= uint64(len(data))
}

func validPCAPNG(data []byte) bool {
	if len(data) < 28 {
		return false
	}
	var order binary.ByteOrder
	switch binary.BigEndian.Uint32(data[8:12]) {
	case 0x1a2b3c4d:
		order = binary.BigEndian
	case 0x4d3c2b1a:
		order = binary.LittleEndian
	default:
		return false
	}
	sectionLength := int(order.Uint32(data[4:8]))
	if !validPCAPNGBlock(data, 0, sectionLength, order) || sectionLength < 28 {
		return false
	}
	seenInterface := false
	for offset := sectionLength; offset+12 <= len(data); {
		blockType := order.Uint32(data[offset : offset+4])
		blockLength := int(order.Uint32(data[offset+4 : offset+8]))
		if !validPCAPNGBlock(data, offset, blockLength, order) {
			return false
		}
		switch blockType {
		case 1:
			seenInterface = true
		case 6, 2:
			if !seenInterface || blockLength < 33 {
				return false
			}
			captured := int(order.Uint32(data[offset+20 : offset+24]))
			if captured > 0 && offset+28+captured <= offset+blockLength-4 {
				return true
			}
		case 3:
			if seenInterface && blockLength > 16 && order.Uint32(data[offset+8:offset+12]) > 0 {
				return true
			}
		}
		offset += blockLength
	}
	return false
}

func validPCAPNGBlock(data []byte, offset, length int, order binary.ByteOrder) bool {
	return length >= 12 && length%4 == 0 && offset >= 0 && offset+length <= len(data) &&
		int(order.Uint32(data[offset+length-4:offset+length])) == length
}

func checkArtifact(builder *resultBuilder, context, kind string, artifact EvidenceArtifact, baseDir string) {
	_, _ = readArtifact(builder, context, kind, artifact, baseDir)
}

func readArtifact(builder *resultBuilder, context, kind string, artifact EvidenceArtifact, baseDir string) ([]byte, bool) {
	if strings.TrimSpace(artifact.MetaPath) == "" || strings.TrimSpace(artifact.MetaSHA256) == "" {
		builder.inconclusive("%s %s artifact is missing signed metadata sidecar", context, kind)
		return nil, false
	}
	if filepath.IsAbs(artifact.Path) {
		builder.fail("%s %s artifact path must be relative", context, kind)
		return nil, false
	}
	clean := filepath.Clean(artifact.Path)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		builder.fail("%s %s artifact path escapes the report directory", context, kind)
		return nil, false
	}
	claim := context + " " + kind
	if previous, exists := builder.artifactPaths[clean]; exists && previous != claim {
		builder.fail("%s reuses artifact path across report: %q was already claimed by %s", claim, clean, previous)
		return nil, false
	}
	builder.artifactPaths[clean] = claim
	fullPath := filepath.Join(baseDir, clean)
	info, err := os.Lstat(fullPath)
	if err != nil {
		builder.inconclusive("%s artifact cannot be read: %v", claim, err)
		return nil, false
	}
	if !info.Mode().IsRegular() {
		builder.fail("%s artifact must be a regular file", claim)
		return nil, false
	}
	data, err := os.ReadFile(fullPath)
	if err != nil {
		builder.inconclusive("%s artifact cannot be read: %v", claim, err)
		return nil, false
	}
	digest, err := hex.DecodeString(artifact.SHA256)
	if err != nil || len(digest) != sha256.Size {
		builder.fail("%s artifact has invalid SHA-256", claim)
		return nil, false
	}
	sum := sha256.Sum256(data)
	if !slices.Equal(digest, sum[:]) {
		builder.fail("%s artifact digest mismatch", claim)
		return nil, false
	}
	if !checkArtifactMetadata(builder, context, kind, clean, artifact, baseDir) {
		return nil, false
	}
	return data, true
}

func checkArtifactMetadata(builder *resultBuilder, context, kind, artifactPath string, artifact EvidenceArtifact, baseDir string) bool {
	if filepath.IsAbs(artifact.MetaPath) {
		builder.fail("%s %s artifact metadata path must be relative", context, kind)
		return false
	}
	clean := filepath.Clean(artifact.MetaPath)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		builder.fail("%s %s artifact metadata path escapes the report directory", context, kind)
		return false
	}
	claim := context + " " + kind + " metadata"
	if previous, exists := builder.artifactPaths[clean]; exists && previous != claim {
		builder.fail("%s reuses artifact path across report: %q was already claimed by %s", claim, clean, previous)
		return false
	}
	builder.artifactPaths[clean] = claim
	fullPath := filepath.Join(baseDir, clean)
	info, err := os.Lstat(fullPath)
	if err != nil {
		builder.inconclusive("%s cannot be read: %v", claim, err)
		return false
	}
	if !info.Mode().IsRegular() {
		builder.fail("%s must be a regular file", claim)
		return false
	}
	data, err := os.ReadFile(fullPath)
	if err != nil {
		builder.inconclusive("%s cannot be read: %v", claim, err)
		return false
	}
	digest, err := hex.DecodeString(artifact.MetaSHA256)
	if err != nil || len(digest) != sha256.Size {
		builder.fail("%s has invalid SHA-256", claim)
		return false
	}
	sum := sha256.Sum256(data)
	if !slices.Equal(digest, sum[:]) {
		builder.fail("%s digest mismatch", claim)
		return false
	}
	var metadata ArtifactMetadata
	if err := decodeStrictJSON(data, &metadata); err != nil || metadata.SchemaVersion != 1 || metadata.Context != context ||
		metadata.Kind != kind || metadata.ArtifactPath != artifactPath || metadata.ArtifactSHA256 != artifact.SHA256 {
		builder.fail("%s does not bind exact context, kind, path, and digest", claim)
		return false
	}
	return true
}

func sameStringSet(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	leftCopy := append([]string(nil), left...)
	rightCopy := append([]string(nil), right...)
	slices.Sort(leftCopy)
	slices.Sort(rightCopy)
	return slices.Equal(leftCopy, rightCopy)
}

func (builder *resultBuilder) fail(format string, args ...any) {
	builder.status = statusFail
	builder.issues = append(builder.issues, fmt.Sprintf(format, args...))
}

func (builder *resultBuilder) inconclusive(format string, args ...any) {
	if builder.status == statusPass {
		builder.status = statusInconclusive
	}
	builder.issues = append(builder.issues, fmt.Sprintf(format, args...))
}

func (builder *resultBuilder) result() CheckResult {
	return CheckResult{Status: builder.status, Issues: builder.issues}
}
