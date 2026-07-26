package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

const collectTestFinalSHA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const collectTestBaseSHA = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

func TestCollectFlagFrontDoorRejectsIncompleteAndUnknownRequests(t *testing.T) {
	for _, args := range [][]string{
		{"collect"},
		{"collect", "-target", "unknown"},
		{"collect", "-target", "all", "positional"},
	} {
		if err := run(args, io.Discard); err == nil {
			t.Fatalf("run(%q) unexpectedly succeeded", args)
		}
	}
}

func TestBuildCollectionPlanHasProducerCoverageForEveryCurrentReleaseTarget(t *testing.T) {
	manifest := loadFixtureManifest(t)
	registry := loadFixtureRegistry(t)
	for target := range collectTargets {
		plan, err := buildCollectionPlan(target, manifest, registry)
		if err != nil {
			t.Fatalf("%s: %v", target, err)
		}
		if len(plan.Missing) != 0 {
			t.Fatalf("%s has incomplete producer coverage: %v", target, plan.Missing)
		}
	}
	abPlan, err := buildCollectionPlan("bench-transport-ab", manifest, registry)
	if err != nil {
		t.Fatal(err)
	}
	if len(abPlan.Jobs) != 30 || len(abPlan.Missing) != 0 {
		t.Fatalf("A/B plan jobs=%d missing=%v", len(abPlan.Jobs), abPlan.Missing)
	}
	allPlan, err := buildCollectionPlan("all", manifest, registry)
	if err != nil {
		t.Fatal(err)
	}
	if len(allPlan.Jobs) != len(abPlan.Jobs)+21 || len(allPlan.Missing) != 0 {
		t.Fatalf("all plan does not include performance jobs plus case gaps: jobs=%d missing=%d", len(allPlan.Jobs), len(allPlan.Missing))
	}
	wantCaseCounts := map[string]int{
		"bench-transport-capacity":    12,
		"bench-transport-soak":        1,
		"transport-browser-smoke":     3,
		"transport-conformance-smoke": 6,
		"transport-conformance-full":  8,
		"weaknet-full":                4,
		"weaknet-system":              8,
		"quic-native-smoke":           4,
		"quic-native-proof":           7,
		"quic-native-race":            4,
	}
	seenCaseCounts := make(map[string]int, len(wantCaseCounts))
	seenJobCounts := make(map[string]int, len(wantCaseCounts))
	for _, job := range allPlan.Jobs {
		wantCount, exists := wantCaseCounts[job.CaseOwner]
		if !exists {
			continue
		}
		wantMode := "normal"
		if job.CaseOwner == "quic-native-race" {
			wantMode = "race"
		}
		if job.RunnerTarget != "release-case-suite" || job.CaseMode != wantMode {
			t.Fatalf("all plan contains an incomplete %s producer: %+v", job.CaseOwner, job)
		}
		if job.CaseOwner == "bench-transport-capacity" {
			if job.CaseID == "" || !slices.Equal(job.CaseIDs, []string{job.CaseID}) {
				t.Fatalf("capacity producer is not bound to one exact case: %+v", job)
			}
		} else if job.CaseID != "" || len(job.CaseIDs) != wantCount {
			t.Fatalf("owner suite producer changed shape: %+v", job)
		}
		seenCaseCounts[job.CaseOwner] += len(job.CaseIDs)
		seenJobCounts[job.CaseOwner]++
	}
	for owner, wantCount := range wantCaseCounts {
		wantJobs := 1
		if owner == "bench-transport-capacity" {
			wantJobs = wantCount
		}
		if seenCaseCounts[owner] != wantCount || seenJobCounts[owner] != wantJobs {
			t.Fatalf("owner %s producer coverage = %d cases/%d jobs, want %d/%d", owner, seenCaseCounts[owner], seenJobCounts[owner], wantCount, wantJobs)
		}
	}
	systemPlan, err := buildCollectionPlan("weaknet-system", manifest, registry)
	if err != nil {
		t.Fatal(err)
	}
	if len(systemPlan.Missing) != 0 || len(systemPlan.Jobs) != 1 || systemPlan.Jobs[0].CaseOwner != "weaknet-system" ||
		!systemPlan.Jobs[0].NeedsBPF || len(systemPlan.Jobs[0].CaseIDs) != 8 {
		t.Fatalf("weaknet-system plan does not bind its exact eight-case BPF producer: %+v", systemPlan)
	}
	for _, target := range []string{"quic-native-proof", "quic-native-race"} {
		plan, err := buildCollectionPlan(target, manifest, registry)
		if err != nil {
			t.Fatal(err)
		}
		wantMode, wantCount := "normal", 7
		if target == "quic-native-race" {
			wantMode, wantCount = "race", 4
		}
		if len(plan.Missing) != 0 || len(plan.Jobs) != 1 || plan.Jobs[0].CaseOwner != target ||
			plan.Jobs[0].CaseMode != wantMode || !plan.Jobs[0].NeedsBPF || len(plan.Jobs[0].CaseIDs) != wantCount {
			t.Fatalf("%s plan does not bind its exact BPF producer: %+v", target, plan)
		}
	}
}

func TestBuildCollectionPlanSplitsCapacityIntoExactCaseJobs(t *testing.T) {
	plan, err := buildCollectionPlan("bench-transport-capacity", loadFixtureManifest(t), loadFixtureRegistry(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Missing) != 0 || len(plan.Jobs) != 12 {
		t.Fatalf("capacity plan = %d jobs, %d gaps", len(plan.Jobs), len(plan.Missing))
	}
	seen := make(map[string]struct{}, len(plan.Jobs))
	for _, job := range plan.Jobs {
		if job.CaseOwner != "bench-transport-capacity" || job.CaseMode != "normal" || job.CaseID == "" ||
			!slices.Equal(job.CaseIDs, []string{job.CaseID}) {
			t.Fatalf("capacity job is not exact-case scoped: %+v", job)
		}
		if _, duplicate := seen[job.CaseID]; duplicate {
			t.Fatalf("capacity case %s is scheduled more than once", job.CaseID)
		}
		seen[job.CaseID] = struct{}{}
		args := collectionJobArgs(job, "/manifest", "/report", "/artifacts", collectTestFinalSHA, "/repository", "/bpf.o")
		if !argumentHasPair(args, "--case-id", job.CaseID) {
			t.Fatalf("capacity job command does not bind case %s: %v", job.CaseID, args)
		}
	}
}

func TestCollectionPlanBindsCleanRevisionVariantsToIndependentSources(t *testing.T) {
	jobs, missing := supportedPerformanceJobs(loadFixtureManifest(t))
	if slices.Contains(missing, "cell clean-01 (direct_wss_revision)") {
		t.Fatal("clean-01 still lacks a producer")
	}
	want := map[string]struct {
		variant  string
		revision string
	}{
		"clean-01-base":      {variant: "base", revision: collectionRevisionBase},
		"clean-01-candidate": {variant: "candidate", revision: collectionRevisionFinal},
	}
	for _, job := range jobs {
		expected, ok := want[job.ID]
		if !ok {
			continue
		}
		if job.VariantID != expected.variant || job.SourceRevision != expected.revision ||
			job.RunnerTarget != "direct-clean-baseline" || !slices.Equal(job.CellIDs, []string{"clean-01"}) {
			t.Fatalf("job %s = %+v", job.ID, job)
		}
		delete(want, job.ID)
	}
	if len(want) != 0 {
		t.Fatalf("missing clean-01 jobs: %v", want)
	}
}

func TestFrozenCollectionLaneScheduleMatchesSixLane30MinuteContract(t *testing.T) {
	manifest := loadFixtureManifest(t)
	if !requiresProductionLaneIsolation(manifest) {
		t.Fatal("frozen production manifest did not require cgroup lane isolation")
	}
	if requiresProductionLaneIsolation(&PerformanceManifest{EligibleLaneCount: 2}) {
		t.Fatal("schedule-free unit manifest required production cgroup lane isolation")
	}
	jobs := make([]collectionJob, 0, len(manifest.Cells))
	for _, cell := range manifest.Cells {
		if slices.Contains([]string{"clean-01", "clean-02", "clean-03"}, cell.ID) {
			continue
		}
		jobs = append(jobs, collectionJob{ID: cell.ID, CellIDs: []string{cell.ID}})
	}
	jobs = append(jobs,
		collectionJob{ID: "clean-01-base", CellIDs: []string{"clean-01"}},
		collectionJob{ID: "clean-01-candidate", CellIDs: []string{"clean-01"}},
		collectionJob{ID: "clean-direct-baseline", CellIDs: []string{"clean-02", "clean-03"}},
	)
	schedule, err := scheduleCollectionJobs(manifest, jobs)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := schedule.loads, []int{25, 25, 25, 25, 25, 25}; !slices.Equal(got, want) {
		t.Fatalf("lane loads = %v, want %v", got, want)
	}
	if schedule.loads[len(schedule.loads)-1]+manifest.GlobalSetupMinutes != manifest.GlobalWatchdogMinutes {
		t.Fatalf("schedule does not consume the exact frozen watchdog: loads=%v setup=%d watchdog=%d", schedule.loads, manifest.GlobalSetupMinutes, manifest.GlobalWatchdogMinutes)
	}
	cleanLanes := map[string]int{}
	for lane, scheduledJobs := range schedule.lanes {
		for _, scheduled := range scheduledJobs {
			if scheduled.job.ID == "clean-01-base" || scheduled.job.ID == "clean-01-candidate" {
				cleanLanes[scheduled.job.ID] = lane
			}
		}
	}
	if cleanLanes["clean-01-base"] != cleanLanes["clean-01-candidate"] {
		t.Fatalf("clean revision variants may collide across lanes: %v", cleanLanes)
	}
}

func TestOnlyCleanRevisionBaseJobCanSelectBaseExecution(t *testing.T) {
	request := collectRequest{
		ManifestPath: "/final/manifest", BaseManifestPath: "/base/manifest",
		RepositoryPath: "/final", BaseRepositoryPath: "/base",
		FinalSHA: collectTestFinalSHA, BaseSHA: collectTestBaseSHA,
		RunnerExecutable: "/final/runner", BaseRunnerExecutable: "/base/runner",
	}
	baseJob := collectionJob{ID: "clean-01-base", CellIDs: []string{"clean-01"}, RunnerTarget: "direct-clean-baseline", VariantID: "base", SourceRevision: collectionRevisionBase}
	execution, err := executionForCollectionJob(request, baseJob)
	if err != nil {
		t.Fatal(err)
	}
	if execution.executable != request.BaseRunnerExecutable || execution.repository != request.BaseRepositoryPath || execution.sourceSHA != request.BaseSHA {
		t.Fatalf("base execution = %+v", execution)
	}
	for _, mutation := range []collectionJob{
		{ID: "other", CellIDs: baseJob.CellIDs, RunnerTarget: baseJob.RunnerTarget, VariantID: baseJob.VariantID, SourceRevision: collectionRevisionBase},
		{ID: baseJob.ID, CellIDs: baseJob.CellIDs, RunnerTarget: baseJob.RunnerTarget, VariantID: "candidate", SourceRevision: collectionRevisionBase},
		{ID: baseJob.ID, CellIDs: []string{"clean-02"}, RunnerTarget: baseJob.RunnerTarget, VariantID: baseJob.VariantID, SourceRevision: collectionRevisionBase},
	} {
		if _, err := executionForCollectionJob(request, mutation); err == nil {
			t.Fatalf("accepted invalid base execution job: %+v", mutation)
		}
	}
}

func TestBuildCollectionPlanRunsConformanceSmokeProducerIndependently(t *testing.T) {
	manifest := loadFixtureManifest(t)
	registry := loadFixtureRegistry(t)
	plan, err := buildCollectionPlan("transport-conformance-smoke", manifest, registry)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Missing) != 0 || len(plan.Jobs) != 1 {
		t.Fatalf("conformance smoke plan = %d jobs, %d gaps", len(plan.Jobs), len(plan.Missing))
	}
	job := plan.Jobs[0]
	if job.RunnerTarget != "release-case-suite" || job.CaseOwner != "transport-conformance-smoke" || job.CaseMode != "normal" || len(job.CaseIDs) != 6 {
		t.Fatalf("conformance smoke job is incomplete: %+v", job)
	}
}

func TestRunCollectionJobsUsesRealExecutableAndEmptyPerCellArtifactDirectories(t *testing.T) {
	root := canonicalCollectTestRoot(t)
	runner := writeFakeCollectRunner(t, root, false)
	manifest := &PerformanceManifest{Digest: "sha256:collect-test-manifest"}
	t.Setenv("FAKE_FINAL_SHA", collectTestFinalSHA)
	t.Setenv("FAKE_MANIFEST_DIGEST", manifest.Digest)
	request := collectRequest{
		ManifestPath: filepath.Join(root, "manifest.json"), RepositoryPath: root,
		FinalSHA: collectTestFinalSHA, RunnerExecutable: runner,
		BPFObject: filepath.Join(root, "packet_fault.o"),
	}
	jobs := []collectionJob{
		{ID: "mobile-01", CellIDs: []string{"mobile-01"}, RunnerTarget: "direct-network-profile-cell", Profile: "mobile-v1", Carrier: "websocket", NeedsBPF: true},
		{ID: "clean-08", CellIDs: []string{"clean-08"}, RunnerTarget: "browser-webtransport-cell", Profile: "clean-v1", Topology: "browser_webtransport"},
	}
	staging := filepath.Join(root, "staging")
	if err := os.Mkdir(staging, 0o700); err != nil {
		t.Fatal(err)
	}
	records, err := runCollectionJobs(context.Background(), request, manifest, nil, jobs, staging)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != len(jobs) {
		t.Fatalf("records=%d, want %d", len(records), len(jobs))
	}
	for _, job := range jobs {
		jobRoot := filepath.Join(staging, "jobs", job.ID)
		for _, name := range []string{"cell.json", "command.json", "stdout.log", "stderr.log"} {
			if info, err := os.Stat(filepath.Join(jobRoot, name)); err != nil || !info.Mode().IsRegular() {
				t.Fatalf("%s/%s is not preserved: %v", job.ID, name, err)
			}
		}
		if _, err := os.Stat(filepath.Join(jobRoot, "artifacts", "run-1", "traffic.pcap")); err != nil {
			t.Fatalf("%s raw artifact missing: %v", job.ID, err)
		}
		var command struct {
			Executable string   `json:"executable"`
			Args       []string `json:"args"`
		}
		data, err := os.ReadFile(filepath.Join(jobRoot, "command.json"))
		if err != nil || json.Unmarshal(data, &command) != nil {
			t.Fatalf("decode %s command: %v", job.ID, err)
		}
		if command.Executable != runner || !argumentHasPair(command.Args, "--artifact-dir", filepath.Join(jobRoot, "artifacts")) ||
			!argumentHasPair(command.Args, "--report", filepath.Join(jobRoot, "cell.json")) {
			t.Fatalf("%s command does not bind report/artifacts: %+v", job.ID, command)
		}
		gotBPF := argumentHasPair(command.Args, "--bpf-object", request.BPFObject)
		if gotBPF != job.NeedsBPF {
			t.Fatalf("%s BPF argv=%t, want %t: %v", job.ID, gotBPF, job.NeedsBPF, command.Args)
		}
	}
}

func TestRunCollectionJobsUsesParallelLanesAndStableRecordOrder(t *testing.T) {
	root := canonicalCollectTestRoot(t)
	runner := filepath.Join(root, "parallel-runner.sh")
	script := `#!/bin/sh
set -eu
while [ "$#" -gt 0 ]; do
  case "$1" in
    --report) report=$2; shift 2 ;;
    --artifact-dir) artifacts=$2; shift 2 ;;
    --source-sha) source_sha=$2; shift 2 ;;
    *) shift ;;
  esac
done
job_dir=$(dirname "$report")
jobs_root=$(dirname "$job_dir")
touch "$job_dir.started"
attempt=0
while [ "$(find "$jobs_root" -maxdepth 1 -name '*.started' | wc -l | tr -d ' ')" -lt 2 ]; do
  attempt=$((attempt + 1))
  [ "$attempt" -lt 200 ] || exit 41
  sleep 0.01
done
mkdir "$artifacts/run-1"
printf packet >"$artifacts/run-1/traffic.pcap"
printf '{"schema_version":1,"classification":"raw_parallel","source_sha":"%s","manifest_digest":"sha256:parallel"}\n' "$source_sha" >"$report"
`
	if err := os.WriteFile(runner, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	staging := filepath.Join(root, "staging")
	if err := os.Mkdir(staging, 0o700); err != nil {
		t.Fatal(err)
	}
	manifest := &PerformanceManifest{Digest: "sha256:parallel", EligibleLaneCount: 2, Cells: []PerformanceCell{
		{ID: "short", DurationMinutes: 1}, {ID: "long", DurationMinutes: 2},
	}}
	request := collectRequest{ManifestPath: filepath.Join(root, "manifest.json"), RepositoryPath: root, FinalSHA: collectTestFinalSHA, RunnerExecutable: runner}
	jobs := []collectionJob{
		{ID: "short", CellIDs: []string{"short"}, RunnerTarget: "direct-clean-baseline"},
		{ID: "long", CellIDs: []string{"long"}, RunnerTarget: "direct-clean-baseline"},
	}
	records, err := runCollectionJobs(context.Background(), request, manifest, nil, jobs, staging)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 || records[0].ID != "short" || records[1].ID != "long" || records[0].Lane.Index == records[1].Lane.Index {
		t.Fatalf("parallel records lost input order or lane identity: %+v", records)
	}
}

func TestRunCollectionJobsCancelsSiblingLaneOnFailure(t *testing.T) {
	root := canonicalCollectTestRoot(t)
	runner := filepath.Join(root, "cancel-runner.sh")
	script := `#!/bin/sh
set -eu
while [ "$#" -gt 0 ]; do
  case "$1" in
    --report) report=$2; shift 2 ;;
    *) shift ;;
  esac
done
case "$report" in
  */fail/*) exit 42 ;;
  *) exec sleep 30 ;;
esac
`
	if err := os.WriteFile(runner, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	staging := filepath.Join(root, "staging")
	if err := os.Mkdir(staging, 0o700); err != nil {
		t.Fatal(err)
	}
	manifest := &PerformanceManifest{Digest: "sha256:cancel", EligibleLaneCount: 2, Cells: []PerformanceCell{
		{ID: "fail", DurationMinutes: 1}, {ID: "wait", DurationMinutes: 1},
	}}
	request := collectRequest{ManifestPath: filepath.Join(root, "manifest.json"), RepositoryPath: root, FinalSHA: collectTestFinalSHA, RunnerExecutable: runner}
	started := time.Now()
	_, err := runCollectionJobs(context.Background(), request, manifest, nil, []collectionJob{
		{ID: "fail", CellIDs: []string{"fail"}, RunnerTarget: "direct-clean-baseline"},
		{ID: "wait", CellIDs: []string{"wait"}, RunnerTarget: "direct-clean-baseline"},
	}, staging)
	if err == nil || time.Since(started) > 3*time.Second {
		t.Fatalf("sibling lane cancellation error=%v elapsed=%s", err, time.Since(started))
	}
}

func TestRunCollectionJobsUsesIndependentBaseAndCandidateBindings(t *testing.T) {
	root := canonicalCollectTestRoot(t)
	baseRoot := filepath.Join(root, "base")
	finalRoot := filepath.Join(root, "final")
	for _, directory := range []string{baseRoot, finalRoot} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	baseRunner := writeFakeCollectRunner(t, baseRoot, false)
	finalRunner := writeFakeCollectRunner(t, finalRoot, false)
	manifest := &PerformanceManifest{Digest: "sha256:collect-test-manifest"}
	t.Setenv("FAKE_MANIFEST_DIGEST", manifest.Digest)
	request := collectRequest{
		ManifestPath: filepath.Join(finalRoot, "manifest.json"), BaseManifestPath: filepath.Join(baseRoot, "manifest.json"),
		RepositoryPath: finalRoot, BaseRepositoryPath: baseRoot, FinalSHA: collectTestFinalSHA, BaseSHA: collectTestBaseSHA,
		RunnerExecutable: finalRunner, BaseRunnerExecutable: baseRunner,
	}
	staging := filepath.Join(root, "staging")
	if err := os.Mkdir(staging, 0o700); err != nil {
		t.Fatal(err)
	}
	jobs := []collectionJob{
		{ID: "clean-01-base", CellIDs: []string{"clean-01"}, RunnerTarget: "direct-clean-baseline", VariantID: "base", SourceRevision: collectionRevisionBase},
		{ID: "clean-01-candidate", CellIDs: []string{"clean-01"}, RunnerTarget: "direct-clean-baseline", VariantID: "candidate", SourceRevision: collectionRevisionFinal},
	}
	records, err := runCollectionJobs(context.Background(), request, manifest, nil, jobs, staging)
	if err != nil {
		t.Fatal(err)
	}
	for index, expected := range []struct {
		runner, repository, sourceSHA, variant string
	}{{baseRunner, baseRoot, collectTestBaseSHA, "base"}, {finalRunner, finalRoot, collectTestFinalSHA, "candidate"}} {
		record := records[index]
		if record.SourceSHA != expected.sourceSHA || record.VariantID != expected.variant || len(record.CommandSHA256) != 64 || len(record.RunnerExecutableSHA256) != 64 {
			t.Fatalf("record %d = %+v", index, record)
		}
		commandPath := filepath.Join(staging, record.Directory, "command.json")
		data, err := os.ReadFile(commandPath)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(data)
		if record.CommandSHA256 != hex.EncodeToString(digest[:]) {
			t.Fatalf("record %d command digest does not bind command.json", index)
		}
		var command struct {
			Executable string   `json:"executable"`
			Args       []string `json:"args"`
		}
		if err := json.Unmarshal(data, &command); err != nil {
			t.Fatal(err)
		}
		if command.Executable != expected.runner || !argumentHasPair(command.Args, "--source-root", expected.repository) ||
			!argumentHasPair(command.Args, "--source-sha", expected.sourceSHA) {
			t.Fatalf("record %d command = %+v", index, command)
		}
	}
}

func TestValidateRawCaseSuiteReportBindsExactRegistryAndArtifacts(t *testing.T) {
	reportPath, artifactDirectory, manifest, registry, job := writeRawCaseSuiteFixture(t)
	caseIDs, err := validateRawCaseSuiteReport(reportPath, artifactDirectory, collectTestFinalSHA, manifest.Digest, strings.Repeat("1", 64), job, registry)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(caseIDs, job.CaseIDs) {
		t.Fatalf("validated case IDs = %v, want %v", caseIDs, job.CaseIDs)
	}
}

func TestValidateRawCaseArtifactsAcceptsMultipleImmutableSourcesAndRejectsAttributionTampering(t *testing.T) {
	newFixture := func(t *testing.T) (string, string, rawCaseSuiteResult, PacketAttributionArtifact) {
		t.Helper()
		root := canonicalCollectTestRoot(t)
		artifactDirectory := filepath.Join(root, "artifacts")
		caseID := "CAP-DIRECT-QUIC-1000"
		caseDirectory := filepath.Join(artifactDirectory, strings.ToLower(caseID))
		rawDirectory := filepath.Join(caseDirectory, "raw")
		if err := os.MkdirAll(rawDirectory, 0o700); err != nil {
			t.Fatal(err)
		}
		result := rawCaseSuiteResult{ID: caseID, Profile: "capacity-direct-quic-1000", Status: "pass", CompletedOperations: 1000, ElapsedNanoseconds: 1}
		attribution := PacketAttributionArtifact{SchemaVersion: 1, Kind: "transport_qlog_attribution", Context: "case " + caseID}
		reference := time.Date(2026, 7, 25, 1, 2, 3, 0, time.UTC)
		for index, groupID := range []string{"0102030405060708", "1112131415161718"} {
			id := fmt.Sprintf("qlog-%03d", index+1)
			data := encodeRawQLOGSequence(reference, groupID, nil, []map[string]any{{
				"time": float64(index + 1), "name": "transport:packet_sent", "data": map[string]any{
					"header": map[string]any{"packet_type": "1RTT", "packet_number": index + 1},
					"frames": []any{map[string]any{"frame_type": "ping"}},
				},
			}})
			path := filepath.Join(rawDirectory, id+".sqlog")
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(data)
			result.RawSources = append(result.RawSources, rawProducedSource{
				ID: id, Kind: "qlog", Path: filepath.ToSlash(filepath.Join("artifacts", strings.ToLower(caseID), "raw", id+".sqlog")),
				SHA256: hex.EncodeToString(digest[:]), SizeBytes: int64(len(data)),
			})
			events, err := parseQLOGSequenceSource(data, id)
			if err != nil {
				t.Fatal(err)
			}
			event := events[0]
			packetNumber := uint64(index + 1)
			attribution.Records = append(attribution.Records, PacketAttributionRecord{
				Sequence: uint64(index + 1), SourceID: id, SourceSHA256: hex.EncodeToString(digest[:]), ByteOffset: event.recordOffset,
				ByteLength: event.recordLength, UnixNanoseconds: event.at.UnixNano(), Event: event.name, ConnectionGroupID: groupID,
				PacketNumberSpace: "1RTT", PacketNumber: &packetNumber,
			})
		}
		netlog := []byte(`{"constants":{},"events":[{"time":"1","type":1}]}` + "\n")
		netlogPath := filepath.Join(rawDirectory, "netlog-001.json")
		if err := os.WriteFile(netlogPath, netlog, 0o600); err != nil {
			t.Fatal(err)
		}
		netlogDigest := sha256.Sum256(netlog)
		result.RawSources = append(result.RawSources, rawProducedSource{
			ID: "netlog-001", Kind: "netlog", Path: filepath.ToSlash(filepath.Join("artifacts", strings.ToLower(caseID), "raw", "netlog-001.json")),
			SHA256: hex.EncodeToString(netlogDigest[:]), SizeBytes: int64(len(netlog)),
		})
		data, err := json.Marshal(attribution)
		if err != nil {
			t.Fatal(err)
		}
		data = append(data, '\n')
		path := filepath.Join(caseDirectory, "qlog.json")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(data)
		result.Artifacts = []rawProducedArtifact{{
			Kind: "qlog", Path: filepath.ToSlash(filepath.Join("artifacts", strings.ToLower(caseID), "qlog.json")),
			SHA256: hex.EncodeToString(digest[:]), SizeBytes: int64(len(data)),
		}}
		return root, artifactDirectory, result, attribution
	}
	rewriteAttribution := func(t *testing.T, root string, result *rawCaseSuiteResult, attribution PacketAttributionArtifact) {
		t.Helper()
		data, err := json.Marshal(attribution)
		if err != nil {
			t.Fatal(err)
		}
		data = append(data, '\n')
		path := filepath.Join(root, filepath.FromSlash(result.Artifacts[0].Path))
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(data)
		result.Artifacts[0].SHA256 = hex.EncodeToString(digest[:])
		result.Artifacts[0].SizeBytes = int64(len(data))
	}

	root, artifactDirectory, result, _ := newFixture(t)
	if err := validateRawCaseArtifacts(root, artifactDirectory, "normal", result, []string{"qlog"}); err != nil {
		t.Fatalf("valid multi-source attribution: %v", err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*rawCaseSuiteResult, *PacketAttributionArtifact)
	}{
		{name: "source ID", mutate: func(_ *rawCaseSuiteResult, artifact *PacketAttributionArtifact) {
			artifact.Records[0].SourceID = "qlog-002"
		}},
		{name: "source digest", mutate: func(_ *rawCaseSuiteResult, artifact *PacketAttributionArtifact) {
			artifact.Records[0].SourceSHA256 = strings.Repeat("0", 64)
		}},
		{name: "byte offset", mutate: func(_ *rawCaseSuiteResult, artifact *PacketAttributionArtifact) { artifact.Records[0].ByteOffset++ }},
		{name: "timestamp", mutate: func(_ *rawCaseSuiteResult, artifact *PacketAttributionArtifact) {
			artifact.Records[0].UnixNanoseconds++
		}},
		{name: "connection", mutate: func(_ *rawCaseSuiteResult, artifact *PacketAttributionArtifact) {
			artifact.Records[0].ConnectionGroupID = "ffffffffffffffff"
		}},
		{name: "packet number", mutate: func(_ *rawCaseSuiteResult, artifact *PacketAttributionArtifact) { *artifact.Records[0].PacketNumber++ }},
	} {
		t.Run(test.name, func(t *testing.T) {
			root, artifactDirectory, result, attribution := newFixture(t)
			test.mutate(&result, &attribution)
			rewriteAttribution(t, root, &result, attribution)
			if err := validateRawCaseArtifacts(root, artifactDirectory, "normal", result, []string{"qlog"}); err == nil {
				t.Fatal("tampered attribution passed validation")
			}
		})
	}
}

func TestValidateAttributedQLOGStreamOpenedRequiresFirstRawStreamFrame(t *testing.T) {
	reference := time.Date(2026, 7, 25, 1, 2, 3, 0, time.UTC)
	data := encodeRawQLOGSequence(reference, "0102030405060708", nil, []map[string]any{
		{"time": 1.0, "name": "transport:packet_received", "data": map[string]any{
			"header": map[string]any{"packet_type": "1RTT", "packet_number": 1},
			"frames": []any{map[string]any{"frame_type": "stream", "stream_id": 12}},
		}},
		{"time": 2.0, "name": "transport:packet_received", "data": map[string]any{
			"header": map[string]any{"packet_type": "1RTT", "packet_number": 2},
			"frames": []any{map[string]any{"frame_type": "stream", "stream_id": 12}},
		}},
	})
	events, err := parseQLOGSequenceSource(data, "qlog-001")
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	source := validatedRawSource{id: "qlog-001", kind: "qlog", digest: hex.EncodeToString(digest[:]), data: data}
	streamID := uint64(12)
	packetNumber := uint64(1)
	record := PacketAttributionRecord{
		Sequence: 1, SourceID: source.id, SourceSHA256: source.digest,
		ByteOffset: events[0].recordOffset, ByteLength: events[0].recordLength, UnixNanoseconds: events[0].at.UnixNano(),
		Event: "transport:stream_opened", ConnectionGroupID: events[0].groupID,
		PacketNumberSpace: "1RTT", PacketNumber: &packetNumber, NativeStreamID: &streamID,
	}
	if err := validateAttributedQLOGRecord(source, record); err != nil {
		t.Fatal(err)
	}
	packetNumber = 2
	record.ByteOffset, record.ByteLength, record.UnixNanoseconds = events[1].recordOffset, events[1].recordLength, events[1].at.UnixNano()
	if err := validateAttributedQLOGRecord(source, record); err == nil {
		t.Fatal("retransmitted STREAM frame was accepted as STREAM_OPENED")
	}
}

func TestValidateRawCaseSuiteReportRejectsMissingExtraAndMismatchedClaims(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*rawCaseSuiteReport)
	}{
		{name: "missing", mutate: func(report *rawCaseSuiteReport) { report.Results = report.Results[:1] }},
		{name: "extra", mutate: func(report *rawCaseSuiteReport) { report.Results = append(report.Results, report.Results[0]) }},
		{name: "owner", mutate: func(report *rawCaseSuiteReport) { report.Owner = "wrong-owner" }},
		{name: "profile", mutate: func(report *rawCaseSuiteReport) { report.Results[0].Profile = "wrong-profile" }},
		{name: "digest", mutate: func(report *rawCaseSuiteReport) { report.Results[0].Artifacts[0].SHA256 = strings.Repeat("0", 64) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reportPath, artifactDirectory, manifest, registry, job := writeRawCaseSuiteFixture(t)
			data, err := os.ReadFile(reportPath)
			if err != nil {
				t.Fatal(err)
			}
			var report rawCaseSuiteReport
			if err := json.Unmarshal(data, &report); err != nil {
				t.Fatal(err)
			}
			test.mutate(&report)
			data, err = json.Marshal(report)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(reportPath, append(data, '\n'), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := validateRawCaseSuiteReport(reportPath, artifactDirectory, collectTestFinalSHA, manifest.Digest, strings.Repeat("1", 64), job, registry); err == nil {
				t.Fatal("accepted mismatched case suite report")
			}
		})
	}
}

func TestExecuteCollectionRetainsFailedStagingAndPublishesNothing(t *testing.T) {
	root := canonicalCollectTestRoot(t)
	artifactDirectory := filepath.Join(root, "bundle")
	if err := os.Mkdir(artifactDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	runner := writeFakeCollectRunner(t, root, true)
	reportPath := filepath.Join(artifactDirectory, "report.unsigned.json")
	environment := &collectEnvironment{
		request: collectRequest{
			ManifestPath: filepath.Join(root, "manifest.json"), RepositoryPath: root,
			FinalSHA: collectTestFinalSHA, RunnerExecutable: runner,
			ArtifactDirectory: artifactDirectory, ReportPath: reportPath,
		},
		manifest: &PerformanceManifest{Digest: "sha256:collect-test-manifest"},
	}
	plan := collectionPlan{Target: "bench-transport-ab", Jobs: []collectionJob{{
		ID: "clean-direct-baseline", CellIDs: []string{"clean-02", "clean-03"}, RunnerTarget: "direct-clean-baseline",
	}}}
	t.Setenv("FAKE_MANIFEST_DIGEST", environment.manifest.Digest)
	if err := executeCollection(context.Background(), environment, plan); err == nil || !strings.Contains(err.Error(), "failed") {
		t.Fatalf("executeCollection() error=%v, want low-level failure", err)
	}
	if _, err := os.Lstat(reportPath); !os.IsNotExist(err) {
		t.Fatalf("failed collection published report: %v", err)
	}
	for _, path := range []string{
		filepath.Join(artifactDirectory, "jobs", "clean-direct-baseline", "command.json"),
		filepath.Join(artifactDirectory, "jobs", "clean-direct-baseline", "stdout.log"),
		filepath.Join(artifactDirectory, "jobs", "clean-direct-baseline", "stderr.log"),
		filepath.Join(artifactDirectory, "jobs", "clean-direct-baseline", "cell.json"),
		filepath.Join(artifactDirectory, "jobs", "clean-direct-baseline", "artifacts", "run-1", "traffic.pcap"),
	} {
		if info, err := os.Stat(path); err != nil || !info.Mode().IsRegular() {
			t.Fatalf("failed collection did not preserve diagnostic file %s: info=%v err=%v", path, info, err)
		}
	}
}

func TestExecuteCollectionPublishesIndexAfterStableJobArtifacts(t *testing.T) {
	root := canonicalCollectTestRoot(t)
	repository := filepath.Join(root, "repository")
	if err := os.Mkdir(repository, 0o700); err != nil {
		t.Fatal(err)
	}
	artifactDirectory := filepath.Join(root, "bundle")
	if err := os.Mkdir(artifactDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	runner := writeFakeCollectRunner(t, repository, false)
	regularInput := filepath.Join(repository, "input")
	if err := os.WriteFile(regularInput, []byte("input\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"init", "-q"}, {"add", "."}, {"-c", "user.name=Test", "-c", "user.email=test@example.com", "commit", "-qm", "test inputs"}} {
		runGitTestCommand(t, repository, args...)
	}
	sourceSHA := gitTestOutput(t, repository, "rev-parse", "HEAD")
	reportPath := filepath.Join(artifactDirectory, "report.unsigned.json")
	manifest := &PerformanceManifest{Digest: "sha256:collect-test-manifest"}
	t.Setenv("FAKE_FINAL_SHA", collectTestFinalSHA)
	t.Setenv("FAKE_MANIFEST_DIGEST", manifest.Digest)
	_, regularDigest, err := snapshotRegularFile(regularInput, false)
	if err != nil {
		t.Fatal(err)
	}
	_, executableDigest, err := snapshotRegularFile(runner, true)
	if err != nil {
		t.Fatal(err)
	}
	environment := &collectEnvironment{
		request: collectRequest{
			ManifestPath: regularInput, BaseManifestPath: regularInput, RegistryPath: regularInput,
			RepositoryPath: repository, BaseRepositoryPath: repository,
			BaseSHA: sourceSHA, FinalSHA: sourceSHA,
			RunnerExecutable: runner, BaseRunnerExecutable: runner,
			RunnerWrapper: runner, BPFObject: regularInput, HostBPFTool: runner,
			TrustPolicyPath: regularInput, EffectiveConfigPath: regularInput,
			ArtifactDirectory: artifactDirectory, ReportPath: reportPath,
		},
		manifest: manifest,
		inputDigests: map[string]string{
			"manifest": regularDigest, "base_manifest": regularDigest, "registry": regularDigest,
			"runner_executable": executableDigest, "base_runner_executable": executableDigest, "runner_wrapper": executableDigest,
			"bpf_object": regularDigest, "host_bpftool": executableDigest,
			"trust_policy": regularDigest, "effective_config": regularDigest,
		},
	}
	plan := collectionPlan{Target: "bench-transport-ab", Jobs: []collectionJob{{
		ID: "clean-direct-baseline", CellIDs: []string{"clean-02", "clean-03"}, RunnerTarget: "direct-clean-baseline",
	}}}
	if err := executeCollection(context.Background(), environment, plan); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(artifactDirectory, "jobs", "clean-direct-baseline", "artifacts", "run-1", "traffic.pcap")); err != nil {
		t.Fatalf("published collection lost stable job artifacts: %v", err)
	}
	data, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	var index rawCollectionIndex
	if err := json.Unmarshal(data, &index); err != nil {
		t.Fatal(err)
	}
	if index.Classification != "raw_transport_collection" || len(index.Jobs) != 1 || index.Jobs[0].Directory != "jobs/clean-direct-baseline" {
		t.Fatalf("published raw collection index is incomplete: %+v", index)
	}
}

func TestFreshCollectionOutputRejectsAliasesAndExistingContent(t *testing.T) {
	root := canonicalCollectTestRoot(t)
	bundle := filepath.Join(root, "bundle")
	if err := os.Mkdir(bundle, 0o700); err != nil {
		t.Fatal(err)
	}
	report := filepath.Join(bundle, "raw.json")
	if _, _, err := validateFreshCollectionOutput(report, bundle); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundle, "existing"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := validateFreshCollectionOutput(report, bundle); err == nil {
		t.Fatal("accepted non-empty artifact directory")
	}
	alias := filepath.Join(root, "bundle-link")
	if err := os.Symlink(bundle, alias); err != nil {
		t.Fatal(err)
	}
	if _, _, err := validateFreshCollectionOutput(filepath.Join(alias, "raw.json"), alias); err == nil {
		t.Fatal("accepted symlink artifact directory")
	}
}

func TestCollectionOutputIdentityRejectsPathReplacement(t *testing.T) {
	root := canonicalCollectTestRoot(t)
	bundle := filepath.Join(root, "bundle")
	if err := os.Mkdir(bundle, 0o700); err != nil {
		t.Fatal(err)
	}
	identity, err := pinCollectionDirectory(bundle)
	if err != nil {
		t.Fatal(err)
	}
	defer identity.Close()
	if err := os.Rename(bundle, filepath.Join(root, "original-bundle")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(bundle, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := identity.Verify(); err == nil {
		t.Fatal("accepted a replacement at the pinned collection output path")
	}
}

func writeFakeCollectRunner(t *testing.T, root string, fail bool) string {
	t.Helper()
	path := filepath.Join(root, "fake-runner.sh")
	exit := "0"
	if fail {
		exit = "9"
	}
	script := `#!/bin/sh
set -eu
report=
artifacts=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --report) report=$2; shift 2 ;;
    --artifact-dir) artifacts=$2; shift 2 ;;
    --source-sha) source_sha=$2; shift 2 ;;
    *) shift ;;
  esac
done
test -n "$report"
test -d "$artifacts"
test -z "$(find "$artifacts" -mindepth 1 -maxdepth 1 -print -quit)"
mkdir "$artifacts/run-1"
printf 'real packet bytes' >"$artifacts/run-1/traffic.pcap"
printf '{"schema_version":1,"classification":"raw_fake_runner_output","source_sha":"%s","manifest_digest":"%s"}\n' "$source_sha" "$FAKE_MANIFEST_DIGEST" >"$report"
printf 'fake runner stdout\n'
printf 'fake runner stderr\n' >&2
exit ` + exit + "\n"
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func argumentHasPair(args []string, name, value string) bool {
	for index := 0; index+1 < len(args); index++ {
		if args[index] == name && args[index+1] == value {
			return true
		}
	}
	return false
}

func writeRawCaseSuiteFixture(t *testing.T) (string, string, *PerformanceManifest, *CaseRegistry, collectionJob) {
	t.Helper()
	root := canonicalCollectTestRoot(t)
	artifactDirectory := filepath.Join(root, "artifacts")
	if err := os.Mkdir(artifactDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	manifest := &PerformanceManifest{Digest: "sha256:collect-test-manifest"}
	registry := loadFixtureRegistry(t)
	job := collectionJob{
		ID: "case-normal-transport-conformance-smoke", RunnerTarget: "release-case-suite",
		CaseOwner: "transport-conformance-smoke", CaseMode: "normal", CaseIDs: []string{"CS-C1", "CS-C2"},
	}
	definitions := make(map[string]CaseDefinition, len(registry.Cases))
	for _, definition := range registry.Cases {
		definitions[definition.ID] = definition
	}
	report := rawCaseSuiteReport{
		SchemaVersion: 1, Classification: "linux_transport_case_suite", SourceSHA: collectTestFinalSHA,
		ManifestDigest: manifest.Digest, ManifestSHA256: strings.Repeat("1", 64), Runner: map[string]any{"os": "linux"},
		Owner: job.CaseOwner, Mode: job.CaseMode, StartedAt: "2026-07-25T00:00:00Z", FinishedAt: "2026-07-25T00:00:01Z",
	}
	for _, id := range job.CaseIDs {
		definition := definitions[id]
		result := rawCaseSuiteResult{ID: id, Profile: definition.Profile, Status: "pass", CompletedOperations: 1, ElapsedNanoseconds: 1}
		caseDirectory := filepath.Join(artifactDirectory, strings.ToLower(id))
		if err := os.Mkdir(caseDirectory, 0o700); err != nil {
			t.Fatal(err)
		}
		for _, kind := range definition.EvidenceFields {
			data := []byte(`{"schema_version":1,"kind":"` + kind + `"}` + "\n")
			path := filepath.Join(caseDirectory, kind+".json")
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(data)
			result.Artifacts = append(result.Artifacts, rawProducedArtifact{
				Kind: kind, Path: filepath.ToSlash(filepath.Join("artifacts", strings.ToLower(id), kind+".json")),
				SHA256: hex.EncodeToString(digest[:]), SizeBytes: int64(len(data)),
			})
		}
		report.Results = append(report.Results, result)
	}
	reportPath := filepath.Join(root, "cell.json")
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(reportPath, append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	return reportPath, artifactDirectory, manifest, registry, job
}

func canonicalCollectTestRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return root
}
