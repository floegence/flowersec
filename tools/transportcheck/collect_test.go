package main

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const collectTestFinalSHA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

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

func TestBuildCollectionPlanFailsClosedOnEveryCurrentReleaseTarget(t *testing.T) {
	manifest := loadFixtureManifest(t)
	registry := loadFixtureRegistry(t)
	for target := range collectTargets {
		plan, err := buildCollectionPlan(target, manifest, registry)
		if err != nil {
			t.Fatalf("%s: %v", target, err)
		}
		if len(plan.Missing) == 0 {
			t.Fatalf("%s unexpectedly has complete producer coverage", target)
		}
	}
	abPlan, err := buildCollectionPlan("bench-transport-ab", manifest, registry)
	if err != nil {
		t.Fatal(err)
	}
	if len(abPlan.Jobs) != 22 || len(abPlan.Missing) != 7 {
		t.Fatalf("A/B plan jobs=%d missing=%v", len(abPlan.Jobs), abPlan.Missing)
	}
	for _, want := range []string{
		"cell adaptive-selection-01 (adaptive_native)",
		"cell clean-01 (direct_wss_revision)",
		"cell clean-04 (ww)",
	} {
		if !slices.Contains(abPlan.Missing, want) {
			t.Fatalf("A/B plan does not report %q: %v", want, abPlan.Missing)
		}
	}
	allPlan, err := buildCollectionPlan("all", manifest, registry)
	if err != nil {
		t.Fatal(err)
	}
	if len(allPlan.Jobs) != len(abPlan.Jobs) || len(allPlan.Missing) <= len(abPlan.Missing) {
		t.Fatalf("all plan does not include performance jobs plus case gaps: jobs=%d missing=%d", len(allPlan.Jobs), len(allPlan.Missing))
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
	records, err := runCollectionJobs(context.Background(), request, manifest, jobs, staging)
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

func TestExecuteCollectionRemovesFailedStagingAndPublishesNothing(t *testing.T) {
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
	if err := executeCollection(context.Background(), environment, plan); err == nil || !strings.Contains(err.Error(), "failed") {
		t.Fatalf("executeCollection() error=%v, want low-level failure", err)
	}
	if _, err := os.Lstat(reportPath); !os.IsNotExist(err) {
		t.Fatalf("failed collection published report: %v", err)
	}
	entries, err := os.ReadDir(artifactDirectory)
	if err != nil || len(entries) != 0 {
		t.Fatalf("failed collection published artifacts: entries=%v err=%v", entries, err)
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
			ManifestPath: regularInput, RegistryPath: regularInput, RepositoryPath: repository,
			FinalSHA: collectTestFinalSHA, RunnerExecutable: runner,
			RunnerWrapper: runner, BPFObject: regularInput, HostBPFTool: runner,
			TrustPolicyPath: regularInput, EffectiveConfigPath: regularInput,
			ArtifactDirectory: artifactDirectory, ReportPath: reportPath,
		},
		manifest: manifest,
		inputDigests: map[string]string{
			"manifest": regularDigest, "registry": regularDigest,
			"runner_executable": executableDigest, "runner_wrapper": executableDigest,
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
    *) shift ;;
  esac
done
test -n "$report"
test -d "$artifacts"
test -z "$(find "$artifacts" -mindepth 1 -maxdepth 1 -print -quit)"
mkdir "$artifacts/run-1"
printf 'real packet bytes' >"$artifacts/run-1/traffic.pcap"
printf '{"schema_version":1,"classification":"raw_fake_runner_output","source_sha":"%s","manifest_digest":"%s"}\n' "$FAKE_FINAL_SHA" "$FAKE_MANIFEST_DIGEST" >"$report"
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

func canonicalCollectTestRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return root
}
