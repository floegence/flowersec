package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/artifactv2"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/protocolv2"
	flowersession "github.com/floegence/flowersec/flowersec-go/v2/internal/session"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/transportrelease"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/transportrelease/linuxnetlab"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/transportrelease/tunnelworkload"
)

func TestWorkloadScheduleContainsEveryIndependentRun(t *testing.T) {
	schedule := workloadSchedule(15)
	if len(schedule) != 3 {
		t.Fatalf("cell count = %d, want 3", len(schedule))
	}
	counts := map[carrier.Kind]int{}
	for _, cell := range schedule {
		counts[cell.Carrier] += len(cell.Runs)
		for index, run := range cell.Runs {
			if run != index+1 {
				t.Fatalf("invalid scheduled cell %+v", cell)
			}
		}
	}
	for _, kind := range []carrier.Kind{carrier.KindWebSocket, carrier.KindQUIC, carrier.KindWebTransport} {
		if counts[kind] != 15 {
			t.Fatalf("%s run count = %d, want 15", kind, counts[kind])
		}
	}
}

func TestForcedProfileRunShardsPreserveFifteenIndependentRuns(t *testing.T) {
	want := [][]int{
		{1, 2, 3},
		{4, 5, 6},
		{7, 8, 9},
		{10, 11, 12},
		{13, 14, 15},
	}
	if got := forcedProfileRunShards(15); !reflect.DeepEqual(got, want) {
		t.Fatalf("forced profile run shards = %v, want %v", got, want)
	}
}

func TestForcedProfileRunShardSelectsOneBoundedInvocation(t *testing.T) {
	want := [][]int{
		{1, 2, 3},
		{4, 5, 6},
		{7, 8, 9},
		{10, 11, 12},
		{13, 14, 15},
	}
	for index, expected := range want {
		got, err := forcedProfileRunShard(15, index+1)
		if err != nil {
			t.Fatalf("shard %d: %v", index+1, err)
		}
		if !reflect.DeepEqual(got, expected) {
			t.Fatalf("shard %d runs = %v, want %v", index+1, got, expected)
		}
	}
	for _, index := range []int{0, 6} {
		if _, err := forcedProfileRunShard(15, index); err == nil {
			t.Fatalf("shard %d unexpectedly accepted", index)
		}
	}
	var ran []int
	if err := runSelectedForcedProfileShard(context.Background(), 15, 3, time.Second, func(_ context.Context, run int) error {
		ran = append(ran, run)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(ran, []int{7, 8, 9}) {
		t.Fatalf("selected shard runs = %v, want [7 8 9]", ran)
	}
}

func TestMergeBrowserCellShardReportsRequiresCompleteArtifactBoundRunSet(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	reports := make([]browserCellReport, 0, 5)
	for shardIndex, runs := range forcedProfileRunShards(15) {
		report := browserCellReport{
			SchemaVersion: 1, Classification: "linux_chromium_webtransport_profile",
			SourceSHA: strings.Repeat("a", 40), ManifestDigest: "sha256:manifest", ManifestSHA256: strings.Repeat("b", 64),
			Runner:    baselineRunner{OS: "linux", Architecture: "amd64", KernelRelease: "test"},
			ProfileID: "edge-v1", Topology: "browser_webtransport", BPFObjectSHA256: strings.Repeat("c", 64),
			StartedAt: time.Unix(int64(100+shardIndex), 0).UTC(), FinishedAt: time.Unix(int64(200+shardIndex), 0).UTC(),
			ShardIndex: shardIndex + 1, ShardCount: 5,
		}
		for _, run := range runs {
			path := filepath.Join("artifacts", fmt.Sprintf("run-%03d.pcap", run))
			value := append([]byte{0xd4, 0xc3, 0xb2, 0xa1}, make([]byte, 21)...)
			value = append(value, []byte(fmt.Sprintf("run-%03d", run))...)
			if err := os.MkdirAll(filepath.Join(root, "artifacts"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, path), value, 0o600); err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(value)
			report.Results = append(report.Results, browserCellResult{
				Run: run, Workload: json.RawMessage(fmt.Sprintf(`{"schema_version":1,"topology":"browser_webtransport","profile_id":"edge-v1","run_number":%d,"status":"passed"}`, run)),
				Artifacts: []releaseArtifact{{Kind: "classic-pcap", Path: filepath.ToSlash(path), SHA256: hex.EncodeToString(digest[:]), SizeBytes: int64(len(value))}},
			})
		}
		reports = append(reports, report)
	}

	merged, err := mergeBrowserCellShardReports(reports, 15)
	if err != nil {
		t.Fatal(err)
	}
	if merged.ShardIndex != 0 || merged.ShardCount != 0 || len(merged.Results) != 15 {
		t.Fatalf("merged report = shard %d/%d results=%d", merged.ShardIndex, merged.ShardCount, len(merged.Results))
	}
	for index, result := range merged.Results {
		if result.Run != index+1 {
			t.Fatalf("merged run order = %+v", merged.Results)
		}
	}
	if err := verifyBrowserCellReportArtifacts(root, merged); err != nil {
		t.Fatal(err)
	}
	for _, report := range reports {
		value, err := json.Marshal(report)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(root, fmt.Sprintf("shard-%02d.json", report.ShardIndex))
		if err := os.WriteFile(path, value, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var manifestSum [32]byte
	for index := range manifestSum {
		manifestSum[index] = 0xbb
	}
	shardPaths := make([]string, 0, len(reports))
	for index := 1; index <= len(reports); index++ {
		shardPaths = append(shardPaths, filepath.Join(root, fmt.Sprintf("shard-%02d.json", index)))
	}
	if err := mergeBrowserCellShardReportFiles(
		root, filepath.Join(root, "cell.json"), shardPaths,
		strings.Repeat("a", 40), "edge-v1", "browser_webtransport",
		transportrelease.ReleasePlan{RunCount: 15, Edge: transportrelease.ProfilePlan{ID: "edge-v1"}},
		transportrelease.ManifestBinding{Digest: "sha256:manifest", SHA256Sum: manifestSum},
	); err != nil {
		t.Fatal(err)
	}
	finalValue, err := os.ReadFile(filepath.Join(root, "cell.json"))
	if err != nil {
		t.Fatal(err)
	}
	var finalReport browserCellReport
	if err := json.Unmarshal(finalValue, &finalReport); err != nil || len(finalReport.Results) != 15 || finalReport.ShardIndex != 0 || finalReport.ShardCount != 0 {
		t.Fatalf("final report contract is invalid: results=%d shard=%d/%d err=%v", len(finalReport.Results), finalReport.ShardIndex, finalReport.ShardCount, err)
	}

	incomplete := append([]browserCellReport(nil), reports...)
	incomplete[4].Results = incomplete[4].Results[:2]
	if _, err := mergeBrowserCellShardReports(incomplete, 15); err == nil {
		t.Fatal("merge accepted a missing run")
	}
	if err := os.WriteFile(filepath.Join(root, "artifacts", "run-015.pcap"), []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyBrowserCellReportArtifacts(root, merged); err == nil {
		t.Fatal("artifact verification accepted tampering")
	}
}

func TestRunForcedProfileShardsUsesFiveSequentialWatchdogContexts(t *testing.T) {
	var runs []int
	var contexts []context.Context
	err := runForcedProfileShards(context.Background(), 15, 5*time.Minute, func(ctx context.Context, run int) error {
		runs = append(runs, run)
		contexts = append(contexts, ctx)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for index, run := range runs {
		if run != index+1 {
			t.Fatalf("run order = %v, want 1..15", runs)
		}
		if index%forcedProfileRunsPerShard != 0 && contexts[index] != contexts[index-1] {
			t.Fatalf("run %d unexpectedly changed shard context", run)
		}
		if index >= forcedProfileRunsPerShard && index%forcedProfileRunsPerShard == 0 && contexts[index] == contexts[index-1] {
			t.Fatalf("run %d reused the preceding shard context", run)
		}
	}
}

func TestNetworkWorkerCommandPreservesBPFMountNamespace(t *testing.T) {
	command := networkWorkerCommand(context.Background(), "fc-1234", "/release/runner")
	want := []string{"/usr/bin/nsenter", "--net=/var/run/netns/fc-1234", "--", "/release/runner", networkWorkerArg}
	if command.Path != want[0] || strings.Join(command.Args, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("network worker command = path %q args %v, want %v", command.Path, command.Args, want)
	}
}

func TestSupportedLinuxRunnerArchitecture(t *testing.T) {
	tests := []struct {
		name   string
		goos   string
		goarch string
		want   bool
	}{
		{name: "amd64", goos: "linux", goarch: "amd64", want: true},
		{name: "arm64", goos: "linux", goarch: "arm64", want: true},
		{name: "unsupported Linux architecture", goos: "linux", goarch: "386"},
		{name: "non-Linux", goos: "darwin", goarch: "arm64"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := supportedLinuxRunnerArchitecture(test.goos, test.goarch); got != test.want {
				t.Fatalf("supportedLinuxRunnerArchitecture(%q, %q) = %t, want %t", test.goos, test.goarch, got, test.want)
			}
		})
	}
}

func TestTunnelProfileAllowsOnlyCleanWithoutBPF(t *testing.T) {
	plan := transportrelease.ReleasePlan{
		Clean:  transportrelease.ProfilePlan{ID: "clean-v1"},
		Mobile: transportrelease.ProfilePlan{ID: "mobile-v1"},
		Edge:   transportrelease.ProfilePlan{ID: "edge-v1"},
	}
	tests := []struct {
		name      string
		profileID string
		bpfObject string
		wantID    string
		wantError bool
	}{
		{name: "clean", profileID: "clean-v1", wantID: "clean-v1"},
		{name: "clean rejects BPF", profileID: "clean-v1", bpfObject: "/fault.o", wantError: true},
		{name: "mobile requires BPF", profileID: "mobile-v1", wantError: true},
		{name: "mobile", profileID: "mobile-v1", bpfObject: "/fault.o", wantID: "mobile-v1"},
		{name: "edge requires BPF", profileID: "edge-v1", wantError: true},
		{name: "edge", profileID: "edge-v1", bpfObject: "/fault.o", wantID: "edge-v1"},
		{name: "unknown", profileID: "other", wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			profile, err := tunnelProfile(plan, test.profileID, test.bpfObject)
			if (err != nil) != test.wantError {
				t.Fatalf("error = %v, want error %t", err, test.wantError)
			}
			if err == nil && profile.ID != test.wantID {
				t.Fatalf("profile = %q, want %q", profile.ID, test.wantID)
			}
		})
	}
}

func TestAdaptiveCandidatesForTopologyMatchesFrozenManifest(t *testing.T) {
	for _, test := range []struct {
		topology string
		want     []transportrelease.AdaptiveCandidate
	}{
		{topology: adaptiveNativeTopology, want: []transportrelease.AdaptiveCandidate{{ID: "runtime-wss", Kind: carrier.KindWebSocket}, {ID: "runtime-raw-quic", Kind: carrier.KindQUIC}}},
		{topology: adaptiveWebTopology, want: []transportrelease.AdaptiveCandidate{{ID: "runtime-wss", Kind: carrier.KindWebSocket}, {ID: "runtime-webtransport", Kind: carrier.KindWebTransport}}},
	} {
		got, err := adaptiveCandidatesForTopology(test.topology)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != len(test.want) {
			t.Fatalf("%s candidates = %+v", test.topology, got)
		}
		for index := range got {
			if got[index] != test.want[index] {
				t.Fatalf("%s candidate %d = %+v, want %+v", test.topology, index, got[index], test.want[index])
			}
		}
	}
	if candidates, err := adaptiveCandidatesForTopology("other"); err == nil || candidates != nil {
		t.Fatal("accepted an unknown adaptive topology")
	}
}

func TestVerifySourceCheckoutBindsCleanHeadAndManifest(t *testing.T) {
	root := t.TempDir()
	runGit(t, root, "init", "-q")
	runGit(t, root, "config", "user.email", "runner@example.invalid")
	runGit(t, root, "config", "user.name", "Runner Test")
	manifest := filepath.Join(root, "testdata", "transport_v2", "performance_manifest.json")
	if err := os.MkdirAll(filepath.Dir(manifest), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifest, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runGit(t, root, "add", ".")
	runGit(t, root, "commit", "-q", "-m", "test")
	head := runGit(t, root, "rev-parse", "HEAD")
	if err := verifySourceCheckout(root, manifest, head); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "dirty"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifySourceCheckout(root, manifest, head); err == nil {
		t.Fatal("accepted dirty source checkout")
	}
}

func TestValidateArtifactDirectoryRequiresEmptyCanonicalSibling(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	artifactDir := filepath.Join(root, "artifacts")
	if err := os.Mkdir(artifactDir, 0o700); err != nil {
		t.Fatal(err)
	}
	reportPath := filepath.Join(root, "cell.json")
	destination, err := newArtifactDestination(artifactDir, reportPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := destination.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(artifactDir, "occupied"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if destination, err := newArtifactDestination(artifactDir, reportPath); err == nil {
		_ = destination.Close()
		t.Fatal("accepted a non-empty artifact directory")
	}
	if err := os.Remove(filepath.Join(artifactDir, "occupied")); err != nil {
		t.Fatal(err)
	}
	if destination, err := newArtifactDestination(artifactDir, filepath.Join(artifactDir, "cell.json")); err == nil {
		_ = destination.Close()
		t.Fatal("accepted a report inside the artifact directory")
	}
	symlink := filepath.Join(root, "artifact-link")
	if err := os.Symlink(artifactDir, symlink); err != nil {
		t.Fatal(err)
	}
	if destination, err := newArtifactDestination(symlink, reportPath); err == nil {
		_ = destination.Close()
		t.Fatal("accepted a symlinked artifact directory")
	}
}

func TestPacketCaptureLifecycleBindsPcapDigest(t *testing.T) {
	previous := packetCaptureCommand
	packetCaptureCommand = func(ctx context.Context, _, _, outputPath string) *exec.Cmd {
		return exec.CommandContext(ctx, "sh", "-c", `trap 'exit 0' INT TERM; printf '\324\303\262\24101234567890123456789x' > "$1"; while :; do :; done`, "capture", outputPath)
	}
	t.Cleanup(func() { packetCaptureCommand = previous })
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	artifactDir := filepath.Join(root, "artifacts")
	if err := os.Mkdir(artifactDir, 0o700); err != nil {
		t.Fatal(err)
	}
	destination, err := newArtifactDestination(artifactDir, filepath.Join(root, "cell.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer destination.Close()
	evidence, err := startRunEvidence(context.Background(), destination, "clean-wss-run-001", "", "lo")
	if err != nil {
		t.Fatal(err)
	}
	artifacts, err := evidence.Finish()
	if err != nil {
		t.Fatal(err)
	}
	if len(artifacts) != 1 || artifacts[0].Kind != "classic-pcap" || artifacts[0].SizeBytes != 25 ||
		artifacts[0].Path != "artifacts/clean-wss-run-001/traffic.pcap" || len(artifacts[0].SHA256) != 64 {
		t.Fatalf("unexpected capture artifacts: %+v", artifacts)
	}
}

func TestArtifactDestinationRejectsPathReplacement(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	artifactDir := filepath.Join(root, "artifacts")
	if err := os.Mkdir(artifactDir, 0o700); err != nil {
		t.Fatal(err)
	}
	destination, err := newArtifactDestination(artifactDir, filepath.Join(root, "cell.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer destination.Close()
	if err := os.Rename(artifactDir, filepath.Join(root, "original-artifacts")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(artifactDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := destination.Verify(); err == nil {
		t.Fatal("accepted a replacement at the pinned artifact path")
	}
}

func runGit(t *testing.T, root string, args ...string) string {
	t.Helper()
	commandArgs := append([]string{"-C", root}, args...)
	command := exec.Command("git", commandArgs...)
	command.Env = make([]string, 0, len(os.Environ()))
	for _, item := range os.Environ() {
		if !strings.HasPrefix(item, "GIT_") {
			command.Env = append(command.Env, item)
		}
	}
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v: %s", strings.Join(args, " "), err, output)
	}
	return strings.TrimSpace(string(output))
}

func TestCompletedWithinRejectsExpiredContext(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if err := completedWithin(ctx, time.Now().Add(-time.Second), 2*time.Second); err == nil {
		t.Fatal("accepted completion after context deadline")
	}
}

func TestCompletedWithinRejectsElapsedLimit(t *testing.T) {
	if err := completedWithin(context.Background(), time.Now().Add(-2*time.Second), time.Second); err == nil {
		t.Fatal("accepted completion after explicit phase limit")
	}
}

func TestBrowserCollectorPlanKeepsModuleSiteOnClientSide(t *testing.T) {
	var request browserWorkerRequest
	if err := json.Unmarshal([]byte(`{
		"client_namespace":"client-netns",
		"client_address":"198.18.13.41",
		"server_namespace":"server-netns",
		"server_address":"198.18.13.42"
	}`), &request); err != nil {
		t.Fatal(err)
	}
	plan := newBrowserCollectorPlan(request, "http://198.18.13.42:443/artifacts", "certificate-hash")
	if plan.ModuleBindAddress != "198.18.13.41" || plan.ModuleAdvertiseHost != "198.18.13.41" {
		t.Fatalf("module site = %s/%s, want client address", plan.ModuleBindAddress, plan.ModuleAdvertiseHost)
	}
	if plan.ArtifactSourceURL != "http://198.18.13.42:443/artifacts" {
		t.Fatalf("artifact source URL = %q, want server-side weak-network endpoint", plan.ArtifactSourceURL)
	}
}

func TestBrowserCollectorPlanBindsMeasuredEdgeRecoveryBudget(t *testing.T) {
	plan, _, err := transportrelease.LoadReleasePlan("../../../../testdata/transport_v2/performance_manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	request := browserWorkerRequest{Plan: plan.Edge}
	got := newBrowserCollectorPlan(request, "http://198.18.13.42:443/artifacts", "certificate-hash")
	if got.Bulk.PhaseDeadlineMS != 27_000 {
		t.Fatalf("edge browser bulk timeout = %dms, want 27000ms", got.Bulk.PhaseDeadlineMS)
	}
}

func TestBrowserWorkerRequestUsesUnprefixedClientAddressAndOrigin(t *testing.T) {
	request := newBrowserWorkerRequest(
		transportrelease.ProfilePlan{ID: "edge-v1"},
		browserDirectTopology,
		3,
		linuxnetlab.Config{
			ClientNamespace: "client-netns",
			ServerNamespace: "server-netns",
			ClientAddress:   netip.MustParsePrefix("198.18.13.41/30"),
			ServerAddress:   netip.MustParsePrefix("198.18.13.42/30"),
		},
		"/source",
	)
	if request.ClientAddress != "198.18.13.41" || request.ServerAddress != "198.18.13.42" {
		t.Fatalf("worker addresses = %q/%q, want unprefixed client/server IPs", request.ClientAddress, request.ServerAddress)
	}
	if got := browserWorkerAllowedOrigin(request); got != "http://198.18.13.41" {
		t.Fatalf("allowed origin = %q, want client module-site origin", got)
	}
}

func TestBrowserArtifactSourceIssuesAndSpendsEveryArtifactOnce(t *testing.T) {
	endpoint, err := transportrelease.OpenProductDirectBrowserEndpointAt(context.Background(), "127.0.0.1", "http://127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	defer endpoint.Close()
	plan := transportrelease.ProfilePlan{
		ID: "mobile-v1", Cold: transportrelease.ColdPlan{Operations: 2},
		CleanupDeadlineSeconds: 1, CellWatchdogMinutes: 1,
	}
	source, err := newBrowserArtifactSource(endpoint, plan, "browser_webtransport", 3)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(browserArtifactRequest{
		SchemaVersion: 1, Action: "acquire", Topology: "browser_webtransport",
		ProfileID: "mobile-v1", RunNumber: 3, Phase: "cold", Count: 2,
	})
	request := httptest.NewRequest(http.MethodPost, "/artifacts", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	source.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("acquire status = %d: %s", response.Code, response.Body.String())
	}
	var batch browserArtifactResponse
	if err := json.Unmarshal(response.Body.Bytes(), &batch); err != nil {
		t.Fatal(err)
	}
	if len(batch.Artifacts) != 2 || batch.Artifacts[0].SpendToken == batch.Artifacts[1].SpendToken {
		t.Fatalf("invalid artifact batch: %+v", batch)
	}
	for _, artifact := range batch.Artifacts {
		spendBody, _ := json.Marshal(browserArtifactRequest{SchemaVersion: 1, Action: "spend", SpendToken: artifact.SpendToken})
		for attempt, want := range []int{http.StatusNoContent, http.StatusConflict} {
			spendRequest := httptest.NewRequest(http.MethodPost, "/artifacts", bytes.NewReader(spendBody))
			spendRequest.Header.Set("Content-Type", "application/json")
			spendResponse := httptest.NewRecorder()
			source.ServeHTTP(spendResponse, spendRequest)
			if spendResponse.Code != want {
				t.Fatalf("spend attempt %d status = %d, want %d", attempt+1, spendResponse.Code, want)
			}
		}
	}
	finalizeCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := source.Finalize(finalizeCtx, true); err == nil {
		t.Fatal("aborted incomplete browser source finalized successfully")
	}
}

func TestBrowserArtifactSourceKeepsColdSessionAliveForOperationDeadline(t *testing.T) {
	termination := make(chan struct{})
	session := &browserSourceDeadlineSession{termination: termination}
	profile := transportrelease.ProfilePlan{
		ID: "edge-v1",
		Cold: transportrelease.ColdPlan{
			Operations: 1, OperationDeadlineSeconds: 3, PhaseDeadlineSeconds: 3,
		},
		CleanupDeadlineSeconds: 1,
		CellWatchdogMinutes:    1,
	}
	source, err := newBrowserArtifactSourceWithIssuer(func() (browserServerArtifact, error) {
		return nil, errors.New("unused")
	}, profile, "browser_webtransport", 1)
	if err != nil {
		t.Fatal(err)
	}
	source.wg.Add(1)
	done := make(chan struct{})
	go func() {
		source.serve(&browserArtifactRecord{
			artifact: browserSourceDeadlineArtifact{session: session},
			phase:    "cold",
		})
		close(done)
	}()
	time.AfterFunc(1250*time.Millisecond, func() { close(termination) })
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("cold browser server did not observe natural termination")
	}
	if got := session.closeCalls.Load(); got != 0 {
		t.Fatalf("forced session close calls = %d, want 0 before the cold operation deadline", got)
	}
}

func TestBrowserServerSessionCloseDeadlineCoversColdPhaseAndCleanup(t *testing.T) {
	profile := transportrelease.ProfilePlan{
		Cold: transportrelease.ColdPlan{
			OperationDeadlineSeconds: 10,
			PhaseDeadlineSeconds:     15,
		},
		CleanupDeadlineSeconds: 5,
	}
	if got, want := browserServerSessionCloseDeadline(profile, "cold"), 20*time.Second; got != want {
		t.Fatalf("cold server session close deadline = %s, want phase plus cleanup %s", got, want)
	}
	if got, want := browserServerSessionCloseDeadline(profile, "rpc"), 5*time.Second; got != want {
		t.Fatalf("rpc server session close deadline = %s, want cleanup %s", got, want)
	}
}

type browserSourceDeadlineArtifact struct {
	session flowersession.SessionV2
}

func (artifact browserSourceDeadlineArtifact) ArtifactJSON() string { return "{}" }
func (artifact browserSourceDeadlineArtifact) AwaitServer(context.Context) (flowersession.SessionV2, error) {
	return artifact.session, nil
}
func (browserSourceDeadlineArtifact) Cancel() {}

type browserSourceDeadlineSession struct {
	flowersession.SessionV2
	termination <-chan struct{}
	closeCalls  atomic.Int32
}

func (session *browserSourceDeadlineSession) Termination() <-chan struct{} {
	return session.termination
}
func (session *browserSourceDeadlineSession) Close() error {
	session.closeCalls.Add(1)
	return nil
}

func TestBrowserTunnelArtifactSourceIssuesChromiumWebTransportLeg(t *testing.T) {
	plan := transportrelease.ProfilePlan{
		ID: "mobile-v1", Cold: transportrelease.ColdPlan{Operations: 1},
		CleanupDeadlineSeconds: 2, CellWatchdogMinutes: 1,
	}
	for _, topology := range tunnelworkload.BrowserTopologies() {
		t.Run(string(topology), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			endpoint, err := tunnelworkload.OpenBrowserEndpointAt(ctx, topology, "127.0.0.1", "http://127.0.0.1")
			if err != nil {
				t.Fatal(err)
			}
			defer endpoint.Close(context.Background())
			source, err := newBrowserTunnelArtifactSource(endpoint, plan, string(topology), 2)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := json.Marshal(browserArtifactRequest{
				SchemaVersion: 1, Action: "acquire", Topology: string(topology),
				ProfileID: plan.ID, RunNumber: 2, Phase: "cold", Count: 1,
			})
			request := httptest.NewRequest(http.MethodPost, "/artifacts", bytes.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			source.ServeHTTP(response, request)
			if response.Code != http.StatusOK {
				t.Fatalf("acquire status = %d: %s", response.Code, response.Body.String())
			}
			var batch browserArtifactResponse
			if err := json.Unmarshal(response.Body.Bytes(), &batch); err != nil || len(batch.Artifacts) != 1 {
				t.Fatalf("artifact batch = %+v: %v", batch, err)
			}
			artifact, err := artifactv2.DecodeArtifactJSON(strings.NewReader(batch.Artifacts[0].ArtifactJSON))
			if err != nil {
				t.Fatal(err)
			}
			if artifact.Path.Kind != artifactv2.PathTunnel || artifact.Path.Role != 1 || len(artifact.Path.Candidates) != 2 {
				t.Fatalf("browser artifact contract = %+v", artifact.Path)
			}
			var browserCandidate artifactv2.Candidate
			for _, candidate := range artifact.Path.Candidates {
				if candidate.ID == "browser-leg" {
					browserCandidate = candidate
				}
			}
			if browserCandidate.Carrier != artifactv2.CarrierWebTransport {
				t.Fatalf("browser candidate = %+v", browserCandidate)
			}
			spendBody, _ := json.Marshal(browserArtifactRequest{
				SchemaVersion: 1, Action: "spend", SpendToken: batch.Artifacts[0].SpendToken,
			})
			spendRequest := httptest.NewRequest(http.MethodPost, "/artifacts", bytes.NewReader(spendBody))
			spendRequest.Header.Set("Content-Type", "application/json")
			spendResponse := httptest.NewRecorder()
			source.ServeHTTP(spendResponse, spendRequest)
			if spendResponse.Code != http.StatusNoContent {
				t.Fatalf("spend status = %d", spendResponse.Code)
			}
			finalizeCtx, finalizeCancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer finalizeCancel()
			if err := source.Finalize(finalizeCtx, true); err == nil {
				t.Fatal("aborted browser tunnel source finalized successfully")
			}
		})
	}
}

func TestBrowserTopologyValidationIncludesFrozenMixedCells(t *testing.T) {
	for _, topology := range []string{
		browserDirectTopology,
		string(tunnelworkload.BrowserTunnelWTWSS),
		string(tunnelworkload.BrowserTunnelWTQUIC),
	} {
		if !supportedBrowserTopology(topology) {
			t.Fatalf("supported topology %q was rejected", topology)
		}
	}
	if supportedBrowserTopology("browser_tunnel_wt_wt") {
		t.Fatal("unsupported browser tunnel topology was accepted")
	}
}

func TestFaultProfileFromFrozenNetworkPlan(t *testing.T) {
	plan := transportrelease.ProfilePlan{
		Network: transportrelease.NetworkPlan{
			OneWayDelayMilliseconds: 60,
			JitterMilliseconds:      []int{0, 8, -4, 12, -8, 4, -2, 6},
			Loss:                    transportrelease.LossPlan{Mode: "periodic", EveryNth: 50},
			Shape:                   &transportrelease.ShapePlan{RateBitsPerSecond: 5_000_000, TokenBurstBytes: 32_768, QueueBytes: 262_144},
			LinkMTU:                 1280,
		},
		Fault: transportrelease.FaultPlan{
			ReorderPercent: 1, DuplicatePercent: 1,
			OutageStart: time.Second, OutageDuration: 2 * time.Second,
		},
	}
	profile, err := faultProfileFromPlan(plan, "/release/packet_fault.o")
	if err != nil {
		t.Fatal(err)
	}
	if profile.BPFObject != "/release/packet_fault.o" || profile.BaseDelay != 60*time.Millisecond ||
		profile.LossMode != linuxnetlab.LossPeriodic || profile.EveryNth != 50 ||
		profile.RateBitsPerSecond != 5_000_000 || profile.TokenBurstBytes != 32_768 ||
		profile.QueueBytes != 262_144 || profile.LinkMTU != 1280 || len(profile.Jitter) != 8 ||
		profile.Jitter[4] != -8*time.Millisecond || profile.ReorderPercent != 1 ||
		profile.DuplicatePercent != 1 || profile.ReorderDelay != 250*time.Millisecond ||
		profile.OutageStart != time.Second || profile.OutageDuration != 2*time.Second {
		t.Fatalf("unexpected fault profile: %+v", profile)
	}
}

func TestFaultProfileRejectsCleanNetworkPlan(t *testing.T) {
	if _, err := faultProfileFromPlan(transportrelease.ProfilePlan{}, "/release/packet_fault.o"); err == nil {
		t.Fatal("accepted network plan without traffic shaping")
	}
}

func TestTunnelTopologyMatrixIsFrozen(t *testing.T) {
	want := []tunnelworkload.Topology{
		tunnelworkload.TopologyWW,
		tunnelworkload.TopologyQQ,
		tunnelworkload.TopologyWQ,
		tunnelworkload.TopologyQW,
	}
	got := tunnelworkload.Topologies()
	if len(got) != len(want) {
		t.Fatalf("tunnel topology count = %d, want %d", len(got), len(want))
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("tunnel topology %d = %s, want %s", index, got[index], want[index])
		}
	}
}

func TestFreezeBPFObjectCreatesReadOnlyPrivateCopy(t *testing.T) {
	path, cleanup, err := freezeBPFObject([]byte("immutable bpf object"))
	if err != nil {
		t.Fatal(err)
	}
	value, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(value) != "immutable bpf object" {
		t.Fatalf("frozen bytes = %q", value)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o400 {
		t.Fatalf("frozen mode = %o", info.Mode().Perm())
	}
	directory := filepath.Dir(path)
	if err := cleanup(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(directory); !os.IsNotExist(err) {
		t.Fatalf("frozen directory remained: %v", err)
	}
}

func TestValidateKernelEvidenceChecksExactLossAndConservation(t *testing.T) {
	plan := transportrelease.ProfilePlan{
		Network: transportrelease.NetworkPlan{
			JitterMilliseconds: []int{0, 8, -4, 12, -8, 4, -2, 6},
			Loss:               transportrelease.LossPlan{Mode: "periodic", EveryNth: 50},
		},
	}
	network := plan.Network
	stats := linuxnetlab.KernelFaultStats{
		Packets: 100, Bytes: 64_000, DelayPackets: 98, DeliveredPackets: 98, PeriodicLossPackets: 2,
	}
	for ordinal := 1; ordinal <= 100; ordinal++ {
		if ordinal%50 != 0 {
			slot := (ordinal - 1) % 8
			stats.JitterSlotPackets[slot]++
			if network.JitterMilliseconds[slot] != 0 {
				stats.JitterPackets++
			}
		}
	}
	evidence := linuxnetlab.KernelFaultEvidence{Client: stats, Server: stats}
	if err := validateKernelEvidence(plan, evidence); err != nil {
		t.Fatal(err)
	}
	evidence.Server.TimestampErrors = 1
	if err := validateKernelEvidence(plan, evidence); err == nil {
		t.Fatal("accepted a kernel timestamp error")
	}
}

func TestValidateKernelEvidenceAccountsForOutageAndDeterministicInjection(t *testing.T) {
	plan := transportrelease.ProfilePlan{
		Network: transportrelease.NetworkPlan{
			JitterMilliseconds: []int{0, 8, -4, 12, -8, 4, -2, 6},
			Loss:               transportrelease.LossPlan{Mode: "periodic", EveryNth: 50},
		},
		Fault: transportrelease.FaultPlan{
			ReorderPercent: 1, DuplicatePercent: 1,
			OutageStart: time.Second, OutageDuration: 2 * time.Second,
		},
	}
	stats := linuxnetlab.KernelFaultStats{
		Packets: 200, Bytes: 128_000, FirstPacketNS: 1,
		OutageDropPackets: 10, PeriodicLossPackets: 3,
		DeliveredPackets: 187, DelayPackets: 187,
		ReorderPackets: 2, DuplicatePackets: 2,
	}
	for ordinal := uint64(1); ordinal <= stats.Packets; ordinal++ {
		if ordinal >= 91 && ordinal <= 100 || ordinal%50 == 0 {
			continue
		}
		slot := (ordinal - 1) % 8
		stats.JitterSlotPackets[slot]++
		if plan.Network.JitterMilliseconds[slot] != 0 {
			stats.JitterPackets++
		}
	}
	evidence := linuxnetlab.KernelFaultEvidence{Client: stats, Server: stats}
	if err := validateKernelEvidence(plan, evidence); err != nil {
		t.Fatal(err)
	}
	evidence.Server.DuplicatePackets = 3
	if err := validateKernelEvidence(plan, evidence); err == nil {
		t.Fatal("accepted duplication outside the deterministic ordinal schedule")
	}
}

func TestPrivilegedProductionCarriersTraverseKernelProfile(t *testing.T) {
	if os.Getenv("FLOWERSEC_RELEASE_NETWORK_INTEGRATION") != "1" {
		t.Skip("set FLOWERSEC_RELEASE_NETWORK_INTEGRATION=1 on the audited privileged Linux runner")
	}
	bpfObject := os.Getenv("FLOWERSEC_BPF_OBJECT")
	if bpfObject == "" {
		t.Fatal("FLOWERSEC_BPF_OBJECT is required")
	}
	previousWorkerArguments := networkWorkerArguments
	networkWorkerArguments = func() []string { return []string{"-test.run=^TestNetworkWorkerProcess$"} }
	t.Cleanup(func() { networkWorkerArguments = previousWorkerArguments })
	t.Setenv("FLOWERSEC_NETWORK_WORKER_TEST", "1")
	artifactRoot := t.TempDir()
	reportPath := filepath.Join(filepath.Dir(artifactRoot), "privileged-network-cell.json")
	destination, err := newArtifactDestination(artifactRoot, reportPath)
	if err != nil {
		t.Fatal(err)
	}
	defer destination.Close()
	plan := transportrelease.ProfilePlan{
		ID: "mobile-v1",
		Cold: transportrelease.ColdPlan{
			Operations: 8, MaxInflight: 4, StartRatePerSecond: 20,
			OperationDeadlineSeconds: 10, PhaseDeadlineSeconds: 30,
		},
		RPC: transportrelease.RPCPlan{
			Operations: 16, RequestBytes: 1024, ResponseBytes: 1024, Workers: 4,
			OperationDeadlineSeconds: 10, PhaseDeadlineSeconds: 40,
		},
		Bulk: transportrelease.BulkPlan{
			WarmupBytesPerDirection: 16 * 1024, ScoreBytesPerDirection: 64 * 1024,
			PhaseDeadlineSeconds: 60,
		},
		Network: transportrelease.NetworkPlan{
			EvidenceLayer: "kernel_packet", OneWayDelayMilliseconds: 60,
			JitterMilliseconds: []int{0, 8, -4, 12, -8, 4, -2, 6},
			Loss:               transportrelease.LossPlan{Mode: "periodic", EveryNth: 50},
			Shape:              &transportrelease.ShapePlan{RateBitsPerSecond: 5_000_000, TokenBurstBytes: 32_768, QueueBytes: 262_144},
			LinkMTU:            1280, Firewall: linuxnetlab.FrozenFirewall,
		},
		CleanupDeadlineSeconds: 10, CellWatchdogMinutes: 4,
	}
	edgePlan := plan
	edgePlan.ID = "edge-v1"
	edgePlan.Network.OneWayDelayMilliseconds = 150
	edgePlan.Network.JitterMilliseconds = []int{0, 30, -20, 45, -35, 10, -5, 25}
	edgePlan.Network.Loss = transportrelease.LossPlan{Mode: "burst", BlockSize: 100, BurstFirst: 41, BurstLast: 45}
	edgePlan.Network.Shape = &transportrelease.ShapePlan{RateBitsPerSecond: 1_000_000, TokenBurstBytes: 16_384, QueueBytes: 65_536}
	cleanPlan := plan
	cleanPlan.ID = "clean-v1"
	cleanPlan.Network = transportrelease.NetworkPlan{
		EvidenceLayer: "kernel_packet", JitterMilliseconds: []int{0},
		Loss: transportrelease.LossPlan{Mode: "none"}, LinkMTU: 1500, Firewall: linuxnetlab.FrozenFirewall,
	}
	t.Run("clean-v1-isolated", func(t *testing.T) {
		for _, kind := range []carrier.Kind{carrier.KindWebSocket, carrier.KindQUIC, carrier.KindWebTransport} {
			t.Run(string(kind), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
				defer cancel()
				result, err := runNetworkCarrier(ctx, kind, cleanPlan, 1, "", destination)
				if err != nil {
					t.Fatal(err)
				}
				if result.Kernel == nil || result.Kernel.ClientNamespace == "" || result.Kernel.ServerNamespace == "" ||
					result.Kernel.ClientNamespace == result.Kernel.ServerNamespace {
					t.Fatalf("clean baseline did not use isolated namespaces: %+v", result.Kernel)
				}
				assertPrivilegedRunArtifacts(t, result.Artifacts, kind != carrier.KindWebSocket)
			})
		}
	})
	for _, profile := range []transportrelease.ProfilePlan{plan, edgePlan} {
		profile := profile
		t.Run(profile.ID, func(t *testing.T) {
			for _, kind := range []carrier.Kind{carrier.KindWebSocket, carrier.KindQUIC, carrier.KindWebTransport} {
				t.Run(string(kind), func(t *testing.T) {
					ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
					defer cancel()
					result, err := runNetworkCarrier(ctx, kind, profile, 1, bpfObject, destination)
					if err != nil {
						t.Fatal(err)
					}
					if len(result.Cold) != profile.Cold.Operations || len(result.RPC) != profile.RPC.Operations ||
						result.Bulk.BytesPerDirection != profile.Bulk.ScoreBytesPerDirection || result.CleanupDuration <= 0 ||
						result.Resource.FinishedAt.Before(result.Resource.StartedAt) || result.Kernel == nil {
						t.Fatalf("incomplete production workload: %+v", result)
					}
					assertPrivilegedRunArtifacts(t, result.Artifacts, kind != carrier.KindWebSocket)
				})
			}
		})
	}
	for _, profile := range []transportrelease.ProfilePlan{plan, edgePlan} {
		profile := profile
		t.Run(profile.ID+"-tunnel", func(t *testing.T) {
			for _, topology := range tunnelworkload.Topologies() {
				t.Run(string(topology), func(t *testing.T) {
					ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
					defer cancel()
					result, err := runNetworkTunnel(ctx, topology, profile, 1, bpfObject, destination)
					if err != nil {
						t.Fatal(err)
					}
					if len(result.Workload.Cold) != profile.Cold.Operations || len(result.Workload.RPC) != profile.RPC.Operations ||
						result.Workload.Bulk.BytesPerDirection != profile.Bulk.ScoreBytesPerDirection || result.Workload.CleanupDuration <= 0 ||
						result.Resource.FinishedAt.Before(result.Resource.StartedAt) || result.Kernel == nil {
						t.Fatalf("incomplete production tunnel workload: %+v", result)
					}
					clientCarrier, serverCarrier, err := topology.Carriers()
					if err != nil {
						t.Fatal(err)
					}
					assertPrivilegedRunArtifacts(t, result.Artifacts, clientCarrier != carrier.KindWebSocket || serverCarrier != carrier.KindWebSocket)
				})
			}
		})
	}
}

func assertPrivilegedRunArtifacts(t *testing.T, artifacts []releaseArtifact, wantQLOG bool) {
	t.Helper()
	pcaps, qlogs := 0, 0
	for _, artifact := range artifacts {
		if artifact.SizeBytes <= 0 || len(artifact.SHA256) != 64 {
			t.Fatalf("invalid release artifact: %+v", artifact)
		}
		switch artifact.Kind {
		case "classic-pcap":
			pcaps++
		case "qlog-json-seq":
			qlogs++
		}
	}
	if pcaps != 1 || wantQLOG && qlogs == 0 || !wantQLOG && qlogs != 0 {
		t.Fatalf("release artifacts pcap=%d qlog=%d want_qlog=%t: %+v", pcaps, qlogs, wantQLOG, artifacts)
	}
}

func TestNetworkWorkerProcess(t *testing.T) {
	if os.Getenv("FLOWERSEC_NETWORK_WORKER_TEST") != "1" {
		t.Skip("network worker subprocess only")
	}
	if err := runNetworkWorker(os.Stdin, os.Stdout); err != nil {
		t.Fatal(err)
	}
}

func TestConformanceSmokeCaseDefinitionsStayBoundToRegistryProfiles(t *testing.T) {
	want := []struct{ id, profile string }{
		{"CS-C1", "direct-wss-x25519"},
		{"CS-C2", "direct-raw-quic-p256"},
		{"CS-C3", "tunnel-wss-wss-p256"},
		{"CS-C4", "tunnel-quic-quic-x25519"},
		{"CS-C5", "tunnel-wss-quic-x25519"},
		{"CS-C6", "tunnel-quic-wss-p256"},
	}
	if len(conformanceSmokeCases) != len(want) {
		t.Fatalf("case definitions = %d, want %d", len(conformanceSmokeCases), len(want))
	}
	for index, definition := range conformanceSmokeCases {
		if definition.ID != want[index].id || definition.Profile != want[index].profile {
			t.Fatalf("case %d = %+v, want %+v", index, definition, want[index])
		}
		if (definition.Carrier == "") == (definition.Topology == "") || (definition.Suite != protocolv2.SuiteChaCha20Poly1305 && definition.Suite != protocolv2.SuiteAES256GCM) {
			t.Fatalf("case %s must select exactly one production path: %+v", definition.ID, definition)
		}
	}
}

func TestConformanceSmokeCaseWritesArtifactsAfterRealProductRoundTrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	completed, err := runConformanceSmokeCase(ctx, conformanceSmokeCases[0])
	if err != nil {
		t.Fatal(err)
	}
	if completed.CompletedOperations != 1 || completed.NegotiatedSuite != conformanceSmokeCases[0].Suite {
		t.Fatalf("completed workload = %+v", completed)
	}

	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	artifacts := filepath.Join(root, "artifacts")
	if err := os.Mkdir(artifacts, 0o700); err != nil {
		t.Fatal(err)
	}
	destination, err := newArtifactDestination(artifacts, filepath.Join(root, "case-suite.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer destination.Close()
	references, err := writeCaseIdentityArtifacts(destination, conformanceSmokeCases[0], completed, time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if len(references) != 3 || references[0].Kind != "trace" || references[1].Kind != "metrics" || references[2].Kind != "config" {
		t.Fatalf("case artifacts = %+v", references)
	}
	for _, reference := range references {
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(reference.Path)))
		if err != nil || len(data) == 0 {
			t.Fatalf("read %s: %v", reference.Path, err)
		}
	}
	traceData, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(references[0].Path)))
	if err != nil {
		t.Fatal(err)
	}
	var trace rawTraceArtifact
	if err := json.Unmarshal(traceData, &trace); err != nil {
		t.Fatal(err)
	}
	wantExecutionID := releaseCaseExecutionID("case " + conformanceSmokeCases[0].ID)
	if len(trace.Records) != 1 || trace.Records[0].Digest != wantExecutionID {
		t.Fatalf("trace execution identity = %+v, want %s", trace.Records, wantExecutionID)
	}
	configData, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(references[2].Path)))
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
	if values["test_id"] != wantExecutionID || values["suite"] != "1" {
		t.Fatalf("config identity = %+v", values)
	}
}

func TestAllConformanceSmokeCasesCompleteTheirProductionPaths(t *testing.T) {
	for _, definition := range conformanceSmokeCases {
		definition := definition
		t.Run(definition.ID, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			completed, err := runConformanceSmokeCase(ctx, definition)
			if err != nil {
				t.Fatal(err)
			}
			if completed.CompletedOperations != 1 || completed.NegotiatedSuite != definition.Suite {
				t.Fatalf("completed workload = %+v", completed)
			}
		})
	}
}
