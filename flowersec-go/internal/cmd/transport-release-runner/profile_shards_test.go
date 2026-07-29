package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/transportrelease"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/transportrelease/tunnelworkload"
)

func TestMergeNetworkCellShardReportsRequiresCompleteRunSet(t *testing.T) {
	reports := make([]networkCellReport, 0, 5)
	for shardIndex, runs := range forcedProfileRunShards(15) {
		report := networkCellReport{
			SchemaVersion: 1, Classification: "linux_kernel_network_profile",
			SourceSHA: strings.Repeat("a", 40), ManifestDigest: "sha256:manifest", ManifestSHA256: strings.Repeat("b", 64),
			Runner:    baselineRunner{OS: "linux", Architecture: "amd64", KernelRelease: "test"},
			ProfileID: "edge-v1", BPFObjectSHA256: strings.Repeat("c", 64),
			StartedAt: time.Unix(int64(100+shardIndex), 0).UTC(), FinishedAt: time.Unix(int64(200+shardIndex), 0).UTC(),
			ShardIndex: shardIndex + 1, ShardCount: 5,
		}
		for _, run := range runs {
			report.Results = append(report.Results, baselineCarrierResult{
				Run: run, Carrier: string(carrier.KindWebSocket),
				Artifacts: []releaseArtifact{{Path: fmt.Sprintf("artifacts/run-%03d.pcap", run)}},
			})
		}
		reports = append(reports, report)
	}

	merged, err := mergeNetworkCellShardReports(reports, 15)
	if err != nil {
		t.Fatal(err)
	}
	assertMergedProfileRuns(t, merged.ShardIndex, merged.ShardCount, networkResultRuns(merged.Results))

	incomplete := append([]networkCellReport(nil), reports...)
	incomplete[4].Results = incomplete[4].Results[:2]
	if _, err := mergeNetworkCellShardReports(incomplete, 15); err == nil {
		t.Fatal("merge accepted a missing direct run")
	}
}

func TestMergeTunnelCellShardReportsRequiresCompleteRunSet(t *testing.T) {
	reports := make([]tunnelCellReport, 0, 5)
	for shardIndex, runs := range forcedProfileRunShards(15) {
		report := tunnelCellReport{
			SchemaVersion: 1, Classification: "linux_kernel_tunnel_network_profile",
			SourceSHA: strings.Repeat("a", 40), ManifestDigest: "sha256:manifest", ManifestSHA256: strings.Repeat("b", 64),
			Runner:    baselineRunner{OS: "linux", Architecture: "amd64", KernelRelease: "test"},
			ProfileID: "edge-v1", Topology: tunnelworkload.TopologyWQ, BPFObjectSHA256: strings.Repeat("c", 64),
			StartedAt: time.Unix(int64(100+shardIndex), 0).UTC(), FinishedAt: time.Unix(int64(200+shardIndex), 0).UTC(),
			ShardIndex: shardIndex + 1, ShardCount: 5,
		}
		for _, run := range runs {
			report.Results = append(report.Results, tunnelCarrierResult{
				Run: run, Workload: tunnelworkload.Result{Topology: tunnelworkload.TopologyWQ},
				Artifacts: []releaseArtifact{{Path: fmt.Sprintf("artifacts/run-%03d.pcap", run)}},
			})
		}
		reports = append(reports, report)
	}

	merged, err := mergeTunnelCellShardReports(reports, 15)
	if err != nil {
		t.Fatal(err)
	}
	assertMergedProfileRuns(t, merged.ShardIndex, merged.ShardCount, tunnelResultRuns(merged.Results))

	incomplete := append([]tunnelCellReport(nil), reports...)
	incomplete[4].Results = incomplete[4].Results[:2]
	if _, err := mergeTunnelCellShardReports(incomplete, 15); err == nil {
		t.Fatal("merge accepted a missing tunnel run")
	}
}

func assertMergedProfileRuns(t *testing.T, shardIndex, shardCount int, runs []int) {
	t.Helper()
	want := make([]int, 15)
	for index := range want {
		want[index] = index + 1
	}
	if shardIndex != 0 || shardCount != 0 || !reflect.DeepEqual(runs, want) {
		t.Fatalf("merged report = shard %d/%d runs=%v, want canonical 1..15", shardIndex, shardCount, runs)
	}
}

func networkResultRuns(results []baselineCarrierResult) []int {
	runs := make([]int, len(results))
	for index, result := range results {
		runs[index] = result.Run
	}
	return runs
}

func tunnelResultRuns(results []tunnelCarrierResult) []int {
	runs := make([]int, len(results))
	for index, result := range results {
		runs[index] = result.Run
	}
	return runs
}

func TestProfileShardReportNamesRemainCanonical(t *testing.T) {
	for shard := 1; shard <= 5; shard++ {
		if got, want := profileShardReportName(shard), fmt.Sprintf("shard-%02d.json", shard); got != want {
			t.Fatalf("shard %d report name = %q, want %q", shard, got, want)
		}
	}
}

func TestMergeNetworkCellShardReportFilesBindsFrozenInputsAndArtifacts(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var manifestSum [sha256.Size]byte
	for index := range manifestSum {
		manifestSum[index] = 0xbb
	}
	profile := transportrelease.ProfilePlan{ID: "edge-v1"}
	manifest := transportrelease.ManifestBinding{Digest: "sha256:manifest", SHA256Sum: manifestSum}
	reports := make([]networkCellReport, 0, 5)
	paths := make([]string, 0, 5)
	for shardIndex, runs := range forcedProfileRunShards(15) {
		report := networkCellReport{
			SchemaVersion: 1, Classification: "linux_kernel_network_profile",
			SourceSHA: strings.Repeat("a", 40), ManifestDigest: manifest.Digest, ManifestSHA256: hex.EncodeToString(manifestSum[:]),
			Runner:    baselineRunner{OS: "linux", Architecture: "amd64", KernelRelease: "test"},
			ProfileID: profile.ID, BPFObjectSHA256: strings.Repeat("c", 64),
			StartedAt: time.Unix(int64(100+shardIndex), 0).UTC(), FinishedAt: time.Unix(int64(200+shardIndex), 0).UTC(),
			ShardIndex: shardIndex + 1, ShardCount: 5,
		}
		for _, run := range runs {
			artifact := writeProfileShardPCAP(t, root, shardIndex+1, run)
			report.Results = append(report.Results, baselineCarrierResult{Run: run, Carrier: string(carrier.KindWebSocket), Artifacts: []releaseArtifact{artifact}})
		}
		reports = append(reports, report)
		path := filepath.Join(root, profileShardReportName(shardIndex+1))
		writeProfileShardReport(t, path, report)
		paths = append(paths, path)
	}
	if err := mergeNetworkCellShardReportFiles(
		root, filepath.Join(root, "cell.json"), paths, strings.Repeat("a", 40), profile.ID, carrier.KindWebSocket,
		transportrelease.ReleasePlan{RunCount: 15, Edge: profile}, manifest,
	); err != nil {
		t.Fatal(err)
	}
	value, err := os.ReadFile(filepath.Join(root, "cell.json"))
	if err != nil {
		t.Fatal(err)
	}
	var merged networkCellReport
	if err := json.Unmarshal(value, &merged); err != nil {
		t.Fatal(err)
	}
	assertMergedProfileRuns(t, merged.ShardIndex, merged.ShardCount, networkResultRuns(merged.Results))

	artifactPath := filepath.Join(root, filepath.FromSlash(reports[0].Results[0].Artifacts[0].Path))
	if err := os.WriteFile(artifactPath, []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyProfileReportArtifacts(root, networkArtifacts(merged.Results)); err == nil {
		t.Fatal("artifact verification accepted tampering")
	}
}

func writeProfileShardPCAP(t *testing.T, root string, shard, run int) releaseArtifact {
	t.Helper()
	path := filepath.Join(fmt.Sprintf("artifacts-shard-%02d", shard), fmt.Sprintf("run-%03d", run), "traffic.pcap")
	value := append([]byte{0xd4, 0xc3, 0xb2, 0xa1}, make([]byte, 21)...)
	value = append(value, []byte(fmt.Sprintf("run-%03d", run))...)
	fullPath := filepath.Join(root, path)
	if err := os.MkdirAll(filepath.Dir(fullPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fullPath, value, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(value)
	return releaseArtifact{Kind: "classic-pcap", Path: filepath.ToSlash(path), SHA256: hex.EncodeToString(digest[:]), SizeBytes: int64(len(value))}
}

func writeProfileShardReport(t *testing.T, path string, report any) {
	t.Helper()
	value, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, value, 0o600); err != nil {
		t.Fatal(err)
	}
}
