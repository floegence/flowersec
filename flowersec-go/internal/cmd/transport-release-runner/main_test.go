package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/artifactv2"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier"
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
