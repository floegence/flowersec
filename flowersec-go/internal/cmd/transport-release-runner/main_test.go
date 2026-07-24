package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/transportrelease"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/transportrelease/linuxnetlab"
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

func TestFaultProfileFromFrozenNetworkPlan(t *testing.T) {
	plan := transportrelease.NetworkPlan{
		OneWayDelayMilliseconds: 60,
		JitterMilliseconds:      []int{0, 8, -4, 12, -8, 4, -2, 6},
		Loss:                    transportrelease.LossPlan{Mode: "periodic", EveryNth: 50},
		Shape:                   &transportrelease.ShapePlan{RateBitsPerSecond: 5_000_000, TokenBurstBytes: 32_768, QueueBytes: 262_144},
		LinkMTU:                 1280,
	}
	profile, err := faultProfileFromPlan(plan, "/release/packet_fault.o")
	if err != nil {
		t.Fatal(err)
	}
	if profile.BPFObject != "/release/packet_fault.o" || profile.BaseDelay != 60*time.Millisecond ||
		profile.LossMode != linuxnetlab.LossPeriodic || profile.EveryNth != 50 ||
		profile.RateBitsPerSecond != 5_000_000 || profile.TokenBurstBytes != 32_768 ||
		profile.QueueBytes != 262_144 || profile.LinkMTU != 1280 || len(profile.Jitter) != 8 ||
		profile.Jitter[4] != -8*time.Millisecond {
		t.Fatalf("unexpected fault profile: %+v", profile)
	}
}

func TestFaultProfileRejectsCleanNetworkPlan(t *testing.T) {
	if _, err := faultProfileFromPlan(transportrelease.NetworkPlan{}, "/release/packet_fault.o"); err == nil {
		t.Fatal("accepted network plan without traffic shaping")
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
	network := transportrelease.NetworkPlan{
		JitterMilliseconds: []int{0, 8, -4, 12, -8, 4, -2, 6},
		Loss:               transportrelease.LossPlan{Mode: "periodic", EveryNth: 50},
	}
	stats := linuxnetlab.KernelFaultStats{
		Packets: 100, Bytes: 64_000, DelayPackets: 98, PeriodicLossPackets: 2,
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
	if err := validateKernelEvidence(network, evidence); err != nil {
		t.Fatal(err)
	}
	evidence.Server.TimestampErrors = 1
	if err := validateKernelEvidence(network, evidence); err == nil {
		t.Fatal("accepted a kernel timestamp error")
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
	plan := transportrelease.ProfilePlan{
		ID: "mobile-v1",
		Cold: transportrelease.ColdPlan{
			Operations: 8, MaxInflight: 4, StartRatePerSecond: 20,
			OperationDeadlineSeconds: 10, PhaseDeadlineSeconds: 30,
		},
		RPC: transportrelease.RPCPlan{
			Operations: 16, RequestBytes: 1024, ResponseBytes: 1024, Workers: 4,
			OperationDeadlineSeconds: 5, PhaseDeadlineSeconds: 20,
		},
		Bulk: transportrelease.BulkPlan{
			WarmupBytesPerDirection: 16 * 1024, ScoreBytesPerDirection: 64 * 1024,
			PhaseDeadlineSeconds: 20,
		},
		Network: transportrelease.NetworkPlan{
			EvidenceLayer: "kernel_packet", OneWayDelayMilliseconds: 60,
			JitterMilliseconds: []int{0, 8, -4, 12, -8, 4, -2, 6},
			Loss:               transportrelease.LossPlan{Mode: "periodic", EveryNth: 50},
			Shape:              &transportrelease.ShapePlan{RateBitsPerSecond: 5_000_000, TokenBurstBytes: 32_768, QueueBytes: 262_144},
			LinkMTU:            1280, Firewall: linuxnetlab.FrozenFirewall,
		},
		CleanupDeadlineSeconds: 10, CellWatchdogMinutes: 2,
	}
	edgePlan := plan
	edgePlan.ID = "edge-v1"
	edgePlan.Network.OneWayDelayMilliseconds = 150
	edgePlan.Network.JitterMilliseconds = []int{0, 30, -20, 45, -35, 10, -5, 25}
	edgePlan.Network.Loss = transportrelease.LossPlan{Mode: "burst", BlockSize: 100, BurstFirst: 41, BurstLast: 45}
	edgePlan.Network.Shape = &transportrelease.ShapePlan{RateBitsPerSecond: 1_000_000, TokenBurstBytes: 16_384, QueueBytes: 65_536}
	for _, profile := range []transportrelease.ProfilePlan{plan, edgePlan} {
		profile := profile
		t.Run(profile.ID, func(t *testing.T) {
			for _, kind := range []carrier.Kind{carrier.KindWebSocket, carrier.KindQUIC, carrier.KindWebTransport} {
				t.Run(string(kind), func(t *testing.T) {
					ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
					defer cancel()
					result, err := runNetworkCarrier(ctx, kind, profile, 1, bpfObject)
					if err != nil {
						t.Fatal(err)
					}
					if len(result.Cold) != profile.Cold.Operations || len(result.RPC) != profile.RPC.Operations ||
						result.Bulk.BytesPerDirection != profile.Bulk.ScoreBytesPerDirection || result.CleanupDuration <= 0 || result.Kernel == nil {
						t.Fatalf("incomplete production workload: %+v", result)
					}
				})
			}
		})
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
