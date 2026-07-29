package transportrelease

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadReleasePlanUsesFrozenCleanWorkloads(t *testing.T) {
	plan, binding, err := LoadReleasePlan("../../../testdata/transport_v2/performance_manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	if binding.Digest != FrozenPerformanceManifestDigest || binding.SHA256Sum == [32]byte{} {
		t.Fatalf("manifest binding = %+v", binding)
	}
	if plan.RunCount != 15 || plan.Clean.ID != "clean-v1" || plan.Clean.CellWatchdogMinutes != 5 {
		t.Fatalf("plan header = %+v", plan)
	}
	if plan.Clean.Cold.Operations != 100 || plan.Clean.Cold.MaxInflight != 32 || plan.Clean.Cold.Retries != 0 ||
		plan.Clean.RPC.Operations != 100 || plan.Clean.RPC.Workers != 32 || plan.Clean.RPC.RequestBytes != 1024 || plan.Clean.RPC.Retries != 0 ||
		plan.Clean.Bulk.WarmupBytesPerDirection != 128<<10 || plan.Clean.Bulk.ScoreBytesPerDirection != 8<<20 {
		t.Fatalf("clean workload = %+v", plan.Clean)
	}
}

func TestLoadReleasePlanUsesFrozenWeakNetworkWorkloads(t *testing.T) {
	plan, _, err := LoadReleasePlan("../../../testdata/transport_v2/performance_manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	if plan.Mobile.ID != "mobile-v1" || plan.Mobile.CellWatchdogMinutes != 5 ||
		plan.Mobile.Cold.Operations != 30 || plan.Mobile.Cold.StartRatePerSecond != 15 || plan.Mobile.Cold.PhaseDeadlineSeconds != 7 ||
		plan.Mobile.RPC.Operations != 60 || plan.Mobile.RPC.PhaseDeadlineSeconds != 5 ||
		plan.Mobile.Bulk.WarmupBytesPerDirection != 64<<10 ||
		plan.Mobile.Bulk.ScoreBytesPerDirection != 256<<10 ||
		plan.Mobile.Bulk.PhaseDeadlineSeconds != 4 {
		t.Fatalf("mobile workload = %+v", plan.Mobile)
	}
	if plan.Edge.ID != "edge-v1" || plan.Edge.CellWatchdogMinutes != 5 ||
		plan.Edge.Cold.Operations != 10 || plan.Edge.Cold.StartRatePerSecond != 5 || plan.Edge.Cold.Retries != 0 ||
		plan.Edge.Cold.OperationDeadlineSeconds != 53 || plan.Edge.Cold.PhaseDeadlineSeconds != 55 ||
		plan.Edge.RPC.Operations != 30 || plan.Edge.RPC.Workers != 30 || plan.Edge.RPC.OperationDeadlineSeconds != 24 || plan.Edge.RPC.PhaseDeadlineSeconds != 26 ||
		plan.Edge.Bulk.ScoreBytesPerDirection != 128<<10 || plan.Edge.Bulk.PhaseDeadlineSeconds != 25 ||
		plan.Edge.CleanupDeadlineSeconds != 12 {
		t.Fatalf("edge workload = %+v", plan.Edge)
	}
	if plan.Mobile.Fault.ReorderPercent != 1 || plan.Mobile.Fault.DuplicatePercent != 1 ||
		plan.Mobile.Fault.OutageStart != time.Second || plan.Mobile.Fault.OutageDuration != 2*time.Second {
		t.Fatalf("mobile fault matrix = %+v", plan.Mobile.Fault)
	}
	if plan.Edge.Fault.ReorderPercent != 2 || plan.Edge.Fault.DuplicatePercent != 2 ||
		plan.Edge.Fault.OutageStart != time.Second || plan.Edge.Fault.OutageDuration != 2*time.Second {
		t.Fatalf("edge fault matrix = %+v", plan.Edge.Fault)
	}

	mobileNetwork := plan.Mobile.Network
	if mobileNetwork.EvidenceLayer != "kernel_packet" || mobileNetwork.OneWayDelayMilliseconds != 60 ||
		mobileNetwork.Loss.Mode != "periodic" || mobileNetwork.Loss.EveryNth != 50 ||
		mobileNetwork.Shape == nil || mobileNetwork.Shape.RateBitsPerSecond != 5_000_000 ||
		mobileNetwork.Shape.TokenBurstBytes != 32_768 || mobileNetwork.Shape.QueueBytes != 262_144 ||
		mobileNetwork.LinkMTU != 1280 || len(mobileNetwork.JitterMilliseconds) != 8 {
		t.Fatalf("mobile network = %+v", mobileNetwork)
	}

	edgeNetwork := plan.Edge.Network
	if edgeNetwork.EvidenceLayer != "kernel_packet" || edgeNetwork.OneWayDelayMilliseconds != 150 ||
		edgeNetwork.Loss.Mode != "burst" || edgeNetwork.Loss.BlockSize != 100 ||
		edgeNetwork.Loss.BurstFirst != 41 || edgeNetwork.Loss.BurstLast != 45 ||
		edgeNetwork.Shape == nil || edgeNetwork.Shape.RateBitsPerSecond != 1_000_000 ||
		edgeNetwork.Shape.TokenBurstBytes != 16_384 || edgeNetwork.Shape.QueueBytes != 65_536 ||
		edgeNetwork.LinkMTU != 1280 || len(edgeNetwork.JitterMilliseconds) != 8 {
		t.Fatalf("edge network = %+v", edgeNetwork)
	}
}

func TestLoadReleasePlanUsesFrozenAdaptiveSelectionStages(t *testing.T) {
	plan, _, err := LoadReleasePlan("../../../testdata/transport_v2/performance_manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	if plan.Adaptive.ID != "adaptive-selection-v1" || plan.Adaptive.CellWatchdogMinutes != 5 ||
		plan.Adaptive.HarnessSlackSeconds != 45 || len(plan.Adaptive.Stages) != 2 {
		t.Fatalf("adaptive plan = %+v", plan.Adaptive)
	}
	for index, profile := range []ProfilePlan{plan.Clean, plan.Mobile} {
		stage := plan.Adaptive.Stages[index]
		if stage.ProfileID != profile.ID || stage.Cold != profile.Cold || stage.CleanupDeadlineSeconds != profile.CleanupDeadlineSeconds {
			t.Fatalf("adaptive stage %d = %+v, want cold/cleanup from %+v", index, stage, profile)
		}
	}
}

func TestLoadReleasePlanRejectsManifestOutsideFrozenContract(t *testing.T) {
	raw, err := os.ReadFile("../../../testdata/transport_v2/performance_manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-2] = ' '
	path := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadReleasePlan(path); err == nil {
		t.Fatal("accepted a manifest whose content no longer matches its frozen digest")
	}
}
