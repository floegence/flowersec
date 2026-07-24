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
	if plan.RunCount != 15 || plan.Clean.ID != "clean-v1" || plan.Clean.CellWatchdogMinutes != 15 {
		t.Fatalf("plan header = %+v", plan)
	}
	if plan.Clean.Cold.Operations != 2000 || plan.Clean.Cold.MaxInflight != 32 || plan.Clean.Cold.Retries != 0 ||
		plan.Clean.RPC.Operations != 2000 || plan.Clean.RPC.Workers != 32 || plan.Clean.RPC.RequestBytes != 1024 || plan.Clean.RPC.Retries != 0 ||
		plan.Clean.Bulk.WarmupBytesPerDirection != 1<<20 || plan.Clean.Bulk.ScoreBytesPerDirection != 64<<20 {
		t.Fatalf("clean workload = %+v", plan.Clean)
	}
}

func TestLoadReleasePlanUsesFrozenWeakNetworkWorkloads(t *testing.T) {
	plan, _, err := LoadReleasePlan("../../../testdata/transport_v2/performance_manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	if plan.Mobile.ID != "mobile-v1" || plan.Mobile.CellWatchdogMinutes != 70 ||
		plan.Mobile.Cold.StartRatePerSecond != 15 || plan.Mobile.Cold.PhaseDeadlineSeconds != 150 ||
		plan.Mobile.RPC.PhaseDeadlineSeconds != 70 ||
		plan.Mobile.Bulk.WarmupBytesPerDirection != 128<<10 ||
		plan.Mobile.Bulk.ScoreBytesPerDirection != 512<<10 ||
		plan.Mobile.Bulk.PhaseDeadlineSeconds != 55 {
		t.Fatalf("mobile workload = %+v", plan.Mobile)
	}
	if plan.Edge.ID != "edge-v1" || plan.Edge.CellWatchdogMinutes != 175 ||
		plan.Edge.Cold.StartRatePerSecond != 5 || plan.Edge.Cold.PhaseDeadlineSeconds != 430 ||
		plan.Edge.RPC.PhaseDeadlineSeconds != 170 || plan.Edge.Bulk.ScoreBytesPerDirection != 2<<20 {
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
