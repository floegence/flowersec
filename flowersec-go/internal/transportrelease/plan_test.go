package transportrelease

import (
	"os"
	"path/filepath"
	"testing"
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
