//go:build linux

package main

import (
	"os"
	"testing"
)

func TestLinuxProcessTreeFallbackRecordsAccountingProvenance(t *testing.T) {
	sampler, err := newLinuxProcessTreeSampler(os.Getpid(), "", "delegated cgroup counters unavailable")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := sampler.Close(); err != nil {
			t.Fatal(err)
		}
	}()
	snapshot, err := sampler.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.AccountingMode != "pid_starttime_process_tree_fallback" || snapshot.FallbackReason != "delegated cgroup counters unavailable" || snapshot.SampleIntervalMS != 10 {
		t.Fatalf("fallback provenance = %+v", snapshot)
	}
}
