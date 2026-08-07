//go:build linux

package performance

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
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

func TestLinuxProcessTreeCgroupKillDoesNotWaitForSnapshotLock(t *testing.T) {
	cgroupPath := t.TempDir()
	killPath := filepath.Join(cgroupPath, "cgroup.kill")
	if err := os.WriteFile(killPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	sampler := &linuxProcessTreeSampler{cgroupPath: cgroupPath}

	sampler.sampleMu.Lock()
	killDone := make(chan error, 1)
	go func() { killDone <- sampler.Kill() }()
	select {
	case err := <-killDone:
		if err != nil {
			sampler.sampleMu.Unlock()
			t.Fatal(err)
		}
	case <-time.After(250 * time.Millisecond):
		sampler.sampleMu.Unlock()
		_ = <-killDone
		t.Fatal("cgroup kill waited for the resource snapshot lock")
	}
	sampler.sampleMu.Unlock()
	value, err := os.ReadFile(killPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(value) != "1" {
		t.Fatalf("cgroup.kill = %q, want 1", value)
	}
}

func TestLinuxProcessTreeCgroupKillAlsoStopsEscapedProcessGroup(t *testing.T) {
	command := exec.Command("sh", "-c", "while :; do sleep 1; done")
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	waitDone := make(chan error, 1)
	go func() { waitDone <- command.Wait() }()
	defer func() {
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		select {
		case <-waitDone:
		case <-time.After(time.Second):
		}
	}()

	cgroupPath := t.TempDir()
	if err := os.WriteFile(filepath.Join(cgroupPath, "cgroup.kill"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	sampler := &linuxProcessTreeSampler{cgroupPath: cgroupPath, pgid: command.Process.Pid}
	if err := sampler.Kill(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-waitDone:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("cgroup kill left the escaped process group running")
	}
}
