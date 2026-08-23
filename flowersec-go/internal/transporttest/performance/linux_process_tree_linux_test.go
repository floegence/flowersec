//go:build linux

package performance

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
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

func TestLinuxProcessTreeSnapshotRetriesOnlyTransientIncompleteSamples(t *testing.T) {
	var captures, waits int
	want := linuxProcessTreeSnapshot{RootPID: 42}
	got, err := retryLinuxProcessTreeSnapshot(func() (linuxProcessTreeSnapshot, error) {
		captures++
		if captures < 3 {
			return linuxProcessTreeSnapshot{}, errLinuxProcessTreeSnapshotIncomplete
		}
		return want, nil
	}, func(delay time.Duration) {
		if delay != 25*time.Millisecond {
			t.Fatalf("retry delay = %s, want 25ms", delay)
		}
		waits++
	})
	if err != nil || got != want || captures != 3 || waits != 2 {
		t.Fatalf("retry result/error/captures/waits = %+v / %v / %d / %d", got, err, captures, waits)
	}

	permanent := errors.New("permanent")
	captures = 0
	_, err = retryLinuxProcessTreeSnapshot(func() (linuxProcessTreeSnapshot, error) {
		captures++
		return linuxProcessTreeSnapshot{}, permanent
	}, func(time.Duration) { t.Fatal("permanent error was retried") })
	if !errors.Is(err, permanent) || captures != 1 {
		t.Fatalf("permanent result/captures = %v / %d", err, captures)
	}
}

func TestReadLinuxCgroupResourcesSupportsSampledAndNativeMemoryPeak(t *testing.T) {
	directory := t.TempDir()
	write := func(name, value string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(directory, name), []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("cpu.stat", "usage_usec 42\n")
	write("memory.current", "1024\n")
	write("pids.current", "3\n")
	cpu, current, peak, pids, native, err := readLinuxCgroupResources(directory)
	if err != nil || cpu != 42_000 || current != 1024 || peak != 0 || pids != 3 || native {
		t.Fatalf("sampled resources = %d/%d/%d/%d/%t, error = %v", cpu, current, peak, pids, native, err)
	}
	write("memory.peak", "2048\n")
	cpu, current, peak, pids, native, err = readLinuxCgroupResources(directory)
	if err != nil || cpu != 42_000 || current != 1024 || peak != 2048 || pids != 3 || !native {
		t.Fatalf("native resources = %d/%d/%d/%d/%t, error = %v", cpu, current, peak, pids, native, err)
	}
}

func TestLinuxProcessTreeCgroupPeakSamplerReadsOnlyMemoryCurrent(t *testing.T) {
	directory := t.TempDir()
	memoryCurrent := filepath.Join(directory, "memory.current")
	if err := os.WriteFile(memoryCurrent, []byte("1024\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sampler := &linuxProcessTreeSampler{procRoot: filepath.Join(directory, "missing-proc"), cgroupPath: directory}
	sampler.sampleResourcePeakLocked()
	if sampler.cgroupPeak != 1024 {
		t.Fatalf("sampled cgroup peak = %d, want 1024", sampler.cgroupPeak)
	}
	if err := os.WriteFile(memoryCurrent, []byte("512\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sampler.sampleResourcePeakLocked()
	if sampler.cgroupPeak != 1024 {
		t.Fatalf("sampled cgroup peak regressed to %d", sampler.cgroupPeak)
	}
	if err := os.WriteFile(memoryCurrent, []byte("2048\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sampler.sampleResourcePeakLocked()
	if sampler.cgroupPeak != 2048 {
		t.Fatalf("sampled cgroup peak = %d, want 2048", sampler.cgroupPeak)
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

func TestLinuxProcessTreeCgroupKillFallsBackWithoutCgroupKillFile(t *testing.T) {
	command := exec.Command("sh", "-c", "while :; do sleep 1; done")
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	waitDone := make(chan error, 1)
	go func() { waitDone <- command.Wait() }()
	waited := false
	defer func() {
		if waited {
			return
		}
		_ = command.Process.Kill()
		select {
		case <-waitDone:
		case <-time.After(time.Second):
		}
	}()

	cgroupPath := t.TempDir()
	if err := os.WriteFile(filepath.Join(cgroupPath, "cgroup.procs"), []byte(strconv.Itoa(command.Process.Pid)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sampler := &linuxProcessTreeSampler{cgroupPath: cgroupPath}
	if err := sampler.Kill(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-waitDone:
		waited = true
	case <-time.After(250 * time.Millisecond):
		t.Fatal("cgroup kill fallback left the listed process running")
	}
}
