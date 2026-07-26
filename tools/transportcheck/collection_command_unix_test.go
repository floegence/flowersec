//go:build linux || darwin

package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestCollectionCommandCancellationRequestsGracefulCleanup(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "terminated")
	ctx, cancel := context.WithCancel(context.Background())
	command := exec.CommandContext(ctx, "sh", "-c", `trap 'printf terminated > "$1"; exit 0' INT; while :; do sleep 1; done`, "runner", marker)
	configureCollectionCommand(command)
	if err := command.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	cancel()
	if err := command.Wait(); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(marker); err != nil || string(data) != "terminated" {
		t.Fatalf("collection cancellation skipped graceful cleanup: data=%q err=%v", data, err)
	}
}

func TestCollectionCgroupKillDoesNotDependOnRunnerCleanup(t *testing.T) {
	cgroup := t.TempDir()
	killPath := filepath.Join(cgroup, "cgroup.kill")
	if err := os.WriteFile(killPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	scheduleCollectionCgroupKill(cgroup, time.Millisecond)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		value, err := os.ReadFile(killPath)
		if err == nil && string(value) == "1" {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("collection cancellation did not trigger the lane cgroup kill")
}

func TestCollectionCleanupAllowsNestedBrowserWorkerToFinish(t *testing.T) {
	const nestedBrowserWorkerCleanupGrace = 35 * time.Second
	if collectionCommandCleanupGrace < nestedBrowserWorkerCleanupGrace+10*time.Second {
		t.Fatalf("outer cleanup grace %s does not allow the nested %s browser cleanup to finish", collectionCommandCleanupGrace, nestedBrowserWorkerCleanupGrace)
	}
	if collectionCommandCgroupKillDelay <= nestedBrowserWorkerCleanupGrace || collectionCommandCgroupKillDelay >= collectionCommandCleanupGrace {
		t.Fatalf("lane cgroup failsafe %s must follow nested cleanup and precede outer cleanup %s", collectionCommandCgroupKillDelay, collectionCommandCleanupGrace)
	}
}
