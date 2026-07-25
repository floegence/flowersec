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
