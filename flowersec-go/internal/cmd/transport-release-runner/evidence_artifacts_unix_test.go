//go:build linux || darwin

package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestPacketCaptureCancellationStopsDescendantProcess(t *testing.T) {
	previous := packetCaptureCommand
	childPIDPath := filepath.Join(t.TempDir(), "child.pid")
	packetCaptureCommand = func(ctx context.Context, _, _, outputPath string) *exec.Cmd {
		return exec.CommandContext(ctx, "sh", "-c", `
printf '\324\303\262\24101234567890123456789x' > "$1"
(trap '' HUP INT TERM; while :; do sleep 1; done) &
printf '%s\n' "$!" > "$2"
printf 'listening on test\n' >&2
wait
`, "capture", outputPath, childPIDPath)
	}
	t.Cleanup(func() { packetCaptureCommand = previous })

	ctx, cancel := context.WithCancel(context.Background())
	capturePath := filepath.Join(t.TempDir(), "traffic.pcap")
	capture, err := startPacketCapture(ctx, "", "lo", capturePath)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	data, err := os.ReadFile(childPIDPath)
	if err != nil {
		cancel()
		_ = capture.Stop()
		t.Fatal(err)
	}
	childPID, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || childPID <= 0 {
		cancel()
		_ = capture.Stop()
		t.Fatalf("invalid child PID %q: %v", data, err)
	}
	t.Cleanup(func() { _ = syscall.Kill(childPID, syscall.SIGKILL) })

	cancel()
	_ = capture.Stop()
	deadline := time.Now().Add(2 * time.Second)
	for processIsActive(childPID) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if processIsActive(childPID) {
		t.Fatalf("packet capture descendant PID %d remained active after context cancellation", childPID)
	}
}

func processIsActive(pid int) bool {
	err := syscall.Kill(pid, 0)
	if errors.Is(err, syscall.ESRCH) {
		return false
	}
	if err != nil {
		return true
	}
	data, readErr := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if readErr == nil {
		fields := strings.Fields(string(data))
		return len(fields) < 3 || fields[2] != "Z"
	}
	return true
}
