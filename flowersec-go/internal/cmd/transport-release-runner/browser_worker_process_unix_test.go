//go:build unix

package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"testing"
	"time"
)

func TestConfigureBrowserWorkerCommandAllowsSignalCleanup(t *testing.T) {
	if os.Getenv("FLOWERSEC_BROWSER_WORKER_SIGNAL_HELPER") == "1" {
		runBrowserWorkerSignalHelper()
		return
	}
	directory := t.TempDir()
	readyPath := filepath.Join(directory, "ready")
	cleanupPath := filepath.Join(directory, "cleanup")
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	command := exec.CommandContext(ctx, executable, "-test.run=^TestConfigureBrowserWorkerCommandAllowsSignalCleanup$")
	command.Env = append(os.Environ(),
		"FLOWERSEC_BROWSER_WORKER_SIGNAL_HELPER=1",
		"FLOWERSEC_BROWSER_WORKER_READY="+readyPath,
		"FLOWERSEC_BROWSER_WORKER_CLEANUP="+cleanupPath,
	)
	configureBrowserWorkerCommand(command)
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	waitForTestPath(t, readyPath)
	cancel()
	if err := command.Wait(); !errors.Is(err, context.Canceled) {
		t.Fatalf("worker wait = %v, want context.Canceled", err)
	}
	if _, err := os.Stat(cleanupPath); err != nil {
		t.Fatalf("worker cleanup marker: %v", err)
	}
}

func runBrowserWorkerSignalHelper() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := os.WriteFile(os.Getenv("FLOWERSEC_BROWSER_WORKER_READY"), []byte("ready\n"), 0o600); err != nil {
		os.Exit(2)
	}
	<-ctx.Done()
	if err := os.WriteFile(os.Getenv("FLOWERSEC_BROWSER_WORKER_CLEANUP"), []byte("cleanup\n"), 0o600); err != nil {
		os.Exit(3)
	}
}

func waitForTestPath(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", path)
}
