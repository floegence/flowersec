package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRustProbeDirectoriesAreIsolated(t *testing.T) {
	repoRoot := t.TempDir()
	first, err := createRustProbeDir(repoRoot)
	if err != nil {
		t.Fatalf("create first probe directory: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(first) })

	second, err := createRustProbeDir(repoRoot)
	if err != nil {
		t.Fatalf("create second probe directory: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(second) })

	if first == second {
		t.Fatalf("concurrent Rust probes share scratch directory %q", first)
	}
	sentinel := filepath.Join(second, "still-present")
	if err := os.WriteFile(sentinel, []byte("ok"), 0o600); err != nil {
		t.Fatalf("write second probe sentinel: %v", err)
	}
	if err := os.RemoveAll(first); err != nil {
		t.Fatalf("remove first probe directory: %v", err)
	}
	if _, err := os.Stat(sentinel); err != nil {
		t.Fatalf("cleaning one Rust probe affected another: %v", err)
	}
}
