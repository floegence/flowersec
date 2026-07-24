package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier"
)

func TestWorkloadScheduleContainsEveryIndependentRun(t *testing.T) {
	schedule := workloadSchedule(15)
	if len(schedule) != 3 {
		t.Fatalf("cell count = %d, want 3", len(schedule))
	}
	counts := map[carrier.Kind]int{}
	for _, cell := range schedule {
		counts[cell.Carrier] += len(cell.Runs)
		for index, run := range cell.Runs {
			if run != index+1 {
				t.Fatalf("invalid scheduled cell %+v", cell)
			}
		}
	}
	for _, kind := range []carrier.Kind{carrier.KindWebSocket, carrier.KindQUIC, carrier.KindWebTransport} {
		if counts[kind] != 15 {
			t.Fatalf("%s run count = %d, want 15", kind, counts[kind])
		}
	}
}

func TestVerifySourceCheckoutBindsCleanHeadAndManifest(t *testing.T) {
	root := t.TempDir()
	runGit(t, root, "init", "-q")
	runGit(t, root, "config", "user.email", "runner@example.invalid")
	runGit(t, root, "config", "user.name", "Runner Test")
	manifest := filepath.Join(root, "testdata", "transport_v2", "performance_manifest.json")
	if err := os.MkdirAll(filepath.Dir(manifest), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifest, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runGit(t, root, "add", ".")
	runGit(t, root, "commit", "-q", "-m", "test")
	head := runGit(t, root, "rev-parse", "HEAD")
	if err := verifySourceCheckout(root, manifest, head); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "dirty"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifySourceCheckout(root, manifest, head); err == nil {
		t.Fatal("accepted dirty source checkout")
	}
}

func runGit(t *testing.T, root string, args ...string) string {
	t.Helper()
	commandArgs := append([]string{"-C", root}, args...)
	command := exec.Command("git", commandArgs...)
	command.Env = make([]string, 0, len(os.Environ()))
	for _, item := range os.Environ() {
		if !strings.HasPrefix(item, "GIT_") {
			command.Env = append(command.Env, item)
		}
	}
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v: %s", strings.Join(args, " "), err, output)
	}
	return strings.TrimSpace(string(output))
}

func TestCompletedWithinRejectsExpiredContext(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if err := completedWithin(ctx, time.Now().Add(-time.Second), 2*time.Second); err == nil {
		t.Fatal("accepted completion after context deadline")
	}
}

func TestCompletedWithinRejectsElapsedLimit(t *testing.T) {
	if err := completedWithin(context.Background(), time.Now().Add(-2*time.Second), time.Second); err == nil {
		t.Fatal("accepted completion after explicit phase limit")
	}
}
