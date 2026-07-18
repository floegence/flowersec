package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
)

func TestCoverageQualityGates(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	m, err := loadManifest(root)
	if err != nil {
		t.Fatal(err)
	}

	wantGo := map[string]float64{
		"github.com/floegence/flowersec/flowersec-go/controlplane/http":   74,
		"github.com/floegence/flowersec/flowersec-go/controlplane/issuer": 78,
		"github.com/floegence/flowersec/flowersec-go/protocolio":          69,
		"github.com/floegence/flowersec/flowersec-go/tunnel/server":       69,
	}
	gotGo := make(map[string]float64, len(m.Coverage.Go))
	for _, target := range m.Coverage.Go {
		gotGo[target.Package] = target.MinStatementsPct
	}
	for pkg, want := range wantGo {
		if got := gotGo[pkg]; got != want {
			t.Errorf("Go coverage threshold for %s = %.1f, want %.1f", pkg, got, want)
		}
	}

	if got, want := m.Coverage.TS, (tsCoverageTarget{Lines: 82, Functions: 82, Statements: 77, Branches: 68}); got != want {
		t.Errorf("TypeScript coverage thresholds = %+v, want %+v", got, want)
	}

	assertFileThresholds(t, filepath.Join(root, "flowersec-ts", "vitest.config.ts"), map[string]int{
		"lines": 82, "functions": 82, "statements": 77, "branches": 68,
	})
	assertMakeThreshold(t, filepath.Join(root, "Makefile"), `check-swift-coverage\.mjs[^\n]*\$\$coverage_path"\s+(\d+)\s+(\d+)`, []int{79, 80})
	assertMakeThreshold(t, filepath.Join(root, "Makefile"), `cargo llvm-cov[^\n]*--fail-under-lines\s+(\d+)`, []int{85})
}

func assertFileThresholds(t *testing.T, path string, want map[string]int) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for name, threshold := range want {
		re := regexp.MustCompile(name + `:\s*(\d+)`)
		match := re.FindSubmatch(b)
		if len(match) != 2 {
			t.Errorf("missing %s threshold in %s", name, path)
			continue
		}
		got, err := strconv.Atoi(string(match[1]))
		if err != nil {
			t.Fatal(err)
		}
		if got != threshold {
			t.Errorf("%s threshold in %s = %d, want %d", name, path, got, threshold)
		}
	}
}

func assertMakeThreshold(t *testing.T, path, pattern string, want []int) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	match := regexp.MustCompile(pattern).FindSubmatch(b)
	if len(match) != len(want)+1 {
		t.Fatalf("threshold pattern %q not found in %s", pattern, path)
	}
	for i, threshold := range want {
		got, err := strconv.Atoi(string(match[i+1]))
		if err != nil {
			t.Fatal(err)
		}
		if got != threshold {
			t.Errorf("threshold %d in %s = %d, want %d", i, path, got, threshold)
		}
	}
}
