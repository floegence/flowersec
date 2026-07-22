package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestRaceShardRunnerCoversEveryTopLevelTestExactlyOnce(t *testing.T) {
	repoRoot := filepath.Clean(filepath.Join("..", ".."))
	runner := filepath.Join(repoRoot, "scripts", "run-go-test-race-shards.sh")
	testNames := []string{"TestAlpha", "TestBeta", "TestGamma", "TestDelta", "TestEpsilon"}

	t.Run("partitions discovered tests", func(t *testing.T) {
		tempDir := t.TempDir()
		logPath := filepath.Join(tempDir, "race-invocations.log")
		installFakeGo(t, tempDir, strings.Join(testNames, "\n")+"\n", logPath)

		cmd := exec.Command("bash", runner, tempDir, "3", "10m")
		cmd.Env = append(os.Environ(), "PATH="+tempDir+string(os.PathListSeparator)+os.Getenv("PATH"), "RACE_SHARD_LOG="+logPath)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("run race shard runner: %v\n%s", err, output)
		}

		logBytes, err := os.ReadFile(logPath)
		if err != nil {
			t.Fatalf("read fake go log: %v", err)
		}
		invocations := strings.Split(strings.TrimSpace(string(logBytes)), "\n")
		if len(invocations) != 3 {
			t.Fatalf("race invocations = %d, want 3: %q", len(invocations), invocations)
		}

		patterns := make([]*regexp.Regexp, 0, len(invocations))
		for _, invocation := range invocations {
			fields := strings.Fields(invocation)
			if !contains(fields, "-race") || !contains(fields, "-count=1") || !contains(fields, "-timeout=10m") {
				t.Fatalf("race invocation is missing required flags: %q", invocation)
			}
			pattern := flagValue(fields, "-run")
			compiled, err := regexp.Compile(pattern)
			if err != nil {
				t.Fatalf("compile shard pattern %q: %v", pattern, err)
			}
			patterns = append(patterns, compiled)
		}

		for _, name := range testNames {
			matches := 0
			for _, pattern := range patterns {
				if pattern.MatchString(name) {
					matches++
				}
			}
			if matches != 1 {
				t.Errorf("%s matched %d shards, want exactly 1", name, matches)
			}
		}
		for _, pattern := range patterns {
			if pattern.MatchString("TestUnknown") {
				t.Errorf("shard pattern %q matches an undiscovered test", pattern.String())
			}
		}
	})

	t.Run("fails closed when no tests are discovered", func(t *testing.T) {
		tempDir := t.TempDir()
		logPath := filepath.Join(tempDir, "race-invocations.log")
		installFakeGo(t, tempDir, "", logPath)

		cmd := exec.Command("bash", runner, tempDir, "3", "10m")
		cmd.Env = append(os.Environ(), "PATH="+tempDir+string(os.PathListSeparator)+os.Getenv("PATH"), "RACE_SHARD_LOG="+logPath)
		if output, err := cmd.CombinedOutput(); err == nil {
			t.Fatalf("runner succeeded without discovered tests:\n%s", output)
		}
	})
}

func installFakeGo(t *testing.T, dir, listedTests, logPath string) {
	t.Helper()
	script := `#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "test" && "${2:-}" == "-list" ]]; then
  printf '%s' "${FAKE_GO_TEST_LIST:-}"
  exit 0
fi
printf '%s\n' "$*" >> "${RACE_SHARD_LOG:?}"
`
	goPath := filepath.Join(dir, "go")
	if err := os.WriteFile(goPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake go: %v", err)
	}
	t.Setenv("FAKE_GO_TEST_LIST", listedTests)
	if err := os.WriteFile(logPath, nil, 0o600); err != nil {
		t.Fatalf("initialize fake go log: %v", err)
	}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func flagValue(fields []string, flag string) string {
	for index := 0; index+1 < len(fields); index++ {
		if fields[index] == flag {
			return fields[index+1]
		}
	}
	return ""
}
