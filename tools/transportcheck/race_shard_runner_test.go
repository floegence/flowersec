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

		cmd := exec.Command("bash", runner, tempDir, "3", "5m", "2")
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
			if !contains(fields, "-test.count=1") || !contains(fields, "-test.timeout=5m") {
				t.Fatalf("race invocation is missing required flags: %q", invocation)
			}
			pattern := flagValue(fields, "-test.run")
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

	t.Run("partitions normal tests without race instrumentation", func(t *testing.T) {
		tempDir := t.TempDir()
		logPath := filepath.Join(tempDir, "normal-invocations.log")
		installFakeGo(t, tempDir, strings.Join(testNames, "\n")+"\n", logPath)

		cmd := exec.Command("bash", runner, tempDir, "3", "5m", "2", "normal")
		cmd.Env = append(os.Environ(), "PATH="+tempDir+string(os.PathListSeparator)+os.Getenv("PATH"), "RACE_SHARD_LOG="+logPath)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("run normal shard runner: %v\n%s", err, output)
		}

		logBytes, err := os.ReadFile(logPath)
		if err != nil {
			t.Fatalf("read fake go log: %v", err)
		}
		invocations := strings.Split(strings.TrimSpace(string(logBytes)), "\n")
		if len(invocations) != 3 {
			t.Fatalf("normal invocations = %d, want 3: %q", len(invocations), invocations)
		}
		for _, invocation := range invocations {
			fields := strings.Fields(invocation)
			if !contains(fields, "-test.count=1") || !contains(fields, "-test.timeout=5m") {
				t.Fatalf("normal invocation has incorrect flags: %q", invocation)
			}
		}
	})

	t.Run("rejects invalid parallelism", func(t *testing.T) {
		tempDir := t.TempDir()
		logPath := filepath.Join(tempDir, "race-invocations.log")
		installFakeGo(t, tempDir, strings.Join(testNames, "\n")+"\n", logPath)

		cmd := exec.Command("bash", runner, tempDir, "3", "5m", "0")
		cmd.Env = append(os.Environ(), "PATH="+tempDir+string(os.PathListSeparator)+os.Getenv("PATH"), "RACE_SHARD_LOG="+logPath)
		output, err := cmd.CombinedOutput()
		if err == nil || !strings.Contains(string(output), "parallelism must be a positive integer") {
			t.Fatalf("runner parallelism validation = %v\n%s", err, output)
		}
	})

	t.Run("fails closed when no tests are discovered", func(t *testing.T) {
		tempDir := t.TempDir()
		logPath := filepath.Join(tempDir, "race-invocations.log")
		installFakeGo(t, tempDir, "", logPath)

		cmd := exec.Command("bash", runner, tempDir, "3", "5m")
		cmd.Env = append(os.Environ(), "PATH="+tempDir+string(os.PathListSeparator)+os.Getenv("PATH"), "RACE_SHARD_LOG="+logPath, "TMPDIR="+tempDir)
		if output, err := cmd.CombinedOutput(); err == nil {
			t.Fatalf("runner succeeded without discovered tests:\n%s", output)
		}
	})

	t.Run("retains shard logs on failure", func(t *testing.T) {
		tempDir := t.TempDir()
		logPath := filepath.Join(tempDir, "race-invocations.log")
		installFakeGo(t, tempDir, strings.Join(testNames, "\n")+"\n", logPath)

		cmd := exec.Command("bash", runner, tempDir, "3", "5m", "2")
		cmd.Env = append(os.Environ(), "PATH="+tempDir+string(os.PathListSeparator)+os.Getenv("PATH"), "RACE_SHARD_LOG="+logPath, "FAKE_GO_TEST_FAIL=1")
		output, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatalf("race shard runner succeeded despite a shard failure:\n%s", output)
		}
		const marker = "race shard logs retained at "
		markerIndex := strings.LastIndex(string(output), marker)
		if markerIndex < 0 {
			t.Fatalf("race shard runner did not report retained logs:\n%s", output)
		}
		artifactDir := strings.TrimSpace(string(output)[markerIndex+len(marker):])
		t.Cleanup(func() { _ = os.RemoveAll(artifactDir) })
		if info, statErr := os.Stat(filepath.Join(artifactDir, "shard-0.log")); statErr != nil || info.Size() == 0 {
			t.Fatalf("retained shard log is unavailable: %v", statErr)
		}
	})

	t.Run("rejects a timeout above five minutes", func(t *testing.T) {
		tempDir := t.TempDir()
		logPath := filepath.Join(tempDir, "race-invocations.log")
		installFakeGo(t, tempDir, strings.Join(testNames, "\n")+"\n", logPath)

		cmd := exec.Command("bash", runner, tempDir, "3", "6m")
		cmd.Env = append(os.Environ(), "PATH="+tempDir+string(os.PathListSeparator)+os.Getenv("PATH"), "RACE_SHARD_LOG="+logPath)
		output, err := cmd.CombinedOutput()
		if err == nil || !strings.Contains(string(output), "between 1m and 5m") {
			t.Fatalf("runner timeout validation = %v\n%s", err, output)
		}
	})
}

func TestRaceShardRunnerRefillsAvailableSlotsWithoutBatchBarrier(t *testing.T) {
	repoRoot := filepath.Clean(filepath.Join("..", ".."))
	runner := filepath.Join(repoRoot, "scripts", "run-go-test-race-shards.sh")
	tempDir := t.TempDir()
	logPath := filepath.Join(tempDir, "timeline.log")
	goPath := filepath.Join(tempDir, "go")
	script := `#!/usr/bin/env bash
set -euo pipefail
output=""
while (( $# > 0 )); do
  if [[ "$1" == "-o" ]]; then output="${2:-}"; shift; fi
  shift
done
cat > "$output" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "-test.list" ]]; then
  printf 'TestSlow\nTestFastOne\nTestFastTwo\n'
  exit 0
fi
pattern=""
while (( $# > 0 )); do
  if [[ "$1" == "-test.run" ]]; then pattern="${2:-}"; break; fi
  shift
done
printf 'start %s\n' "$pattern" >> "${RACE_SHARD_LOG:?}"
if [[ "$pattern" == *TestSlow* ]]; then
  sleep 0.6
else
  sleep 0.05
fi
printf 'end %s\n' "$pattern" >> "${RACE_SHARD_LOG:?}"
EOF
chmod +x "$output"
`
	if err := os.WriteFile(goPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write timed fake go: %v", err)
	}
	if err := os.WriteFile(logPath, nil, 0o600); err != nil {
		t.Fatalf("initialize timeline log: %v", err)
	}

	cmd := exec.Command("bash", runner, tempDir, "3", "1m", "2", "race", "1")
	cmd.Env = append(os.Environ(), "PATH="+tempDir+string(os.PathListSeparator)+os.Getenv("PATH"), "RACE_SHARD_LOG="+logPath)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("run timed race shard runner: %v\n%s", err, output)
	}

	eventsBytes, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read timeline log: %v", err)
	}
	events := strings.Split(strings.TrimSpace(string(eventsBytes)), "\n")
	fastTwoStart := eventIndex(events, "start ^(TestFastTwo)$")
	slowEnd := eventIndex(events, "end ^(TestSlow)$")
	if fastTwoStart < 0 || slowEnd < 0 {
		t.Fatalf("timeline is missing required events: %q", events)
	}
	if fastTwoStart > slowEnd {
		t.Fatalf("next shard started only after the whole batch completed: %q", events)
	}
}

func TestRaceShardRunnerAutoCreatesOneShardPerTest(t *testing.T) {
	repoRoot := filepath.Clean(filepath.Join("..", ".."))
	runner := filepath.Join(repoRoot, "scripts", "run-go-test-race-shards.sh")
	tempDir := t.TempDir()
	logPath := filepath.Join(tempDir, "race-invocations.log")
	testNames := []string{"TestOne", "TestTwo", "TestThree", "TestFour"}
	installFakeGo(t, tempDir, strings.Join(testNames, "\n")+"\n", logPath)

	cmd := exec.Command("bash", runner, tempDir, "auto", "1m", "2", "race", "1")
	cmd.Env = append(os.Environ(), "PATH="+tempDir+string(os.PathListSeparator)+os.Getenv("PATH"), "RACE_SHARD_LOG="+logPath, "FAKE_GO_TEST_LIST="+strings.Join(testNames, "\n")+"\n")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("run auto-sharded race runner: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "4 tests across 4 shards") {
		t.Fatalf("auto shard summary = %s", output)
	}
	invocations, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range testNames {
		if count := strings.Count(string(invocations), "^("+name+")$"); count != 1 {
			t.Fatalf("%s invocation count = %d, want 1\n%s", name, count, invocations)
		}
	}
}

func TestRaceShardRunnerOrdersTestsBySourceCost(t *testing.T) {
	repoRoot := filepath.Clean(filepath.Join("..", ".."))
	runner := filepath.Join(repoRoot, "scripts", "run-go-test-race-shards.sh")
	tempDir := t.TempDir()
	logPath := filepath.Join(tempDir, "race-invocations.log")
	installFakeGo(t, tempDir, "TestShort\nTestLong\nTestMedium\n", logPath)
	source := `package cost

func TestShort(t any) {}

func TestLong(t any) {
	_ = 1
	_ = 2
	_ = 3
	_ = 4
	_ = 5
}

func TestMedium(t any) {
	_ = 1
	_ = 2
}
`
	if err := os.WriteFile(filepath.Join(tempDir, "cost_test.go"), []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", runner, tempDir, "3", "1m", "1", "normal", "1")
	cmd.Env = append(os.Environ(), "PATH="+tempDir+string(os.PathListSeparator)+os.Getenv("PATH"), "RACE_SHARD_LOG="+logPath, "TMPDIR="+tempDir)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("runner failed: %v\n%s", err, output)
	}
	lines, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	invocations := strings.Split(strings.TrimSpace(string(lines)), "\n")
	if len(invocations) != 3 {
		t.Fatalf("invocations = %d, want 3: %q", len(invocations), invocations)
	}
	want := []string{"TestLong", "TestMedium", "TestShort"}
	for index, name := range want {
		if !strings.Contains(invocations[index], name) {
			t.Fatalf("invocation %d = %q, want %s first", index, invocations[index], name)
		}
	}
}

func TestRaceShardRunnerPrioritizesCompleteReportFixtures(t *testing.T) {
	repoRoot := filepath.Clean(filepath.Join("..", ".."))
	runner := filepath.Join(repoRoot, "scripts", "run-go-test-race-shards.sh")
	tempDir := t.TempDir()
	logPath := filepath.Join(tempDir, "race-invocations.log")
	installFakeGo(t, tempDir, "TestLongDefault\nTestFixtureHeavy\nTestShort\n", logPath)
	source := `package cost

func TestLongDefault(t any) {
	_ = 1
	_ = 2
	_ = 3
	_ = 4
	_ = 5
}

func TestFixtureHeavy(t any) {
	report := completeReport(t, nil, nil)
	_ = report
}

func TestShort(t any) {}
`
	if err := os.WriteFile(filepath.Join(tempDir, "cost_test.go"), []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", runner, tempDir, "auto", "1m", "1", "normal", "1")
	cmd.Env = append(os.Environ(), "PATH="+tempDir+string(os.PathListSeparator)+os.Getenv("PATH"), "RACE_SHARD_LOG="+logPath, "TMPDIR="+tempDir)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("runner failed: %v\n%s", err, output)
	}
	lines, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	invocations := strings.Split(strings.TrimSpace(string(lines)), "\n")
	if len(invocations) != 3 {
		t.Fatalf("invocations = %d, want 3: %q", len(invocations), invocations)
	}
	if !strings.Contains(invocations[0], "TestFixtureHeavy") {
		t.Fatalf("first invocation = %q, want completeReport fixture test", invocations[0])
	}
}

func TestRaceShardRunnerOrdersFixtureTierBySourceCost(t *testing.T) {
	repoRoot := filepath.Clean(filepath.Join("..", ".."))
	runner := filepath.Join(repoRoot, "scripts", "run-go-test-race-shards.sh")
	tempDir := t.TempDir()
	logPath := filepath.Join(tempDir, "race-invocations.log")
	installFakeGo(t, tempDir, "TestShortFixture\nTestLongFixture\n", logPath)
	source := `package cost

func TestShortFixture(t any) {
	report := completeReport(t, nil, nil)
	_ = report
}

func TestLongFixture(t any) {
	report := completeReport(t, nil, nil)
	_ = report
	_ = 1
	_ = 2
	_ = 3
	_ = 4
}
`
	if err := os.WriteFile(filepath.Join(tempDir, "cost_test.go"), []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", runner, tempDir, "auto", "1m", "1", "normal", "1")
	cmd.Env = append(os.Environ(), "PATH="+tempDir+string(os.PathListSeparator)+os.Getenv("PATH"), "RACE_SHARD_LOG="+logPath, "TMPDIR="+tempDir)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("runner failed: %v\n%s", err, output)
	}
	lines, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	invocations := strings.Split(strings.TrimSpace(string(lines)), "\n")
	if len(invocations) != 2 {
		t.Fatalf("invocations = %d, want 2: %q", len(invocations), invocations)
	}
	if !strings.Contains(invocations[0], "TestLongFixture") {
		t.Fatalf("first invocation = %q, want longer fixture-tier test", invocations[0])
	}
}

func TestRaceShardRunnerHonorsExplicitHighCostAnnotations(t *testing.T) {
	repoRoot := filepath.Clean(filepath.Join("..", ".."))
	runner := filepath.Join(repoRoot, "scripts", "run-go-test-race-shards.sh")
	tempDir := t.TempDir()
	logPath := filepath.Join(tempDir, "race-invocations.log")
	installFakeGo(t, tempDir, "TestLongDefault\nTestMeasuredHighCost\n", logPath)
	source := `package cost

func TestLongDefault(t any) {
	_ = 1
	_ = 2
	_ = 3
	_ = 4
	_ = 5
}

// flowersec:race-cost=high
func TestMeasuredHighCost(t any) {}
`
	if err := os.WriteFile(filepath.Join(tempDir, "cost_test.go"), []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", runner, tempDir, "auto", "1m", "1", "normal", "1")
	cmd.Env = append(os.Environ(), "PATH="+tempDir+string(os.PathListSeparator)+os.Getenv("PATH"), "RACE_SHARD_LOG="+logPath, "TMPDIR="+tempDir)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("runner failed: %v\n%s", err, output)
	}
	lines, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	invocations := strings.Split(strings.TrimSpace(string(lines)), "\n")
	if len(invocations) != 2 {
		t.Fatalf("invocations = %d, want 2: %q", len(invocations), invocations)
	}
	if !strings.Contains(invocations[0], "TestMeasuredHighCost") {
		t.Fatalf("first invocation = %q, want explicitly high-cost test", invocations[0])
	}
}

func TestRaceShardRunnerStartsCriticalCostBeforeHighCost(t *testing.T) {
	repoRoot := filepath.Clean(filepath.Join("..", ".."))
	runner := filepath.Join(repoRoot, "scripts", "run-go-test-race-shards.sh")
	tempDir := t.TempDir()
	logPath := filepath.Join(tempDir, "race-invocations.log")
	installFakeGo(t, tempDir, "TestLongDefault\nTestMeasuredHighCost\nTestMeasuredCriticalCost\n", logPath)
	source := `package cost

func TestLongDefault(t any) {
	_ = 1
	_ = 2
	_ = 3
	_ = 4
	_ = 5
}

// flowersec:race-cost=high
func TestMeasuredHighCost(t any) {}

// flowersec:race-cost=critical
func TestMeasuredCriticalCost(t any) {}
`
	if err := os.WriteFile(filepath.Join(tempDir, "cost_test.go"), []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", runner, tempDir, "auto", "1m", "1", "normal", "1")
	cmd.Env = append(os.Environ(), "PATH="+tempDir+string(os.PathListSeparator)+os.Getenv("PATH"), "RACE_SHARD_LOG="+logPath, "TMPDIR="+tempDir)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("runner failed: %v\n%s", err, output)
	}
	lines, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	invocations := strings.Split(strings.TrimSpace(string(lines)), "\n")
	if len(invocations) != 3 {
		t.Fatalf("invocations = %d, want 3: %q", len(invocations), invocations)
	}
	if !strings.Contains(invocations[0], "TestMeasuredCriticalCost") {
		t.Fatalf("first invocation = %q, want explicitly critical-cost test", invocations[0])
	}
	if !strings.Contains(invocations[1], "TestMeasuredHighCost") {
		t.Fatalf("second invocation = %q, want explicitly high-cost test", invocations[1])
	}
}

func TestRaceShardRunnerBuildsOneBinaryForAllShards(t *testing.T) {
	repoRoot := filepath.Clean(filepath.Join("..", ".."))
	runner := filepath.Join(repoRoot, "scripts", "run-go-test-race-shards.sh")
	tempDir := t.TempDir()
	logPath := filepath.Join(tempDir, "race-invocations.log")
	goPath := filepath.Join(tempDir, "go")
	script := `#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "test" && "${2:-}" == "-list" ]]; then
  printf 'TestOne\nTestTwo\nTestThree\nTestFour\n'
  exit 0
fi
if [[ "${1:-}" == "test" ]]; then
  output=""
  compile=0
  while (( $# > 0 )); do
    if [[ "$1" == "-c" ]]; then compile=1; fi
    if [[ "$1" == "-o" ]]; then output="${2:-}"; shift; fi
    shift
  done
  if (( compile == 1 )); then
    printf 'compile\n' >> "${RACE_SHARD_LOG:?}"
    cat > "$output" <<'EOF'
#!/usr/bin/env bash
if [[ "$*" == *"-test.list"* ]]; then
  printf 'TestOne\nTestTwo\nTestThree\nTestFour\n'
  exit 0
fi
printf 'binary %s\n' "$*" >> "${RACE_SHARD_LOG:?}"
EOF
    chmod +x "$output"
    exit 0
  fi
  printf 'go-shard\n' >> "${RACE_SHARD_LOG:?}"
  exit 0
fi
exit 2
`
	if err := os.WriteFile(goPath, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", runner, tempDir, "auto", "1m", "2", "race", "1")
	cmd.Env = append(os.Environ(), "PATH="+tempDir+string(os.PathListSeparator)+os.Getenv("PATH"), "RACE_SHARD_LOG="+logPath, "TMPDIR="+tempDir)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("runner failed: %v\n%s", err, output)
	}
	logBytes, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(logBytes)), "\n")
	compileCount, binaryCount, goShardCount := 0, 0, 0
	for _, line := range lines {
		switch {
		case line == "compile":
			compileCount++
		case strings.HasPrefix(line, "binary "):
			binaryCount++
		case line == "go-shard":
			goShardCount++
		}
	}
	if compileCount != 1 || binaryCount != 4 || goShardCount != 0 {
		t.Fatalf("race build invocations = compile:%d binary:%d go-shard:%d; log=%q", compileCount, binaryCount, goShardCount, string(logBytes))
	}
}

func TestRaceShardRunnerStopsSchedulingAfterFirstFailure(t *testing.T) {
	repoRoot := filepath.Clean(filepath.Join("..", ".."))
	runner := filepath.Join(repoRoot, "scripts", "run-go-test-race-shards.sh")
	tempDir := t.TempDir()
	logPath := filepath.Join(tempDir, "race-invocations.log")
	goPath := filepath.Join(tempDir, "go")
	script := `#!/usr/bin/env bash
set -euo pipefail
output=""
while (( $# > 0 )); do
  if [[ "$1" == "-o" ]]; then output="${2:-}"; shift; fi
  shift
done
cat > "$output" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "-test.list" ]]; then
  printf 'TestOne\nTestTwo\nTestThree\nTestFour\n'
  exit 0
fi
pattern=""
while (( $# > 0 )); do
  if [[ "$1" == "-test.run" ]]; then pattern="${2:-}"; break; fi
  shift
done
printf '%s\n' "$pattern" >> "${RACE_SHARD_LOG:?}"
if [[ "$pattern" == *TestOne* ]]; then exit 42; fi
sleep 0.1
EOF
chmod +x "$output"
`
	if err := os.WriteFile(goPath, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", runner, tempDir, "auto", "1m", "2", "race", "1")
	cmd.Env = append(os.Environ(), "PATH="+tempDir+string(os.PathListSeparator)+os.Getenv("PATH"), "RACE_SHARD_LOG="+logPath, "TMPDIR="+tempDir)
	if output, err := cmd.CombinedOutput(); err == nil {
		t.Fatalf("runner succeeded despite shard failure:\n%s", output)
	}
	invocations, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if lines := strings.Fields(string(invocations)); len(lines) != 2 {
		t.Fatalf("runner scheduled work after first failure: %q", invocations)
	}
}

func installFakeGo(t *testing.T, dir, listedTests, logPath string) {
	t.Helper()
	script := `#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "test" && "${2:-}" == "-list" ]]; then
  printf '%s' "${FAKE_GO_TEST_LIST:-}"
  exit 0
fi
if [[ "${1:-}" == "test" ]]; then
  output=""
  compile=0
  while (( $# > 0 )); do
    if [[ "$1" == "-c" ]]; then compile=1; fi
    if [[ "$1" == "-o" ]]; then output="${2:-}"; shift; fi
    shift
  done
  if (( compile == 1 )); then
    cat > "$output" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "-test.list" ]]; then
  printf '%s' "${FAKE_GO_TEST_LIST:-}"
  exit 0
fi
printf '%s\n' "$*" >> "${RACE_SHARD_LOG:?}"
if [[ "${FAKE_GO_TEST_FAIL:-}" == "1" ]]; then exit 1; fi
EOF
    chmod +x "$output"
    exit 0
  fi
fi
exit 2
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

func eventIndex(events []string, want string) int {
	for index, event := range events {
		if event == want {
			return index
		}
	}
	return -1
}

func flagValue(fields []string, flag string) string {
	for index := 0; index+1 < len(fields); index++ {
		if fields[index] == flag {
			return fields[index+1]
		}
	}
	return ""
}
