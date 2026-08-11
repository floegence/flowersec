package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const testSourceSHA = "0123456789abcdef0123456789abcdef01234567"

func TestExactTitleMatchesOnlyTheCompleteTitle(t *testing.T) {
	title := "runs direct admission and Session semantics over WSS"
	pattern := regexp.MustCompile(exactTitle(title))
	if !pattern.MatchString(title) {
		t.Fatal("exact title did not match itself")
	}
	for _, value := range []string{"prefix " + title, title + " suffix"} {
		if pattern.MatchString(value) {
			t.Fatalf("exact title matched %q", value)
		}
	}
}

func TestPlaywrightTitleMatchesAUniqueTitleInsideTheFullTestName(t *testing.T) {
	title := "Firefox reports unsupported native WebTransport connection"
	pattern := regexp.MustCompile(playwrightTitle(title))
	if !pattern.MatchString("transport-v2.spec.ts › " + title) {
		t.Fatal("Playwright selector did not match the full test name")
	}
	if pattern.MatchString("Firefox reports another capability") {
		t.Fatal("Playwright selector matched a different title")
	}
}

func TestVitestEntryUsesRepositoryConfigFromTheRunnerRoot(t *testing.T) {
	entry := vitestEntry("test/typescript", "acceptance", "src/example.test.ts", "exact title")
	if entry.ID != "test/typescript" || entry.Suite != "acceptance" || entry.Timeout != 5*time.Minute {
		t.Fatalf("entry identity = %+v", entry)
	}
	want := []string{"--prefix", "flowersec-ts", "exec", "--", "vitest", "run", "--config", "flowersec-ts/vitest.config.ts", "flowersec-ts/src/example.test.ts", "-t", "^exact title$"}
	if got := vitestArguments("src/example.test.ts", "exact title"); strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("vitest arguments = %q, want %q", got, want)
	}
}

func TestPerformanceRegistryUsesCanonicalRunIDEnvironment(t *testing.T) {
	capacityEntries := 0
	for _, test := range registry() {
		if test.Suite != "performance" || !strings.HasPrefix(test.ID, "performance/capacity/") {
			continue
		}
		capacityEntries++
		runID, err := newRunID(test.ID)
		if err != nil {
			t.Fatalf("%s: generate run ID: %v", test.ID, err)
		}
		if !strings.HasPrefix(runID, safeName(test.ID)+"-") {
			t.Fatalf("%s: run ID %q does not use canonical test prefix", test.ID, runID)
		}
		parts := withRunID(performanceCapacityEnvironment("CAP-TEST"), runID)
		if len(parts) != 2 || parts[0] != "FLOWERSEC_TEST_CAPACITY_CASE=CAP-TEST" || parts[1] != "FLOWERSEC_TEST_RUN_ID="+runID {
			t.Fatalf("%s: capacity environment = %#v", test.ID, parts)
		}
	}
	if capacityEntries != 12 {
		t.Fatalf("capacity registry entries = %d, want 12", capacityEntries)
	}
}

func TestRegistryEntriesSatisfyRunnerBounds(t *testing.T) {
	if _, err := selectSuite(registry(), "acceptance"); err != nil {
		t.Fatalf("registry validation failed: %v", err)
	}
}

func acceptanceProgress(completed ...string) progress {
	return progress{Plan: planName, SourceSHA: testSourceSHA, Suite: "acceptance", Completed: completed}
}

func testRegistry(runA, runB func(context.Context, runContext) error) []registeredTest {
	return []registeredTest{
		{ID: "test/a", Suite: "acceptance", Timeout: time.Second, Run: runA},
		{ID: "test/b", Suite: "acceptance", Timeout: time.Second, Run: runB},
	}
}

func TestRedDoesNotAdvanceAndResumeRunsTheFirstIncompleteTest(t *testing.T) {
	state := t.TempDir()
	progressPath := filepath.Join(state, "acceptance.json")
	var aRuns, bRuns atomic.Int32
	tests := testRegistry(
		func(context.Context, runContext) error { aRuns.Add(1); return nil },
		func(context.Context, runContext) error {
			if bRuns.Add(1) == 1 {
				return errors.New("observed first failure")
			}
			return nil
		},
	)
	var stdout, stderr bytes.Buffer
	if err := executeSuite(context.Background(), &stdout, &stderr, "run", progressPath, t.TempDir(), "acceptance", testSourceSHA, tests, false); err == nil {
		t.Fatal("RED suite returned success")
	}
	current, err := readProgress(progressPath, tests, "acceptance")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(current.Completed, ","); got != "test/a" {
		t.Fatalf("completed after RED = %q", got)
	}
	if current.SourceSHA != testSourceSHA || current.Suite != "acceptance" {
		t.Fatalf("progress identity = %q/%q", current.SourceSHA, current.Suite)
	}
	if next := firstIncomplete(tests, current.Completed); next == nil || next.ID != "test/b" {
		t.Fatalf("next after RED = %+v", next)
	}
	if err := executeSuite(context.Background(), &stdout, &stderr, "resume", progressPath, t.TempDir(), "acceptance", testSourceSHA, tests, false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(progressPath); !errors.Is(err, os.ErrNotExist) || aRuns.Load() != 1 || bRuns.Load() != 2 {
		t.Fatalf("completed progress=%v runs=%d/%d", err, aRuns.Load(), bRuns.Load())
	}
}

func TestResumeContinuesThroughAllIncompleteTests(t *testing.T) {
	state := t.TempDir()
	progressPath := filepath.Join(state, "acceptance.json")
	var aRuns, bRuns, cRuns atomic.Int32
	tests := []registeredTest{
		{ID: "test/a", Suite: "acceptance", Timeout: time.Second, Run: func(context.Context, runContext) error { aRuns.Add(1); return nil }},
		{ID: "test/b", Suite: "acceptance", Timeout: time.Second, Run: func(context.Context, runContext) error { bRuns.Add(1); return nil }},
		{ID: "test/c", Suite: "acceptance", Timeout: time.Second, Run: func(context.Context, runContext) error { cRuns.Add(1); return nil }},
	}
	if err := writeProgress(progressPath, acceptanceProgress("test/a"), tests); err != nil {
		t.Fatal(err)
	}
	if err := executeSuite(context.Background(), ioDiscard{}, ioDiscard{}, "resume", progressPath, t.TempDir(), "acceptance", testSourceSHA, tests, false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(progressPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("completed progress remains: %v", err)
	}
	if aRuns.Load() != 0 || bRuns.Load() != 1 || cRuns.Load() != 1 {
		t.Fatalf("resume runs=%d/%d/%d", aRuns.Load(), bRuns.Load(), cRuns.Load())
	}
}

func TestRunAlwaysStartsFreshAndProgressHasOnlyIdentityAndCompleted(t *testing.T) {
	state := t.TempDir()
	progressPath := filepath.Join(state, "acceptance.json")
	var runs atomic.Int32
	tests := testRegistry(
		func(context.Context, runContext) error { runs.Add(1); return nil },
		func(context.Context, runContext) error { runs.Add(1); return nil },
	)
	if err := writeProgress(progressPath, acceptanceProgress("test/a", "test/b"), tests); err != nil {
		t.Fatal(err)
	}
	if err := executeSuite(context.Background(), ioDiscard{}, ioDiscard{}, "run", progressPath, t.TempDir(), "acceptance", testSourceSHA, tests, false); err != nil {
		t.Fatal(err)
	}
	if runs.Load() != 2 {
		t.Fatalf("fresh run executed %d tests", runs.Load())
	}
	if _, err := os.Stat(progressPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("completed progress remains: %v", err)
	}
}

func TestResumeStartsFreshWhenSourceSHAChanges(t *testing.T) {
	state := t.TempDir()
	progressPath := filepath.Join(state, "acceptance.json")
	var firstRuns atomic.Int32
	var secondRuns atomic.Int32
	tests := testRegistry(
		func(context.Context, runContext) error { firstRuns.Add(1); return nil },
		func(context.Context, runContext) error {
			secondRuns.Add(1)
			return errors.New("current source failure")
		},
	)
	old := acceptanceProgress("test/a")
	old.SourceSHA = "abcdef0123456789abcdef0123456789abcdef01"
	if err := writeProgress(progressPath, old, tests); err != nil {
		t.Fatal(err)
	}
	stale := failurePath(progressPath, "test/a")
	if err := atomicWrite(stale, []byte("old source failure\n")); err != nil {
		t.Fatal(err)
	}
	if err := executeSuite(context.Background(), ioDiscard{}, ioDiscard{}, "resume", progressPath, t.TempDir(), "acceptance", testSourceSHA, tests, false); err == nil || !strings.Contains(err.Error(), "current source failure") {
		t.Fatalf("resume error = %v", err)
	}
	current, err := readProgress(progressPath, tests, "acceptance")
	if err != nil {
		t.Fatal(err)
	}
	if current.SourceSHA != testSourceSHA || strings.Join(current.Completed, ",") != "test/a" || firstRuns.Load() != 0 || secondRuns.Load() != 1 {
		t.Fatalf("resumed progress = %+v runs=%d/%d", current, firstRuns.Load(), secondRuns.Load())
	}
	if _, err := os.Stat(stale); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("resume retained old-source failure log: %v", err)
	}
}

func TestStatusMigratesSourceSHAWithoutDroppingCompletedIDs(t *testing.T) {
	state := t.TempDir()
	progressPath := filepath.Join(state, "acceptance.json")
	tests := testRegistry(func(context.Context, runContext) error { return nil }, func(context.Context, runContext) error { return nil })
	old := acceptanceProgress("test/a")
	old.SourceSHA = "abcdef0123456789abcdef0123456789abcdef01"
	if err := writeProgress(progressPath, old, tests); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := printStatus(&output, progressPath, tests, "acceptance", testSourceSHA); err != nil {
		t.Fatal(err)
	}
	current, err := readProgress(progressPath, tests, "acceptance")
	if err != nil {
		t.Fatal(err)
	}
	if current.SourceSHA != testSourceSHA || strings.Join(current.Completed, ",") != "test/a" || !strings.Contains(output.String(), `"next":"test/b"`) {
		t.Fatalf("migrated status=%+v output=%s", current, output.String())
	}
}

func TestSuccessfulRunRemovesTempDirectoryAndFailureLog(t *testing.T) {
	state := t.TempDir()
	progressPath := filepath.Join(state, "acceptance.json")
	var created string
	tests := []registeredTest{{ID: "test/green", Suite: "acceptance", Timeout: time.Second, Run: func(_ context.Context, run runContext) error {
		created = run.TempDir
		return os.WriteFile(filepath.Join(run.TempDir, "scratch"), []byte("temporary"), 0o600)
	}}}
	if err := atomicWrite(failurePath(progressPath, tests[0].ID), []byte("old failure\n")); err != nil {
		t.Fatal(err)
	}
	if err := executeSuite(context.Background(), ioDiscard{}, ioDiscard{}, "run", progressPath, t.TempDir(), "acceptance", testSourceSHA, tests, false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(created); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("successful temp directory remains: %v", err)
	}
	if _, err := os.Stat(failurePath(progressPath, tests[0].ID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("successful failure log remains: %v", err)
	}
}

func TestCancelledCommandReceivesTermAndIsWaited(t *testing.T) {
	directory := t.TempDir()
	marker := filepath.Join(directory, "descendant-terminated")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- runCommand(ctx, directory, []string{"MARKER=" + marker}, "sh", "-c", `trap 'exit 0' TERM; sh -c 'trap '\''sleep 0.2; touch "$MARKER"; exit 0'\'' TERM; while :; do sleep 1; done' & wait`)
	}()
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err == nil || !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled command = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cancelled command was not waited")
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("descendant teardown did not finish before the runner returned: %v", err)
	}
}

func TestCancelledGoTestFinishesTestOwnedCleanup(t *testing.T) {
	directory := t.TempDir()
	ready := filepath.Join(directory, "ready")
	cleaned := filepath.Join(directory, "cleaned")
	workingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- runCommand(ctx, workingDirectory, []string{
			"FLOWERSEC_SIGNAL_READY=" + ready,
			"FLOWERSEC_SIGNAL_CLEANED=" + cleaned,
		}, "go", "test", "-count=1", "./testdata/signalcleanup")
	}()
	deadline := time.Now().Add(30 * time.Second)
	for !regularFile(ready) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !regularFile(ready) {
		cancel()
		<-done
		t.Fatal("Go child test did not become ready")
	}
	cancel()
	if err := <-done; err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled Go test = %v", err)
	}
	if !regularFile(cleaned) {
		t.Fatal("runner returned before the Go child test completed t.Cleanup")
	}
}

func TestTimedOutTestReceivesCancellationAndFinishesTeardown(t *testing.T) {
	teardown := make(chan struct{})
	test := registeredTest{ID: "test/timeout", Suite: "acceptance", Timeout: 20 * time.Millisecond, Run: func(ctx context.Context, _ runContext) error {
		<-ctx.Done()
		close(teardown)
		return nil
	}}
	err := runRegisteredTest(context.Background(), test, runContext{})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timed out test = %v", err)
	}
	select {
	case <-teardown:
	default:
		t.Fatal("timed out test did not finish teardown")
	}
}

func TestFreshRunClearsOldFailureLogs(t *testing.T) {
	state := t.TempDir()
	progressPath := filepath.Join(state, "acceptance.json")
	stale := failurePath(progressPath, "test/b")
	if err := atomicWrite(stale, []byte("obsolete\n")); err != nil {
		t.Fatal(err)
	}
	tests := testRegistry(func(context.Context, runContext) error { return errors.New("current failure") }, func(context.Context, runContext) error { return nil })
	_ = executeSuite(context.Background(), ioDiscard{}, ioDiscard{}, "run", progressPath, t.TempDir(), "acceptance", testSourceSHA, tests, false)
	if _, err := os.Stat(stale); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("fresh run retained stale failure log: %v", err)
	}
}

func TestCancelledSuiteDoesNotScheduleAnotherTest(t *testing.T) {
	state := t.TempDir()
	progressPath := filepath.Join(state, "acceptance.json")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var secondRuns atomic.Int32
	tests := testRegistry(
		func(context.Context, runContext) error { cancel(); return nil },
		func(context.Context, runContext) error { secondRuns.Add(1); return nil },
	)
	if err := executeSuite(ctx, ioDiscard{}, ioDiscard{}, "run", progressPath, t.TempDir(), "acceptance", testSourceSHA, tests, false); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled suite = %v", err)
	}
	if secondRuns.Load() != 0 {
		t.Fatalf("cancelled suite scheduled %d subsequent tests", secondRuns.Load())
	}
}

func TestPrivilegedSuitesRequireFixedRootEnvironment(t *testing.T) {
	if err := validateExecutionEnvironment("diagnostic", "linux", 1000, "/var/lib/flowersec-test/home", externalHostPath, "/var/lib/flowersec-test/tmp", "/var/lib/flowersec-test/state", "/var/lib/flowersec-test/workspace"); err == nil {
		t.Fatal("non-root external suite was accepted")
	}
	if err := validateExecutionEnvironment("performance", "linux", 0, "/home/user", externalHostPath, "/tmp", "/var/lib/flowersec-test/state", "/var/lib/flowersec-test/workspace"); err == nil {
		t.Fatal("wrong root environment was accepted")
	}
	if err := validateExecutionEnvironment("diagnostic", "linux", 0, "/var/lib/flowersec-test/home", externalHostPath, "/var/lib/flowersec-test/tmp", "/var/lib/flowersec-test/state", "/var/lib/flowersec-test/workspace/flowersec"); err != nil {
		t.Fatalf("fixed root environment rejected: %v", err)
	}
}

func TestLocalSuitesDoNotRequireRoot(t *testing.T) {
	for _, suite := range []string{"acceptance", "browser-smoke"} {
		if err := validateExecutionEnvironment(suite, "darwin", 501, "/Users/test", "/usr/bin:/bin", "/tmp", "", "/repo"); err != nil {
			t.Fatalf("local suite %q rejected ordinary user: %v", suite, err)
		}
	}
}

type ioDiscard struct{}

func (ioDiscard) Write(value []byte) (int, error) { return len(value), nil }
