package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

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
	if err := executeSuite(context.Background(), &stdout, &stderr, "run", progressPath, t.TempDir(), tests, false); err == nil {
		t.Fatal("RED suite returned success")
	}
	current, err := readProgress(progressPath, tests)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(current.Completed, ","); got != "test/a" {
		t.Fatalf("completed after RED = %q", got)
	}
	if next := firstIncomplete(tests, current.Completed); next == nil || next.ID != "test/b" {
		t.Fatalf("next after RED = %+v", next)
	}
	if err := executeSuite(context.Background(), &stdout, &stderr, "resume", progressPath, t.TempDir(), tests, false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(progressPath); !errors.Is(err, os.ErrNotExist) || aRuns.Load() != 1 || bRuns.Load() != 2 {
		t.Fatalf("completed progress=%v runs=%d/%d", err, aRuns.Load(), bRuns.Load())
	}
}

func TestResumeStopsAfterTheFirstIncompleteTest(t *testing.T) {
	state := t.TempDir()
	progressPath := filepath.Join(state, "acceptance.json")
	var aRuns, bRuns, cRuns atomic.Int32
	tests := []registeredTest{
		{ID: "test/a", Suite: "acceptance", Timeout: time.Second, Run: func(context.Context, runContext) error { aRuns.Add(1); return nil }},
		{ID: "test/b", Suite: "acceptance", Timeout: time.Second, Run: func(context.Context, runContext) error { bRuns.Add(1); return nil }},
		{ID: "test/c", Suite: "acceptance", Timeout: time.Second, Run: func(context.Context, runContext) error { cRuns.Add(1); return nil }},
	}
	if err := writeProgress(progressPath, progress{Plan: planName, Completed: []string{"test/a"}}, tests); err != nil {
		t.Fatal(err)
	}
	if err := executeSuite(context.Background(), ioDiscard{}, ioDiscard{}, "resume", progressPath, t.TempDir(), tests, false); err != nil {
		t.Fatal(err)
	}
	current, err := readProgress(progressPath, tests)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(current.Completed, ","); got != "test/a,test/b" {
		t.Fatalf("completed after resume = %q", got)
	}
	if aRuns.Load() != 0 || bRuns.Load() != 1 || cRuns.Load() != 0 {
		t.Fatalf("resume runs=%d/%d/%d", aRuns.Load(), bRuns.Load(), cRuns.Load())
	}
}

func TestRunAlwaysStartsFreshAndProgressHasOnlyPlanAndCompleted(t *testing.T) {
	state := t.TempDir()
	progressPath := filepath.Join(state, "acceptance.json")
	var runs atomic.Int32
	tests := testRegistry(
		func(context.Context, runContext) error { runs.Add(1); return nil },
		func(context.Context, runContext) error { runs.Add(1); return nil },
	)
	if err := writeProgress(progressPath, progress{Plan: planName, Completed: []string{"test/a", "test/b"}}, tests); err != nil {
		t.Fatal(err)
	}
	if err := executeSuite(context.Background(), ioDiscard{}, ioDiscard{}, "run", progressPath, t.TempDir(), tests, false); err != nil {
		t.Fatal(err)
	}
	if runs.Load() != 2 {
		t.Fatalf("fresh run executed %d tests", runs.Load())
	}
	if _, err := os.Stat(progressPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("completed progress remains: %v", err)
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
	if err := executeSuite(context.Background(), ioDiscard{}, ioDiscard{}, "run", progressPath, t.TempDir(), tests, false); err != nil {
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
	marker := filepath.Join(directory, "terminated")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- runCommand(ctx, directory, []string{"MARKER=" + marker}, "sh", "-c", `trap 'touch "$MARKER"; exit 0' TERM; while :; do sleep 1; done`)
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
		t.Fatalf("subprocess did not handle TERM: %v", err)
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
	_ = executeSuite(context.Background(), ioDiscard{}, ioDiscard{}, "run", progressPath, t.TempDir(), tests, false)
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
	if err := executeSuite(ctx, ioDiscard{}, ioDiscard{}, "run", progressPath, t.TempDir(), tests, false); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled suite = %v", err)
	}
	if secondRuns.Load() != 0 {
		t.Fatalf("cancelled suite scheduled %d subsequent tests", secondRuns.Load())
	}
}

func TestRunnerRequiresFixedRootEnvironment(t *testing.T) {
	if err := validateExecutionEnvironment("linux", 1000, "/var/lib/flowersec-test/home", externalHostPath, "/var/lib/flowersec-test/tmp", "/var/lib/flowersec-test/state", "/var/lib/flowersec-test/workspace"); err == nil {
		t.Fatal("non-root external suite was accepted")
	}
	if err := validateExecutionEnvironment("linux", 0, "/home/user", externalHostPath, "/tmp", "/var/lib/flowersec-test/state", "/var/lib/flowersec-test/workspace"); err == nil {
		t.Fatal("wrong root environment was accepted")
	}
	if err := validateExecutionEnvironment("linux", 0, "/var/lib/flowersec-test/home", externalHostPath, "/var/lib/flowersec-test/tmp", "/var/lib/flowersec-test/state", "/var/lib/flowersec-test/workspace/flowersec"); err != nil {
		t.Fatalf("fixed root environment rejected: %v", err)
	}
}

type ioDiscard struct{}

func (ioDiscard) Write(value []byte) (int, error) { return len(value), nil }
