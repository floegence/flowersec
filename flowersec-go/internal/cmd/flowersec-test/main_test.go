package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v3/internal/perfreport"
)

const testSourceSHA = "0123456789abcdef0123456789abcdef01234567"

var testPerformanceEnvironment = perfreport.Environment{HostName: "orange", OS: "Ubuntu 22.04", Kernel: "5.10", Architecture: "arm64", CPUModel: "Cortex-A55", LogicalCPUs: 8, MemoryBytes: 16 << 30, GoVersion: "go1.26", NodeVersion: "v22", ChromiumVersion: "Chromium 140"}

func TestExactTitleMatchesTheCompleteTitleWithAnOptionalSuitePrefix(t *testing.T) {
	title := "runs direct admission and Session semantics over WSS"
	pattern := regexp.MustCompile(exactTitle(title))
	if !pattern.MatchString(title) {
		t.Fatal("exact title did not match itself")
	}
	if !pattern.MatchString("TypeScript-Go interoperability " + title) {
		t.Fatal("exact title did not match the Vitest full-name suffix")
	}
	for _, value := range []string{"prefix" + title, title + " suffix", "similar " + title + " suffix"} {
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

func TestVitestEntryScopesDiscoveryToTheCurrentTypeScriptPackage(t *testing.T) {
	entry := vitestEntry("test/typescript", "acceptance", "src/example.test.ts", "exact title")
	if entry.ID != "test/typescript" || entry.Suite != "acceptance" || entry.Timeout != 5*time.Minute {
		t.Fatalf("entry identity = %+v", entry)
	}
	want := []string{"--prefix", "flowersec-ts", "exec", "--", "vitest", "run", "--root", "flowersec-ts", "--config", "vitest.config.ts", "src/example.test.ts", "-t", "(^|\\s)exact title$"}
	if got := vitestArguments("src/example.test.ts", "exact title"); strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("vitest arguments = %q, want %q", got, want)
	}
}

func TestPerformanceRegistrySeparatesRequiredAndOptionalCarriers(t *testing.T) {
	capacityEntries := 0
	optionalCapacityEntries := 0
	for _, test := range registry() {
		if !strings.HasPrefix(test.ID, "performance/capacity/") {
			continue
		}
		if strings.Contains(test.ID, "wt") || strings.Contains(test.ID, "webtransport") {
			if test.Suite != "performance-optional" {
				t.Fatalf("optional WebTransport capacity %s is registered in %s", test.ID, test.Suite)
			}
			optionalCapacityEntries++
		} else {
			if test.Suite != "performance" {
				t.Fatalf("required capacity %s is registered in %s", test.ID, test.Suite)
			}
			capacityEntries++
		}
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
	if capacityEntries != 6 || optionalCapacityEntries != 6 {
		t.Fatalf("capacity registry entries = required %d optional %d, want 6 and 6", capacityEntries, optionalCapacityEntries)
	}
	for _, test := range registry() {
		if test.Suite == "performance" && strings.Contains(test.ID, "webtransport") {
			t.Fatalf("required performance contains optional WebTransport test %s", test.ID)
		}
	}
}

func TestRegistryEntriesSatisfyRunnerBounds(t *testing.T) {
	if _, err := selectSuite(registry(), "acceptance"); err != nil {
		t.Fatalf("registry validation failed: %v", err)
	}
}

func TestAcceptanceRegistryOwnsPrivateLoopbackInterop(t *testing.T) {
	for _, entry := range registry() {
		if entry.ID == "interop/typescript-go/private-loopback/direct" && entry.Suite == "acceptance" {
			return
		}
	}
	t.Fatal("private loopback TypeScript-Go interop is missing from the acceptance registry")
}

func TestGoAcceptorRegistryPatternEnumeratesProductionNativeListeners(t *testing.T) {
	command := exec.Command("go", "test", "-list", goAcceptorTestPattern, "../../..")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("list Go acceptor tests: %v\n%s", err, output)
	}
	listed := string(output)
	for _, name := range []string{
		"TestRawQUICAcceptorListenerEstablishesApplicationSession",
		"TestRawQUICAcceptorServeCancellationWaitsForSessionCleanup",
		"TestWebTransportAcceptorListenerEstablishesApplicationSession",
	} {
		if !strings.Contains(listed, name+"\n") {
			t.Fatalf("server/go-acceptor pattern did not enumerate %s:\n%s", name, listed)
		}
	}
}

func TestOptionalPerformanceUsesThePrivilegedHostBoundary(t *testing.T) {
	if err := validateExecutionEnvironment("performance-optional", "linux", 0, "/var/lib/flowersec-test/home", externalHostPath, externalHostGoRoot, "/var/lib/flowersec-test/tmp", "/var/lib/flowersec-test/state", "/var/lib/flowersec-test/workspace"); err != nil {
		t.Fatal(err)
	}
	if err := validateExecutionEnvironment("performance-optional", "darwin", 501, "/Users/test", "/usr/bin", "", "/tmp", "", "/tmp/flowersec"); err == nil {
		t.Fatal("optional performance was allowed outside the fixed privileged host")
	}
}

func TestOptionalPerformanceStartsWithWebTransportCapabilityPreflight(t *testing.T) {
	tests, err := selectSuite(registry(), "performance-optional")
	if err != nil {
		t.Fatal(err)
	}
	if tests[0].ID != "performance-optional/webtransport-capability" {
		t.Fatalf("optional performance first test = %q", tests[0].ID)
	}
}

func TestStandaloneOptionalPerformanceIsRejected(t *testing.T) {
	err := runCLI([]string{"run", "--suite", "performance-optional"})
	if err == nil || !strings.Contains(err.Error(), "only available through the integrated") {
		t.Fatalf("standalone optional performance error = %v", err)
	}
}

func TestProgressLockHonorsCancellation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "progress.json")
	owner, err := lockProgress(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := lockProgress(ctx, path)
		done <- err
	}()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled progress lock = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("progress lock did not honor cancellation")
	}
	if err := syscall.Flock(int(owner.Fd()), syscall.LOCK_UN); err != nil {
		t.Fatal(err)
	}
}

func TestRequiredPerformanceRegistersBothPayloadThroughputCarriers(t *testing.T) {
	want := map[string]bool{
		"performance/throughput/wss":      false,
		"performance/throughput/raw-quic": false,
	}
	for _, entry := range registry() {
		if _, ok := want[entry.ID]; ok {
			if entry.Suite != "performance" {
				t.Fatalf("throughput %s suite = %s", entry.ID, entry.Suite)
			}
			want[entry.ID] = true
		}
	}
	for id, found := range want {
		if !found {
			t.Fatalf("required payload throughput %s is not registered", id)
		}
	}
}

func TestIntegratedPerformancePlanIncludesRequiredAndOptional(t *testing.T) {
	tests, err := selectPerformancePlan(registry())
	if err != nil {
		t.Fatal(err)
	}
	required, optional := 0, 0
	for _, entry := range tests {
		switch entry.Suite {
		case "performance":
			required++
		case "performance-optional":
			optional++
		default:
			t.Fatalf("integrated performance plan contains %s", entry.Suite)
		}
	}
	if required == 0 || optional == 0 || tests[required].ID != "performance-optional/webtransport-capability" {
		t.Fatalf("integrated performance plan = required %d optional %d", required, optional)
	}
}

func TestPerformanceReportPathIsRequiredAbsoluteMarkdownOutsideRepository(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(filepath.Dir(root), "flowersec-performance-report.md")
	if err := validatePerformanceReportPath(outside, root); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"", "relative.md", filepath.Join(root, "inside.md"), filepath.Join(filepath.Dir(root), "report.json")} {
		if err := validatePerformanceReportPath(path, root); err == nil {
			t.Fatalf("invalid performance report path %q was accepted", path)
		}
	}
}

func TestPerformanceBudgetDefaultsToTenMinutesAndRejectsIncompleteWindows(t *testing.T) {
	budget, err := parsePerformanceBudget("")
	if err != nil {
		t.Fatal(err)
	}
	if budget != 10*time.Minute {
		t.Fatalf("default performance budget = %s, want 10m", budget)
	}
	if _, err := parsePerformanceBudget("4m59s"); err == nil {
		t.Fatal("accepted a performance budget too short for the complete plan")
	}
	if budget, err := parsePerformanceBudget("25m"); err != nil || budget != 25*time.Minute {
		t.Fatalf("custom performance budget = %s, %v", budget, err)
	}
}

func TestPerformanceBudgetEnvironmentIsExplicit(t *testing.T) {
	got := performanceBudgetEnvironment(10 * time.Minute)
	if len(got) != 1 || got[0] != "FLOWERSEC_PERFORMANCE_BUDGET=10m0s" {
		t.Fatalf("performance budget environment = %#v", got)
	}
}

func TestCPUModelFromSourcesSupportsARMWithoutProcModelName(t *testing.T) {
	procCPUInfo := "processor\t: 0\nCPU part\t: 0xd05\n"
	lscpuOutput := "Architecture: aarch64\nModel name: Cortex-A55\n"
	if got := cpuModelFromSources(procCPUInfo, lscpuOutput); got != "Cortex-A55" {
		t.Fatalf("ARM CPU model = %q, want Cortex-A55", got)
	}
}

func TestCPUModelFromSourcesIgnoresMalformedProcModelName(t *testing.T) {
	procCPUInfo := "model name\n"
	lscpuOutput := "Model name:\nModel name: Cortex-A76\n"
	if got := cpuModelFromSources(procCPUInfo, lscpuOutput); got != "Cortex-A76" {
		t.Fatalf("malformed proc CPU model = %q, want lscpu fallback", got)
	}
}

func TestPerformanceStateRestoresSameSHAAndRejectsDifferentSHA(t *testing.T) {
	path := filepath.Join(t.TempDir(), "performance-results.json")
	state := performanceState{SourceSHA: testSourceSHA, StartedAt: time.Now(), Environment: testPerformanceEnvironment, Cases: []perfreport.CaseResult{{ID: "case/a", Section: perfreport.SectionCapacity, Status: perfreport.StatusPass, Measurements: []perfreport.Measurement{{Name: "sessions", Observed: 1000, Threshold: 1000, Unit: "sessions", Comparator: ">=", Status: perfreport.StatusPass}}}}}
	if err := writePerformanceState(path, state); err != nil {
		t.Fatal(err)
	}
	loaded, err := readPerformanceState(path, testSourceSHA, testPerformanceEnvironment)
	if err != nil || len(loaded.Cases) != 1 || loaded.Cases[0].Measurements[0].Observed != 1000 {
		t.Fatalf("restored performance state = %+v, %v", loaded, err)
	}
	if _, err := readPerformanceState(path, strings.Repeat("f", 40), testPerformanceEnvironment); err == nil || !strings.Contains(err.Error(), "source SHA") {
		t.Fatalf("different source SHA was not rejected: %v", err)
	}
	otherEnvironment := testPerformanceEnvironment
	otherEnvironment.HostName = "other-host"
	if _, err := readPerformanceState(path, testSourceSHA, otherEnvironment); err == nil || !strings.Contains(err.Error(), "environment") {
		t.Fatalf("different environment was not rejected: %v", err)
	}
}

func TestPerformanceStateRejectsMalformedOrUnboundEnvironment(t *testing.T) {
	path := filepath.Join(t.TempDir(), "performance-results.json")
	valid := performanceState{SourceSHA: testSourceSHA, StartedAt: time.Now(), Environment: testPerformanceEnvironment, Cases: []perfreport.CaseResult{}}
	data, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	for name, payload := range map[string][]byte{
		"unknown field":       append(append([]byte(nil), data[:len(data)-1]...), []byte(`,"extra":true}`)...),
		"trailing json":       append(append([]byte(nil), data...), []byte(`{}`)...),
		"missing environment": []byte(`{"source_sha":"0123456789abcdef0123456789abcdef01234567","started_at":"2026-08-22T00:00:00Z","cases":[]}`),
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(path, payload, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := readPerformanceState(path, testSourceSHA, testPerformanceEnvironment); err == nil {
				t.Fatal("malformed performance state was accepted")
			}
		})
	}
}

func TestPerformanceResumeRejectsDifferentBudget(t *testing.T) {
	root := t.TempDir()
	reportPath := filepath.Join(t.TempDir(), "performance-report.md")
	progressPath := filepath.Join(t.TempDir(), "test-progress.json")
	tests := []registeredTest{{ID: "performance/case", Suite: "performance", Timeout: time.Second, Run: func(_ context.Context, run runContext) error {
		return perfreport.WriteCaseResult(run.ResultPath, perfreport.CaseResult{ID: "performance/case", Section: perfreport.SectionCapacity, Status: perfreport.StatusPass, Measurements: []perfreport.Measurement{{Name: "sessions", Observed: 1, Threshold: 1, Unit: "sessions", Comparator: "==", Status: perfreport.StatusPass}}})
	}}}
	environment := testPerformanceEnvironment
	var stdout, stderr bytes.Buffer
	if err := executePerformanceSuite(context.Background(), &stdout, &stderr, "run", progressPath, root, testSourceSHA, tests, false, reportPath, environment, 10*time.Minute); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(filepath.Dir(progressPath), "performance-results.json")
	state := performanceState{SourceSHA: testSourceSHA, StartedAt: time.Now(), Budget: 10 * time.Minute, Environment: environment, Cases: []perfreport.CaseResult{}}
	if err := writePerformanceState(statePath, state); err != nil {
		t.Fatal(err)
	}
	if err := writeProgress(progressPath, progress{Plan: planName, SourceSHA: testSourceSHA, Suite: "performance", Completed: []string{}}, tests); err != nil {
		t.Fatal(err)
	}
	err := executePerformanceSuite(context.Background(), &stdout, &stderr, "resume", progressPath, root, testSourceSHA, tests, false, reportPath, environment, 20*time.Minute)
	if err == nil || !strings.Contains(err.Error(), "budget") {
		t.Fatalf("resume with a different budget = %v", err)
	}
}

func TestPerformanceBudgetCancellationWritesPartialReport(t *testing.T) {
	root := t.TempDir()
	reportPath := filepath.Join(t.TempDir(), "performance-report.md")
	progressPath := filepath.Join(t.TempDir(), "test-progress.json")
	tests := []registeredTest{{ID: "performance/slow", Suite: "performance", Timeout: time.Hour, Run: func(ctx context.Context, _ runContext) error {
		<-ctx.Done()
		return context.Cause(ctx)
	}}}
	environment := perfreport.Environment{HostName: "udesk24", OS: "Ubuntu", LogicalCPUs: 4, MemoryBytes: 8 << 30}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var stdout, stderr bytes.Buffer
	err := executePerformanceSuite(ctx, &stdout, &stderr, "run", progressPath, root, testSourceSHA, tests, false, reportPath, environment, 5*time.Minute)
	if err == nil {
		t.Fatal("cancelled performance suite returned success")
	}
	data, readErr := os.ReadFile(reportPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	for _, want := range []string{"Overall status | **FAIL**", "suite budget", "5m0s wall-clock budget"} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("budget cancellation report missing %q:\n%s", want, data)
		}
	}
}

func TestPerformanceBudgetBoundsProgressLockContention(t *testing.T) {
	root := t.TempDir()
	reportPath := filepath.Join(t.TempDir(), "performance-report.md")
	progressPath := filepath.Join(t.TempDir(), "test-progress.json")
	owner, err := lockProgress(context.Background(), progressPath)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	var runs atomic.Int32
	tests := []registeredTest{{ID: "performance/blocked", Suite: "performance", Timeout: time.Second, Run: func(context.Context, runContext) error {
		runs.Add(1)
		return nil
	}}}
	var stdout, stderr bytes.Buffer
	started := time.Now()
	err = executePerformanceSuiteWithLimits(context.Background(), &stdout, &stderr, "run", progressPath, root, testSourceSHA, tests, false, reportPath, testPerformanceEnvironment, 60*time.Millisecond, 10*time.Millisecond, time.Second, 20*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "exhausted its 60ms wall-clock budget while waiting for progress lock") {
		t.Fatalf("performance lock contention = %v", err)
	}
	if elapsed := time.Since(started); elapsed < 30*time.Millisecond || elapsed > time.Second {
		t.Fatalf("performance lock contention duration = %s", elapsed)
	}
	if runs.Load() != 0 {
		t.Fatal("performance case started before the progress lock was acquired")
	}
}

func TestPerformanceCancellationRemovesCaseTempDirectory(t *testing.T) {
	root := t.TempDir()
	reportPath := filepath.Join(t.TempDir(), "performance-report.md")
	progressPath := filepath.Join(t.TempDir(), "test-progress.json")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var tempDir string
	tests := []registeredTest{{ID: "performance/cancelled", Suite: "performance", Timeout: time.Second, Run: func(ctx context.Context, run runContext) error {
		tempDir = run.TempDir
		cancel()
		<-ctx.Done()
		return context.Cause(ctx)
	}}}
	var stdout, stderr bytes.Buffer
	if err := executePerformanceSuite(ctx, &stdout, &stderr, "run", progressPath, root, testSourceSHA, tests, false, reportPath, testPerformanceEnvironment, 5*time.Minute); err == nil {
		t.Fatal("cancelled performance case returned success")
	}
	if tempDir == "" {
		t.Fatal("performance case did not receive a temp directory")
	}
	if _, err := os.Stat(tempDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cancelled performance case retained temp directory: %v", err)
	}
}

func TestPerformanceFailureWritesPartialReportAndReturnsNonzero(t *testing.T) {
	root := t.TempDir()
	reportPath := filepath.Join(t.TempDir(), "performance-report.md")
	progressPath := filepath.Join(t.TempDir(), "test-progress.json")
	tests := []registeredTest{{ID: "performance/failing", Suite: "performance", Timeout: time.Second, Run: func(_ context.Context, run runContext) error {
		result := perfreport.CaseResult{ID: "performance/failing", Section: perfreport.SectionStreamingThroughput, Status: perfreport.StatusFail, Stage: "measurement", FirstError: "first observed error", Measurements: []perfreport.Measurement{{Name: "throughput", Observed: 1, Threshold: 2, Unit: "MiB/s", Comparator: ">=", Status: perfreport.StatusFail}}}
		if err := perfreport.WriteCaseResult(run.ResultPath, result); err != nil {
			return err
		}
		return errors.New("first observed error")
	}}}
	environment := perfreport.Environment{HostName: "udesk24", OS: "Ubuntu", LogicalCPUs: 4, MemoryBytes: 8 << 30}
	var stdout, stderr bytes.Buffer
	err := executePerformanceSuite(context.Background(), &stdout, &stderr, "run", progressPath, root, testSourceSHA, tests, false, reportPath, environment)
	if err == nil {
		t.Fatal("failed performance case returned success")
	}
	data, readErr := os.ReadFile(reportPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	for _, want := range []string{"Wall-clock budget | 10m0s", "Overall status | **FAIL**", "first observed error", "1.000", "2.000"} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("partial report missing %q:\n%s", want, data)
		}
	}
}

func TestChromiumPerformanceCapabilityResultClassification(t *testing.T) {
	if err := parseChromiumPerformanceCapability([]byte(`{"status":"GREEN","secure_context":true,"webtransport":"function"}`)); err != nil {
		t.Fatalf("GREEN capability result: %v", err)
	}
	err := parseChromiumPerformanceCapability([]byte(`{"status":"UNSUPPORTED","limitation":"Chromium does not expose the WebTransport constructor"}`))
	var unavailable *performanceCapabilityUnavailableError
	if !errors.As(err, &unavailable) || unavailable.Error() != chromiumWebTransportUnavailableLimitation {
		t.Fatalf("UNSUPPORTED capability result = %T %v", err, err)
	}
	for name, payload := range map[string]string{
		"malformed":                 `{"status":"GREEN"} trailing`,
		"unknown field":             `{"status":"GREEN","secure_context":true,"webtransport":"function","extra":true}`,
		"incomplete green":          `{"status":"GREEN","secure_context":true}`,
		"empty limitation":          `{"status":"UNSUPPORTED","limitation":" "}`,
		"runner failure limitation": `{"status":"UNSUPPORTED","limitation":"Chromium launch failed"}`,
		"contradictory state":       `{"status":"UNSUPPORTED","secure_context":true,"limitation":"missing"}`,
	} {
		t.Run(name, func(t *testing.T) {
			if err := parseChromiumPerformanceCapability([]byte(payload)); err == nil {
				t.Fatal("invalid Chromium capability result was accepted")
			} else if errors.As(err, &unavailable) {
				t.Fatalf("invalid result was classified as unavailable: %v", err)
			}
		})
	}
}

func TestPerformanceCapabilityOnlyStructuredUnavailableSkipsOptionalCases(t *testing.T) {
	for _, scenario := range []struct {
		name          string
		capabilityErr error
		wantSuccess   bool
		wantReport    string
	}{
		{name: "structured unavailable", capabilityErr: &performanceCapabilityUnavailableError{limitation: chromiumWebTransportUnavailableLimitation}, wantSuccess: true, wantReport: "UNSUPPORTED"},
		{name: "runner failure", capabilityErr: errors.New("synthetic Chromium launch failure"), wantSuccess: false, wantReport: "synthetic Chromium launch failure"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			root := t.TempDir()
			reportPath := filepath.Join(root, "performance-report.md")
			progressPath := filepath.Join(root, "test-progress.json")
			optionalRan := false
			tests := []registeredTest{
				{ID: "performance-optional/webtransport-capability", Suite: "performance-optional", Timeout: time.Second, Run: func(context.Context, runContext) error {
					return scenario.capabilityErr
				}},
				{ID: "performance/single-connection/webtransport", Suite: "performance-optional", Timeout: time.Second, Run: func(context.Context, runContext) error {
					optionalRan = true
					return nil
				}},
			}
			var stdout, stderr bytes.Buffer
			err := executePerformanceSuite(context.Background(), &stdout, &stderr, "run", progressPath, root, testSourceSHA, tests, false, reportPath, testPerformanceEnvironment)
			if (err == nil) != scenario.wantSuccess {
				t.Fatalf("performance capability result = %v, stdout=%s stderr=%s", err, stdout.String(), stderr.String())
			}
			if optionalRan {
				t.Fatal("optional performance case ran after capability preflight did not pass")
			}
			report, readErr := os.ReadFile(reportPath)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if !strings.Contains(string(report), scenario.wantReport) {
				t.Fatalf("report missing %q:\n%s", scenario.wantReport, report)
			}
			if scenario.wantSuccess && !strings.Contains(stdout.String(), "ALL GREEN") {
				t.Fatalf("unavailable optional capability did not complete the suite: %s", stdout.String())
			}
		})
	}
}

func TestPerformanceStructuredFailureWritesImmediatelyAndContinues(t *testing.T) {
	root := t.TempDir()
	reportPath := filepath.Join(t.TempDir(), "performance-report.md")
	progressPath := filepath.Join(t.TempDir(), "test-progress.json")
	partialObserved := false
	tests := []registeredTest{
		{ID: "performance/single-connection/wss", Suite: "performance", Timeout: time.Second, Run: func(_ context.Context, run runContext) error {
			return perfreport.WriteCaseResult(run.ResultPath, perfreport.CaseResult{
				ID: "performance/single-connection/wss", Section: perfreport.SectionSingleConnection, Status: perfreport.StatusFail,
				Stage: "measurement", FirstError: "CPU time observed 121 CPU-s, threshold <= 120 CPU-s",
				Measurements: []perfreport.Measurement{{Name: "CPU time", Observed: 121, Threshold: 120, Unit: "CPU-s", Comparator: "<=", Status: perfreport.StatusFail}},
			})
		}},
		{ID: "performance/throughput/wss", Suite: "performance", Timeout: time.Second, Run: func(_ context.Context, run runContext) error {
			data, err := os.ReadFile(reportPath)
			partialObserved = err == nil && strings.Contains(string(data), "121.000")
			return perfreport.WriteCaseResult(run.ResultPath, perfreport.CaseResult{
				ID: "performance/throughput/wss", Section: perfreport.SectionStreamingThroughput, Status: perfreport.StatusPass,
				Measurements: []perfreport.Measurement{{Name: "throughput", Observed: 10, Threshold: 1, Unit: "MiB/s", Comparator: ">=", Status: perfreport.StatusPass}},
			})
		}},
	}
	environment := perfreport.Environment{HostName: "udesk24", OS: "Ubuntu", LogicalCPUs: 4, MemoryBytes: 8 << 30}
	var stdout, stderr bytes.Buffer
	err := executePerformanceSuite(context.Background(), &stdout, &stderr, "run", progressPath, root, testSourceSHA, tests, false, reportPath, environment)
	if err == nil {
		t.Fatal("integrated performance returned success after a structured threshold failure")
	}
	if !partialObserved {
		t.Fatal("structured threshold failure was not atomically reported before the next case")
	}
	data, readErr := os.ReadFile(reportPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	for _, want := range []string{"Overall status | **FAIL**", "121.000", "10.000", "CPU time observed"} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("integrated failure report missing %q:\n%s", want, data)
		}
	}
}

func TestRequiredGoTestOutputRejectsSkipAndMissingTarget(t *testing.T) {
	for name, output := range map[string]string{
		"skip": strings.Join([]string{
			jsonLine(goTestEvent{Action: "start", Test: "TestRequired"}),
			jsonLine(goTestEvent{Action: "skip", Test: "TestRequired", Output: "--- SKIP: TestRequired (0.00s)\\n"}),
			jsonLine(goTestEvent{Action: "pass", Package: "example.test"}),
		}, ""),
		"subtest skip": strings.Join([]string{
			jsonLine(goTestEvent{Action: "run", Package: "example.test", Test: "TestRequired"}),
			jsonLine(goTestEvent{Action: "run", Package: "example.test", Test: "TestRequired/required-cell"}),
			jsonLine(goTestEvent{Action: "skip", Package: "example.test", Test: "TestRequired/required-cell"}),
			jsonLine(goTestEvent{Action: "pass", Package: "example.test", Test: "TestRequired"}),
		}, ""),
		"missing": jsonLine(goTestEvent{Action: "pass", Package: "example.test"}),
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateRequiredGoTestOutput([]byte(output), "example.test", "TestRequired"); err == nil {
				t.Fatal("required diagnostic output was accepted without a target pass")
			}
		})
	}
}

func TestRequiredGoTestOutputAcceptsTargetPass(t *testing.T) {
	output := strings.Join([]string{
		jsonLine(goTestEvent{Action: "run", Package: "example.test", Test: "TestRequired"}),
		jsonLine(goTestEvent{Action: "pass", Package: "example.test", Test: "TestRequired"}),
		jsonLine(goTestEvent{Action: "pass", Package: "example.test"}),
	}, "")
	if err := validateRequiredGoTestOutput([]byte(output), "example.test", "TestRequired"); err != nil {
		t.Fatal(err)
	}
}

func TestRequiredDiagnosticRegistryUsesExactGoTestCompletion(t *testing.T) {
	want := map[string]bool{
		"diagnostic/weaknet/raw-quic/direct":         false,
		"diagnostic/weaknet/websocket/direct":        false,
		"diagnostic/kernel/topology-lifecycle":       false,
		"diagnostic/kernel/fault-schedules":          false,
		"diagnostic/kernel/reorder-duplicate-outage": false,
		"diagnostic/kernel/socket-traversal":         false,
	}
	for _, carrierName := range []string{"websocket", "raw-quic"} {
		for _, scenario := range []string{"delay-jitter", "periodic-loss", "burst-loss", "outage", "mtu-large-payload", "rate-5mbps", "rate-1mbps", "reorder-duplicate"} {
			want["diagnostic/flowersec-weaknet/"+carrierName+"/direct/"+scenario] = false
		}
	}
	want["diagnostic/flowersec-weaknet/websocket/tunnel/representative"] = false
	want["diagnostic/flowersec-weaknet/raw-quic/tunnel/representative"] = false
	for _, entry := range registry() {
		if _, ok := want[entry.ID]; ok {
			want[entry.ID] = true
		}
	}
	for id, found := range want {
		if !found {
			t.Fatalf("required diagnostic %q is not registered", id)
		}
	}
}

type goTestEvent struct {
	Action  string `json:"Action"`
	Package string `json:"Package"`
	Test    string `json:"Test"`
	Output  string `json:"Output"`
}

func jsonLine(event goTestEvent) string {
	value, err := json.Marshal(event)
	if err != nil {
		panic(err)
	}
	return string(value) + "\n"
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
	if err := printStatus(context.Background(), &output, progressPath, tests, "acceptance", testSourceSHA); err != nil {
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

func TestSuccessfulCommandCleansDescendantsBeforeReturning(t *testing.T) {
	directory := t.TempDir()
	marker := filepath.Join(directory, "descendant-survived")
	if err := runCommand(context.Background(), directory, []string{"MARKER=" + marker}, "sh", "-c", `sh -c 'sleep 1; touch "$MARKER"' & exit 0`); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1200 * time.Millisecond)
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("successful command left a descendant running: %v", err)
	}
}

func TestCancelledCommandWaitsForSigkillFallbackGroupCleanup(t *testing.T) {
	directory := t.TempDir()
	ready := filepath.Join(directory, "ready")
	marker := filepath.Join(directory, "descendant-survived")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := runCommandOutputWithGrace(ctx, 20*time.Millisecond, directory, []string{
			"READY=" + ready,
			"MARKER=" + marker,
		}, "sh", "-c", `trap '' TERM; sh -c 'trap '\'' '\'' TERM; sleep 0.2; touch "$MARKER"; while :; do sleep 1; done' & touch "$READY"; wait`)
		done <- err
	}()
	deadline := time.Now().Add(time.Second)
	for !regularFile(ready) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !regularFile(ready) {
		cancel()
		t.Fatal("SIGKILL fallback command did not become ready")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("SIGKILL fallback command = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("SIGKILL fallback did not finish group cleanup")
	}
	time.Sleep(250 * time.Millisecond)
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("SIGKILL fallback left a descendant running: %v", err)
	}
}

func TestCancelledCommandWaitsForSigkillGroupBarrierAndReportsFailure(t *testing.T) {
	directory := t.TempDir()
	ready := filepath.Join(directory, "ready")
	ctx, cancel := context.WithCancel(context.Background())
	barrierEntered := make(chan struct{})
	releaseBarrier := make(chan struct{})
	defer func() {
		select {
		case <-releaseBarrier:
		default:
			close(releaseBarrier)
		}
	}()
	done := make(chan error, 1)
	go func() {
		_, err := runCommandOutputWithGraceAndGroupWait(ctx, 20*time.Millisecond, func(_ int, _ time.Duration) bool {
			close(barrierEntered)
			<-releaseBarrier
			return false
		}, directory, []string{"READY=" + ready}, "sh", "-c", `trap '' TERM; sh -c 'trap '\'' '\'' TERM; while :; do sleep 1; done' & touch "$READY"; wait`)
		done <- err
	}()
	deadline := time.Now().Add(time.Second)
	for !regularFile(ready) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !regularFile(ready) {
		cancel()
		t.Fatal("SIGKILL barrier command did not become ready")
	}
	cancel()
	select {
	case <-barrierEntered:
	case <-time.After(time.Second):
		t.Fatal("SIGKILL process-group barrier was not called")
	}
	select {
	case err := <-done:
		t.Fatalf("runner returned before the process-group barrier completed: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(releaseBarrier)
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), "subprocess group did not exit after SIGKILL") {
			t.Fatalf("SIGKILL barrier failure = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("runner did not report the process-group barrier failure")
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
	if err := validateExecutionEnvironment("diagnostic", "linux", 1000, "/var/lib/flowersec-test/home", externalHostPath, externalHostGoRoot, "/var/lib/flowersec-test/tmp", "/var/lib/flowersec-test/state", "/var/lib/flowersec-test/workspace"); err == nil {
		t.Fatal("non-root external suite was accepted")
	}
	if err := validateExecutionEnvironment("performance", "linux", 0, "/home/user", externalHostPath, externalHostGoRoot, "/tmp", "/var/lib/flowersec-test/state", "/var/lib/flowersec-test/workspace"); err == nil {
		t.Fatal("wrong root environment was accepted")
	}
	if err := validateExecutionEnvironment("diagnostic", "linux", 0, "/var/lib/flowersec-test/home", externalHostPath, "/usr/local/go", "/var/lib/flowersec-test/tmp", "/var/lib/flowersec-test/state", "/var/lib/flowersec-test/workspace"); err == nil {
		t.Fatal("wrong Go root was accepted")
	}
	if err := validateExecutionEnvironment("performance", "linux", 0, "/var/lib/flowersec-test/home", externalHostPath, "", "/var/lib/flowersec-test/tmp", "/var/lib/flowersec-test/state", "/var/lib/flowersec-test/workspace"); err == nil {
		t.Fatal("missing Go root was accepted")
	}
	if err := validateExecutionEnvironment("diagnostic", "linux", 0, "/var/lib/flowersec-test/home", externalHostPath, externalHostGoRoot, "/var/lib/flowersec-test/tmp", "/var/lib/flowersec-test/state", "/var/lib/flowersec-test/workspace/flowersec"); err != nil {
		t.Fatalf("fixed root environment rejected: %v", err)
	}
}

func TestLocalSuitesDoNotRequireRoot(t *testing.T) {
	for _, suite := range []string{"acceptance", "browser-smoke"} {
		if err := validateExecutionEnvironment(suite, "darwin", 501, "/Users/test", "/usr/bin:/bin", "", "/tmp", "", "/repo"); err != nil {
			t.Fatalf("local suite %q rejected ordinary user: %v", suite, err)
		}
	}
}

type ioDiscard struct{}

func (ioDiscard) Write(value []byte) (int, error) { return len(value), nil }
