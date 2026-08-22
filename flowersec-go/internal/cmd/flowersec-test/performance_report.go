package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v3/internal/perfreport"
)

type performanceState struct {
	SourceSHA string                  `json:"source_sha"`
	StartedAt time.Time               `json:"started_at"`
	Budget    time.Duration           `json:"budget_ns,omitempty"`
	Cases     []perfreport.CaseResult `json:"cases"`
}

func selectPerformancePlan(all []registeredTest) ([]registeredTest, error) {
	required, err := selectSuite(all, "performance")
	if err != nil {
		return nil, err
	}
	optional, err := selectSuite(all, "performance-optional")
	if err != nil {
		return nil, err
	}
	return append(required, optional...), nil
}

func readPerformanceState(path, sourceSHA string) (performanceState, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return performanceState{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var state performanceState
	if err := decoder.Decode(&state); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return performanceState{}, errors.New("performance result state is not strict JSON")
	}
	if state.SourceSHA != sourceSHA {
		return performanceState{}, fmt.Errorf("performance result source SHA %s does not match current source SHA %s", state.SourceSHA, sourceSHA)
	}
	if state.StartedAt.IsZero() || state.Cases == nil {
		return performanceState{}, errors.New("performance result state is invalid")
	}
	for _, result := range state.Cases {
		if err := result.Validate(); err != nil {
			return performanceState{}, fmt.Errorf("performance result state: %w", err)
		}
	}
	return state, nil
}

func writePerformanceState(path string, state performanceState) error {
	if !validSourceSHA(state.SourceSHA) || state.StartedAt.IsZero() || state.Cases == nil {
		return errors.New("performance result state is invalid")
	}
	for _, result := range state.Cases {
		if err := result.Validate(); err != nil {
			return err
		}
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomicFile(path, append(data, '\n'), 0o600)
}

func writeAtomicFile(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".performance-state-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}

func executePerformanceSuite(ctx context.Context, stdout, stderr io.Writer, action, progressPath, root, sourceSHA string, tests []registeredTest, debug bool, reportPath string, environment perfreport.Environment, configuredBudget ...time.Duration) error {
	budget := standardPerformanceBudget
	if len(configuredBudget) > 0 {
		budget = configuredBudget[0]
	}
	if budget < minimumPerformanceBudget || budget > maximumPerformanceBudget {
		return fmt.Errorf("performance budget must be between %s and %s", minimumPerformanceBudget, maximumPerformanceBudget)
	}
	executionCtx, cancelExecution := context.WithTimeout(ctx, budget-teardownGrace)
	defer cancelExecution()
	progressLock, err := lockProgress(progressPath)
	if err != nil {
		return err
	}
	defer progressLock.Close()
	statePath := filepath.Join(filepath.Dir(progressPath), "performance-results.json")
	current := progress{Plan: planName, SourceSHA: sourceSHA, Suite: "performance", Completed: []string{}}
	state := performanceState{SourceSHA: sourceSHA, StartedAt: time.Now(), Budget: budget, Cases: []perfreport.CaseResult{}}
	if action == "run" {
		if err := os.RemoveAll(filepath.Join(filepath.Dir(progressPath), "failures")); err != nil {
			return fmt.Errorf("clear stale failure logs: %w", err)
		}
		if err := os.Remove(statePath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("clear stale performance results: %w", err)
		}
	} else if action == "resume" {
		loadedProgress, err := readProgress(progressPath, tests, "performance")
		if err != nil {
			return err
		}
		if loadedProgress.SourceSHA != sourceSHA {
			return fmt.Errorf("performance resume source SHA %s does not match current source SHA %s", loadedProgress.SourceSHA, sourceSHA)
		}
		loadedState, err := readPerformanceState(statePath, sourceSHA)
		if err != nil {
			return err
		}
		if loadedState.Budget != budget {
			return fmt.Errorf("performance resume budget %s does not match current budget %s", loadedState.Budget, budget)
		}
		current, state = loadedProgress, loadedState
		completed := make(map[string]struct{}, len(current.Completed))
		for _, id := range current.Completed {
			completed[id] = struct{}{}
		}
		filtered := state.Cases[:0]
		for _, result := range state.Cases {
			if _, ok := completed[result.ID]; ok {
				filtered = append(filtered, result)
			}
		}
		state.Cases = filtered
		resultIDs := make(map[string]struct{}, len(state.Cases))
		for _, result := range state.Cases {
			resultIDs[result.ID] = struct{}{}
		}
		for _, id := range current.Completed {
			if id == "performance-optional/webtransport-capability" {
				continue
			}
			if _, ok := resultIDs[id]; !ok {
				return errors.New("performance progress and structured result state disagree")
			}
		}
	}
	if err := writeProgress(progressPath, current, tests); err != nil {
		return err
	}
	if err := writePerformanceState(statePath, state); err != nil {
		return err
	}
	for {
		if cause := context.Cause(executionCtx); cause != nil {
			next := firstIncomplete(tests, current.Completed)
			if next != nil {
				state.Cases = mergeCaseResult(state.Cases, perfreport.CaseResult{ID: next.ID, Section: sectionForCase(next.ID), Status: perfreport.StatusFail, Stage: "suite budget", FirstError: fmt.Sprintf("performance suite exhausted its %s wall-clock budget", budget), StartedAt: time.Now(), EndedAt: time.Now()})
			}
			if len(state.Cases) > 0 {
				if writeErr := writePerformanceState(statePath, state); writeErr != nil {
					return errors.Join(cause, writeErr)
				}
				if writeErr := perfreport.WriteMarkdown(reportPath, performanceReport(sourceSHA, state, environment, perfreport.StatusFail)); writeErr != nil {
					return errors.Join(cause, writeErr)
				}
			}
			return fmt.Errorf("performance suite exhausted its %s wall-clock budget: %w", budget, cause)
		}
		next := firstIncomplete(tests, current.Completed)
		if next == nil {
			status := perfreport.StatusPass
			failure := firstPerformanceCaseFailure(state.Cases)
			if failure != nil {
				status = perfreport.StatusFail
			}
			report := performanceReport(sourceSHA, state, environment, status)
			if err := perfreport.WriteMarkdown(reportPath, report); err != nil {
				return fmt.Errorf("write performance report: %w", err)
			}
			if failure != nil {
				return failure
			}
			if err := clearProgress(progressPath); err != nil {
				return err
			}
			if err := os.Remove(statePath); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
			_, err := fmt.Fprintln(stdout, "ALL GREEN")
			return err
		}
		runID, err := newRunID(next.ID)
		if err != nil {
			return err
		}
		tempDir, err := os.MkdirTemp("", "flowersec-test-"+safeName(next.ID)+"-")
		if err != nil {
			return err
		}
		resultPath := filepath.Join(tempDir, "case-result.json")
		started := time.Now()
		fmt.Fprintf(stdout, "[RUN ] %s\n", next.ID)
		runErr := runRegisteredTest(executionCtx, *next, runContext{RunID: runID, TempDir: tempDir, ResultPath: resultPath, Root: root, Debug: debug, PerformanceBudget: budget})
		duration := time.Since(started).Round(time.Millisecond)
		if next.ID == "performance-optional/webtransport-capability" && runErr != nil {
			reason := firstLine(runErr.Error())
			for _, candidate := range tests {
				if candidate.Suite != "performance-optional" || candidate.ID == next.ID {
					continue
				}
				state.Cases = append(state.Cases, perfreport.CaseResult{ID: candidate.ID, Section: sectionForCase(candidate.ID), Status: perfreport.StatusUnsupported, Limitation: "WebTransport/Chromium capability preflight failed: " + reason})
				current.Completed = append(current.Completed, candidate.ID)
			}
			current.Completed = append(current.Completed, next.ID)
			if err := writePerformanceState(statePath, state); err != nil {
				return err
			}
			if err := writeProgress(progressPath, current, tests); err != nil {
				return err
			}
			_ = os.RemoveAll(tempDir)
			fmt.Fprintf(stdout, "[UNSUPPORTED] WebTransport/Chromium: %s\n", reason)
			continue
		}
		if next.ID == "performance-optional/webtransport-capability" {
			current.Completed = append(current.Completed, next.ID)
			if err := writeProgress(progressPath, current, tests); err != nil {
				return err
			}
			if err := os.RemoveAll(tempDir); err != nil {
				return err
			}
			fmt.Fprintf(stdout, "[PASS] %s %s\n", next.ID, duration)
			continue
		}
		result, resultErr := perfreport.ReadCaseResult(resultPath)
		result.StartedAt = started
		result.EndedAt = time.Now()
		if resultErr == nil && result.ID != next.ID {
			resultErr = fmt.Errorf("structured case result ID %q does not match registry ID %q", result.ID, next.ID)
		}
		if runErr == nil && resultErr != nil {
			runErr = fmt.Errorf("structured case result: %w", resultErr)
		}
		if runErr == nil && result.Status == perfreport.StatusFail {
			state.Cases = mergeCaseResult(state.Cases, result)
			current.Completed = append(current.Completed, next.ID)
			if err := writePerformanceState(statePath, state); err != nil {
				return err
			}
			if err := writeProgress(progressPath, current, tests); err != nil {
				return err
			}
			if err := perfreport.WriteMarkdown(reportPath, performanceReport(sourceSHA, state, environment, perfreport.StatusFail)); err != nil {
				return fmt.Errorf("write partial performance report: %w", err)
			}
			failure := boundedText(result.FirstError, 64<<10)
			logPath, logErr := writeFailure(progressPath, next.ID, failure)
			if !debug {
				_ = os.RemoveAll(tempDir)
			}
			fmt.Fprintf(stderr, "[FAIL] %s %s: %s\n", next.ID, duration, firstLine(failure))
			if logErr == nil {
				fmt.Fprintf(stderr, "failure log: %s\n", logPath)
			}
			if logErr != nil {
				return logErr
			}
			continue
		}
		if runErr != nil {
			if resultErr != nil {
				result = perfreport.CaseResult{ID: next.ID, Section: sectionForCase(next.ID), Status: perfreport.StatusFail, StartedAt: started, EndedAt: time.Now(), Stage: "runner", FirstError: firstLine(runErr.Error())}
			} else {
				result.Status = perfreport.StatusFail
				result.FirstError = firstLine(result.FirstError)
				if result.Stage == "" {
					result.Stage = "test"
				}
				if result.FirstError == "" {
					result.FirstError = firstLine(runErr.Error())
				}
			}
			state.Cases = mergeCaseResult(state.Cases, result)
			if err := writePerformanceState(statePath, state); err != nil {
				return errors.Join(runErr, err)
			}
			if err := perfreport.WriteMarkdown(reportPath, performanceReport(sourceSHA, state, environment, perfreport.StatusFail)); err != nil {
				return errors.Join(runErr, err)
			}
			failure := boundedText(runErr.Error(), 64<<10)
			logPath, logErr := writeFailure(progressPath, next.ID, failure)
			if !debug && !errors.Is(runErr, errTeardownTimeout) {
				_ = os.RemoveAll(tempDir)
			}
			fmt.Fprintf(stderr, "[FAIL] %s %s: %s\n", next.ID, duration, firstLine(failure))
			if logErr == nil {
				fmt.Fprintf(stderr, "failure log: %s\n", logPath)
			}
			return errors.Join(runErr, logErr)
		}
		state.Cases = mergeCaseResult(state.Cases, result)
		current.Completed = append(current.Completed, next.ID)
		if err := writePerformanceState(statePath, state); err != nil {
			return err
		}
		if err := writeProgress(progressPath, current, tests); err != nil {
			return err
		}
		if firstPerformanceCaseFailure(state.Cases) != nil {
			if err := perfreport.WriteMarkdown(reportPath, performanceReport(sourceSHA, state, environment, perfreport.StatusFail)); err != nil {
				return fmt.Errorf("refresh partial performance report: %w", err)
			}
		}
		_ = os.Remove(failurePath(progressPath, next.ID))
		if err := os.RemoveAll(tempDir); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "[PASS] %s %s\n", next.ID, duration)
	}
}

func performanceReport(sourceSHA string, state performanceState, environment perfreport.Environment, status perfreport.Status) perfreport.Report {
	return perfreport.Report{SourceSHA: sourceSHA, Status: status, StartedAt: state.StartedAt, EndedAt: time.Now(), Budget: state.Budget, Environment: environment, Cases: state.Cases}
}

func firstPerformanceCaseFailure(results []perfreport.CaseResult) error {
	for _, result := range results {
		if result.Status == perfreport.StatusFail {
			return fmt.Errorf("performance case %s failed: %s", result.ID, result.FirstError)
		}
	}
	return nil
}

func mergeCaseResult(results []perfreport.CaseResult, next perfreport.CaseResult) []perfreport.CaseResult {
	for index := range results {
		if results[index].ID == next.ID {
			results[index] = next
			return results
		}
	}
	return append(results, next)
}

func sectionForCase(id string) perfreport.Section {
	switch {
	case strings.Contains(id, "/capacity/"):
		return perfreport.SectionCapacity
	case strings.Contains(id, "/throughput/"):
		return perfreport.SectionStreamingThroughput
	case strings.Contains(id, "/single-connection/"):
		return perfreport.SectionSingleConnection
	case strings.Contains(id, "/soak"):
		return perfreport.SectionSoak
	default:
		return perfreport.SectionConnectionEstablishment
	}
}

func capturePerformanceEnvironment() (perfreport.Environment, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return perfreport.Environment{}, err
	}
	environment := perfreport.Environment{HostName: hostname, Architecture: runtime.GOARCH, LogicalCPUs: runtime.NumCPU(), GoVersion: runtime.Version()}
	environment.Kernel = commandVersion("uname", "-r")
	environment.NodeVersion = commandVersion("node", "--version")
	chromium := os.Getenv("FLOWERSEC_CHROMIUM_EXECUTABLE")
	if chromium != "" {
		environment.ChromiumVersion = commandVersion(chromium, "--version")
	}
	osRelease, _ := os.ReadFile("/etc/os-release")
	for _, line := range strings.Split(string(osRelease), "\n") {
		if strings.HasPrefix(line, "PRETTY_NAME=") {
			environment.OS = strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), "\"")
		}
	}
	cpuInfo, _ := os.ReadFile("/proc/cpuinfo")
	environment.CPUModel = cpuModelFromSources(string(cpuInfo), commandVersion("lscpu"))
	memoryInfo, _ := os.ReadFile("/proc/meminfo")
	for _, line := range strings.Split(string(memoryInfo), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "MemTotal:" {
			kib, _ := strconv.ParseUint(fields[1], 10, 64)
			environment.MemoryBytes = kib << 10
			break
		}
	}
	if strings.TrimSpace(environment.HostName) == "" || environment.OS == "" || environment.Kernel == "" || environment.CPUModel == "" || environment.MemoryBytes == 0 {
		return perfreport.Environment{}, fmt.Errorf("incomplete or unsupported performance environment: host=%q os=%q kernel=%q cpu=%q memory=%d", environment.HostName, environment.OS, environment.Kernel, environment.CPUModel, environment.MemoryBytes)
	}
	return environment, nil
}

func commandVersion(name string, arguments ...string) string {
	output, err := exec.Command(name, arguments...).Output()
	if err != nil {
		return "unavailable"
	}
	return strings.TrimSpace(string(output))
}

func cpuModelFromSources(procCPUInfo, lscpuOutput string) string {
	for _, line := range strings.Split(procCPUInfo, "\n") {
		if strings.HasPrefix(line, "model name") {
			return strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
		}
	}
	for _, line := range strings.Split(lscpuOutput, "\n") {
		if strings.HasPrefix(line, "Model name:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "Model name:"))
		}
	}
	return ""
}
