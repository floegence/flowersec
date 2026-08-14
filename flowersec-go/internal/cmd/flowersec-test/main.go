package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

const planName = "flowersec-tests-v1"

const externalHostRoot = "/var/lib/flowersec-test"

const externalHostPath = "/var/lib/flowersec-test/cache/toolchains/go/bin:/var/lib/flowersec-test/cache/toolchains/node/bin:/var/lib/flowersec-test/home/.cargo/bin:/usr/local/go/bin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/var/lib/flowersec-test/home/.local/bin:/var/lib/flowersec-test/home/.swiftly/bin"

const teardownGrace = 10 * time.Second

const (
	standardPerformanceBudget = 10 * time.Minute
	minimumPerformanceBudget  = 5 * time.Minute
	maximumPerformanceBudget  = 24 * time.Hour
)

var errTeardownTimeout = errors.New("test teardown did not finish within the grace period")

type runContext struct {
	RunID             string
	TempDir           string
	ResultPath        string
	Root              string
	Debug             bool
	PerformanceBudget time.Duration
}

type registeredTest struct {
	ID      string
	Suite   string
	Timeout time.Duration
	Run     func(context.Context, runContext) error
}

type progress struct {
	Plan      string   `json:"plan"`
	SourceSHA string   `json:"source_sha"`
	Suite     string   `json:"suite"`
	Completed []string `json:"completed"`
}

func main() {
	if err := runCLI(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runCLI(args []string) error {
	if len(args) == 0 || (args[0] != "run" && args[0] != "resume" && args[0] != "status") {
		return errors.New("usage: flowersec-test <run|resume|status> [--suite NAME] [--report ABSOLUTE.md] [--budget DURATION] [--debug]")
	}
	action := args[0]
	flags := flag.NewFlagSet(action, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	suite := flags.String("suite", "acceptance", "test suite")
	report := flags.String("report", "", "absolute performance Markdown report path")
	budgetValue := flags.String("budget", "", "integrated performance suite wall-clock budget")
	debug := flags.Bool("debug", false, "retain test-owned debug output")
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 || (action == "status" && (*debug || *report != "" || *budgetValue != "")) {
		return errors.New("usage: flowersec-test <run|resume|status> [--suite NAME] [--report ABSOLUTE.md] [--budget DURATION] [--debug]")
	}
	performanceBudget := time.Duration(0)
	if *suite == "performance" && action != "status" {
		var err error
		performanceBudget, err = parsePerformanceBudget(*budgetValue)
		if err != nil {
			return err
		}
	} else if *budgetValue != "" {
		return errors.New("--budget is only valid for the integrated performance suite")
	}
	var tests []registeredTest
	var err error
	if *suite == "performance" {
		tests, err = selectPerformancePlan(registry())
	} else {
		tests, err = selectSuite(registry(), *suite)
	}
	if err != nil {
		return err
	}
	workingDirectory, err := os.Getwd()
	if err != nil {
		return err
	}
	if err := validateExecutionEnvironment(*suite, runtime.GOOS, os.Geteuid(), os.Getenv("HOME"), os.Getenv("PATH"), os.Getenv("TMPDIR"), os.Getenv("FLOWERSEC_TEST_STATE_DIR"), workingDirectory); err != nil {
		return err
	}
	stateDir, err := testStateDirectory(*suite)
	if err != nil {
		return err
	}
	path := filepath.Join(stateDir, safeName(*suite), "test-progress.json")
	root, err := repositoryRoot()
	if err != nil {
		return err
	}
	if *suite == "performance" && action != "status" {
		if err := validatePerformanceReportPath(*report, root); err != nil {
			return err
		}
	} else if *report != "" {
		return errors.New("--report is only valid for the integrated performance suite")
	}
	sha, err := repositorySourceSHA(root)
	if err != nil {
		return err
	}
	if action == "status" {
		return printStatus(os.Stdout, path, tests, *suite, sha)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *suite == "performance" {
		environment, err := capturePerformanceEnvironment()
		if err != nil {
			return err
		}
		return executePerformanceSuite(ctx, os.Stdout, os.Stderr, action, path, root, sha, tests, *debug, *report, environment, performanceBudget)
	}
	return executeSuite(ctx, os.Stdout, os.Stderr, action, path, root, *suite, sha, tests, *debug)
}

func parsePerformanceBudget(value string) (time.Duration, error) {
	if value == "" {
		return standardPerformanceBudget, nil
	}
	budget, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("invalid performance budget %q: %w", value, err)
	}
	if budget < minimumPerformanceBudget || budget > maximumPerformanceBudget {
		return 0, fmt.Errorf("performance budget must be between %s and %s", minimumPerformanceBudget, maximumPerformanceBudget)
	}
	return budget, nil
}

func performanceBudgetEnvironment(budget time.Duration) []string {
	return []string{"FLOWERSEC_PERFORMANCE_BUDGET=" + budget.String()}
}

func validatePerformanceReportPath(path, root string) error {
	if path == "" {
		return errors.New("integrated performance requires --report /absolute/path/performance-report.md")
	}
	if !filepath.IsAbs(path) || filepath.Ext(path) != ".md" {
		return errors.New("performance report path must be absolute and end in .md")
	}
	relative, err := filepath.Rel(root, filepath.Clean(path))
	if err != nil {
		return err
	}
	if relative == "." || relative != ".." && !strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
		return errors.New("performance report must be outside the repository")
	}
	return nil
}

func validateExecutionEnvironment(suite, goos string, euid int, home, path, temporary, state, workingDirectory string) error {
	if suite != "diagnostic" && suite != "performance" && suite != "performance-optional" {
		return nil
	}
	if goos != "linux" || euid != 0 {
		return errors.New("privileged test suites require a dedicated Linux host with root access")
	}
	wantHome := filepath.Join(externalHostRoot, "home")
	wantPath := externalHostPath
	wantTemporary := filepath.Join(externalHostRoot, "tmp")
	wantState := filepath.Join(externalHostRoot, "state")
	wantWorkspace := filepath.Join(externalHostRoot, "workspace")
	if home != wantHome || path != wantPath || temporary != wantTemporary || state != wantState || (workingDirectory != wantWorkspace && !strings.HasPrefix(workingDirectory, wantWorkspace+string(os.PathSeparator))) {
		return errors.New("privileged test suite environment is not the fixed root context")
	}
	return nil
}

func testStateDirectory(suite string) (string, error) {
	if suite == "diagnostic" || suite == "performance" || suite == "performance-optional" {
		return filepath.Join(externalHostRoot, "state"), nil
	}
	if configured := os.Getenv("FLOWERSEC_TEST_STATE_DIR"); configured != "" {
		return filepath.Abs(configured)
	}
	cache, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("resolve user cache directory: %w", err)
	}
	return filepath.Join(cache, "flowersec-test", "state"), nil
}

func repositorySourceSHA(root string) (string, error) {
	command := exec.Command("git", "-C", root, "rev-parse", "HEAD")
	output, err := command.Output()
	if err != nil {
		return "", fmt.Errorf("resolve repository source SHA: %w", err)
	}
	sha := strings.TrimSpace(string(output))
	if !validSourceSHA(sha) {
		return "", errors.New("repository source SHA is invalid")
	}
	return sha, nil
}

func validSourceSHA(value string) bool {
	if len(value) != 40 {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' && character < 'a' || character > 'f' {
			return false
		}
	}
	return true
}

func executeSuite(ctx context.Context, stdout, stderr io.Writer, action, path, root, suite, sourceSHA string, tests []registeredTest, debug bool) error {
	progressLock, err := lockProgress(path)
	if err != nil {
		return err
	}
	defer progressLock.Close()
	current := progress{Plan: planName, SourceSHA: sourceSHA, Suite: suite, Completed: []string{}}
	if action == "run" {
		if err := os.RemoveAll(filepath.Join(filepath.Dir(path), "failures")); err != nil {
			return fmt.Errorf("clear stale failure logs: %w", err)
		}
	}
	if action == "resume" {
		loaded, err := readProgress(path, tests, suite)
		if err == nil {
			current.Completed = loaded.Completed
			if loaded.SourceSHA != sourceSHA {
				if err := os.RemoveAll(filepath.Join(filepath.Dir(path), "failures")); err != nil {
					return fmt.Errorf("clear stale failure logs: %w", err)
				}
			} else {
				current = loaded
			}
			if loaded.SourceSHA != sourceSHA {
				current.SourceSHA = sourceSHA
			}
			if err := writeProgress(path, current, tests); err != nil {
				return err
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if err := writeProgress(path, current, tests); err != nil {
		return err
	}
	for {
		if err := context.Cause(ctx); err != nil {
			return err
		}
		next := firstIncomplete(tests, current.Completed)
		if next == nil {
			if err := clearProgress(path); err != nil {
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
		started := time.Now()
		fmt.Fprintf(stdout, "[RUN ] %s\n", next.ID)
		runErr := runRegisteredTest(ctx, *next, runContext{RunID: runID, TempDir: tempDir, Root: root, Debug: debug})
		duration := time.Since(started).Round(time.Millisecond)
		if runErr != nil {
			failure := boundedText(runErr.Error(), 64<<10)
			logPath, logErr := writeFailure(path, next.ID, failure)
			if !debug && !errors.Is(runErr, errTeardownTimeout) {
				_ = os.RemoveAll(tempDir)
			}
			fmt.Fprintf(stderr, "[FAIL] %s %s: %s\n", next.ID, duration, firstLine(failure))
			if logErr != nil {
				return errors.Join(runErr, logErr)
			}
			fmt.Fprintf(stderr, "failure log: %s\n", logPath)
			return runErr
		}
		if err := os.RemoveAll(tempDir); err != nil {
			return fmt.Errorf("remove successful test directory: %w", err)
		}
		_ = os.Remove(failurePath(path, next.ID))
		current.Completed = append(current.Completed, next.ID)
		if err := writeProgress(path, current, tests); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "[PASS] %s %s\n", next.ID, duration)
	}
}

func runRegisteredTest(parent context.Context, test registeredTest, run runContext) error {
	if err := context.Cause(parent); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(parent, test.Timeout)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- test.Run(ctx, run) }()
	select {
	case err := <-done:
		if cause := context.Cause(ctx); cause != nil {
			return errors.Join(cause, err)
		}
		return err
	case <-ctx.Done():
		timer := time.NewTimer(teardownGrace)
		defer timer.Stop()
		select {
		case err := <-done:
			return errors.Join(context.Cause(ctx), err)
		case <-timer.C:
			return errors.Join(context.Cause(ctx), errTeardownTimeout)
		}
	}
}

func selectSuite(all []registeredTest, suite string) ([]registeredTest, error) {
	var selected []registeredTest
	seen := make(map[string]struct{})
	for _, test := range all {
		if test.ID == "" || test.Suite == "" || test.Timeout <= 0 || test.Timeout > 10*time.Minute || test.Run == nil {
			return nil, errors.New("test registry contains an invalid entry")
		}
		if _, duplicate := seen[test.ID]; duplicate {
			return nil, fmt.Errorf("test registry contains duplicate ID %q", test.ID)
		}
		seen[test.ID] = struct{}{}
		if test.Suite == suite {
			selected = append(selected, test)
		}
	}
	if len(selected) == 0 {
		return nil, fmt.Errorf("unknown or empty test suite %q", suite)
	}
	return selected, nil
}

func repositoryRoot() (string, error) {
	current, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if regularFile(filepath.Join(current, "Makefile")) && regularFile(filepath.Join(current, "flowersec-go", "go.mod")) {
			return current, nil
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", errors.New("flowersec repository root not found")
		}
		current = parent
	}
}

func regularFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

func lockProgress(path string) (*os.File, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create test progress directory: %w", err)
	}
	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open test progress lock: %w", err)
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		_ = lock.Close()
		return nil, fmt.Errorf("lock test progress: %w", err)
	}
	return lock, nil
}

func readProgress(path string, tests []registeredTest, suite string) (progress, error) {
	file, err := os.Open(path)
	if err != nil {
		return progress{}, err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 1<<20))
	decoder.DisallowUnknownFields()
	var value progress
	if err := decoder.Decode(&value); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return progress{}, errors.New("test progress is not strict JSON")
	}
	if err := validateProgress(value, tests, suite); err != nil {
		return progress{}, err
	}
	return value, nil
}

func validateProgress(value progress, tests []registeredTest, suite string) error {
	if value.Plan != planName || !validSourceSHA(value.SourceSHA) || value.Suite != suite || value.Completed == nil {
		return errors.New("test progress plan is invalid; start a fresh run")
	}
	known := make(map[string]struct{}, len(tests))
	for _, test := range tests {
		known[test.ID] = struct{}{}
	}
	seen := make(map[string]struct{}, len(value.Completed))
	for _, id := range value.Completed {
		_, ok := known[id]
		if !ok {
			return errors.New("test progress completed IDs are invalid")
		}
		if _, duplicate := seen[id]; duplicate {
			return errors.New("test progress completed IDs contain duplicates")
		}
		seen[id] = struct{}{}
	}
	return nil
}

func clearProgress(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove completed test progress: %w", err)
	}
	if err := os.RemoveAll(filepath.Join(filepath.Dir(path), "failures")); err != nil {
		return fmt.Errorf("remove completed test failures: %w", err)
	}
	return nil
}

func writeProgress(path string, value progress, tests []registeredTest) error {
	if err := validateProgress(value, tests, value.Suite); err != nil {
		return err
	}
	var raw bytes.Buffer
	encoder := json.NewEncoder(&raw)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		return err
	}
	return atomicWrite(path, raw.Bytes())
}

func atomicWrite(path string, raw []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".flowersec-test-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(raw); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func firstIncomplete(tests []registeredTest, completed []string) *registeredTest {
	done := make(map[string]struct{}, len(completed))
	for _, id := range completed {
		done[id] = struct{}{}
	}
	for index := range tests {
		if _, ok := done[tests[index].ID]; !ok {
			return &tests[index]
		}
	}
	return nil
}

func printStatus(output io.Writer, path string, tests []registeredTest, suite, sourceSHA string) error {
	current, err := readProgress(path, tests, suite)
	if errors.Is(err, os.ErrNotExist) {
		current = progress{Plan: planName, SourceSHA: sourceSHA, Suite: suite, Completed: []string{}}
	} else if err != nil {
		return err
	}
	if current.SourceSHA != sourceSHA {
		current.SourceSHA = sourceSHA
		if err := writeProgress(path, current, tests); err != nil {
			return err
		}
	}
	next := firstIncomplete(tests, current.Completed)
	nextID := ""
	if next != nil {
		nextID = next.ID
	}
	return json.NewEncoder(output).Encode(map[string]any{"plan": current.Plan, "source_sha": current.SourceSHA, "suite": current.Suite, "completed": current.Completed, "next": nextID})
}

func newRunID(testID string) (string, error) {
	random := make([]byte, 8)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	return safeName(testID) + "-" + hex.EncodeToString(random), nil
}

func safeName(value string) string {
	value = strings.Map(func(character rune) rune {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' {
			return character
		}
		return '-'
	}, strings.ToLower(value))
	return strings.Trim(value, "-")
}

func boundedText(value string, limit int) string {
	value = strings.TrimSpace(value)
	if len(value) > limit {
		value = value[len(value)-limit:]
	}
	return value
}

func firstLine(value string) string {
	if line, _, found := strings.Cut(value, "\n"); found {
		return line
	}
	return value
}

func failurePath(progressPath, testID string) string {
	return filepath.Join(filepath.Dir(progressPath), "failures", safeName(testID)+".log")
}

func writeFailure(progressPath, testID, failure string) (string, error) {
	path := failurePath(progressPath, testID)
	return path, atomicWrite(path, []byte(boundedText(failure, 64<<10)+"\n"))
}
