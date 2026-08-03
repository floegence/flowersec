package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestRunnerPreflightEveryCheckIsClosedAndFailClosed(t *testing.T) {
	request, facts := greenRunnerPreflightFixture("formal")
	report := evaluateRunnerPreflight(request, facts)
	if report.Status != "GREEN" || report.Classification != "none" {
		t.Fatalf("green report = %#v", report)
	}

	mutations := map[string]func(*runnerPreflightFacts){
		"runner_context":         func(f *runnerPreflightFacts) { f.Context = false },
		"runner_reachability":    func(f *runnerPreflightFacts) { f.Reachable = false },
		"launcher_runtime":       func(f *runnerPreflightFacts) { f.LauncherRuntime = "" },
		"runner_platform":        func(f *runnerPreflightFacts) { f.PlatformValid = false },
		"source_sha":             func(f *runnerPreflightFacts) { f.SourceSHA = strings.Repeat("b", 40) },
		"source_clean":           func(f *runnerPreflightFacts) { f.Clean = false },
		"base_ancestry":          func(f *runnerPreflightFacts) { f.BaseAncestor = false },
		"manifest_identity":      func(f *runnerPreflightFacts) { f.ManifestEqual = false },
		"base_checkout":          func(f *runnerPreflightFacts) { f.BaseCheckoutReady = false },
		"runner_identity":        func(f *runnerPreflightFacts) { f.IdentityValid = false },
		"toolchain_digest":       func(f *runnerPreflightFacts) { f.ToolchainSHA = strings.Repeat("c", 64) },
		"typescript_dist_digest": func(f *runnerPreflightFacts) { f.DistSHA = strings.Repeat("d", 64) },
		"required_tools":         func(f *runnerPreflightFacts) { f.Tools["go"] = false },
		"tool_versions":          func(f *runnerPreflightFacts) { f.GoVersion = "wrong" },
		"rust_dependency_cache":  func(f *runnerPreflightFacts) { f.RustDepsReady = false },
		"chromium":               func(f *runnerPreflightFacts) { f.ChromiumVersion = "wrong" },
		"netns_canary":           func(f *runnerPreflightFacts) { f.NetNSCanary = false },
		"bpf_canary":             func(f *runnerPreflightFacts) { f.BPFCanary = false },
		"cgroup_canary":          func(f *runnerPreflightFacts) { f.CgroupCanary = false },
		"cgroup_controllers":     func(f *runnerPreflightFacts) { f.Controllers = []string{"cpu"} },
		"cpu":                    func(f *runnerPreflightFacts) { f.EffectiveCPUs = 5 },
		"memory":                 func(f *runnerPreflightFacts) { f.MemoryAvailable = 1 },
		"swap":                   func(f *runnerPreflightFacts) { f.LaneSwapLimit = "max" },
		"pids":                   func(f *runnerPreflightFacts) { f.PidsLimit = "1" },
		"disk":                   func(f *runnerPreflightFacts) { f.DiskAvailable = 1 },
		"nofile":                 func(f *runnerPreflightFacts) { f.NoFileLimit = 1 },
		"artifact_fresh":         func(f *runnerPreflightFacts) { f.ArtifactFresh = false },
		"unique_job_lock":        func(f *runnerPreflightFacts) { f.LockAvailable = false },
		"residual_processes":     func(f *runnerPreflightFacts) { f.ResidualProcess = 1 },
		"residual_netns":         func(f *runnerPreflightFacts) { f.ResidualNetNS = 1 },
		"residual_cgroups":       func(f *runnerPreflightFacts) { f.ResidualCgroup = 1 },
		"residual_bpf":           func(f *runnerPreflightFacts) { f.ResidualBPF = 1 },
		"remote_dns":             func(f *runnerPreflightFacts) { f.DNSReachable = false },
		"dependency_metadata":    func(f *runnerPreflightFacts) { f.DependencyReady = false },
	}
	for id, mutate := range mutations {
		t.Run(id, func(t *testing.T) {
			copy := facts
			copy.Tools = cloneBoolMap(facts.Tools)
			mutate(&copy)
			failed := evaluateRunnerPreflight(request, copy)
			if failed.Status != "RED" {
				t.Fatalf("status = %q", failed.Status)
			}
			check := runnerPreflightCheckByID(t, failed, id)
			if check.Status != "RED" || check.Classification == "" || check.Message == "" || check.Expected == "" {
				t.Fatalf("check = %#v", check)
			}
		})
	}
	if len(mutations) != len(report.Checks) {
		t.Fatalf("tested checks = %d, report checks = %d", len(mutations), len(report.Checks))
	}
}

func TestRunnerPreflightRejectsNarrowFormalLaneCPUCanary(t *testing.T) {
	request, facts := greenRunnerPreflightFixture("formal")
	facts.LaneCPUs = 1
	facts.LaneCPUMax = "100000 100000"

	report := evaluateRunnerPreflight(request, facts)
	check := runnerPreflightCheckByID(t, report, "cpu")
	if report.Status != "RED" || check.Status != "RED" || check.Classification != "environment" || !strings.Contains(check.Expected, "lane=2") {
		t.Fatalf("CPU check = %#v, report status = %s", check, report.Status)
	}
}

func TestRunnerPreflightEffectiveCPUCountUsesWorkloadCgroupRoot(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "cpuset.cpus.effective"), []byte("0-5\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := runnerPreflightEffectiveCPUCount(root); got != 6 {
		t.Fatalf("effective CPU count = %d, want 6", got)
	}
}

func TestRunnerPreflightRejectsMissingRustDependencyCacheBeforeFormalWorkload(t *testing.T) {
	request, facts := greenRunnerPreflightFixture("formal")
	facts.RustDepsReady = false

	report := evaluateRunnerPreflight(request, facts)
	if report.Status != "RED" || report.WorkloadStarted {
		t.Fatalf("report = %#v", report)
	}
	check := runnerPreflightCheckByID(t, report, "rust_dependency_cache")
	if check.Status != "RED" || check.Classification != "environment" || check.Actual != "false" || check.Expected != "true" {
		t.Fatalf("check = %#v", check)
	}
}

func TestRunnerPreflightIdentityFailureReportsTheValidatorReason(t *testing.T) {
	request, facts := greenRunnerPreflightFixture("formal")
	facts.IdentityValid = false
	facts.IdentityError = "runner source or argv digest drift"

	report := evaluateRunnerPreflight(request, facts)
	check := runnerPreflightCheckByID(t, report, "runner_identity")
	if check.Status != "RED" || !strings.Contains(check.Actual, `identity_error="runner source or argv digest drift"`) {
		t.Fatalf("runner identity check = %#v", check)
	}
}

func TestRunnerPreflightRustDependencyProbeIsOfflineAndPreservesArguments(t *testing.T) {
	directory := t.TempDir()
	argumentsPath := filepath.Join(directory, "arguments")
	offlinePath := filepath.Join(directory, "offline")
	rustupPath := filepath.Join(directory, "rustup")
	script := `#!/bin/sh
printf '%s\n' "$@" > "$FLOWERSEC_TEST_ARGUMENTS"
printf '%s\n' "${CARGO_NET_OFFLINE:-}" > "$FLOWERSEC_TEST_OFFLINE"
exit "${FLOWERSEC_TEST_STATUS:-0}"
`
	if err := os.WriteFile(rustupPath, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", directory)
	t.Setenv("FLOWERSEC_TEST_ARGUMENTS", argumentsPath)
	t.Setenv("FLOWERSEC_TEST_OFFLINE", offlinePath)
	t.Setenv("CARGO_NET_OFFLINE", "false")
	repository := filepath.Join(directory, `repo $() 'quoted'`)
	if !runnerPreflightRustDependencies(context.Background(), repository) {
		t.Fatal("offline dependency probe rejected the successful command")
	}
	arguments, err := os.ReadFile(argumentsPath)
	if err != nil {
		t.Fatal(err)
	}
	wantArguments := strings.Join([]string{
		"run", "1.88.0", "cargo", "metadata", "--locked", "--offline", "--format-version", "1",
		"--manifest-path", filepath.Join(repository, "flowersec-rust", "Cargo.toml"), "",
	}, "\n")
	if string(arguments) != wantArguments {
		t.Fatalf("arguments = %q, want %q", arguments, wantArguments)
	}
	offline, err := os.ReadFile(offlinePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(offline) != "true\n" {
		t.Fatalf("CARGO_NET_OFFLINE = %q", offline)
	}

	t.Setenv("FLOWERSEC_TEST_STATUS", "17")
	if runnerPreflightRustDependencies(context.Background(), repository) {
		t.Fatal("offline dependency probe accepted the failed command")
	}
}

func TestRunnerPreflightBaseCheckoutUsesFormalCloneAndCleansScratch(t *testing.T) {
	directory := t.TempDir()
	argumentsPath := filepath.Join(directory, "arguments")
	gitPath := filepath.Join(directory, "git")
	script := `#!/bin/sh
printf '%s\n' "$*" >> "$FLOWERSEC_TEST_ARGUMENTS"
exit "${FLOWERSEC_TEST_STATUS:-0}"
`
	if err := os.WriteFile(gitPath, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", directory)
	t.Setenv("FLOWERSEC_TEST_ARGUMENTS", argumentsPath)
	repository := filepath.Join(directory, "repository")
	baseSHA := strings.Repeat("b", 40)
	if !runnerPreflightBaseCheckout(context.Background(), repository, baseSHA) {
		t.Fatal("base checkout probe rejected successful formal clone commands")
	}
	arguments, err := os.ReadFile(argumentsPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(arguments)), "\n")
	if len(lines) != 2 || !strings.HasPrefix(lines[0], "clone --quiet --no-local --no-checkout "+repository+" ") ||
		!strings.Contains(lines[1], "checkout --quiet --detach "+baseSHA) {
		t.Fatalf("git arguments = %q", lines)
	}
	cloneFields := strings.Fields(lines[0])
	checkout := cloneFields[len(cloneFields)-1]
	if _, err := os.Lstat(filepath.Dir(checkout)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("base checkout scratch was not removed: %v", err)
	}
	t.Setenv("FLOWERSEC_TEST_STATUS", "17")
	if runnerPreflightBaseCheckout(context.Background(), repository, baseSHA) {
		t.Fatal("base checkout probe accepted a failed formal clone")
	}
}

func TestRunnerPreflightStableExitCodes(t *testing.T) {
	request, facts := greenRunnerPreflightFixture("formal")
	for name, test := range map[string]struct {
		mutate func(*runnerPreflightFacts)
		want   int
	}{
		"environment": {func(f *runnerPreflightFacts) { f.Reachable = false }, runnerPreflightEnvironment},
		"identity":    {func(f *runnerPreflightFacts) { f.Clean = false }, runnerPreflightIdentity},
		"residual":    {func(f *runnerPreflightFacts) { f.ResidualNetNS = 1 }, runnerPreflightResidual},
	} {
		t.Run(name, func(t *testing.T) {
			copy := facts
			test.mutate(&copy)
			if got := runnerPreflightExitCode(evaluateRunnerPreflight(request, copy)); got != test.want {
				t.Fatalf("exit code = %d, want %d", got, test.want)
			}
		})
	}
	err := runnerPreflightError(runnerPreflightInput, "bad input")
	var coded interface{ ExitCode() int }
	if !errors.As(err, &coded) || coded.ExitCode() != runnerPreflightInput {
		t.Fatalf("input error = %v", err)
	}
}

func TestRunnerPreflightInvalidInputWritesClosedReportWithoutCollection(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(root, "preflight.json")
	request := runnerPreflightRequest{Mode: "invalid", OutputPath: output}
	err = runRunnerPreflight(context.Background(), request, io.Discard)
	var coded interface{ ExitCode() int }
	if !errors.As(err, &coded) || coded.ExitCode() != runnerPreflightInput {
		t.Fatalf("error = %v", err)
	}
	data, readErr := os.ReadFile(output)
	if readErr != nil {
		t.Fatal(readErr)
	}
	var report runnerPreflightReport
	if decodeErr := decodeStrictJSON(data, &report); decodeErr != nil {
		t.Fatal(decodeErr)
	}
	if report.Status != "RED" || report.Classification != "input" || report.CheckID != "input_config" || report.WorkloadStarted {
		t.Fatalf("report = %#v", report)
	}
}

func TestRunnerPreflightJSONSchemaIsClosed(t *testing.T) {
	request, facts := greenRunnerPreflightFixture("focused")
	report := evaluateRunnerPreflight(request, facts)
	var output bytes.Buffer
	if err := writeRunnerPreflightReport("-", report, &output); err != nil {
		t.Fatal(err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(output.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	assertExactKeys(t, raw, []string{"base_sha", "check_id", "checks", "classification", "duration_ms", "message", "mode", "schema", "source_sha", "status", "workload_started"})
	var checks []map[string]json.RawMessage
	if err := json.Unmarshal(raw["checks"], &checks); err != nil {
		t.Fatal(err)
	}
	for _, check := range checks {
		assertExactKeys(t, check, []string{"actual", "check_id", "classification", "expected", "message", "status"})
	}
	if report.WorkloadStarted {
		t.Fatal("preflight report claimed that workload started")
	}
}

func TestRunnerPreflightLockRequiresExactOwnerAndContention(t *testing.T) {
	path := filepath.Join(t.TempDir(), "job.lock")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := file.WriteString("formal-job\n"); err != nil {
		t.Fatal(err)
	}
	if runnerPreflightLockHeld(path, "formal-job") {
		t.Fatal("unlocked file was accepted")
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	if !runnerPreflightLockHeld(path, "formal-job") {
		t.Fatal("held exact-owner lock was rejected")
	}
	if runnerPreflightLockHeld(path, "other-job") {
		t.Fatal("wrong lock owner was accepted")
	}
}

func TestRunnerPreflightDependencyProbeHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	started := time.Now()
	dns, metadata := runnerPreflightDependencies(ctx, "formal", []string{"https://preflight.invalid/metadata"})
	if dns || metadata || time.Since(started) > time.Second {
		t.Fatalf("cancelled probe = dns:%t metadata:%t duration:%s", dns, metadata, time.Since(started))
	}
}

func TestRunnerPreflightRequestRejectsDriftAndUnsafePaths(t *testing.T) {
	request, _ := greenRunnerPreflightFixture("formal")
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	request.RepositoryPath = filepath.Join(root, "repository")
	request.RunnerConfigPath = filepath.Join(root, "runner.json")
	request.OutputPath = filepath.Join(root, "preflight.json")
	request.ArtifactPath = filepath.Join(root, "report.json")
	request.LockPath = filepath.Join(root, ".formal.lock")
	request.RunnerExecutable = filepath.Join(root, "transport-release-runner")
	request.RunnerExecutableSHA256 = strings.Repeat("3", 64)
	request.HostBPFExecutable = filepath.Join(root, "bpftool")
	if err := validateRunnerPreflightRequest(request); err != nil {
		t.Fatal(err)
	}
	mutations := []func(*runnerPreflightRequest){
		func(r *runnerPreflightRequest) { r.SHA = "short" },
		func(r *runnerPreflightRequest) { r.BaseSHA = r.SHA },
		func(r *runnerPreflightRequest) { r.OutputPath = filepath.Join(root, "missing", "unsafe.json") },
		func(r *runnerPreflightRequest) { r.LockOwner = "job;bad" },
		func(r *runnerPreflightRequest) { r.DependencyURLs = []string{"file:///etc/passwd"} },
	}
	for index, mutate := range mutations {
		copy := request
		mutate(&copy)
		if err := validateRunnerPreflightRequest(copy); err == nil {
			t.Fatalf("mutation %d was accepted", index)
		}
	}
}

func TestRunnerPreflightRegressionRuleAndBoundedCallers(t *testing.T) {
	repository := filepath.Clean(filepath.Join("..", ".."))
	agents, err := os.ReadFile(filepath.Join(repository, "AGENTS.md"))
	if err != nil {
		t.Fatal(err)
	}
	rule := "Every remote focused or formal workload must pass the checked-in preflight in the exact workload context. Any later environment-class failure that preflight could have detected requires a regression contract and preflight update before retry."
	if strings.Count(string(agents), rule) != 1 {
		t.Fatal("AGENTS.md must contain the unified preflight regression rule exactly once")
	}
	for _, name := range []string{"transport-v2-focused-tail-remote.sh", "transport-v2-release-runner.sh"} {
		data, err := os.ReadFile(filepath.Join(repository, "scripts", name))
		if err != nil {
			t.Fatal(err)
		}
		script := string(data)
		if !strings.Contains(script, "runner-preflight") || !strings.Contains(script, "timeout --signal=TERM --kill-after=1s 30s") {
			t.Fatalf("%s does not use the bounded unified preflight", name)
		}
	}
}

func greenRunnerPreflightFixture(mode string) (runnerPreflightRequest, runnerPreflightFacts) {
	sha := strings.Repeat("a", 40)
	toolchain := strings.Repeat("1", 64)
	dist := strings.Repeat("2", 64)
	request := runnerPreflightRequest{Mode: mode, SHA: sha, BaseSHA: strings.Repeat("0", 40), ExpectedToolchainSHA256: toolchain, ExpectedDistSHA256: dist, LockOwner: "preflight-job", CgroupRootPath: "/sys/fs/cgroup", DependencyURLs: []string{"https://dependencies.example.invalid/metadata"}}
	tools := make(map[string]bool)
	for _, tool := range runnerPreflightTools(mode) {
		tools[tool] = true
	}
	facts := runnerPreflightFacts{
		Context: true, Reachable: true, LauncherRuntime: "lxc", PlatformValid: true, PlatformActual: "linux/arm64 ubuntu 24.04", SourceSHA: sha, Clean: true, BaseAncestor: true, ManifestEqual: true,
		ConfigValid: true, IdentityValid: true, BaseCheckoutReady: true, ToolchainSHA: toolchain, DistSHA: dist, Tools: tools,
		GoVersion: "go version go1.26.5 linux/arm64", NodeVersion: "v24.14.1", TiniVersion: "tini version 0.19.0",
		RustVersion: "rustc 1.88.0 (6b00bc388 2025-06-23)", CargoVersion: "cargo 1.88.0 (873a06493 2025-05-10)",
		RustDepsReady:   true,
		ChromiumVersion: "151.0.7922.34", NetNSCanary: true, BPFCanary: true, CgroupCanary: true,
		Controllers: []string{"cpuset", "cpu", "memory", "pids"}, EffectiveCPUs: 6, LaneCPUs: 2, LaneCPUMax: "200000 100000", MemoryAvailable: 8 << 30, MemoryLimit: "max",
		LaneMemoryLimit: "4294967296", LaneSwapLimit: "0", LanePidsLimit: "8192",
		SwapLimit: "1073741824", PidsLimit: "8192", DiskAvailable: 8 << 30, NoFileLimit: 32768,
		ArtifactFresh: true, LockAvailable: true, DNSReachable: true, DependencyReady: true,
	}
	if mode == "focused" {
		facts.SwapLimit = "0"
		facts.LaneCPUs = 1
		facts.LaneCPUMax = "100000 100000"
		facts.LaneMemoryLimit = "3221225472"
		request.BaseSHA = ""
	}
	return request, facts
}

func TestRunnerPreflightFormalToolVersionsRejectMissingPinnedRust(t *testing.T) {
	request, facts := greenRunnerPreflightFixture("formal")
	facts.RustVersion = ""
	facts.CargoVersion = ""
	report := evaluateRunnerPreflight(request, facts)
	check := runnerPreflightCheckByID(t, report, "tool_versions")
	if check.Status != "RED" || !strings.Contains(check.Expected, "rustc/cargo 1.88.0") {
		t.Fatalf("tool_versions check = %#v", check)
	}
}

func runnerPreflightCheckByID(t *testing.T, report runnerPreflightReport, id string) runnerPreflightCheck {
	t.Helper()
	for _, check := range report.Checks {
		if check.CheckID == id {
			return check
		}
	}
	t.Fatalf("missing check %q", id)
	return runnerPreflightCheck{}
}

func cloneBoolMap(input map[string]bool) map[string]bool {
	output := make(map[string]bool, len(input))
	for key, value := range input {
		output[key] = value
	}
	return output
}

func assertExactKeys(t *testing.T, object map[string]json.RawMessage, want []string) {
	t.Helper()
	got := make([]string, 0, len(object))
	for key := range object {
		got = append(got, key)
	}
	sort.Strings(got)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("keys = %v, want %v", got, want)
	}
}
