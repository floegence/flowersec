package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	runnerPreflightSchema      = "flowersec-runner-preflight-v1"
	runnerPreflightInput       = 10
	runnerPreflightEnvironment = 20
	runnerPreflightIdentity    = 30
	runnerPreflightResidual    = 40
)

type runnerPreflightRequest struct {
	Mode                    string   `json:"mode"`
	RepositoryPath          string   `json:"repository_path"`
	SHA                     string   `json:"sha"`
	BaseSHA                 string   `json:"base_sha,omitempty"`
	RunnerConfigPath        string   `json:"runner_config_path"`
	OutputPath              string   `json:"output_path"`
	ArtifactPath            string   `json:"artifact_path"`
	RunnerExecutable        string   `json:"runner_executable,omitempty"`
	RunnerExecutableSHA256  string   `json:"runner_executable_sha256,omitempty"`
	HostBPFExecutable       string   `json:"host_bpf_executable,omitempty"`
	ExpectedToolchainSHA256 string   `json:"expected_toolchain_sha256,omitempty"`
	ExpectedDistSHA256      string   `json:"expected_dist_sha256,omitempty"`
	LockPath                string   `json:"lock_path"`
	LockOwner               string   `json:"lock_owner"`
	CgroupRootPath          string   `json:"cgroup_root_path"`
	DependencyURLs          []string `json:"dependency_urls"`
}

type runnerPreflightCheck struct {
	CheckID        string `json:"check_id"`
	Status         string `json:"status"`
	Classification string `json:"classification"`
	Message        string `json:"message"`
	Actual         string `json:"actual"`
	Expected       string `json:"expected"`
}

type runnerPreflightReport struct {
	Schema          string                 `json:"schema"`
	Status          string                 `json:"status"`
	Classification  string                 `json:"classification"`
	Mode            string                 `json:"mode"`
	SourceSHA       string                 `json:"source_sha"`
	BaseSHA         string                 `json:"base_sha"`
	WorkloadStarted bool                   `json:"workload_started"`
	DurationMS      int64                  `json:"duration_ms"`
	CheckID         string                 `json:"check_id"`
	Message         string                 `json:"message"`
	Checks          []runnerPreflightCheck `json:"checks"`
}

type runnerPreflightFacts struct {
	Context           bool
	Reachable         bool
	LauncherRuntime   string
	PlatformValid     bool
	PlatformActual    string
	SourceSHA         string
	Clean             bool
	BaseAncestor      bool
	ManifestEqual     bool
	BaseCheckoutReady bool
	ConfigValid       bool
	IdentityValid     bool
	ConfigError       string
	IdentityError     string
	ToolchainSHA      string
	DistSHA           string
	Tools             map[string]bool
	GoVersion         string
	NodeVersion       string
	TiniVersion       string
	RustVersion       string
	CargoVersion      string
	RustDepsReady     bool
	ChromiumVersion   string
	NetNSCanary       bool
	BPFCanary         bool
	CgroupCanary      bool
	Controllers       []string
	EffectiveCPUs     int
	LaneCPUs          int
	LaneCPUMax        string
	LaneMemoryLimit   string
	LaneSwapLimit     string
	LanePidsLimit     string
	MemoryAvailable   uint64
	MemoryLimit       string
	SwapLimit         string
	PidsLimit         string
	DiskAvailable     uint64
	NoFileLimit       uint64
	ArtifactFresh     bool
	LockAvailable     bool
	ResidualProcess   int
	ResidualNetNS     int
	ResidualCgroup    int
	ResidualBPF       int
	DNSReachable      bool
	DependencyReady   bool
}

type runnerPreflightExitError struct {
	code int
	err  error
}

func (err *runnerPreflightExitError) Error() string { return err.err.Error() }
func (err *runnerPreflightExitError) Unwrap() error { return err.err }
func (err *runnerPreflightExitError) ExitCode() int { return err.code }

func runnerPreflightError(code int, message string) error {
	return &runnerPreflightExitError{code: code, err: errors.New(message)}
}

func runRunnerPreflight(ctx context.Context, request runnerPreflightRequest, output io.Writer) error {
	started := time.Now()
	if err := validateRunnerPreflightRequest(request); err != nil {
		report := runnerPreflightReport{
			Schema: runnerPreflightSchema, Status: "RED", Classification: "input", Mode: request.Mode,
			SourceSHA: request.SHA, BaseSHA: request.BaseSHA, WorkloadStarted: false,
			DurationMS: time.Since(started).Milliseconds(), CheckID: "input_config", Message: err.Error(),
			Checks: []runnerPreflightCheck{{CheckID: "input_config", Status: "RED", Classification: "input", Message: err.Error(), Actual: "invalid", Expected: "valid closed request"}},
		}
		if runnerPreflightOutputIsSafe(request.OutputPath) {
			if writeErr := writeRunnerPreflightReport(request.OutputPath, report, output); writeErr != nil {
				return runnerPreflightError(runnerPreflightInput, fmt.Sprintf("%v; write input report: %v", err, writeErr))
			}
		}
		return runnerPreflightError(runnerPreflightInput, err.Error())
	}
	if ctx == nil {
		ctx = context.Background()
	}
	bounded, cancel := context.WithTimeout(ctx, 29*time.Second)
	defer cancel()
	facts, collectErr := collectRunnerPreflightFacts(bounded, request)
	report := evaluateRunnerPreflight(request, facts)
	report.DurationMS = time.Since(started).Milliseconds()
	if collectErr != nil {
		report.Status = "RED"
		report.Classification = classifyRunnerPreflightError(collectErr)
		report.Checks = append(report.Checks, runnerPreflightCheck{
			CheckID: "preflight_collection", Status: "RED", Classification: report.Classification,
			Message: collectErr.Error(), Actual: "collection_error", Expected: "complete bounded collection",
		})
	}
	if report.Status != "GREEN" {
		report.Classification = runnerPreflightReportClassification(report)
		for _, check := range report.Checks {
			if check.Status == "RED" {
				report.CheckID, report.Message = check.CheckID, check.Message
				break
			}
		}
	}
	if err := writeRunnerPreflightReport(request.OutputPath, report, output); err != nil {
		return runnerPreflightError(runnerPreflightInput, fmt.Sprintf("write preflight report: %v", err))
	}
	if report.Status == "GREEN" {
		return nil
	}
	return runnerPreflightError(runnerPreflightExitCode(report), runnerPreflightFailureMessage(report))
}

func validateRunnerPreflightRequest(request runnerPreflightRequest) error {
	if request.Mode != "focused" && request.Mode != "formal" {
		return errors.New("runner-preflight mode must be focused or formal")
	}
	if !focusedTailSHA.MatchString(request.SHA) {
		return errors.New("runner-preflight sha must be a full lowercase Git SHA")
	}
	if request.Mode == "formal" {
		if !focusedTailSHA.MatchString(request.BaseSHA) || request.BaseSHA == request.SHA {
			return errors.New("formal runner-preflight requires a distinct full base SHA")
		}
	} else if request.BaseSHA != "" && !focusedTailSHA.MatchString(request.BaseSHA) {
		return errors.New("runner-preflight base SHA is invalid")
	}
	for name, path := range map[string]string{
		"repository": request.RepositoryPath, "runner config": request.RunnerConfigPath,
		"output": request.OutputPath, "artifact": request.ArtifactPath, "lock": request.LockPath,
		"cgroup root": request.CgroupRootPath,
	} {
		if path != "-" && (!filepath.IsAbs(path) || filepath.Clean(path) != path) {
			return fmt.Errorf("runner-preflight %s path must be absolute and canonical", name)
		}
	}
	if request.HostBPFExecutable != "" && (!filepath.IsAbs(request.HostBPFExecutable) || filepath.Clean(request.HostBPFExecutable) != request.HostBPFExecutable) {
		return errors.New("runner-preflight host BPF executable path must be absolute and canonical")
	}
	if !focusedTailName.MatchString(request.LockOwner) {
		return errors.New("runner-preflight lock owner must be a stable job identifier")
	}
	if request.RunnerExecutable == "" || request.RunnerExecutableSHA256 == "" || request.ExpectedToolchainSHA256 == "" || request.ExpectedDistSHA256 == "" {
		return errors.New("runner-preflight requires prepared runner, runner digest, toolchain digest, and TypeScript dist digest")
	}
	if request.Mode == "formal" && request.HostBPFExecutable == "" {
		return errors.New("formal runner-preflight requires the exact-kernel host bpftool")
	}
	if request.Mode == "formal" && len(request.DependencyURLs) == 0 {
		return errors.New("formal runner-preflight requires dependency URLs")
	}
	for _, endpoint := range request.DependencyURLs {
		if !strings.HasPrefix(endpoint, "https://") && !strings.HasPrefix(endpoint, "http://") {
			return errors.New("runner-preflight dependency URLs must use HTTP or HTTPS")
		}
	}
	if request.OutputPath != "-" {
		parent, err := canonicalDirectory(filepath.Dir(request.OutputPath), true)
		if err != nil || parent != filepath.Dir(request.OutputPath) {
			return errors.New("runner-preflight output parent must be an existing canonical non-symlink directory")
		}
	}
	artifactParent, err := canonicalDirectory(filepath.Dir(request.ArtifactPath), true)
	if err != nil || artifactParent != filepath.Dir(request.ArtifactPath) {
		return errors.New("runner-preflight artifact parent must be an existing canonical non-symlink directory")
	}
	for name, value := range map[string]string{
		"runner executable": request.RunnerExecutableSHA256,
		"toolchain digest":  request.ExpectedToolchainSHA256,
		"dist digest":       request.ExpectedDistSHA256,
	} {
		if value != "" && !validSHA256(value) {
			return fmt.Errorf("runner-preflight %s must be a SHA-256 digest", name)
		}
	}
	return nil
}

func collectRunnerPreflightFacts(ctx context.Context, request runnerPreflightRequest) (runnerPreflightFacts, error) {
	facts := runnerPreflightFacts{Tools: make(map[string]bool)}
	repository := filepath.Clean(request.RepositoryPath)
	if ctx == nil {
		ctx = context.Background()
	}
	if runtime.GOOS != "linux" {
		return facts, runnerPreflightError(runnerPreflightEnvironment, "runner-preflight requires Linux")
	}
	facts.Context = os.Getenv("FLOWERSEC_RUNNER_CONTEXT") == request.Mode &&
		os.Getenv("FLOWERSEC_RUNNER_CONTEXT_SHA") == request.SHA &&
		os.Getenv("FLOWERSEC_RUNNER_LOCK_OWNER") == request.LockOwner &&
		os.Getenv("FLOWERSEC_RUNNER_LAUNCHER_VERIFIED") == "1"
	facts.Reachable = os.Getenv("FLOWERSEC_RUNNER_REACHABILITY_VERIFIED") == "1"
	facts.LauncherRuntime = os.Getenv("FLOWERSEC_RUNNER_LAUNCHER_RUNTIME")
	facts.PlatformValid, facts.PlatformActual = runnerPreflightPlatform()
	facts.SourceSHA, _ = collectGitOutput(repository, "rev-parse", "HEAD")
	status, statusErr := collectGitOutput(repository, "status", "--porcelain", "--untracked-files=all")
	facts.Clean = statusErr == nil && status == ""
	facts.BaseAncestor = request.Mode == "focused"
	facts.ManifestEqual = request.Mode == "focused"
	if request.Mode == "formal" {
		facts.BaseAncestor = gitIsAncestor(repository, request.BaseSHA, request.SHA)
		facts.ManifestEqual = false
		if facts.BaseAncestor {
			baseManifest, err := gitShowFile(repository, request.BaseSHA, "testdata/transport_v2/performance_manifest.json")
			finalManifest, finalErr := os.ReadFile(filepath.Join(repository, "testdata/transport_v2/performance_manifest.json"))
			facts.ManifestEqual = err == nil && finalErr == nil && string(baseManifest) == string(finalManifest)
		}
		facts.BaseCheckoutReady = runnerPreflightBaseCheckout(ctx, repository, request.BaseSHA)
	}
	if err := validateRunnerPreflightConfig(request, repository); err == nil {
		facts.ConfigValid = true
	} else {
		facts.ConfigError = err.Error()
	}
	if err := validateRunnerPreflightIdentity(request, repository); err == nil {
		facts.IdentityValid = true
	} else {
		facts.IdentityError = err.Error()
	}
	facts.ToolchainSHA = runnerPreflightToolchainDigest(repository)
	facts.DistSHA = runnerPreflightDistDigest(filepath.Join(repository, "flowersec-ts/dist"))
	for _, tool := range runnerPreflightTools(request.Mode) {
		_, err := exec.LookPath(tool)
		facts.Tools[tool] = err == nil
	}
	if request.HostBPFExecutable != "" {
		info, err := os.Lstat(request.HostBPFExecutable)
		facts.Tools["host-bpftool"] = err == nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 && info.Mode()&0111 != 0
	}
	facts.GoVersion = runnerPreflightCommandOutput("go", "version")
	facts.NodeVersion = runnerPreflightCommandOutput("node", "--version")
	facts.TiniVersion = runnerPreflightCommandOutput("tini", "--version")
	if request.Mode == "formal" {
		facts.RustVersion = runnerPreflightCommandOutput("rustup", "run", "1.88.0", "rustc", "--version")
		facts.CargoVersion = runnerPreflightCommandOutput("rustup", "run", "1.88.0", "cargo", "--version")
		facts.RustDepsReady = runnerPreflightRustDependencies(ctx, repository)
	}
	facts.ChromiumVersion = runnerPreflightChromiumVersion(ctx, repository)
	facts.NetNSCanary = runnerPreflightNetNSCanary(ctx)
	facts.BPFCanary = runnerPreflightBPFCanary(ctx)
	facts.EffectiveCPUs = runnerPreflightEffectiveCPUCount(request.CgroupRootPath)
	facts.CgroupCanary, facts.Controllers, facts.LaneCPUs, facts.LaneCPUMax, facts.LaneMemoryLimit, facts.LaneSwapLimit, facts.LanePidsLimit = runnerPreflightCgroupCanary(ctx, request.CgroupRootPath, request.Mode)
	facts.MemoryAvailable = readMeminfoBytes("MemAvailable")
	facts.MemoryLimit = runnerPreflightCgroupValue("memory.max")
	facts.SwapLimit = runnerPreflightCgroupValue("memory.swap.max")
	facts.PidsLimit = runnerPreflightCgroupValue("pids.max")
	facts.DiskAvailable = runnerPreflightDiskAvailable(request.ArtifactPath)
	facts.NoFileLimit = runnerPreflightNoFileLimit()
	facts.ArtifactFresh = runnerPreflightFreshPath(request.ArtifactPath)
	facts.LockAvailable = runnerPreflightLockHeld(request.LockPath, request.LockOwner)
	facts.ResidualProcess, facts.ResidualNetNS, facts.ResidualCgroup, facts.ResidualBPF = runnerPreflightResiduals()
	facts.DNSReachable, facts.DependencyReady = runnerPreflightDependencies(ctx, request.Mode, request.DependencyURLs)
	return facts, nil
}

func evaluateRunnerPreflight(request runnerPreflightRequest, facts runnerPreflightFacts) runnerPreflightReport {
	report := runnerPreflightReport{Schema: runnerPreflightSchema, Status: "GREEN", Classification: "none", Mode: request.Mode, SourceSHA: facts.SourceSHA, BaseSHA: request.BaseSHA, WorkloadStarted: false, CheckID: "", Message: "", Checks: []runnerPreflightCheck{}}
	add := func(id string, ok bool, class, message, actual, expected string) {
		status := "GREEN"
		if !ok {
			status = "RED"
			report.Status = "RED"
		}
		report.Checks = append(report.Checks, runnerPreflightCheck{CheckID: id, Status: status, Classification: class, Message: message, Actual: actual, Expected: expected})
	}
	add("runner_context", facts.Context, "environment", "preflight ran in the exact workload context", fmt.Sprintf("mode=%s verified=%t", request.Mode, facts.Context), "mode and launcher context verified")
	add("runner_reachability", facts.Reachable, "environment", "the launcher verified the target and host key before entering the workload context", strconv.FormatBool(facts.Reachable), "true")
	add("launcher_runtime", facts.LauncherRuntime == "lxc" || facts.LauncherRuntime == "docker", "environment", "the checked-in launcher verified its container runtime", facts.LauncherRuntime, "lxc or docker")
	add("runner_platform", facts.PlatformValid, "identity", "runner uses the supported native Ubuntu workload platform", facts.PlatformActual, "linux/amd64 or linux/arm64; Ubuntu 24.04")
	add("source_sha", facts.SourceSHA == request.SHA, "identity", "checkout SHA matches the request", facts.SourceSHA, request.SHA)
	add("source_clean", facts.Clean, "identity", "checkout has no tracked or untracked changes", strconv.FormatBool(facts.Clean), "true")
	if request.Mode == "formal" {
		add("base_ancestry", facts.BaseAncestor, "identity", "base SHA is an ancestor of the candidate", strconv.FormatBool(facts.BaseAncestor), "true")
		add("manifest_identity", facts.ManifestEqual, "identity", "base and candidate manifests are byte-identical", strconv.FormatBool(facts.ManifestEqual), "true")
		add("base_checkout", facts.BaseCheckoutReady, "environment", "base checkout can be cloned in the exact workload context", strconv.FormatBool(facts.BaseCheckoutReady), "true")
	}
	identityActual := fmt.Sprintf("config=%t identity=%t", facts.ConfigValid, facts.IdentityValid)
	if facts.ConfigError != "" || facts.IdentityError != "" {
		identityActual += fmt.Sprintf(" config_error=%q identity_error=%q", facts.ConfigError, facts.IdentityError)
	}
	add("runner_identity", facts.ConfigValid && facts.IdentityValid, "identity", "private runner identity and executable/source/argv digests match", identityActual, "true/true")
	if request.ExpectedToolchainSHA256 != "" {
		add("toolchain_digest", facts.ToolchainSHA == request.ExpectedToolchainSHA256, "identity", "toolchain digest matches the prepared artifact", facts.ToolchainSHA, request.ExpectedToolchainSHA256)
	}
	if request.ExpectedDistSHA256 != "" {
		add("typescript_dist_digest", facts.DistSHA == request.ExpectedDistSHA256, "identity", "TypeScript dist digest matches the prepared artifact", facts.DistSHA, request.ExpectedDistSHA256)
	}
	missingTools := []string{}
	for _, tool := range runnerPreflightTools(request.Mode) {
		if !facts.Tools[tool] {
			missingTools = append(missingTools, tool)
		}
	}
	if request.HostBPFExecutable != "" && !facts.Tools["host-bpftool"] {
		missingTools = append(missingTools, "host-bpftool")
	}
	add("required_tools", len(missingTools) == 0, "environment", "required executables are available", strings.Join(missingTools, ","), "empty")
	versionsOK := strings.HasPrefix(facts.GoVersion, "go version go1.26.5 linux/") && facts.NodeVersion == "v24.14.1" && facts.TiniVersion == "tini version 0.19.0"
	versionExpected := "go1.26.5 linux/*; node v24.14.1; tini 0.19.0"
	if request.Mode == "formal" {
		versionsOK = versionsOK && facts.RustVersion == "rustc 1.88.0 (6b00bc388 2025-06-23)" && facts.CargoVersion == "cargo 1.88.0 (873a06493 2025-05-10)"
		versionExpected += "; rustc/cargo 1.88.0"
	}
	add("tool_versions", versionsOK, "environment", "workload tools match the pinned versions", fmt.Sprintf("go=%s node=%s tini=%s rustc=%s cargo=%s", facts.GoVersion, facts.NodeVersion, facts.TiniVersion, facts.RustVersion, facts.CargoVersion), versionExpected)
	if request.Mode == "formal" {
		add("rust_dependency_cache", facts.RustDepsReady, "environment", "the locked Rust dependency graph is available offline", strconv.FormatBool(facts.RustDepsReady), "true")
	}
	add("chromium", facts.ChromiumVersion == "151.0.7922.34", "environment", "Chromium is the pinned release", facts.ChromiumVersion, "151.0.7922.34")
	add("netns_canary", facts.NetNSCanary, "environment", "network namespace canary was created and removed", strconv.FormatBool(facts.NetNSCanary), "true")
	add("bpf_canary", facts.BPFCanary, "environment", "BPF canary was created and removed", strconv.FormatBool(facts.BPFCanary), "true")
	add("cgroup_canary", facts.CgroupCanary, "environment", "cgroup canary was created and removed", strconv.FormatBool(facts.CgroupCanary), "true")
	add("cgroup_controllers", containsAll(facts.Controllers, []string{"cpuset", "cpu", "memory", "pids"}), "environment", "required cgroup controllers are delegated", strings.Join(facts.Controllers, ","), "cpuset,cpu,memory,pids")
	requiredCPUs, laneCPUs := 1, 1
	if request.Mode == "formal" {
		requiredCPUs, laneCPUs = 8, collectionLaneCPUs
	}
	laneCPUMax := fmt.Sprintf("%d00000 100000", laneCPUs)
	add("cpu", facts.EffectiveCPUs >= requiredCPUs && facts.LaneCPUs == laneCPUs && facts.LaneCPUMax == laneCPUMax, "environment", "effective CPUs and the workload lane CPU window match the execution contract", fmt.Sprintf("effective=%d lane=%d cpu.max=%s", facts.EffectiveCPUs, facts.LaneCPUs, facts.LaneCPUMax), fmt.Sprintf("effective>=%d lane=%d cpu.max=%s", requiredCPUs, laneCPUs, laneCPUMax))
	memoryRequired := uint64(8 << 30)
	if request.Mode == "focused" {
		memoryRequired = 3 << 30
	}
	laneMemoryRequired := uint64(4 << 30)
	if request.Mode == "focused" {
		laneMemoryRequired = 3 << 30
	}
	add("memory", facts.MemoryAvailable >= memoryRequired && cgroupAtLeast(facts.MemoryLimit, memoryRequired) && cgroupAtLeast(facts.LaneMemoryLimit, laneMemoryRequired), "environment", "memory is available in the current cgroup and workload lane canary", fmt.Sprintf("available=%d current=%s lane=%s", facts.MemoryAvailable, facts.MemoryLimit, facts.LaneMemoryLimit), fmt.Sprintf("current>=%d lane>=%d", memoryRequired, laneMemoryRequired))
	add("swap", facts.LaneSwapLimit == "0", "environment", "workload lane canary has isolated zero swap", fmt.Sprintf("current=%s lane=%s", facts.SwapLimit, facts.LaneSwapLimit), "lane=0")
	add("pids", cgroupAtLeast(facts.PidsLimit, 8192) && cgroupAtLeast(facts.LanePidsLimit, 8192), "environment", "current cgroup and workload lane canary provide the task budget", fmt.Sprintf("current=%s lane=%s", facts.PidsLimit, facts.LanePidsLimit), ">=8192")
	add("disk", facts.DiskAvailable >= 6<<30, "environment", "artifact filesystem has space", strconv.FormatUint(facts.DiskAvailable, 10), ">=6GiB")
	add("nofile", facts.NoFileLimit >= 32768, "environment", "file descriptor limit covers the workload", strconv.FormatUint(facts.NoFileLimit, 10), ">=32768")
	add("artifact_fresh", facts.ArtifactFresh, "environment", "artifact path is fresh", strconv.FormatBool(facts.ArtifactFresh), "true")
	add("unique_job_lock", facts.LockAvailable, "environment", "the exact job owns the unique workload lock", strconv.FormatBool(facts.LockAvailable), "true")
	add("residual_processes", facts.ResidualProcess == 0, "residual", "no runner or Chromium process remains", strconv.Itoa(facts.ResidualProcess), "0")
	add("residual_netns", facts.ResidualNetNS == 0, "residual", "no Flowersec network namespace remains", strconv.Itoa(facts.ResidualNetNS), "0")
	add("residual_cgroups", facts.ResidualCgroup == 0, "residual", "no task cgroup remains", strconv.Itoa(facts.ResidualCgroup), "0")
	add("residual_bpf", facts.ResidualBPF == 0, "residual", "no Flowersec BPF pin remains", strconv.Itoa(facts.ResidualBPF), "0")
	if request.Mode == "formal" {
		add("remote_dns", facts.DNSReachable, "environment", "formal dependency endpoints are reachable", strconv.FormatBool(facts.DNSReachable), "true")
		add("dependency_metadata", facts.DependencyReady, "environment", "formal dependency metadata is reachable", strconv.FormatBool(facts.DependencyReady), "true")
	}
	return report
}

func runnerPreflightReportClassification(report runnerPreflightReport) string {
	for _, check := range report.Checks {
		if check.Status == "RED" {
			return check.Classification
		}
	}
	return "environment"
}

func runnerPreflightExitCode(report runnerPreflightReport) int {
	for _, check := range report.Checks {
		if check.Status != "RED" {
			continue
		}
		switch check.Classification {
		case "input":
			return runnerPreflightInput
		case "identity":
			return runnerPreflightIdentity
		case "residual":
			return runnerPreflightResidual
		default:
			return runnerPreflightEnvironment
		}
	}
	return runnerPreflightEnvironment
}

func runnerPreflightOutputIsSafe(path string) bool {
	if path == "-" {
		return true
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false
	}
	parent, err := canonicalDirectory(filepath.Dir(path), true)
	if err != nil || parent != filepath.Dir(path) {
		return false
	}
	if info, err := os.Lstat(path); err == nil {
		return info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0
	} else {
		return errors.Is(err, os.ErrNotExist)
	}
}

func runnerPreflightFailureMessage(report runnerPreflightReport) string {
	for _, check := range report.Checks {
		if check.Status == "RED" {
			return check.CheckID + ": " + check.Message + " (actual=" + check.Actual + ", expected=" + check.Expected + ")"
		}
	}
	return "runner-preflight failed"
}

func writeRunnerPreflightReport(path string, report runnerPreflightReport, output io.Writer) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if path == "-" {
		_, err = output.Write(data)
		return err
	}
	if info, err := os.Lstat(path); err == nil && (!info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0) {
		return errors.New("preflight output must be absent or a regular non-symlink file")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".runner-preflight-*.json")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
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
	return os.Rename(temporaryPath, path)
}

func runnerPreflightTools(mode string) []string {
	tools := []string{"git", "sha256sum", "ip", "nft", "tc", "jq", "flock", "timeout", "tini", "bpftool", "go", "node"}
	if mode == "formal" {
		tools = append(tools, "clang", "rustup", "cargo", "rustc")
	}
	return tools
}

func runnerPreflightCommandOutput(name string, arguments ...string) string {
	output, err := exec.Command(name, arguments...).CombinedOutput()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(output))
}

func runnerPreflightRustDependencies(ctx context.Context, repository string) bool {
	command := exec.CommandContext(ctx, "rustup", "run", "1.88.0", "cargo", "fetch",
		"--locked", "--offline",
		"--manifest-path", filepath.Join(repository, "flowersec-rust", "Cargo.toml"))
	command.Env = append(os.Environ(), "CARGO_NET_OFFLINE=true")
	return command.Run() == nil
}

func runnerPreflightBaseCheckout(ctx context.Context, repository, baseSHA string) bool {
	root, err := os.MkdirTemp("", "flowersec-runner-preflight-base-")
	if err != nil {
		return false
	}
	defer os.RemoveAll(root)
	checkout := filepath.Join(root, "base-source")
	clone := exec.CommandContext(ctx, "git", "clone", "--quiet", "--no-local", "--no-checkout", repository, checkout)
	if clone.Run() != nil {
		return false
	}
	return exec.CommandContext(ctx, "git", "-C", checkout, "checkout", "--quiet", "--detach", baseSHA).Run() == nil
}

func runnerPreflightPlatform() (bool, string) {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return false, runtime.GOOS + "/" + runtime.GOARCH
	}
	values := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if ok {
			values[key] = strings.Trim(strings.TrimSpace(value), `"`)
		}
	}
	actual := fmt.Sprintf("%s/%s %s %s", runtime.GOOS, runtime.GOARCH, values["ID"], values["VERSION_ID"])
	validArch := runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64"
	return runtime.GOOS == "linux" && validArch && values["ID"] == "ubuntu" && values["VERSION_ID"] == "24.04", actual
}

func runnerPreflightToolchainDigest(repository string) string {
	parts := []string{}
	for _, command := range [][]string{{"go", "version"}, {"go", "env", "GOOS", "GOARCH", "CGO_ENABLED"}, {"node", "--version"}} {
		output, err := exec.Command(command[0], command[1:]...).CombinedOutput()
		if err != nil {
			return ""
		}
		parts = append(parts, strings.TrimSpace(string(output)))
	}
	var sums []string
	for _, relative := range []string{"flowersec-go/go.mod", "flowersec-go/go.sum", "flowersec-ts/package-lock.json"} {
		data, err := os.ReadFile(filepath.Join(repository, filepath.FromSlash(relative)))
		if err != nil {
			return ""
		}
		digest := sha256.Sum256(data)
		sums = append(sums, hex.EncodeToString(digest[:])+"  "+relative)
	}
	parts = append(parts, strings.Join(sums, "\n"))
	hash := sha256.Sum256([]byte(strings.Join(parts, "\n")))
	return hex.EncodeToString(hash[:])
}

func runnerPreflightDistDigest(root string) string {
	var paths []string
	_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err == nil && !entry.IsDir() {
			paths = append(paths, path)
		}
		return nil
	})
	sort.Strings(paths)
	inner := strings.Builder{}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return ""
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return ""
		}
		digest := sha256.Sum256(data)
		inner.WriteString(hex.EncodeToString(digest[:]))
		inner.WriteString("  dist/")
		inner.WriteString(filepath.ToSlash(relative))
		inner.WriteByte('\n')
	}
	digest := sha256.Sum256([]byte(inner.String()))
	return hex.EncodeToString(digest[:])
}

func runnerPreflightChromiumVersion(ctx context.Context, repository string) string {
	command := exec.CommandContext(ctx, "node", "-e", `const { chromium } = require("playwright"); process.stdout.write(chromium.executablePath())`)
	command.Dir = filepath.Join(repository, "flowersec-ts")
	path, err := command.Output()
	if err != nil {
		return ""
	}
	version, err := exec.CommandContext(ctx, strings.TrimSpace(string(path)), "--version").Output()
	if err != nil {
		return ""
	}
	fields := strings.Fields(string(version))
	if len(fields) == 0 {
		return ""
	}
	return fields[len(fields)-1]
}

func runnerPreflightNetNSCanary(ctx context.Context) bool {
	name := fmt.Sprintf("flowersec-preflight-%d", os.Getpid())
	if err := exec.CommandContext(ctx, "ip", "netns", "add", name).Run(); err != nil {
		return false
	}
	if exec.CommandContext(ctx, "ip", "netns", "exec", name, "ip", "link", "set", "lo", "up").Run() != nil {
		_ = exec.Command("ip", "netns", "del", name).Run()
		return false
	}
	return exec.CommandContext(ctx, "ip", "netns", "del", name).Run() == nil
}

func runnerPreflightBPFCanary(ctx context.Context) bool {
	path := filepath.Join("/sys/fs/bpf", fmt.Sprintf("flowersec-preflight-%d", os.Getpid()))
	command := exec.CommandContext(ctx, "bpftool", "map", "create", path, "type", "array", "key", "4", "value", "4", "entries", "1", "name", "fs_preflight")
	if err := command.Run(); err != nil {
		return false
	}
	return os.Remove(path) == nil
}

func runnerPreflightCgroupCanary(ctx context.Context, root, mode string) (bool, []string, int, string, string, string, string) {
	controllers, _ := os.ReadFile(filepath.Join(root, "cgroup.controllers"))
	path := filepath.Join(root, fmt.Sprintf("flowersec-preflight-%d", os.Getpid()))
	if err := os.Mkdir(path, 0700); err != nil {
		return false, strings.Fields(string(controllers)), 0, "", "", "", ""
	}
	cleaned := false
	defer func() {
		if !cleaned {
			_ = os.Remove(path)
		}
	}()
	memory := "4294967296"
	laneCPUCount := collectionLaneCPUs
	if mode == "focused" {
		memory = "3221225472"
		laneCPUCount = 1
	}
	allowed, err := runnerPreflightCPUSet(filepath.Join(root, "cpuset.cpus.effective"))
	if err != nil || len(allowed) < laneCPUCount {
		return false, strings.Fields(string(controllers)), 0, "", "", "", ""
	}
	memoryNodes := runnerPreflightReadValue(root, "cpuset.mems.effective")
	if memoryNodes == "" {
		return false, strings.Fields(string(controllers)), 0, "", "", "", ""
	}
	cpuMax := fmt.Sprintf("%d00000 100000", laneCPUCount)
	for name, value := range map[string]string{
		"cpuset.cpus": formatCPUSet(allowed[:laneCPUCount]), "cpuset.mems": memoryNodes, "cpu.max": cpuMax,
		"memory.max": memory, "memory.swap.max": "0", "pids.max": "8192",
	} {
		if err := os.WriteFile(filepath.Join(path, name), []byte(value), 0600); err != nil {
			return false, strings.Fields(string(controllers)), 0, "", "", "", ""
		}
	}
	laneCPUs, _ := runnerPreflightCPUSet(filepath.Join(path, "cpuset.cpus.effective"))
	laneCPUMax := runnerPreflightReadValue(path, "cpu.max")
	laneMemory := runnerPreflightReadValue(path, "memory.max")
	laneSwap := runnerPreflightReadValue(path, "memory.swap.max")
	lanePids := runnerPreflightReadValue(path, "pids.max")
	command := exec.CommandContext(ctx, "/bin/sh", "-c", `printf '%s' "$$" > "$1/cgroup.procs"`, "flowersec-cgroup-canary", path)
	if err := command.Run(); err != nil {
		return false, strings.Fields(string(controllers)), len(laneCPUs), laneCPUMax, laneMemory, laneSwap, lanePids
	}
	for attempt := 0; attempt < 20; attempt++ {
		if err := os.Remove(path); err == nil {
			cleaned = true
			return len(laneCPUs) == laneCPUCount && laneCPUMax == cpuMax && laneMemory == memory && laneSwap == "0" && lanePids == "8192", strings.Fields(string(controllers)), len(laneCPUs), laneCPUMax, laneMemory, laneSwap, lanePids
		}
		select {
		case <-ctx.Done():
			return false, strings.Fields(string(controllers)), len(laneCPUs), laneCPUMax, laneMemory, laneSwap, lanePids
		case <-time.After(25 * time.Millisecond):
		}
	}
	return false, strings.Fields(string(controllers)), len(laneCPUs), laneCPUMax, laneMemory, laneSwap, lanePids
}

func runnerPreflightEffectiveCPUCount(root string) int {
	cpus, _ := runnerPreflightCPUSet(filepath.Join(root, "cpuset.cpus.effective"))
	return len(cpus)
}

func runnerPreflightCPUSet(path string) ([]int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseCPUSet(strings.TrimSpace(string(data)))
}

func runnerPreflightReadValue(root, name string) string {
	data, err := os.ReadFile(filepath.Join(root, name))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func runnerPreflightCgroupValue(name string) string {
	path := filepath.Join(runnerPreflightCurrentCgroup(), name)
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func runnerPreflightCurrentCgroup() string {
	data, err := os.ReadFile("/proc/self/cgroup")
	if err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "0::/") || line == "0::/" {
				relative := strings.TrimPrefix(line, "0::")
				clean := filepath.Clean("/" + strings.TrimPrefix(relative, "/"))
				return filepath.Join("/sys/fs/cgroup", clean)
			}
		}
	}
	return "/sys/fs/cgroup"
}

func cgroupAtLeast(value string, want uint64) bool {
	if value == "max" {
		return true
	}
	number, err := strconv.ParseUint(value, 10, 64)
	return err == nil && number >= want
}

func runnerPreflightDiskAvailable(path string) uint64 {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(filepath.Dir(path), &stat); err != nil {
		return 0
	}
	return stat.Bavail * uint64(stat.Bsize)
}
func runnerPreflightNoFileLimit() uint64 {
	var limit syscall.Rlimit
	if syscall.Getrlimit(syscall.RLIMIT_NOFILE, &limit) != nil {
		return 0
	}
	return limit.Cur
}
func runnerPreflightFreshPath(path string) bool {
	_, err := os.Lstat(path)
	return errors.Is(err, os.ErrNotExist)
}

func runnerPreflightLockHeld(path, owner string) bool {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return false
	}
	data, err := os.ReadFile(path)
	if err != nil || strings.TrimSpace(string(data)) != owner {
		return false
	}
	file, err := os.OpenFile(path, os.O_RDWR, 0600)
	if err != nil {
		return false
	}
	defer file.Close()
	err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	return errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN)
}

func runnerPreflightResiduals() (int, int, int, int) {
	processes := 0
	entries, _ := os.ReadDir("/proc")
	for _, entry := range entries {
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue
		}
		pid, _ := strconv.Atoi(entry.Name())
		if pid == os.Getpid() {
			continue
		}
		data, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "comm"))
		name := strings.TrimSpace(string(data))
		if err == nil && (strings.HasPrefix(name, "transport-rele") || name == "chrome" || name == "chromium") {
			processes++
		}
	}
	netns := 0
	if output, err := exec.Command("ip", "netns", "list").Output(); err == nil {
		for _, line := range strings.Split(string(output), "\n") {
			if strings.HasPrefix(line, "fc-") || strings.HasPrefix(line, "fs-") || strings.HasPrefix(line, "flowersec-") {
				netns++
			}
		}
	}
	cgroups := 0
	currentCgroup := runnerPreflightCurrentCgroup()
	if entries, err := os.ReadDir("/sys/fs/cgroup"); err == nil {
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), "flowersec-focused-") || strings.HasPrefix(entry.Name(), "flowersec-transport-") {
				path := filepath.Join("/sys/fs/cgroup", entry.Name())
				if currentCgroup != path && !strings.HasPrefix(currentCgroup, path+string(filepath.Separator)) {
					cgroups++
				}
			}
		}
	}
	bpf := 0
	if entries, err := os.ReadDir("/sys/fs/bpf"); err == nil {
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), "flowersec-fc-") || strings.HasPrefix(entry.Name(), "flowersec-preflight-") {
				bpf++
			}
		}
	}
	return processes, netns, cgroups, bpf
}

func runnerPreflightDependencies(ctx context.Context, mode string, endpoints []string) (bool, bool) {
	if mode != "formal" {
		return true, true
	}
	resolver := net.Resolver{}
	client := http.Client{Timeout: 3 * time.Second}
	dns, dep := true, true
	for _, endpoint := range endpoints {
		request, err := http.NewRequestWithContext(ctx, http.MethodHead, endpoint, nil)
		if err != nil {
			return false, false
		}
		host := request.URL.Hostname()
		lookup, lookupErr := resolver.LookupHost(ctx, host)
		dns = dns && lookupErr == nil && len(lookup) > 0
		response, requestErr := client.Do(request)
		dep = dep && requestErr == nil && response != nil && response.StatusCode < 500
		if response != nil {
			response.Body.Close()
		}
	}
	return dns, dep
}

func validateRunnerPreflightConfig(request runnerPreflightRequest, repository string) error {
	info, err := os.Lstat(request.RunnerConfigPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return errors.New("runner config is not a private regular file")
	}
	relative, err := filepath.Rel(repository, request.RunnerConfigPath)
	if err != nil {
		return err
	}
	if relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		relative = filepath.ToSlash(relative)
		if tracked, trackedErr := collectGitOutput(repository, "ls-files", "--", relative); trackedErr != nil || tracked != "" {
			return errors.New("runner config inside the checkout must not be tracked")
		}
		if _, ignoredErr := collectGitOutput(repository, "check-ignore", "-q", "--", relative); ignoredErr != nil {
			return errors.New("runner config inside the checkout must be git-ignored")
		}
	}
	var config RunnerLocalConfig
	if err := decodeStrictFile(request.RunnerConfigPath, &config); err != nil {
		return err
	}
	policy, err := loadEvidenceTrustPolicy(filepath.Join(repository, "testdata/transport_v2/evidence_trust_policy.json"))
	if err != nil {
		return err
	}
	if err := validateRunnerLocalConfig(config, policy); err != nil {
		return err
	}
	if config.OS != runtime.GOOS || config.Architecture != runtime.GOARCH {
		return errors.New("runner config platform identity drift")
	}
	kernel, _ := os.ReadFile("/proc/sys/kernel/osrelease")
	if config.KernelRelease != strings.TrimSpace(string(kernel)) {
		return errors.New("runner config kernel identity drift")
	}
	return nil
}

func validateRunnerPreflightIdentity(request runnerPreflightRequest, repository string) error {
	var config RunnerLocalConfig
	if err := decodeStrictFile(request.RunnerConfigPath, &config); err != nil {
		return err
	}
	if request.RunnerExecutable != "" {
		_, digest, err := snapshotRegularFile(request.RunnerExecutable, true)
		if err != nil {
			return err
		}
		if request.RunnerExecutableSHA256 != "" && digest != request.RunnerExecutableSHA256 {
			return errors.New("runner executable digest drift")
		}
		if request.Mode == "formal" && digest != config.ExecutableSHA256 {
			return errors.New("runner executable differs from the private identity")
		}
	}
	manifest, err := loadPerformanceManifest(filepath.Join(repository, "testdata/transport_v2/performance_manifest.json"))
	if err != nil {
		return err
	}
	registry, err := loadCaseRegistry(filepath.Join(repository, "testdata/transport_v2/case_registry.json"))
	if err != nil {
		return err
	}
	source, err := runnerSourceSHA256(repository)
	if err != nil {
		return err
	}
	argv, err := canonicalAllTargetArgvSHA256(manifest, registry)
	if err != nil {
		return err
	}
	if config.SourceSHA256 != source || config.ArgvSHA256 != argv {
		return errors.New("runner source or argv digest drift")
	}
	return nil
}

func gitIsAncestor(repository, base, final string) bool {
	return exec.Command("git", "-C", repository, "merge-base", "--is-ancestor", base, final).Run() == nil
}
func gitShowFile(repository, revision, path string) ([]byte, error) {
	return exec.Command("git", "-C", repository, "show", revision+":"+path).Output()
}
func readMeminfoBytes(key string) uint64 {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && strings.TrimSuffix(fields[0], ":") == key {
			value, _ := strconv.ParseUint(fields[1], 10, 64)
			return value * 1024
		}
	}
	return 0
}
func containsAll(have, want []string) bool {
	set := map[string]bool{}
	for _, v := range have {
		set[v] = true
	}
	for _, v := range want {
		if !set[v] {
			return false
		}
	}
	return true
}
func classifyRunnerPreflightError(err error) string {
	var coded interface{ ExitCode() int }
	if errors.As(err, &coded) {
		switch coded.ExitCode() {
		case runnerPreflightIdentity:
			return "identity"
		case runnerPreflightResidual:
			return "residual"
		}
	}
	return "environment"
}
