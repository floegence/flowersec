package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

var collectTargets = map[string]struct{}{
	"all": {}, "transport-conformance-full": {}, "weaknet-full": {}, "weaknet-system": {},
	"quic-native-smoke": {}, "quic-native-proof": {}, "quic-native-race": {}, "bench-transport-capacity": {},
	"bench-transport-soak": {}, "bench-transport-ab": {}, "transport-conformance-smoke": {},
}

var normalCaseProducerOwners = map[string]struct{}{
	"bench-transport-capacity":    {},
	"bench-transport-soak":        {},
	"transport-conformance-smoke": {},
	"transport-conformance-full":  {},
	"transport-browser-smoke":     {},
	"weaknet-full":                {},
	"weaknet-system":              {},
	"quic-native-smoke":           {},
	"quic-native-proof":           {},
}

var raceCaseProducerOwners = map[string]struct{}{
	"quic-native-race": {},
}

const (
	collectionRevisionBase  = "base"
	collectionRevisionFinal = "final"
	capacityJobWatchdog     = 5 * time.Minute
	capacityStageWatchdog   = 10 * time.Minute
	caseSuiteJobHardStop    = 10 * time.Minute
	caseSuiteStageHardStop  = 10 * time.Minute
)

type collectRequest struct {
	ManifestPath         string
	BaseManifestPath     string
	RegistryPath         string
	RepositoryPath       string
	BaseRepositoryPath   string
	BaseSHA              string
	FinalSHA             string
	Target               string
	ReportPath           string
	ArtifactDirectory    string
	RunnerExecutable     string
	RaceRunnerExecutable string
	BaseRunnerExecutable string
	RunnerWrapper        string
	BPFObject            string
	HostBPFTool          string
	TrustPolicyPath      string
	EffectiveConfigPath  string
	KernelRelease        string
}

type collectEnvironment struct {
	request      collectRequest
	manifest     *PerformanceManifest
	registry     *CaseRegistry
	inputDigests map[string]string
	output       *collectionDirectoryIdentity
}

type collectionDirectoryIdentity struct {
	path   string
	handle *os.File
	info   os.FileInfo
}

func pinCollectionDirectory(path string) (*collectionDirectoryIdentity, error) {
	handle, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	info, err := handle.Stat()
	if err != nil {
		_ = handle.Close()
		return nil, err
	}
	stat, ownerOK := info.Sys().(*syscall.Stat_t)
	if !info.IsDir() || info.Mode().Perm()&0o022 != 0 || !ownerOK || stat.Uid != uint32(os.Geteuid()) {
		_ = handle.Close()
		return nil, errors.New("collection output must be owned by the runner and must not be group-writable or world-writable")
	}
	pathInfo, err := os.Stat(path)
	if err != nil || !os.SameFile(info, pathInfo) {
		_ = handle.Close()
		return nil, errors.New("collection output changed while it was pinned")
	}
	return &collectionDirectoryIdentity{path: path, handle: handle, info: info}, nil
}

func (identity *collectionDirectoryIdentity) Verify() error {
	if identity == nil || identity.handle == nil {
		return errors.New("collection output identity is required")
	}
	handleInfo, err := identity.handle.Stat()
	if err != nil || !os.SameFile(identity.info, handleInfo) {
		return errors.New("collection output handle changed")
	}
	pathInfo, err := os.Stat(identity.path)
	if err != nil {
		return errors.New("collection output path identity changed")
	}
	stat, ownerOK := pathInfo.Sys().(*syscall.Stat_t)
	if !os.SameFile(identity.info, pathInfo) || pathInfo.Mode().Perm()&0o022 != 0 || !ownerOK || stat.Uid != uint32(os.Geteuid()) {
		return errors.New("collection output path identity, owner, or permissions changed")
	}
	return nil
}

func (identity *collectionDirectoryIdentity) Close() error {
	if identity == nil || identity.handle == nil {
		return nil
	}
	return identity.handle.Close()
}

type collectionPlan struct {
	Target  string
	Jobs    []collectionJob
	Missing []string
}

type collectionJob struct {
	ID             string
	CellIDs        []string
	RunnerTarget   string
	Profile        string
	Carrier        string
	Topology       string
	NeedsBPF       bool
	CaseOwner      string
	CaseMode       string
	CaseID         string
	CaseIDs        []string
	VariantID      string
	SourceRevision string
}

type rawJobRecord struct {
	ID                     string                 `json:"id"`
	CellIDs                []string               `json:"cell_ids"`
	CaseIDs                []string               `json:"case_ids,omitempty"`
	VariantID              string                 `json:"variant_id,omitempty"`
	SourceSHA              string                 `json:"source_sha"`
	RunnerExecutableSHA256 string                 `json:"runner_executable_sha256"`
	CommandSHA256          string                 `json:"command_sha256"`
	Lane                   collectionLaneIdentity `json:"lane"`
	Directory              string                 `json:"directory"`
	ReportSHA              string                 `json:"report_sha256"`
}

type rawCaseSuiteReport struct {
	SchemaVersion  int                  `json:"schema_version"`
	Classification string               `json:"classification"`
	SourceSHA      string               `json:"source_sha"`
	ManifestDigest string               `json:"manifest_digest"`
	ManifestSHA256 string               `json:"manifest_file_sha256"`
	Runner         map[string]any       `json:"runner"`
	Owner          string               `json:"owner"`
	Mode           string               `json:"mode"`
	StartedAt      string               `json:"started_at"`
	FinishedAt     string               `json:"finished_at"`
	Results        []rawCaseSuiteResult `json:"results"`
}

type rawCaseSuiteResult struct {
	ID                  string                `json:"id"`
	Profile             string                `json:"profile"`
	Status              string                `json:"status"`
	CompletedOperations int                   `json:"completed_operations"`
	ElapsedNanoseconds  int64                 `json:"elapsed_nanoseconds"`
	RawSources          []rawProducedSource   `json:"raw_sources,omitempty"`
	Attachments         []rawProducedSource   `json:"attachments,omitempty"`
	Artifacts           []rawProducedArtifact `json:"artifacts"`
}

type rawProducedSource struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
}

type rawProducedArtifact struct {
	Kind      string `json:"kind"`
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
}

type rawCollectionIndex struct {
	SchemaVersion  int               `json:"schema_version"`
	Classification string            `json:"classification"`
	Target         string            `json:"target"`
	BaseSHA        string            `json:"base_sha"`
	FinalSHA       string            `json:"final_sha"`
	InputSHA256    map[string]string `json:"input_sha256"`
	Jobs           []rawJobRecord    `json:"jobs"`
}

func collect(request collectRequest) error {
	environment, err := validateCollectRequest(request)
	if err != nil {
		return err
	}
	defer environment.output.Close()
	plan, err := buildCollectionPlan(request.Target, environment.manifest, environment.registry)
	if err != nil {
		return err
	}
	if len(plan.Missing) != 0 {
		return fmt.Errorf("collection target %s has no production producer for: %s", request.Target, strings.Join(plan.Missing, "; "))
	}
	return executeCollection(context.Background(), environment, plan)
}

func validateCollectRequest(request collectRequest) (*collectEnvironment, error) {
	if _, ok := collectTargets[request.Target]; !ok {
		return nil, fmt.Errorf("collect target %q is outside the frozen release target set", request.Target)
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		return nil, errors.New("collect requires Linux amd64")
	}
	if os.Geteuid() != 0 {
		return nil, errors.New("collect requires the dedicated privileged runner")
	}
	repository, err := canonicalDirectory(request.RepositoryPath, false)
	if err != nil {
		return nil, fmt.Errorf("repository: %w", err)
	}
	request.RepositoryPath = repository
	baseRepository, err := canonicalDirectory(request.BaseRepositoryPath, false)
	if err != nil {
		return nil, fmt.Errorf("base repository: %w", err)
	}
	request.BaseRepositoryPath = baseRepository
	if baseRepository == repository {
		return nil, errors.New("collect base and final repositories must be independent checkouts")
	}
	if !gitSHAPattern.MatchString(request.BaseSHA) || !gitSHAPattern.MatchString(request.FinalSHA) {
		return nil, errors.New("collect requires full lowercase base and final Git SHAs")
	}
	if request.BaseSHA == request.FinalSHA {
		return nil, errors.New("collect base and final SHAs must differ")
	}
	if err := validateCollectCheckout(repository, request.FinalSHA, "final"); err != nil {
		return nil, err
	}
	if err := validateCollectCheckout(baseRepository, request.BaseSHA, "base"); err != nil {
		return nil, err
	}
	if err := exec.Command("git", "-C", repository, "merge-base", "--is-ancestor", request.BaseSHA, request.FinalSHA).Run(); err != nil {
		return nil, errors.New("collect base SHA is not an ancestor of final SHA")
	}
	fixedPaths := map[string]*string{
		"manifest":         &request.ManifestPath,
		"registry":         &request.RegistryPath,
		"trust_policy":     &request.TrustPolicyPath,
		"effective_config": &request.EffectiveConfigPath,
	}
	request.BaseManifestPath = filepath.Join(baseRepository, "testdata", "transport_v2", "performance_manifest.json")
	wants := map[string]string{
		"manifest":         filepath.Join(repository, "testdata", "transport_v2", "performance_manifest.json"),
		"registry":         filepath.Join(repository, "testdata", "transport_v2", "case_registry.json"),
		"trust_policy":     filepath.Join(repository, "testdata", "transport_v2", "evidence_trust_policy.json"),
		"effective_config": filepath.Join(repository, "testdata", "transport_v2", "runner_effective_config.json"),
	}
	for name, value := range fixedPaths {
		canonical, _, err := snapshotRegularFile(*value, false)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		if canonical != wants[name] {
			return nil, fmt.Errorf("%s must be the fixed file in the source checkout", name)
		}
		*value = canonical
	}

	report, artifactDirectory, err := validateFreshCollectionOutput(request.ReportPath, request.ArtifactDirectory)
	if err != nil {
		return nil, err
	}
	request.ReportPath, request.ArtifactDirectory = report, artifactDirectory

	inputSpecs := []struct {
		name       string
		path       *string
		executable bool
	}{
		{"manifest", &request.ManifestPath, false}, {"base_manifest", &request.BaseManifestPath, false}, {"registry", &request.RegistryPath, false},
		{"runner_executable", &request.RunnerExecutable, true}, {"race_runner_executable", &request.RaceRunnerExecutable, true}, {"base_runner_executable", &request.BaseRunnerExecutable, true}, {"runner_wrapper", &request.RunnerWrapper, true},
		{"bpf_object", &request.BPFObject, false}, {"host_bpftool", &request.HostBPFTool, true},
		{"trust_policy", &request.TrustPolicyPath, false}, {"effective_config", &request.EffectiveConfigPath, false},
	}
	if request.BaseRunnerExecutable == request.RunnerExecutable {
		return nil, errors.New("collect base and final runner executables must be independent files")
	}
	if request.RaceRunnerExecutable == request.RunnerExecutable || request.RaceRunnerExecutable == request.BaseRunnerExecutable {
		return nil, errors.New("collect race runner executable must be an independent file")
	}
	digests := make(map[string]string, len(inputSpecs))
	for _, spec := range inputSpecs {
		canonical, digest, err := snapshotRegularFile(*spec.path, spec.executable)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", spec.name, err)
		}
		*spec.path = canonical
		digests[spec.name] = digest
	}
	wrapperSource := filepath.Join(repository, "scripts", "transport-v2-release-runner.sh")
	_, wrapperSourceDigest, err := snapshotRegularFile(wrapperSource, true)
	if err != nil || wrapperSourceDigest != digests["runner_wrapper"] {
		return nil, errors.New("installed runner wrapper does not match the clean source checkout")
	}
	digests["runner_wrapper_source"] = wrapperSourceDigest
	if digests["base_manifest"] != digests["manifest"] {
		return nil, errors.New("collect base and final manifests must be byte-identical for paired revision evidence")
	}

	manifest, err := loadPerformanceManifest(request.ManifestPath)
	if err != nil {
		return nil, err
	}
	if err := validateManifest(manifest); err != nil {
		return nil, err
	}
	registry, err := loadCaseRegistry(request.RegistryPath)
	if err != nil {
		return nil, err
	}
	if err := validateCaseRegistry(registry); err != nil {
		return nil, err
	}
	if err := verifyDeterministicRunnerExecutable(repository, request.RunnerExecutable, false); err != nil {
		return nil, fmt.Errorf("final runner identity: %w", err)
	}
	if err := verifyDeterministicRunnerExecutable(repository, request.RaceRunnerExecutable, true); err != nil {
		return nil, fmt.Errorf("race runner identity: %w", err)
	}
	if err := verifyDeterministicRunnerExecutable(baseRepository, request.BaseRunnerExecutable, false); err != nil {
		return nil, fmt.Errorf("base runner identity: %w", err)
	}
	digests["runner_source"], err = runnerSourceSHA256(repository)
	if err != nil {
		return nil, fmt.Errorf("final runner source identity: %w", err)
	}
	digests["base_runner_source"], err = runnerSourceSHA256(baseRepository)
	if err != nil {
		return nil, fmt.Errorf("base runner source identity: %w", err)
	}
	digests["runner_argv"], err = canonicalAllTargetArgvSHA256(manifest, registry)
	if err != nil {
		return nil, fmt.Errorf("canonical runner argv identity: %w", err)
	}
	policy, err := loadEvidenceTrustPolicy(request.TrustPolicyPath)
	if err != nil {
		return nil, err
	}
	if filepath.Join(filepath.Dir(request.TrustPolicyPath), policy.Runner.EffectiveConfigPath) != request.EffectiveConfigPath ||
		digests["effective_config"] != policy.Runner.EffectiveConfigSHA256 {
		return nil, errors.New("collect effective config does not match the frozen policy")
	}
	actualKernel, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return nil, fmt.Errorf("read actual kernel release: %w", err)
	}
	if strings.TrimSpace(string(actualKernel)) != request.KernelRelease || request.KernelRelease != policy.Runner.KernelRelease ||
		policy.Runner.OS != runtime.GOOS || policy.Runner.Architecture != runtime.GOARCH {
		return nil, errors.New("collect kernel or platform does not match the frozen policy")
	}

	output, err := pinCollectionDirectory(request.ArtifactDirectory)
	if err != nil {
		return nil, err
	}
	return &collectEnvironment{request: request, manifest: manifest, registry: registry, inputDigests: digests, output: output}, nil
}

func validateCollectCheckout(repository, sourceSHA, label string) error {
	top, err := collectGitOutput(repository, "rev-parse", "--show-toplevel")
	if err != nil || top != repository {
		return fmt.Errorf("collect %s repository is not its canonical Git root", label)
	}
	head, err := collectGitOutput(repository, "rev-parse", "HEAD")
	if err != nil || head != sourceSHA {
		return fmt.Errorf("collect %s SHA does not match repository HEAD", label)
	}
	status, err := collectGitOutput(repository, "status", "--porcelain", "--untracked-files=all")
	if err != nil || status != "" {
		return fmt.Errorf("collect %s repository must be clean with no untracked files", label)
	}
	return nil
}

func validateFreshCollectionOutput(reportPath, artifactDirectory string) (string, string, error) {
	if !filepath.IsAbs(reportPath) || filepath.Clean(reportPath) != reportPath {
		return "", "", errors.New("collect report path must be absolute and canonical")
	}
	if _, err := os.Lstat(reportPath); err == nil || !errors.Is(err, os.ErrNotExist) {
		return "", "", errors.New("collect report path must be fresh")
	}
	canonicalDirectoryPath, err := canonicalDirectory(artifactDirectory, true)
	if err != nil {
		return "", "", fmt.Errorf("artifact directory: %w", err)
	}
	if filepath.Dir(reportPath) != canonicalDirectoryPath {
		return "", "", errors.New("collect report must be a direct child of the artifact directory")
	}
	entries, err := os.ReadDir(canonicalDirectoryPath)
	if err != nil {
		return "", "", err
	}
	if len(entries) != 0 {
		return "", "", errors.New("collect artifact directory must be fresh and empty")
	}
	return reportPath, canonicalDirectoryPath, nil
}

func canonicalDirectory(path string, rejectSymlink bool) (string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", errors.New("path must be absolute and canonical")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || rejectSymlink && info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("path must be an existing non-symlink directory")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return "", errors.New("path must not traverse symlinks")
	}
	return path, nil
}

func snapshotRegularFile(path string, executable bool) (string, string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", "", errors.New("path must be absolute and canonical")
	}
	pathInfo, err := os.Lstat(path)
	if err != nil || !pathInfo.Mode().IsRegular() || pathInfo.Mode()&os.ModeSymlink != 0 {
		return "", "", errors.New("path must be an existing regular non-symlink file")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return "", "", errors.New("path must not traverse symlinks")
	}
	if pathInfo.Size() == 0 {
		return "", "", errors.New("file must not be empty")
	}
	if executable && pathInfo.Mode().Perm()&0o111 == 0 {
		return "", "", errors.New("file must be executable")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", "", err
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !os.SameFile(pathInfo, openedInfo) {
		return "", "", errors.New("file changed while it was opened")
	}
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		return "", "", err
	}
	return path, hex.EncodeToString(digest.Sum(nil)), nil
}

func buildCollectionPlan(target string, manifest *PerformanceManifest, registry *CaseRegistry) (collectionPlan, error) {
	if _, ok := collectTargets[target]; !ok {
		return collectionPlan{}, fmt.Errorf("collect target %q is outside the frozen release target set", target)
	}
	if err := validateManifest(manifest); err != nil {
		return collectionPlan{}, err
	}
	if err := validateCaseRegistry(registry); err != nil {
		return collectionPlan{}, err
	}
	plan := collectionPlan{Target: target}
	if target == "all" || target == "bench-transport-ab" {
		jobs, missing := supportedPerformanceJobs(manifest)
		plan.Jobs = append(plan.Jobs, jobs...)
		plan.Missing = append(plan.Missing, missing...)
	}
	caseJobs := make(map[string]*collectionJob)
	for _, entry := range registry.Cases {
		if (target == "all" || target == entry.Owner) && entry.Required {
			if _, supported := normalCaseProducerOwners[entry.Owner]; supported {
				key := "normal:" + entry.Owner
				if entry.Owner == "bench-transport-capacity" {
					key += ":" + entry.ID
				}
				job := caseJobs[key]
				if job == nil {
					needsBPF := entry.Owner == "weaknet-system" || entry.Owner == "quic-native-proof"
					jobID := "case-normal-" + entry.Owner
					caseID := ""
					if entry.Owner == "bench-transport-capacity" {
						jobID += "-" + strings.ToLower(entry.ID)
						caseID = entry.ID
					}
					job = &collectionJob{ID: jobID, RunnerTarget: "release-case-suite", CaseOwner: entry.Owner, CaseMode: "normal", CaseID: caseID, NeedsBPF: needsBPF}
					caseJobs[key] = job
				}
				job.CaseIDs = append(job.CaseIDs, entry.ID)
			} else {
				plan.Missing = append(plan.Missing, fmt.Sprintf("case %s owned by %s", entry.ID, entry.Owner))
			}
		}
		if entry.RaceOwner != "" && (target == "all" || target == entry.RaceOwner) {
			if _, supported := raceCaseProducerOwners[entry.RaceOwner]; supported {
				key := "race:" + entry.RaceOwner
				job := caseJobs[key]
				if job == nil {
					job = &collectionJob{ID: "case-race-" + entry.RaceOwner, RunnerTarget: "release-case-suite", CaseOwner: entry.RaceOwner, CaseMode: "race", NeedsBPF: entry.RaceOwner == "quic-native-race"}
					caseJobs[key] = job
				}
				job.CaseIDs = append(job.CaseIDs, entry.ID)
			} else {
				plan.Missing = append(plan.Missing, fmt.Sprintf("race case %s owned by %s", entry.ID, entry.RaceOwner))
			}
		}
	}
	for _, job := range caseJobs {
		sort.Strings(job.CaseIDs)
		plan.Jobs = append(plan.Jobs, *job)
	}
	sort.Strings(plan.Missing)
	sort.Slice(plan.Jobs, func(left, right int) bool { return plan.Jobs[left].ID < plan.Jobs[right].ID })
	return plan, nil
}

func supportedPerformanceJobs(manifest *PerformanceManifest) ([]collectionJob, []string) {
	var jobs []collectionJob
	var missing []string
	var baselineCells []string
	for _, cell := range manifest.Cells {
		if cell.ID == "clean-01" && cell.ProfileID == "clean-v1" && cell.Topology == "direct_wss_revision" {
			jobs = append(jobs,
				collectionJob{ID: "clean-01-base", CellIDs: []string{cell.ID}, RunnerTarget: "direct-clean-baseline", VariantID: "base", SourceRevision: collectionRevisionBase, NeedsBPF: true},
				collectionJob{ID: "clean-01-candidate", CellIDs: []string{cell.ID}, RunnerTarget: "direct-clean-baseline", VariantID: "candidate", SourceRevision: collectionRevisionFinal, NeedsBPF: true},
			)
			continue
		}
		job, supported := performanceJob(cell)
		if !supported {
			missing = append(missing, fmt.Sprintf("cell %s (%s)", cell.ID, cell.Topology))
			continue
		}
		if job.RunnerTarget == "direct-clean-baseline" {
			baselineCells = append(baselineCells, cell.ID)
			continue
		}
		jobs = append(jobs, job)
	}
	if len(baselineCells) != 0 {
		slices.Sort(baselineCells)
		jobs = append(jobs, collectionJob{ID: "clean-direct-baseline", CellIDs: baselineCells, RunnerTarget: "direct-clean-baseline", NeedsBPF: true})
	}
	return jobs, missing
}

func performanceJob(cell PerformanceCell) (collectionJob, bool) {
	job := collectionJob{ID: cell.ID, CellIDs: []string{cell.ID}, Profile: cell.ProfileID}
	if cell.ProfileID == "clean-v1" {
		switch cell.Topology {
		case "direct_wss", "direct_quic":
			job.NeedsBPF = true
			job.RunnerTarget = "direct-clean-baseline"
			return job, true
		case "ww", "qq", "wq", "qw":
			job.RunnerTarget, job.Topology = "tunnel-network-profile-cell", strings.ToUpper(cell.Topology)
			return job, true
		case "browser_webtransport", "browser_tunnel_wt_wss", "browser_tunnel_wt_quic":
			job.RunnerTarget, job.Topology = "browser-webtransport-cell", cell.Topology
			return job, true
		default:
			return collectionJob{}, false
		}
	}
	if cell.ProfileID == "adaptive-selection-v1" && (cell.Topology == "adaptive_native" || cell.Topology == "adaptive_web") {
		job.RunnerTarget, job.Topology, job.NeedsBPF = "adaptive-selection-cell", cell.Topology, true
		return job, true
	}
	if cell.ProfileID != "mobile-v1" && cell.ProfileID != "edge-v1" {
		return collectionJob{}, false
	}
	job.NeedsBPF = true
	switch cell.Topology {
	case "direct_wss":
		job.RunnerTarget, job.Carrier = "direct-network-profile-cell", "websocket"
	case "direct_quic":
		job.RunnerTarget, job.Carrier = "direct-network-profile-cell", "raw_quic"
	case "ww", "qq", "wq", "qw":
		job.RunnerTarget, job.Topology = "tunnel-network-profile-cell", strings.ToUpper(cell.Topology)
	case "browser_webtransport", "browser_tunnel_wt_wss", "browser_tunnel_wt_quic":
		job.RunnerTarget, job.Topology = "browser-webtransport-cell", cell.Topology
	default:
		return collectionJob{}, false
	}
	return job, true
}

func executeCollection(ctx context.Context, environment *collectEnvironment, plan collectionPlan) error {
	if environment == nil || len(plan.Missing) != 0 {
		return errors.New("collection cannot execute an incomplete producer plan")
	}
	if environment.output == nil {
		identity, err := pinCollectionDirectory(environment.request.ArtifactDirectory)
		if err != nil {
			return err
		}
		environment.output = identity
		defer identity.Close()
	}
	if err := environment.output.Verify(); err != nil {
		return err
	}
	records, err := runCollectionJobs(ctx, environment.request, environment.manifest, environment.registry, plan.Jobs, environment.request.ArtifactDirectory, environment.output)
	if err != nil {
		return err
	}
	if err := verifyInputDigests(environment.request, environment.inputDigests); err != nil {
		return err
	}
	if err := environment.output.Verify(); err != nil {
		return err
	}
	index := rawCollectionIndex{
		SchemaVersion: 1, Classification: "raw_transport_collection", Target: plan.Target,
		BaseSHA: environment.request.BaseSHA, FinalSHA: environment.request.FinalSHA,
		InputSHA256: environment.inputDigests, Jobs: records,
	}
	if err := publishRawCollection(environment.output, environment.request.ReportPath, index); err != nil {
		return err
	}
	return nil
}

type collectionJobExecution struct {
	executable   string
	repository   string
	manifestPath string
	sourceSHA    string
}

func executionForCollectionJob(request collectRequest, job collectionJob) (collectionJobExecution, error) {
	if job.CaseMode == "race" {
		if job.SourceRevision != "" || job.CaseOwner == "" || job.RunnerTarget != "release-case-suite" {
			return collectionJobExecution{}, errors.New("race execution is reserved for registered final case-suite jobs")
		}
		return collectionJobExecution{
			executable: request.RaceRunnerExecutable, repository: request.RepositoryPath,
			manifestPath: request.ManifestPath, sourceSHA: request.FinalSHA,
		}, nil
	}
	switch job.SourceRevision {
	case collectionRevisionBase:
		if job.ID != "clean-01-base" || job.VariantID != "base" || !slices.Equal(job.CellIDs, []string{"clean-01"}) || job.RunnerTarget != "direct-clean-baseline" {
			return collectionJobExecution{}, errors.New("only clean-01/base may use the base runner")
		}
		return collectionJobExecution{
			executable: request.BaseRunnerExecutable, repository: request.BaseRepositoryPath,
			manifestPath: request.BaseManifestPath, sourceSHA: request.BaseSHA,
		}, nil
	case "", collectionRevisionFinal:
		if job.SourceRevision == collectionRevisionFinal && (job.ID != "clean-01-candidate" || job.VariantID != "candidate" || !slices.Equal(job.CellIDs, []string{"clean-01"}) || job.RunnerTarget != "direct-clean-baseline") {
			return collectionJobExecution{}, errors.New("explicit final revision is reserved for clean-01/candidate")
		}
		return collectionJobExecution{
			executable: request.RunnerExecutable, repository: request.RepositoryPath,
			manifestPath: request.ManifestPath, sourceSHA: request.FinalSHA,
		}, nil
	default:
		return collectionJobExecution{}, fmt.Errorf("collection job %s has unknown source revision %q", job.ID, job.SourceRevision)
	}
}

func runCollectionJobs(ctx context.Context, request collectRequest, manifest *PerformanceManifest, registry *CaseRegistry, jobs []collectionJob, staging string, identities ...*collectionDirectoryIdentity) (records []rawJobRecord, resultErr error) {
	var identity *collectionDirectoryIdentity
	if len(identities) > 1 {
		return nil, errors.New("collection jobs accept at most one output identity")
	}
	if len(identities) == 1 {
		identity = identities[0]
		if err := identity.Verify(); err != nil {
			return nil, err
		}
	}
	jobsRoot := filepath.Join(staging, "jobs")
	if err := os.Mkdir(jobsRoot, 0o700); err != nil {
		return nil, err
	}
	schedule, err := scheduleCollectionJobs(manifest, jobs)
	if err != nil {
		return nil, err
	}
	records = make([]rawJobRecord, len(jobs))
	globalWatchdog := time.Duration(0)
	if manifest.GlobalWatchdogMinutes > 0 {
		globalWatchdog = time.Duration(manifest.GlobalWatchdogMinutes) * time.Minute
	}
	if err := executeCollectionLaneStage(ctx, request, manifest, registry, schedule.lanes, staging, identity, records, false, globalWatchdog, 0); err != nil {
		return nil, err
	}
	var capacityCases []scheduledCollectionJob
	var ownerSuites []scheduledCollectionJob
	for _, scheduled := range schedule.caseSuite {
		if scheduled.job.CaseOwner == "bench-transport-capacity" && scheduled.job.CaseID != "" {
			capacityCases = append(capacityCases, scheduled)
		} else {
			ownerSuites = append(ownerSuites, scheduled)
		}
	}
	if len(ownerSuites) != 0 {
		if err := executeCollectionLaneStage(ctx, request, manifest, registry, [][]scheduledCollectionJob{ownerSuites}, staging, identity, records, true, caseSuiteStageHardStop, caseSuiteJobHardStop); err != nil {
			return nil, err
		}
	}
	if len(capacityCases) != 0 {
		lanes := scheduleCapacityCaseLanes(capacityCases)
		if err := executeCollectionLaneStage(ctx, request, manifest, registry, lanes, staging, identity, records, true, capacityStageWatchdog, capacityJobWatchdog); err != nil {
			return nil, err
		}
	}
	return records, nil
}

func scheduleCapacityCaseLanes(cases []scheduledCollectionJob) [][]scheduledCollectionJob {
	lanes := make([][]scheduledCollectionJob, collectionCaseParallelism)
	for index, scheduled := range cases {
		lanes[index%len(lanes)] = append(lanes[index%len(lanes)], scheduled)
	}
	return lanes
}

func executeCollectionLaneStage(ctx context.Context, request collectRequest, manifest *PerformanceManifest, registry *CaseRegistry, lanes [][]scheduledCollectionJob, staging string, identity *collectionDirectoryIdentity, records []rawJobRecord, caseSuite bool, stageWatchdog, jobWatchdog time.Duration) (resultErr error) {
	if len(lanes) == 0 {
		return nil
	}
	laneSet, err := openCollectionLaneSet(len(lanes), requiresProductionLaneIsolation(manifest), caseSuite)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, laneSet.Close()) }()
	if stageWatchdog > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, stageWatchdog)
		defer cancel()
	}
	workerContext, cancelWorkers := context.WithCancel(ctx)
	defer cancelWorkers()
	var workers sync.WaitGroup
	errorsByLane := make([]error, len(lanes))
	browserSlots := make(chan struct{}, collectionBrowserParallelism)
	for laneIndex, laneJobs := range lanes {
		laneIndex, laneJobs := laneIndex, laneJobs
		workers.Add(1)
		go func() {
			defer workers.Done()
			lane := laneSet.Lane(laneIndex)
			for _, scheduled := range laneJobs {
				jobContext := workerContext
				cancelJob := func() {}
				if jobWatchdog > 0 {
					jobContext, cancelJob = context.WithTimeout(workerContext, jobWatchdog)
				}
				if scheduled.browser {
					select {
					case browserSlots <- struct{}{}:
					case <-jobContext.Done():
						cancelJob()
						errorsByLane[laneIndex] = fmt.Errorf("collection job %s browser slot: %w", scheduled.job.ID, jobContext.Err())
						cancelWorkers()
						return
					}
				}
				record, err := runCollectionJob(jobContext, request, manifest, registry, scheduled.job, staging, identity, lane)
				if scheduled.browser {
					<-browserSlots
				}
				watchdogErr := jobContext.Err()
				cancelJob()
				if err != nil {
					if watchdogErr != nil {
						err = errors.Join(err, fmt.Errorf("collection job %s watchdog: %w", scheduled.job.ID, watchdogErr))
					}
					errorsByLane[laneIndex] = err
					cancelWorkers()
					return
				}
				records[scheduled.index] = record
			}
		}()
	}
	workers.Wait()
	if err := errors.Join(errorsByLane...); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("collection stage watchdog: %w", err)
	}
	return nil
}

func runCollectionJob(ctx context.Context, request collectRequest, manifest *PerformanceManifest, registry *CaseRegistry, job collectionJob, staging string, identity *collectionDirectoryIdentity, lane collectionLaneRuntime) (rawJobRecord, error) {
	if lane == nil {
		return rawJobRecord{}, errors.New("collection job requires an isolated execution lane")
	}
	jobsRoot := filepath.Join(staging, "jobs")
	if identity != nil {
		if err := identity.Verify(); err != nil {
			return rawJobRecord{}, err
		}
	}
	jobDirectory := filepath.Join(jobsRoot, job.ID)
	artifactDirectory := filepath.Join(jobDirectory, "artifacts")
	if err := os.MkdirAll(artifactDirectory, 0o700); err != nil {
		return rawJobRecord{}, err
	}
	reportPath := filepath.Join(jobDirectory, "cell.json")
	execution, err := executionForCollectionJob(request, job)
	if err != nil {
		return rawJobRecord{}, err
	}
	args := collectionJobArgs(job, execution.manifestPath, reportPath, artifactDirectory, execution.sourceSHA, execution.repository, request.BPFObject)
	commandRecord, err := json.MarshalIndent(struct {
		Executable string   `json:"executable"`
		Args       []string `json:"args"`
	}{execution.executable, args}, "", "  ")
	if err != nil {
		return rawJobRecord{}, err
	}
	commandRecord = append(commandRecord, '\n')
	commandDigest := sha256.Sum256(commandRecord)
	_, runnerDigest, err := snapshotRegularFile(execution.executable, true)
	if err != nil {
		return rawJobRecord{}, fmt.Errorf("low-level runner job %s executable: %w", job.ID, err)
	}
	if err := os.WriteFile(filepath.Join(jobDirectory, "command.json"), commandRecord, 0o600); err != nil {
		return rawJobRecord{}, err
	}
	stdout, err := os.OpenFile(filepath.Join(jobDirectory, "stdout.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return rawJobRecord{}, err
	}
	stderr, err := os.OpenFile(filepath.Join(jobDirectory, "stderr.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		_ = stdout.Close()
		return rawJobRecord{}, err
	}
	command := lane.Command(ctx, execution.executable, args...)
	configureCollectionCommand(command)
	command.Dir = execution.repository
	command.Env = slices.DeleteFunc(command.Env, func(value string) bool { return strings.HasPrefix(value, "GIT_") })
	command.Stdout, command.Stderr = stdout, stderr
	runErr := command.Run()
	outputErr := errors.Join(stdout.Sync(), stderr.Sync(), stdout.Close(), stderr.Close())
	if outputErr != nil {
		return rawJobRecord{}, outputErr
	}
	if runErr != nil {
		return rawJobRecord{}, fmt.Errorf("low-level runner job %s failed: %w", job.ID, runErr)
	}
	_, recordedCommandDigest, err := snapshotRegularFile(filepath.Join(jobDirectory, "command.json"), false)
	if err != nil || recordedCommandDigest != hex.EncodeToString(commandDigest[:]) {
		return rawJobRecord{}, fmt.Errorf("low-level runner job %s command record changed during execution", job.ID)
	}
	_, reportDigest, err := snapshotRegularFile(reportPath, false)
	if err != nil {
		return rawJobRecord{}, fmt.Errorf("low-level runner job %s report: %w", job.ID, err)
	}
	if err := validateRawCellReport(reportPath, execution.sourceSHA, manifest.Digest); err != nil {
		return rawJobRecord{}, fmt.Errorf("low-level runner job %s report: %w", job.ID, err)
	}
	recordCaseIDs := job.CaseIDs
	if job.CaseOwner != "" {
		_, manifestFileSHA256, err := snapshotRegularFile(execution.manifestPath, false)
		if err != nil {
			return rawJobRecord{}, fmt.Errorf("low-level runner job %s manifest: %w", job.ID, err)
		}
		actualCaseIDs, err := validateRawCaseSuiteReport(reportPath, artifactDirectory, execution.sourceSHA, manifest.Digest, manifestFileSHA256, job, registry)
		if err != nil {
			return rawJobRecord{}, fmt.Errorf("low-level runner job %s case report: %w", job.ID, err)
		}
		recordCaseIDs = actualCaseIDs
	}
	if err := validateProducedArtifacts(artifactDirectory); err != nil {
		return rawJobRecord{}, fmt.Errorf("low-level runner job %s artifacts: %w", job.ID, err)
	}
	if identity != nil {
		if err := identity.Verify(); err != nil {
			return rawJobRecord{}, err
		}
	}
	return rawJobRecord{
		ID: job.ID, CellIDs: job.CellIDs, CaseIDs: recordCaseIDs, VariantID: job.VariantID, SourceSHA: execution.sourceSHA,
		RunnerExecutableSHA256: runnerDigest, CommandSHA256: hex.EncodeToString(commandDigest[:]),
		Lane: lane.Identity(), Directory: filepath.ToSlash(filepath.Join("jobs", job.ID)), ReportSHA: reportDigest,
	}, nil
}

func collectionJobArgs(job collectionJob, manifestPath, reportPath, artifactDirectory, sourceSHA, repository, bpfObject string) []string {
	args := []string{
		"--target", job.RunnerTarget, "--manifest", manifestPath, "--report", reportPath,
		"--artifact-dir", artifactDirectory, "--source-sha", sourceSHA, "--source-root", repository,
	}
	if job.Profile != "" {
		args = append(args, "--profile", job.Profile)
	}
	if job.Carrier != "" {
		args = append(args, "--carrier", job.Carrier)
	}
	if job.Topology != "" {
		args = append(args, "--topology", job.Topology)
	}
	if job.NeedsBPF {
		args = append(args, "--bpf-object", bpfObject)
	}
	if job.CaseOwner != "" {
		args = append(args, "--case-owner", job.CaseOwner, "--case-mode", job.CaseMode)
	}
	if job.CaseID != "" {
		args = append(args, "--case-id", job.CaseID)
	}
	return args
}

func validateProducedArtifacts(root string) error {
	files := 0
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("produced artifacts must not contain symlinks")
		}
		if entry.IsDir() {
			return nil
		}
		if !info.Mode().IsRegular() || info.Size() == 0 {
			return errors.New("produced artifacts must be non-empty regular files")
		}
		files++
		return nil
	})
	if err != nil {
		return err
	}
	if files == 0 {
		return errors.New("low-level runner produced no raw artifacts")
	}
	return nil
}

func validateRawCellReport(path, finalSHA, manifestDigest string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var envelope map[string]any
	if err := decodeSingleJSON(data, &envelope); err != nil {
		return err
	}
	if envelope["schema_version"] != float64(1) || strings.TrimSpace(fmt.Sprint(envelope["classification"])) == "" ||
		envelope["source_sha"] != finalSHA || envelope["manifest_digest"] != manifestDigest {
		return errors.New("raw cell report does not bind schema, classification, final SHA, and manifest digest")
	}
	return nil
}

func validateRawCaseSuiteReport(path, artifactDirectory, finalSHA, manifestDigest, manifestFileSHA256 string, job collectionJob, registry *CaseRegistry) ([]string, error) {
	if registry == nil || job.CaseOwner == "" || job.CaseMode == "" || len(job.CaseIDs) == 0 ||
		(job.CaseID != "" && (len(job.CaseIDs) != 1 || job.CaseIDs[0] != job.CaseID)) {
		return nil, errors.New("case suite validation requires a registry and a complete case job")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var report rawCaseSuiteReport
	if err := decodeStrictJSON(data, &report); err != nil {
		return nil, err
	}
	if report.SchemaVersion != 1 || report.Classification != "linux_transport_case_suite" || report.SourceSHA != finalSHA ||
		report.ManifestDigest != manifestDigest || report.ManifestSHA256 != manifestFileSHA256 || report.Owner != job.CaseOwner || report.Mode != job.CaseMode ||
		strings.TrimSpace(report.StartedAt) == "" || strings.TrimSpace(report.FinishedAt) == "" {
		return nil, errors.New("case suite report does not bind its schema, classification, source, manifest, owner, mode, and timestamps")
	}
	definitions := make(map[string]CaseDefinition, len(registry.Cases))
	for _, definition := range registry.Cases {
		definitions[definition.ID] = definition
	}
	if len(report.Results) != len(job.CaseIDs) {
		return nil, fmt.Errorf("case suite result count = %d, want %d", len(report.Results), len(job.CaseIDs))
	}
	actualIDs := make([]string, 0, len(report.Results))
	seen := make(map[string]struct{}, len(report.Results))
	for index, result := range report.Results {
		if result.ID != job.CaseIDs[index] {
			return nil, fmt.Errorf("case result %d ID = %q, want %q", index, result.ID, job.CaseIDs[index])
		}
		if _, duplicate := seen[result.ID]; duplicate {
			return nil, fmt.Errorf("duplicate case result %s", result.ID)
		}
		seen[result.ID] = struct{}{}
		definition, exists := definitions[result.ID]
		ownerMatches := job.CaseMode == "normal" && definition.Owner == job.CaseOwner && definition.Mode == "normal" ||
			job.CaseMode == "race" && definition.RaceOwner == job.CaseOwner && definition.Mode == "normal"
		if !exists || !ownerMatches || result.Profile != definition.Profile {
			return nil, fmt.Errorf("case %s does not match its registered owner, mode, and profile", result.ID)
		}
		if result.Status != "pass" || result.CompletedOperations < 1 || result.ElapsedNanoseconds <= 0 {
			return nil, fmt.Errorf("case %s does not prove a successful measured workload", result.ID)
		}
		if err := validateRawCaseArtifacts(filepath.Dir(path), artifactDirectory, job.CaseMode, result, definition.EvidenceFields); err != nil {
			return nil, fmt.Errorf("case %s artifacts: %w", result.ID, err)
		}
		actualIDs = append(actualIDs, result.ID)
	}
	return actualIDs, nil
}

func validateRawCaseArtifacts(reportDirectory, artifactDirectory, mode string, result rawCaseSuiteResult, requiredKinds []string) error {
	if len(result.Artifacts) != len(requiredKinds) {
		return fmt.Errorf("artifact count = %d, want %d", len(result.Artifacts), len(requiredKinds))
	}
	wants := make(map[string]struct{}, len(requiredKinds))
	for _, kind := range requiredKinds {
		wants[kind] = struct{}{}
	}
	sources, sourcePaths, sourceDigests, err := validateRawCaseSources(reportDirectory, artifactDirectory, result)
	if err != nil {
		return err
	}
	seen := make(map[string]struct{}, len(result.Artifacts))
	for _, artifact := range result.Artifacts {
		if _, exists := wants[artifact.Kind]; !exists {
			return fmt.Errorf("unexpected artifact kind %q", artifact.Kind)
		}
		if _, duplicate := seen[artifact.Kind]; duplicate {
			return fmt.Errorf("duplicate artifact kind %q", artifact.Kind)
		}
		seen[artifact.Kind] = struct{}{}
		extension := ".json"
		wantPath := filepath.ToSlash(filepath.Join("artifacts", strings.ToLower(result.ID), artifact.Kind+extension))
		if artifact.Path != wantPath || filepath.IsAbs(filepath.FromSlash(artifact.Path)) {
			return fmt.Errorf("%s path = %q, want %q", artifact.Kind, artifact.Path, wantPath)
		}
		absolute := filepath.Clean(filepath.Join(reportDirectory, filepath.FromSlash(artifact.Path)))
		relative, err := filepath.Rel(artifactDirectory, absolute)
		if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return fmt.Errorf("%s path escapes the case artifact directory", artifact.Kind)
		}
		canonical, digest, err := snapshotRegularFile(absolute, false)
		if err != nil {
			return err
		}
		info, err := os.Stat(canonical)
		if err != nil {
			return err
		}
		if digest != artifact.SHA256 || info.Size() != artifact.SizeBytes {
			return fmt.Errorf("%s size or digest mismatch", artifact.Kind)
		}
		if _, duplicate := sourcePaths[canonical]; duplicate {
			return fmt.Errorf("%s typed artifact reuses a raw source path", artifact.Kind)
		}
		if _, duplicate := sourceDigests[digest]; duplicate {
			return fmt.Errorf("%s typed artifact reuses a raw source digest", artifact.Kind)
		}
		if artifact.Kind == "pcap" || artifact.Kind == "qlog" {
			context := "case " + result.ID
			if mode == "race" {
				context = "race case " + result.ID
			}
			if err := validateRawCaseAttribution(artifact.Kind, context, canonical, sources); err != nil {
				return fmt.Errorf("%s attribution: %w", artifact.Kind, err)
			}
		}
	}
	return nil
}

type validatedRawSource struct {
	id, kind, digest, path string
	data                   []byte
}

func validateRawCaseSources(reportDirectory, artifactDirectory string, result rawCaseSuiteResult) (map[string]validatedRawSource, map[string]struct{}, map[string]struct{}, error) {
	sources := make(map[string]validatedRawSource, len(result.RawSources))
	paths := make(map[string]struct{}, len(result.RawSources))
	digests := make(map[string]struct{}, len(result.RawSources))
	counts := make(map[string]int)
	caseRoot := filepath.Clean(filepath.Join(artifactDirectory, strings.ToLower(result.ID)))
	for _, source := range result.RawSources {
		if source.Kind != "pcap" && source.Kind != "qlog" && source.Kind != "netlog" {
			return nil, nil, nil, fmt.Errorf("raw source %q has unknown kind %q", source.ID, source.Kind)
		}
		counts[source.Kind]++
		wantID := fmt.Sprintf("%s-%03d", source.Kind, counts[source.Kind])
		if source.ID != wantID {
			return nil, nil, nil, fmt.Errorf("raw source ID = %q, want %q", source.ID, wantID)
		}
		if _, duplicate := sources[source.ID]; duplicate {
			return nil, nil, nil, fmt.Errorf("duplicate raw source ID %q", source.ID)
		}
		if filepath.IsAbs(filepath.FromSlash(source.Path)) {
			return nil, nil, nil, fmt.Errorf("raw source %s path must be relative", source.ID)
		}
		absolute := filepath.Clean(filepath.Join(reportDirectory, filepath.FromSlash(source.Path)))
		relative, err := filepath.Rel(caseRoot, absolute)
		if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return nil, nil, nil, fmt.Errorf("raw source %s path escapes its case artifact directory", source.ID)
		}
		canonical, digest, err := snapshotRegularFile(absolute, false)
		if err != nil {
			return nil, nil, nil, err
		}
		info, err := os.Stat(canonical)
		if err != nil {
			return nil, nil, nil, err
		}
		if digest != source.SHA256 || info.Size() != source.SizeBytes || source.SizeBytes <= 0 {
			return nil, nil, nil, fmt.Errorf("raw source %s size or digest mismatch", source.ID)
		}
		if _, duplicate := paths[canonical]; duplicate {
			return nil, nil, nil, fmt.Errorf("raw source %s reuses a source path", source.ID)
		}
		if _, duplicate := digests[digest]; duplicate {
			return nil, nil, nil, fmt.Errorf("raw source %s reuses a source digest", source.ID)
		}
		data, err := os.ReadFile(canonical)
		if err != nil {
			return nil, nil, nil, err
		}
		sources[source.ID] = validatedRawSource{id: source.ID, kind: source.Kind, digest: digest, path: canonical, data: data}
		paths[canonical] = struct{}{}
		digests[digest] = struct{}{}
	}
	attachmentKinds := map[string]struct{}{
		"playwright-trace": {}, "browser-controller-result": {}, "browser-controller-config": {},
		"producer-resource": {}, "browser-controller-stderr": {},
	}
	attachmentCounts := make(map[string]int)
	for _, attachment := range result.Attachments {
		if _, exists := attachmentKinds[attachment.Kind]; !exists {
			return nil, nil, nil, fmt.Errorf("attachment %q has unknown kind %q", attachment.ID, attachment.Kind)
		}
		attachmentCounts[attachment.Kind]++
		wantID := fmt.Sprintf("%s-%03d", attachment.Kind, attachmentCounts[attachment.Kind])
		if attachment.ID != wantID {
			return nil, nil, nil, fmt.Errorf("attachment ID = %q, want %q", attachment.ID, wantID)
		}
		if filepath.IsAbs(filepath.FromSlash(attachment.Path)) {
			return nil, nil, nil, fmt.Errorf("attachment %s path must be relative", attachment.ID)
		}
		absolute := filepath.Clean(filepath.Join(reportDirectory, filepath.FromSlash(attachment.Path)))
		relative, err := filepath.Rel(caseRoot, absolute)
		if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return nil, nil, nil, fmt.Errorf("attachment %s path escapes its case artifact directory", attachment.ID)
		}
		canonical, digest, err := snapshotRegularFile(absolute, false)
		if err != nil {
			return nil, nil, nil, err
		}
		info, err := os.Stat(canonical)
		if err != nil {
			return nil, nil, nil, err
		}
		if digest != attachment.SHA256 || info.Size() != attachment.SizeBytes || attachment.SizeBytes <= 0 {
			return nil, nil, nil, fmt.Errorf("attachment %s size or digest mismatch", attachment.ID)
		}
		if _, duplicate := paths[canonical]; duplicate {
			return nil, nil, nil, fmt.Errorf("attachment %s reuses an indexed path", attachment.ID)
		}
		if _, duplicate := digests[digest]; duplicate {
			return nil, nil, nil, fmt.Errorf("attachment %s reuses an indexed digest", attachment.ID)
		}
		paths[canonical] = struct{}{}
		digests[digest] = struct{}{}
	}
	return sources, paths, digests, nil
}

func validateRawCaseAttribution(kind, context, path string, sources map[string]validatedRawSource) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var attribution PacketAttributionArtifact
	if err := decodeStrictJSON(data, &attribution); err != nil {
		return err
	}
	if attribution.SchemaVersion != 1 || attribution.Kind != "transport_"+kind+"_attribution" || attribution.Context != context || len(attribution.Records) == 0 {
		return errors.New("typed attribution identity or records are incomplete")
	}
	seenSources := make(map[string]struct{})
	for index, record := range attribution.Records {
		source, exists := sources[record.SourceID]
		if record.Sequence != uint64(index+1) || !exists || source.kind != kind || record.SourceSHA256 != source.digest ||
			record.ByteOffset < 0 || record.ByteLength <= 0 || record.ByteOffset > int64(len(source.data))-record.ByteLength || record.UnixNanoseconds <= 0 {
			return fmt.Errorf("record %d does not bind a valid indexed %s source range", index+1, kind)
		}
		if kind == "pcap" {
			if err := validateAttributedPCAPRecord(source.data, record); err != nil {
				return fmt.Errorf("record %d: %w", index+1, err)
			}
		} else if err := validateAttributedQLOGRecord(source, record); err != nil {
			return fmt.Errorf("record %d: %w", index+1, err)
		}
		seenSources[source.id] = struct{}{}
	}
	for id, source := range sources {
		if source.kind == kind {
			if _, exists := seenSources[id]; !exists {
				return fmt.Errorf("indexed %s source %s has no attribution record", kind, id)
			}
		}
	}
	return nil
}

func validateAttributedPCAPRecord(data []byte, record PacketAttributionRecord) error {
	if len(data) < 24 {
		return errors.New("indexed pcap source is truncated")
	}
	format, err := parsePCAPFormat(data[:4])
	if err != nil {
		return err
	}
	for offset := 24; offset < len(data); {
		if len(data)-offset < 16 {
			return errors.New("indexed pcap source has a truncated record header")
		}
		included := int(format.order.Uint32(data[offset+8 : offset+12]))
		if included <= 0 || included > len(data)-offset-16 {
			return errors.New("indexed pcap source has an invalid record length")
		}
		length := 16 + included
		if int64(offset) == record.ByteOffset && int64(length) == record.ByteLength {
			fraction := int64(format.order.Uint32(data[offset+4 : offset+8]))
			if !format.nanosecond {
				fraction *= 1000
			}
			at := time.Unix(int64(format.order.Uint32(data[offset:offset+4])), fraction).UTC()
			if fraction < 0 || fraction >= int64(time.Second) || at.UnixNano() != record.UnixNanoseconds ||
				record.Event != "" || record.ConnectionGroupID != "" || record.PacketNumberSpace != "" || record.PacketNumber != nil {
				return errors.New("pcap attribution timestamp or pcap-only identity does not match source bytes")
			}
			return nil
		}
		offset += length
	}
	return errors.New("pcap attribution range is not an exact source record")
}

func validateAttributedQLOGRecord(source validatedRawSource, record PacketAttributionRecord) error {
	return validateAttributedQLOGRecords(source, []PacketAttributionRecord{record})
}

func validateAttributedQLOGRecords(source validatedRawSource, records []PacketAttributionRecord) error {
	events, err := parseQLOGSequenceSource(source.data, source.id)
	if err != nil {
		return err
	}
	type eventRange struct {
		offset int64
		length int64
	}
	byRange := make(map[eventRange]rawQLOGEvent, len(events))
	firstStreams := make(map[uint64]eventRange)
	firstResets := make(map[uint64]eventRange)
	for _, event := range events {
		key := eventRange{offset: event.recordOffset, length: event.recordLength}
		if _, duplicate := byRange[key]; duplicate {
			return errors.New("qlog source reuses an event byte range")
		}
		byRange[key] = event
		collectFirstAttributedQLOGFrameRanges(event, key, firstStreams, firstResets)
	}
	for _, record := range records {
		key := eventRange{offset: record.ByteOffset, length: record.ByteLength}
		event, exists := byRange[key]
		if !exists {
			return errors.New("qlog attribution range is not an exact source event record")
		}
		if event.at.UnixNano() != record.UnixNanoseconds || event.groupID != record.ConnectionGroupID {
			return errors.New("qlog attribution time, event, or connection identity does not match source bytes")
		}
		if record.NativeStreamID == nil {
			if event.name != record.Event {
				return errors.New("qlog attribution event does not match source bytes")
			}
		} else if event.name != "transport:packet_sent" && event.name != "transport:packet_received" {
			return errors.New("qlog stream attribution is not bound to a packet event")
		} else if record.Event == "transport:stream_opened" {
			if firstStreams[*record.NativeStreamID] != key || !qlogEventContainsFrameID(event, "stream", *record.NativeStreamID) {
				return errors.New("qlog STREAM_OPENED attribution is not the first matching raw STREAM frame")
			}
		} else if record.Event == "transport:reset_stream" {
			if firstResets[*record.NativeStreamID] != key || !qlogEventContainsFrameID(event, "reset_stream", *record.NativeStreamID) {
				return errors.New("qlog RESET_STREAM attribution is not the first matching raw RESET_STREAM frame")
			}
		} else {
			return errors.New("qlog stream attribution semantic is unsupported")
		}
		packetNumber, hasPacketNumber := uint64(0), false
		packetSpace := ""
		if header, ok := event.data["header"].(map[string]any); ok {
			packetNumber, hasPacketNumber = qlogUint(header["packet_number"])
			packetSpace, _ = header["packet_type"].(string)
			hasPacketNumber = hasPacketNumber && strings.TrimSpace(packetSpace) != ""
		}
		if hasPacketNumber != (record.PacketNumber != nil) || hasPacketNumber && (*record.PacketNumber != packetNumber || record.PacketNumberSpace != packetSpace) ||
			!hasPacketNumber && record.PacketNumberSpace != "" {
			return errors.New("qlog attribution packet number or PN space does not match source bytes")
		}
	}
	return nil
}

func collectFirstAttributedQLOGFrameRanges[T comparable](event rawQLOGEvent, key T, streams, resets map[uint64]T) {
	frames, ok := event.data["frames"].([]any)
	if !ok {
		return
	}
	for _, rawFrame := range frames {
		frame, ok := rawFrame.(map[string]any)
		streamID, idOK := qlogUint(frame["stream_id"])
		if !ok || !idOK {
			continue
		}
		switch frame["frame_type"] {
		case "stream":
			if _, exists := streams[streamID]; !exists {
				streams[streamID] = key
			}
		case "reset_stream":
			if _, exists := resets[streamID]; !exists {
				resets[streamID] = key
			}
		}
	}
}

func qlogEventContainsFrameID(event rawQLOGEvent, frameType string, want uint64) bool {
	frames, ok := event.data["frames"].([]any)
	if !ok {
		return false
	}
	for _, rawFrame := range frames {
		frame, ok := rawFrame.(map[string]any)
		streamID, idOK := qlogUint(frame["stream_id"])
		if ok && idOK && frame["frame_type"] == frameType && streamID == want {
			return true
		}
	}
	return false
}

func verifyInputDigests(request collectRequest, want map[string]string) error {
	paths := map[string]string{
		"manifest": request.ManifestPath, "base_manifest": request.BaseManifestPath, "registry": request.RegistryPath,
		"runner_executable": request.RunnerExecutable, "base_runner_executable": request.BaseRunnerExecutable, "runner_wrapper": request.RunnerWrapper,
		"bpf_object": request.BPFObject, "host_bpftool": request.HostBPFTool,
		"trust_policy": request.TrustPolicyPath, "effective_config": request.EffectiveConfigPath,
	}
	if request.RaceRunnerExecutable != "" {
		paths["race_runner_executable"] = request.RaceRunnerExecutable
	}
	for name, path := range paths {
		executable := name == "runner_executable" || name == "race_runner_executable" || name == "base_runner_executable" || name == "runner_wrapper" || name == "host_bpftool"
		_, got, err := snapshotRegularFile(path, executable)
		if err != nil || got != want[name] {
			return fmt.Errorf("collection input %s changed during execution", name)
		}
	}
	if err := validateCollectCheckout(request.RepositoryPath, request.FinalSHA, "final"); err != nil {
		return errors.New("final source checkout changed during collection")
	}
	if err := validateCollectCheckout(request.BaseRepositoryPath, request.BaseSHA, "base"); err != nil {
		return errors.New("base source checkout changed during collection")
	}
	if want["runner_source"] != "" {
		finalSource, err := runnerSourceSHA256(request.RepositoryPath)
		if err != nil || finalSource != want["runner_source"] {
			return errors.New("final runner source graph changed during collection")
		}
	}
	if want["base_runner_source"] != "" {
		baseSource, err := runnerSourceSHA256(request.BaseRepositoryPath)
		if err != nil || baseSource != want["base_runner_source"] {
			return errors.New("base runner source graph changed during collection")
		}
	}
	if want["runner_argv"] != "" {
		manifest, err := loadPerformanceManifest(request.ManifestPath)
		if err != nil {
			return errors.New("reload manifest for canonical runner argv verification")
		}
		registry, err := loadCaseRegistry(request.RegistryPath)
		if err != nil {
			return errors.New("reload registry for canonical runner argv verification")
		}
		argv, err := canonicalAllTargetArgvSHA256(manifest, registry)
		if err != nil || argv != want["runner_argv"] {
			return errors.New("canonical runner argv changed during collection")
		}
	}
	return nil
}

func publishRawCollection(identity *collectionDirectoryIdentity, reportPath string, index rawCollectionIndex) error {
	if err := identity.Verify(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	temporary, err := os.CreateTemp(identity.path, ".raw-collection-*")
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
	if err := identity.Verify(); err != nil {
		return err
	}
	if err := os.Link(temporaryPath, reportPath); err != nil {
		return err
	}
	if err := identity.Verify(); err != nil {
		return err
	}
	return nil
}

func collectGitOutput(repository string, args ...string) (string, error) {
	command := exec.Command("git", append([]string{"-C", repository}, args...)...)
	command.Env = slices.DeleteFunc(os.Environ(), func(value string) bool { return strings.HasPrefix(value, "GIT_") })
	output, err := command.Output()
	return strings.TrimSpace(string(output)), err
}
