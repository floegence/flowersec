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
	"syscall"
)

var collectTargets = map[string]struct{}{
	"all": {}, "transport-conformance-full": {}, "weaknet-full": {}, "weaknet-system": {},
	"quic-native-proof": {}, "quic-native-race": {}, "bench-transport-capacity": {},
	"bench-transport-soak": {}, "bench-transport-ab": {}, "transport-conformance-smoke": {},
}

var normalCaseProducerOwners = map[string]struct{}{
	"transport-conformance-smoke": {},
}

type collectRequest struct {
	ManifestPath        string
	RegistryPath        string
	RepositoryPath      string
	BaseSHA             string
	FinalSHA            string
	Target              string
	ReportPath          string
	ArtifactDirectory   string
	RunnerExecutable    string
	RunnerWrapper       string
	BPFObject           string
	HostBPFTool         string
	TrustPolicyPath     string
	EffectiveConfigPath string
	KernelRelease       string
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
	ID           string
	CellIDs      []string
	RunnerTarget string
	Profile      string
	Carrier      string
	Topology     string
	NeedsBPF     bool
	CaseOwner    string
	CaseMode     string
	CaseIDs      []string
}

type rawJobRecord struct {
	ID        string   `json:"id"`
	CellIDs   []string `json:"cell_ids"`
	CaseIDs   []string `json:"case_ids,omitempty"`
	Directory string   `json:"directory"`
	ReportSHA string   `json:"report_sha256"`
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
	Artifacts           []rawProducedArtifact `json:"artifacts"`
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
	if !gitSHAPattern.MatchString(request.BaseSHA) || !gitSHAPattern.MatchString(request.FinalSHA) {
		return nil, errors.New("collect requires full lowercase base and final Git SHAs")
	}
	if request.BaseSHA == request.FinalSHA {
		return nil, errors.New("collect base and final SHAs must differ")
	}
	top, err := collectGitOutput(repository, "rev-parse", "--show-toplevel")
	if err != nil || top != repository {
		return nil, errors.New("collect repository is not its canonical Git root")
	}
	head, err := collectGitOutput(repository, "rev-parse", "HEAD")
	if err != nil || head != request.FinalSHA {
		return nil, errors.New("collect final SHA does not match repository HEAD")
	}
	if err := exec.Command("git", "-C", repository, "merge-base", "--is-ancestor", request.BaseSHA, request.FinalSHA).Run(); err != nil {
		return nil, errors.New("collect base SHA is not an ancestor of final SHA")
	}
	status, err := collectGitOutput(repository, "status", "--porcelain", "--untracked-files=all")
	if err != nil || status != "" {
		return nil, errors.New("collect repository must be clean with no untracked files")
	}

	fixedPaths := map[string]*string{
		"manifest":         &request.ManifestPath,
		"registry":         &request.RegistryPath,
		"trust_policy":     &request.TrustPolicyPath,
		"effective_config": &request.EffectiveConfigPath,
	}
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
		{"manifest", &request.ManifestPath, false}, {"registry", &request.RegistryPath, false},
		{"runner_executable", &request.RunnerExecutable, true}, {"runner_wrapper", &request.RunnerWrapper, true},
		{"bpf_object", &request.BPFObject, false}, {"host_bpftool", &request.HostBPFTool, true},
		{"trust_policy", &request.TrustPolicyPath, false}, {"effective_config", &request.EffectiveConfigPath, false},
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
	if err := verifyCleanGoVCSStamp(request.RunnerExecutable, request.FinalSHA); err != nil {
		return nil, err
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

func verifyCleanGoVCSStamp(executable, finalSHA string) error {
	output, err := exec.Command("go", "version", "-m", executable).Output()
	if err != nil {
		return fmt.Errorf("inspect low-level runner VCS stamp: %w", err)
	}
	var revision, modified string
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "build\tvcs.revision=") {
			revision = strings.TrimPrefix(line, "build\tvcs.revision=")
		}
		if strings.HasPrefix(line, "build\tvcs.modified=") {
			modified = strings.TrimPrefix(line, "build\tvcs.modified=")
		}
	}
	if revision != finalSHA || modified != "false" {
		return errors.New("low-level runner must carry the clean final-SHA VCS stamp")
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
				job := caseJobs[key]
				if job == nil {
					job = &collectionJob{ID: "case-normal-" + entry.Owner, RunnerTarget: "release-case-suite", CaseOwner: entry.Owner, CaseMode: "normal"}
					caseJobs[key] = job
				}
				job.CaseIDs = append(job.CaseIDs, entry.ID)
			} else {
				plan.Missing = append(plan.Missing, fmt.Sprintf("case %s owned by %s", entry.ID, entry.Owner))
			}
		}
		if entry.RaceOwner != "" && (target == "all" || target == entry.RaceOwner) {
			plan.Missing = append(plan.Missing, fmt.Sprintf("race case %s owned by %s", entry.ID, entry.RaceOwner))
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
		jobs = append(jobs, collectionJob{ID: "clean-direct-baseline", CellIDs: baselineCells, RunnerTarget: "direct-clean-baseline"})
	}
	return jobs, missing
}

func performanceJob(cell PerformanceCell) (collectionJob, bool) {
	job := collectionJob{ID: cell.ID, CellIDs: []string{cell.ID}, Profile: cell.ProfileID}
	if cell.ProfileID == "clean-v1" {
		switch cell.Topology {
		case "direct_wss", "direct_quic":
			job.RunnerTarget = "direct-clean-baseline"
			return job, true
		case "browser_webtransport", "browser_tunnel_wt_wss", "browser_tunnel_wt_quic":
			job.RunnerTarget, job.Topology = "browser-webtransport-cell", cell.Topology
			return job, true
		default:
			return collectionJob{}, false
		}
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
	jobsRoot := filepath.Join(environment.request.ArtifactDirectory, "jobs")
	published := false
	defer func() {
		if !published && environment.output.Verify() == nil {
			_ = os.RemoveAll(jobsRoot)
		}
	}()
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
	published = true
	return nil
}

func runCollectionJobs(ctx context.Context, request collectRequest, manifest *PerformanceManifest, registry *CaseRegistry, jobs []collectionJob, staging string, identities ...*collectionDirectoryIdentity) ([]rawJobRecord, error) {
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
	records := make([]rawJobRecord, 0, len(jobs))
	for _, job := range jobs {
		if identity != nil {
			if err := identity.Verify(); err != nil {
				return nil, err
			}
		}
		jobDirectory := filepath.Join(jobsRoot, job.ID)
		artifactDirectory := filepath.Join(jobDirectory, "artifacts")
		if err := os.MkdirAll(artifactDirectory, 0o700); err != nil {
			return nil, err
		}
		reportPath := filepath.Join(jobDirectory, "cell.json")
		args := []string{
			"--target", job.RunnerTarget,
			"--manifest", request.ManifestPath,
			"--report", reportPath,
			"--artifact-dir", artifactDirectory,
			"--source-sha", request.FinalSHA,
			"--source-root", request.RepositoryPath,
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
			args = append(args, "--bpf-object", request.BPFObject)
		}
		if job.CaseOwner != "" {
			args = append(args, "--case-owner", job.CaseOwner, "--case-mode", job.CaseMode)
		}
		commandRecord, err := json.MarshalIndent(struct {
			Executable string   `json:"executable"`
			Args       []string `json:"args"`
		}{request.RunnerExecutable, args}, "", "  ")
		if err != nil {
			return nil, err
		}
		commandRecord = append(commandRecord, '\n')
		if err := os.WriteFile(filepath.Join(jobDirectory, "command.json"), commandRecord, 0o600); err != nil {
			return nil, err
		}
		stdout, err := os.OpenFile(filepath.Join(jobDirectory, "stdout.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, err
		}
		stderr, err := os.OpenFile(filepath.Join(jobDirectory, "stderr.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			_ = stdout.Close()
			return nil, err
		}
		command := exec.CommandContext(ctx, request.RunnerExecutable, args...)
		command.Dir = request.RepositoryPath
		command.Env = slices.DeleteFunc(os.Environ(), func(value string) bool { return strings.HasPrefix(value, "GIT_") })
		command.Stdout, command.Stderr = stdout, stderr
		runErr := command.Run()
		outputErr := errors.Join(stdout.Sync(), stderr.Sync(), stdout.Close(), stderr.Close())
		if outputErr != nil {
			return nil, outputErr
		}
		if runErr != nil {
			return nil, fmt.Errorf("low-level runner job %s failed: %w", job.ID, runErr)
		}
		_, reportDigest, err := snapshotRegularFile(reportPath, false)
		if err != nil {
			return nil, fmt.Errorf("low-level runner job %s report: %w", job.ID, err)
		}
		if err := validateRawCellReport(reportPath, request.FinalSHA, manifest.Digest); err != nil {
			return nil, fmt.Errorf("low-level runner job %s report: %w", job.ID, err)
		}
		recordCaseIDs := job.CaseIDs
		if job.CaseOwner != "" {
			_, manifestFileSHA256, err := snapshotRegularFile(request.ManifestPath, false)
			if err != nil {
				return nil, fmt.Errorf("low-level runner job %s manifest: %w", job.ID, err)
			}
			actualCaseIDs, err := validateRawCaseSuiteReport(reportPath, artifactDirectory, request.FinalSHA, manifest.Digest, manifestFileSHA256, job, registry)
			if err != nil {
				return nil, fmt.Errorf("low-level runner job %s case report: %w", job.ID, err)
			}
			recordCaseIDs = actualCaseIDs
		}
		if err := validateProducedArtifacts(artifactDirectory); err != nil {
			return nil, fmt.Errorf("low-level runner job %s artifacts: %w", job.ID, err)
		}
		if identity != nil {
			if err := identity.Verify(); err != nil {
				return nil, err
			}
		}
		records = append(records, rawJobRecord{ID: job.ID, CellIDs: job.CellIDs, CaseIDs: recordCaseIDs, Directory: filepath.ToSlash(filepath.Join("jobs", job.ID)), ReportSHA: reportDigest})
	}
	return records, nil
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
	if registry == nil || job.CaseOwner == "" || job.CaseMode == "" || len(job.CaseIDs) == 0 {
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
		if !exists || definition.Owner != job.CaseOwner || definition.Mode != job.CaseMode || result.Profile != definition.Profile {
			return nil, fmt.Errorf("case %s does not match its registered owner, mode, and profile", result.ID)
		}
		if result.Status != "pass" || result.CompletedOperations < 1 || result.ElapsedNanoseconds <= 0 {
			return nil, fmt.Errorf("case %s does not prove a successful measured workload", result.ID)
		}
		if err := validateRawCaseArtifacts(filepath.Dir(path), artifactDirectory, result, definition.EvidenceFields); err != nil {
			return nil, fmt.Errorf("case %s artifacts: %w", result.ID, err)
		}
		actualIDs = append(actualIDs, result.ID)
	}
	return actualIDs, nil
}

func validateRawCaseArtifacts(reportDirectory, artifactDirectory string, result rawCaseSuiteResult, requiredKinds []string) error {
	if len(result.Artifacts) != len(requiredKinds) {
		return fmt.Errorf("artifact count = %d, want %d", len(result.Artifacts), len(requiredKinds))
	}
	wants := make(map[string]struct{}, len(requiredKinds))
	for _, kind := range requiredKinds {
		wants[kind] = struct{}{}
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
		wantPath := filepath.ToSlash(filepath.Join("artifacts", strings.ToLower(result.ID), artifact.Kind+".json"))
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
	}
	return nil
}

func verifyInputDigests(request collectRequest, want map[string]string) error {
	paths := map[string]string{
		"manifest": request.ManifestPath, "registry": request.RegistryPath,
		"runner_executable": request.RunnerExecutable, "runner_wrapper": request.RunnerWrapper,
		"bpf_object": request.BPFObject, "host_bpftool": request.HostBPFTool,
		"trust_policy": request.TrustPolicyPath, "effective_config": request.EffectiveConfigPath,
	}
	for name, path := range paths {
		_, got, err := snapshotRegularFile(path, name == "runner_executable" || name == "runner_wrapper" || name == "host_bpftool")
		if err != nil || got != want[name] {
			return fmt.Errorf("collection input %s changed during execution", name)
		}
	}
	status, err := collectGitOutput(request.RepositoryPath, "status", "--porcelain", "--untracked-files=all")
	if err != nil || status != "" {
		return errors.New("source checkout changed during collection")
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
