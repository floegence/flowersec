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
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	focusedTailSchemaVersion = 1
	focusedTailShardCount    = 5
	focusedTailReceiptSchema = "flowersec-focused-success-receipt-v1"
)

var focusedTailTimeouts = struct {
	Lock      time.Duration
	Prepare   time.Duration
	Receipt   time.Duration
	Preflight time.Duration
	Shard     time.Duration
	Cleanup   time.Duration
}{
	Lock:      2 * time.Minute,
	Prepare:   5 * time.Minute,
	Receipt:   30 * time.Second,
	Preflight: 30 * time.Second,
	Shard:     10 * time.Minute,
	Cleanup:   30 * time.Second,
}

var (
	focusedTailSHA        = regexp.MustCompile(`^[0-9a-f]{40}$`)
	focusedTailName       = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,95}$`)
	focusedTailTarget     = regexp.MustCompile(`^[A-Za-z0-9._@-]{1,160}$`)
	focusedTailRemotePath = regexp.MustCompile(`^/[A-Za-z0-9._/-]{1,511}$`)
	focusedTailSSHOption  = regexp.MustCompile(`^-[A-Za-z0-9][A-Za-z0-9=,._:/@+-]{0,255}$`)
)

type focusedTailRequest struct {
	RepositoryPath   string
	SHA              string
	CellID           string
	StartShard       int
	StatePath        string
	ReceiptDirectory string
	RunnerConfigPath string
}

type focusedTailRunnerConfig struct {
	SchemaVersion        int      `json:"schema_version"`
	SSHExecutable        string   `json:"ssh_executable"`
	SCPExecutable        string   `json:"scp_executable"`
	SSHOptions           []string `json:"ssh_options"`
	SSHTarget            string   `json:"ssh_target"`
	ContainerExecutable  string   `json:"container_executable"`
	ContainerName        string   `json:"container_name"`
	RemoteSourceRoot     string   `json:"remote_source_root"`
	RemoteArtifactRoot   string   `json:"remote_artifact_root"`
	RemoteCacheRoot      string   `json:"remote_cache_root"`
	RemoteStagingRoot    string   `json:"remote_staging_root"`
	ContainerStagingRoot string   `json:"container_staging_root"`
	EnvironmentRetries   int      `json:"environment_retries"`
}

type focusedTailCell struct {
	ID           string `json:"id"`
	Profile      string `json:"profile"`
	Topology     string `json:"topology"`
	RunnerTarget string `json:"runner_target"`
}

type focusedTailPrepared struct {
	SourceSHA       string `json:"source_sha"`
	RunnerPath      string `json:"runner_path"`
	RunnerSHA256    string `json:"runner_sha256"`
	ToolchainSHA256 string `json:"toolchain_sha256"`
	DistSHA256      string `json:"typescript_dist_sha256"`
}

type focusedTailReceipt struct {
	Schema              string `json:"schema"`
	SourceSHA           string `json:"source_sha"`
	CellID              string `json:"cell_id"`
	Shard               int    `json:"shard"`
	ShardCount          int    `json:"shard_count"`
	Result              string `json:"result"`
	RunnerSHA256        string `json:"runner_sha256"`
	ToolchainSHA256     string `json:"toolchain_sha256"`
	DistSHA256          string `json:"typescript_dist_sha256"`
	ReportSHA256        string `json:"report_sha256"`
	ClosureSHA256       string `json:"closure_manifest_sha256"`
	DeletedStreamSHA256 string `json:"deleted_content_stream_sha256"`
	StartedAt           string `json:"started_at"`
	FinishedAt          string `json:"finished_at"`
	Summary             string `json:"summary"`
	ResidualProcesses   int    `json:"residual_processes"`
	ResidualCgroups     int    `json:"residual_cgroups"`
	ResidualNamespaces  int    `json:"residual_namespaces"`
}

type focusedTailFailure struct {
	Classification   string `json:"classification"`
	WorkloadStarted  bool   `json:"workload_started"`
	Message          string `json:"message"`
	DiagnosticPath   string `json:"diagnostic_path,omitempty"`
	DiagnosticSHA256 string `json:"diagnostic_sha256,omitempty"`
}

type focusedTailShardResult struct {
	Receipt *focusedTailReceipt `json:"receipt"`
	Failure *focusedTailFailure `json:"failure"`
}

type focusedTailState struct {
	SchemaVersion int                 `json:"schema_version"`
	SourceSHA     string              `json:"source_sha"`
	CellID        string              `json:"cell_id"`
	StartShard    int                 `json:"start_shard"`
	NextShard     int                 `json:"next_shard"`
	Status        string              `json:"status"`
	Completed     []int               `json:"completed_shards"`
	Attempts      map[string]int      `json:"environment_attempts"`
	Failure       *focusedTailFailure `json:"failure,omitempty"`
	UpdatedAt     string              `json:"updated_at"`
}

type focusedTailExecutor interface {
	Acquire(context.Context, focusedTailRequest, focusedTailRunnerConfig, focusedTailCell) error
	Prepare(context.Context, focusedTailRequest, focusedTailRunnerConfig, focusedTailCell) (focusedTailPrepared, error)
	RecoverShard(context.Context, focusedTailRequest, focusedTailRunnerConfig, focusedTailCell, focusedTailPrepared, int) (focusedTailShardResult, error)
	Preflight(context.Context, focusedTailRequest, focusedTailRunnerConfig, focusedTailCell, focusedTailPrepared, int) error
	RunShard(context.Context, focusedTailRequest, focusedTailRunnerConfig, focusedTailCell, focusedTailPrepared, int) (focusedTailShardResult, error)
	Close(context.Context) error
}

type focusedTailExitError struct {
	code int
	err  error
}

func (err *focusedTailExitError) Error() string { return err.err.Error() }
func (err *focusedTailExitError) Unwrap() error { return err.err }
func (err *focusedTailExitError) ExitCode() int { return err.code }

func focusedTailError(code int, format string, args ...any) error {
	return &focusedTailExitError{code: code, err: fmt.Errorf(format, args...)}
}

func runFocusedTail(ctx context.Context, request focusedTailRequest, output io.Writer, executor focusedTailExecutor) (returnErr error) {
	if ctx == nil || executor == nil {
		return focusedTailError(10, "focused-tail requires a context and executor")
	}
	repository, config, cell, err := validateFocusedTailRequest(request)
	if err != nil {
		return focusedTailError(10, "%v", err)
	}
	request.RepositoryPath = repository
	lock, err := acquireFocusedTailLock(request.StatePath + ".lock")
	if err != nil {
		return focusedTailError(20, "focused-tail lock: %v", err)
	}
	defer lock.Close()

	state, err := loadOrCreateFocusedTailState(request)
	if err != nil {
		return focusedTailError(10, "focused-tail state: %v", err)
	}
	if state.Status == "product_failure" {
		return focusedTailError(30, "focused-tail is stopped on a persisted product failure; automatic retry is forbidden: %s", state.failureMessage())
	}
	interruptedShard := 0
	if state.Status == "running" {
		interruptedShard = state.NextShard
	}

	lockContext, cancel := context.WithTimeout(ctx, focusedTailTimeouts.Lock)
	err = executor.Acquire(lockContext, request, config, cell)
	cancel()
	if err != nil {
		return focusedTailError(20, "focused-tail remote lock: %v", err)
	}
	defer func() {
		cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), focusedTailTimeouts.Cleanup)
		defer cleanupCancel()
		if err := executor.Close(cleanupContext); err != nil && returnErr == nil {
			returnErr = focusedTailError(20, "focused-tail remote cleanup: %v", err)
		}
	}()

	prepareContext, cancel := context.WithTimeout(ctx, focusedTailTimeouts.Prepare)
	prepared, err := executor.Prepare(prepareContext, request, config, cell)
	cancel()
	if err != nil {
		return focusedTailError(20, "focused-tail prepare: %v", err)
	}
	if err := validateFocusedTailPrepared(prepared, request.SHA); err != nil {
		return focusedTailError(20, "focused-tail prepared identity: %v", err)
	}

	for shard := request.StartShard; shard <= focusedTailShardCount; shard++ {
		receiptPath := focusedTailReceiptPath(request, shard)
		receipt, receiptErr := loadFocusedTailReceipt(receiptPath)
		if errors.Is(receiptErr, os.ErrNotExist) {
			receiptContext, receiptCancel := context.WithTimeout(ctx, focusedTailTimeouts.Receipt)
			recovery, recoveryErr := executor.RecoverShard(receiptContext, request, config, cell, prepared, shard)
			receiptCancel()
			if recoveryErr != nil {
				receiptErr = recoveryErr
			} else if recovery.Failure != nil {
				failure := *recovery.Failure
				failure.Classification, failure.WorkloadStarted = "product", true
				state.Status, state.Failure = "product_failure", &failure
				if err := persistFocusedTailState(request.StatePath, state); err != nil {
					return focusedTailError(20, "persist recovered focused-tail failure: %v", err)
				}
				return focusedTailError(30, "focused-tail shard %d recovered an interrupted product outcome; automatic retry is forbidden: %s", shard, failure.Message)
			} else {
				receipt = recovery.Receipt
				receiptErr = nil
			}
			if receiptErr == nil && receipt != nil {
				receiptErr = persistFocusedTailReceipt(receiptPath, *receipt)
			}
		}
		if receiptErr == nil && receipt != nil {
			if err := validateFocusedTailReceipt(*receipt, request, prepared, shard); err != nil {
				return focusedTailError(10, "focused-tail receipt shard %d: %v", shard, err)
			}
			state.completeShard(shard)
			if err := persistFocusedTailState(request.StatePath, state); err != nil {
				return focusedTailError(20, "persist resumed focused-tail state: %v", err)
			}
			_, _ = fmt.Fprintf(output, "focused-tail resume: sha=%s cell=%s shard=%d receipt=%s\n", request.SHA, request.CellID, shard, receiptPath)
			continue
		}
		if receiptErr != nil && !errors.Is(receiptErr, os.ErrNotExist) {
			return focusedTailError(10, "load focused-tail receipt shard %d: %v", shard, receiptErr)
		}
		if shard == interruptedShard {
			failure := focusedTailFailure{Classification: "product", WorkloadStarted: true, Message: "the previous process ended while this shard was running and no exact-SHA receipt proves its outcome"}
			state.Status, state.Failure = "product_failure", &failure
			if err := persistFocusedTailState(request.StatePath, state); err != nil {
				return focusedTailError(20, "persist interrupted focused-tail state: %v", err)
			}
			return focusedTailError(30, "focused-tail shard %d has an unknown interrupted outcome; automatic retry is forbidden", shard)
		}
		if state.Status == "complete" {
			return focusedTailError(10, "focused-tail completed state is missing the exact receipt for shard %d", shard)
		}

		attemptKey := strconv.Itoa(shard)
		if state.Attempts[attemptKey] > config.EnvironmentRetries {
			return focusedTailError(20, "focused-tail shard %d already exhausted its bounded environment retries", shard)
		}
		for {
			preflightContext, cancel := context.WithTimeout(ctx, focusedTailTimeouts.Preflight)
			preflightErr := executor.Preflight(preflightContext, request, config, cell, prepared, shard)
			cancel()
			if preflightErr == nil {
				break
			}
			state.Attempts[attemptKey]++
			state.Status = "environment_failure"
			state.Failure = &focusedTailFailure{Classification: "environment", WorkloadStarted: false, Message: preflightErr.Error()}
			if err := persistFocusedTailState(request.StatePath, state); err != nil {
				return focusedTailError(20, "persist preflight failure: %v", err)
			}
			if state.Attempts[attemptKey] > config.EnvironmentRetries {
				return focusedTailError(20, "focused-tail preflight shard %d exhausted bounded environment retries: %v", shard, preflightErr)
			}
		}

		state.Status, state.NextShard, state.Failure = "running", shard, nil
		if err := persistFocusedTailState(request.StatePath, state); err != nil {
			return focusedTailError(20, "persist running focused-tail state: %v", err)
		}
		shardContext, cancel := context.WithTimeout(ctx, focusedTailTimeouts.Shard)
		result, runErr := executor.RunShard(shardContext, request, config, cell, prepared, shard)
		cancel()
		if runErr != nil {
			failure := focusedTailFailure{Classification: "product", WorkloadStarted: true, Message: runErr.Error()}
			state.Status, state.Failure = "product_failure", &failure
			_ = persistFocusedTailState(request.StatePath, state)
			return focusedTailError(30, "focused-tail shard %d product failure; automatic retry is forbidden: %v", shard, runErr)
		}
		if result.Failure != nil {
			failure := *result.Failure
			if failure.Classification != "environment" || failure.WorkloadStarted {
				failure.Classification = "product"
				failure.WorkloadStarted = true
				state.Status, state.Failure = "product_failure", &failure
				_ = persistFocusedTailState(request.StatePath, state)
				return focusedTailError(30, "focused-tail shard %d product failure; automatic retry is forbidden: %s", shard, failure.Message)
			}
			state.Status, state.Failure = "environment_failure", &failure
			state.Attempts[attemptKey]++
			if err := persistFocusedTailState(request.StatePath, state); err != nil {
				return focusedTailError(20, "persist shard environment failure: %v", err)
			}
			if state.Attempts[attemptKey] > config.EnvironmentRetries {
				return focusedTailError(20, "focused-tail shard %d exhausted bounded environment retries: %s", shard, failure.Message)
			}
			continue
		}
		if result.Receipt == nil {
			return focusedTailError(20, "focused-tail shard %d returned neither receipt nor failure", shard)
		}
		if err := validateFocusedTailReceipt(*result.Receipt, request, prepared, shard); err != nil {
			return focusedTailError(20, "focused-tail shard %d invalid success receipt: %v", shard, err)
		}
		if err := persistFocusedTailReceipt(receiptPath, *result.Receipt); err != nil {
			return focusedTailError(20, "persist focused-tail receipt shard %d: %v", shard, err)
		}
		state.completeShard(shard)
		if err := persistFocusedTailState(request.StatePath, state); err != nil {
			return focusedTailError(20, "persist completed focused-tail state: %v", err)
		}
		_, _ = fmt.Fprintf(output, "focused-tail green: sha=%s cell=%s shard=%d receipt=%s\n", request.SHA, request.CellID, shard, receiptPath)
	}
	state.Status, state.NextShard, state.Failure = "complete", focusedTailShardCount+1, nil
	if err := persistFocusedTailState(request.StatePath, state); err != nil {
		return focusedTailError(20, "persist final focused-tail state: %v", err)
	}
	_, _ = fmt.Fprintf(output, "focused-tail complete: sha=%s cell=%s shards=%d-%d\n", request.SHA, request.CellID, request.StartShard, focusedTailShardCount)
	return nil
}

func (state focusedTailState) failureMessage() string {
	if state.Failure == nil || state.Failure.Message == "" {
		return "stored failure has no diagnostic message"
	}
	return state.Failure.Message
}

func validateFocusedTailRequest(request focusedTailRequest) (string, focusedTailRunnerConfig, focusedTailCell, error) {
	var config focusedTailRunnerConfig
	if !focusedTailSHA.MatchString(request.SHA) || !focusedTailName.MatchString(request.CellID) || request.StartShard < 1 || request.StartShard > focusedTailShardCount {
		return "", config, focusedTailCell{}, errors.New("focused-tail requires a full SHA, canonical cell ID, and start shard 1-5")
	}
	repository, err := canonicalDirectory(request.RepositoryPath, true)
	if err != nil {
		return "", config, focusedTailCell{}, err
	}
	if head, err := collectGitOutput(repository, "rev-parse", "HEAD"); err != nil || head != request.SHA {
		return "", config, focusedTailCell{}, errors.New("focused-tail repository HEAD must equal the exact SHA")
	}
	if status, err := collectGitOutput(repository, "status", "--porcelain", "--untracked-files=all"); err != nil || status != "" {
		return "", config, focusedTailCell{}, errors.New("focused-tail repository must be clean")
	}
	for _, path := range []string{request.StatePath, request.ReceiptDirectory, request.RunnerConfigPath} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return "", config, focusedTailCell{}, errors.New("focused-tail state, receipt, and runner config paths must be absolute and canonical")
		}
	}
	if err := validatePrivateFocusedTailConfigPath(repository, request.RunnerConfigPath); err != nil {
		return "", config, focusedTailCell{}, err
	}
	if err := decodeStrictFile(request.RunnerConfigPath, &config); err != nil {
		return "", config, focusedTailCell{}, err
	}
	if err := validateFocusedTailRunnerConfig(config); err != nil {
		return "", config, focusedTailCell{}, err
	}
	manifest, err := loadPerformanceManifest(filepath.Join(repository, "testdata", "transport_v2", "performance_manifest.json"))
	if err != nil {
		return "", config, focusedTailCell{}, err
	}
	var selected *PerformanceCell
	for index := range manifest.Cells {
		if manifest.Cells[index].ID == request.CellID {
			selected = &manifest.Cells[index]
			break
		}
	}
	if selected == nil {
		return "", config, focusedTailCell{}, errors.New("focused-tail cell is absent from the frozen manifest")
	}
	job, supported := performanceJob(*selected)
	if !supported || job.RunnerTarget != "browser-webtransport-cell" {
		return "", config, focusedTailCell{}, errors.New("focused-tail currently requires a frozen browser WebTransport cell")
	}
	stateParent := filepath.Dir(request.StatePath)
	if err := os.MkdirAll(stateParent, 0o700); err != nil {
		return "", config, focusedTailCell{}, err
	}
	if err := os.MkdirAll(request.ReceiptDirectory, 0o700); err != nil {
		return "", config, focusedTailCell{}, err
	}
	for _, entry := range []struct {
		path      string
		directory bool
	}{
		{request.StatePath, false}, {request.ReceiptDirectory, true}, {stateParent, true},
	} {
		info, err := os.Lstat(entry.path)
		if errors.Is(err, os.ErrNotExist) && !entry.directory {
			continue
		}
		if err != nil {
			return "", config, focusedTailCell{}, err
		}
		if info.Mode()&os.ModeSymlink != 0 || entry.directory && !info.IsDir() || !entry.directory && !info.Mode().IsRegular() {
			return "", config, focusedTailCell{}, errors.New("focused-tail state and receipt paths must not be symlinks")
		}
		resolved, err := filepath.EvalSymlinks(entry.path)
		if err != nil || resolved != entry.path {
			return "", config, focusedTailCell{}, errors.New("focused-tail state and receipt paths must not traverse symlinks")
		}
	}
	return repository, config, focusedTailCell{ID: selected.ID, Profile: selected.ProfileID, Topology: job.Topology, RunnerTarget: job.RunnerTarget}, nil
}

func validatePrivateFocusedTailConfigPath(repository, path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return errors.New("focused-tail runner config must be a private regular non-symlink file")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return errors.New("focused-tail runner config must not traverse symlinks")
	}
	relative, err := filepath.Rel(repository, path)
	if err != nil {
		return err
	}
	if relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		relative = filepath.ToSlash(relative)
		if tracked, _ := collectGitOutput(repository, "ls-files", "--", relative); tracked != "" {
			return errors.New("focused-tail runner config inside the repository must not be tracked")
		}
		if _, err := collectGitOutput(repository, "check-ignore", "-q", "--", relative); err != nil {
			return errors.New("focused-tail runner config inside the repository must be git-ignored")
		}
	}
	return nil
}

func validateFocusedTailRunnerConfig(config focusedTailRunnerConfig) error {
	if config.SchemaVersion != 1 || !filepath.IsAbs(config.SSHExecutable) || !filepath.IsAbs(config.SCPExecutable) ||
		!focusedTailTarget.MatchString(config.SSHTarget) || !focusedTailRemotePath.MatchString(config.ContainerExecutable) ||
		!focusedTailName.MatchString(config.ContainerName) || !focusedTailRemotePath.MatchString(config.RemoteSourceRoot) ||
		!focusedTailRemotePath.MatchString(config.RemoteArtifactRoot) || !focusedTailRemotePath.MatchString(config.RemoteCacheRoot) ||
		!focusedTailRemotePath.MatchString(config.RemoteStagingRoot) || !focusedTailRemotePath.MatchString(config.ContainerStagingRoot) ||
		config.EnvironmentRetries < 0 || config.EnvironmentRetries > 2 {
		return errors.New("focused-tail runner config is invalid")
	}
	for _, option := range config.SSHOptions {
		if !focusedTailSSHOption.MatchString(option) {
			return errors.New("focused-tail SSH options must use single-argument safe forms such as -oBatchMode=yes")
		}
	}
	return nil
}

func validateFocusedTailPrepared(prepared focusedTailPrepared, sha string) error {
	if prepared.SourceSHA != sha || !focusedTailRemotePath.MatchString(prepared.RunnerPath) ||
		!validSHA256(prepared.RunnerSHA256) || !validSHA256(prepared.ToolchainSHA256) || !validSHA256(prepared.DistSHA256) {
		return errors.New("prepared source, runner, toolchain, or TypeScript identity drifted")
	}
	return nil
}

func validateFocusedTailReceipt(receipt focusedTailReceipt, request focusedTailRequest, prepared focusedTailPrepared, shard int) error {
	if receipt.Schema != focusedTailReceiptSchema || receipt.SourceSHA != request.SHA || receipt.CellID != request.CellID ||
		receipt.Shard != shard || receipt.ShardCount != focusedTailShardCount || receipt.Result != "GREEN" ||
		receipt.RunnerSHA256 != prepared.RunnerSHA256 || receipt.ToolchainSHA256 != prepared.ToolchainSHA256 || receipt.DistSHA256 != prepared.DistSHA256 ||
		!validSHA256(receipt.ReportSHA256) || !validSHA256(receipt.ClosureSHA256) || !validSHA256(receipt.DeletedStreamSHA256) ||
		receipt.StartedAt == "" || receipt.FinishedAt == "" || receipt.Summary == "" ||
		receipt.ResidualProcesses != 0 || receipt.ResidualCgroups != 0 || receipt.ResidualNamespaces != 0 {
		return errors.New("receipt does not bind the exact green shard and zero-residual identities")
	}
	return nil
}

func loadOrCreateFocusedTailState(request focusedTailRequest) (focusedTailState, error) {
	var state focusedTailState
	err := decodeStrictFile(request.StatePath, &state)
	if errors.Is(err, os.ErrNotExist) {
		state = focusedTailState{SchemaVersion: focusedTailSchemaVersion, SourceSHA: request.SHA, CellID: request.CellID, StartShard: request.StartShard, NextShard: request.StartShard, Status: "ready", Attempts: make(map[string]int)}
		return state, persistFocusedTailState(request.StatePath, state)
	}
	if err != nil {
		return state, err
	}
	if state.SchemaVersion != focusedTailSchemaVersion || state.SourceSHA != request.SHA || state.CellID != request.CellID || state.StartShard != request.StartShard || state.Attempts == nil {
		return state, errors.New("existing focused-tail state belongs to another exact task")
	}
	if err := validateFocusedTailState(state); err != nil {
		return state, err
	}
	return state, nil
}

func validateFocusedTailState(state focusedTailState) error {
	validStatus := state.Status == "ready" || state.Status == "running" || state.Status == "environment_failure" || state.Status == "product_failure" || state.Status == "complete"
	if !validStatus || state.NextShard < state.StartShard || state.NextShard > focusedTailShardCount+1 {
		return errors.New("existing focused-tail state has an invalid status or next shard")
	}
	seen := make(map[int]bool, len(state.Completed))
	for _, shard := range state.Completed {
		if shard < state.StartShard || shard >= state.NextShard || shard > focusedTailShardCount || seen[shard] {
			return errors.New("existing focused-tail state has invalid completed shards")
		}
		seen[shard] = true
	}
	if state.Status == "complete" && state.NextShard != focusedTailShardCount+1 {
		return errors.New("completed focused-tail state has an invalid next shard")
	}
	if state.Status == "product_failure" && (state.Failure == nil || state.Failure.Classification != "product") {
		return errors.New("product-failure focused-tail state is missing its failure identity")
	}
	return nil
}

func (state *focusedTailState) completeShard(shard int) {
	for _, completed := range state.Completed {
		if completed == shard {
			state.NextShard, state.Status, state.Failure = shard+1, "ready", nil
			return
		}
	}
	state.Completed = append(state.Completed, shard)
	state.NextShard, state.Status, state.Failure = shard+1, "ready", nil
}

func persistFocusedTailState(path string, state focusedTailState) error {
	state.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	return writeAtomicFocusedTailJSON(path, state)
}

func focusedTailReceiptPath(request focusedTailRequest, shard int) string {
	return filepath.Join(request.ReceiptDirectory, fmt.Sprintf("%s-%s-shard-%02d.receipt.json", request.SHA, request.CellID, shard))
}

func loadFocusedTailReceipt(path string) (*focusedTailReceipt, error) {
	var receipt focusedTailReceipt
	if err := decodeStrictFile(path, &receipt); err != nil {
		return nil, err
	}
	return &receipt, nil
}

func persistFocusedTailReceipt(path string, receipt focusedTailReceipt) error {
	if existing, err := loadFocusedTailReceipt(path); err == nil {
		left, _ := json.Marshal(existing)
		right, _ := json.Marshal(receipt)
		if string(left) == string(right) {
			return nil
		}
		return errors.New("existing focused-tail receipt differs")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return writeAtomicFocusedTailJSON(path, receipt)
}

func writeAtomicFocusedTailJSON(path string, value any) error {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	parent := filepath.Dir(path)
	temporary, err := os.CreateTemp(parent, ".focused-tail-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(encoded); err != nil {
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
	directory, err := os.Open(parent)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

type focusedTailLock struct{ file *os.File }

func acquireFocusedTailLock(path string) (*focusedTailLock, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		return nil, errors.New("another focused-tail job owns the state lock")
	}
	if err := file.Truncate(0); err != nil {
		_ = file.Close()
		return nil, err
	}
	_, _ = fmt.Fprintf(file, "%d\n", os.Getpid())
	_ = file.Sync()
	return &focusedTailLock{file: file}, nil
}

func (lock *focusedTailLock) Close() error {
	if lock == nil || lock.file == nil {
		return nil
	}
	err := syscall.Flock(int(lock.file.Fd()), syscall.LOCK_UN)
	return errors.Join(err, lock.file.Close())
}

func focusedTailBundleSHA256(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:]), nil
}

func createFocusedTailBundle(ctx context.Context, repository, path string) error {
	command := exec.CommandContext(ctx, "git", "-C", repository, "bundle", "create", path, "HEAD")
	command.Env = slices.DeleteFunc(os.Environ(), func(value string) bool { return strings.HasPrefix(value, "GIT_") })
	if output, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("create exact focused-tail bundle: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}
