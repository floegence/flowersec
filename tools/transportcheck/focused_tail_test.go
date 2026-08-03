package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakeFocusedTailExecutor struct {
	acquireErr       error
	prepared         focusedTailPrepared
	recovered        map[int]*focusedTailReceipt
	preflightErrors  map[int][]error
	shardResults     map[int][]focusedTailShardResult
	blockShard       int
	acquireCalls     int
	prepareCalls     int
	recoverCalls     []int
	preflightCalls   []int
	runCalls         []int
	closeCalls       int
	shardContextDone bool
}

func (executor *fakeFocusedTailExecutor) Acquire(context.Context, focusedTailRequest, focusedTailRunnerConfig, focusedTailCell) error {
	executor.acquireCalls++
	return executor.acquireErr
}

func (executor *fakeFocusedTailExecutor) Prepare(context.Context, focusedTailRequest, focusedTailRunnerConfig, focusedTailCell) (focusedTailPrepared, error) {
	executor.prepareCalls++
	return executor.prepared, nil
}

func (executor *fakeFocusedTailExecutor) RecoverShard(_ context.Context, _ focusedTailRequest, _ focusedTailRunnerConfig, _ focusedTailCell, _ focusedTailPrepared, shard int) (focusedTailShardResult, error) {
	executor.recoverCalls = append(executor.recoverCalls, shard)
	return focusedTailShardResult{Receipt: executor.recovered[shard]}, nil
}

func (executor *fakeFocusedTailExecutor) Preflight(_ context.Context, _ focusedTailRequest, _ focusedTailRunnerConfig, _ focusedTailCell, _ focusedTailPrepared, shard int) error {
	executor.preflightCalls = append(executor.preflightCalls, shard)
	errorsForShard := executor.preflightErrors[shard]
	if len(errorsForShard) == 0 {
		return nil
	}
	err := errorsForShard[0]
	executor.preflightErrors[shard] = errorsForShard[1:]
	return err
}

func (executor *fakeFocusedTailExecutor) RunShard(ctx context.Context, request focusedTailRequest, _ focusedTailRunnerConfig, _ focusedTailCell, prepared focusedTailPrepared, shard int) (focusedTailShardResult, error) {
	executor.runCalls = append(executor.runCalls, shard)
	if executor.blockShard == shard {
		<-ctx.Done()
		executor.shardContextDone = true
		return focusedTailShardResult{}, ctx.Err()
	}
	results := executor.shardResults[shard]
	if len(results) != 0 {
		result := results[0]
		executor.shardResults[shard] = results[1:]
		return result, nil
	}
	receipt := validFocusedTailReceipt(request, prepared, shard)
	return focusedTailShardResult{Receipt: &receipt}, nil
}

func (executor *fakeFocusedTailExecutor) Close(context.Context) error {
	executor.closeCalls++
	return nil
}

func TestFocusedTailResumesExactReceiptsWithoutRerunningGreenShards(t *testing.T) {
	request, prepared := newFocusedTailTestRequest(t, 3, 0)
	executor := newFakeFocusedTailExecutor(prepared)
	for shard := 3; shard <= focusedTailShardCount; shard++ {
		receipt := validFocusedTailReceipt(request, prepared, shard)
		executor.recovered[shard] = &receipt
	}
	if err := runFocusedTail(context.Background(), request, io.Discard, executor); err != nil {
		t.Fatal(err)
	}
	if len(executor.runCalls) != 0 {
		t.Fatalf("run calls = %v, want no replay of GREEN shards", executor.runCalls)
	}
	if executor.closeCalls != 1 {
		t.Fatalf("close calls = %d, want 1", executor.closeCalls)
	}

	second := newFakeFocusedTailExecutor(prepared)
	if err := runFocusedTail(context.Background(), request, io.Discard, second); err != nil {
		t.Fatal(err)
	}
	if len(second.recoverCalls) != 0 || len(second.runCalls) != 0 {
		t.Fatalf("second invocation recovered %v and ran %v, want local receipt-only resume", second.recoverCalls, second.runCalls)
	}
	state := loadFocusedTailTestState(t, request.StatePath)
	if state.Status != "complete" || state.NextShard != focusedTailShardCount+1 {
		t.Fatalf("state = %+v, want complete", state)
	}
}

func TestFocusedTailCLIRequiresExplicitResumableInputs(t *testing.T) {
	for _, args := range [][]string{
		{"focused-tail"},
		{"focused-tail", "-repo", "/workspace/flowersec", "-sha", strings.Repeat("1", 40), "-cell", "clean-08"},
		{"focused-tail", "-repo", "/workspace/flowersec", "-sha", strings.Repeat("1", 40), "-cell", "clean-08", "-state", "/state.json", "-receipt-dir", "/receipts", "-runner-config", "/runner.json", "unexpected"},
	} {
		err := runContext(context.Background(), args, io.Discard)
		if err == nil || !strings.Contains(err.Error(), "focused-tail requires") {
			t.Fatalf("runContext(%q) error = %v, want explicit-input failure", args, err)
		}
	}
}

func TestFocusedTailCheckedInEntryPointStaysOutsideAutomaticGates(t *testing.T) {
	makefileData, err := os.ReadFile(filepath.Join("..", "..", "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	makefile := string(makefileData)
	recipeStart := strings.Index(makefile, "\ntransportcheck-focused-tail:\n")
	if recipeStart < 0 {
		t.Fatal("Makefile is missing transportcheck-focused-tail")
	}
	recipe := makefile[recipeStart:]
	if next := strings.Index(recipe[1:], "\n\n"); next >= 0 {
		recipe = recipe[:next+1]
	}
	for _, flag := range []string{"-sha", "-cell", "-start-shard", "-state", "-receipt-dir", "-runner-config"} {
		if !strings.Contains(recipe, flag) {
			t.Fatalf("focused-tail Make recipe is missing %s", flag)
		}
	}
	for _, automatic := range []string{"precommit:", "check:"} {
		line := makefile[strings.Index(makefile, automatic):]
		line = strings.SplitN(line, "\n", 2)[0]
		if strings.Contains(line, "transportcheck-focused-tail") {
			t.Fatalf("%s must not depend on remote focused-tail orchestration", automatic)
		}
	}
	agentsData, err := os.ReadFile(filepath.Join("..", "..", "AGENTS.md"))
	if err != nil {
		t.Fatal(err)
	}
	rule := "Remote focused and tail recovery must use the checked-in resumable orchestrator. Inline SSH/LXC pipelines are limited to read-only diagnosis. The orchestrator resumes from exact-SHA receipts, stops on the first failure, and never retries product failures automatically."
	if strings.Count(string(agentsData), rule) != 1 {
		t.Fatal("AGENTS.md must contain exactly the concise remote focused-tail rule")
	}
}

func TestFocusedTailStopsAtFirstProductFailureAndPersistsNoRetry(t *testing.T) {
	request, prepared := newFocusedTailTestRequest(t, 3, 0)
	executor := newFakeFocusedTailExecutor(prepared)
	executor.shardResults[3] = []focusedTailShardResult{{Failure: &focusedTailFailure{
		Classification: "product", WorkloadStarted: true, Message: "browser admission failed",
	}}}
	err := runFocusedTail(context.Background(), request, io.Discard, executor)
	requireFocusedTailExitCode(t, err, 30)
	if len(executor.runCalls) != 1 || executor.runCalls[0] != 3 {
		t.Fatalf("run calls = %v, want only failing shard 3", executor.runCalls)
	}
	state := loadFocusedTailTestState(t, request.StatePath)
	if state.Status != "product_failure" || state.Failure == nil || state.Failure.Message != "browser admission failed" {
		t.Fatalf("state = %+v, want persisted product failure", state)
	}

	second := newFakeFocusedTailExecutor(prepared)
	err = runFocusedTail(context.Background(), request, io.Discard, second)
	requireFocusedTailExitCode(t, err, 30)
	if second.acquireCalls != 0 || len(second.runCalls) != 0 {
		t.Fatalf("persisted product failure acquired %d and ran %v", second.acquireCalls, second.runCalls)
	}
}

func TestFocusedTailBoundsEnvironmentRetriesAcrossProcessRestarts(t *testing.T) {
	request, prepared := newFocusedTailTestRequest(t, 3, 1)
	executor := newFakeFocusedTailExecutor(prepared)
	executor.preflightErrors[3] = []error{errors.New("artifact path is stale"), errors.New("artifact path is still stale")}
	err := runFocusedTail(context.Background(), request, io.Discard, executor)
	requireFocusedTailExitCode(t, err, 20)
	if len(executor.preflightCalls) != 2 || len(executor.runCalls) != 0 {
		t.Fatalf("preflight calls = %v, run calls = %v", executor.preflightCalls, executor.runCalls)
	}
	state := loadFocusedTailTestState(t, request.StatePath)
	if state.Status != "environment_failure" || state.Attempts["3"] != 2 || state.Failure == nil || state.Failure.WorkloadStarted {
		t.Fatalf("state = %+v, want exhausted pre-workload environment failure", state)
	}

	second := newFakeFocusedTailExecutor(prepared)
	err = runFocusedTail(context.Background(), request, io.Discard, second)
	requireFocusedTailExitCode(t, err, 20)
	if len(second.preflightCalls) != 0 || len(second.runCalls) != 0 {
		t.Fatalf("restart preflight calls = %v, run calls = %v, want no extra attempt", second.preflightCalls, second.runCalls)
	}
}

func TestFocusedTailTreatsPostStartTimeoutAsProductAndDrains(t *testing.T) {
	request, prepared := newFocusedTailTestRequest(t, 3, 0)
	executor := newFakeFocusedTailExecutor(prepared)
	executor.blockShard = 3
	savedTimeouts := focusedTailTimeouts
	focusedTailTimeouts.Shard = 20 * time.Millisecond
	defer func() { focusedTailTimeouts = savedTimeouts }()

	err := runFocusedTail(context.Background(), request, io.Discard, executor)
	requireFocusedTailExitCode(t, err, 30)
	if !executor.shardContextDone || executor.closeCalls != 1 {
		t.Fatalf("context drained = %v, close calls = %d", executor.shardContextDone, executor.closeCalls)
	}
}

func TestFocusedTailInterruptedStateRequiresReceiptOrStops(t *testing.T) {
	t.Run("receipt recovers", func(t *testing.T) {
		request, prepared := newFocusedTailTestRequest(t, 3, 0)
		persistRunningFocusedTailTestState(t, request)
		executor := newFakeFocusedTailExecutor(prepared)
		for shard := 3; shard <= focusedTailShardCount; shard++ {
			receipt := validFocusedTailReceipt(request, prepared, shard)
			executor.recovered[shard] = &receipt
		}
		if err := runFocusedTail(context.Background(), request, io.Discard, executor); err != nil {
			t.Fatal(err)
		}
		if len(executor.runCalls) != 0 {
			t.Fatalf("run calls = %v, want receipt recovery", executor.runCalls)
		}
	})

	t.Run("unknown outcome stops", func(t *testing.T) {
		request, prepared := newFocusedTailTestRequest(t, 3, 0)
		persistRunningFocusedTailTestState(t, request)
		executor := newFakeFocusedTailExecutor(prepared)
		err := runFocusedTail(context.Background(), request, io.Discard, executor)
		requireFocusedTailExitCode(t, err, 30)
		if len(executor.runCalls) != 0 {
			t.Fatalf("run calls = %v, want no replay after unknown interruption", executor.runCalls)
		}
	})
}

func TestFocusedTailRejectsSHAAndDigestDrift(t *testing.T) {
	request, prepared := newFocusedTailTestRequest(t, 3, 0)
	wrongSHA := request
	wrongSHA.SHA = strings.Repeat("f", 40)
	executor := newFakeFocusedTailExecutor(prepared)
	err := runFocusedTail(context.Background(), wrongSHA, io.Discard, executor)
	requireFocusedTailExitCode(t, err, 10)
	if executor.acquireCalls != 0 {
		t.Fatal("SHA drift reached the remote executor")
	}

	receipt := validFocusedTailReceipt(request, prepared, 3)
	receipt.RunnerSHA256 = strings.Repeat("9", 64)
	executor = newFakeFocusedTailExecutor(prepared)
	executor.recovered[3] = &receipt
	err = runFocusedTail(context.Background(), request, io.Discard, executor)
	requireFocusedTailExitCode(t, err, 10)
	if len(executor.runCalls) != 0 {
		t.Fatalf("digest drift ran shards %v", executor.runCalls)
	}
}

func TestFocusedTailRejectsDirtyCheckoutBeforeRemoteMutation(t *testing.T) {
	request, prepared := newFocusedTailTestRequest(t, 3, 0)
	if err := os.WriteFile(filepath.Join(request.RepositoryPath, "dirty.txt"), []byte("dirty\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	executor := newFakeFocusedTailExecutor(prepared)
	err := runFocusedTail(context.Background(), request, io.Discard, executor)
	requireFocusedTailExitCode(t, err, 10)
	if executor.acquireCalls != 0 {
		t.Fatal("dirty checkout reached the remote executor")
	}
}

func TestFocusedTailLocalAndRemoteLocksRejectContention(t *testing.T) {
	t.Run("local", func(t *testing.T) {
		request, prepared := newFocusedTailTestRequest(t, 3, 0)
		lock, err := acquireFocusedTailLock(request.StatePath + ".lock")
		if err != nil {
			t.Fatal(err)
		}
		defer lock.Close()
		executor := newFakeFocusedTailExecutor(prepared)
		err = runFocusedTail(context.Background(), request, io.Discard, executor)
		requireFocusedTailExitCode(t, err, 20)
		if executor.acquireCalls != 0 {
			t.Fatal("local contention reached remote lock acquisition")
		}
	})

	t.Run("remote", func(t *testing.T) {
		request, prepared := newFocusedTailTestRequest(t, 3, 0)
		executor := newFakeFocusedTailExecutor(prepared)
		executor.acquireErr = errors.New("remote lock busy")
		err := runFocusedTail(context.Background(), request, io.Discard, executor)
		requireFocusedTailExitCode(t, err, 20)
		if executor.prepareCalls != 0 {
			t.Fatal("remote contention reached deployment")
		}
	})
}

func TestFocusedTailSSHExecutorHoldsRemoteLockUntilClose(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("FOCUSED_TAIL_TEST_ROOT", root)
	ssh := filepath.Join(root, "ssh")
	scp := filepath.Join(root, "scp")
	writeFocusedTailTestExecutable(t, ssh, `#!/bin/sh
set -eu
while [ "$1" != "--" ]; do shift; done
shift
target=$1
shift
if [ "$1" = "/fake/lxc" ]; then
  shift
  operation=$1
  shift
  if [ "$operation" = "file" ]; then
    shift
    source=$1
    destination=$2
    destination=${destination#runner-01}
    cp "$source" "$destination"
    exit 0
  fi
  container=$1
  shift
  [ "$1" = "--" ]
  shift
fi
case "$1" in
  mkdir) exec "$@" ;;
  chmod) exec "$@" ;;
  sha256sum)
    path=$3
    digest=$(shasum -a 256 "$path" | awk '{print $1}')
    printf '%s  %s\n' "$digest" "$path"
    ;;
  unlink) exec "$@" ;;
  *focused-tail-agent-*)
    action=$2
    [ "$action" = "hold-lock" ]
    IFS= read -r request
    [ -n "$request" ]
    lock=$FOCUSED_TAIL_TEST_ROOT/remote-lock
    if ! mkdir "$lock" 2>/dev/null; then
      owner=$(cat "$lock/pid" 2>/dev/null || true)
      if [ -n "$owner" ] && ! kill -0 "$owner" 2>/dev/null; then
        unlink "$lock/pid"
        rmdir "$lock"
        mkdir "$lock"
      else
        printf 'remote lock busy\n' >&2
        exit 20
      fi
    fi
    printf '%s\n' "$$" >"$lock/pid"
    printf '{"status":"LOCKED"}\n'
    exec sleep 86400
    ;;
  *) printf 'unexpected fake SSH command for %s: %s\n' "$target" "$*" >&2; exit 99 ;;
esac
`)
	writeFocusedTailTestExecutable(t, scp, `#!/bin/sh
set -eu
while [ "$1" != "--" ]; do shift; done
shift
source=$1
destination=${2#*:}
cp "$source" "$destination"
`)
	repository, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	repository, err = filepath.EvalSymlinks(repository)
	if err != nil {
		t.Fatal(err)
	}
	config := focusedTailRunnerConfig{
		SSHExecutable: ssh, SCPExecutable: scp, SSHTarget: "runner",
		ContainerExecutable: "/fake/lxc", ContainerName: "runner-01",
		RemoteSourceRoot: "/source", RemoteArtifactRoot: "/artifact", RemoteCacheRoot: "/cache",
		RemoteStagingRoot: filepath.Join(root, "host"), ContainerStagingRoot: filepath.Join(root, "container"),
	}
	request := focusedTailRequest{RepositoryPath: repository, SHA: strings.Repeat("1", 40)}
	cell := focusedTailCell{ID: "clean-08", Profile: "clean-v1", Topology: "browser_webtransport", RunnerTarget: "browser-webtransport-cell"}

	first := &sshFocusedTailExecutor{}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := first.Acquire(ctx, request, config, cell); err != nil {
		t.Fatal(err)
	}
	second := &sshFocusedTailExecutor{}
	if err := second.Acquire(ctx, request, config, cell); err == nil || !strings.Contains(err.Error(), "remote lock") {
		t.Fatalf("second Acquire() error = %v, want remote contention", err)
	}
	if err := first.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if err := second.Acquire(ctx, request, config, cell); err != nil {
		t.Fatalf("Acquire() after Close: %v", err)
	}
	if err := second.Close(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestFocusedTailRejectsShellSpecialCharactersInCommandConfig(t *testing.T) {
	valid := focusedTailRunnerConfig{
		SchemaVersion: 1, SSHExecutable: "/usr/bin/ssh", SCPExecutable: "/usr/bin/scp",
		SSHOptions: []string{"-oBatchMode=yes"}, SSHTarget: "runner@example.invalid",
		ContainerExecutable: "/usr/bin/lxc", ContainerName: "runner-01",
		RemoteSourceRoot: "/workspace/flowersec", RemoteArtifactRoot: "/var/lib/flowersec/artifacts",
		RemoteCacheRoot: "/var/lib/flowersec/cache", RemoteStagingRoot: "/var/lib/flowersec/staging",
		ContainerStagingRoot: "/var/lib/flowersec/staging", EnvironmentRetries: 1,
	}
	if err := validateFocusedTailRunnerConfig(valid); err != nil {
		t.Fatal(err)
	}
	mutations := []func(*focusedTailRunnerConfig){
		func(config *focusedTailRunnerConfig) { config.SSHTarget = "runner;touch-pwned" },
		func(config *focusedTailRunnerConfig) { config.ContainerName = "runner$(id)" },
		func(config *focusedTailRunnerConfig) {
			config.RemoteArtifactRoot = "/var/lib/flowersec/artifacts with spaces"
		},
		func(config *focusedTailRunnerConfig) { config.SSHOptions = []string{"-oProxyCommand=$(touch pwned)"} },
		func(config *focusedTailRunnerConfig) {
			config.SSHOptions = []string{"-oBatchMode=yes\nProxyCommand=bad"}
		},
	}
	for index, mutate := range mutations {
		config := valid
		mutate(&config)
		if err := validateFocusedTailRunnerConfig(config); err == nil {
			t.Fatalf("mutation %d accepted shell-special command input", index)
		}
	}
}

func TestFocusedTailRemoteAgentVerifiesSuccessfulScratchBeforeDeletion(t *testing.T) {
	scriptPath := filepath.Join("..", "..", "scripts", "transport-v2-focused-tail-remote.sh")
	data, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	required := []string{
		`actual_closure=$(sha256sum "$output_root/SHA256SUMS"`,
		`sha256sum -c SHA256SUMS`,
		`actual_stream=$(tar -C "$artifact_root" -cf -`,
		`[[ $actual_stream == "$expected_stream" ]] || fail "successful scratch content-stream digest mismatch; refusing deletion"`,
		`find "$output_root" -depth -delete`,
	}
	last := -1
	for _, fragment := range required {
		position := strings.Index(script, fragment)
		if position <= last {
			t.Fatalf("remote agent fragment %q is missing or out of order", fragment)
		}
		last = position
	}
	if strings.Index(script, `classification:"environment",workload_started:false`) > strings.Index(script, `timeout --signal=INT`) {
		t.Fatal("pre-workload environment classification must precede workload execution")
	}
}

func TestFocusedTailBundleIsExactAndDigestDetectsMutation(t *testing.T) {
	request, _ := newFocusedTailTestRequest(t, 3, 0)
	bundle := filepath.Join(t.TempDir(), "exact.bundle")
	if err := createFocusedTailBundle(context.Background(), request.RepositoryPath, bundle); err != nil {
		t.Fatal(err)
	}
	command := gitTestOutput(t, request.RepositoryPath, "bundle", "list-heads", bundle)
	if !strings.Contains(command, request.SHA) {
		t.Fatalf("bundle heads = %q, want exact SHA %s", command, request.SHA)
	}
	before, err := focusedTailBundleSHA256(bundle)
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(bundle, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("drift"); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	after, err := focusedTailBundleSHA256(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if before == after {
		t.Fatal("bundle digest did not detect mutation")
	}
}

func newFakeFocusedTailExecutor(prepared focusedTailPrepared) *fakeFocusedTailExecutor {
	return &fakeFocusedTailExecutor{
		prepared: prepared, recovered: make(map[int]*focusedTailReceipt),
		preflightErrors: make(map[int][]error), shardResults: make(map[int][]focusedTailShardResult),
	}
}

func newFocusedTailTestRequest(t *testing.T, startShard, environmentRetries int) (focusedTailRequest, focusedTailPrepared) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	repository := filepath.Join(root, "repository")
	manifestDirectory := filepath.Join(repository, "testdata", "transport_v2")
	if err := os.MkdirAll(manifestDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	manifest, err := os.ReadFile(fixturePath(t, "performance_manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(manifestDirectory, "performance_manifest.json"), manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	runGitTestCommand(t, repository, "init", "-q")
	runGitTestCommand(t, repository, "add", ".")
	runGitTestCommand(t, repository, "-c", "user.name=Focused Tail", "-c", "user.email=focused@example.invalid", "commit", "-qm", "fixture")
	sha := gitTestOutput(t, repository, "rev-parse", "HEAD")
	config := focusedTailRunnerConfig{
		SchemaVersion: 1, SSHExecutable: "/usr/bin/ssh", SCPExecutable: "/usr/bin/scp",
		SSHOptions: []string{"-oBatchMode=yes"}, SSHTarget: "runner@example.invalid",
		ContainerExecutable: "/usr/bin/lxc", ContainerName: "runner-01",
		RemoteSourceRoot: "/workspace/flowersec", RemoteArtifactRoot: "/var/lib/flowersec/artifacts",
		RemoteCacheRoot: "/var/lib/flowersec/cache", RemoteStagingRoot: "/var/lib/flowersec/staging",
		ContainerStagingRoot: "/var/lib/flowersec/staging", EnvironmentRetries: environmentRetries,
	}
	configData, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(root, "focused-tail-runner.json")
	if err := os.WriteFile(configPath, configData, 0o600); err != nil {
		t.Fatal(err)
	}
	request := focusedTailRequest{
		RepositoryPath: repository, SHA: sha, CellID: "clean-08", StartShard: startShard,
		StatePath: filepath.Join(root, "state.json"), ReceiptDirectory: filepath.Join(root, "receipts"), RunnerConfigPath: configPath,
	}
	prepared := focusedTailPrepared{
		SourceSHA: sha, RunnerPath: "/var/lib/flowersec/cache/runner", RunnerSHA256: strings.Repeat("1", 64),
		ToolchainSHA256: strings.Repeat("2", 64), DistSHA256: strings.Repeat("3", 64),
	}
	return request, prepared
}

func validFocusedTailReceipt(request focusedTailRequest, prepared focusedTailPrepared, shard int) focusedTailReceipt {
	return focusedTailReceipt{
		Schema: focusedTailReceiptSchema, SourceSHA: request.SHA, CellID: request.CellID, Shard: shard, ShardCount: focusedTailShardCount,
		Result: "GREEN", RunnerSHA256: prepared.RunnerSHA256, ToolchainSHA256: prepared.ToolchainSHA256, DistSHA256: prepared.DistSHA256,
		ReportSHA256: strings.Repeat("4", 64), ClosureSHA256: strings.Repeat("5", 64), DeletedStreamSHA256: strings.Repeat("6", 64),
		StartedAt: "2026-08-03T10:00:00Z", FinishedAt: "2026-08-03T10:04:00Z", Summary: "three frozen runs passed",
	}
}

func persistRunningFocusedTailTestState(t *testing.T, request focusedTailRequest) {
	t.Helper()
	state := focusedTailState{
		SchemaVersion: focusedTailSchemaVersion, SourceSHA: request.SHA, CellID: request.CellID,
		StartShard: request.StartShard, NextShard: request.StartShard, Status: "running", Attempts: make(map[string]int),
	}
	if err := persistFocusedTailState(request.StatePath, state); err != nil {
		t.Fatal(err)
	}
}

func loadFocusedTailTestState(t *testing.T, path string) focusedTailState {
	t.Helper()
	var state focusedTailState
	if err := decodeStrictFile(path, &state); err != nil {
		t.Fatal(err)
	}
	return state
}

func requireFocusedTailExitCode(t *testing.T, err error, code int) {
	t.Helper()
	if err == nil {
		t.Fatalf("error = nil, want exit code %d", code)
	}
	var coded interface{ ExitCode() int }
	if !errors.As(err, &coded) || coded.ExitCode() != code {
		t.Fatalf("error = %v, exit code = %v, want %d", err, coded, code)
	}
}

func writeFocusedTailTestExecutable(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o700); err != nil {
		t.Fatal(err)
	}
}
