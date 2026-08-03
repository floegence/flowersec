package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

type sshFocusedTailExecutor struct {
	mu                   sync.Mutex
	lockCancel           context.CancelFunc
	lockDone             chan error
	lockError            error
	lockConfig           focusedTailRunnerConfig
	stagedAgentHost      string
	stagedAgentContainer string
	stagedAgentSHA256    string
}

type focusedTailAgentRequest struct {
	SchemaVersion int                 `json:"schema_version"`
	SourceSHA     string              `json:"source_sha"`
	Cell          focusedTailCell     `json:"cell"`
	Shard         int                 `json:"shard"`
	SourceRoot    string              `json:"source_root"`
	ArtifactRoot  string              `json:"artifact_root"`
	CacheRoot     string              `json:"cache_root"`
	Prepared      focusedTailPrepared `json:"prepared,omitempty"`
}

func newSSHFocusedTailExecutor() focusedTailExecutor { return &sshFocusedTailExecutor{} }

func (executor *sshFocusedTailExecutor) Acquire(ctx context.Context, request focusedTailRequest, config focusedTailRunnerConfig, cell focusedTailCell) (returnErr error) {
	executor.mu.Lock()
	if executor.lockCancel != nil || executor.lockDone != nil {
		executor.mu.Unlock()
		return errors.New("focused-tail remote lock is already active")
	}
	executor.mu.Unlock()

	agentSource := filepath.Join(request.RepositoryPath, "scripts", "transport-v2-focused-tail-remote.sh")
	agentDigest, err := focusedTailBundleSHA256(agentSource)
	if err != nil {
		return fmt.Errorf("digest focused-tail remote agent: %w", err)
	}
	nonce := make([]byte, 8)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("create focused-tail staging nonce: %w", err)
	}
	agentName := "focused-tail-agent-" + agentDigest + "-" + hex.EncodeToString(nonce) + ".sh"
	hostAgent := filepath.ToSlash(filepath.Join(config.RemoteStagingRoot, agentName))
	containerAgent := filepath.ToSlash(filepath.Join(config.ContainerStagingRoot, agentName))
	acquired := false
	defer func() {
		if acquired {
			return
		}
		cleanupContext, cancel := context.WithTimeout(context.Background(), focusedTailTimeouts.Cleanup)
		defer cancel()
		returnErr = errors.Join(returnErr,
			removeVerifiedFocusedTailRemoteFile(cleanupContext, config, true, containerAgent, agentDigest),
			removeVerifiedFocusedTailRemoteFile(cleanupContext, config, false, hostAgent, agentDigest),
		)
	}()
	if err := stageFocusedTailFile(ctx, config, agentSource, hostAgent, containerAgent, agentDigest); err != nil {
		return fmt.Errorf("stage focused-tail remote agent: %w", err)
	}

	agentRequest := newFocusedTailAgentRequest(request, config, cell, focusedTailPrepared{}, 0)
	data, err := json.Marshal(agentRequest)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	keeperContext, keeperCancel := context.WithCancel(context.Background())
	arguments := append([]string(nil), config.SSHOptions...)
	arguments = append(arguments, "--", config.SSHTarget, config.ContainerExecutable, "exec", config.ContainerName, "--", containerAgent, "hold-lock")
	command := exec.CommandContext(keeperContext, config.SSHExecutable, arguments...)
	command.Stdin = bytes.NewReader(data)
	stdout, err := command.StdoutPipe()
	if err != nil {
		keeperCancel()
		return err
	}
	stderr := newBoundedOutputBuffer(1 << 20)
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		keeperCancel()
		return err
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	ready := make(chan []byte, 1)
	go func() {
		line, _ := bufio.NewReader(io.LimitReader(stdout, 64<<10)).ReadBytes('\n')
		ready <- line
	}()
	select {
	case <-ctx.Done():
		keeperCancel()
		<-done
		return fmt.Errorf("acquire focused-tail remote lock: %w", ctx.Err())
	case err := <-done:
		keeperCancel()
		return fmt.Errorf("focused-tail remote lock keeper exited before readiness: %w: %s", err, strings.TrimSpace(stderr.String()))
	case line := <-ready:
		var response struct {
			Status string `json:"status"`
		}
		if err := decodeStrictJSON(line, &response); err != nil || response.Status != "LOCKED" {
			keeperCancel()
			<-done
			return errors.New("focused-tail remote lock keeper returned an invalid readiness response")
		}
	}

	executor.mu.Lock()
	executor.lockCancel = keeperCancel
	executor.lockDone = done
	executor.lockConfig = config
	executor.stagedAgentHost = hostAgent
	executor.stagedAgentContainer = containerAgent
	executor.stagedAgentSHA256 = agentDigest
	executor.mu.Unlock()
	acquired = true
	return nil
}

func (executor *sshFocusedTailExecutor) Close(ctx context.Context) error {
	executor.mu.Lock()
	cancel, done := executor.lockCancel, executor.lockDone
	config := executor.lockConfig
	hostAgent, containerAgent, digest := executor.stagedAgentHost, executor.stagedAgentContainer, executor.stagedAgentSHA256
	executor.lockCancel, executor.lockDone = nil, nil
	executor.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if done != nil {
		select {
		case <-done:
		case <-ctx.Done():
			return fmt.Errorf("drain focused-tail remote lock keeper: %w", ctx.Err())
		}
	}
	var cleanupErr error
	if containerAgent != "" {
		cleanupErr = errors.Join(cleanupErr, removeVerifiedFocusedTailRemoteFile(ctx, config, true, containerAgent, digest))
	}
	if hostAgent != "" {
		cleanupErr = errors.Join(cleanupErr, removeVerifiedFocusedTailRemoteFile(ctx, config, false, hostAgent, digest))
	}
	return errors.Join(executor.lockError, cleanupErr)
}

func (executor *sshFocusedTailExecutor) requireLock() error {
	executor.mu.Lock()
	defer executor.mu.Unlock()
	if executor.lockDone == nil {
		if executor.lockError != nil {
			return executor.lockError
		}
		return errors.New("focused-tail remote lock is not held")
	}
	select {
	case err := <-executor.lockDone:
		executor.lockDone = nil
		executor.lockError = fmt.Errorf("focused-tail remote lock keeper exited unexpectedly: %w", err)
		return executor.lockError
	default:
		return nil
	}
}

func (executor *sshFocusedTailExecutor) Prepare(ctx context.Context, request focusedTailRequest, config focusedTailRunnerConfig, cell focusedTailCell) (focusedTailPrepared, error) {
	if err := executor.requireLock(); err != nil {
		return focusedTailPrepared{}, err
	}
	if err := executor.deployExactSHA(ctx, request, config); err != nil {
		return focusedTailPrepared{}, err
	}
	if err := executor.requireLock(); err != nil {
		return focusedTailPrepared{}, err
	}
	agentRequest := newFocusedTailAgentRequest(request, config, cell, focusedTailPrepared{}, 0)
	var prepared focusedTailPrepared
	if err := executor.runAgent(ctx, config, "prepare", agentRequest, &prepared); err != nil {
		return focusedTailPrepared{}, err
	}
	if err := executor.requireLock(); err != nil {
		return focusedTailPrepared{}, err
	}
	return prepared, nil
}

func (executor *sshFocusedTailExecutor) RecoverShard(ctx context.Context, request focusedTailRequest, config focusedTailRunnerConfig, cell focusedTailCell, prepared focusedTailPrepared, shard int) (focusedTailShardResult, error) {
	if err := executor.requireLock(); err != nil {
		return focusedTailShardResult{}, err
	}
	agentRequest := newFocusedTailAgentRequest(request, config, cell, prepared, shard)
	var result focusedTailShardResult
	if err := executor.runAgent(ctx, config, "recover-receipt", agentRequest, &result); err != nil {
		return focusedTailShardResult{}, err
	}
	if err := executor.requireLock(); err != nil {
		return focusedTailShardResult{}, err
	}
	return result, nil
}

func (executor *sshFocusedTailExecutor) Preflight(ctx context.Context, request focusedTailRequest, config focusedTailRunnerConfig, cell focusedTailCell, prepared focusedTailPrepared, shard int) error {
	if err := executor.requireLock(); err != nil {
		return err
	}
	agentRequest := newFocusedTailAgentRequest(request, config, cell, prepared, shard)
	var response struct {
		Status string `json:"status"`
	}
	if err := executor.runAgent(ctx, config, "preflight", agentRequest, &response); err != nil {
		return err
	}
	if err := executor.requireLock(); err != nil {
		return err
	}
	if response.Status != "GREEN" {
		return errors.New("focused-tail remote preflight did not return GREEN")
	}
	return nil
}

func (executor *sshFocusedTailExecutor) RunShard(ctx context.Context, request focusedTailRequest, config focusedTailRunnerConfig, cell focusedTailCell, prepared focusedTailPrepared, shard int) (focusedTailShardResult, error) {
	if err := executor.requireLock(); err != nil {
		return focusedTailShardResult{}, err
	}
	agentRequest := newFocusedTailAgentRequest(request, config, cell, prepared, shard)
	var result focusedTailShardResult
	if err := executor.runAgent(ctx, config, "run-shard", agentRequest, &result); err != nil {
		return focusedTailShardResult{}, err
	}
	if err := executor.requireLock(); err != nil {
		return focusedTailShardResult{}, err
	}
	return result, nil
}

func newFocusedTailAgentRequest(request focusedTailRequest, config focusedTailRunnerConfig, cell focusedTailCell, prepared focusedTailPrepared, shard int) focusedTailAgentRequest {
	return focusedTailAgentRequest{
		SchemaVersion: focusedTailSchemaVersion, SourceSHA: request.SHA, Cell: cell, Shard: shard,
		SourceRoot: config.RemoteSourceRoot, ArtifactRoot: config.RemoteArtifactRoot, CacheRoot: config.RemoteCacheRoot,
		Prepared: prepared,
	}
}

func (executor *sshFocusedTailExecutor) runAgent(ctx context.Context, config focusedTailRunnerConfig, action string, request focusedTailAgentRequest, response any) error {
	if err := executor.requireLock(); err != nil {
		return err
	}
	executor.mu.Lock()
	agentPath, agentDigest := executor.stagedAgentContainer, executor.stagedAgentSHA256
	executor.mu.Unlock()
	if agentPath == "" || agentDigest == "" {
		return errors.New("focused-tail staged remote agent identity is unavailable")
	}
	if err := verifyFocusedTailRemoteFile(ctx, config, true, agentPath, agentDigest); err != nil {
		return fmt.Errorf("verify focused-tail remote agent before %s: %w", action, err)
	}
	data, err := json.Marshal(request)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	arguments := []string{config.ContainerExecutable, "exec", config.ContainerName, "--", agentPath, action}
	output, err := runFocusedTailSSHCommand(ctx, config, data, arguments...)
	if err != nil {
		return err
	}
	if err := decodeStrictJSON(output, response); err != nil {
		return fmt.Errorf("decode focused-tail remote %s response: %w", action, err)
	}
	return nil
}

func (executor *sshFocusedTailExecutor) deployExactSHA(ctx context.Context, request focusedTailRequest, config focusedTailRunnerConfig) (returnErr error) {
	head, headErr := runFocusedTailSSHCommand(ctx, config, nil, config.ContainerExecutable, "exec", config.ContainerName, "--", "git", "-C", config.RemoteSourceRoot, "rev-parse", "HEAD")
	status, statusErr := runFocusedTailSSHCommand(ctx, config, nil, config.ContainerExecutable, "exec", config.ContainerName, "--", "git", "-C", config.RemoteSourceRoot, "status", "--porcelain=v1", "--untracked-files=all")
	if headErr == nil && statusErr == nil && strings.TrimSpace(string(head)) == request.SHA && strings.TrimSpace(string(status)) == "" {
		return nil
	}
	if statusErr == nil && strings.TrimSpace(string(status)) != "" {
		return errors.New("remote focused-tail checkout is dirty")
	}

	bundleDirectory := filepath.Join(filepath.Dir(request.StatePath), "bundles")
	if err := os.MkdirAll(bundleDirectory, 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(bundleDirectory, ".focused-tail-*.bundle")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	if err := temporary.Close(); err != nil {
		return err
	}
	defer os.Remove(temporaryPath)
	if err := createFocusedTailBundle(ctx, request.RepositoryPath, temporaryPath); err != nil {
		return err
	}
	digest, err := focusedTailBundleSHA256(temporaryPath)
	if err != nil {
		return err
	}
	bundlePath := filepath.Join(bundleDirectory, request.SHA+"-"+digest+".bundle")
	if _, err := os.Lstat(bundlePath); errors.Is(err, os.ErrNotExist) {
		if err := os.Rename(temporaryPath, bundlePath); err != nil {
			return err
		}
	} else if err != nil {
		return err
	} else if info, infoErr := os.Lstat(bundlePath); infoErr != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("cached focused-tail bundle shape is invalid")
	} else if existingDigest, digestErr := focusedTailBundleSHA256(bundlePath); digestErr != nil || existingDigest != digest {
		return errors.New("cached focused-tail bundle digest drifted")
	}

	name := request.SHA + "-" + digest + ".bundle"
	hostBundle := filepath.ToSlash(filepath.Join(config.RemoteStagingRoot, name))
	containerBundle := filepath.ToSlash(filepath.Join(config.ContainerStagingRoot, name))
	if _, err := runFocusedTailSSHCommand(ctx, config, nil, "mkdir", "-p", config.RemoteStagingRoot); err != nil {
		return err
	}
	if _, err := runFocusedTailSSHCommand(ctx, config, nil, config.ContainerExecutable, "exec", config.ContainerName, "--", "mkdir", "-p", config.ContainerStagingRoot); err != nil {
		return err
	}
	defer func() {
		cleanupContext, cancel := context.WithTimeout(context.Background(), focusedTailTimeouts.Cleanup)
		defer cancel()
		cleanupErr := errors.Join(
			removeVerifiedFocusedTailRemoteFile(cleanupContext, config, true, containerBundle, digest),
			removeVerifiedFocusedTailRemoteFile(cleanupContext, config, false, hostBundle, digest),
		)
		if cleanupErr != nil {
			returnErr = errors.Join(returnErr, cleanupErr)
		}
	}()
	if err := runFocusedTailSCPCommand(ctx, config, bundlePath, config.SSHTarget+":"+hostBundle); err != nil {
		return err
	}
	if err := verifyFocusedTailRemoteFile(ctx, config, false, hostBundle, digest); err != nil {
		return err
	}
	containerDestination := config.ContainerName + containerBundle
	if _, err := runFocusedTailSSHCommand(ctx, config, nil, config.ContainerExecutable, "file", "push", hostBundle, containerDestination); err != nil {
		return err
	}
	if err := verifyFocusedTailRemoteFile(ctx, config, true, containerBundle, digest); err != nil {
		return err
	}
	if _, err := runFocusedTailSSHCommand(ctx, config, nil, config.ContainerExecutable, "exec", config.ContainerName, "--", "git", "-C", config.RemoteSourceRoot, "fetch", containerBundle, "HEAD"); err != nil {
		return err
	}
	if _, err := runFocusedTailSSHCommand(ctx, config, nil, config.ContainerExecutable, "exec", config.ContainerName, "--", "git", "-C", config.RemoteSourceRoot, "switch", "--detach", "FETCH_HEAD"); err != nil {
		return err
	}
	head, err = runFocusedTailSSHCommand(ctx, config, nil, config.ContainerExecutable, "exec", config.ContainerName, "--", "git", "-C", config.RemoteSourceRoot, "rev-parse", "HEAD")
	if err != nil || strings.TrimSpace(string(head)) != request.SHA {
		return errors.New("remote focused-tail deployment did not reach the exact SHA")
	}
	status, err = runFocusedTailSSHCommand(ctx, config, nil, config.ContainerExecutable, "exec", config.ContainerName, "--", "git", "-C", config.RemoteSourceRoot, "status", "--porcelain=v1", "--untracked-files=all")
	if err != nil || strings.TrimSpace(string(status)) != "" {
		return errors.New("remote focused-tail deployment is dirty")
	}
	return nil
}

func stageFocusedTailFile(ctx context.Context, config focusedTailRunnerConfig, source, hostPath, containerPath, digest string) error {
	if _, err := runFocusedTailSSHCommand(ctx, config, nil, "mkdir", "-p", config.RemoteStagingRoot); err != nil {
		return err
	}
	if _, err := runFocusedTailSSHCommand(ctx, config, nil, config.ContainerExecutable, "exec", config.ContainerName, "--", "mkdir", "-p", config.ContainerStagingRoot); err != nil {
		return err
	}
	if err := runFocusedTailSCPCommand(ctx, config, source, config.SSHTarget+":"+hostPath); err != nil {
		return err
	}
	if err := verifyFocusedTailRemoteFile(ctx, config, false, hostPath, digest); err != nil {
		return err
	}
	if _, err := runFocusedTailSSHCommand(ctx, config, nil, config.ContainerExecutable, "file", "push", hostPath, config.ContainerName+containerPath); err != nil {
		return err
	}
	if _, err := runFocusedTailSSHCommand(ctx, config, nil, config.ContainerExecutable, "exec", config.ContainerName, "--", "chmod", "0700", containerPath); err != nil {
		return err
	}
	return verifyFocusedTailRemoteFile(ctx, config, true, containerPath, digest)
}

func verifyFocusedTailRemoteFile(ctx context.Context, config focusedTailRunnerConfig, container bool, path, digest string) error {
	arguments := []string{"sha256sum", "--", path}
	if container {
		arguments = append([]string{config.ContainerExecutable, "exec", config.ContainerName, "--"}, arguments...)
	}
	output, err := runFocusedTailSSHCommand(ctx, config, nil, arguments...)
	if err != nil {
		return err
	}
	fields := strings.Fields(string(output))
	if len(fields) != 2 || fields[0] != digest || fields[1] != path {
		return fmt.Errorf("focused-tail staged file digest mismatch for %s", path)
	}
	return nil
}

func removeVerifiedFocusedTailRemoteFile(ctx context.Context, config focusedTailRunnerConfig, container bool, path, digest string) error {
	if path == "" {
		return nil
	}
	if err := verifyFocusedTailRemoteFile(ctx, config, container, path, digest); err != nil {
		return fmt.Errorf("refuse to delete unverified focused-tail file %s: %w", path, err)
	}
	arguments := []string{"unlink", "--", path}
	if container {
		arguments = append([]string{config.ContainerExecutable, "exec", config.ContainerName, "--"}, arguments...)
	}
	_, err := runFocusedTailSSHCommand(ctx, config, nil, arguments...)
	return err
}

func runFocusedTailSSHCommand(ctx context.Context, config focusedTailRunnerConfig, stdin []byte, remoteArguments ...string) ([]byte, error) {
	arguments := append([]string(nil), config.SSHOptions...)
	arguments = append(arguments, "--", config.SSHTarget)
	arguments = append(arguments, remoteArguments...)
	command := exec.CommandContext(ctx, config.SSHExecutable, arguments...)
	if stdin != nil {
		command.Stdin = bytes.NewReader(stdin)
	}
	stdout := newBoundedOutputBuffer(4 << 20)
	stderr := newBoundedOutputBuffer(1 << 20)
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := command.Run(); err != nil {
		return nil, fmt.Errorf("focused-tail SSH command failed: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return []byte(stdout.String()), nil
}

func runFocusedTailSCPCommand(ctx context.Context, config focusedTailRunnerConfig, source, destination string) error {
	arguments := append([]string(nil), config.SSHOptions...)
	arguments = append(arguments, "--", source, destination)
	command := exec.CommandContext(ctx, config.SCPExecutable, arguments...)
	stderr := newBoundedOutputBuffer(1 << 20)
	command.Stdout, command.Stderr = io.Discard, &stderr
	if err := command.Run(); err != nil {
		return fmt.Errorf("focused-tail SCP failed: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}
