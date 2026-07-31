package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

func generateRunnerLocalConfig(repositoryPath, outputPath string) (RunnerLocalConfig, error) {
	var config RunnerLocalConfig
	if !supportedCollectPlatform(runtime.GOOS, runtime.GOARCH) {
		return config, fmt.Errorf("runner config generation requires supported native Linux, got %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	repository, err := canonicalDirectory(repositoryPath, true)
	if err != nil {
		return config, fmt.Errorf("runner config repository: %w", err)
	}
	top, err := collectGitOutput(repository, "rev-parse", "--show-toplevel")
	if err != nil || top != repository {
		return config, errors.New("runner config repository must be its canonical Git root")
	}
	status, err := collectGitOutput(repository, "status", "--porcelain", "--untracked-files=all")
	if err != nil || status != "" {
		return config, errors.New("runner config repository must be clean with no untracked files")
	}
	if err := validateRunnerConfigOutputPath(repository, outputPath); err != nil {
		return config, err
	}

	manifest, err := loadPerformanceManifest(filepath.Join(repository, "testdata", "transport_v2", "performance_manifest.json"))
	if err != nil {
		return config, err
	}
	if err := validateManifest(manifest); err != nil {
		return config, err
	}
	registry, err := loadCaseRegistry(filepath.Join(repository, "testdata", "transport_v2", "case_registry.json"))
	if err != nil {
		return config, err
	}
	if err := validateCaseRegistry(registry); err != nil {
		return config, err
	}
	policy, err := loadEvidenceTrustPolicy(filepath.Join(repository, "testdata", "transport_v2", "evidence_trust_policy.json"))
	if err != nil {
		return config, err
	}

	executableDigest, err := deterministicRunnerExecutableSHA256(repository)
	if err != nil {
		return config, err
	}
	sourceDigest, err := runnerSourceSHA256(repository)
	if err != nil {
		return config, fmt.Errorf("runner source identity: %w", err)
	}
	argvDigest, err := canonicalAllTargetArgvSHA256(manifest, registry)
	if err != nil {
		return config, fmt.Errorf("canonical runner argv identity: %w", err)
	}
	kernel, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return config, fmt.Errorf("read actual kernel release: %w", err)
	}
	config = RunnerLocalConfig{
		SchemaVersion: 1, RunnerID: policy.Runner.ID, OS: runtime.GOOS, Architecture: runtime.GOARCH,
		KernelRelease: strings.TrimSpace(string(kernel)), ExecutableSHA256: executableDigest,
		SourceSHA256: sourceDigest, ArgvSHA256: argvDigest,
	}
	if err := validateRunnerLocalConfig(config, policy); err != nil {
		return RunnerLocalConfig{}, err
	}
	if err := writeRunnerLocalConfig(outputPath, config); err != nil {
		return RunnerLocalConfig{}, err
	}
	return config, nil
}

func deterministicRunnerExecutableSHA256(repository string) (string, error) {
	directory, err := os.MkdirTemp("", "flowersec-runner-config-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(directory)
	executable := filepath.Join(directory, "transport-release-runner")
	command := exec.Command("go", "build", "-trimpath", "-buildvcs=false", "-o", executable, lowLevelRunnerPackage)
	command.Dir = filepath.Join(repository, "flowersec-go")
	command.Env = runnerGoEnvironment(runtime.GOOS, runtime.GOARCH)
	if output, err := command.CombinedOutput(); err != nil {
		return "", fmt.Errorf("build deterministic low-level runner: %w: %s", err, strings.TrimSpace(string(output)))
	}
	_, digest, err := snapshotRegularFile(executable, true)
	return digest, err
}

func validateRunnerConfigOutputPath(repository, path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("runner config output path must be absolute and canonical")
	}
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
			return errors.New("existing runner config output must be a private regular non-symlink file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	relative, err := filepath.Rel(repository, path)
	if err != nil {
		return err
	}
	if relative == ".flowersec/transport-runner.json" {
		parent := filepath.Dir(path)
		if err := os.Mkdir(parent, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
	}
	if relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		relative = filepath.ToSlash(relative)
		tracked, err := collectGitOutput(repository, "ls-files", "--", relative)
		if err != nil || tracked != "" {
			return errors.New("runner config output inside the checkout must not be tracked")
		}
		if _, err := collectGitOutput(repository, "check-ignore", "-q", "--", relative); err != nil {
			return errors.New("runner config output inside the checkout must be git-ignored")
		}
	}
	parent, err := canonicalDirectory(filepath.Dir(path), true)
	if err != nil || parent != filepath.Dir(path) {
		return errors.New("runner config output parent must be an existing canonical non-symlink directory")
	}
	return nil
}

func writeRunnerLocalConfig(path string, config RunnerLocalConfig) error {
	encoded, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	parent := filepath.Dir(path)
	temporary, err := os.CreateTemp(parent, ".transport-runner-*.json")
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
	return os.Rename(temporaryPath, path)
}
