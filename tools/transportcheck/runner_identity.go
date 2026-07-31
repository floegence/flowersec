package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
)

const lowLevelRunnerPackage = "./internal/cmd/transport-release-runner"

type goListPackage struct {
	Dir          string
	GoFiles      []string
	CgoFiles     []string
	CFiles       []string
	CXXFiles     []string
	MFiles       []string
	HFiles       []string
	FFiles       []string
	SFiles       []string
	SwigFiles    []string
	SwigCXXFiles []string
	SysoFiles    []string
	EmbedFiles   []string
	Module       *struct {
		Main bool
		Dir  string
	}
}

type boundedOutputBuffer struct {
	data  []byte
	limit int
}

func newBoundedOutputBuffer(limit int) boundedOutputBuffer {
	return boundedOutputBuffer{limit: limit}
}

func (buffer *boundedOutputBuffer) Write(data []byte) (int, error) {
	written := len(data)
	if remaining := buffer.limit - len(buffer.data); remaining > 0 {
		buffer.data = append(buffer.data, data[:min(remaining, len(data))]...)
	}
	return written, nil
}

func (buffer *boundedOutputBuffer) String() string {
	return string(buffer.data)
}

func runnerSourceSHA256(repository string) (string, error) {
	return runnerSourceSHA256ForPlatform(repository, "linux", runtime.GOARCH)
}

func runnerSourceSHA256ForPlatform(repository, goos, goarch string) (string, error) {
	if !supportedCollectPlatform(goos, goarch) {
		return "", fmt.Errorf("unsupported runner source platform %s/%s", goos, goarch)
	}
	moduleRoot := filepath.Join(repository, "flowersec-go")
	command := exec.Command("go", "list", "-deps", "-json", lowLevelRunnerPackage)
	command.Dir = moduleRoot
	command.Env = runnerGoEnvironment(goos, goarch)
	stdout, err := command.StdoutPipe()
	if err != nil {
		return "", err
	}
	stderr := newBoundedOutputBuffer(1 << 20)
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		return "", err
	}
	decoder := json.NewDecoder(bufio.NewReader(stdout))
	paths := map[string]struct{}{
		filepath.Join(moduleRoot, "go.mod"): {},
		filepath.Join(moduleRoot, "go.sum"): {},
	}
	for {
		var pkg goListPackage
		err := decoder.Decode(&pkg)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			_ = command.Process.Kill()
			waitErr := command.Wait()
			return "", fmt.Errorf("decode runner dependency graph: %w: %s", errors.Join(err, waitErr), strings.TrimSpace(stderr.String()))
		}
		if pkg.Module == nil || !pkg.Module.Main || filepath.Clean(pkg.Module.Dir) != moduleRoot {
			continue
		}
		groups := [][]string{pkg.GoFiles, pkg.CgoFiles, pkg.CFiles, pkg.CXXFiles, pkg.MFiles, pkg.HFiles, pkg.FFiles, pkg.SFiles, pkg.SwigFiles, pkg.SwigCXXFiles, pkg.SysoFiles, pkg.EmbedFiles}
		for _, group := range groups {
			for _, name := range group {
				paths[filepath.Join(pkg.Dir, name)] = struct{}{}
			}
		}
	}
	waitErr := command.Wait()
	if waitErr != nil {
		return "", fmt.Errorf("enumerate runner dependency graph: %w: %s", waitErr, strings.TrimSpace(stderr.String()))
	}
	relativePaths := make([]string, 0, len(paths))
	pathByRelative := make(map[string]string, len(paths))
	for path := range paths {
		clean := filepath.Clean(path)
		relative, err := filepath.Rel(repository, clean)
		if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return "", errors.New("runner dependency source escapes the repository")
		}
		info, err := os.Lstat(clean)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return "", fmt.Errorf("runner dependency source %s is not a regular non-symlink file", filepath.ToSlash(relative))
		}
		resolved, err := filepath.EvalSymlinks(clean)
		if err != nil || resolved != clean {
			return "", fmt.Errorf("runner dependency source %s changes through symlink resolution", filepath.ToSlash(relative))
		}
		relative = filepath.ToSlash(relative)
		relativePaths = append(relativePaths, relative)
		pathByRelative[relative] = clean
	}
	sort.Strings(relativePaths)
	digest := sha256.New()
	for _, relative := range relativePaths {
		data, err := os.ReadFile(pathByRelative[relative])
		if err != nil {
			return "", err
		}
		writeDigestFrame(digest, []byte(relative))
		writeDigestFrame(digest, data)
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func runnerGoEnvironment(goos, goarch string) []string {
	environment := slices.DeleteFunc(os.Environ(), func(value string) bool {
		name, _, _ := strings.Cut(value, "=")
		return strings.HasPrefix(name, "GIT_") || name == "GOOS" || name == "GOARCH" || name == "CGO_ENABLED"
	})
	return append(environment, "GOOS="+goos, "GOARCH="+goarch, "CGO_ENABLED=0")
}

func verifyDeterministicRunnerExecutable(repository, executable string, race bool) error {
	directory, err := os.MkdirTemp("", "flowersec-runner-rebuild-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(directory)
	rebuilt := filepath.Join(directory, "transport-release-runner")
	arguments := []string{"build", "-trimpath", "-buildvcs=false"}
	if race {
		arguments = append(arguments, "-race")
	}
	arguments = append(arguments, "-o", rebuilt, lowLevelRunnerPackage)
	command := exec.Command("go", arguments...)
	command.Dir = filepath.Join(repository, "flowersec-go")
	command.Env = runnerGoEnvironment(runtime.GOOS, runtime.GOARCH)
	if output, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("rebuild deterministic low-level runner: %w: %s", err, strings.TrimSpace(string(output)))
	}
	_, rebuiltDigest, err := snapshotRegularFile(rebuilt, true)
	if err != nil {
		return err
	}
	_, providedDigest, err := snapshotRegularFile(executable, true)
	if err != nil {
		return err
	}
	if rebuiltDigest != providedDigest {
		return fmt.Errorf("low-level runner bytes differ from deterministic rebuild (race=%t)", race)
	}
	return nil
}

type canonicalArgvRecord struct {
	Scope      string   `json:"scope"`
	JobID      string   `json:"job_id,omitempty"`
	Executable string   `json:"executable"`
	Args       []string `json:"args"`
}

func canonicalAllTargetArgvSHA256(manifest *PerformanceManifest, registry *CaseRegistry) (string, error) {
	records, err := canonicalAllTargetArgvRecords(manifest, registry)
	if err != nil {
		return "", err
	}
	encoded, err := json.Marshal(records)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func validateRunnerRepositoryIdentity(repository string, manifest *PerformanceManifest, registry *CaseRegistry, runner EvidenceRunner) error {
	sourceDigest, err := runnerSourceSHA256ForPlatform(repository, runner.OS, runner.Architecture)
	if err != nil {
		return fmt.Errorf("recompute runner source identity: %w", err)
	}
	argvDigest, err := canonicalAllTargetArgvSHA256(manifest, registry)
	if err != nil {
		return fmt.Errorf("recompute canonical runner argv identity: %w", err)
	}
	if runner.SourceSHA256 != sourceDigest || runner.ArgvSHA256 != argvDigest {
		return errors.New("signed runner source or argv identity does not match the audited repository")
	}
	return nil
}

func canonicalAllTargetArgvRecords(manifest *PerformanceManifest, registry *CaseRegistry) ([]canonicalArgvRecord, error) {
	plan, err := buildCollectionPlan("all", manifest, registry)
	if err != nil {
		return nil, err
	}
	if len(plan.Missing) != 0 {
		return nil, fmt.Errorf("canonical all-target argv requires complete producers: %s", strings.Join(plan.Missing, "; "))
	}
	jobs := append([]collectionJob(nil), plan.Jobs...)
	sort.Slice(jobs, func(i, j int) bool { return jobs[i].ID < jobs[j].ID })
	records := []canonicalArgvRecord{{Scope: "top-level", Executable: "$RUNNER_WRAPPER", Args: []string{"all"}}}
	for _, job := range jobs {
		root, sourceSHA, manifestPath, executable := "$FINAL_ROOT", "$FINAL_SHA", "$FINAL_ROOT/testdata/transport_v2/performance_manifest.json", "$FINAL_RUNNER"
		if job.SourceRevision == collectionRevisionBase {
			root, sourceSHA, manifestPath, executable = "$BASE_ROOT", "$BASE_SHA", "$BASE_ROOT/testdata/transport_v2/performance_manifest.json", "$BASE_RUNNER"
		}
		if job.CaseMode == "race" {
			executable = "$RACE_RUNNER"
		}
		output := "$OUTPUT/jobs/" + job.ID
		commands := collectionJobCommands(job, manifestPath, output, sourceSHA, root, "$BUILD_DIR/packet_fault.o")
		for _, command := range commands {
			scope := "low-level"
			jobID := job.ID
			if len(commands) > 1 {
				scope = "low-level-shard"
				if !command.Workload {
					scope = "low-level-merge"
				}
				jobID += "/" + command.ID
			}
			records = append(records, canonicalArgvRecord{Scope: scope, JobID: jobID, Executable: executable, Args: command.Args})
		}
	}
	return records, nil
}

func writeDigestFrame(destination hash.Hash, value []byte) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	_, _ = destination.Write(length[:])
	_, _ = destination.Write(value)
}
