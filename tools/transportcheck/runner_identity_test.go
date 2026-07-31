package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestBoundedOutputBufferRetainsOnlyTheDiagnosticLimit(t *testing.T) {
	buffer := newBoundedOutputBuffer(4)
	input := []byte("abcdef")
	written, err := buffer.Write(input)
	if err != nil || written != len(input) {
		t.Fatalf("Write() = %d, %v, want %d, nil", written, err, len(input))
	}
	if got := []byte(buffer.String()); !bytes.Equal(got, input[:4]) {
		t.Fatalf("bounded output = %q, want %q", got, input[:4])
	}
	if written, err := buffer.Write([]byte("ignored")); err != nil || written != len("ignored") || buffer.String() != "abcd" {
		t.Fatalf("full buffer Write() = %d, %v, %q", written, err, buffer.String())
	}
}

func TestRunnerSourceSHA256DrainsDependencyGraphWhileGoListRuns(t *testing.T) {
	repository, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	type result struct {
		digest string
		err    error
	}
	results := make(chan result, 1)
	go func() {
		digest, runErr := runnerSourceSHA256(repository)
		results <- result{digest: digest, err: runErr}
	}()
	select {
	case got := <-results:
		if got.err != nil {
			t.Fatal(got.err)
		}
		if len(got.digest) != 64 {
			t.Fatalf("runner source digest length = %d, want 64", len(got.digest))
		}
	case <-time.After(30 * time.Second):
		t.Fatal("runner dependency graph collection deadlocked")
	}
}

func TestRunnerSourceSHA256UsesTheEvidencePlatform(t *testing.T) {
	repository, _, _ := newCleanTestRepository(t)
	commandRoot := filepath.Join(repository, "flowersec-go", "internal", "cmd", "transport-release-runner")
	for name, contents := range map[string]string{
		"platform_amd64.go": "package main\n\nvar platformIdentity = \"amd64\"\n",
		"platform_arm64.go": "package main\n\nvar platformIdentity = \"arm64\"\n",
	} {
		if err := os.WriteFile(filepath.Join(commandRoot, name), []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	linuxDigest, err := runnerSourceSHA256ForPlatform(repository, "linux", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	arm64Digest, err := runnerSourceSHA256ForPlatform(repository, "linux", "arm64")
	if err != nil {
		t.Fatal(err)
	}
	if linuxDigest == arm64Digest {
		t.Fatal("Linux amd64 and arm64 source identities unexpectedly match")
	}
	if _, err := runnerSourceSHA256ForPlatform(repository, "darwin", "arm64"); err == nil || !strings.Contains(err.Error(), "unsupported runner source platform") {
		t.Fatalf("unsupported platform error = %v", err)
	}
	if linuxDigest == "" {
		t.Fatal("Linux runner source digest is empty")
	}
}

func TestCanonicalAllTargetArgvRecordsEveryForcedProfileShardAndMerge(t *testing.T) {
	records, err := canonicalAllTargetArgvRecords(loadFixtureManifest(t), loadFixtureRegistry(t))
	if err != nil {
		t.Fatal(err)
	}
	type counts struct{ shards, merges int }
	byJob := make(map[string]counts)
	for _, record := range records {
		base, suffix, sharded := strings.Cut(record.JobID, "/")
		if !sharded {
			continue
		}
		count := byJob[base]
		switch {
		case record.Scope == "low-level-shard" && strings.HasPrefix(suffix, "shard-") && argumentHasName(record.Args, "--run-shard"):
			count.shards++
		case record.Scope == "low-level-merge" && suffix == "merge" && !argumentHasName(record.Args, "--run-shard") && !argumentHasName(record.Args, "--bpf-object"):
			count.merges++
		default:
			t.Fatalf("invalid canonical sharded record: %+v", record)
		}
		byJob[base] = count
	}
	if len(byJob) == 0 {
		t.Fatal("canonical argv contains no forced profile jobs")
	}
	for job, count := range byJob {
		if count.shards != profileShardCount || count.merges != 1 {
			t.Fatalf("canonical job %s = %d shards/%d merges, want %d/1", job, count.shards, count.merges, profileShardCount)
		}
	}
}

func TestWriteRunnerLocalConfigAtomicallyKeepsPrivateShape(t *testing.T) {
	path := filepath.Join(t.TempDir(), "transport-runner.json")
	want := RunnerLocalConfig{
		SchemaVersion: 1, RunnerID: "flowersec-linux-release-v1", OS: "linux", Architecture: "arm64",
		KernelRelease: "6.8.0-test", ExecutableSHA256: strings.Repeat("1", 64),
		SourceSHA256: strings.Repeat("2", 64), ArgvSHA256: strings.Repeat("3", 64),
	}
	if err := writeRunnerLocalConfig(path, want); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("runner config mode = %o, want 600", info.Mode().Perm())
	}
	var got RunnerLocalConfig
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("runner config = %+v, want %+v", got, want)
	}
	if err := writeRunnerLocalConfig(path, want); err != nil {
		t.Fatalf("replace runner config: %v", err)
	}
}

func TestRunnerRepositoryIdentityRejectsSourceOrArgvDrift(t *testing.T) {
	repository, _, _ := newCleanTestRepository(t)
	manifest := loadFixtureManifest(t)
	registry := loadFixtureRegistry(t)
	sourceDigest, err := runnerSourceSHA256(repository)
	if err != nil {
		t.Fatal(err)
	}
	argvDigest, err := canonicalAllTargetArgvSHA256(manifest, registry)
	if err != nil {
		t.Fatal(err)
	}
	runner := EvidenceRunner{OS: "linux", Architecture: runtime.GOARCH, SourceSHA256: sourceDigest, ArgvSHA256: argvDigest}
	if err := validateRunnerRepositoryIdentity(repository, manifest, registry, runner); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*EvidenceRunner){
		func(value *EvidenceRunner) { value.SourceSHA256 = strings.Repeat("0", 64) },
		func(value *EvidenceRunner) { value.ArgvSHA256 = strings.Repeat("0", 64) },
	} {
		mutated := runner
		mutate(&mutated)
		if err := validateRunnerRepositoryIdentity(repository, manifest, registry, mutated); err == nil {
			t.Fatal("accepted signed runner identity that differs from the audited repository")
		}
	}
}
