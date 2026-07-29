package main

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

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
