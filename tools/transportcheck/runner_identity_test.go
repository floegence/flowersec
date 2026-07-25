package main

import (
	"path/filepath"
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
