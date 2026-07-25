//go:build linux

package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNativeProofSystemCasesUseRealQLOGAndPCAP(t *testing.T) {
	object := os.Getenv("FLOWERSEC_BPF_OBJECT")
	if object == "" {
		t.Skip("set FLOWERSEC_BPF_OBJECT to the verifier-loadable classifier")
	}
	previousWorkerArguments := systemWorkerArguments
	systemWorkerArguments = func() []string { return []string{"-test.run=^TestWeaknetSystemWorkerProcess$"} }
	t.Cleanup(func() { systemWorkerArguments = previousWorkerArguments })
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	artifactRoot := filepath.Join(root, "artifacts")
	if err := os.Mkdir(artifactRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	destination, err := newArtifactDestination(artifactRoot, filepath.Join(root, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer destination.Close()
	for _, definition := range nativeProofCases {
		if definition.ID != "NP-PMTUD-STATE" && definition.ID != "NP-REBIND" && definition.ID != "NP-TARGET-LOSS" {
			continue
		}
		t.Run(definition.ID, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			result, err := runNativeProofCase(ctx, destination, definition, "normal", object)
			if err != nil {
				t.Fatal(err)
			}
			if result.CompletedOperations < 1 || len(result.Artifacts) != 5 || len(result.RawSources) != 2 {
				t.Fatalf("native proof system result = %+v", result)
			}
		})
	}
}
