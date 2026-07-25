package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/transportrelease"
)

func TestNativeRaceCasesExerciseProductionQUICUnderRaceDetector(t *testing.T) {
	if !raceDetectorEnabled() {
		t.Skip("requires go test -race")
	}
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	artifacts := filepath.Join(root, "artifacts")
	if err := os.Mkdir(artifacts, 0o700); err != nil {
		t.Fatal(err)
	}
	destination, err := newArtifactDestination(artifacts, filepath.Join(root, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer destination.Close()
	for _, definition := range nativeRaceCoreCases {
		t.Run(definition.ID, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			result, err := runNativeRaceCase(ctx, destination, definition, "race", "", "", transportrelease.ReleasePlan{})
			if err != nil {
				t.Fatal(err)
			}
			if result.CompletedOperations != 2 || len(result.Artifacts) != 4 {
				t.Fatalf("native race result = %+v", result)
			}
			assertNativeArtifactsUseRawQLOG(t, root, result)
		})
	}
}
