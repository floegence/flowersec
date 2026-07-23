package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/interopprotocol"
)

func TestSmokeProfileExercisesEveryDeterministicLimit(t *testing.T) {
	repoRoot, err := findRepoRoot()
	if err != nil {
		t.Fatal(err)
	}
	document, err := loadProfiles(filepath.Join(repoRoot, "testdata/interop/v1/profiles.json"))
	if err != nil {
		t.Fatal(err)
	}
	smoke := document.Profiles["smoke"]
	if smoke.LimitChecks != len(interopprotocol.DiagnosticExpectations) {
		t.Fatalf("smoke limit checks got %d, want %d", smoke.LimitChecks, len(interopprotocol.DiagnosticExpectations))
	}
	if err := interopprotocol.ValidateDiagnosticExpectations(smoke.Diagnostics, smoke.LimitChecks); err != nil {
		t.Fatalf("smoke diagnostics do not cover every deterministic limit: %v", err)
	}
}

func TestActiveStreamLimitChecksControlBeforeResetCleanup(t *testing.T) {
	var order []string
	controlErr := errors.New("control failed")
	resetErr := errors.New("reset failed")
	err := completeActiveStreamLimit(
		func() error {
			order = append(order, "control")
			return controlErr
		},
		func() error {
			order = append(order, "reset")
			return resetErr
		},
	)
	if len(order) != 2 || order[0] != "control" || order[1] != "reset" {
		t.Fatalf("active stream completion order got %v, want [control reset]", order)
	}
	if !errors.Is(err, controlErr) || !errors.Is(err, resetErr) {
		t.Fatalf("active stream completion did not preserve both failures: %v", err)
	}
}

func TestExternalClientHarnessesCheckControlBeforeResetCleanup(t *testing.T) {
	repoRoot, err := findRepoRoot()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name          string
		path          string
		startMarker   string
		controlMarker string
		resetMarker   string
	}{
		{
			name:          "typescript",
			path:          "flowersec-ts/scripts/interop-harness.mjs",
			startMarker:   `case "active_streams": {`,
			controlMarker: "await rpcControl(client, 5);",
			resetMarker:   "await held.reset(",
		},
		{
			name:          "swift",
			path:          "flowersec-swift/InteropHarness/main.swift",
			startMarker:   `case "active_streams":`,
			controlMarker: "try await rpcControl(client, typeID: 5)",
			resetMarker:   "try await held.reset()",
		},
		{
			name:          "rust",
			path:          "flowersec-rust/examples/interop_harness.rs",
			startMarker:   `"active_streams" => {`,
			controlMarker: "let control_result = rpc_control(client, 5).await;",
			resetMarker:   "let reset_result = held.reset().await;",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			source, err := os.ReadFile(filepath.Join(repoRoot, test.path))
			if err != nil {
				t.Fatal(err)
			}
			startIndex := strings.Index(string(source), test.startMarker)
			if startIndex < 0 {
				t.Fatalf("active stream case is missing from %s", test.path)
			}
			activeStreamCase := string(source[startIndex:])
			controlIndex := strings.Index(activeStreamCase, test.controlMarker)
			resetIndex := strings.Index(activeStreamCase, test.resetMarker)
			if controlIndex < 0 || resetIndex < 0 {
				t.Fatalf("active stream markers are missing from %s", test.path)
			}
			if controlIndex > resetIndex {
				t.Fatalf("%s resets the held stream before checking the existing RPC control stream", test.path)
			}
		})
	}
}

func TestInteropProfilesDeclareStreamingAndMixedConcurrency(t *testing.T) {
	repoRoot, err := findRepoRoot()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(repoRoot, "testdata/interop/v1/profiles.json"))
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Profiles map[string]struct {
			Streams struct {
				BytesPerStream      int `json:"bytes_per_stream"`
				MixedConcurrent     int `json:"mixed_concurrent"`
				MixedBytesPerStream int `json:"mixed_bytes_per_stream"`
			} `json:"streams"`
			Proxy struct {
				StreamingHTTPBodyBytes int `json:"streaming_http_body_bytes"`
			} `json:"proxy"`
		} `json:"profiles"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	smoke := document.Profiles["smoke"]
	if smoke.Streams.MixedConcurrent != 2 {
		t.Fatalf("smoke mixed concurrency got %d, want 2", smoke.Streams.MixedConcurrent)
	}
	if smoke.Streams.MixedBytesPerStream <= smoke.Streams.BytesPerStream {
		t.Fatalf(
			"smoke mixed stream body got %d, want greater than regular %d",
			smoke.Streams.MixedBytesPerStream,
			smoke.Streams.BytesPerStream,
		)
	}
	stress := document.Profiles["stress"]
	if stress.Proxy.StreamingHTTPBodyBytes != 16*1024*1024 {
		t.Fatalf("stress streaming proxy body got %d, want 16 MiB", stress.Proxy.StreamingHTTPBodyBytes)
	}
	if stress.Streams.MixedConcurrent != 8 {
		t.Fatalf("stress mixed concurrency got %d, want 8", stress.Streams.MixedConcurrent)
	}
	if stress.Streams.MixedBytesPerStream < 1024*1024 {
		t.Fatalf("stress mixed stream body got %d, want at least 1 MiB", stress.Streams.MixedBytesPerStream)
	}
}

func TestInteropProfilesSerializeDirectedCellsSharingReferenceEnvironment(t *testing.T) {
	repoRoot, err := findRepoRoot()
	if err != nil {
		t.Fatal(err)
	}
	document, err := loadProfiles(filepath.Join(repoRoot, "testdata/interop/v1/profiles.json"))
	if err != nil {
		t.Fatal(err)
	}
	for name, profile := range document.Profiles {
		if profile.MaxParallelCells != 1 {
			t.Fatalf(
				"%s profile directed-cell parallelism got %d, want 1 because cells share the reference environment",
				name,
				profile.MaxParallelCells,
			)
		}
	}
}

func TestBaselineFailureStopsRemainingVariants(t *testing.T) {
	variants := []variant{
		{Transport: "direct", Suite: "x25519"},
		{Transport: "tunnel", Suite: "p256"},
	}
	called := 0
	reports, err := runBaselineVariants(context.Background(), variants, nil, func(variant) (timedResult, error) {
		called++
		return timedResult{}, errors.New("baseline failed")
	})
	if err == nil || called != 1 || len(reports) != 1 {
		t.Fatalf("baseline failure did not stop the matrix: called=%d reports=%d err=%v", called, len(reports), err)
	}
}

func TestExternalJobsBoundConcurrencyAndPreserveMatrixOrder(t *testing.T) {
	jobs := []externalCellJob{
		{index: 0, cell: "typescript_to_go"},
		{index: 1, cell: "swift_to_go"},
		{index: 2, cell: "rust_to_go"},
	}
	var active atomic.Int32
	var maximum atomic.Int32
	reports, err := runExternalJobs(context.Background(), jobs, 2, func(_ context.Context, job externalCellJob) ([]cellReport, error) {
		current := active.Add(1)
		for {
			previous := maximum.Load()
			if current <= previous || maximum.CompareAndSwap(previous, current) {
				break
			}
		}
		defer active.Add(-1)
		time.Sleep(time.Duration(3-job.index) * 10 * time.Millisecond)
		return []cellReport{{Cell: job.cell}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if maximum.Load() != 2 {
		t.Fatalf("maximum concurrency got %d, want 2", maximum.Load())
	}
	want := []string{"typescript_to_go", "swift_to_go", "rust_to_go"}
	if len(reports) != len(want) {
		t.Fatalf("report count got %d, want %d", len(reports), len(want))
	}
	for index, report := range reports {
		if report.Cell != want[index] {
			t.Fatalf("report %d got %q, want %q", index, report.Cell, want[index])
		}
	}
}

func TestExternalJobsRejectInvalidParallelism(t *testing.T) {
	jobs := []externalCellJob{{index: 0, cell: "typescript_to_go"}}
	if _, err := runExternalJobs(context.Background(), jobs, 0, func(context.Context, externalCellJob) ([]cellReport, error) {
		return nil, nil
	}); err == nil {
		t.Fatal("zero parallelism must fail instead of deadlocking")
	}
}

func TestExternalJobsAggregateTaskAndShutdownFailures(t *testing.T) {
	jobs := []externalCellJob{
		{index: 0, cell: "typescript_to_go"},
		{index: 1, cell: "swift_to_go"},
	}
	primary := errors.New("primary task failed")
	shutdown := errors.New("peer shutdown failed")
	var started sync.WaitGroup
	started.Add(len(jobs))
	_, err := runExternalJobs(context.Background(), jobs, 2, func(ctx context.Context, job externalCellJob) ([]cellReport, error) {
		started.Done()
		started.Wait()
		if job.index == 0 {
			return nil, primary
		}
		<-ctx.Done()
		return nil, shutdown
	})
	if !errors.Is(err, primary) || !errors.Is(err, shutdown) {
		t.Fatalf("task and shutdown failures were not aggregated: %v", err)
	}
}

func TestDiagnosticValidationRejectsWrongPathOrderAndCount(t *testing.T) {
	expected := interopprotocol.DiagnosticExpectations[:2]
	valid := []interopprotocol.Diagnostic{
		{Case: "rpc_queue", Path: "direct", Stage: "rpc", Code: "resource_exhausted"},
		{Case: "active_streams", Path: "direct", Stage: "yamux", Code: "resource_exhausted"},
	}
	if err := interopprotocol.ValidateDiagnostics(valid, "direct", expected); err != nil {
		t.Fatal(err)
	}
	invalid := append([]interopprotocol.Diagnostic(nil), valid...)
	invalid[0].Path = "tunnel"
	if err := interopprotocol.ValidateDiagnostics(invalid, "direct", expected); err == nil {
		t.Fatal("wrong diagnostic path must fail")
	}
	if err := interopprotocol.ValidateDiagnostics(valid[:1], "direct", expected); err == nil {
		t.Fatal("missing diagnostic must fail")
	}
	invalid = []interopprotocol.Diagnostic{valid[1], valid[0]}
	if err := interopprotocol.ValidateDiagnostics(invalid, "direct", expected); err == nil {
		t.Fatal("out-of-order diagnostics must fail")
	}
}
