package main

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/internal/interopprotocol"
)

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
