package sessionv4

import (
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"testing"
	"time"
)

func TestOperationsExecutorReportsOriginalRunningTails(t *testing.T) {
	f := newExecutorConfigFixture(t, ApplicationExecutorConfig{Running: 2, ResidentRunning: 1, Ready: 4, ResidentReady: 2,
		CompletionRunning: 1, CompletionReserved: 4, Diagnostics: true, QueryOwners: 4, RuntimeBytes: 4096, RuntimeBytesPerTask: 65536})
	ref, err := f.executor.BorrowOperations(f.reserve(t, 2, resourcev4.Vector{resourcev4.Items: 1}))
	if err != nil {
		t.Fatal(err)
	}
	defer ref.Release()
	entered, release := make(chan struct{}), make(chan struct{})
	task, input := f.job(t, 2)
	h, err := f.executor.TrySubmit(ApplicationResident, task, input, func() { close(entered); <-release })
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		close(release)
		t.Fatal("callback did not start")
	}
	baseline := f.root.Snapshot()
	s := f.executor.OperationsSnapshot()
	if s.Counts.Running != 1 || s.Counts.ResidentRunning != 1 || s.Limits.DiagnosticRunning != 2 || s.Limits.DiagnosticReady != 4 || s.Limits.QueryRunning != 1 || s.Limits.QueryReady != 4 || s.Limits.CompletionReserved != 4 || s.Limits.Ready != 4 || f.root.Snapshot() != baseline {
		close(release)
		t.Fatal("operations read changed original queue or limits", s)
	}
	f.executor.Close()
	s = f.executor.OperationsSnapshot()
	if !s.Counts.Closed || s.Counts.CleanupComplete || s.Counts.Running != 1 {
		close(release)
		t.Fatal("close reported physically idle lane", s)
	}
	close(release)
	select {
	case <-h.Done():
	case <-time.After(time.Second):
		t.Fatal("callback tail retained")
	}
	select {
	case <-f.executor.Done():
	case <-time.After(time.Second):
		t.Fatal("executor did not retire")
	}
	s = f.executor.OperationsSnapshot()
	if !s.Counts.CleanupComplete || s.Counts.Running != 0 || s.Limits.Running != 2 || s.Limits.DiagnosticReady != 4 {
		t.Fatal("cleanup erased caps or retained activity", s)
	}
}
