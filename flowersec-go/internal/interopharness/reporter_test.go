package interopharness

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestReporterClosedChildDetachesItsParentCleanup(t *testing.T) {
	parent, err := NewPeerReporter()
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	parent.mu.Lock()
	baseline := len(parent.cleanup)
	parent.mu.Unlock()
	for index := 0; index < 100; index++ {
		child, err := parent.ForkAuthority()
		if err != nil {
			t.Fatal(err)
		}
		if child.AuthorityClock() != parent.AuthorityClock() || child.AuthorityEpochMS() != parent.AuthorityEpochMS() {
			t.Fatal("child replaced its original authority time domain")
		}
		if child.AuthorityLeaseID() == parent.AuthorityLeaseID() || child.AuthorityAttemptID() == parent.AuthorityAttemptID() {
			t.Fatal("independent issuance reused original once-only identities")
		}
		if child.AuthorityCandidateID() != parent.AuthorityCandidateID() {
			t.Fatal("independent issuance changed the original endpoint identity")
		}
		if err := child.Close(); err != nil {
			t.Fatal(err)
		}
		parent.mu.Lock()
		retained := len(parent.cleanup)
		parent.mu.Unlock()
		if retained != baseline {
			t.Fatalf("closed child retained %d parent callbacks, baseline %d", retained, baseline)
		}
	}
	if err := parent.Close(); err != nil {
		t.Fatal(err)
	}
	if child, err := parent.ForkAuthority(); err == nil {
		_ = child.Close()
		t.Fatal("closed authority created a new child")
	}
}
func TestReporterCloseJoinsConcurrentCloseAndLateCleanup(t *testing.T) {
	reporter, err := NewPeerReporter()
	if err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	reporter.Cleanup(func() { close(entered); <-release; calls.Add(1) })
	first, second := make(chan error, 1), make(chan error, 1)
	go func() { first <- reporter.Close() }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("original cleanup did not start")
	}
	reporter.Cleanup(func() { calls.Add(1) })
	go func() { second <- reporter.Close() }()
	premature := false
	select {
	case <-second:
		premature = true
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	if premature {
		t.Fatal("concurrent Close returned before the original cleanup callback")
	}
	select {
	case err := <-second:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("concurrent Close did not join the actual callback")
	}
	if calls.Load() != 2 {
		t.Fatalf("original and late cleanup callbacks = %d", calls.Load())
	}
	reporter.Cleanup(func() { calls.Add(1) })
	if calls.Load() != 3 {
		t.Fatal("post-closure cleanup registration was lost")
	}
}
func TestReporterConcurrentClosePreservesCleanupFailure(t *testing.T) {
	reporter, err := NewPeerReporter()
	if err != nil {
		t.Fatal(err)
	}
	want := errors.New("original cleanup failure")
	reporter.Cleanup(func() { reporter.ErrorIf(want) })
	for index := 0; index < 2; index++ {
		if err := reporter.Close(); !errors.Is(err, want) {
			t.Fatalf("Close %d discarded original cleanup failure: %v", index, err)
		}
	}
}

func TestReporterConstructionPreservesOriginalError(t *testing.T) {
	reporter, err := NewPeerReporter()
	if err != nil {
		t.Fatal(err)
	}
	defer reporter.Close()
	want := errors.New("original application constructor failure")
	_, err = construct(reporter, func() bool { reporter.Fatal(want); return false })
	if !errors.Is(err, want) {
		t.Fatalf("construction lost the original failure: %v", err)
	}
}

// An authority may be descheduled while its identities and clock are built.
// Its independently signed issue times must still share the current local
// envelope with another peer, instead of permanently lagging by setup time.
func TestReporterClockIncludesConstructionElapsedTime(t *testing.T) {
	started := time.Now().Add(-250 * time.Millisecond)
	clock, err := newReporterClock(started, [16]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	defer clock.Close()
	before := uint64(time.Now().UnixMilli())
	sample, err := clock.Sample()
	after := uint64(time.Now().UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	if sample.LowerMS > after || sample.UpperMS < before {
		t.Fatalf("local envelope %+v does not intersect its actual sample [%d,%d]", sample.Interval, before, after)
	}
	if sample.Milliseconds < 250 || sample.UpperMS-sample.LowerMS != 2 {
		t.Fatalf("construction changed the elapsed-time or uncertainty contract: %+v", sample)
	}
}
