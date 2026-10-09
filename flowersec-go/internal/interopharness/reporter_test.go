package interopharness

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
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

func TestReporterClocksCalibrateIndependentMonotonicOrigins(t *testing.T) {
	wall := time.Unix(1700000000, 123456789)
	elapsed := [2]time.Duration{250 * time.Millisecond, 1003 * time.Millisecond}
	var clocks [2]*timev4.Clock
	for index := range clocks {
		clock, err := newReporterClockFromSources(func() time.Duration { return elapsed[index] }, func() time.Time { return wall }, [16]byte{byte(index + 1)})
		if err != nil {
			t.Fatal(err)
		}
		defer clock.Close()
		clocks[index] = clock
	}
	for _, advance := range []time.Duration{0, time.Microsecond, 999 * time.Microsecond, 731 * time.Millisecond} {
		wall = wall.Add(advance)
		for index, clock := range clocks {
			elapsed[index] += advance
			sample, err := clock.Sample()
			if err != nil {
				t.Fatal(err)
			}
			current := uint64(wall.UnixMilli())
			if sample.LowerMS != current || sample.UpperMS != current+2 {
				t.Fatalf("peer %d inherited its counter origin at %s: %+v, local wall %d", index, advance, sample.Interval, current)
			}
		}
	}
}

func TestReporterClockDiscardsDelayedWallPairing(t *testing.T) {
	origin := time.Unix(1700000000, 987654321)
	var elapsed time.Duration
	reads := 0
	clock, err := newReporterClockFromSources(func() time.Duration { return elapsed }, func() time.Time {
		reads++
		wall := origin.Add(elapsed)
		if reads == 1 {
			elapsed += 5 * time.Millisecond
		} else {
			elapsed += 500 * time.Microsecond
		}
		return wall
	}, [16]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	defer clock.Close()
	if reads != 2 {
		t.Fatalf("wall reads = %d, want one rejected pair and one bounded pair", reads)
	}
	for _, advance := range []time.Duration{0, 500 * time.Microsecond, 731 * time.Millisecond} {
		elapsed += advance
		sample, err := clock.Sample()
		if err != nil {
			t.Fatal(err)
		}
		current := uint64(origin.Add(elapsed).UnixMilli())
		if sample.LowerMS > current || sample.UpperMS < current || current-sample.LowerMS > 1 || sample.UpperMS-sample.LowerMS != 2 {
			t.Fatalf("delayed pairing escaped the original envelope: %+v, local wall %d", sample.Interval, current)
		}
	}
}

func TestReporterClockRejectsUnboundedWallPairing(t *testing.T) {
	origin := time.Unix(1700000000, 123456789)
	var elapsed time.Duration
	reads := 0
	clock, err := newReporterClockFromSources(func() time.Duration { return elapsed }, func() time.Time {
		reads++
		wall := origin.Add(elapsed)
		elapsed += 3 * time.Millisecond
		return wall
	}, [16]byte{1})
	if clock != nil || err != timev4.ErrUnavailable || reads != 16 {
		t.Fatalf("unbounded local pairing: clock=%v, err=%v, reads=%d", clock, err, reads)
	}
}
