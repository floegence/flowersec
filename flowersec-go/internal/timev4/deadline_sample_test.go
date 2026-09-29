package timev4

import (
	"errors"
	"testing"
)

func TestDeadlineSampleForkRetainsOriginalProjectionWithoutAdapter(t *testing.T) {
	clock, source := testClock(t, &Interval{1000, 1100})
	parent, err := NewDeadline(clock, 1500)
	if err != nil {
		t.Fatal(err)
	}
	source.set(100, 1, nil)
	installTest(t, clock, Interval{1100, 1100})
	sample, err := clock.Sample()
	if err != nil {
		t.Fatal(err)
	}
	// Sample-based operations must not touch the adapter, even when it fails.
	source.set(100, 1, ErrUnavailable)
	child, err := parent.ForkAt(1500, sample)
	if err != nil {
		t.Fatal(err)
	}
	age, err := parent.ForkAgeUsingSample(sample, 1000)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []*Deadline{parent, child, age} {
		if left, err := d.RemainingMSAt(sample); err != nil || left != 300 {
			t.Fatal("fork extended original projection or sampled the adapter", left, err)
		}
	}
	if err := child.TightenAt(1400, sample); err != nil {
		t.Fatal(err)
	}
	if err := child.TightenAt(1500, sample); !errors.Is(err, ErrOwner) {
		t.Fatal("cap increased", err)
	}
	child.Cancel()
	if _, err := child.ForkAt(1400, sample); !errors.Is(err, ErrCancelled) {
		t.Fatal("cancelled parent revived", err)
	}
	if err := parent.CheckAt(sample); err != nil {
		t.Fatal("child cancellation revoked parent", err)
	}
}

func TestDeadlineSampleRejectsForeignAndRetiredClockEra(t *testing.T) {
	clock, source := testClock(t, &Interval{1000, 1100})
	parent, err := NewDeadline(clock, 1500)
	if err != nil {
		t.Fatal(err)
	}
	original, err := clock.Sample()
	if err != nil {
		t.Fatal(err)
	}
	foreign, _ := testClock(t, &Interval{1000, 1100})
	other, _ := foreign.Sample()
	if _, err := parent.ForkAt(1400, other); !errors.Is(err, ErrOwner) {
		t.Fatal(err)
	}
	source.set(1, 2, nil)
	_, _ = clock.Monotonic()
	if err := clock.CheckSample(original); !errors.Is(err, ErrContinuity) {
		t.Fatal(err)
	}
	if _, err := parent.ForkAgeUsingSample(original, 200); !errors.Is(err, ErrContinuity) {
		t.Fatal("retired sample forked a new owner", err)
	}
}

func TestCheckSampleRejectsSampleBehindPublishedFrontier(t *testing.T) {
	clock, source := testClock(t, &Interval{1000, 1100})
	captured, err := clock.Sample()
	if err != nil {
		t.Fatal(err)
	}
	source.set(1, 1, nil)
	if _, err = clock.Monotonic(); err != nil {
		t.Fatal(err)
	}
	if err = clock.CheckSample(captured); !errors.Is(err, ErrContinuity) {
		t.Fatalf("stale sample accepted at newer frontier: %v", err)
	}
	latest, err := clock.Sample()
	if err != nil {
		t.Fatal(err)
	}
	if err = clock.CheckSample(latest); err != nil {
		t.Fatalf("latest sample rejected: %v", err)
	}
}

func TestRefreshSampleUsesPublishedBoundsWithoutAdapter(t *testing.T) {
	clock, source := testClock(t, &Interval{1000, 1100})
	captured, err := clock.Sample()
	if err != nil {
		t.Fatal(err)
	}
	deadline, err := NewDeadlineAt(clock, captured, 1150)
	if err != nil {
		t.Fatal(err)
	}
	source.set(100, 1, nil)
	latest, err := clock.Sample()
	if err != nil {
		t.Fatal(err)
	}
	// No host call may occur while an authorization owner holds its gate.
	source.set(100, 1, ErrUnavailable)
	current, err := clock.RefreshSample(captured)
	if err != nil || current != latest || current.ValidBefore(1150) {
		t.Fatal("refresh reused stale validity or called the adapter", current, err)
	}
	if err := deadline.CheckAt(current); !errors.Is(err, ErrExpired) {
		t.Fatal("concurrent publication extended an original deadline", err)
	}
}

func TestRefreshSampleRejectsRetiredEraAndTrust(t *testing.T) {
	for _, changed := range []string{"incarnation", "trust"} {
		t.Run(changed, func(t *testing.T) {
			clock, source := testClock(t, &Interval{1000, 1100})
			captured, err := clock.Sample()
			if err != nil {
				t.Fatal(err)
			}
			if changed == "incarnation" {
				source.set(100, 2, nil)
				_, _ = clock.Monotonic()
			} else if err := clock.InstallTrusted(captured.Mark, Interval{2000, 2100}); !errors.Is(err, ErrContradiction) {
				t.Fatal(err)
			}
			mark, err := clock.Monotonic()
			if err != nil {
				t.Fatal(err)
			}
			if err := clock.InstallTrusted(mark, Interval{2000, 2100}); err != nil {
				t.Fatal(err)
			}
			if _, err := clock.RefreshSample(captured); err == nil {
				t.Fatal("refresh revived a retired sample")
			}
		})
	}
}
