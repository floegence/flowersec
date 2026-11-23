package timev4

import (
	"errors"
	"math"
	"testing"
)

func TestDeadlineForkPreservesOriginalProjectionAndIndependentClose(t *testing.T) {
	clock, source := testClock(t, &Interval{1000, 1100})
	original, err := NewDeadline(clock, 1500)
	if err != nil {
		t.Fatal(err)
	}
	installTest(t, clock, Interval{1000, 1001})
	child, err := original.Fork(1500)
	if err != nil {
		t.Fatal(err)
	}
	if remaining, err := child.RemainingMS(); err != nil || remaining != 400 {
		t.Fatal("fork reset the original conservative projection", remaining, err)
	}
	original.Cancel()
	if err := child.Check(); err != nil {
		t.Fatal("parent lifecycle cancelled separately owned deadline", err)
	}
	source.set(400, 1, nil)
	if !errors.Is(child.Check(), ErrExpired) {
		t.Fatal("child survived original monotonic cap")
	}
	if _, err := original.Fork(1500); !errors.Is(err, ErrCancelled) {
		t.Fatal("fork resurrected closed parent", err)
	}
}

func TestDeadlineForkAgePreservesPrepareSampleAndParentProjection(t *testing.T) {
	for _, parentCap := range []uint64{1300, 5000} {
		clock, source := testClock(t, &Interval{1000, 1100})
		parent, err := NewDeadline(clock, parentCap)
		if err != nil {
			t.Fatal(err)
		}
		start, err := clock.Sample()
		if err != nil {
			t.Fatal(err)
		}
		installTest(t, clock, Interval{1000, 1000})
		child, err := parent.ForkAgeAt(start, 500)
		if err != nil {
			t.Fatal(err)
		}
		want := min(parentCap-1100, 400)
		if remaining, err := child.RemainingMS(); err != nil || remaining != want {
			t.Fatal("narrower anchor extended an original child or parent projection", remaining, want, err)
		}
		source.set(want, 1, nil)
		if !errors.Is(child.Check(), ErrExpired) {
			t.Fatal("age child survived original monotonic deadline")
		}
	}
}

func TestDeadlineForkAgeRejectsExpiredOwnerAndInvalidStart(t *testing.T) {
	clock, source := testClock(t, &Interval{1000, 1100})
	parent, _ := NewDeadline(clock, 5000)
	start, _ := clock.Sample()
	if _, err := parent.ForkAgeAt(start, math.MaxUint64); err == nil {
		t.Fatal("age overflow accepted")
	}
	foreign, _ := testClock(t, &Interval{1000, 1100})
	wrong, _ := foreign.Sample()
	if _, err := parent.ForkAgeAt(wrong, 500); !errors.Is(err, ErrOwner) {
		t.Fatal(err)
	}
	source.set(450, 1, nil)
	if _, err := parent.ForkAgeAt(start, 500); !errors.Is(err, ErrExpired) {
		t.Fatal("late preparation renewed age", err)
	}
	parent.Cancel()
	if _, err := parent.ForkAgeAt(start, 2000); !errors.Is(err, ErrCancelled) {
		t.Fatal("canceled parent revived", err)
	}
}

func TestDeadlineForkCannotExtendOriginalAbsoluteCap(t *testing.T) {
	clock, _ := testClock(t, &Interval{1000, 1100})
	d, _ := NewDeadline(clock, 1500)
	if _, err := d.Fork(1501); !errors.Is(err, ErrOwner) {
		t.Fatal(err)
	}
	child, err := d.Fork(1200)
	if err != nil {
		t.Fatal(err)
	}
	if remaining, err := child.RemainingMS(); err != nil || remaining != 100 {
		t.Fatal("tightened child lost original cap", remaining, err)
	}
}
