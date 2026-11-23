package timev4

import (
	"errors"
	"math"
	"testing"
)

func TestIdleOriginalActivityDeadline(t *testing.T) {
	clock, source := testClock(t, &Interval{10000, 12000})
	idle, err := NewIdle(clock, 1000, 0)
	if err != nil {
		t.Fatal(err)
	}
	source.set(5000, 1, nil)
	if err = idle.Refresh(); err != nil {
		t.Fatal(err)
	}
	if remaining, armed, err := idle.RemainingMS(); err != nil || armed || remaining != 0 {
		t.Fatal("private work armed idle", remaining, armed, err)
	}
	if err = idle.Start(); err != nil {
		t.Fatal(err)
	}
	source.set(5999, 1, nil)
	if err = idle.Refresh(); err != nil {
		t.Fatal("wall uncertainty deducted from idle", err)
	}
	source.set(6500, 1, nil)
	if ms, _, err := idle.RemainingMS(); err != nil || ms != 499 {
		t.Fatal("wakeup restarted timer", ms, err)
	}
	// No timer needed to observe the exact original deadline at this gate.
	source.set(6999, 1, nil)
	if err = idle.Refresh(); !errors.Is(err, ErrExpired) {
		t.Fatal("late activity revived idle", err)
	}
	source.set(7000, 2, nil)
	installTest(t, clock, Interval{17000, 17000})
	if err = idle.Start(); !errors.Is(err, ErrExpired) {
		t.Fatal("new era rearmed idle", err)
	}
}

func TestIdleUnsignedPolicyAndContinuity(t *testing.T) {
	clock, source := testClock(t, nil)
	if _, err := NewIdle(clock, 100, 101); !errors.Is(err, ErrInterval) {
		t.Fatal("local policy extended signed idle", err)
	}
	disabled, err := NewIdle(clock, 0, 0)
	if err != nil || disabled.Start() != nil {
		t.Fatal(err)
	}
	local, err := NewIdle(clock, 0, 100)
	if err != nil || local.Start() != nil {
		t.Fatal(err)
	}
	source.set(1, 2, nil)
	if err := local.Refresh(); !errors.Is(err, ErrContinuity) {
		t.Fatal("clock switch resumed old idle", err)
	}
	if _, armed, err := disabled.RemainingMS(); armed || err != nil {
		t.Fatal("signed zero installed a default", armed, err)
	}
	source.set(math.MaxUint64-10, 2, nil)
	wide, err := NewIdle(clock, math.MaxUint64, 0)
	if err != nil || wide.Start() != nil {
		t.Fatal("full uint64 duration rejected", err)
	}
	source.set(math.MaxUint64, 2, nil)
	if ms, armed, err := wide.RemainingMS(); err != nil || !armed || ms != math.MaxUint64-10 {
		t.Fatal("duration narrowed or anchor addition overflowed", ms, armed, err)
	}
}

func TestIdleConservativeRateAndQuantization(t *testing.T) {
	source := &testSource{tick: Tick{Incarnation: [16]byte{1}}}
	clock, err := NewClock(Profile{Rate: Rate{Numerator: 1, Denominator: 10, QuantizationMS: 2}, MaxWidthMS: 100, MaxAgeMS: 10000, MaxRoundTripMS: 100}, source.read)
	if err != nil {
		t.Fatal(err)
	}
	defer clock.Close()
	idle, err := NewIdle(clock, 1000, 100)
	if err != nil || idle.Start() != nil {
		t.Fatal(err)
	}
	source.set(87, 1, nil)
	if ms, _, err := idle.RemainingMS(); err != nil || ms != 1 {
		t.Fatal(ms, err)
	}
	source.set(88, 1, nil)
	if err := idle.Check(); !errors.Is(err, ErrExpired) {
		t.Fatal("raw monotonic difference used without conservative bound", err)
	}
}
