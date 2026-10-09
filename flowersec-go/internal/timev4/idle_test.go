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

func TestIdleCheckAtRechecksPublishedFrontierWithoutHostCallback(t *testing.T) {
	clock, source := testClock(t, &Interval{10000, 10000})
	idle, err := NewIdle(clock, 100, 0)
	if err != nil || idle.Start() != nil {
		t.Fatal(err)
	}
	before, err := clock.Sample()
	if err != nil {
		t.Fatal(err)
	}
	source.set(100, 1, nil)
	if _, err := clock.Sample(); err != nil {
		t.Fatal(err)
	}
	// Sampling the adapter is forbidden during the final ownership gate.
	clock.sample = func() (Tick, error) { t.Fatal("final gate called host clock"); return Tick{}, ErrUnavailable }
	if err := idle.CheckAt(before); !errors.Is(err, ErrExpired) {
		t.Fatal("stale preflight accepted after idle expiry", err)
	}
	if err := idle.CheckAt(before); !errors.Is(err, ErrExpired) {
		t.Fatal("expired idle owner revived", err)
	}
}

func TestIdleAdjacentGatesPreserveMonotonicOwnerAcrossWallRepair(t *testing.T) {
	for _, gate := range []string{"check", "refresh", "remaining"} {
		t.Run(gate, func(t *testing.T) {
			clock, source := testClock(t, &Interval{10000, 10000})
			idle, err := NewIdle(clock, 30000, 0)
			if err != nil || idle.Start() != nil {
				t.Fatal(err)
			}
			before, err := clock.Sample()
			if err != nil {
				t.Fatal(err)
			}
			check := func(sample Sample, wantRemaining uint64) error {
				t.Helper()
				adapter := clock.sample
				clock.sample = func() (Tick, error) {
					t.Fatal("adjacent idle gate called host clock")
					return Tick{}, ErrUnavailable
				}
				defer func() { clock.sample = adapter }()
				switch gate {
				case "check":
					return idle.CheckAt(sample)
				case "refresh":
					return idle.RefreshAt(sample)
				default:
					remaining, armed, err := idle.RemainingMSAt(sample)
					if err == nil && (!armed || remaining != wantRemaining) {
						t.Fatalf("remaining = %d, armed = %v, want %d", remaining, armed, wantRemaining)
					}
					return err
				}
			}
			// Another read ages the wall anchor while the original idle remains
			// continuous and unexpired. Both valid and wall-invalid samples
			// must reach the same latest monotonic frontier.
			source.set(10001, 1, nil)
			unavailable, err := clock.Sample()
			if !errors.Is(err, ErrUnavailable) {
				t.Fatal("old wall anchor authorized work", err)
			}
			if _, err := clock.RefreshSample(before); !errors.Is(err, ErrUnavailable) {
				t.Fatal("adjacent wall gate accepted aged anchor", err)
			}
			for _, sample := range []Sample{before, unavailable} {
				if err := check(sample, 19999); err != nil {
					t.Fatal("anchor ageing poisoned idle", err)
				}
			}
			installTest(t, clock, Interval{20001, 20001})
			source.set(10002, 1, nil)
			mark, err := clock.Monotonic()
			if err != nil {
				t.Fatal(err)
			}
			if err := clock.InstallTrusted(mark, Interval{40000, 40000}); !errors.Is(err, ErrContradiction) {
				t.Fatal("contradiction did not invalidate wall trust", err)
			}
			if err := check(before, 19998); err != nil {
				t.Fatal("wall invalidation poisoned idle", err)
			}
			source.set(10003, 1, nil)
			installTest(t, clock, Interval{20003, 20003})
			if _, err := clock.RefreshSample(before); !errors.Is(err, ErrUnavailable) {
				t.Fatal("repair revived retired wall authorization", err)
			}
			if err := check(before, 19997); err != nil {
				t.Fatal("wall repair poisoned idle", err)
			}
			deadline := uint64(30000)
			if gate == "refresh" {
				// Only actual qualifying activity above moved the idle deadline.
				deadline = 40003
			}
			source.set(deadline, 1, nil)
			if _, err := clock.Monotonic(); err != nil {
				t.Fatal(err)
			}
			if err := check(before, 0); !errors.Is(err, ErrExpired) {
				t.Fatal("wall repair extended original idle deadline", err)
			}
			installTest(t, clock, Interval{10000 + deadline, 10000 + deadline})
			if err := check(before, 0); !errors.Is(err, ErrExpired) {
				t.Fatal("repair revived expired idle", err)
			}
		})
	}
}

func TestIdleAdjacentGatesRejectRetiredMonotonicEra(t *testing.T) {
	for _, gate := range []string{"check", "refresh", "remaining"} {
		t.Run(gate, func(t *testing.T) {
			clock, source := testClock(t, &Interval{10000, 10000})
			idle, err := NewIdle(clock, 1000, 0)
			if err != nil || idle.Start() != nil {
				t.Fatal(err)
			}
			before, err := clock.Sample()
			if err != nil {
				t.Fatal(err)
			}
			check := func(sample Sample) error {
				switch gate {
				case "check":
					return idle.CheckAt(sample)
				case "refresh":
					return idle.RefreshAt(sample)
				default:
					_, _, err := idle.RemainingMSAt(sample)
					return err
				}
			}
			source.set(1, 2, nil)
			installTest(t, clock, Interval{10001, 10001})
			after, err := clock.Sample()
			if err != nil {
				t.Fatal(err)
			}
			if err := check(before); !errors.Is(err, ErrContinuity) {
				t.Fatal("retired monotonic era authorized idle", err)
			}
			if err := check(after); !errors.Is(err, ErrContinuity) {
				t.Fatal("new era revived original idle", err)
			}
		})
	}
}
