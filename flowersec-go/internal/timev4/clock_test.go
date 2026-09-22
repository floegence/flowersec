package timev4

import (
	"errors"
	"math"
	"sync"
	"testing"
)

type testSource struct {
	mu   sync.Mutex
	tick Tick
	err  error
}

func (s *testSource) read() (Tick, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.tick, s.err }
func (s *testSource) set(ms uint64, incarnation byte, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tick = Tick{ms, [16]byte{incarnation}}
	s.err = err
}

func testClock(t *testing.T, interval *Interval) (*Clock, *testSource) {
	t.Helper()
	source := &testSource{tick: Tick{Incarnation: [16]byte{1}}}
	clock, err := NewClock(Profile{Rate: Rate{Denominator: 1}, MaxWidthMS: 2000, MaxAgeMS: 10000, MaxRoundTripMS: 1500}, source.read)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(clock.Close)
	if interval != nil {
		installTest(t, clock, *interval)
	}
	return clock, source
}

func installTest(t *testing.T, clock *Clock, interval Interval) {
	t.Helper()
	mark, err := clock.Monotonic()
	if err != nil {
		t.Fatal(err)
	}
	if err = clock.InstallTrusted(mark, interval); err != nil {
		t.Fatal(err)
	}
}

func TestNetworkAnchorFullRoundTripAndOriginalOwner(t *testing.T) {
	clock, source := testClock(t, nil)
	r, err := clock.BeginNetwork()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = clock.BeginNetwork(); !errors.Is(err, ErrCapacity) {
		t.Fatal(err)
	}
	source.set(1000, 1, nil)
	if err = r.CompleteVerified(r.Nonce(), 100000, 100); err != nil {
		t.Fatal(err)
	}
	sample, err := clock.Sample()
	if err != nil || sample.Interval != (Interval{99900, 101100}) {
		t.Fatal(sample, err)
	}
	r, err = clock.BeginNetwork()
	if err != nil {
		t.Fatal(err)
	}
	r.Cancel()
	if _, err = clock.BeginNetwork(); !errors.Is(err, ErrCapacity) {
		t.Fatal("cancel freed live refresh", err)
	}
	if err = r.CompleteVerified(r.Nonce(), 100000, 100); !errors.Is(err, ErrCancelled) {
		t.Fatal(err)
	}
	next, err := clock.BeginNetwork()
	if err != nil {
		t.Fatal(err)
	}
	if next.Nonce() == r.Nonce() {
		t.Fatal("nonce reused")
	}
	if err = r.Release(); !errors.Is(err, ErrOwner) {
		t.Fatal("old release freed new owner", err)
	}
	if _, err = clock.BeginNetwork(); !errors.Is(err, ErrCapacity) {
		t.Fatal(err)
	}
	if err = next.CompleteVerified(r.Nonce(), 100000, 100); !errors.Is(err, ErrOwner) {
		t.Fatal("cross-query nonce", err)
	}
	if _, err = clock.Sample(); err != nil {
		t.Fatal("bad response discarded live old anchor", err)
	}
	late, err := clock.BeginNetwork()
	if err != nil {
		t.Fatal(err)
	}
	source.set(2501, 1, nil)
	if err = late.CompleteVerified(late.Nonce(), 101000, 100); !errors.Is(err, ErrRoundTrip) {
		t.Fatal(err)
	}
	if _, err = clock.Sample(); err != nil {
		t.Fatal("failed refresh reset old anchor", err)
	}
}

func TestClockAnchorAgeContradictionAndContinuity(t *testing.T) {
	clock, source := testClock(t, &Interval{1000, 1100})
	original, err := clock.Monotonic()
	if err != nil {
		t.Fatal(err)
	}
	source.set(9000, 1, nil)
	if err = clock.InstallTrusted(original, Interval{1000, 1100}); err != nil {
		t.Fatal(err)
	}
	source.set(10001, 1, nil)
	if _, err = clock.Sample(); !errors.Is(err, ErrUnavailable) {
		t.Fatal("reinstall renewed anchor age", err)
	}
	installTest(t, clock, Interval{11001, 11101})
	mark, _ := clock.Monotonic()
	if err = clock.InstallTrusted(mark, Interval{13000, 13100}); !errors.Is(err, ErrContradiction) {
		t.Fatal(err)
	}
	if _, err = clock.Sample(); !errors.Is(err, ErrUnavailable) {
		t.Fatal("picked favorable contradictory envelope", err)
	}
	installTest(t, clock, Interval{11001, 11101})
	source.set(0, 2, nil)
	if _, err = clock.Sample(); !errors.Is(err, ErrUnavailable) {
		t.Fatal("old anchor survived incarnation", err)
	}
	installTest(t, clock, Interval{11001, 11101})
	a, _ := clock.Monotonic()
	source.set(0, 2, ErrUnavailable)
	if _, err = clock.Monotonic(); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	source.set(1, 2, nil)
	b, err := clock.Monotonic()
	if err != nil || a.SameEra(b) {
		t.Fatal("source failure erased by old incarnation", err)
	}
	if _, err = clock.Sample(); !errors.Is(err, ErrUnavailable) {
		t.Fatal("source recovery invented wall anchor", err)
	}
}

func TestDeadlineNoExtensionOrTerminalRevival(t *testing.T) {
	clock, source := testClock(t, &Interval{1000, 1100})
	d, err := NewDeadline(clock, 1500)
	if err != nil {
		t.Fatal(err)
	}
	source.set(100, 1, nil)
	installTest(t, clock, Interval{1100, 1100})
	if remaining, err := d.RemainingMS(); err != nil || remaining != 300 {
		t.Fatal("tighter time extended original deadline", remaining, err)
	}
	if err = d.Tighten(1600); !errors.Is(err, ErrOwner) {
		t.Fatal("absolute cap extended", err)
	}
	source.set(400, 1, nil)
	if err = d.Check(); !errors.Is(err, ErrExpired) {
		t.Fatal(err)
	}
	source.set(0, 2, nil)
	installTest(t, clock, Interval{1000, 1000})
	if err = d.Check(); !errors.Is(err, ErrExpired) {
		t.Fatal("terminal deadline revived", err)
	}
}

func TestAgeRevalidationKeepsOriginalAbsoluteCap(t *testing.T) {
	clock, source := testClock(t, &Interval{1000, 1100})
	d, err := NewAge(clock, 1000, math.MaxUint64)
	if err != nil || d.Cap() != 2000 {
		t.Fatal(err)
	}
	source.set(0, 2, nil)
	if err = d.Check(); !errors.Is(err, ErrUnavailable) {
		t.Fatal("missing new incarnation envelope", err)
	}
	installTest(t, clock, Interval{1700, 1800})
	if err = d.Check(); err != nil {
		t.Fatal(err)
	}
	if d.Cap() != 2000 {
		t.Fatal("age reset at recovery")
	}
	source.set(200, 2, nil)
	if err = d.Check(); !errors.Is(err, ErrExpired) {
		t.Fatal(err)
	}
	if _, err = NewAge(clock, math.MaxUint64, math.MaxUint64); !errors.Is(err, ErrOverflow) {
		t.Fatal(err)
	}
}

func TestLocalWindowDoesNotConsumeWallWidthOrRecover(t *testing.T) {
	clock, source := testClock(t, &Interval{1000, 3000})
	if _, err := NewAge(clock, 2000, math.MaxUint64); !errors.Is(err, ErrExpired) {
		t.Fatal("absolute age ignored initial uncertainty", err)
	}
	w, err := NewWindow(clock, 2000)
	if err != nil {
		t.Fatal(err)
	}
	source.set(1999, 1, nil)
	if err = w.Check(); err != nil {
		t.Fatal("local window incorrectly deducted wall width", err)
	}
	source.set(2000, 1, nil)
	if err = w.Check(); !errors.Is(err, ErrExpired) {
		t.Fatal(err)
	}
	other, err := NewWindow(clock, 2000)
	if err != nil {
		t.Fatal(err)
	}
	source.set(0, 2, nil)
	if err = other.Check(); !errors.Is(err, ErrContinuity) {
		t.Fatal(err)
	}
	installTest(t, clock, Interval{4000, 4000})
	if err = other.Check(); !errors.Is(err, ErrContinuity) {
		t.Fatal("local work recovered on new clock", err)
	}
	clock, source = testClock(t, nil)
	w, err = NewWindow(clock, 2000)
	if err != nil {
		t.Fatal("time bootstrap requires itself", err)
	}
	source.set(500, 1, nil)
	if err = w.Check(); err != nil {
		t.Fatal(err)
	}
}

func TestDirectionalTimePredicates(t *testing.T) {
	i := Interval{1000, 1200}
	if i.ValidBefore(1200) || i.RetainedThrough(1100) {
		t.Fatal("wrong bound or expiry equality")
	}
	if err := i.LowerBound(1100, true); !errors.Is(err, ErrPending) {
		t.Fatal(err)
	}
	if err := i.LowerBound(1201, true); !errors.Is(err, ErrFutureTimestamp) {
		t.Fatal(err)
	}
	if err := i.LowerBound(1201, false); !errors.Is(err, ErrPending) {
		t.Fatal("future not_before treated as forged issuance", err)
	}
	if err := i.LowerBound(1000, true); err != nil {
		t.Fatal(err)
	}
}

func TestDeadlineAndRefreshConcurrentWithCancellation(t *testing.T) {
	clock, _ := testClock(t, &Interval{1000, 1100})
	d, err := NewAge(clock, 1000, 5000)
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	for range 4 {
		workers.Go(func() {
			for range 100 {
				_ = d.Check()
				mark, err := clock.Monotonic()
				if err == nil {
					_ = clock.InstallTrusted(mark, Interval{1000, 1050})
				}
			}
		})
	}
	d.Cancel()
	workers.Wait()
	if err = d.Check(); !errors.Is(err, ErrCancelled) {
		t.Fatal(err)
	}
}

func TestMinimumDelayUsesElapsedLower(t *testing.T) {
	source := &testSource{tick: Tick{Incarnation: [16]byte{1}}}
	clock, err := NewClock(Profile{Rate: Rate{Numerator: 1, Denominator: 2, QuantizationMS: 2}, MaxWidthMS: 100, MaxAgeMS: 10000, MaxRoundTripMS: 1000}, source.read)
	if err != nil {
		t.Fatal(err)
	}
	delay, err := NewDelay(clock, 1000)
	if err != nil {
		t.Fatal(err)
	}
	source.set(1000, 1, nil)
	if left, err := delay.RemainingMS(); !errors.Is(err, ErrPending) || left != 502 {
		t.Fatal("upper elapsed shortened minimum pause", left, err)
	}
	source.set(1502, 1, nil)
	if err = delay.Check(); err != nil {
		t.Fatal(err)
	}
}
