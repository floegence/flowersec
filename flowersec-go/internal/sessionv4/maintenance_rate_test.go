package sessionv4

import (
	"errors"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

func TestMaintenanceRateSustainedTrafficPreservesQuantizationCredit(t *testing.T) {
	var tick uint64
	rate := timev4.Rate{Numerator: 1, Denominator: 10000, QuantizationMS: 2}
	clock := newTestRekeyClock(t, rate, func() (timev4.Tick, error) {
		return timev4.Tick{Milliseconds: tick, Incarnation: [16]byte{1}}, nil
	})
	var refill maintenanceRefill
	tokens := uint32(256)
	// Two maintenance records per stream, faster than one record per quantum
	// but below the declared sustained rate, must not consume the whole burst.
	for stream := range 1024 {
		tick = uint64(stream * 3)
		for range 2 {
			mark, err := clock.Monotonic()
			if err != nil {
				t.Fatal(err)
			}
			if err = refill.consume(mark, rate, 1, 256, &tokens); err != nil {
				t.Fatal("legal sustained maintenance was refused", stream, err)
			}
		}
	}
}

func TestMaintenanceRateBurstFractionAndContinuity(t *testing.T) {
	var tick uint64
	incarnation := [16]byte{1}
	rate := timev4.Rate{Denominator: 1, QuantizationMS: 2}
	clock := newTestRekeyClock(t, rate, func() (timev4.Tick, error) {
		return timev4.Tick{Milliseconds: tick, Incarnation: incarnation}, nil
	})
	var refill maintenanceRefill
	tokens := uint32(4)
	consume := func() error {
		mark, err := clock.Monotonic()
		if err != nil {
			return err
		}
		return refill.consume(mark, rate, 100, 4, &tokens)
	}
	for range 4 {
		if err := consume(); err != nil {
			t.Fatal(err)
		}
	}
	for tick = 1; tick < 102; tick++ {
		if err := consume(); !errors.Is(err, ErrMaintenanceRate) {
			t.Fatal("refilled before proven lower bound", tick, err)
		}
	}
	if err := consume(); err != nil {
		t.Fatal("refused attempts moved the refill origin", err)
	}
	tick = 303
	for range 2 {
		if err := consume(); err != nil {
			t.Fatal("elapsed intervals were lost", err)
		}
	}
	if err := consume(); !errors.Is(err, ErrMaintenanceRate) {
		t.Fatal("fractional elapsed time funded a whole token", err)
	}
	tick = 1000000
	for range 4 {
		if err := consume(); err != nil {
			t.Fatal(err)
		}
	}
	if err := consume(); !errors.Is(err, ErrMaintenanceRate) {
		t.Fatal("idle time exceeded the finite burst", err)
	}
	incarnation = [16]byte{2}
	if err := consume(); !errors.Is(err, timev4.ErrContinuity) {
		t.Fatal("new clock incarnation refilled old owner", err)
	}
	incarnation = [16]byte{1}
	if err := consume(); !errors.Is(err, timev4.ErrContinuity) {
		t.Fatal("failed original rate owner revived", err)
	}
}
