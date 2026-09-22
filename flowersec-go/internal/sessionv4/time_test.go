package sessionv4

import (
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

func sessionTestClock(t *testing.T) *timev4.Clock {
	t.Helper()
	origin := time.Now()
	return newTestRekeyClock(t, RekeyClockRate{Numerator: 1, Denominator: 10000, QuantizationMS: 2}, func() (RekeyClockSample, error) {
		return RekeyClockSample{Milliseconds: uint64(time.Since(origin) / time.Millisecond), Incarnation: [16]byte{1}}, nil
	})
}

func rekeyTestDeadline(t *testing.T, e *cryptov4.Engine) uint64 {
	t.Helper()
	sample, err := e.Clock().Sample()
	if err != nil {
		t.Fatal(err)
	}
	return sample.LowerMS + 60000
}

func streamTestDeadline(t *testing.T, e *cryptov4.Engine) *timev4.Deadline {
	t.Helper()
	d, err := timev4.NewAge(e.Clock(), 60000, ^uint64(0))
	if err != nil {
		t.Fatal(err)
	}
	return d
}
