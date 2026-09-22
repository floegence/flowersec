package cryptov4

import (
	"errors"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

// Test fixtures supply a synthetic authenticated envelope. This adapter is not
// a production assertion that time.Now has a qualified wall-clock error bound.
func cryptoClock(t *testing.T, source func() time.Time) *timev4.Clock {
	t.Helper()
	origin := source()
	c, err := timev4.NewClock(timev4.Profile{Rate: timev4.Rate{Denominator: 1}, MaxWidthMS: 30000, MaxAgeMS: 3600000, MaxRoundTripMS: 1000}, func() (timev4.Tick, error) {
		now := source()
		if now.Before(origin) {
			return timev4.Tick{}, timev4.ErrContinuity
		}
		return timev4.Tick{Milliseconds: uint64(now.Sub(origin) / time.Millisecond), Incarnation: [16]byte{1}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	mark, err := c.Monotonic()
	if err != nil {
		t.Fatal(err)
	}
	ms := uint64(origin.UnixMilli()) + mark.Milliseconds
	if err = c.InstallTrusted(mark, timev4.Interval{LowerMS: ms, UpperMS: ms}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}

type clockTicketGuard struct {
	advance   func()
	submitted bool
}

func (g *clockTicketGuard) LockTicket() error           { g.advance(); return nil }
func (g *clockTicketGuard) UnlockTicket(submitted bool) { g.submitted = submitted }

func TestRecordTicketRechecksOriginalTimeAfterGuard(t *testing.T) {
	e, _, now := enginePair(t, protocolv4.DHProfileX25519)
	deadline := e.current.deadline.Cap()
	guard := &clockTicketGuard{advance: func() { *now = now.Add(time.Duration(deadline-e.config.RootBorn.LowerMS) * time.Millisecond) }}
	_, err := e.SealBuildGuard(protocolv4.FrameStreamData, 1, 0, func(protocolv4.RecordHeader, []byte) (int, error) {
		t.Fatal("expired ticket reached encoder")
		return 0, nil
	}, nil, guard)
	if !errors.Is(err, ErrExpired) || guard.submitted || e.current.keys.get(1).keys[0].next != 0 {
		t.Fatal("deadline crossed while entering ticket", err, guard.submitted)
	}
}

func TestRootClockIncarnationRetainsOriginalAge(t *testing.T) {
	for _, profile := range []string{protocolv4.DHProfileX25519, protocolv4.DHProfileP256} {
		t.Run(profile, func(t *testing.T) {
			tick := timev4.Tick{Incarnation: [16]byte{1}}
			clock, err := timev4.NewClock(timev4.Profile{Rate: timev4.Rate{Denominator: 1}, MaxWidthMS: 100, MaxAgeMS: 3600000, MaxRoundTripMS: 1000}, func() (timev4.Tick, error) { return tick, nil })
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(clock.Close)
			install := func(ms uint64) {
				mark, err := clock.Monotonic()
				if err != nil {
					t.Fatal(err)
				}
				if err = clock.InstallTrusted(mark, timev4.Interval{LowerMS: ms, UpperMS: ms}); err != nil {
					t.Fatal(err)
				}
			}
			install(100000)
			e, _ := enginePairWithClock(t, profile, clock)
			cap := e.current.deadline.Cap()
			packet, err := e.Seal(protocolv4.FrameStreamData, 1, []byte("original provider tail"))
			if err != nil {
				t.Fatal(err)
			}
			defer packet.Release()
			tick.Incarnation[0]++
			if _, err = packet.Bytes(); !errors.Is(err, timev4.ErrUnavailable) {
				t.Fatal("used old anchor after clock change", err)
			}
			install(cap - 100)
			if _, err = packet.Bytes(); err != nil {
				t.Fatal("continuous protocol owner could not revalidate original cap", err)
			}
			if e.current.deadline.Cap() != cap {
				t.Fatal("root age reset")
			}
			tick.Milliseconds = 100
			if _, err = packet.Bytes(); !errors.Is(err, ErrExpired) {
				t.Fatal(err)
			}
			tick.Incarnation[0]++
			tick.Milliseconds = 0
			install(100000)
			if _, err = packet.Bytes(); !errors.Is(err, ErrExpired) {
				t.Fatal("expired root revived", err)
			}
			if _, err = e.Seal(protocolv4.FrameStreamData, 1, nil); !errors.Is(err, ErrExpired) {
				t.Fatal(err)
			}
		})
	}
}

func cryptoSample(t *testing.T, e *Engine) timev4.Sample {
	t.Helper()
	s, err := e.Clock().Sample()
	if err != nil {
		t.Fatal(err)
	}
	return s
}
