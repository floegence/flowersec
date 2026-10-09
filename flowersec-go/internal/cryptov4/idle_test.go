package cryptov4

import (
	"errors"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

func TestIdleStartsAtOriginalDualReady(t *testing.T) {
	for _, profile := range []string{protocolv4.DHProfileX25519, protocolv4.DHProfileP256} {
		t.Run(profile, func(t *testing.T) {
			now := time.Now()
			clock := cryptoClock(t, func() time.Time { return now })
			client, server := handshakePairWithIdle(t, profile, clock, 100)
			c, s := completeNoise(t, client, server)
			ce, err := c.PrepareRecords(initialRecordConfig())
			if err != nil {
				t.Fatal(err)
			}
			se, err := s.PrepareRecords(initialRecordConfig())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(ce.Close)
			t.Cleanup(se.Close)
			cr, err := c.Ready()
			if err != nil {
				t.Fatal(err)
			}
			sr, err := s.Ready()
			if err != nil {
				t.Fatal(err)
			}
			now = now.Add(150 * time.Millisecond)
			if _, armed, err := se.IdleRemainingMS(); err != nil || armed {
				t.Fatal("pre-READY time consumed idle", armed, err)
			}
			if err = c.MarkReadySubmitted(); err != nil {
				t.Fatal(err)
			}
			if err = c.VerifyReady(sr); err != nil {
				t.Fatal(err)
			}
			if _, err = c.StartRecords(); err != nil {
				t.Fatal(err)
			}
			if err = s.MarkReadySubmitted(); err != nil {
				t.Fatal(err)
			}
			wire := sealed(t, ce, protocolv4.FramePing, 0, nil)
			packet, _, _, err := se.Open(wire, acceptRecord)
			if err != nil {
				t.Fatal(err)
			}
			defer packet.Release()
			if err = packet.Accepted(); err != nil {
				t.Fatal(err)
			}
			now = now.Add(50 * time.Millisecond)
			if err = s.VerifyReady(cr); err != nil {
				t.Fatal(err)
			}
			if _, err = s.StartRecords(); err != nil {
				t.Fatal(err)
			}
			if ms, armed, err := se.IdleRemainingMS(); err != nil || !armed || ms != 100 {
				t.Fatal("READY did not retain original signed policy", ms, armed, err)
			}
			now = now.Add(50 * time.Millisecond)
			if err = packet.Accepted(); err != nil {
				t.Fatal(err)
			}
			if ms, _, err := se.IdleRemainingMS(); err != nil || ms != 50 {
				t.Fatal("retained early record refreshed twice", ms, err)
			}
			now = now.Add(50 * time.Millisecond)
			if _, err = se.Seal(protocolv4.FramePing, 0, nil); !errors.Is(err, ErrIdle) {
				t.Fatal("late timer allowed another ticket", err)
			}
		})
	}
}

func TestApplicationAndPacketWallRepairPreserveOriginalIdleDeadline(t *testing.T) {
	tick := timev4.Tick{Incarnation: [16]byte{1}}
	clock, err := timev4.NewClock(timev4.Profile{Rate: timev4.Rate{Denominator: 1}, MaxWidthMS: 100, MaxAgeMS: 100, MaxRoundTripMS: 100}, func() (timev4.Tick, error) { return tick, nil })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(clock.Close)
	install := func(wall uint64) error {
		t.Helper()
		mark, err := clock.Monotonic()
		if err != nil {
			t.Fatal(err)
		}
		return clock.InstallTrusted(mark, timev4.Interval{LowerMS: wall, UpperMS: wall})
	}
	if err := install(100000); err != nil {
		t.Fatal(err)
	}
	engine, _ := enginePairWithClock(t, protocolv4.DHProfileX25519, clock, func(config *Config) { config.IdleDurationMS = 1000 })
	packet, err := engine.Seal(protocolv4.FrameStreamData, 1, []byte("original provider tail"))
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Release()
	gate, err := engine.PrepareApplicationAcceptance()
	if err != nil {
		t.Fatal(err)
	}
	tick.Milliseconds = 101
	if _, err := clock.Sample(); !errors.Is(err, timev4.ErrUnavailable) {
		t.Fatal("aged wall anchor remained authorized", err)
	}
	if _, err := gate.Check(); !errors.Is(err, timev4.ErrUnavailable) {
		t.Fatal("application gate accepted aged wall time", err)
	}
	if _, err := packet.Bytes(); !errors.Is(err, timev4.ErrUnavailable) {
		t.Fatal("provider gate accepted aged wall time", err)
	}
	if err := install(100101); err != nil {
		t.Fatal(err)
	}
	if _, err := gate.Check(); err != nil {
		t.Fatal("same-era anchor repair poisoned application idle", err)
	}
	if _, err := packet.Bytes(); err != nil {
		t.Fatal("same-era anchor repair poisoned provider idle", err)
	}
	tick.Milliseconds = 102
	if err := install(400000); !errors.Is(err, timev4.ErrContradiction) {
		t.Fatal("wall contradiction remained authorized", err)
	}
	if _, err := gate.Check(); !errors.Is(err, timev4.ErrUnavailable) {
		t.Fatal("application gate accepted invalid wall trust", err)
	}
	if _, err := packet.Bytes(); !errors.Is(err, timev4.ErrUnavailable) {
		t.Fatal("provider gate accepted invalid wall trust", err)
	}
	if err := install(100102); err != nil {
		t.Fatal(err)
	}
	if _, err := gate.Check(); !errors.Is(err, timev4.ErrUnavailable) {
		t.Fatal("wall repair revived retired application authorization", err)
	}
	current, err := engine.PrepareApplicationAcceptance()
	if err != nil {
		t.Fatal("wall repair poisoned original idle", err)
	}
	if _, err := current.Check(); err != nil {
		t.Fatal(err)
	}
	if _, err := packet.Bytes(); err != nil {
		t.Fatal(err)
	}
	tick.Milliseconds = 1000
	if err := install(101000); err != nil {
		t.Fatal(err)
	}
	if _, err := current.Check(); !errors.Is(err, ErrIdle) {
		t.Fatal("wall repair extended application idle deadline", err)
	}
	if _, err := packet.Bytes(); !errors.Is(err, ErrIdle) {
		t.Fatal("wall repair extended provider idle deadline", err)
	}
}
