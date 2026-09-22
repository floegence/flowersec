package cryptov4

import (
	"errors"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
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
