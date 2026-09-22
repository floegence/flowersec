package cryptov4

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
)

func initialRecordConfig() Config {
	return Config{MaxFrame: 4096, MaxScopes: 4, PendingScopes: 2, WorkSlots: 2, Datagrams: true, Maintenance: MaintenanceReserve{Calls: 4, Blocks: 128, Bytes: 1024}}
}

func TestInitialRecordsPreservePrivateInputAcrossDualReady(t *testing.T) {
	for _, profile := range []string{protocolv4.DHProfileX25519, protocolv4.DHProfileP256} {
		t.Run(profile, func(t *testing.T) {
			client, server := handshakePair(t, profile)
			c, s := completeNoise(t, client, server)
			if _, err := c.Ready(); !errors.Is(err, ErrNotReady) {
				t.Fatal("READY signed before record reservation", err)
			}
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
			if _, err = c.PrepareRecords(initialRecordConfig()); !errors.Is(err, ErrHandshake) {
				t.Fatal("second record owner", err)
			}
			if err = se.Activate(); !errors.Is(err, ErrNotReady) {
				t.Fatal("direct activation bypassed handshake", err)
			}
			cr, err := c.Ready()
			if err != nil {
				t.Fatal(err)
			}
			sr, err := s.Ready()
			if err != nil {
				t.Fatal(err)
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
			if err = ce.OpenLocalScope(3); err != nil {
				t.Fatal(err)
			}
			wire := sealed(t, ce, protocolv4.FrameOpenStream, 3, []byte("original early OPEN"))
			if _, _, err = se.OpenIncoming(wire, acceptRecord); !errors.Is(err, ErrNotReady) {
				t.Fatal("input before own READY ticket", err)
			}
			if err = s.MarkReadySubmitted(); err != nil {
				t.Fatal(err)
			}
			packet, incoming, err := se.OpenIncoming(wire, acceptRecord)
			if err != nil {
				t.Fatal(err)
			}
			defer packet.Release()
			plain, err := packet.Bytes()
			if err != nil || !bytes.Equal(plain, []byte("original early OPEN")) {
				t.Fatal("private reader could not take over original bytes", err)
			}
			if err = incoming.Resolve(true); !errors.Is(err, ErrNotReady) {
				t.Fatal("outcome before peer proof", err)
			}
			if err = se.ApplicationInputReady(0); !errors.Is(err, ErrNotReady) {
				t.Fatal("application delivery before peer proof", err)
			}
			if _, err = se.Seal(protocolv4.FramePing, 0, nil); !errors.Is(err, ErrNotReady) {
				t.Fatal("ordinary output before peer proof", err)
			}
			if err = s.VerifyReady(cr); err != nil {
				t.Fatal(err)
			}
			started, err := s.StartRecords()
			if err != nil || started != se {
				t.Fatal("READY replaced original receive owner", err)
			}
			if err = incoming.PrepareAccept(); err != nil {
				t.Fatal(err)
			}
			if err = incoming.Resolve(true); err != nil {
				t.Fatal(err)
			}
			frontier, err := se.ScopeFrontier(3, protocolv4.ClientToServer)
			if err != nil || frontier.Sequence != 1 {
				t.Fatal("READY reset authenticated frontier", frontier, err)
			}
			if _, _, _, err = se.Open(wire, acceptRecord); !errors.Is(err, ErrSequence) {
				t.Fatal("early OPEN replayed after READY", err)
			}
			if err = se.ApplicationInputReady(0); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestInitialRecordsCloseAndDeadlineRevokePrivateInput(t *testing.T) {
	for _, failure := range []string{"close", "forged_ready", "deadline"} {
		t.Run(failure, func(t *testing.T) {
			now := time.Now()
			client, server := handshakePairWithClock(t, protocolv4.DHProfileX25519, cryptoClock(t, func() time.Time { return now }))
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
			cr, err := c.Ready()
			if err != nil {
				t.Fatal(err)
			}
			sr, err := s.Ready()
			if err != nil {
				t.Fatal(err)
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
			wire := sealed(t, ce, protocolv4.FrameDatagram, protocolv4.DatagramScope(), []byte("early"))
			packet, _, _, err := se.Open(wire, acceptRecord)
			if err != nil {
				t.Fatal(err)
			}
			defer packet.Release()
			switch failure {
			case "close":
				s.Close()
			case "forged_ready":
				cr[len(cr)-1] ^= 1
				if err = s.VerifyReady(cr); !errors.Is(err, ErrHandshake) {
					t.Fatal(err)
				}
			case "deadline":
				now = now.Add(time.Minute)
			}
			if _, err = packet.Bytes(); err == nil {
				t.Fatal("failed establishment retained private receive authority")
			}
			if _, err = s.StartRecords(); !errors.Is(err, ErrNotReady) {
				t.Fatal("failed establishment published Session", err)
			}
		})
	}
}
