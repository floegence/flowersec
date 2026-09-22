package cryptov4

import (
	"errors"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
)

func TestServiceInitializationBeforeReadyDoesNotEnableIO(t *testing.T) {
	for _, profile := range []string{protocolv4.DHProfileX25519, protocolv4.DHProfileP256} {
		client, server := handshakePair(t, profile)
		c, s := completeNoise(t, client, server)
		for _, finished := range []*FinishedHandshake{c, s} {
			e, err := finished.PrepareRecords(initialRecordConfig())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(e.Close)
			if epoch, err := e.ServiceInitializationEpoch(); err != nil || epoch != 0 {
				t.Fatal("original maintenance initialization unavailable", epoch, err)
			}
			if err := e.ReserveSharedInput(); err != nil {
				t.Fatal("original shared reader unavailable", err)
			}
			if err := e.ReserveSharedInput(); !errors.Is(err, ErrConfiguration) {
				t.Fatal("duplicate shared reader", err)
			}
			if _, err := e.ScopeFrontier(0, e.config.SendDirection); !errors.Is(err, ErrNotReady) {
				t.Fatal("service setup exposed a record frontier", err)
			}
			if _, err := e.Seal(protocolv4.FramePing, 0, nil); !errors.Is(err, ErrNotReady) {
				t.Fatal("service setup enabled publication", err)
			}
			if _, err := e.BeginRekey(e.config.AuthorizationDeadlineMS); !errors.Is(err, ErrNotReady) {
				t.Fatal("service setup began a rekey round", err)
			}
			if err := e.OpenLocalScope(3 + uint64(e.config.SendDirection)); !errors.Is(err, ErrNotReady) {
				t.Fatal("service setup opened an application scope", err)
			}
			if _, err := finished.Ready(); err != nil {
				t.Fatal(err)
			}
			if _, err := e.ServiceInitializationEpoch(); !errors.Is(err, ErrTransition) {
				t.Fatal("service setup remained open after READY signing", err)
			}
		}
	}
}

func TestServiceInitializationKeepsOriginalHandshakeLifetime(t *testing.T) {
	for _, failure := range []string{"close", "deadline", "unsigned_engine"} {
		t.Run(failure, func(t *testing.T) {
			now := time.Now()
			client, server := handshakePairWithClock(t, protocolv4.DHProfileX25519, cryptoClock(t, func() time.Time { return now }))
			finished, _ := completeNoise(t, client, server)
			e, err := finished.PrepareRecords(initialRecordConfig())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(e.Close)
			switch failure {
			case "close":
				finished.Close()
			case "deadline":
				now = now.Add(61 * time.Second)
			case "unsigned_engine":
				e.initial = nil
			}
			if _, err := e.ServiceInitializationEpoch(); err == nil {
				t.Fatal("invalid original owner initialized service")
			}
			if err := e.ReserveSharedInput(); err == nil || e.sharedInputReserved {
				t.Fatal("invalid original owner reserved shared input", err)
			}
		})
	}
}
