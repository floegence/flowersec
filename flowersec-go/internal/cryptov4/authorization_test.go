package cryptov4

import (
	"errors"
	"sync/atomic"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
)

// Synthetic authority for isolated crypto tests only. It grants no provider,
// TrustConfig or deployment qualification.
type testAuthorization struct{}

func (testAuthorization) Check() error                 { return nil }
func (testAuthorization) RemainingMS() (uint64, error) { return ^uint64(0), nil }
func (testAuthorization) Wake() <-chan struct{}        { return nil }
func (testAuthorization) Notify()                      {}
func (testAuthorization) Close(error)                  {}

var errTestRevoked = errors.New("original authorization revoked")

type revocableAuthorization struct{ rejected atomic.Bool }

func (g *revocableAuthorization) Check() error {
	if g.rejected.Load() {
		return errTestRevoked
	}
	return nil
}
func (g *revocableAuthorization) RemainingMS() (uint64, error) { return ^uint64(0), g.Check() }
func (*revocableAuthorization) Wake() <-chan struct{}          { return nil }
func (*revocableAuthorization) Notify()                        {}
func (g *revocableAuthorization) Close(error)                  { g.rejected.Store(true) }

func TestCurrentAuthorizationSealsRecordUseAndPublication(t *testing.T) {
	client, server, _ := enginePair(t, protocolv4.DHProfileX25519)
	guard := &revocableAuthorization{}
	client.config.Authorization, server.config.Authorization = guard, guard
	packet, err := client.Seal(protocolv4.FrameStreamData, 1, []byte("before revocation"))
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Release()
	wire, err := packet.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	guard.rejected.Store(true)
	if err := packet.Published(); !errors.Is(err, errTestRevoked) {
		t.Fatal("late publication accepted", err)
	}
	if _, err := client.Seal(protocolv4.FrameStreamData, 1, nil); !errors.Is(err, errTestRevoked) {
		t.Fatal("new ticket accepted", err)
	}
	called := false
	if _, _, _, err := server.Open(wire, func(protocolv4.FrameType, protocolv4.RecordHeader, []byte) error { called = true; return nil }); !errors.Is(err, errTestRevoked) || called {
		t.Fatal("revoked input exposed", err, called)
	}
	config := client.config
	config.Authorization = nil
	if _, err := NewEngine(config); !errors.Is(err, ErrConfiguration) {
		t.Fatal("missing current authority accepted", err)
	}
}

func TestOriginalHandshakeAuthorizationTransfersToRecords(t *testing.T) {
	client, server := handshakePair(t, protocolv4.DHProfileX25519)
	guard := &revocableAuthorization{}
	client.config.Authorization = guard
	c, _ := completeNoise(t, client, server)
	records := initialRecordConfig()
	records.Authorization = testAuthorization{}
	engine, err := c.PrepareRecords(records)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(engine.Close)
	if engine.config.Authorization != guard {
		t.Fatal("record template replaced original guard")
	}
	guard.rejected.Store(true)
	if _, err := c.Ready(); err == nil {
		t.Fatal("READY signed after current trust rejection")
	}
}
