package cryptov4

import (
	"bytes"
	"errors"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
)

func TestReliableOutputReturnsCryptoButRetainsOriginalCleanup(t *testing.T) {
	for _, profile := range []string{protocolv4.DHProfileX25519, protocolv4.DHProfileP256} {
		t.Run(profile, func(t *testing.T) {
			e, peer, _ := enginePair(t, profile, func(c *Config) { c.WorkSlots = 1 })
			p, err := e.Seal(protocolv4.FrameStreamData, 1, []byte("original ciphertext"))
			if err != nil {
				t.Fatal(err)
			}
			defer p.Release()
			wire, err := p.Bytes()
			if err != nil {
				t.Fatal(err)
			}
			want := bytes.Clone(wire)
			if err := p.MoveReliableOutput(make([]byte, len(wire)-1)); !errors.Is(err, ErrConfiguration) {
				t.Fatal(err)
			}
			if e.borrowedWork != 1 || e.detachedPackets != 0 {
				t.Fatal("failed transfer changed ownership")
			}
			output := make([]byte, len(wire))
			if err := p.MoveReliableOutput(output); err != nil {
				t.Fatal(err)
			}
			if e.borrowedWork != 0 || e.outgoingPackets != 1 || e.detachedPackets != 1 || !bytes.Equal(output, want) {
				t.Fatal("publication lost original accounting")
			}
			if err := p.MoveReliableOutput(output); !errors.Is(err, ErrConfiguration) {
				t.Fatal("transferred twice", err)
			}
			in, _, _, err := peer.Open(output, acceptRecord)
			if err != nil {
				t.Fatal(err)
			}
			in.Release()
			// The only shared workspace is immediately available to another job.
			next, err := e.Seal(protocolv4.FrameStreamData, 1, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := next.MoveReliableOutput(make([]byte, 4096)); !errors.Is(err, ErrCapacity) {
				t.Fatal("duplicated same-key detached output", err)
			}
			next.Release()
			e.Close()
			requireEngineCleanupPending(t, e)
			if !bytes.Equal(output, want) {
				t.Fatal("Close erased provider's live output")
			}
			if _, err := p.Bytes(); !errors.Is(err, ErrClosed) {
				t.Fatal(err)
			}
			p.Release()
			requireEngineCleanup(t, e)
			if !bytes.Equal(output, make([]byte, len(output))) || e.detachedPackets != 0 {
				t.Fatal("original output not erased and retired")
			}
		})
	}
}

func TestNativeInputPartitionSurvivesOutgoingPressure(t *testing.T) {
	e, peer, _ := enginePair(t, protocolv4.DHProfileX25519, func(c *Config) { c.WorkSlots = 2 })
	if err := e.ReserveNativeInput(1); err != nil {
		t.Fatal(err)
	}
	if e.OrdinaryWorkSlots() != 1 {
		t.Fatal("partition added outgoing capacity")
	}
	held, err := e.Seal(protocolv4.FrameStreamData, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Release()
	if _, err := e.Seal(protocolv4.FrameStreamData, 1, nil); !errors.Is(err, ErrCapacity) {
		t.Fatal(err)
	}
	wire := sealed(t, peer, protocolv4.FrameStreamData, 1, []byte("independent receive"))
	in, _, _, err := e.Open(wire, acceptRecord)
	if err != nil {
		t.Fatal("outgoing pressure consumed input partition", err)
	}
	in.Release()
	e.Close()
	requireEngineCleanupPending(t, e)
	held.Release()
	requireEngineCleanup(t, e)
}
