package cryptov4

import (
	"bytes"
	"errors"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
)

func TestIncomingScopeRetainsOnePositionFromDerivationThroughAuthentication(t *testing.T) {
	client, server, _ := enginePair(t, protocolv4.DHProfileX25519, func(c *Config) { c.PendingScopes = 1 })
	if err := client.OpenLocalScope(3); err != nil {
		t.Fatal(err)
	}
	wire := sealed(t, client, protocolv4.FrameOpenStream, 3, nil)
	var held []*Packet
	for range server.config.WorkSlots {
		p, err := server.Seal(protocolv4.FrameStreamData, 1, nil)
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, p)
		defer p.Release()
	}
	before := server.derivations
	if _, _, err := server.OpenIncoming(wire, acceptRecord); !errors.Is(err, ErrCapacity) || server.derivations != before || server.pending != 0 {
		t.Fatal("unavailable input position performed KDF", err, server.derivations)
	}
	held[0].Release()
	packet, owner, err := server.OpenIncoming(wire, func(protocolv4.FrameType, protocolv4.RecordHeader, []byte) error {
		if len(server.free) != 0 || server.derivations != before+1 {
			t.Fatal("KDF position did not transfer to AEAD")
		}
		return nil
	})
	if err != nil || owner == nil || server.derivations != before+1 {
		t.Fatal(owner, err)
	}
	packet.Release()
	if err := owner.Resolve(false); err != nil {
		t.Fatal(err)
	}
}

func TestIncomingScopeTemporaryKeyAndPermanentOutcome(t *testing.T) {
	client, server, _ := enginePair(t, protocolv4.DHProfileX25519, func(c *Config) {
		c.PendingScopes = 1
		if c.SendDirection == protocolv4.ServerToClient {
			c.MaxScopes = 1 // Its existing accepted ID 1 consumes this slot.
		}
	})
	if err := client.OpenLocalScope(3); err != nil {
		t.Fatal(err)
	}
	wire := sealed(t, client, protocolv4.FrameOpenStream, 3, []byte("crypto-layer OPEN"))
	before := server.derivations
	bad := bytes.Clone(wire)
	bad[len(bad)-1] ^= 1
	if _, _, err := server.OpenIncoming(bad, acceptRecord); !errors.Is(err, ErrAuthentication) {
		t.Fatal(err)
	}
	if server.pending != 0 || !server.unusedScope(3) || server.derivations != before+1 {
		t.Fatal("failed authentication created a logical scope or refunded KDF")
	}
	packet, incoming, err := server.OpenIncoming(wire, acceptRecord)
	if err != nil {
		t.Fatal(err)
	}
	packet.Release()
	if server.active != 1 || server.pending != 1 || !server.unusedScope(3) {
		t.Fatal("pending consumed accepted resources")
	}
	if _, _, err := server.OpenIncoming(wire, acceptRecord); !errors.Is(err, ErrScope) {
		t.Fatal("duplicate association", err)
	}
	if err := incoming.Resolve(true); !errors.Is(err, ErrCapacity) {
		t.Fatal(err)
	}
	if server.pending != 1 {
		t.Fatal("resource denial lost pending owner")
	}
	if err := incoming.Resolve(false); err != nil {
		t.Fatal(err)
	}
	if server.active != 1 || server.pending != 0 || server.unusedScope(3) {
		t.Fatal("rejection did not permanently consume ID")
	}
	if err := incoming.Resolve(true); !errors.Is(err, ErrScope) {
		t.Fatal("second outcome", err)
	}
	if _, _, err := server.OpenIncoming(wire, acceptRecord); !errors.Is(err, ErrScope) {
		t.Fatal("rejected ID reused", err)
	}
}

func TestIncomingScopeAcceptanceTransfersOriginalFrontier(t *testing.T) {
	for _, profile := range []string{protocolv4.DHProfileX25519, protocolv4.DHProfileP256} {
		t.Run(profile, func(t *testing.T) {
			client, server, _ := enginePair(t, profile, func(c *Config) { c.PendingScopes = 1 })
			if err := client.OpenLocalScope(3); err != nil {
				t.Fatal(err)
			}
			wire := sealed(t, client, protocolv4.FrameOpenStream, 3, nil)
			packet, incoming, err := server.OpenIncoming(wire, acceptRecord)
			if err != nil {
				t.Fatal(err)
			}
			packet.Release()
			if err := incoming.PrepareAccept(); err != nil {
				t.Fatal(err)
			}
			if err := incoming.Resolve(true); err != nil {
				t.Fatal(err)
			}
			if err := client.AcceptLocalScope(3); err != nil {
				t.Fatal(err)
			}
			for _, e := range []*Engine{client, server} {
				c2s, err := e.ScopeFrontier(3, protocolv4.ClientToServer)
				if err != nil || c2s.Sequence != 1 {
					t.Fatal(c2s, err)
				}
				s2c, err := e.ScopeFrontier(3, protocolv4.ServerToClient)
				if err != nil || s2c.Sequence != 0 {
					t.Fatal(s2c, err)
				}
			}
			if _, err := client.Seal(protocolv4.FrameOpenStream, 3, nil); !errors.Is(err, ErrNotReady) {
				t.Fatal("OPEN replayed after accepted", err)
			}
		})
	}
}
