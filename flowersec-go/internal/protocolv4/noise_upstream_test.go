package protocolv4

import (
	"bytes"
	"encoding/hex"
	"testing"

	upstream "github.com/flynn/noise"
)

// Keep the unmodified pinned upstream library as an independent X25519
// comparison for the vendored interface extension. Neither is a runtime API.
func TestV4NoiseOriginalX25519Library(t *testing.T) {
	corpus := loadNoiseCorpus(t)
	count := 0
	for _, vector := range corpus.Transcripts {
		if vector.Profile != DHProfileX25519 {
			continue
		}
		for _, initiator := range []bool{true, false} {
			count++
			input := corpus.input(t, vector.Profile, initiator)
			state, err := upstream.NewHandshakeState(upstream.Config{
				CipherSuite: upstream.NewCipherSuite(upstream.DH25519, upstream.CipherChaChaPoly, upstream.HashSHA256),
				Pattern:     upstream.HandshakeKK, Initiator: initiator,
				Random: bytes.NewReader(input.ephemeral), Prologue: input.prologue,
				PresharedKey: input.psk, PresharedKeyPlacement: 0,
				StaticKeypair: upstream.DHKey{Private: input.private, Public: input.public}, PeerStatic: input.remote,
			})
			if err != nil {
				t.Fatal(err)
			}
			if !initiator {
				payload, a, b, err := state.ReadMessage(nil, noiseHex(t, vector.Message1))
				if err != nil || len(payload) != 0 || a != nil || b != nil {
					t.Fatal("upstream first read", err)
				}
			}
			message, a, b, err := state.WriteMessage(nil, nil)
			want := vector.Message2
			if initiator {
				want = vector.Message1
			}
			if err != nil || hex.EncodeToString(message) != want {
				t.Fatal("upstream message differs", err)
			}
			if initiator {
				if a != nil || b != nil {
					t.Fatal("upstream premature completion")
				}
				var payload []byte
				payload, a, b, err = state.ReadMessage(nil, noiseHex(t, vector.Message2))
				if err != nil || len(payload) != 0 {
					t.Fatal("upstream second read", err)
				}
			}
			if a == nil || b == nil || hex.EncodeToString(state.ChannelBinding()) != vector.Hash {
				t.Fatal("upstream completion differs")
			}
			i2r, r2i := a.UnsafeKey(), b.UnsafeKey()
			if hex.EncodeToString(i2r[:]) != vector.I2R || hex.EncodeToString(r2i[:]) != vector.R2I {
				t.Fatal("upstream Split differs")
			}
			clear(i2r[:])
			clear(r2i[:])
		}
	}
	if count != 2 {
		t.Fatal("missing original-library comparisons")
	}
}
