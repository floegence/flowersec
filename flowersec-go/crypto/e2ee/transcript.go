package e2ee

import (
	"crypto/sha256"
	"errors"

	"github.com/floegence/flowersec/flowersec-go/internal/bin"
)

// ErrInvalidTranscriptInput signals a missing or oversized transcript field.
var ErrInvalidTranscriptInput = errors.New("invalid transcript input")

// TranscriptInputs captures the deterministic fields hashed into the transcript.
type TranscriptInputs struct {
	Version        uint8    // Protocol version byte.
	Suite          uint16   // Numeric suite identifier.
	Role           uint8    // Role byte (client/server).
	ClientFeatures uint32   // Client feature bitset.
	ServerFeatures uint32   // Server feature bitset.
	ChannelID      string   // Shared channel identifier.
	NonceC         [32]byte // Client nonce.
	NonceS         [32]byte // Server nonce.
	ClientEphPub   []byte   // Client ephemeral public key bytes.
	ServerEphPub   []byte   // Server ephemeral public key bytes.
}

// TranscriptHash computes the SHA-256 hash of the canonical handshake transcript.
func TranscriptHash(in TranscriptInputs) ([32]byte, error) {
	if in.ChannelID == "" {
		return [32]byte{}, ErrInvalidTranscriptInput
	}
	if len(in.ClientEphPub) == 0 || len(in.ServerEphPub) == 0 {
		return [32]byte{}, ErrInvalidTranscriptInput
	}

	channelIDBytes := []byte(in.ChannelID)
	if len(channelIDBytes) > 0xffff {
		return [32]byte{}, ErrInvalidTranscriptInput
	}
	if len(in.ClientEphPub) > 0xffff || len(in.ServerEphPub) > 0xffff {
		return [32]byte{}, ErrInvalidTranscriptInput
	}

	// transcript =
	//   "flowersec-e2ee-v1" ||
	//   version:u8 ||
	//   suite:u16be ||
	//   role:u8 ||
	//   client_features:u32be ||
	//   server_features:u32be ||
	//   channel_id_len:u16be || channel_id ||
	//   nonce_c(32) || nonce_s(32) ||
	//   client_pub_len:u16be || client_pub ||
	//   server_pub_len:u16be || server_pub
	prefix := []byte("flowersec-e2ee-v1")
	size := len(prefix) + 1 + 2 + 1 + 4 + 4 + 2 + len(channelIDBytes) + 32 + 32 + 2 + len(in.ClientEphPub) + 2 + len(in.ServerEphPub)
	buf := make([]byte, 0, size)
	buf = append(buf, prefix...)
	buf = append(buf, in.Version)
	tmp := make([]byte, 8)
	bin.PutU16BE(tmp[:2], in.Suite)
	buf = append(buf, tmp[:2]...)
	buf = append(buf, in.Role)
	bin.PutU32BE(tmp[:4], in.ClientFeatures)
	buf = append(buf, tmp[:4]...)
	bin.PutU32BE(tmp[:4], in.ServerFeatures)
	buf = append(buf, tmp[:4]...)
	bin.PutU16BE(tmp[:2], uint16(len(channelIDBytes)))
	buf = append(buf, tmp[:2]...)
	buf = append(buf, channelIDBytes...)
	buf = append(buf, in.NonceC[:]...)
	buf = append(buf, in.NonceS[:]...)
	bin.PutU16BE(tmp[:2], uint16(len(in.ClientEphPub)))
	buf = append(buf, tmp[:2]...)
	buf = append(buf, in.ClientEphPub...)
	bin.PutU16BE(tmp[:2], uint16(len(in.ServerEphPub)))
	buf = append(buf, tmp[:2]...)
	buf = append(buf, in.ServerEphPub...)

	return sha256.Sum256(buf), nil
}
