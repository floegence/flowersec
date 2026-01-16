package e2ee

import (
	"errors"
	"fmt"

	"github.com/floegence/flowersec/internal/bin"
)

const (
	handshakeHeaderLen = 4 + 1 + 1 + 4
	recordHeaderLen    = 4 + 1 + 1 + 8 + 4
)

var (
	// ErrInvalidMagic indicates the frame prefix is not recognized.
	ErrInvalidMagic = errors.New("invalid magic")
	// ErrInvalidVersion signals the wire protocol version mismatched.
	ErrInvalidVersion = errors.New("invalid version")
	// ErrInvalidLength indicates a malformed or truncated frame length.
	ErrInvalidLength = errors.New("invalid length")
)

// EncodeHandshakeFrame wraps a JSON payload with the handshake header.
func EncodeHandshakeFrame(handshakeType uint8, payloadJSON []byte) []byte {
	out := make([]byte, handshakeHeaderLen+len(payloadJSON))
	copy(out[:4], []byte(HandshakeMagic))
	out[4] = ProtocolVersion
	out[5] = handshakeType
	bin.PutU32BE(out[6:10], uint32(len(payloadJSON)))
	copy(out[10:], payloadJSON)
	return out
}

// DecodeHandshakeFrame validates and extracts a handshake frame.
func DecodeHandshakeFrame(frame []byte, maxPayload int) (handshakeType uint8, payloadJSON []byte, err error) {
	if len(frame) < handshakeHeaderLen {
		return 0, nil, ErrInvalidLength
	}
	if string(frame[:4]) != HandshakeMagic {
		return 0, nil, ErrInvalidMagic
	}
	if frame[4] != ProtocolVersion {
		return 0, nil, ErrInvalidVersion
	}
	handshakeType = frame[5]
	n := int(bin.U32BE(frame[6:10]))
	if n < 0 || n > len(frame)-handshakeHeaderLen {
		return 0, nil, ErrInvalidLength
	}
	if maxPayload > 0 && n > maxPayload {
		return 0, nil, fmt.Errorf("handshake payload too large: %w", ErrInvalidLength)
	}
	if handshakeHeaderLen+n != len(frame) {
		return 0, nil, ErrInvalidLength
	}
	return handshakeType, frame[10:], nil
}

// LooksLikeRecordFrame quickly checks a frame header without decrypting.
func LooksLikeRecordFrame(frame []byte, maxCiphertext int) bool {
	if len(frame) < recordHeaderLen {
		return false
	}
	if string(frame[:4]) != RecordMagic {
		return false
	}
	if frame[4] != ProtocolVersion {
		return false
	}
	n := int(bin.U32BE(frame[14:18]))
	if n < 0 {
		return false
	}
	if maxCiphertext > 0 && n > maxCiphertext {
		return false
	}
	return recordHeaderLen+n == len(frame)
}
