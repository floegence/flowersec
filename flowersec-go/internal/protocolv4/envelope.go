// Package protocolv4 implements the fixed Flowersec v4 wire primitives using
// the generated registry. Authentication and owner state live in cryptov4.
package protocolv4

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// FrameType is the registry-assigned v4 frame identifier.
type FrameType byte

func (f FrameType) valid() bool { return f >= FrameNegotiate && f <= FrameHopAuth }

var (
	ErrTruncated       = errors.New("protocolv4: truncated envelope")
	ErrPayloadTooLarge = errors.New("protocolv4: payload exceeds v4 limit")
	ErrInvalidFlags    = errors.New("protocolv4: flags/reserved must be zero")
	ErrUnknownFrame    = errors.New("protocolv4: unknown frame type")
)

// Envelope is the fixed v4 binary envelope. PayloadLength excludes the
// eight-byte prefix, matching the wire contract.
type Envelope struct {
	FrameType FrameType
	Flags     byte
	Reserved  uint16
	Payload   []byte
}

// Encode serializes an envelope after validating all wire limits.
func (e Envelope) Encode() ([]byte, error) {
	if !e.FrameType.valid() {
		return nil, ErrUnknownFrame
	}
	if e.Flags != 0 || e.Reserved != 0 {
		return nil, ErrInvalidFlags
	}
	if len(e.Payload) > MaxPayloadLength {
		return nil, ErrPayloadTooLarge
	}
	out := make([]byte, EnvelopePrefixSize+len(e.Payload))
	binary.BigEndian.PutUint32(out[0:4], uint32(len(e.Payload)))
	out[4] = byte(e.FrameType)
	out[5] = e.Flags
	binary.BigEndian.PutUint16(out[6:8], e.Reserved)
	copy(out[8:], e.Payload)
	return out, nil
}

// Decode parses exactly one envelope. Trailing bytes are rejected so callers
// cannot accidentally concatenate records across carrier boundaries.
func Decode(in []byte) (Envelope, error) {
	if len(in) < EnvelopePrefixSize {
		return Envelope{}, ErrTruncated
	}
	n := binary.BigEndian.Uint32(in[:4])
	if n > MaxPayloadLength {
		return Envelope{}, ErrPayloadTooLarge
	}
	if uint64(n)+EnvelopePrefixSize != uint64(len(in)) {
		return Envelope{}, ErrTruncated
	}
	f := FrameType(in[4])
	if !f.valid() {
		return Envelope{}, fmt.Errorf("%w: %d", ErrUnknownFrame, in[4])
	}
	if in[5] != 0 || binary.BigEndian.Uint16(in[6:8]) != 0 {
		return Envelope{}, ErrInvalidFlags
	}
	p := make([]byte, n)
	copy(p, in[8:])
	return Envelope{FrameType: f, Payload: p}, nil
}
