package jsonframe

import (
	"encoding/json"
	"errors"
	"io"

	"github.com/floegence/flowersec/flowersec-go/internal/bin"
)

var ErrFrameTooLarge = errors.New("json frame too large")

// DefaultMaxJSONFrameBytes is the recommended maximum size for a single framed JSON message.
//
// Do not call ReadJSONFrame with maxLen<=0 on untrusted inputs, because it disables size
// checks and may lead to large allocations (memory DoS).
const DefaultMaxJSONFrameBytes = 1 << 20

// WriteJSONFrame writes a length-prefixed JSON message to the writer.
func WriteJSONFrame(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	var hdr [4]byte
	bin.PutU32BE(hdr[:], uint32(len(b)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

// ReadJSONFrame reads a length-prefixed JSON payload with a maximum size guard.
//
// Callers MUST pass a positive maxLen when reading from untrusted peers. Passing
// maxLen<=0 disables the guard and can result in large allocations.
func ReadJSONFrame(r io.Reader, maxLen int) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := int(bin.U32BE(hdr[:]))
	if n < 0 {
		return nil, ErrFrameTooLarge
	}
	if maxLen > 0 && n > maxLen {
		return nil, ErrFrameTooLarge
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}
	return b, nil
}

// ReadJSONFrameDefaultMax is a convenience wrapper around ReadJSONFrame using DefaultMaxJSONFrameBytes.
func ReadJSONFrameDefaultMax(r io.Reader) ([]byte, error) {
	return ReadJSONFrame(r, DefaultMaxJSONFrameBytes)
}
