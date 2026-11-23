package jsonframe

import (
	"encoding/json"
	"errors"
	"io"
	"math"

	"github.com/floegence/flowersec/flowersec-go/v7/internal/bin"
	"github.com/floegence/flowersec/flowersec-go/v7/internal/defaults"
)

var ErrFrameTooLarge = errors.New("json frame too large")

// DefaultMaxJSONFrameBytes is the recommended maximum size for a single framed JSON message.
//
// Do not call ReadJSONFrame with maxLen<=0 on untrusted inputs, because it disables size
// checks and may lead to large allocations (memory DoS).
const DefaultMaxJSONFrameBytes = defaults.RPCMaxJSONFrameBytes

// WriteJSONFrame writes a length-prefixed JSON message to the writer.
func WriteJSONFrame(w io.Writer, v any) error {
	b, err := Encode(v, DefaultMaxJSONFrameBytes)
	if err != nil {
		return err
	}
	return WriteEncoded(w, b)
}

// Encode checks the complete encoded JSON body before any prefix can be sent.
func Encode(v any, maxLen int) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	if len(b) > maxLen || uint64(len(b)) > math.MaxUint32 {
		return nil, ErrFrameTooLarge
	}
	return b, nil
}

// WriteEncoded writes the output of Encode under the caller's frame write lock.
func WriteEncoded(w io.Writer, b []byte) error {
	if len(b) > DefaultMaxJSONFrameBytes {
		// Keep the same prefix on the wire without copying a large envelope again.
		var header [4]byte
		bin.PutU32BE(header[:], uint32(len(b)))
		if err := writeAll(w, header[:]); err != nil {
			return err
		}
		return writeAll(w, b)
	}
	frame := make([]byte, 4+len(b))
	bin.PutU32BE(frame[:4], uint32(len(b)))
	copy(frame[4:], b)
	return writeAll(w, frame)
}

func writeAll(w io.Writer, frame []byte) error {
	for len(frame) > 0 {
		n, err := w.Write(frame)
		if n < 0 || n > len(frame) {
			return io.ErrShortWrite
		}
		frame = frame[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
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
