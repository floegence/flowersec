package rpc

import (
	"encoding/json"
	"errors"
	"io"

	"github.com/flowersec/flowersec/internal/bin"
)

var ErrFrameTooLarge = errors.New("rpc frame too large")

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
