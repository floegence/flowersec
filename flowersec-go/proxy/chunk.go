package proxy

import (
	"encoding/binary"
	"errors"
	"io"
)

var ErrChunkTooLarge = errors.New("chunk too large")
var ErrBodyTooLarge = errors.New("body too large")

func readChunkFrame(r io.Reader, maxChunkBytes int, maxBodyBytes int64, total *int64) (payload []byte, done bool, err error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, false, err
	}
	n := int(binary.BigEndian.Uint32(hdr[:]))
	if n == 0 {
		return nil, true, nil
	}
	if n < 0 || (maxChunkBytes > 0 && n > maxChunkBytes) {
		return nil, false, ErrChunkTooLarge
	}
	if total != nil {
		if maxBodyBytes > 0 && *total+int64(n) > maxBodyBytes {
			return nil, false, ErrBodyTooLarge
		}
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, false, err
	}
	if total != nil {
		*total += int64(n)
	}
	return b, false, nil
}

func writeChunkFrame(w io.Writer, payload []byte, maxChunkBytes int, maxBodyBytes int64, total *int64) error {
	if len(payload) == 0 {
		return writeChunkTerminator(w)
	}
	if maxChunkBytes > 0 && len(payload) > maxChunkBytes {
		return ErrChunkTooLarge
	}
	if total != nil {
		if maxBodyBytes > 0 && *total+int64(len(payload)) > maxBodyBytes {
			return ErrBodyTooLarge
		}
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if _, err := w.Write(payload); err != nil {
		return err
	}
	if total != nil {
		*total += int64(len(payload))
	}
	return nil
}

func writeChunkTerminator(w io.Writer) error {
	var hdr [4]byte
	_, err := w.Write(hdr[:])
	return err
}
