package proxy

import (
	"encoding/binary"
	"io"
)

func readWSFrame(r io.Reader, maxPayload int) (op byte, payload []byte, err error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	op = hdr[0]
	n := int(binary.BigEndian.Uint32(hdr[1:5]))
	if n < 0 || (maxPayload > 0 && n > maxPayload) {
		return 0, nil, ErrChunkTooLarge
	}
	if n == 0 {
		return op, nil, nil
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return 0, nil, err
	}
	return op, b, nil
}

func writeWSFrame(w io.Writer, op byte, payload []byte, maxPayload int) error {
	if maxPayload > 0 && len(payload) > maxPayload {
		return ErrChunkTooLarge
	}
	var hdr [5]byte
	hdr[0] = op
	binary.BigEndian.PutUint32(hdr[1:5], uint32(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if len(payload) == 0 {
		return nil
	}
	_, err := w.Write(payload)
	return err
}
