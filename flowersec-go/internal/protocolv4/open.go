package protocolv4

import (
	"crypto/sha256"
	"encoding/binary"
)

// EncodeOpen builds the registered projection and digest in the caller's
// reservation, then writes the complete original OPEN. It is invoked exactly
// once with the real irreversible record ticket, never a predicted sequence.
func EncodeOpen(dst []byte, header RecordHeader, direction Direction, kind string, metadata []byte, initialReceiveLimit uint64) ([]byte, [32]byte, error) {
	var digest [32]byte
	if header.Sequence != 0 || header.Scope == 0 || header.Scope >= uint64(1)<<63 || Direction((header.Scope+1)%2) != direction {
		return nil, digest, ErrRecordScope
	}
	r, err := runtimeFrames()
	if err != nil {
		return nil, digest, err
	}
	fields := [...]Field{
		{Name: "stream_id", Number: header.Scope}, {Name: "direction", Number: uint64(direction)},
		{Name: "scope", Number: header.Scope}, {Name: "epoch", Number: uint64(header.Epoch)},
		{Name: "sequence", Number: header.Sequence}, {Name: "kind", Kind: TextString, Text: kind},
		{Name: "metadata", Kind: ByteString, Bytes: metadata}, {Name: "initial_receive_limit", Number: initialReceiveLimit},
		{Name: "open_digest", Kind: ByteString, Bytes: digest[:]},
	}
	projection, err := encodeMap(dst, "OPEN_STREAM", fields[:len(fields)-1], "open_digest")
	if err != nil {
		return nil, digest, err
	}
	h := sha256.New()
	h.Write(r.openLabel)
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(projection)))
	h.Write(size[:])
	h.Write(projection)
	h.Sum(digest[:0])
	wire, err := EncodeMap(dst, "OPEN_STREAM", fields[:])
	return wire, digest, err
}

// FieldByteLimit exposes the compiled generated bound to local admission and
// resource sizing. Callers must not derive bounds from a received field length.
func FieldByteLimit(schema, field string) (int, error) {
	r, err := runtimeSchema()
	if err != nil {
		return 0, err
	}
	m := r.Maps[schema]
	if m == nil || m.byName[field] == nil || m.byName[field].MaxBytes == nil || uint64(*m.byName[field].MaxBytes) > uint64(MaxPayloadLength) {
		return 0, CBORFailure("field_bound_unresolved")
	}
	return int(*m.byName[field].MaxBytes), nil
}
