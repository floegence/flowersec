package protocolv4

import (
	"crypto/sha256"
	"encoding/binary"
)

// StreamContentPolicy projects the exact signed contract without exposing a
// mutable alias to its application definition. Definition is a local equality
// check against the trusted method's codec, selection and read semantics; it
// is not a new wire digest, credential or remote definition resolver.
type StreamContentPolicy struct {
	RetentionOrigin                 uint8
	RetentionMS, MaxItems, MaxBytes uint64
	Definition                      [32]byte
}

// StreamContentDefinitionDigest binds the complete application definition and
// its exact schema revision. Only locally understood definitions are installed
// in a service or client; hashing a peer definition does not make it trusted.
func StreamContentDefinitionDigest(revision string, canonical []byte) [32]byte {
	if len(revision) == 0 || len(revision) > 128 || len(canonical) > 2048 {
		return [32]byte{}
	}
	h := sha256.New()
	h.Write([]byte("flowersec/local-content-definition/1"))
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(revision)))
	h.Write(size[:])
	h.Write([]byte(revision))
	binary.BigEndian.PutUint64(size[:], uint64(len(canonical)))
	h.Write(size[:])
	h.Write(canonical)
	var result [32]byte
	h.Sum(result[:0])
	return result
}
