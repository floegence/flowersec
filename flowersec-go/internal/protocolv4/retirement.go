package protocolv4

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"sync"
)

var retirementDomain = sync.OnceValues(func() ([]byte, error) {
	var domains []struct {
		Name, Operation string
		Label           string `json:"label_bytes"`
	}
	if json.Unmarshal([]byte(DomainRegistryJSON), &domains) != nil {
		return nil, ErrRecordRegistry
	}
	for _, d := range domains {
		if d.Name == "retirement_batch_digest" && d.Operation == "sha256" {
			return hex.DecodeString(d.Label)
		}
	}
	return nil, ErrRecordRegistry
})

func RetirementDigest(handshake [32]byte, profile string, proposer Direction, original []byte) ([32]byte, error) {
	var digest [32]byte
	if _, err := Profile(profile); err != nil {
		return digest, err
	}
	if proposer > ServerToClient || len(original) > int(MaxPayloadLength) {
		return digest, ErrRecordDirection
	}
	label, err := retirementDomain()
	if err != nil {
		return digest, err
	}
	h := sha256.New()
	h.Write(label)
	var prefix [4]byte
	for _, value := range [][]byte{handshake[:], []byte(profile)} {
		binary.BigEndian.PutUint32(prefix[:], uint32(len(value)))
		h.Write(prefix[:])
		h.Write(value)
	}
	h.Write([]byte{byte(proposer)})
	binary.BigEndian.PutUint32(prefix[:], uint32(len(original)))
	h.Write(prefix[:])
	h.Write(original)
	h.Sum(digest[:0])
	return digest, nil
}

// SchemaByteLimit and FieldItemLimit expose generated complete-map and array
// bounds for fixed reservations; neither accepts a peer-provided schema.
func SchemaByteLimit(schema string) (int, error) {
	r, err := runtimeSchema()
	if err != nil {
		return 0, err
	}
	m := r.Maps[schema]
	if m == nil || m.MaxEncodedBytes == nil || *m.MaxEncodedBytes > uint64(MaxPayloadLength) {
		return 0, CBORFailure("field_bound_unresolved")
	}
	return int(*m.MaxEncodedBytes), nil
}
func FieldItemLimit(schema, field string) (int, error) {
	r, err := runtimeSchema()
	if err != nil {
		return 0, err
	}
	m := r.Maps[schema]
	if m == nil || m.byName[field] == nil || m.byName[field].MaxItems == nil || uint64(*m.byName[field].MaxItems) > uint64(MaxPayloadLength) {
		return 0, CBORFailure("field_bound_unresolved")
	}
	return int(*m.byName[field].MaxItems), nil
}

func EncodeScopeArray(dst []byte, ids []uint64) ([]byte, error) {
	cap, err := FieldItemLimit("STREAM_ACK_RETIRE_BATCH", "scope_ids")
	if err != nil {
		return nil, err
	}
	if len(ids) == 0 || len(ids) > cap {
		return nil, CBORFailure("array_limit")
	}
	offset, err := cborHead(dst, 4, uint64(len(ids)))
	if err != nil {
		return nil, err
	}
	for i, scope := range ids {
		if scope == 0 || scope >= uint64(1)<<63 || i > 0 && scope <= ids[i-1] {
			return nil, CBORFailure("scope_order")
		}
		n, err := cborHead(dst[offset:], 0, scope)
		if err != nil {
			return nil, err
		}
		offset += n
	}
	return dst[:offset:offset], nil
}
