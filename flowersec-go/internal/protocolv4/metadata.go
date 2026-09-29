package protocolv4

import (
	"bytes"
	"encoding/json"
	"io"
	"math"
	"sort"
	"unicode/utf8"
)

const maxStreamMetadataBytes = 4096
const jsonStreamMetadataNamespace = "application/json"

// StreamMetadataEnvelope preserves application-owned bytes. The protocol only
// validates the registered shell; application codecs own the value semantics.
type StreamMetadataEnvelope struct {
	Namespace string
	Version   uint16
	Values    map[string][]byte
}

func EncodeStreamMetadataEnvelope(metadata StreamMetadataEnvelope) ([]byte, error) {
	if len(metadata.Namespace) > 64 || len(metadata.Values) > 64 {
		return nil, CBORFailure("metadata_items")
	}
	type item struct{ key, value []byte }
	items := make([]item, 0, len(metadata.Values))
	size := 0
	for key, value := range metadata.Values {
		if len(key) == 0 || len(key) > 64 || !utf8.ValidString(key) || len(value) > 1024 {
			return nil, CBORFailure("metadata_value")
		}
		name := cborText([]byte(key))
		encoded := cborBytesAppend(nil, value)
		size += len(name) + len(encoded)
		if size > maxStreamMetadataBytes {
			return nil, CBORFailure("metadata_bytes")
		}
		items = append(items, item{name, encoded})
	}
	sort.Slice(items, func(i, j int) bool { return bytes.Compare(items[i].key, items[j].key) < 0 })
	out := cborHeadAppend(nil, 5, 3)
	out = cborHeadAppend(out, 0, 0)
	out = cborTextAppend(out, []byte(metadata.Namespace))
	out = cborHeadAppend(out, 0, 1)
	out = cborHeadAppend(out, 0, uint64(metadata.Version))
	out = cborHeadAppend(out, 0, 2)
	out = cborHeadAppend(out, 5, uint64(len(items)))
	for _, item := range items {
		out = append(out, item.key...)
		out = append(out, item.value...)
	}
	// Validate the same registry used by the peer, including namespace and
	// Unicode constraints. Never emit metadata rejected by ordinary OPEN.
	if _, err := DecodeStreamMetadataEnvelope(out); err != nil {
		return nil, err
	}
	return out, nil
}

func DecodeStreamMetadataEnvelope(wire []byte) (StreamMetadataEnvelope, error) {
	if len(wire) == 0 {
		return StreamMetadataEnvelope{}, nil
	}
	d, err := NewDecoder(maxStreamMetadataBytes, 136)
	if err != nil {
		return StreamMetadataEnvelope{}, err
	}
	doc, err := d.DecodeMap(wire, "StreamMetadata", DecodeContext{})
	if err != nil {
		return StreamMetadataEnvelope{}, err
	}
	defer doc.Release()
	namespace, _ := doc.Root().Named("StreamMetadata", "namespace").Text()
	version, _ := doc.Root().Named("StreamMetadata", "version").Uint()
	values := doc.Root().Named("StreamMetadata", "values")
	result := StreamMetadataEnvelope{Namespace: namespace, Version: uint16(version), Values: make(map[string][]byte, values.Len())}
	node := d.nodes[values.index]
	for child := node.first; child >= 0; child = d.nodes[child].next {
		key, _ := (Value{document: doc, index: child}).Text()
		valueNode := d.nodes[child].next
		raw, _ := (Value{document: doc, index: valueNode}).ByteString()
		result.Values[key] = append([]byte(nil), raw...)
		child = valueNode
	}
	return result, nil
}

// EncodeStreamMetadata is the optional application/json convenience codec.
// JSON is carried as opaque value bytes inside the ordinary v4 metadata shell.
func EncodeStreamMetadata(values map[string]any) ([]byte, error) {
	if len(values) == 0 {
		return nil, nil
	}
	if len(values) > 64 {
		return nil, CBORFailure("metadata_items")
	}
	entries := make(map[string][]byte, len(values))
	for key, value := range values {
		raw, err := json.Marshal(value)
		if err != nil || len(raw) > 1024 {
			return nil, CBORFailure("metadata_value")
		}
		entries[key] = raw
	}
	return EncodeStreamMetadataEnvelope(StreamMetadataEnvelope{Namespace: jsonStreamMetadataNamespace, Version: 1, Values: entries})
}

func DecodeStreamMetadata(wire []byte) (map[string]any, error) {
	metadata, err := DecodeStreamMetadataEnvelope(wire)
	if err != nil {
		return nil, err
	}
	if len(wire) != 0 && (metadata.Namespace != jsonStreamMetadataNamespace || metadata.Version != 1) {
		return nil, CBORFailure("metadata_codec")
	}
	result := make(map[string]any, len(metadata.Values))
	for key, raw := range metadata.Values {
		var value any
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		if err := decoder.Decode(&value); err != nil {
			return nil, CBORFailure("metadata_value")
		}
		if err := decoder.Decode(new(any)); err != io.EOF {
			return nil, CBORFailure("metadata_value")
		}
		result[key] = value
	}
	return result, nil
}

func cborText(value []byte) []byte { return cborTextAppend(nil, value) }
func cborTextAppend(dst, value []byte) []byte {
	return append(cborHeadAppend(dst, 3, uint64(len(value))), value...)
}
func cborBytesAppend(dst, value []byte) []byte {
	return append(cborHeadAppend(dst, 2, uint64(len(value))), value...)
}
func cborHeadAppend(dst []byte, major byte, n uint64) []byte {
	if n < 24 {
		return append(dst, major<<5|byte(n))
	}
	if n <= math.MaxUint8 {
		return append(dst, major<<5|24, byte(n))
	}
	if n <= math.MaxUint16 {
		return append(dst, major<<5|25, byte(n>>8), byte(n))
	}
	if n <= math.MaxUint32 {
		return append(dst, major<<5|26, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
	return append(dst, major<<5|27, byte(n>>56), byte(n>>48), byte(n>>40), byte(n>>32), byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
}
