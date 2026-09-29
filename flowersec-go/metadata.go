package flowersec

import (
	"errors"
	"fmt"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
)

// ErrInvalidMetadata reports metadata outside the bounded v4 OPEN shell.
var ErrInvalidMetadata = errors.New("invalid Flowersec metadata")

// StreamMetadata is an immutable application namespace, version and byte map.
// Its zero value is the sole empty metadata representation.
type StreamMetadata struct{ wire []byte }

// NewStreamMetadata encodes an application/json version 1 byte map. JSON values
// are an application convenience; the protocol does not impose a JSON schema.
func NewStreamMetadata(values map[string]any) (StreamMetadata, error) {
	wire, err := protocolv4.EncodeStreamMetadata(values)
	if err != nil {
		return StreamMetadata{}, fmt.Errorf("%w: malformed input", ErrInvalidMetadata)
	}
	return StreamMetadata{wire: wire}, nil
}

// NewStreamMetadataEnvelope captures application-owned metadata without
// interpreting its values or changing their bytes. Reserved SDK namespaces
// cannot be supplied through this ordinary application constructor.
func NewStreamMetadataEnvelope(namespace string, version uint16, values map[string][]byte) (StreamMetadata, error) {
	wire, err := protocolv4.EncodeStreamMetadataEnvelope(protocolv4.StreamMetadataEnvelope{Namespace: namespace, Version: version, Values: values})
	if err != nil {
		return StreamMetadata{}, fmt.Errorf("%w: malformed input", ErrInvalidMetadata)
	}
	return StreamMetadata{wire: wire}, nil
}

func EmptyStreamMetadata() StreamMetadata { return StreamMetadata{} }

// NewStreamMetadataFromBytes validates the canonical v4 shell and captures its
// exact bytes, including metadata whose application codec is unknown locally.
func NewStreamMetadataFromBytes(wire []byte) (StreamMetadata, error) {
	if _, err := protocolv4.DecodeStreamMetadataEnvelope(wire); err != nil {
		return StreamMetadata{}, fmt.Errorf("%w: malformed input", ErrInvalidMetadata)
	}
	return StreamMetadata{wire: append([]byte(nil), wire...)}, nil
}

func (metadata StreamMetadata) Bytes() []byte { return append([]byte(nil), metadata.wire...) }
func (metadata StreamMetadata) Namespace() string {
	envelope, _ := protocolv4.DecodeStreamMetadataEnvelope(metadata.wire)
	return envelope.Namespace
}
func (metadata StreamMetadata) Version() uint16 {
	envelope, _ := protocolv4.DecodeStreamMetadataEnvelope(metadata.wire)
	return envelope.Version
}

// ByteValues returns detached application values without codec interpretation.
func (metadata StreamMetadata) ByteValues() map[string][]byte {
	envelope, _ := protocolv4.DecodeStreamMetadataEnvelope(metadata.wire)
	if envelope.Values == nil {
		return map[string][]byte{}
	}
	return envelope.Values
}

// JSONValues decodes only the application/json version 1 convenience codec.
func (metadata StreamMetadata) JSONValues() (map[string]any, error) {
	values, err := protocolv4.DecodeStreamMetadata(metadata.wire)
	if err != nil {
		return nil, ErrInvalidMetadata
	}
	return values, nil
}

// Values returns a detached JSON object, or an empty object for other codecs.
// Use ByteValues for arbitrary metadata or JSONValues to distinguish a codec error.
func (metadata StreamMetadata) Values() map[string]any {
	values, err := metadata.JSONValues()
	if err != nil {
		return map[string]any{}
	}
	return values
}
func (metadata StreamMetadata) sessionValues() map[string]any { return metadata.Values() }
