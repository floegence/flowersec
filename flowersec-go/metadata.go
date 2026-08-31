package flowersec

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/floegence/flowersec/flowersec-go/v4/internal/protocolv3"
)

// ErrInvalidMetadata reports application stream metadata that cannot be encoded
// as the bounded canonical JSON object required by Transport v3 OPEN.
var ErrInvalidMetadata = errors.New("invalid Flowersec metadata")

// StreamMetadata is a validated, immutable application stream metadata value.
type StreamMetadata struct {
	values map[string]any
}

// NewStreamMetadata validates and defensively copies application stream metadata.
func NewStreamMetadata(values map[string]any) (StreamMetadata, error) {
	if values == nil {
		values = map[string]any{}
	}
	canonical, err := protocolv3.MarshalOpenMetadata(values)
	if err != nil {
		return StreamMetadata{}, fmt.Errorf("%w: malformed input", ErrInvalidMetadata)
	}
	var copied map[string]any
	decoder := json.NewDecoder(bytes.NewReader(canonical))
	decoder.UseNumber()
	if err := decoder.Decode(&copied); err != nil {
		return StreamMetadata{}, fmt.Errorf("%w: malformed input", ErrInvalidMetadata)
	}
	return StreamMetadata{values: copied}, nil
}

// EmptyStreamMetadata returns validated empty metadata.
func EmptyStreamMetadata() StreamMetadata { return StreamMetadata{values: map[string]any{}} }

// Values returns a defensive JSON-object copy.
func (metadata StreamMetadata) Values() map[string]any {
	canonical, err := protocolv3.MarshalOpenMetadata(metadata.values)
	if err != nil {
		return map[string]any{}
	}
	var copied map[string]any
	decoder := json.NewDecoder(bytes.NewReader(canonical))
	decoder.UseNumber()
	if decoder.Decode(&copied) != nil {
		return map[string]any{}
	}
	return copied
}

func (metadata StreamMetadata) sessionValues() map[string]any {
	return metadata.Values()
}
