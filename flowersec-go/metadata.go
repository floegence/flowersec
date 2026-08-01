package flowersec

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/protocolv2"
)

// ErrInvalidMetadata reports application stream metadata that cannot be encoded
// as the bounded canonical JSON object required by Transport v2 OPEN.
var ErrInvalidMetadata = errors.New("invalid Flowersec metadata")

// NewMetadata validates and defensively copies application stream metadata.
//
// The returned value is the same public Metadata type accepted by Session.
// OpenStream also validates metadata, so callers may continue using Metadata
// literals when late failure is acceptable.
func NewMetadata(values map[string]any) (Metadata, error) {
	if values == nil {
		values = map[string]any{}
	}
	canonical, err := protocolv2.MarshalOpenMetadata(values)
	if err != nil {
		return nil, fmt.Errorf("%w: malformed input", ErrInvalidMetadata)
	}
	var metadata Metadata
	decoder := json.NewDecoder(bytes.NewReader(canonical))
	decoder.UseNumber()
	if err := decoder.Decode(&metadata); err != nil {
		return nil, fmt.Errorf("%w: malformed input", ErrInvalidMetadata)
	}
	return metadata, nil
}
