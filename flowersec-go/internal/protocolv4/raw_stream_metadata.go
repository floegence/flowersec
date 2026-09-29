package protocolv4

import (
	"bytes"
	"encoding/json"
	"io"
	"math"
	"strings"
)

type RawStreamMetadataType string

const (
	RawStreamMetadataString  RawStreamMetadataType = "string"
	RawStreamMetadataNumber  RawStreamMetadataType = "number"
	RawStreamMetadataBoolean RawStreamMetadataType = "boolean"
)

type RawStreamMetadataField struct {
	Name     string
	Type     RawStreamMetadataType
	Required bool
}

// RawStreamMetadataContract is a bounded, data-only projection descriptor.
// It never changes the authenticated StreamMetadata wire bytes.
type RawStreamMetadataContract struct {
	ContractID      string
	Namespace       string
	Version         uint16
	Codec           string
	Fields          []RawStreamMetadataField
	MaxEncodedBytes int
	MaxDecodedBytes int
}

func (c RawStreamMetadataContract) Capture() (RawStreamMetadataContract, error) {
	if c.Codec == "" {
		c.Codec = "application/json"
	}
	if c.MaxEncodedBytes == 0 {
		c.MaxEncodedBytes = maxStreamMetadataBytes
	}
	if c.MaxDecodedBytes == 0 {
		c.MaxDecodedBytes = maxStreamMetadataBytes
	}
	if !rawMetadataIdentifier(c.ContractID, 128) || !rawMetadataNamespace(c.Namespace) || c.Codec != "application/json" ||
		len(c.Fields) > 64 || c.MaxEncodedBytes < 1 || c.MaxEncodedBytes > maxStreamMetadataBytes ||
		c.MaxDecodedBytes < 1 || c.MaxDecodedBytes > maxStreamMetadataBytes {
		return RawStreamMetadataContract{}, CBORFailure("metadata_contract")
	}
	seen := make(map[string]struct{}, len(c.Fields))
	for _, field := range c.Fields {
		if _, exists := seen[field.Name]; exists || !rawMetadataIdentifier(field.Name, 64) ||
			(field.Type != RawStreamMetadataString && field.Type != RawStreamMetadataNumber && field.Type != RawStreamMetadataBoolean) {
			return RawStreamMetadataContract{}, CBORFailure("metadata_contract")
		}
		seen[field.Name] = struct{}{}
	}
	return c, nil
}

func (c RawStreamMetadataContract) Project(wire []byte) (map[string]any, error) {
	c, err := c.Capture()
	if err != nil || len(wire) > c.MaxEncodedBytes {
		return nil, CBORFailure("metadata_contract")
	}
	envelope, err := DecodeStreamMetadataEnvelope(wire)
	if err != nil || envelope.Namespace != c.Namespace || envelope.Version != c.Version {
		return nil, CBORFailure("metadata_contract")
	}
	fields := make(map[string]RawStreamMetadataField, len(c.Fields))
	for _, field := range c.Fields {
		fields[field.Name] = field
	}
	for _, field := range c.Fields {
		if field.Required {
			if _, ok := envelope.Values[field.Name]; !ok {
				return nil, CBORFailure("metadata_contract")
			}
		}
	}
	result := make(map[string]any, len(envelope.Values))
	decoded := 0
	for key, raw := range envelope.Values {
		field, ok := fields[key]
		if !ok {
			return nil, CBORFailure("metadata_contract")
		}
		var value any
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		if err := decoder.Decode(&value); err != nil || decoder.Decode(new(any)) != io.EOF {
			return nil, CBORFailure("metadata_contract")
		}
		width := 0
		switch field.Type {
		case RawStreamMetadataString:
			text, ok := value.(string)
			if !ok {
				return nil, CBORFailure("metadata_contract")
			}
			width = len([]byte(text))
		case RawStreamMetadataNumber:
			number, ok := value.(json.Number)
			if !ok {
				return nil, CBORFailure("metadata_contract")
			}
			f, convErr := number.Float64()
			if convErr != nil || math.IsNaN(f) || math.IsInf(f, 0) {
				return nil, CBORFailure("metadata_contract")
			}
			value = f
			width = 8
		case RawStreamMetadataBoolean:
			if _, ok := value.(bool); !ok {
				return nil, CBORFailure("metadata_contract")
			}
			width = 1
		default:
			return nil, CBORFailure("metadata_contract")
		}
		decoded += len([]byte(key)) + width
		if decoded > c.MaxDecodedBytes {
			return nil, CBORFailure("metadata_contract")
		}
		result[key] = value
	}
	return result, nil
}

func rawMetadataIdentifier(value string, maximum int) bool {
	if len(value) == 0 || len(value) > maximum || value != strings.ToValidUTF8(value, "") {
		return false
	}
	for i, r := range value {
		if i == 0 && !((r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z')) {
			return false
		}
		if !((r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == '.' || r == '-') {
			return false
		}
	}
	return true
}

func rawMetadataNamespace(value string) bool {
	if len(value) == 0 || len(value) > 64 || strings.HasPrefix(value, "flowersec/") {
		return false
	}
	parts := strings.Split(value, "/")
	if len(parts) != 2 {
		return false
	}
	for _, part := range parts {
		if len(part) == 0 || len(part) > 32 {
			return false
		}
		for i, r := range part {
			if i == 0 && !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')) {
				return false
			}
			if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == '.' || r == '-') {
				return false
			}
		}
	}
	return true
}
