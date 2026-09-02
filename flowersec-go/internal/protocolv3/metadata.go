package protocolv3

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/unicode151"
	"golang.org/x/text/unicode/norm"
)

const (
	MaxOpenMetadataBytes  = 4_096
	MaxOpenMetadataDepth  = 4
	MaxOpenMetadataNodes  = 64
	MaxOpenMetadataKeys   = 64
	MaxOpenMetadataArray  = 32
	MaxOpenMetadataKey    = 64
	MaxOpenMetadataString = 512
	maxIJSONSafeInteger   = int64(9_007_199_254_740_991)
)

var integerJSONPattern = regexp.MustCompile(`^-?(0|[1-9][0-9]*)$`)

type metadataLimits struct {
	nodes int
}

func validateCanonicalMetadata(raw []byte, allowEmpty bool) ([]byte, error) {
	if len(raw) == 0 && allowEmpty {
		raw = []byte("{}")
	}
	if len(raw) == 0 || len(raw) > MaxOpenMetadataBytes || !utf8.Valid(raw) {
		return nil, ErrInvalidOpenMetadata
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	// The root object is the metadata container; the 64-node budget applies to
	// the values and nested containers it owns.
	limits := &metadataLimits{nodes: -1}
	value, err := parseMetadataValue(decoder, 1, limits)
	if err != nil {
		return nil, err
	}
	if _, ok := value.(map[string]any); !ok {
		return nil, ErrInvalidOpenMetadata
	}
	if token, err := decoder.Token(); err != io.EOF {
		if err == nil {
			_ = token
		}
		return nil, ErrInvalidOpenMetadata
	}
	canonical, err := marshalCanonicalMetadata(value)
	if err != nil {
		return nil, ErrInvalidOpenMetadata
	}
	if len(canonical) > MaxOpenMetadataBytes || !bytes.Equal(raw, canonical) {
		return nil, ErrInvalidOpenMetadata
	}
	return canonical, nil
}

// MarshalOpenMetadata converts a Go JSON value into the exact canonical OPEN
// metadata form. The root must be an object and every v3 Unicode and resource
// limit is enforced before bytes are returned.
func MarshalOpenMetadata(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil || !utf8.Valid(raw) {
		return nil, ErrInvalidOpenMetadata
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	limits := &metadataLimits{nodes: -1}
	parsed, err := parseMetadataValue(decoder, 1, limits)
	if err != nil {
		return nil, err
	}
	if _, ok := parsed.(map[string]any); !ok {
		return nil, ErrInvalidOpenMetadata
	}
	if token, err := decoder.Token(); err != io.EOF {
		if err == nil {
			_ = token
		}
		return nil, ErrInvalidOpenMetadata
	}
	canonical, err := marshalCanonicalMetadata(parsed)
	if err != nil || len(canonical) > MaxOpenMetadataBytes {
		return nil, ErrInvalidOpenMetadata
	}
	return canonical, nil
}

func parseMetadataValue(decoder *json.Decoder, depth int, limits *metadataLimits) (any, error) {
	if depth > MaxOpenMetadataDepth {
		return nil, ErrInvalidOpenMetadata
	}
	limits.nodes++
	if limits.nodes > MaxOpenMetadataNodes {
		return nil, ErrInvalidOpenMetadata
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, ErrInvalidOpenMetadata
	}
	switch value := token.(type) {
	case json.Delim:
		switch value {
		case '{':
			object := make(map[string]any)
			for decoder.More() {
				if len(object) >= MaxOpenMetadataKeys {
					return nil, ErrInvalidOpenMetadata
				}
				keyToken, err := decoder.Token()
				if err != nil {
					return nil, ErrInvalidOpenMetadata
				}
				key, ok := keyToken.(string)
				if !ok || !validOpenUnicodeString(key, MaxOpenMetadataKey, false) {
					return nil, ErrInvalidOpenMetadata
				}
				if _, duplicate := object[key]; duplicate {
					return nil, ErrInvalidOpenMetadata
				}
				child, err := parseMetadataValue(decoder, depth+1, limits)
				if err != nil {
					return nil, err
				}
				object[key] = child
			}
			closing, err := decoder.Token()
			if err != nil || closing != json.Delim('}') {
				return nil, ErrInvalidOpenMetadata
			}
			return object, nil
		case '[':
			array := make([]any, 0)
			for decoder.More() {
				if len(array) >= MaxOpenMetadataArray {
					return nil, ErrInvalidOpenMetadata
				}
				child, err := parseMetadataValue(decoder, depth+1, limits)
				if err != nil {
					return nil, err
				}
				array = append(array, child)
			}
			closing, err := decoder.Token()
			if err != nil || closing != json.Delim(']') {
				return nil, ErrInvalidOpenMetadata
			}
			return array, nil
		default:
			return nil, ErrInvalidOpenMetadata
		}
	case string:
		if !validOpenUnicodeString(value, MaxOpenMetadataString, true) {
			return nil, ErrInvalidOpenMetadata
		}
		return value, nil
	case json.Number:
		if string(value) == "-0" || !integerJSONPattern.MatchString(string(value)) {
			return nil, ErrInvalidOpenMetadata
		}
		integer, err := strconv.ParseInt(string(value), 10, 64)
		if err != nil || integer < -maxIJSONSafeInteger || integer > maxIJSONSafeInteger {
			return nil, ErrInvalidOpenMetadata
		}
		return integer, nil
	case bool:
		return value, nil
	case nil:
		return nil, nil
	default:
		return nil, ErrInvalidOpenMetadata
	}
}

func marshalCanonicalMetadata(value any) ([]byte, error) {
	var out bytes.Buffer
	if err := appendCanonicalMetadata(&out, value); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func appendCanonicalMetadata(out *bytes.Buffer, value any) error {
	switch value := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(value))
		for key := range value {
			keys = append(keys, key)
		}
		sort.Slice(keys, func(i, j int) bool { return lessUTF16(keys[i], keys[j]) })
		out.WriteByte('{')
		for i, key := range keys {
			if i != 0 {
				out.WriteByte(',')
			}
			keyJSON, err := marshalCanonicalJSONString(key)
			if err != nil {
				return err
			}
			out.Write(keyJSON)
			out.WriteByte(':')
			if err := appendCanonicalMetadata(out, value[key]); err != nil {
				return err
			}
		}
		out.WriteByte('}')
	case []any:
		out.WriteByte('[')
		for i, item := range value {
			if i != 0 {
				out.WriteByte(',')
			}
			if err := appendCanonicalMetadata(out, item); err != nil {
				return err
			}
		}
		out.WriteByte(']')
	case string:
		encoded, err := marshalCanonicalJSONString(value)
		if err != nil {
			return err
		}
		out.Write(encoded)
	case int64:
		out.WriteString(strconv.FormatInt(value, 10))
	case bool:
		out.WriteString(strconv.FormatBool(value))
	case nil:
		out.WriteString("null")
	default:
		return fmt.Errorf("unsupported canonical metadata value %T", value)
	}
	return nil
}

func marshalCanonicalJSONString(value string) ([]byte, error) {
	if !validOpenUnicodeString(value, len(value), true) {
		return nil, ErrInvalidOpenMetadata
	}
	var out bytes.Buffer
	out.WriteByte('"')
	for _, scalar := range value {
		switch scalar {
		case '"', '\\':
			out.WriteByte('\\')
			out.WriteRune(scalar)
		default:
			out.WriteRune(scalar)
		}
	}
	out.WriteByte('"')
	return out.Bytes(), nil
}

func validOpenUnicodeString(value string, maxBytes int, allowEmpty bool) bool {
	if len(value) > maxBytes || (!allowEmpty && len(value) == 0) || !utf8.ValidString(value) || !norm.NFC.IsNormalString(value) {
		return false
	}
	for _, scalar := range value {
		if scalar <= 0x1f || (scalar >= 0x7f && scalar <= 0x9f) || !unicode151.Assigned(scalar) {
			return false
		}
	}
	return true
}

func lessUTF16(left, right string) bool {
	leftUnits := utf16.Encode([]rune(left))
	rightUnits := utf16.Encode([]rune(right))
	for index := 0; index < len(leftUnits) && index < len(rightUnits); index++ {
		if leftUnits[index] != rightUnits[index] {
			return leftUnits[index] < rightUnits[index]
		}
	}
	return len(leftUnits) < len(rightUnits)
}
