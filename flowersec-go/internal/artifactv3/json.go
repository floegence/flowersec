package artifactv3

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strconv"
	"unicode/utf16"
)

const maxSignedSafeInteger = int64(9_007_199_254_740_991)
const maxJSONPreflightDepth = 128

var canonicalIntegerPattern = regexp.MustCompile(`^-?(?:0|[1-9][0-9]*)$`)

func canonicalJSON(value any) ([]byte, error) {
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return emitJCSLineSeparators(bytes.TrimSuffix(out.Bytes(), []byte{'\n'})), nil
}

// encoding/json escapes U+2028 and U+2029 for JavaScript compatibility, but
// RFC 8785 emits both scalars literally. Only rewrite escapes introduced by
// the encoder; an even-length backslash run represents literal "\\u2028" or
// "\\u2029" text and must remain untouched.
func emitJCSLineSeparators(encoded []byte) []byte {
	if !bytes.Contains(encoded, []byte(`\u202`)) {
		return encoded
	}
	out := make([]byte, 0, len(encoded))
	for index := 0; index < len(encoded); {
		if encoded[index] != '\\' {
			out = append(out, encoded[index])
			index++
			continue
		}
		start := index
		for index < len(encoded) && encoded[index] == '\\' {
			index++
		}
		if (index-start)%2 == 1 && index+5 <= len(encoded) &&
			(bytes.Equal(encoded[index:index+5], []byte("u2028")) ||
				bytes.Equal(encoded[index:index+5], []byte("u2029"))) {
			out = append(out, encoded[start:index-1]...)
			if encoded[index+4] == '8' {
				out = append(out, '\xe2', '\x80', '\xa8')
			} else {
				out = append(out, '\xe2', '\x80', '\xa9')
			}
			index += 5
			continue
		}
		out = append(out, encoded[start:index]...)
	}
	return out
}

func decodeStrictJSON(raw []byte, value any) error {
	if err := rejectDuplicateJSONFields(raw); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if err := requireJSONEOF(decoder); err != nil {
		return err
	}
	return nil
}

func rejectDuplicateJSONFields(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := scanJSONValue(decoder, 0); err != nil {
		return err
	}
	return requireJSONEOF(decoder)
}

func scanJSONValue(decoder *json.Decoder, depth int) error {
	if depth > maxJSONPreflightDepth {
		return fmt.Errorf("JSON nesting is too deep")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("JSON object key is not a string")
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("duplicate JSON field %q", key)
			}
			seen[key] = struct{}{}
			if err := scanJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim('}') {
			return fmt.Errorf("invalid JSON object terminator")
		}
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim(']') {
			return fmt.Errorf("invalid JSON array terminator")
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delim)
	}
	return nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return fmt.Errorf("trailing JSON value")
		}
		return err
	}
	return nil
}

func requireJSONObjectFields(raw []byte, fields ...string) error {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		return err
	}
	if len(object) != len(fields) {
		return fmt.Errorf("JSON object field count = %d, want %d", len(object), len(fields))
	}
	for _, field := range fields {
		if _, ok := object[field]; !ok {
			return fmt.Errorf("missing JSON field %q", field)
		}
	}
	return nil
}

func validateCanonicalScopedPayload(raw []byte) error {
	if len(raw) == 0 || len(raw) > 4_096 || raw[0] != '{' {
		return fmt.Errorf("scope payload must be a bounded object")
	}
	if err := preflightScopedPayload(raw); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return err
	}
	if err := requireJSONEOF(decoder); err != nil {
		return err
	}
	object, ok := value.(map[string]any)
	if !ok {
		return fmt.Errorf("scope payload root is not an object")
	}
	nodes := 0
	canonical, err := appendCanonicalScopedValue(nil, object, 1, &nodes)
	if err != nil {
		return err
	}
	if !bytes.Equal(canonical, raw) {
		return fmt.Errorf("scope payload is not canonical JCS")
	}
	return nil
}

type scopedPayloadScanLimits struct {
	nodes int
}

func preflightScopedPayload(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	limits := &scopedPayloadScanLimits{}
	if err := scanScopedPayloadValue(decoder, 1, limits, true); err != nil {
		return err
	}
	return requireJSONEOF(decoder)
}

func scanScopedPayloadValue(decoder *json.Decoder, depth int, limits *scopedPayloadScanLimits, requireObject bool) error {
	if depth > 16 {
		return fmt.Errorf("scope payload depth exceeds 16")
	}
	limits.nodes++
	if limits.nodes > 256 {
		return fmt.Errorf("scope payload node count exceeds 256")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, container := token.(json.Delim)
	if requireObject && (!container || delim != '{') {
		return fmt.Errorf("scope payload root is not an object")
	}
	if !container {
		if text, ok := token.(string); ok && len([]byte(text)) > 1_024 {
			return fmt.Errorf("scope payload string exceeds 1024 bytes")
		}
		if number, ok := token.(json.Number); ok {
			if err := validateScopedJSONNumber(number); err != nil {
				return err
			}
		}
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		members := 0
		for decoder.More() {
			members++
			if members > 64 {
				return fmt.Errorf("scope payload object exceeds 64 members")
			}
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("JSON object key is not a string")
			}
			if len([]byte(key)) > 128 {
				return fmt.Errorf("scope payload key exceeds 128 bytes")
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("duplicate JSON field %q", key)
			}
			seen[key] = struct{}{}
			if err := scanScopedPayloadValue(decoder, depth+1, limits, false); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim('}') {
			return fmt.Errorf("invalid JSON object terminator")
		}
	case '[':
		elements := 0
		for decoder.More() {
			elements++
			if elements > 64 {
				return fmt.Errorf("scope payload array exceeds 64 elements")
			}
			if err := scanScopedPayloadValue(decoder, depth+1, limits, false); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim(']') {
			return fmt.Errorf("invalid JSON array terminator")
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delim)
	}
	return nil
}

func validateScopedJSONNumber(number json.Number) error {
	text := number.String()
	if !canonicalIntegerPattern.MatchString(text) || text == "-0" {
		return fmt.Errorf("scope payload number is not a canonical integer")
	}
	integer, err := strconv.ParseInt(text, 10, 64)
	if err != nil || integer < -maxSignedSafeInteger || integer > maxSignedSafeInteger {
		return fmt.Errorf("scope payload integer is outside the signed safe range")
	}
	return nil
}

func appendCanonicalScopedValue(out []byte, value any, depth int, nodes *int) ([]byte, error) {
	if depth > 16 {
		return nil, fmt.Errorf("scope payload depth exceeds 16")
	}
	*nodes++
	if *nodes > 256 {
		return nil, fmt.Errorf("scope payload node count exceeds 256")
	}
	switch typed := value.(type) {
	case nil:
		return append(out, "null"...), nil
	case bool:
		if typed {
			return append(out, "true"...), nil
		}
		return append(out, "false"...), nil
	case string:
		if len([]byte(typed)) > 1_024 {
			return nil, fmt.Errorf("scope payload string exceeds 1024 bytes")
		}
		return appendCanonicalJSONString(out, typed)
	case json.Number:
		text := typed.String()
		if !canonicalIntegerPattern.MatchString(text) || text == "-0" {
			return nil, fmt.Errorf("scope payload number is not a canonical integer")
		}
		integer, err := strconv.ParseInt(text, 10, 64)
		if err != nil || integer < -maxSignedSafeInteger || integer > maxSignedSafeInteger {
			return nil, fmt.Errorf("scope payload integer is outside the signed safe range")
		}
		return append(out, text...), nil
	case []any:
		if len(typed) > 64 {
			return nil, fmt.Errorf("scope payload array exceeds 64 elements")
		}
		out = append(out, '[')
		for index, item := range typed {
			if index != 0 {
				out = append(out, ',')
			}
			var err error
			out, err = appendCanonicalScopedValue(out, item, depth+1, nodes)
			if err != nil {
				return nil, err
			}
		}
		return append(out, ']'), nil
	case map[string]any:
		if len(typed) > 64 {
			return nil, fmt.Errorf("scope payload object exceeds 64 members")
		}
		keys := make([]string, 0, len(typed))
		for key := range typed {
			if len([]byte(key)) > 128 {
				return nil, fmt.Errorf("scope payload key exceeds 128 bytes")
			}
			keys = append(keys, key)
		}
		slices.SortFunc(keys, compareUTF16Strings)
		out = append(out, '{')
		for index, key := range keys {
			if index != 0 {
				out = append(out, ',')
			}
			var err error
			out, err = appendCanonicalJSONString(out, key)
			if err != nil {
				return nil, err
			}
			out = append(out, ':')
			out, err = appendCanonicalScopedValue(out, typed[key], depth+1, nodes)
			if err != nil {
				return nil, err
			}
		}
		return append(out, '}'), nil
	default:
		return nil, fmt.Errorf("scope payload contains unsupported JSON value %T", value)
	}
}

func appendCanonicalJSONString(out []byte, value string) ([]byte, error) {
	var encoded bytes.Buffer
	encoder := json.NewEncoder(&encoded)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	canonical := emitJCSLineSeparators(bytes.TrimSuffix(encoded.Bytes(), []byte{'\n'}))
	return append(out, canonical...), nil
}

func compareUTF16Strings(left, right string) int {
	leftUnits := utf16.Encode([]rune(left))
	rightUnits := utf16.Encode([]rune(right))
	for index := 0; index < len(leftUnits) && index < len(rightUnits); index++ {
		if leftUnits[index] < rightUnits[index] {
			return -1
		}
		if leftUnits[index] > rightUnits[index] {
			return 1
		}
	}
	return len(leftUnits) - len(rightUnits)
}
