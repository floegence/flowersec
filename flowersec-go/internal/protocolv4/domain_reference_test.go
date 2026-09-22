package protocolv4

// Independent test-only input construction. No trust, key custody or exporter.
import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"math"
	"math/big"
	"strconv"
	"testing"
)

type domainRefPart struct {
	Name, Encoding, Projection, Selector, Hex string
	SchemaRef                                 string            `json:"schema_ref"`
	SchemaCases                               map[string]string `json:"schema_cases"`
	ConstRef                                  string            `json:"const_ref"`
	TextEnumRef                               string            `json:"text_enum_ref"`
	Const                                     *uint64
	Enum                                      []uint64
	Min, Max, Length                          *cborRefBound
	MultipleOf                                *cborRefBound `json:"multiple_of"`
	MaxLength                                 *cborRefBound `json:"max_length"`
	Nonzero                                   bool
	Fields                                    []string
	Bindings                                  map[string]string
	OneOfBindings                             map[string][]string `json:"one_of_bindings"`
}
type domainRefSpec struct {
	Name, Operation string
	Label           string  `json:"label_bytes"`
	OutputLength    *uint64 `json:"output_length"`
	Input           struct {
		Parts          []domainRefPart
		Key, Salt, IKM *domainRefPart
		Relations      []struct {
			Op, Left, Right string
			Pairs           [][2]uint64
		}
	} `json:"input_schema"`
}
type domainRefResult struct {
	Label, Input, Output, Salt, IKM []byte
	OutputLength                    *uint64
}
type domainReference struct {
	*cborTextReference
	domains map[string]domainRefSpec
}

func newDomainReference(t testing.TB) *domainReference {
	t.Helper()
	r := &domainReference{cborTextReference: newCBORTextReference(t), domains: map[string]domainRefSpec{}}
	var domains []domainRefSpec
	if err := json.Unmarshal([]byte(DomainRegistryJSON), &domains); err != nil {
		t.Fatal(err)
	}
	for _, domain := range domains {
		r.domains[domain.Name] = domain
	}
	return r
}

func domainInteger(value any) (uint64, error) {
	switch value := value.(type) {
	case *big.Int:
		if value == nil {
			return 0, cborRefError("domain_integer_type")
		}
		if !value.IsUint64() {
			return 0, cborRefError("domain_integer_range")
		}
		return value.Uint64(), nil
	case uint64:
		return value, nil
	case float64:
		if math.IsNaN(value) || math.IsInf(value, 0) || math.Trunc(value) != value || math.Abs(value) > 9007199254740991 {
			return 0, cborRefError("domain_integer_type")
		}
		if value < 0 {
			return 0, cborRefError("domain_integer_range")
		}
		return uint64(value), nil
	default:
		return 0, cborRefError("domain_integer_type")
	}
}

func domainUnsigned(value any, width int) ([]byte, error) {
	n, err := domainInteger(value)
	if err != nil {
		return nil, err
	}
	if width != 1 && width != 4 && width != 8 {
		return nil, cborRefError("registry_unresolved")
	}
	if width < 8 && n >= uint64(1)<<(width*8) {
		return nil, cborRefError("domain_integer_range")
	}
	full := binary.BigEndian.AppendUint64(nil, n)
	return bytes.Clone(full[8-width:]), nil
}

func domainLP(value []byte) ([]byte, error) {
	if uint64(len(value)) > math.MaxUint32 {
		return nil, cborRefError("domain_integer_range")
	}
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(value))), value...), nil
}

func domainMatches(value *cborRefValue, expected any) bool {
	if value == nil {
		return false
	}
	switch value.major {
	case 0:
		n, err := domainInteger(expected)
		return err == nil && value.n == n
	case 2:
		raw, ok := expected.([]byte)
		return ok && bytes.Equal(value.data, raw)
	case 3:
		text, ok := expected.(string)
		return ok && string(value.data) == text
	default:
		return false
	}
}

func (r *domainReference) mapPart(part domainRefPart, input []byte, args map[string]any, context cborShapeContext, cap uint64) ([]byte, error) {
	name := part.SchemaRef
	if name == "" {
		selector, err := domainInteger(args[part.Selector])
		if err != nil {
			return nil, err
		}
		name = part.SchemaCases[strconv.FormatUint(selector, 10)]
		if name == "" {
			return nil, cborRefError("domain_variant")
		}
	}
	value, err := r.wireMap(input, name, context, cap)
	if err != nil {
		return nil, err
	}
	for field, argument := range part.Bindings {
		actual, err := r.namedValue(name, value, field)
		if err != nil {
			return nil, err
		}
		if !domainMatches(actual, args[argument]) {
			return nil, cborRefError("domain_binding")
		}
	}
	for argument, fields := range part.OneOfBindings {
		matched := false
		for _, field := range fields {
			actual, err := r.namedValue(name, value, field)
			if err != nil {
				return nil, err
			}
			matched = matched || domainMatches(actual, args[argument])
		}
		if !matched {
			return nil, cborRefError("domain_binding")
		}
	}
	if part.Projection == "full" {
		return domainLP(input)
	}
	excluded := map[uint64]bool{}
	add := func(id *uint64) error {
		if id == nil || excluded[*id] || cborLookup(value, *id) == nil {
			return cborRefError("domain_projection")
		}
		excluded[*id] = true
		return nil
	}
	definition := r.registry.Maps[name]
	switch part.Projection {
	case "without_signature":
		err = add(definition.SignatureField)
	case "without_mac":
		err = add(definition.MACField)
	case "without_open_digest", "without_fields", "without_fields_raw":
		fields := part.Fields
		if part.Projection == "without_open_digest" {
			fields = []string{"open_digest"}
		}
		for _, field := range fields {
			id, _, lookupErr := r.namedField(name, field)
			if lookupErr != nil {
				return nil, lookupErr
			}
			if err = add(&id); err != nil {
				return nil, err
			}
		}
	default:
		return nil, cborRefError("domain_projection")
	}
	if err != nil {
		return nil, err
	}
	projected := &cborRefValue{major: 5}
	for _, pair := range value.pairs {
		if !excluded[pair[0].n] {
			projected.pairs = append(projected.pairs, pair)
		}
	}
	encoded := projected.encode(nil)
	if part.Projection == "without_fields_raw" {
		return encoded, nil
	}
	return domainLP(encoded)
}

func (r *domainReference) part(part domainRefPart, args map[string]any, context cborShapeContext, cap uint64) ([]byte, error) {
	if part.Encoding == "hex" {
		raw, err := hex.DecodeString(part.Hex)
		if err != nil {
			return nil, cborRefError("registry_unresolved")
		}
		return raw, nil
	}
	value := args[part.Name]
	if part.Const != nil {
		value = *part.Const
	}
	if part.ConstRef != "" {
		if err := json.Unmarshal(r.registry.FieldRegistries[part.ConstRef], &value); err != nil {
			return nil, cborRefError("registry_unresolved")
		}
	}
	width := map[string]int{"u8": 1, "u32": 4, "u64": 8}[part.Encoding]
	if width != 0 {
		output, err := domainUnsigned(value, width)
		if err != nil {
			return nil, err
		}
		n, _ := domainInteger(value)
		if part.Enum != nil {
			found := false
			for _, candidate := range part.Enum {
				found = found || n == candidate
			}
			if !found {
				return nil, cborRefError("domain_enum")
			}
		}
		if part.Min != nil && n < uint64(*part.Min) || part.Max != nil && n > uint64(*part.Max) {
			return nil, cborRefError("domain_integer_range")
		}
		if part.MultipleOf != nil {
			if *part.MultipleOf == 0 {
				return nil, cborRefError("registry_unresolved")
			}
			if n%uint64(*part.MultipleOf) != 0 {
				return nil, cborRefError("domain_integer_multiple")
			}
		}
		return output, nil
	}
	if part.Encoding == "lp-ascii" {
		text, ok := value.(string)
		if !ok || len(text) == 0 {
			return nil, cborRefError("domain_ascii")
		}
		for _, b := range []byte(text) {
			if b > 127 {
				return nil, cborRefError("domain_ascii")
			}
		}
		if part.TextEnumRef != "" {
			var entries map[string]json.RawMessage
			if json.Unmarshal(r.registry.FieldRegistries[part.TextEnumRef], &entries) != nil {
				return nil, cborRefError("registry_unresolved")
			}
			if _, ok := entries[text]; !ok {
				return nil, cborRefError("domain_enum")
			}
		}
		return domainLP([]byte(text))
	}
	raw, ok := value.([]byte)
	if !ok {
		return nil, cborRefError("domain_bytes_type")
	}
	if part.Encoding == "lp-map" {
		return r.mapPart(part, raw, args, context, cap)
	}
	if part.Encoding != "raw" && part.Encoding != "lp-bytes" {
		return nil, cborRefError("registry_unresolved")
	}
	if part.Length != nil {
		if uint64(len(raw)) != uint64(*part.Length) {
			return nil, cborRefError("domain_bytes_length")
		}
	} else {
		if part.MaxLength == nil {
			return nil, cborRefError("registry_unresolved")
		}
		if uint64(len(raw)) > uint64(*part.MaxLength) {
			return nil, cborRefError("domain_bytes_length")
		}
	}
	if part.Nonzero {
		nonzero := false
		for _, b := range raw {
			nonzero = nonzero || b != 0
		}
		if !nonzero {
			return nil, cborRefError("domain_zero_secret")
		}
	}
	if part.Encoding == "raw" {
		return bytes.Clone(raw), nil
	}
	return domainLP(raw)
}

func (r *domainReference) evaluate(name string, args map[string]any, context cborShapeContext, cap uint64) (*domainRefResult, error) {
	if cap == 0 {
		return nil, cborRefError("limit_unresolved")
	}
	domain, ok := r.domains[name]
	if !ok {
		return nil, cborRefError("domain_unknown")
	}
	fields := append([]domainRefPart(nil), domain.Input.Parts...)
	for _, field := range []*domainRefPart{domain.Input.Key, domain.Input.Salt, domain.Input.IKM} {
		if field != nil {
			fields = append(fields, *field)
		}
	}
	expected := map[string]bool{}
	for _, field := range fields {
		if field.Name != "" {
			expected[field.Name] = true
		}
	}
	if len(args) != len(expected) {
		return nil, cborRefError("domain_arguments")
	}
	for name := range expected {
		if _, ok := args[name]; !ok {
			return nil, cborRefError("domain_arguments")
		}
	}
	if profile, present := args["profile"]; present {
		text, valid := profile.(string)
		if supplied, exists := context.selectors["crypto_profile_id"]; exists && (!valid || supplied != text) {
			return nil, cborRefError("domain_context")
		}
		if !valid {
			return nil, cborRefError("domain_ascii")
		}
		selectors := map[string]string{}
		for key, value := range context.selectors {
			selectors[key] = value
		}
		selectors["crypto_profile_id"] = text
		context.selectors = selectors
	}
	label, err := hex.DecodeString(domain.Label)
	if err != nil {
		return nil, cborRefError("registry_unresolved")
	}
	content := []byte{}
	for _, part := range domain.Input.Parts {
		raw, err := r.part(part, args, context, cap)
		if err != nil {
			return nil, err
		}
		content = append(content, raw...)
	}
	for _, rule := range domain.Input.Relations {
		left, err := domainInteger(args[rule.Left])
		if err != nil {
			return nil, err
		}
		right, err := domainInteger(args[rule.Right])
		if err != nil {
			return nil, err
		}
		valid := false
		switch rule.Op {
		case "successor":
			valid = left != math.MaxUint64 && left+1 == right
		case "allowed_pairs":
			for _, pair := range rule.Pairs {
				valid = valid || pair[0] == left && pair[1] == right
			}
		default:
			return nil, cborRefError("registry_unresolved")
		}
		if !valid {
			return nil, cborRefError("domain_relation")
		}
	}
	input := content
	if domain.Operation != "tls-exporter" && domain.Operation != "sha256-raw" {
		input = append(bytes.Clone(label), content...)
	}
	result := &domainRefResult{Label: label, Input: input}
	if domain.Operation == "sha256" || domain.Operation == "sha256-raw" || domain.Operation == "hmac-sha256" || domain.Operation == "hkdf-expand" || domain.Operation == "hkdf-extract" {
		if domain.OutputLength == nil || *domain.OutputLength != sha256.Size {
			return nil, cborRefError("registry_unresolved")
		}
	}
	switch domain.Operation {
	case "sha256", "sha256-raw":
		digest := sha256.Sum256(input)
		result.Output = digest[:]
	case "hmac-sha256", "hkdf-expand":
		if domain.Input.Key == nil {
			return nil, cborRefError("registry_unresolved")
		}
		key, err := r.part(*domain.Input.Key, args, context, cap)
		if err != nil {
			return nil, err
		}
		mac := hmac.New(sha256.New, key)
		_, _ = mac.Write(input)
		if domain.Operation == "hkdf-expand" {
			_, _ = mac.Write([]byte{1})
		}
		result.Output = mac.Sum(nil)
	case "hkdf-extract":
		if domain.Input.Salt == nil || domain.Input.IKM == nil || len(label) != 0 || len(domain.Input.Parts) != 0 {
			return nil, cborRefError("registry_unresolved")
		}
		result.Salt, err = r.part(*domain.Input.Salt, args, context, cap)
		if err != nil {
			return nil, err
		}
		result.IKM, err = r.part(*domain.Input.IKM, args, context, cap)
		if err != nil {
			return nil, err
		}
		mac := hmac.New(sha256.New, result.Salt)
		_, _ = mac.Write(result.IKM)
		result.Output = mac.Sum(nil)
	case "tls-exporter":
		if domain.OutputLength == nil {
			return nil, cborRefError("registry_unresolved")
		}
		length := *domain.OutputLength
		result.OutputLength = &length
	case "ed25519", "aead-aad", "noise-prologue":
	default:
		return nil, cborRefError("registry_unresolved")
	}
	return result, nil
}
