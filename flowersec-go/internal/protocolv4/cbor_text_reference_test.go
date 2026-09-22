package protocolv4

// Test-only signed DNS/host/Origin syntax. Passing this reference does not
// authorize actual DNS, TLS, HTTP admission, origin headers or provider behavior.
import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

type cborTextReference struct {
	*cborReference
	idna *idnaReference
}

func newCBORTextReference(t testing.TB) *cborTextReference {
	r := newCBORReference(t)
	return &cborTextReference{cborReference: r, idna: newIDNAReference(t, r)}
}

var numericHost = regexp.MustCompile(`^[0-9.]+$`)
var numericLastLabel = regexp.MustCompile(`^(?:[0-9]+|0x[0-9a-f]*)$`)
var originPattern = regexp.MustCompile(`^([a-z][a-z0-9+.-]*)://(\[[0-9a-f:]+\]|[^:/?#@\\\[\]]+)(?::([0-9]+))?$`)
var originPort = regexp.MustCompile(`^(?:0|[1-9][0-9]{0,4})$`)

func forbiddenHostRune(cp rune) bool {
	// The explicit host separator/whitespace set does not depend on Go's
	// current Unicode property tables. U+0085 remains an IDNA validity error.
	if cp >= 9 && cp <= 13 || cp >= 0x2000 && cp <= 0x200a {
		return true
	}
	switch cp {
	case ' ', '[', ']', '%', '\\', '/', '?', '#', '@', 0xa0, 0x1680, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff:
		return true
	}
	return false
}

func ipv6Hex(addr netip.Addr) string {
	data := addr.As16()
	words, text := [8]uint16{}, make([]string, 8)
	for i := range words {
		words[i] = binary.BigEndian.Uint16(data[i*2 : i*2+2])
		text[i] = strconv.FormatUint(uint64(words[i]), 16)
	}
	best, length := -1, 1
	for i := 0; i < len(words); {
		if words[i] != 0 {
			i++
			continue
		}
		end := i + 1
		for end < len(words) && words[end] == 0 {
			end++
		}
		if end-i > length {
			best, length = i, end-i
		}
		i = end
	}
	if best < 0 {
		return strings.Join(text, ":")
	}
	return strings.Join(text[:best], ":") + "::" + strings.Join(text[best+length:], ":")
}

func (r *cborTextReference) issuerHost(input string) (string, error) {
	if input == "" {
		return "", cborRefError("host_text")
	}
	if strings.ContainsFunc(input, forbiddenHostRune) {
		return "", cborRefError("host_syntax")
	}
	if strings.Contains(input, ":") {
		addr, err := netip.ParseAddr(input)
		if err != nil || !addr.Is6() {
			return "", cborRefError("host_ipv6")
		}
		// Preserve IPv4-mapped address family and all bits; never Unmap.
		return ipv6Hex(addr), nil
	}
	if numericHost.MatchString(input) {
		addr, err := netip.ParseAddr(input)
		if err != nil || !addr.Is4() {
			return "", cborRefError("host_ipv4")
		}
		return addr.String(), nil
	}
	dns, err := r.idna.issuerDNS(input)
	if err != nil {
		return "", err
	}
	if numericLastLabel.MatchString(dns[strings.LastIndexByte(dns, '.')+1:]) {
		return "", cborRefError("host_numeric_final_label")
	}
	return dns, nil
}

func (r *cborTextReference) wireHost(input string) error {
	if input == "" || strings.ContainsFunc(input, func(cp rune) bool { return cp >= 128 }) {
		return cborRefError("host_wire_ascii")
	}
	canonical, err := r.issuerHost(input)
	if err != nil {
		return err
	}
	if canonical != input {
		return cborRefError("host_noncanonical")
	}
	return nil
}

func (r *cborTextReference) originDefaultPort(scheme string) (uint64, error) {
	entries, err := r.fieldRegistry("origin_schemes")
	if err != nil {
		return 0, err
	}
	raw, ok := entries[scheme]
	if !ok {
		return 0, cborRefError("origin_scheme_unregistered")
	}
	var entry struct {
		Port *uint64 `json:"default_port"`
	}
	if json.Unmarshal(raw, &entry) != nil || entry.Port == nil {
		return 0, cborRefError("registry_unresolved")
	}
	return *entry.Port, nil
}

func (r *cborTextReference) wireOrigin(input string) error {
	if input == "" || strings.ContainsFunc(input, func(cp rune) bool { return cp < 0x21 || cp > 0x7e }) {
		return cborRefError("origin_ascii")
	}
	parts := originPattern.FindStringSubmatch(input)
	if parts == nil {
		return cborRefError("origin_syntax")
	}
	defaultPort, err := r.originDefaultPort(parts[1])
	if err != nil {
		return err
	}
	host := parts[2]
	if strings.HasPrefix(host, "[") {
		host = host[1 : len(host)-1]
		if !strings.Contains(host, ":") {
			return cborRefError("origin_syntax")
		}
	}
	if err := r.wireHost(host); err != nil {
		return err
	}
	if portText := parts[3]; portText != "" {
		port, err := strconv.ParseUint(portText, 10, 16)
		if err != nil || !originPort.MatchString(portText) {
			return cborRefError("origin_port")
		}
		if port == defaultPort {
			return cborRefError("origin_default_port")
		}
	}
	return nil
}

func (r *cborTextReference) textFormat(format, value string) error {
	switch format {
	case "host":
		return r.wireHost(value)
	case "origin":
		return r.wireOrigin(value)
	case "loopback_host":
		if err := r.wireHost(value); err != nil {
			return err
		}
		addr, err := netip.ParseAddr(value)
		if err != nil || !(value == "::1" || addr.Is4() && addr.As4()[0] == 127) {
			return cborRefError("host_loopback")
		}
		return nil
	}
	return cborRefError("text_format_unresolved")
}

func (r *cborTextReference) fieldFormats(field *cborRefField, value *cborRefValue, context cborShapeContext) error {
	field, err := r.resolveShapeField(field, context)
	if err != nil {
		return err
	}
	if field.TextFormat != "" {
		if value.major != 3 {
			return cborRefError("field_type")
		}
		return r.textFormat(field.TextFormat, string(value.data))
	}
	switch field.Type {
	case "array":
		for _, item := range value.items {
			if err := r.fieldFormats(field.Items, item, context); err != nil {
				return err
			}
		}
	case "text_map":
		for _, pair := range value.pairs {
			if err := r.fieldFormats(field.Keys, pair[0], context); err != nil {
				return err
			}
			child := field.Values
			if field.Entries != nil {
				child = field.Entries[string(pair[0].data)]
			}
			if err := r.fieldFormats(child, pair[1], context); err != nil {
				return err
			}
		}
	}
	// Map/embedded document children are visited by the common rule walker.
	return nil
}

func (r *cborTextReference) checkTextMap(name string, value *cborRefValue, context cborShapeContext) error {
	for _, pair := range value.pairs {
		field := r.registry.Maps[name].Fields[strconv.FormatUint(pair[0].n, 10)]
		if err := r.fieldFormats(field, pair[1], context); err != nil {
			return err
		}
	}
	if err := r.checkRelations(name, value, context); err != nil {
		return err
	}
	for _, raw := range r.registry.TextRules[name] {
		var rule struct {
			Op, Field, Format, Host, Port, Origin, Scheme string
			When                                          *cborRuleCondition
		}
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&rule) != nil {
			return cborRefError("rule_unresolved")
		}
		applies, err := r.ruleApplies(name, value, rule.When, context)
		if err != nil {
			return err
		}
		if !applies {
			continue
		}
		switch rule.Op {
		case "text_format":
			v, err := r.variantPath(name, value, rule.Field, context)
			if err != nil {
				return err
			}
			if v == nil || v.major != 3 {
				return cborRefError("field_type")
			}
			if err := r.textFormat(rule.Format, string(v.data)); err != nil {
				return err
			}
		case "origin_endpoint":
			fields := make([]*cborRefValue, 0, 3)
			for _, field := range []string{rule.Host, rule.Port, rule.Origin} {
				v, err := r.variantPath(name, value, field, context)
				if err != nil || v == nil {
					return cborRefError("unknown_rule_field")
				}
				fields = append(fields, v)
			}
			if fields[0].major != 3 || fields[1].major != 0 || fields[2].major != 3 {
				return cborRefError("field_type")
			}
			host := string(fields[0].data)
			if strings.Contains(host, ":") {
				host = "[" + host + "]"
			}
			defaultPort, err := r.originDefaultPort(rule.Scheme)
			if err != nil {
				return err
			}
			expected := rule.Scheme + "://" + host
			if fields[1].n != defaultPort {
				expected += ":" + strconv.FormatUint(fields[1].n, 10)
			}
			if expected != string(fields[2].data) {
				return cborRefError("origin_endpoint")
			}
		default:
			return cborRefError("rule_unresolved")
		}
	}
	return nil
}

func (r *cborTextReference) wireMap(input []byte, name string, context cborShapeContext, cap uint64) (*cborRefValue, error) {
	value, err := r.shape(input, name, context, cap)
	if err != nil {
		return nil, err
	}
	if name != "" {
		if err := r.walkRuleMap(name, value, context, r.checkTextMap); err != nil {
			return nil, err
		}
	}
	return value, nil
}

// v4.cbor.text_corpus
func TestCBORTextReferenceCorpus(t *testing.T) {
	r := newCBORTextReference(t)
	raw, err := os.ReadFile("../../../testdata/transport_v4/text.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Vectors []struct {
			ID, Operation, Input, Output string
			ExpectedError                string `json:"expected_error"`
			Hex                          string `json:"utf8_hex"`
		}
	}
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	for _, vector := range corpus.Vectors {
		t.Run(vector.ID, func(t *testing.T) {
			output, err := vector.Input, error(nil)
			switch vector.Operation {
			case "issuer_dns":
				output, err = r.idna.issuerDNS(vector.Input)
			case "wire_dns":
				err = r.idna.wireDNS(vector.Input)
			case "issuer_host":
				output, err = r.issuerHost(vector.Input)
			case "wire_host":
				err = r.wireHost(vector.Input)
			case "wire_origin":
				err = r.wireOrigin(vector.Input)
			default:
				t.Fatal("unknown text operation")
			}
			if vector.ExpectedError != "" {
				if err == nil {
					t.Fatal("accepted invalid text")
				}
				return
			}
			if err != nil || output != vector.Output || hex.EncodeToString([]byte(output)) != vector.Hex {
				t.Fatalf("text result %q/%v, want %q", output, err, vector.Output)
			}
		})
	}
	if len(corpus.Vectors) == 0 {
		t.Fatal("empty text coverage")
	}
	t.Logf("all %d shared issuer/wire text cases passed", len(corpus.Vectors))
}

// v4.cbor.wire_maps
func TestCBORWireMapReferenceCorpus(t *testing.T) {
	r := newCBORTextReference(t)
	positive, negative := 0, 0
	for _, vector := range cborRefVectors(t) {
		if vector.ExpectedError == "pool_set_membership" || vector.ExpectedError == "open_digest_mismatch" {
			continue
		}
		t.Run(vector.ID, func(t *testing.T) {
			input, err := hex.DecodeString(vector.Hex)
			if err != nil {
				t.Fatal(err)
			}
			original := bytes.Clone(input)
			value, err := r.wireMap(input, vector.Schema, shapeContext(vector.Limits), uint64(len(input))+1)
			if !bytes.Equal(input, original) {
				t.Fatal("wire validation changed original input")
			}
			if vector.ExpectedError != "" {
				negative++
				if err == nil || value != nil {
					t.Fatal("accepted invalid wire map")
				}
				return
			}
			positive++
			if err != nil || value == nil || !bytes.Equal(value.encode(nil), input) {
				t.Fatalf("wire map result %v", err)
			}
		})
	}
	if positive == 0 || negative == 0 {
		t.Fatal("empty wire-map coverage")
	}
	t.Logf("%d positives and %d negatives; external pool/open-digest oracles excluded", positive, negative)
}

// v4.cbor.text_fuzz
func FuzzCBORTextReference(f *testing.F) {
	r := newCBORTextReference(f)
	for _, seed := range []string{"example.com", "xn--bcher-kva.example", "\u4f8b\u5b50.\u6d4b\u8bd5", "\u0915\u094d\u200d\u0937.example", "a1.\u0645\u062b\u0627\u0644", "xn--zzzzzzzzzzzzzzzzzzzzzz", "EXAMPLE.COM", "127.0.0.1", "::ffff:192.0.2.1", "2001:db8::1"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 1024 {
			return
		}
		if ascii, err := r.idna.issuerDNS(input); err == nil {
			if err := r.idna.wireDNS(ascii); err != nil {
				t.Fatalf("issuer DNS output rejected by wire rules: %q/%v", ascii, err)
			}
		}
		if canonical, err := r.issuerHost(input); err == nil {
			if err := r.wireHost(canonical); err != nil {
				t.Fatalf("issuer host output rejected by wire rules: %q/%v", canonical, err)
			}
			if err := r.wireOrigin("https://" + func() string {
				if strings.Contains(canonical, ":") {
					return "[" + canonical + "]"
				}
				return canonical
			}()); err != nil {
				t.Fatalf("canonical host failed Origin construction: %q/%v", canonical, err)
			}
		}
	})
}
