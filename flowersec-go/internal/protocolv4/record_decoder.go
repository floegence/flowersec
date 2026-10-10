package protocolv4

import (
	"encoding/json"
	"regexp/syntax"
	"sync"
	"unicode/utf8"
)

// Text normalization reuses one workspace for each scalar. Binary payloads and
// arrays of small scalars therefore do not require payload-sized rune storage.
// Discover the scalar bound from the generated record schemas, including every
// nested map. An unresolved future text grammar fails construction explicitly.
var recordTextCapacity = sync.OnceValues(func() (int, error) {
	r, err := runtimeSchema()
	if err != nil {
		return 0, err
	}
	var schemas []string
	for name := range r.Maps {
		if recordSchema(name) {
			schemas = append(schemas, name)
		}
	}
	return schemaTextCapacity(r, schemas)
})

// Each normalization operation consumes one scalar, even in large binary maps
// or arrays. Walk every fixed nested schema and variant before admitting its
// workspace; a missing text bound cannot silently reduce supported input.
func schemaTextCapacity(r *wireRegistry, schemas []string) (int, error) {
	seen := map[string]bool{}
	maximum := uint64(0)
	var visitMap func(string) error
	var visitField func(*wireField) error
	visitField = func(f *wireField) error {
		if f == nil {
			return nil
		}
		if f.Type == "text" {
			switch {
			case f.MaxBytes != nil:
				maximum = max(maximum, uint64(*f.MaxBytes))
			case f.constant != nil && f.constant.major == 3:
				maximum = max(maximum, uint64(len(f.constant.text)))
			case len(f.texts) != 0:
				for text := range f.texts {
					maximum = max(maximum, uint64(len(text)))
				}
			case f.pattern != nil:
				pattern, err := syntax.Parse(f.pattern.String(), syntax.Perl)
				if err != nil {
					return err
				}
				bound, ok := patternTextCapacity(pattern)
				if !ok {
					return CBORFailure("record_text_bound_unresolved")
				}
				maximum = max(maximum, uint64(bound))
			case f.TextFormat == "origin":
				var schemes map[string]json.RawMessage
				if json.Unmarshal(r.Fields["origin_schemes"], &schemes) != nil || len(schemes) == 0 {
					return CBORFailure("registry_unresolved")
				}
				// The existing Origin grammar accepts only a registered scheme,
				// a canonical ASCII host, optional IPv6 brackets and uint16 port.
				for scheme := range schemes {
					maximum = max(maximum, uint64(len(scheme)+3+wireDNSMaxBytes+2+1+5))
				}
			default:
				return CBORFailure("record_text_bound_unresolved")
			}
		}
		for _, name := range []string{f.SchemaRef, f.EncodedSchemaRef} {
			if name != "" {
				if err := visitMap(name); err != nil {
					return err
				}
			}
		}
		for _, child := range []*wireField{f.Items, f.Keys, f.Values} {
			if err := visitField(child); err != nil {
				return err
			}
		}
		for _, group := range []map[string]*wireField{f.Entries, f.Cases} {
			for _, child := range group {
				if err := visitField(child); err != nil {
					return err
				}
			}
		}
		return nil
	}
	visitMap = func(name string) error {
		if seen[name] {
			return nil
		}
		m := r.Maps[name]
		if m == nil {
			return CBORFailure("unknown_schema")
		}
		seen[name] = true
		for _, field := range m.Fields {
			if err := visitField(field); err != nil {
				return err
			}
		}
		return nil
	}
	for _, name := range schemas {
		if err := visitMap(name); err != nil {
			return 0, err
		}
	}
	if maximum > uint64(MaxPayloadLength) {
		return 0, CBORFailure("configuration_capacity")
	}
	return int(maximum), nil
}

// Derive finite byte bounds from the generated pattern itself. In particular,
// security identifiers must not acquire a second, independently maintained cap.
func patternTextCapacity(pattern *syntax.Regexp) (int, bool) {
	switch pattern.Op {
	case syntax.OpEmptyMatch, syntax.OpBeginLine, syntax.OpEndLine, syntax.OpBeginText, syntax.OpEndText, syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		return 0, true
	case syntax.OpLiteral:
		bound := 0
		for _, cp := range pattern.Rune {
			bound += utf8.RuneLen(cp)
		}
		return bound, bound <= MaxPayloadLength
	case syntax.OpCharClass:
		bound := 0
		for _, cp := range pattern.Rune {
			bound = max(bound, utf8.RuneLen(cp))
		}
		return bound, true
	case syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		return utf8.UTFMax, true
	case syntax.OpCapture, syntax.OpQuest, syntax.OpRepeat:
		bound, ok := patternTextCapacity(pattern.Sub[0])
		count := 1
		if pattern.Op == syntax.OpRepeat {
			count = pattern.Max
		}
		if !ok || count < 0 || bound != 0 && count > MaxPayloadLength/bound {
			return 0, false
		}
		return bound * count, true
	case syntax.OpConcat, syntax.OpAlternate:
		bound := 0
		for _, child := range pattern.Sub {
			n, ok := patternTextCapacity(child)
			if !ok {
				return 0, false
			}
			if pattern.Op == syntax.OpAlternate {
				bound = max(bound, n)
			} else {
				if n > MaxPayloadLength-bound {
					return 0, false
				}
				bound += n
			}
		}
		return bound, true
	default:
		return 0, false
	}
}

func RecordDecoderBackingBytes(byteCap, nodeCap int) (uint64, error) {
	textCap, err := recordTextCapacity()
	if err != nil {
		return 0, err
	}
	return decoderBackingBytes(byteCap, nodeCap, min(byteCap, textCap))
}

func NewRecordDecoder(byteCap, nodeCap int) (*Decoder, error) {
	textCap, err := recordTextCapacity()
	if err != nil {
		return nil, err
	}
	d, err := newDecoderWorkspace(byteCap, nodeCap, min(byteCap, textCap))
	if err != nil {
		return nil, err
	}
	// Admission still reserves the complete original byte/node/text charge.
	// A record owns its input copy and arena only through its actual Release.
	d.byteLimit, d.nodeLimit = byteCap, nodeCap
	return d, nil
}
