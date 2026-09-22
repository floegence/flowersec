package protocolv4

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestRuntimeCBORShapeCorpus(t *testing.T) {
	vectors := cborRefVectors(t)
	maxBytes := 1
	for _, v := range vectors {
		if len(v.Hex)/2 > maxBytes {
			maxBytes = len(v.Hex) / 2
		}
	}
	d, err := NewDecoder(maxBytes, maxBytes*2)
	if err != nil {
		t.Fatal(err)
	}
	// Syntax and field shape are a distinct gate. Cross-field rules,
	// signatures and live ownership are exercised by their actual consumers.
	codes := map[string]bool{}
	for _, code := range []string{"non_canonical_text", "unassigned_code_point", "invalid_utf8", "unsupported_type", "array_limit", "duplicate_key", "non_shortest_integer", "map_order", "truncated", "trailing_bytes", "field_id_type", "indefinite_length", "depth_limit", "invalid_header", "map_limit", "unknown_field", "missing_field", "integer_type", "integer_range", "constant_mismatch", "field_type", "field_length", "field_nonzero", "text_pattern", "reserved_namespace", "enum_value", "unknown_bits", "map_type", "map_length", "array_length", "map_size"} {
		codes[code] = true
	}
	for _, v := range vectors {
		if v.ExpectedError != "" && !codes[v.ExpectedError] || v.ID == "admission_rejected_unknown_code" || v.ID == "context_auth_exporter_bytes" {
			continue
		}
		t.Run(v.ID, func(t *testing.T) {
			input, err := hex.DecodeString(v.Hex)
			if err != nil {
				t.Fatal(err)
			}
			original := bytes.Clone(input)
			context := shapeContext(v.Limits)
			doc, err := d.DecodeShape(input, v.Schema, DecodeContext{Limits: context.limits, Selectors: context.selectors})
			if v.ExpectedError != "" {
				if err == nil {
					doc.Release()
					t.Fatal("accepted malformed shape")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer doc.Release()
			clear(input)
			if !bytes.Equal(doc.Bytes(), original) || !bytes.Equal(doc.Root().Encoded(), original) {
				t.Fatal("snapshot was rewritten or aliases caller input")
			}
		})
	}
}

func TestRuntimeCBOROwnershipAndBounds(t *testing.T) {
	d, err := NewDecoder(128, 4)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := d.DecodeShape([]byte{0xa1, 0, 1}, "", DecodeContext{})
	if err != nil {
		t.Fatal(err)
	}
	view := doc.Root().Field(0)
	if n, ok := view.Uint(); !ok || n != 1 {
		t.Fatal("missing value")
	}
	if _, err := d.DecodeShape([]byte{0}, "", DecodeContext{}); err != CBORFailure("decoder_busy") {
		t.Fatal(err)
	}
	doc.Release()
	if _, ok := view.Uint(); ok {
		t.Fatal("released view is live")
	}
	next, err := d.DecodeShape([]byte{1}, "", DecodeContext{})
	if err != nil {
		t.Fatal(err)
	}
	doc.Release()
	if n, ok := next.Root().Uint(); !ok || n != 1 {
		t.Fatal("stale release reclaimed a later owner")
	}
	next.Release()
	if _, err := d.DecodeShape([]byte{0x84, 0, 0, 0, 0}, "", DecodeContext{}); err != CBORFailure("node_capacity") {
		t.Fatal(err)
	}
	if _, err := d.DecodeShape(make([]byte, 129), "", DecodeContext{}); err != CBORFailure("map_size") {
		t.Fatal(err)
	}
	if _, err := d.DecodeShape([]byte{0x9b, 255, 255, 255, 255, 255, 255, 255, 255}, "", DecodeContext{}); err != CBORFailure("array_limit") {
		t.Fatal(err)
	}
}
