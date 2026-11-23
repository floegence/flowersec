package protocolv4

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

func unsignedFixtureFields(t *testing.T, doc *Document, signature uint64) []Field {
	t.Helper()
	d := doc.decoder
	m := d.registry.Maps[doc.schema]
	var fields []Field
	for name, spec := range m.byName {
		if spec.id == signature {
			continue
		}
		value := doc.Root().Field(spec.id)
		if !value.valid() {
			continue
		}
		field := Field{Name: name}
		n := d.nodes[value.index]
		switch n.major {
		case 0:
			field.Number = n.n
		case 2:
			field.Kind = ByteString
			field.Bytes, _ = value.ByteString()
		case 3:
			field.Kind = TextString
			field.Text, _ = value.Text()
		case 4:
			field.Kind, field.Bytes = EncodedArray, value.Encoded()
		case 5:
			field.Kind, field.Bytes = EncodedMap, value.Encoded()
		case 7:
			field.Kind, field.Number = Boolean, n.n-20
		default:
			t.Fatal("unsupported fixture field")
		}
		fields = append(fields, field)
	}
	return fields
}

func TestSignedMapRuntimeMatchesRegisteredSignatureCorpus(t *testing.T) {
	raw, err := os.ReadFile("../../../testdata/transport_v4/signatures.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Seed    string `json:"signing_seed_hex"`
		Vectors []struct {
			Domain    string
			Fixture   string `json:"domain_vector"`
			Signature string `json:"signature_hex"`
			Key       string `json:"public_key_hex"`
			Accept    bool
		}
	}
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	r, err := runtimeSignedMaps()
	if err != nil {
		t.Fatal(err)
	}
	fixtures := map[string]domainFixture{}
	for _, fixture := range domainFixtures(t) {
		fixtures[fixture.ID] = fixture
	}
	covered := map[string]bool{}
	for _, vector := range corpus.Vectors {
		if !vector.Accept || vector.Fixture == "" {
			continue
		}
		schema := ""
		for candidate, domain := range r.signatures {
			if domain.Name == vector.Domain {
				schema = candidate
			}
		}
		if schema == "" {
			continue // READY/hop possession use their distinct composite owners.
		}
		t.Run(vector.Fixture, func(t *testing.T) {
			fixture := fixtures[vector.Fixture]
			var wire []byte
			for _, value := range fixture.args(t) {
				wire = value.([]byte)
			}
			shape := shapeContext(fixture.Context)
			context := DecodeContext{Limits: shape.limits, Selectors: shape.selectors}
			decoder, err := NewDecoder(len(wire), len(wire)*2)
			if err != nil {
				t.Fatal(err)
			}
			doc, err := decoder.DecodeShape(wire, schema, context)
			if err != nil {
				t.Fatal(err)
			}
			defer doc.Release()
			codec, err := NewSignedMapCodec(schema, len(wire), len(wire)*2)
			if err != nil {
				t.Fatal(err)
			}
			fields := unsignedFixtureFields(t, doc, codec.signatureID)
			signed, err := codec.Sign(fields, [32]byte(domainHex(t, corpus.Seed)), context)
			if err != nil {
				t.Fatal(err)
			}
			defer signed.Release()
			sig, ok := signed.Field(codec.signatureName).ByteString()
			if !ok || !bytes.Equal(sig, domainHex(t, vector.Signature)) || signed.Key() != [32]byte(domainHex(t, vector.Key)) {
				t.Fatal("runtime signing differs from original domain vector")
			}
			input, err := signed.Bytes()
			if err != nil {
				t.Fatal(err)
			}
			original := bytes.Clone(input)
			if _, err := codec.Verify(original, signed.Key(), context); err != CBORFailure("decoder_busy") {
				t.Fatal("retained owner was replaced", err)
			}
			signed.Release()
			verified, err := codec.Verify(original, signed.Key(), context)
			if err != nil {
				t.Fatal(err)
			}
			clear(original)
			signed.Release() // Stale cleanup cannot reclaim the next document.
			actual, err := verified.Bytes()
			if err != nil || bytes.Equal(actual, original) {
				t.Fatal("verification borrowed caller or stale owner storage", err)
			}
			if _, err := verified.Digest("record_aad"); err != CBORFailure("digest_schema") {
				t.Fatal("unrelated domain admitted", err)
			}
			corrupt := bytes.Clone(actual)
			corrupt[len(corrupt)-1] ^= 1
			verified.Release()
			if _, err := codec.Verify(corrupt, signed.Key(), context); err == nil {
				t.Fatal("mutated complete credential accepted")
			}
			if _, err := signed.Bytes(); err != CBORFailure("document_released") {
				t.Fatal(err)
			}
			covered[schema] = true
		})
	}
	for schema := range r.signatures {
		if !covered[schema] {
			t.Error("missing production signed-map coverage", schema)
		}
	}
}

func TestSignedMapDigestPreservesOriginalSignedBytes(t *testing.T) {
	r, err := runtimeSignedMaps()
	if err != nil {
		t.Fatal(err)
	}
	for _, fixture := range domainFixtures(t) {
		domain, ok := r.digests[fixture.Domain]
		if !ok || fixture.ExpectedError != "" {
			continue
		}
		schema := domain.Input.Parts[0].Schema
		if _, ok := r.signatures[schema]; !ok {
			continue
		}
		t.Run(fixture.ID, func(t *testing.T) {
			var wire []byte
			for _, value := range fixture.args(t) {
				wire = value.([]byte)
			}
			codec, err := NewSignedMapCodec(schema, len(wire), len(wire)*2)
			if err != nil {
				t.Fatal(err)
			}
			shape := shapeContext(fixture.Context)
			doc, err := codec.decoder.DecodeShape(wire, schema, DecodeContext{Limits: shape.limits, Selectors: shape.selectors})
			if err != nil {
				t.Fatal(err)
			}
			// These digest vectors carry opaque fixture signatures. Isolate the
			// registered digest projection from issuer/signature admission.
			m := &SignedMap{codec: codec, document: doc}
			codec.current = m
			defer m.Release()
			digest, err := m.Digest(fixture.Domain)
			if err != nil || !bytes.Equal(digest[:], domainHex(t, fixture.Result.Output)) {
				t.Fatal("digest did not match the original registered projection", err)
			}
		})
	}
}
