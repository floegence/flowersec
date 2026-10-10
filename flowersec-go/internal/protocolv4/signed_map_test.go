package protocolv4

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"strings"
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

func TestSignedMapCopyRetainsIndependentOriginalSignatureFact(t *testing.T) {
	f := newRuntimeAdmissionFixture(t, "preauthorized_pool", 5)
	source := f.artifact
	wire, err := source.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	original := bytes.Clone(wire)
	key := source.Key()
	codec, err := NewSignedMapCodec("Artifact", 65536, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = source.codec.CopyVerified(source, DecodeContext{}); err != CBORFailure("decoder_busy") {
		t.Fatal("self-copy must refuse without waiting", err)
	}
	wrong, err := NewSignedMapCodec("IdentityCertificate", 65536, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = wrong.CopyVerified(source, DecodeContext{}); err != CBORFailure("signature_schema") {
		t.Fatal("signature fact crossed schema domains", err)
	}
	bounded, err := NewSignedMapCodec("Artifact", len(original)-1, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = bounded.CopyVerified(source, DecodeContext{}); err == nil {
		t.Fatal("copy escaped destination byte capacity")
	}
	copyOwner, err := codec.CopyVerified(source, DecodeContext{})
	if err != nil {
		t.Fatal(err)
	}
	defer copyOwner.Release()
	if _, err = codec.CopyVerified(source, DecodeContext{}); err != CBORFailure("decoder_busy") {
		t.Fatal("copy replaced a retained owner", err)
	}
	source.Release()
	actual, err := copyOwner.Bytes()
	if err != nil || !bytes.Equal(actual, original) || copyOwner.Key() != key {
		t.Fatal("source cleanup changed the copied signature fact", err)
	}
	if _, err = source.codec.CopyVerified(source, DecodeContext{}); err != CBORFailure("document_released") {
		t.Fatal("released original created another signature fact", err)
	}
	verified, err := source.codec.Verify(actual, key, DecodeContext{})
	if err != nil {
		t.Fatal("copy changed exact signature bytes", err)
	}
	defer verified.Release()
}

func TestSignedMapReusableArenaPreservesIndependentIssuerJobs(t *testing.T) {
	f := newRuntimeAdmissionFixture(t, "live_authority", 5)
	large := f.mutate(t, f.certificate, "IdentityCertificate", func(root *cborRefValue) {
		oracleField(t, f.r.cborReference, "IdentityCertificate", root, "subject_id").data = []byte(strings.Repeat("a", 128))
	})
	codec, err := NewSignedMapCodec("IdentityCertificate", 65536, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if codec.decoder.byteLimit != 65536 || codec.decoder.input != nil || codec.decoder.nodeLimit != 4096 || codec.decoder.nodes != nil || len(codec.encoded) != 65536 || len(codec.message) != 65536+len(codec.domain.label)+4 {
		t.Fatal("reusable issuer lost complete backing or allocated idle nodes")
	}
	seed := [32]byte{71, 23, 4}
	signer := &admissionTestSigner{key: ed25519.NewKeyFromSeed(seed[:])}
	guard := func() error { return nil }
	// These are independent bounded issuer jobs. Admission's once gate remains
	// responsible for refusing another signature for the same original request.
	for _, original := range []*SignedMap{f.certificate, large, f.certificate} {
		wire, err := original.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		fields := unsignedFixtureFields(t, original.document, original.codec.signatureID)
		signer.bad = true
		if signed, err := codec.SignWith(fields, original.Key(), signer, DecodeContext{}, guard); signed != nil || err != errSignatureGeneration {
			t.Fatal("invalid provider signature produced an issuer fact", err)
		}
		if codec.current != nil || codec.decoder.active || codec.decoder.input != nil || codec.decoder.nodes != nil || codec.decoder.used != 0 || codec.decoder.size != 0 {
			t.Fatal("failed signing retained its original decoder arena")
		}
		signer.bad = false
		signed, err := codec.SignWith(fields, original.Key(), signer, DecodeContext{}, guard)
		if err != nil {
			t.Fatal("failed signing reduced a later independent job's capacity", err)
		}
		actual, err := signed.Bytes()
		if err != nil || !bytes.Equal(actual, wire) || len(codec.decoder.input) != len(wire) || len(codec.decoder.nodes) != codec.decoder.used {
			t.Fatal("issuer changed the original canonical map or current arena", err)
		}
		if _, err := codec.Verify(wire, original.Key(), DecodeContext{}); err != CBORFailure("decoder_busy") || !bytes.Equal(actual, wire) {
			t.Fatal("verification replaced the live issuer document", err)
		}
		view := signed.Field(codec.signatureName)
		signed.Release()
		if _, ok := view.ByteString(); ok || codec.decoder.input != nil || codec.decoder.nodes != nil || codec.decoder.active || !bytes.Equal(actual, make([]byte, len(actual))) {
			t.Fatal("Release retained live issuer views, nodes or signed bytes")
		}
		wrong := original.Key()
		wrong[0] ^= 1
		if _, err := codec.Verify(wire, wrong, DecodeContext{}); err != CBORFailure("signature_invalid") {
			t.Fatal("wrong verifier key was accepted", err)
		}
		if codec.current != nil || codec.decoder.active || codec.decoder.input != nil || codec.decoder.nodes != nil || codec.decoder.used != 0 || codec.decoder.size != 0 {
			t.Fatal("failed verification retained its original decoder arena")
		}
		verified, err := codec.Verify(wire, original.Key(), DecodeContext{})
		if err != nil {
			t.Fatal("failed verification reduced the original reusable capacity", err)
		}
		signed.Release()
		actual, err = verified.Bytes()
		if err != nil || !bytes.Equal(actual, wire) {
			t.Fatal("stale issuer cleanup reclaimed the next verification", err)
		}
		verified.Release()
		if codec.decoder.byteLimit != 65536 || codec.decoder.input != nil || len(codec.encoded) != 65536 || len(codec.message) != 65536+len(codec.domain.label)+4 || len(codec.decoder.nodes) != 0 {
			t.Fatal("reusable signed-map exit lost complete next-job capacities")
		}
	}
}
