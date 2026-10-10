package protocolv4

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestOnceSigningMapMatchesRegisteredSignatureCorpus(t *testing.T) {
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
			continue
		}
		t.Run(vector.Fixture, func(t *testing.T) {
			fixture := fixtures[vector.Fixture]
			var wire []byte
			for _, value := range fixture.args(t) {
				wire = value.([]byte)
			}
			shape := shapeContext(fixture.Context)
			decode := DecodeContext{Limits: shape.limits, Selectors: shape.selectors}
			decoder, err := NewDecoder(len(wire), len(wire)*2)
			if err != nil {
				t.Fatal(err)
			}
			doc, err := decoder.DecodeShape(wire, schema, decode)
			if err != nil {
				t.Fatal(err)
			}
			defer doc.Release()
			codec, err := NewOnceSigningMapCodec(schema, len(wire), len(wire)*2)
			if err != nil {
				t.Fatal(err)
			}
			signed, err := codec.Sign(unsignedFixtureFields(t, doc, codec.signatureID), [32]byte(domainHex(t, corpus.Seed)), decode)
			if err != nil {
				t.Fatal(err)
			}
			defer signed.Release()
			signature, ok := signed.Field(codec.signatureName).ByteString()
			if !ok || !bytes.Equal(signature, domainHex(t, vector.Signature)) || signed.Key() != [32]byte(domainHex(t, vector.Key)) {
				t.Fatal("one-time signing changed the registered signature fact")
			}
			actual, err := signed.Bytes()
			if err != nil {
				t.Fatal(err)
			}
			verifier, err := NewSignedMapCodec(schema, len(wire), len(wire)*2)
			if err != nil {
				t.Fatal(err)
			}
			verified, err := verifier.Verify(actual, signed.Key(), decode)
			if err != nil {
				t.Fatal("compacted issued bytes lost their exact signature", err)
			}
			verified.Release()
			covered[schema] = true
		})
	}
	for schema := range r.signatures {
		if !covered[schema] {
			t.Error("missing one-time signed-map coverage", schema)
		}
	}
}

func TestOnceSigningMapPreservesFactsProjectionCapacityAndRetirement(t *testing.T) {
	f := newRuntimeAdmissionFixture(t, "live_authority", 5)
	original := f.certificate
	wire, err := original.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	projection, err := original.document.copyWithout(make([]byte, len(wire)), original.codec.signatureID)
	if err != nil {
		t.Fatal(err)
	}
	fields := unsignedFixtureFields(t, original.document, original.codec.signatureID)
	seed := [32]byte{71, 23, 4}
	for _, provider := range []bool{false, true} {
		name := "Sign"
		if provider {
			name = "SignWith"
		}
		t.Run(name, func(t *testing.T) {
			codec, err := NewOnceSigningMapCodec("IdentityCertificate", 65536, 4096)
			if err != nil {
				t.Fatal(err)
			}
			charge, err := SignedMapBackingBytes("IdentityCertificate", 65536, 4096)
			if err != nil {
				t.Fatal(err)
			}
			decoderCharge, err := decoderBackingBytes(65536, 4096, codec.decoder.textCap)
			if err != nil || charge <= decoderCharge+2*65536 {
				t.Fatal("one-time issuance lost the complete original charge", err)
			}
			if codec.decoder.byteLimit != 65536 || codec.decoder.nodeLimit != 4096 || codec.decoder.input != nil || codec.decoder.nodes != nil || len(codec.message) != 65536+len(codec.domain.label)+4 || len(codec.encoded) != 65536 {
				t.Fatal("one-time issuance changed the original signing capacities")
			}
			encoding := &codec.encoded[0]
			textSpace := len(codec.decoder.work)
			var signed *SignedMap
			if provider {
				signer := &admissionTestSigner{key: ed25519.NewKeyFromSeed(seed[:])}
				signed, err = codec.SignWith(fields, original.Key(), signer, DecodeContext{}, func() error { return nil })
			} else {
				signed, err = codec.Sign(fields, seed, DecodeContext{})
			}
			if err != nil {
				t.Fatal(err)
			}
			defer signed.Release()
			actual, err := signed.Bytes()
			if err != nil || !bytes.Equal(actual, wire) || signed.Key() != original.Key() {
				t.Fatal("one-time issuance changed the original bytes or key", err)
			}
			if !codec.sealed || codec.message != nil || &codec.encoded[0] != encoding || len(codec.encoded) != 65536 || len(codec.decoder.work) >= textSpace || codec.decoder.byteLimit != 65536 || codec.decoder.nodeLimit != 4096 {
				t.Fatal("one-time issuance kept signing work or replaced its existing projection array")
			}
			if err := signed.document.ValidateRules(DecodeContext{}); err != nil {
				t.Fatal("compaction discarded complete credential rule workspace", err)
			}
			if err := signed.MatchUnsignedProjection(projection); err != nil {
				t.Fatal("compaction changed the original unsigned projection", err)
			}
			want, err := original.Digest("certificate_digest")
			if err != nil {
				t.Fatal(err)
			}
			got, err := signed.Digest("certificate_digest")
			if err != nil || got != want {
				t.Fatal("compaction changed the registered digest", err)
			}
			wantCredential, err := original.DetachCredential()
			if err != nil {
				t.Fatal(err)
			}
			gotCredential, err := signed.DetachCredential()
			if err != nil || gotCredential.Scope() != wantCredential.Scope() || gotCredential.Facts() != wantCredential.Facts() {
				t.Fatal("compaction changed detached credential authority facts", err)
			}
			view := signed.Field(codec.signatureName)
			signed.Release()
			if _, ok := view.ByteString(); ok || !bytes.Equal(actual, make([]byte, len(actual))) || codec.decoder.input != nil || codec.decoder.nodes != nil || codec.decoder.active {
				t.Fatal("released issuer retained live views or its original signed input")
			}
			signer := &admissionTestSigner{key: ed25519.NewKeyFromSeed(seed[:])}
			if _, err := codec.Sign(fields, seed, DecodeContext{}); err != CBORFailure("decoder_busy") {
				t.Fatal("released one-time issuer signed another map", err)
			}
			if _, err := codec.SignWith(fields, original.Key(), signer, DecodeContext{}, func() error { return nil }); err != CBORFailure("decoder_busy") || signer.calls.Load() != 0 {
				t.Fatal("released one-time issuer invoked another signing provider", err)
			}
			if _, err := codec.Verify(wire, original.Key(), DecodeContext{}); err != CBORFailure("decoder_busy") {
				t.Fatal("released one-time issuer verified another map", err)
			}
			if _, err := codec.CopyVerified(original, DecodeContext{}); err != CBORFailure("decoder_busy") {
				t.Fatal("released one-time issuer copied another map", err)
			}
			if _, err := codec.VerifyCredential(wire, &NamespaceTrustStore{}); err != CBORFailure("decoder_busy") {
				t.Fatal("released one-time issuer adopted another credential", err)
			}
		})
	}
}

func TestOnceSigningMapPreservesFailedJobRefusalsAndRetry(t *testing.T) {
	f := newRuntimeAdmissionFixture(t, "live_authority", 5)
	original := f.certificate
	wire, err := original.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	fields := unsignedFixtureFields(t, original.document, original.codec.signatureID)
	seed := [32]byte{71, 23, 4}
	for _, bounds := range []struct{ bytes, nodes int }{{len(wire) - 1, 4096}, {len(wire), original.document.decoder.used - 1}} {
		ordinary, err := NewSignedMapCodec("IdentityCertificate", bounds.bytes, bounds.nodes)
		if err != nil {
			t.Fatal(err)
		}
		once, err := NewOnceSigningMapCodec("IdentityCertificate", bounds.bytes, bounds.nodes)
		if err != nil {
			t.Fatal(err)
		}
		_, want := ordinary.Sign(fields, seed, DecodeContext{})
		if signed, err := once.Sign(fields, seed, DecodeContext{}); signed != nil || want == nil || err != want || once.sealed || once.current != nil || once.decoder.active {
			t.Fatal("one-time issuance changed a complete original capacity refusal", err, want)
		}
	}
	for _, failure := range []string{"nil_signer", "nil_guard", "wrong_key", "guard", "signature"} {
		t.Run(failure, func(t *testing.T) {
			var want error
			for _, oneTime := range []bool{false, true} {
				var codec *SignedMapCodec
				if oneTime {
					codec, err = NewOnceSigningMapCodec("IdentityCertificate", len(wire), 4096)
				} else {
					codec, err = NewSignedMapCodec("IdentityCertificate", len(wire), 4096)
				}
				if err != nil {
					t.Fatal(err)
				}
				signer := &admissionTestSigner{key: ed25519.NewKeyFromSeed(seed[:]), bad: failure == "signature"}
				var provider MapSigner = signer
				guard := func() error { return nil }
				key := original.Key()
				switch failure {
				case "nil_signer":
					provider = nil
				case "nil_guard":
					guard = nil
				case "wrong_key":
					key[0] ^= 1
				case "guard":
					guard = func() error { return context.Canceled }
				}
				signed, err := codec.SignWith(fields, key, provider, DecodeContext{}, guard)
				if !oneTime {
					want = err
				}
				if signed != nil || err == nil || err != want || codec.sealed || codec.current != nil || codec.decoder.active || codec.decoder.input != nil || codec.decoder.nodes != nil || len(codec.message) != len(wire)+len(codec.domain.label)+4 || len(codec.encoded) != len(wire) {
					t.Fatal("failed signing changed the original refusal or retry capacities", oneTime, err, want)
				}
				signer.bad = false
				signed, err = codec.SignWith(fields, original.Key(), signer, DecodeContext{}, func() error { return nil })
				if err != nil {
					t.Fatal("failed job retired a later independent signing job", oneTime, err)
				}
				signed.Release()
				if codec.sealed != oneTime {
					t.Fatal("one-time retention changed ordinary issuer reuse")
				}
			}
		})
	}
	codec, err := NewOnceSigningMapCodec("IdentityCertificate", len(wire), 4096)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := codec.Verify(wire, original.Key(), DecodeContext{}); err != CBORFailure("signature_owner") {
		t.Fatal("one-time signing constructor admitted a verifier job", err)
	}
	if _, err := codec.CopyVerified(original, DecodeContext{}); err != CBORFailure("signature_owner") {
		t.Fatal("one-time signing constructor admitted a copy job", err)
	}
	if _, err := codec.VerifyCredential(wire, &NamespaceTrustStore{}); err != CBORFailure("signature_owner") || codec.sealed {
		t.Fatal("one-time signing constructor admitted a credential verifier job", err)
	}
}

func TestOnceSigningMapLateProviderRefusalKeepsIndependentRetry(t *testing.T) {
	f := newRuntimeAdmissionFixture(t, "live_authority", 5)
	original := f.certificate
	fields := unsignedFixtureFields(t, original.document, original.codec.signatureID)
	codec, err := NewOnceSigningMapCodec("IdentityCertificate", 65536, 4096)
	if err != nil {
		t.Fatal(err)
	}
	seed := [32]byte{71, 23, 4}
	signer := &admissionTestSigner{key: ed25519.NewKeyFromSeed(seed[:]), entered: make(chan struct{}), release: make(chan struct{})}
	var canceled atomic.Bool
	guard := func() error {
		if canceled.Load() {
			return context.Canceled
		}
		return nil
	}
	result := make(chan error, 1)
	go func() {
		signed, err := codec.SignWith(fields, original.Key(), signer, DecodeContext{}, guard)
		if signed != nil {
			signed.Release()
			err = errors.New("late signing provider published a signature fact")
		}
		result <- err
	}()
	select {
	case <-signer.entered:
	case <-time.After(5 * time.Second):
		close(signer.release)
		t.Fatal("original signing provider did not start")
	}
	_, busy := codec.Sign(fields, seed, DecodeContext{})
	canceled.Store(true)
	close(signer.release)
	if err := <-result; err != context.Canceled || busy != CBORFailure("decoder_busy") || signer.calls.Load() != 1 {
		t.Fatal("busy or late signing changed its original refusal", busy, err)
	}
	if codec.sealed || codec.current != nil || codec.decoder.active || codec.message == nil {
		t.Fatal("late refusal retained a fact or retired original signing work")
	}
	retry := &admissionTestSigner{key: ed25519.NewKeyFromSeed(seed[:])}
	signed, err := codec.SignWith(fields, original.Key(), retry, DecodeContext{}, func() error { return nil })
	if err != nil {
		t.Fatal("late refusal reduced a later independent signing job", err)
	}
	signed.Release()
}

func TestOnceSigningMapKeepsDenseBackingWhenReplacementDoesNotFit(t *testing.T) {
	// A single-candidate Artifact reserves larger route host/Origin text than
	// its maximum legal 128-byte audience. Its small wire keeps the retired
	// signing-message allowance below the two replacement rune arrays.
	seed := oracleSeed(t, "artifact_transport_fields")
	reference := newCBORTextReference(t)
	root, _, err := reference.decode(oracleBytes(t, seed.Hex), "Artifact", nil, 1<<16)
	if err != nil {
		t.Fatal(err)
	}
	oracleField(t, reference.cborReference, "Artifact", root, "audience").data = []byte(strings.Repeat("a", 128))
	original := signRuntimeFixture(t, "Artifact", root.encode(nil), DecodeContext{})
	wire, err := original.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	nodes := original.document.decoder.used + 1
	codec, err := NewOnceSigningMapCodec("Artifact", len(wire), nodes)
	if err != nil {
		t.Fatal(err)
	}
	work, scratch := &codec.decoder.work[0], &codec.decoder.scratch[0]
	space := len(codec.decoder.work)
	maximumText := 0
	for _, node := range original.document.decoder.nodes[:original.document.decoder.used] {
		if node.major == 3 {
			maximumText = max(maximumText, node.end-node.dataStart)
		}
	}
	if maximumText != 128 || maximumText*32 <= len(codec.message) || maximumText*4 >= space {
		t.Fatal("dense fixture does not distinguish the replacement overlap allowance")
	}
	signed, err := codec.Sign(unsignedFixtureFields(t, original.document, original.codec.signatureID), [32]byte{71, 23, 4}, DecodeContext{})
	if err != nil {
		t.Fatal(err)
	}
	defer signed.Release()
	if codec.decoder.byteLimit != len(wire) || codec.decoder.nodeLimit != nodes || len(codec.decoder.nodes) != nodes || len(codec.decoder.work) != space || len(codec.decoder.scratch) != space || &codec.decoder.work[0] != work || &codec.decoder.scratch[0] != scratch {
		t.Fatal("dense issuer allocated an unbudgeted replacement or changed original limits")
	}
	if err := signed.document.ValidateRules(DecodeContext{}); err != nil {
		t.Fatal("dense retained signing backing lost maximum legal text validation", err)
	}
}

func TestOnceSigningMapPreservesShapeFactsAndRuleFailureRetry(t *testing.T) {
	f := newRuntimeAdmissionFixture(t, "live_authority", 5)
	invalid := f.mutate(t, f.certificate, "IdentityCertificate", func(root *cborRefValue) {
		expiry := oracleField(t, f.r.cborReference, "IdentityCertificate", root, "expires_at_ms")
		expiry.n = oracleField(t, f.r.cborReference, "IdentityCertificate", root, "issued_at_ms").n
	})
	want := invalid.document.ValidateRules(DecodeContext{})
	if want == nil {
		t.Fatal("negative certificate fixture has valid rules")
	}
	fields := unsignedFixtureFields(t, invalid.document, invalid.codec.signatureID)
	seed := [32]byte{71, 23, 4}
	codec, err := NewOnceSigningMapCodec("IdentityCertificate", 65536, 4096)
	if err != nil {
		t.Fatal(err)
	}
	signer := &admissionTestSigner{key: ed25519.NewKeyFromSeed(seed[:])}
	if signed, err := codec.SignWith(fields, invalid.Key(), signer, DecodeContext{}, func() error { return nil }); signed != nil || err != want || signer.calls.Load() != 0 || codec.sealed || codec.decoder.active {
		t.Fatal("one-time SignWith changed complete rule validation before provider work", err, want)
	}
	signed, err := codec.SignWith(unsignedFixtureFields(t, f.certificate.document, f.certificate.codec.signatureID), f.certificate.Key(), signer, DecodeContext{}, func() error { return nil })
	if err != nil {
		t.Fatal("failed rule validation reduced the next independent signing job", err)
	}
	signed.Release()
	shapeOnly, err := NewOnceSigningMapCodec("IdentityCertificate", 65536, 4096)
	if err != nil {
		t.Fatal(err)
	}
	fact, err := shapeOnly.Sign(fields, seed, DecodeContext{})
	if err != nil {
		t.Fatal("one-time Sign changed the original shape-only signature fact", err)
	}
	defer fact.Release()
	if err := fact.document.ValidateRules(DecodeContext{}); err != want {
		t.Fatal("compacted signature fact weakened independent credential rules", err, want)
	}
	if credential, err := fact.DetachCredential(); credential != nil || err != want {
		t.Fatal("compacted signature fact authorized an invalid credential", err)
	}
}
