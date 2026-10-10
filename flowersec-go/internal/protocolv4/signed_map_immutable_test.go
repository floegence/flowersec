package protocolv4

import (
	"bytes"
	"strings"
	"testing"
)

func TestSignedMapSchemaWorkspacePreservesNestedMaximumText(t *testing.T) {
	for _, source := range []string{"preauthorized_pool", "live_authority"} {
		t.Run(source, func(t *testing.T) {
			f := newRuntimeAdmissionFixture(t, source, 5)
			subject := strings.Repeat("a", 128)
			certificate := f.mutate(t, f.certificate, "IdentityCertificate", func(root *cborRefValue) {
				oracleField(t, f.r.cborReference, "IdentityCertificate", root, "subject_id").data = []byte(subject)
			})
			certificateBytes, err := certificate.Bytes()
			if err != nil {
				t.Fatal(err)
			}
			admission := f.mutate(t, f.fsb, "FSB4", func(root *cborRefValue) {
				oracleField(t, f.r.cborReference, "FSB4", root, "client_certificate").data = certificateBytes
			})
			for _, original := range []*SignedMap{certificate, admission} {
				for _, immutable := range []bool{false, true} {
					retention := signedMapReusable
					if immutable {
						retention = signedMapVerifiedOnce
					}
					codec, err := newSignedMapCodec(original.codec.schema, 65536, 4096, retention)
					if err != nil {
						t.Fatal(err)
					}
					if codec.decoder.byteLimit != 65536 || codec.decoder.input != nil || codec.decoder.nodeLimit != 4096 || codec.decoder.nodes != nil {
						t.Fatal("signed schema changed complete limits or allocated idle nodes")
					}
					wire, err := original.Bytes()
					if err != nil {
						t.Fatal(err)
					}
					retained, err := codec.Verify(wire, original.Key(), f.context)
					if err != nil {
						t.Fatal("schema workspace rejected a legal maximum nested scalar", original.codec.schema, immutable, err)
					}
					actual, err := retained.Bytes()
					if err != nil || !bytes.Equal(actual, wire) {
						t.Fatal("schema workspace changed the original signed bytes", err)
					}
					if len(codec.decoder.input) != len(wire) || len(codec.decoder.nodes) > min(4096, len(wire)) || codec.decoder.used > len(codec.decoder.nodes) {
						t.Fatal("nested encoded schema escaped its input-sized node arena")
					}
					retained.Release()
					if codec.decoder.input != nil || codec.decoder.nodes != nil || codec.decoder.active {
						t.Fatal("released signed schema retained its node arena")
					}
				}
			}
			if value, ok := certificate.Field("subject_id").Text(); !ok || value != subject {
				t.Fatal("maximum subject fixture was not exercised")
			}
			certificateCharge, err := SignedMapBackingBytes("IdentityCertificate", 65536, 4096)
			if err != nil {
				t.Fatal(err)
			}
			artifactCharge, err := SignedMapBackingBytes("Artifact", 65536, 4096)
			if err != nil || certificateCharge >= artifactCharge {
				t.Fatal("a certificate retained unrelated route normalization capacity", certificateCharge, artifactCharge, err)
			}
		})
	}
}

func TestImmutableSignedMapPreservesOriginalFactsRulesAndProjections(t *testing.T) {
	r, err := runtimeSignedMaps()
	if err != nil {
		t.Fatal(err)
	}
	for _, source := range []string{"preauthorized_pool", "live_authority"} {
		t.Run(source, func(t *testing.T) {
			f := newRuntimeAdmissionFixture(t, source, 5)
			for _, original := range []*SignedMap{f.artifact, f.certificate, f.proof} {
				schema := original.codec.schema
				wire, err := original.Bytes()
				if err != nil {
					t.Fatal(err)
				}
				wire = bytes.Clone(wire)
				projection, err := original.document.copyWithout(make([]byte, len(wire)), original.codec.signatureID)
				if err != nil {
					t.Fatal(err)
				}
				limit, err := SchemaByteLimit(schema)
				if err != nil {
					t.Fatal(err)
				}
				for _, mode := range []string{"verify", "copy"} {
					t.Run(schema+"/"+mode, func(t *testing.T) {
						codec, err := NewImmutableSignedMapCodec(schema, limit, 4096)
						if err != nil {
							t.Fatal(err)
						}
						var retained *SignedMap
						if mode == "verify" {
							input := bytes.Clone(wire)
							retained, err = codec.Verify(input, original.Key(), f.context)
							clear(input)
						} else {
							copyCodec, e := NewSignedMapCodec(schema, limit, 4096)
							if e != nil {
								t.Fatal(e)
							}
							copied, e := copyCodec.CopyVerified(original, f.context)
							if e != nil {
								t.Fatal(e)
							}
							retained, err = codec.CopyVerified(copied, f.context)
							copied.Release()
						}
						if err != nil {
							t.Fatal(err)
						}
						defer retained.Release()
						actual, err := retained.Bytes()
						if err != nil || !bytes.Equal(actual, wire) || retained.Key() != original.Key() {
							t.Fatal("immutable verification changed the original signature fact", err)
						}
						if err := retained.document.ValidateRules(f.context); err != nil {
							t.Fatal("compaction discarded rule workspace", err)
						}
						if err := retained.MatchUnsignedProjection(projection); err != nil {
							t.Fatal("compaction changed the original unsigned projection", err)
						}
						changed := bytes.Clone(projection)
						changed[len(changed)-1] ^= 1
						if err := retained.MatchUnsignedProjection(changed); err != CBORFailure("activation_parent_binding") {
							t.Fatal("projection mismatch lost its rejection", err)
						}
						for name, domain := range r.digests {
							if domain.Input.Parts[0].Schema != schema {
								continue
							}
							want, err := original.Digest(name)
							if err != nil {
								t.Fatal(err)
							}
							got, err := retained.Digest(name)
							if err != nil || got != want {
								t.Fatal("registered digest changed after compaction", name, err)
							}
						}
						if schema != "ActivationAuthorization" {
							want, err := original.DetachCredential()
							if err != nil {
								t.Fatal(err)
							}
							got, err := retained.DetachCredential()
							if err != nil || got.Scope() != want.Scope() || got.Facts() != want.Facts() {
								t.Fatal("compaction changed detached credential facts", err)
							}
						}
						if schema == "Artifact" {
							want, err := original.SessionParameters()
							if err != nil {
								t.Fatal(err)
							}
							got, err := retained.SessionParameters()
							if err != nil || got != want {
								t.Fatal("compaction changed the signed session contract", err)
							}
						}
						if len(codec.decoder.nodes) == 4096 || len(codec.message) != 0 {
							t.Fatal("immutable idle credential retains full decode/signing backing")
						}
						view := retained.Field(codec.signatureName)
						borrowed, ok := view.ByteString()
						if !ok || len(borrowed) != 64 {
							t.Fatal("original field view changed")
						}
						retained.Release()
						if _, ok := view.ByteString(); ok || !bytes.Equal(borrowed, make([]byte, len(borrowed))) {
							t.Fatal("Release retained a live field or uncleared original bytes")
						}
						if _, err := codec.Verify(wire, original.Key(), f.context); err != CBORFailure("decoder_busy") {
							t.Fatal("retired immutable codec admitted another document", err)
						}
						if _, err := codec.CopyVerified(original, f.context); err != CBORFailure("decoder_busy") {
							t.Fatal("retired immutable codec copied another document", err)
						}
					})
				}
			}
		})
	}
}

func TestImmutableSignedMapPreservesOriginalCapacityAndFailureRecovery(t *testing.T) {
	f := newRuntimeAdmissionFixture(t, "preauthorized_pool", 5)
	original := f.artifact
	wire, err := original.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	nodes := original.document.decoder.used
	for _, limit := range []struct {
		name         string
		bytes, nodes int
		failure      CBORFailure
	}{{"bytes", len(wire) - 1, nodes, "map_size"}, {"nodes", len(wire), nodes - 1, "node_capacity"}} {
		t.Run(limit.name, func(t *testing.T) {
			for _, immutable := range []bool{false, true} {
				retention := signedMapReusable
				if immutable {
					retention = signedMapVerifiedOnce
				}
				codec, err := newSignedMapCodec("Artifact", limit.bytes, limit.nodes, retention)
				if err != nil {
					t.Fatal(err)
				}
				if codec.decoder.byteLimit != limit.bytes || codec.decoder.input != nil || codec.decoder.nodeLimit != limit.nodes || codec.decoder.nodes != nil {
					t.Fatal("signed-map constructor changed the original declared capacity", immutable)
				}
				if _, err = codec.Verify(wire, original.Key(), DecodeContext{}); err != limit.failure {
					t.Fatal("verification escaped the original decode capacity", immutable, err)
				}
				if _, err = codec.CopyVerified(original, DecodeContext{}); err != limit.failure {
					t.Fatal("copy escaped the original decode capacity", immutable, err)
				}
				if codec.current != nil || codec.sealed || codec.decoder.active || codec.decoder.input != nil || codec.decoder.nodes != nil || codec.decoder.used != 0 || codec.decoder.size != 0 {
					t.Fatal("capacity refusal retained a partial signed-map owner", immutable)
				}
			}
		})
	}
	codec, err := NewImmutableSignedMapCodec("Artifact", len(wire), nodes+1)
	if err != nil {
		t.Fatal(err)
	}
	wrong := original.Key()
	wrong[0] ^= 1
	if _, err := codec.Verify(wire, wrong, DecodeContext{}); err != CBORFailure("signature_invalid") {
		t.Fatal("immutable owner accepted a wrong key", err)
	}
	if codec.sealed || codec.current != nil || codec.decoder.active || len(codec.message) != 0 || codec.decoder.input != nil || codec.decoder.nodes != nil || codec.decoder.used != 0 || codec.decoder.size != 0 {
		t.Fatal("failed signature retained an active or retired constructor")
	}
	retained, err := codec.Verify(wire, original.Key(), DecodeContext{})
	if err != nil {
		t.Fatal("failed verification reduced the original capacity", err)
	}
	defer retained.Release()
	if len(codec.decoder.nodes) != nodes+1 || len(codec.decoder.input) != len(wire) {
		t.Fatal("nearly full document allocated unbudgeted replacement backing")
	}
	reusable, err := NewSignedMapCodec("Artifact", len(wire), nodes+1)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		verified, err := reusable.Verify(wire, original.Key(), DecodeContext{})
		if err != nil {
			t.Fatal("ordinary reusable codec was retired", err)
		}
		if len(reusable.decoder.nodes) != nodes+1 || reusable.decoder.nodeLimit != nodes+1 || !bytes.Equal(verified.document.Bytes(), wire) {
			t.Fatal("reusable near-full map changed its original arena limit or bytes")
		}
		verified.Release()
		if reusable.decoder.input != nil || reusable.decoder.nodes != nil || reusable.decoder.active {
			t.Fatal("released reusable near-full map retained its node arena")
		}
	}
}

func TestImmutableSignedMapDoesNotAuthorizeInvalidCredentialRules(t *testing.T) {
	f := newRuntimeAdmissionFixture(t, "preauthorized_pool", 5)
	original := f.mutate(t, f.certificate, "IdentityCertificate", func(root *cborRefValue) {
		expiry := oracleField(t, f.r.cborReference, "IdentityCertificate", root, "expires_at_ms")
		expiry.n = oracleField(t, f.r.cborReference, "IdentityCertificate", root, "issued_at_ms").n
	})
	wire, err := original.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	want := original.document.ValidateRules(DecodeContext{})
	if want == nil {
		t.Fatal("negative credential fixture has valid rules")
	}
	codec, err := NewImmutableSignedMapCodec("IdentityCertificate", 65536, 4096)
	if err != nil {
		t.Fatal(err)
	}
	retained, err := codec.Verify(wire, original.Key(), DecodeContext{})
	if err != nil {
		t.Fatal("signature fact changed before independent rule authorization", err)
	}
	defer retained.Release()
	if err := retained.document.ValidateRules(DecodeContext{}); err != want {
		t.Fatal("immutable owner weakened credential rules", err, want)
	}
	if credential, err := retained.DetachCredential(); credential != nil || err != want {
		t.Fatal("immutable owner published an invalid credential", err)
	}
}

func TestImmutableSignedMapPrivateInputKeepsDeclaredCompactionOverlap(t *testing.T) {
	f := newRuntimeAdmissionFixture(t, "preauthorized_pool", 5)
	original := f.certificate
	wire, err := original.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	codec, err := NewImmutableSignedMapCodec("IdentityCertificate", 65536, 4096)
	if err != nil {
		t.Fatal(err)
	}
	declaredTextSpace := len(codec.decoder.work)
	retained, err := codec.Verify(wire, original.Key(), DecodeContext{})
	if err != nil {
		t.Fatal(err)
	}
	defer retained.Release()
	maximumText := 0
	for _, node := range codec.decoder.nodes[:codec.decoder.used] {
		if node.major == 3 {
			maximumText = max(maximumText, node.end-node.dataStart)
		}
	}
	if maximumText == 0 || maximumText*4 >= declaredTextSpace {
		t.Fatal("fixture does not distinguish complete schema text from retained text")
	}
	if codec.decoder.byteLimit != 65536 || len(codec.decoder.input) != len(wire) || len(codec.decoder.nodes) != codec.decoder.used || len(codec.decoder.work) != maximumText*4 || len(codec.decoder.scratch) != maximumText*4 {
		t.Fatal("private input lost declared overlap or complete immutable rule backing")
	}
	projection, err := original.document.copyWithout(make([]byte, len(wire)), original.codec.signatureID)
	if err != nil {
		t.Fatal(err)
	}
	if err := retained.MatchUnsignedProjection(projection); err != nil {
		t.Fatal("compact private input changed the original unsigned signature projection", err)
	}
	if err := retained.document.ValidateRules(DecodeContext{}); err != nil {
		t.Fatal("compact private input discarded original credential rule workspace", err)
	}
	bytesView := retained.document.Bytes()
	retained.Release()
	if codec.decoder.input != nil || codec.decoder.nodes != nil || codec.decoder.active || !bytes.Equal(bytesView, make([]byte, len(bytesView))) {
		t.Fatal("immutable private backing outlived its original signed-map owner")
	}
}

func TestImmutableSignedMapPreservesTunnelCredentialClosure(t *testing.T) {
	f := newEndpointCredentialFixture(t, true, true)
	var maps [7]*SignedMap
	for index, original := range f.originals {
		schema := original.codec.schema
		limit, err := SchemaByteLimit(schema)
		if err != nil {
			t.Fatal(err)
		}
		codec, err := NewImmutableSignedMapCodec(schema, limit, 4096)
		if err != nil {
			t.Fatal(err)
		}
		maps[index], err = codec.CopyVerified(original, DecodeContext{})
		if err != nil {
			t.Fatal(err)
		}
		defer maps[index].Release()
		name := "certificate_digest"
		if schema == "Artifact" {
			name = "artifact_digest"
		} else if schema == "Grant" {
			name = "grant_digest"
		}
		want, err := original.Digest(name)
		if err != nil {
			t.Fatal(err)
		}
		got, err := maps[index].Digest(name)
		if err != nil || got != want {
			t.Fatal("tunnel credential lost its original digest", index, err)
		}
		original.Release()
	}
	for _, role := range []Direction{ClientToServer, ServerToClient} {
		closure, err := BindEndpointCredentials(role, maps[0], 0, maps[1], maps[2], maps[3+2*int(role)], maps[4+2*int(role)])
		if err != nil {
			t.Fatal("immutable tunnel originals lost route/identity/namespace closure", role, err)
		}
		if closure.count != 5 || !closure.tunnel || closure.role != role {
			t.Fatal("immutable tunnel omitted applicable endpoint credentials")
		}
	}
}
