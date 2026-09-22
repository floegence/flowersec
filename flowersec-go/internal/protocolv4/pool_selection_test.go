package protocolv4

import (
	"bytes"
	"testing"
)

func signRuntimeFixture(t *testing.T, schema string, wire []byte, context DecodeContext) *SignedMap {
	t.Helper()
	codec, err := NewSignedMapCodec(schema, 1<<16, 1<<16)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := codec.decoder.DecodeShape(wire, schema, context)
	if err != nil {
		t.Fatal(err)
	}
	fields := unsignedFixtureFields(t, doc, codec.signatureID)
	// Sign uses the same decoder, so detach only the test fixture's fields.
	for i := range fields {
		fields[i].Bytes = bytes.Clone(fields[i].Bytes)
	}
	doc.Release()
	result, err := codec.Sign(fields, [32]byte{71, 23, 4}, context)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(result.Release)
	return result
}

func TestPoolSelectionRuntimeOriginalArtifactAndIndependentDomains(t *testing.T) {
	for _, id := range []string{"artifact_transport_fields", "artifact_pool_sixteen_fields", "artifact_local_fields"} {
		t.Run(id, func(t *testing.T) {
			seed := oracleSeed(t, id)
			artifact := signRuntimeFixture(t, "Artifact", oracleBytes(t, seed.Hex), DecodeContext{})
			wire, err := artifact.Bytes()
			if err != nil {
				t.Fatal(err)
			}
			indices := make([]uint64, artifact.Field("candidates").Len())
			for i := range indices {
				indices[i] = uint64(i)
			}
			reference, err := newCBORTextReference(t).derivePool(wire, indices, 1<<16)
			if err != nil {
				t.Fatal(err)
			}
			workspace, err := NewPoolSelectionWorkspace(1<<16, 4096)
			if err != nil {
				t.Fatal(err)
			}
			selection, err := workspace.Derive(artifact, indices)
			if err != nil {
				t.Fatal(err)
			}
			defer selection.Release()
			actual, err := selection.Bytes()
			if err != nil || !bytes.Equal(actual, reference.encoded) {
				t.Fatal("selection differs from independent canonical derivation", err)
			}
			a, c, r, err := selection.Digests()
			if err != nil || a != [32]byte(reference.artifactDigest) || c != [32]byte(reference.candidateSetDigest) || r != [32]byte(reference.routeSetDigest) || c == r {
				t.Fatal("original Artifact or separate set domains lost", err)
			}
			for _, member := range reference.members {
				if !selection.Member(member.index, [16]byte(member.candidateID), [32]byte(member.routeDigest)) {
					t.Fatal("original member missing")
				}
				_, route, err := artifact.CopyCandidateRoute(member.index, make([]byte, 1<<16))
				if err != nil || route != [32]byte(member.routeDigest) {
					t.Fatal("route projection changed", err)
				}
				if selection.Member(member.index, [16]byte(member.candidateID), c) {
					t.Fatal("set digest substituted for member route")
				}
			}
			artifact.Release()
			clear(indices)
			a[0] ^= 1
			if again, _, _, err := selection.Digests(); err != nil || again != [32]byte(reference.artifactDigest) {
				t.Fatal("selection borrowed input storage", err)
			}
		})
	}
}

func runtimePoolProof(t *testing.T, artifact *SignedMap, indices []uint64, mutate func(*poolBindingFixture)) *SignedMap {
	t.Helper()
	f := newPoolBindingFixture(t, []uint64{0})
	wire, err := artifact.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	f.selection, err = f.r.derivePool(wire, indices, 1<<16)
	if err != nil {
		t.Fatal(err)
	}
	oracleField(t, f.r.cborReference, "ActivationAuthorization", f.proof, "artifact_digest").data = f.selection.artifactDigest
	oracleField(t, f.r.cborReference, "ActivationAuthorization", f.proof, "route_selection").data = f.selection.routeSetDigest
	oracleField(t, f.r.cborReference, "PoolSelectionRef", f.reference, "artifact_digest").data = f.selection.artifactDigest
	oracleField(t, f.r.cborReference, "PoolSelectionRef", f.reference, "candidate_set_digest").data = f.selection.candidateSetDigest
	array := oracleField(t, f.r.cborReference, "PoolSelectionRef", f.reference, "candidate_indices")
	array.items = nil
	for _, index := range indices {
		array.items = append(array.items, &cborRefValue{major: 0, n: index})
	}
	if mutate != nil {
		mutate(f)
	}
	return signRuntimeFixture(t, "ActivationAuthorization", f.proof.encode(nil), DecodeContext{Selectors: map[string]string{"activation_source_profile": "preauthorized_pool"}})
}

func TestPoolSelectionRuntimeProofCannotReplaceOriginalSet(t *testing.T) {
	seed := oracleSeed(t, "artifact_pool_sixteen_fields")
	artifact := signRuntimeFixture(t, "Artifact", oracleBytes(t, seed.Hex), DecodeContext{})
	workspace, err := NewPoolSelectionWorkspace(1<<16, 4096)
	if err != nil {
		t.Fatal(err)
	}
	indices := []uint64{0, 5, 15}
	selection, err := workspace.Derive(artifact, indices)
	if err != nil {
		t.Fatal(err)
	}
	defer selection.Release()
	proof := runtimePoolProof(t, artifact, indices, nil)
	if err := selection.MatchProof(proof); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"artifact_digest", "route_selection"} {
		t.Run(field, func(t *testing.T) {
			wrong := runtimePoolProof(t, artifact, indices, func(f *poolBindingFixture) {
				oracleField(t, f.r.cborReference, "ActivationAuthorization", f.proof, field).data = bytes.Repeat([]byte{0xee}, 32)
			})
			if err := selection.MatchProof(wrong); err != CBORFailure("pool_digest_binding") {
				t.Fatal("valid signature replaced set binding", err)
			}
		})
	}
	for _, field := range []string{"artifact_digest", "candidate_set_digest"} {
		t.Run("reference/"+field, func(t *testing.T) {
			wrong := runtimePoolProof(t, artifact, indices, func(f *poolBindingFixture) {
				oracleField(t, f.r.cborReference, "PoolSelectionRef", f.reference, field).data = f.selection.routeSetDigest
			})
			if err := selection.MatchProof(wrong); err != CBORFailure("pool_digest_binding") {
				t.Fatal("distinct hash domain/reference accepted", err)
			}
		})
	}
	wrong := runtimePoolProof(t, artifact, []uint64{0, 6, 15}, nil)
	if err := selection.MatchProof(wrong); err != CBORFailure("pool_index_membership") {
		t.Fatal("different original indices accepted", err)
	}
	wrong = runtimePoolProof(t, artifact, indices, func(f *poolBindingFixture) {
		once := oracleField(t, f.r.cborReference, "PoolSelectionRef", f.reference, "once_authority_ref")
		oracleField(t, f.r.cborReference, "OnceAuthorityRef", once, "spend_authority_id").data = []byte("another-authority")
	})
	if err := selection.MatchProof(wrong); err != CBORFailure("pool_authority_binding") {
		t.Fatal("different once authority accepted", err)
	}
	proof.Release()
	if err := selection.MatchProof(proof); err != CBORFailure("activation_owner") {
		t.Fatal("released proof accepted", err)
	}
}

func TestPoolSelectionRuntimeBoundsAndActualOwnership(t *testing.T) {
	seed := oracleSeed(t, "artifact_pool_sixteen_fields")
	artifact := signRuntimeFixture(t, "Artifact", oracleBytes(t, seed.Hex), DecodeContext{})
	w, err := NewPoolSelectionWorkspace(1<<16, 4096)
	if err != nil {
		t.Fatal(err)
	}
	for _, indices := range [][]uint64{nil, {0, 0}, {2, 1}, {16}, make([]uint64, 17)} {
		if _, err := w.Derive(artifact, indices); err == nil {
			t.Fatal("invalid indices repaired or admitted", indices)
		}
	}
	selection, err := w.Derive(artifact, []uint64{0})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Derive(artifact, []uint64{1}); err != CBORFailure("decoder_busy") {
		t.Fatal("retained owner overwritten", err)
	}
	wire, _ := selection.Bytes()
	selection.Release()
	if !bytes.Equal(wire, make([]byte, len(wire))) {
		t.Fatal("released backing not cleared")
	}
	if _, err := selection.Bytes(); err == nil {
		t.Fatal("released bytes exposed")
	}
	next, err := w.Derive(artifact, []uint64{1})
	if err != nil {
		t.Fatal(err)
	}
	defer next.Release()
	selection.Release()
	if _, err := next.Bytes(); err != nil {
		t.Fatal("stale release cleared new selection", err)
	}
	tiny, err := NewPoolSelectionWorkspace(1, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tiny.Derive(artifact, []uint64{0}); err == nil || tiny.current != nil {
		t.Fatal("capacity failure produced an owner")
	}
	if _, err := PoolSelectionBackingBytes(-1, 1); err == nil {
		t.Fatal("negative reservation accepted")
	}
	artifact.Release()
	if _, err := tiny.Derive(artifact, []uint64{0}); err != CBORFailure("artifact_owner") {
		t.Fatal("released Artifact accepted", err)
	}
}
