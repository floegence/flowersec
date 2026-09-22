package protocolv4

// Test-only Artifact/proof/winner projection. Matching bytes do not verify a
// signature, grant trust or acquire a claim, ParentWinner or activation guard.
import (
	"bytes"
	"reflect"
	"testing"
)

func (r *cborTextReference) verifyPoolReference(artifact, reference []byte, ownerCap uint64) (*cborPoolProjection, error) {
	value, err := r.wireMap(reference, "PoolSelectionRef", cborShapeContext{}, ownerCap)
	if err != nil {
		return nil, err
	}
	array, err := r.namedValue("PoolSelectionRef", value, "candidate_indices")
	if err != nil || array == nil || array.major != 4 {
		return nil, cborRefError("field_type")
	}
	indices := make([]uint64, len(array.items))
	for i, item := range array.items {
		indices[i] = item.n
	}
	result, err := r.derivePool(artifact, indices, ownerCap)
	if err != nil {
		return nil, err
	}
	for _, binding := range []struct {
		field    string
		expected []byte
		code     string
	}{
		{"artifact_digest", result.artifactDigest, "pool_artifact_digest"},
		{"candidate_set_digest", result.candidateSetDigest, "pool_candidate_set_digest"},
	} {
		got, err := r.namedValue("PoolSelectionRef", value, binding.field)
		if err != nil {
			return nil, err
		}
		if got == nil || got.major != 2 || !bytes.Equal(got.data, binding.expected) {
			return nil, cborRefError(binding.code)
		}
	}
	return result, nil
}

func (r *cborTextReference) poolAuthorizationProjection(artifactBytes, fsbBytes []byte, context cborShapeContext, ownerCap uint64) (*cborPoolProjection, error) {
	// The caller's immutable source profile is mandatory; never infer it from
	// proof shape or a failed live-authority attempt.
	if context.selectors["activation_source_profile"] != "preauthorized_pool" {
		return nil, cborRefError("pool_source_profile")
	}
	artifact, err := r.wireMap(artifactBytes, "Artifact", cborShapeContext{}, ownerCap)
	if err != nil {
		return nil, err
	}
	profile, err := r.namedValue("Artifact", artifact, "crypto_profile_id")
	if err != nil || profile == nil || profile.major != 3 {
		return nil, cborRefError("field_type")
	}
	if supplied, ok := context.selectors["crypto_profile_id"]; ok && supplied != string(profile.data) {
		return nil, cborRefError("pool_crypto_profile")
	}
	selectors := make(map[string]string, len(context.selectors)+1)
	for key, value := range context.selectors {
		selectors[key] = value
	}
	selectors["crypto_profile_id"] = string(profile.data)
	context.selectors = selectors
	fsb, err := r.wireMap(fsbBytes, "FSB4", context, ownerCap)
	if err != nil {
		return nil, err
	}
	encodedProof, err := r.namedValue("FSB4", fsb, "activation_authorization")
	if err != nil || encodedProof == nil || encodedProof.major != 2 {
		return nil, cborRefError("field_type")
	}
	proof, err := r.wireMap(encodedProof.data, "ActivationAuthorization", context, ownerCap)
	if err != nil {
		return nil, err
	}
	reference, err := r.namedValue("ActivationAuthorization", proof, "candidate_selection")
	if err != nil || reference == nil || reference.major != 5 {
		return nil, cborRefError("field_type")
	}
	result, err := r.verifyPoolReference(artifactBytes, reference.encode(nil), ownerCap)
	if err != nil {
		return nil, err
	}
	for _, binding := range []struct {
		targetName string
		target     *cborRefValue
		fields     []string
	}{
		{"FSB4", fsb, []string{"tenant_id", "issuer_key_id", "lease_id", "session_nonce"}},
		{"ActivationAuthorization", proof, []string{"client_identity_digest", "server_identity_digest", "audience"}},
	} {
		for _, field := range binding.fields {
			left, err := r.namedValue("Artifact", artifact, field)
			if err != nil {
				return nil, err
			}
			right, err := r.namedValue(binding.targetName, binding.target, field)
			if err != nil {
				return nil, err
			}
			if left == nil || right == nil || !cborValuesEqual(left, right) {
				return nil, cborRefError("pool_artifact_binding")
			}
		}
	}
	for _, binding := range []struct {
		name     string
		value    *cborRefValue
		field    string
		expected []byte
		code     string
	}{
		{"FSB4", fsb, "artifact_digest", result.artifactDigest, "pool_artifact_digest"},
		{"ActivationAuthorization", proof, "route_selection", result.routeSetDigest, "pool_route_set_digest"},
	} {
		got, err := r.namedValue(binding.name, binding.value, binding.field)
		if err != nil {
			return nil, err
		}
		if got == nil || got.major != 2 || !bytes.Equal(got.data, binding.expected) {
			return nil, cborRefError(binding.code)
		}
	}
	for _, deadline := range [][2]string{{"activation_not_after_ms", "initiation_not_after_ms"}, {"session_not_after_ms", "session_not_after_ms"}} {
		child, err := r.namedValue("ActivationAuthorization", proof, deadline[0])
		if err != nil {
			return nil, err
		}
		parent, err := r.namedValue("Artifact", artifact, deadline[1])
		if err != nil {
			return nil, err
		}
		if child == nil || parent == nil || child.major != 0 || parent.major != 0 {
			return nil, cborRefError("field_type")
		}
		if child.n > parent.n {
			return nil, cborRefError("pool_parent_deadline")
		}
	}
	id, err := r.namedValue("FSB4", fsb, "candidate_id")
	if err != nil || id == nil || id.major != 2 {
		return nil, cborRefError("field_type")
	}
	route, err := r.namedValue("FSB4", fsb, "route_digest")
	if err != nil || route == nil || route.major != 2 {
		return nil, cborRefError("field_type")
	}
	for _, member := range result.members {
		if bytes.Equal(id.data, member.candidateID) && bytes.Equal(route.data, member.routeDigest) {
			return result, nil
		}
	}
	return nil, cborRefError("pool_winner_membership")
}

type poolBindingFixture struct {
	r                               *cborTextReference
	artifact, proof, fsb, reference *cborRefValue
	selection                       *cborPoolProjection
	context                         cborShapeContext
}

func newPoolBindingFixture(t testing.TB, indices []uint64) *poolBindingFixture {
	t.Helper()
	r := newCBORTextReference(t)
	f := &poolBindingFixture{r: r, context: cborShapeContext{selectors: map[string]string{"activation_source_profile": "preauthorized_pool"}}}
	parse := func(id string) *cborRefValue {
		seed := oracleSeed(t, id)
		value, err := r.wireMap(oracleBytes(t, seed.Hex), seed.Schema, shapeContext(seed.Limits), 1<<16)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	f.artifact, f.proof, f.fsb = parse("artifact_transport_fields"), parse("activation_pool_fields"), parse("fsb_fields")
	f.reference = oracleField(t, r.cborReference, "ActivationAuthorization", f.proof, "candidate_selection")
	var err error
	f.selection, err = r.derivePool(f.artifact.encode(nil), indices, 1<<16)
	if err != nil {
		t.Fatal(err)
	}
	setBytes := func(name string, root *cborRefValue, field string, data []byte) {
		oracleField(t, r.cborReference, name, root, field).data = bytes.Clone(data)
	}
	setBytes("PoolSelectionRef", f.reference, "artifact_digest", f.selection.artifactDigest)
	setBytes("PoolSelectionRef", f.reference, "candidate_set_digest", f.selection.candidateSetDigest)
	array := oracleField(t, r.cborReference, "PoolSelectionRef", f.reference, "candidate_indices")
	array.items = nil
	for _, index := range indices {
		array.items = append(array.items, &cborRefValue{major: 0, n: index})
	}
	setBytes("ActivationAuthorization", f.proof, "artifact_digest", f.selection.artifactDigest)
	setBytes("ActivationAuthorization", f.proof, "route_selection", f.selection.routeSetDigest)
	for _, field := range []string{"client_identity_digest", "server_identity_digest"} {
		setBytes("ActivationAuthorization", f.proof, field, oracleField(t, r.cborReference, "Artifact", f.artifact, field).data)
	}
	setBytes("FSB4", f.fsb, "artifact_digest", f.selection.artifactDigest)
	setBytes("FSB4", f.fsb, "session_nonce", oracleField(t, r.cborReference, "Artifact", f.artifact, "session_nonce").data)
	setBytes("FSB4", f.fsb, "candidate_id", f.selection.members[0].candidateID)
	setBytes("FSB4", f.fsb, "route_digest", f.selection.members[0].routeDigest)
	return f
}

func (f *poolBindingFixture) inputs(t testing.TB) ([]byte, []byte) {
	t.Helper()
	oracleField(t, f.r.cborReference, "FSB4", f.fsb, "activation_authorization").data = f.proof.encode(nil)
	return f.artifact.encode(nil), f.fsb.encode(nil)
}

// v4.cbor.pool_reference_binding
func TestCBORPoolReferenceBinding(t *testing.T) {
	f := newPoolBindingFixture(t, []uint64{0, 1})
	artifact, _ := f.inputs(t)
	reference := f.reference.encode(nil)
	got, err := f.r.verifyPoolReference(artifact, reference, 1<<16)
	if err != nil || !bytes.Equal(got.encoded, f.selection.encoded) {
		t.Fatal("valid reference failed", err)
	}
	oracleField(t, f.r.cborReference, "Artifact", f.artifact, "signature").data = bytes.Repeat([]byte{99}, 64)
	if got, err := f.r.verifyPoolReference(f.artifact.encode(nil), reference, 1<<16); err != cborRefError("pool_artifact_digest") || got != nil {
		t.Fatal("reference omitted complete signed Artifact")
	}
	indices := oracleField(t, f.r.cborReference, "PoolSelectionRef", f.reference, "candidate_indices")
	indices.items = indices.items[:1]
	if got, err := f.r.verifyPoolReference(artifact, f.reference.encode(nil), 1<<16); err != cborRefError("pool_candidate_set_digest") || got != nil {
		t.Fatal("subset repaired supplied digest")
	}
	single, err := f.r.derivePool(artifact, []uint64{0}, 1<<16)
	if err != nil {
		t.Fatal(err)
	}
	oracleField(t, f.r.cborReference, "PoolSelectionRef", f.reference, "candidate_set_digest").data = single.routeSetDigest
	if got, err := f.r.verifyPoolReference(artifact, f.reference.encode(nil), 1<<16); err != cborRefError("pool_candidate_set_digest") || got != nil {
		t.Fatal("route-set domain substituted for candidate-set")
	}
}

// v4.cbor.pool_proof_winner
func TestCBORPoolProofWinnerBinding(t *testing.T) {
	f := newPoolBindingFixture(t, []uint64{0, 1})
	artifact, fsb := f.inputs(t)
	contextBefore := map[string]string{"activation_source_profile": "preauthorized_pool"}
	got, err := f.r.poolAuthorizationProjection(artifact, fsb, f.context, 1<<16)
	if err != nil || !bytes.Equal(got.encoded, f.selection.encoded) {
		t.Fatal("valid pool projection rejected", err)
	}
	if !reflect.DeepEqual(f.context.selectors, contextBefore) {
		t.Fatal("caller context changed")
	}
	for _, context := range []cborShapeContext{{}, {selectors: map[string]string{"activation_source_profile": "live_authority"}}} {
		if got, err := f.r.poolAuthorizationProjection(artifact, fsb, context, 1<<16); err != cborRefError("pool_source_profile") || got != nil {
			t.Fatal("source inferred from wire")
		}
	}
	f.context.selectors["crypto_profile_id"] = "wrong"
	if got, err := f.r.poolAuthorizationProjection(artifact, fsb, f.context, 1<<16); err != cborRefError("pool_crypto_profile") || got != nil {
		t.Fatal("profile conflict accepted")
	}
	for _, mutation := range []struct {
		name, schema, field, code string
		secondRoute               bool
	}{
		{"route_set", "ActivationAuthorization", "route_selection", "pool_route_set_digest", false},
		{"candidate_set", "PoolSelectionRef", "candidate_set_digest", "pool_candidate_set_digest", false},
		{"candidate_id", "FSB4", "candidate_id", "pool_winner_membership", false},
		{"cross_member_route", "FSB4", "route_digest", "pool_winner_membership", true},
		{"nonce", "FSB4", "session_nonce", "pool_artifact_binding", false},
		{"client_identity", "ActivationAuthorization", "client_identity_digest", "pool_artifact_binding", false},
		{"server_identity", "ActivationAuthorization", "server_identity_digest", "pool_artifact_binding", false},
		{"activation_deadline", "ActivationAuthorization", "activation_not_after_ms", "pool_parent_deadline", false},
		{"session_deadline", "ActivationAuthorization", "session_not_after_ms", "pool_parent_deadline", false},
		{"ref_artifact", "PoolSelectionRef", "artifact_digest", "field_equality", false},
		{"proof_artifact", "ActivationAuthorization", "artifact_digest", "field_equality", false},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			fresh := newPoolBindingFixture(t, []uint64{0, 1})
			root := map[string]*cborRefValue{"FSB4": fresh.fsb, "ActivationAuthorization": fresh.proof, "PoolSelectionRef": fresh.reference}[mutation.schema]
			item := oracleField(t, fresh.r.cborReference, mutation.schema, root, mutation.field)
			if mutation.secondRoute {
				item.data = bytes.Clone(fresh.selection.members[1].routeDigest)
			} else if item.major == 2 {
				item.data = bytes.Clone(item.data)
				item.data[0] ^= 0x80
			} else {
				parentField := "session_not_after_ms"
				if mutation.field == "activation_not_after_ms" {
					parentField = "initiation_not_after_ms"
				}
				item.n = oracleField(t, fresh.r.cborReference, "Artifact", fresh.artifact, parentField).n + 1
			}
			artifact, fsb := fresh.inputs(t)
			artifactBefore, fsbBefore := bytes.Clone(artifact), bytes.Clone(fsb)
			if got, err := fresh.r.poolAuthorizationProjection(artifact, fsb, fresh.context, 1<<16); err != cborRefError(mutation.code) || got != nil {
				t.Fatalf("want %s, got %v", mutation.code, err)
			}
			if !bytes.Equal(artifact, artifactBefore) || !bytes.Equal(fsb, fsbBefore) {
				t.Fatal("projection changed received bytes")
			}
		})
	}
	for _, winner := range []int{0, 1} {
		fresh := newPoolBindingFixture(t, []uint64{0, 1})
		oracleField(t, fresh.r.cborReference, "FSB4", fresh.fsb, "candidate_id").data = bytes.Clone(fresh.selection.members[winner].candidateID)
		oracleField(t, fresh.r.cborReference, "FSB4", fresh.fsb, "route_digest").data = bytes.Clone(fresh.selection.members[winner].routeDigest)
		artifact, fsb := fresh.inputs(t)
		if _, err := fresh.r.poolAuthorizationProjection(artifact, fsb, fresh.context, 1<<16); err != nil {
			t.Fatal("valid matched member rejected", err)
		}
	}
	single := newPoolBindingFixture(t, []uint64{0})
	oracleField(t, single.r.cborReference, "FSB4", single.fsb, "candidate_id").data = bytes.Clone(f.selection.members[1].candidateID)
	oracleField(t, single.r.cborReference, "FSB4", single.fsb, "route_digest").data = bytes.Clone(f.selection.members[1].routeDigest)
	artifact, fsb = single.inputs(t)
	if got, err := single.r.poolAuthorizationProjection(artifact, fsb, single.context, 1<<16); err != cborRefError("pool_winner_membership") || got != nil {
		t.Fatal("unselected Artifact member accepted")
	}
}

// v4.cbor.pool_binding_boundaries
func TestCBORPoolBindingBoundaries(t *testing.T) {
	f := newPoolBindingFixture(t, []uint64{0, 1})
	artifact, fsb := f.inputs(t)
	for _, cap := range []uint64{0, uint64(len(artifact) - 1)} {
		if got, err := f.r.poolAuthorizationProjection(artifact, fsb, f.context, cap); err == nil || got != nil {
			t.Fatal("unreserved input accepted")
		}
	}
	for _, inputs := range [][2][]byte{{artifact[:len(artifact)-1], fsb}, {artifact, fsb[:len(fsb)-1]}} {
		if got, err := f.r.poolAuthorizationProjection(inputs[0], inputs[1], f.context, 1<<16); err == nil || got != nil {
			t.Fatal("truncated material accepted")
		}
	}
	authority, err := f.r.variantPath("PoolSelectionRef", f.reference, "once_authority_ref.spend_authority_id", f.context)
	if err != nil || authority == nil {
		t.Fatal("missing once authority", err)
	}
	authority.data = []byte("wrong-authority")
	artifact, fsb = f.inputs(t)
	if got, err := f.r.poolAuthorizationProjection(artifact, fsb, f.context, 1<<16); err != cborRefError("field_equality") || got != nil {
		t.Fatal("once authority mismatch accepted", err)
	}
	f = newPoolBindingFixture(t, []uint64{0, 1})
	set := func(name string, root *cborRefValue, field string, n uint64) {
		oracleField(t, f.r.cborReference, name, root, field).n = n
	}
	set("Artifact", f.artifact, "issued_at_ms", ^uint64(0)-2)
	set("Artifact", f.artifact, "initiation_not_after_ms", ^uint64(0)-1)
	set("Artifact", f.artifact, "session_not_after_ms", ^uint64(0))
	set("ActivationAuthorization", f.proof, "issued_at_ms", ^uint64(0)-2)
	set("ActivationAuthorization", f.proof, "activation_not_after_ms", ^uint64(0)-1)
	set("ActivationAuthorization", f.proof, "session_not_after_ms", ^uint64(0))
	// Refresh fixture digests after intentionally changing the issuer input;
	// verification itself never repairs received bytes or authenticates clocks.
	selection, err := f.r.derivePool(f.artifact.encode(nil), []uint64{0, 1}, 1<<16)
	if err != nil {
		t.Fatal(err)
	}
	oracleField(t, f.r.cborReference, "PoolSelectionRef", f.reference, "artifact_digest").data = selection.artifactDigest
	oracleField(t, f.r.cborReference, "PoolSelectionRef", f.reference, "candidate_set_digest").data = selection.candidateSetDigest
	oracleField(t, f.r.cborReference, "ActivationAuthorization", f.proof, "artifact_digest").data = selection.artifactDigest
	oracleField(t, f.r.cborReference, "ActivationAuthorization", f.proof, "route_selection").data = selection.routeSetDigest
	oracleField(t, f.r.cborReference, "FSB4", f.fsb, "artifact_digest").data = selection.artifactDigest
	artifact, fsb = f.inputs(t)
	if _, err := f.r.poolAuthorizationProjection(artifact, fsb, f.context, 1<<16); err != nil {
		t.Fatal("full uint64 deadline rejected", err)
	}
	set("ActivationAuthorization", f.proof, "activation_not_after_ms", ^uint64(0))
	artifact, fsb = f.inputs(t)
	if got, err := f.r.poolAuthorizationProjection(artifact, fsb, f.context, 1<<16); err != cborRefError("pool_parent_deadline") || got != nil {
		t.Fatal("uint64 parent deadline bypassed", err)
	}
}

// v4.cbor.pool_binding_fuzz
func FuzzCBORPoolBindingReference(f *testing.F) {
	seed := newPoolBindingFixture(f, []uint64{0, 1})
	artifact, fsb := seed.inputs(f)
	f.Add(artifact, fsb)
	seed = newPoolBindingFixture(f, []uint64{1})
	artifact, fsb = seed.inputs(f)
	f.Add(artifact, fsb)
	r, context := seed.r, seed.context
	f.Fuzz(func(t *testing.T, artifact, fsb []byte) {
		if len(artifact) > 1<<16 || len(fsb) > 1<<16 {
			return
		}
		originalArtifact, originalFSB := bytes.Clone(artifact), bytes.Clone(fsb)
		result, err := r.poolAuthorizationProjection(artifact, fsb, context, 1<<16)
		if !bytes.Equal(artifact, originalArtifact) || !bytes.Equal(fsb, originalFSB) {
			t.Fatal("pool projection mutated input")
		}
		if err != nil {
			if result != nil {
				t.Fatal("partial failed projection")
			}
			return
		}
		parsed, err := r.wireMap(fsb, "FSB4", context, 1<<16)
		if err != nil {
			t.Fatal(err)
		}
		id := oracleField(t, r.cborReference, "FSB4", parsed, "candidate_id").data
		route := oracleField(t, r.cborReference, "FSB4", parsed, "route_digest").data
		found := false
		for _, member := range result.members {
			if bytes.Equal(member.candidateID, id) && bytes.Equal(member.routeDigest, route) {
				found = true
			}
		}
		if !found {
			t.Fatal("accepted unpaired winner")
		}
		if got, err := r.poolAuthorizationProjection(artifact, fsb, cborShapeContext{}, 1<<16); err != cborRefError("pool_source_profile") || got != nil {
			t.Fatal("missing source profile accepted")
		}
	})
}
