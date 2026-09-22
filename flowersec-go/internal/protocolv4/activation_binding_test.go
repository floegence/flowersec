package protocolv4

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

type runtimeAdmissionFixture struct {
	artifact, proof, certificate, serverCertificate, fsb *SignedMap
	workspace                                            *PoolSelectionWorkspace
	binding                                              *ActivationBinding
	hello                                                *HelloBinding
	clientHello, serverHello                             []byte
	context                                              DecodeContext
	r                                                    *cborTextReference
}

func newRuntimeAdmissionFixture(t *testing.T, source string, index uint64) *runtimeAdmissionFixture {
	t.Helper()
	f := newPoolBindingFixture(t, []uint64{0})
	r := &runtimeAdmissionFixture{r: f.r, context: DecodeContext{Selectors: map[string]string{"activation_source_profile": source}}}
	parse := func(input []byte, schema string) *cborRefValue {
		v, _, err := f.r.decode(input, schema, nil, 1<<16)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	seed := [32]byte{71, 23, 4}
	cert := parse(oracleField(t, f.r.cborReference, "FSB4", f.fsb, "client_certificate").data, "IdentityCertificate")
	oracleField(t, f.r.cborReference, "IdentityCertificate", cert, "ed25519_public_key").data = ed25519.NewKeyFromSeed(seed[:]).Public().(ed25519.PublicKey)
	r.certificate = signRuntimeFixture(t, "IdentityCertificate", cert.encode(nil), DecodeContext{})
	clientDigest, err := r.certificate.Digest("certificate_digest")
	if err != nil {
		t.Fatal(err)
	}
	oracleField(t, f.r.cborReference, "IdentityCertificate", cert, "role").n = 1
	oracleField(t, f.r.cborReference, "IdentityCertificate", cert, "subject_id").data = []byte("server-1")
	r.serverCertificate = signRuntimeFixture(t, "IdentityCertificate", cert.encode(nil), DecodeContext{})
	serverDigest, err := r.serverCertificate.Digest("certificate_digest")
	if err != nil {
		t.Fatal(err)
	}
	artifactSeed := oracleSeed(t, "artifact_pool_sixteen_fields")
	f.artifact = parse(oracleBytes(t, artifactSeed.Hex), "Artifact")
	oracleField(t, f.r.cborReference, "Artifact", f.artifact, "client_identity_digest").data = clientDigest[:]
	oracleField(t, f.r.cborReference, "Artifact", f.artifact, "server_identity_digest").data = serverDigest[:]
	r.artifact = signRuntimeFixture(t, "Artifact", f.artifact.encode(nil), DecodeContext{})
	artifactBytes, _ := r.artifact.Bytes()
	selection, err := f.r.derivePool(artifactBytes, []uint64{0, 5, 15}, 1<<16)
	if err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][2]string{{"tenant_id", "tenant_id"}, {"issuer_key_id", "artifact_issuer_key_id"}, {"lease_id", "lease_id"}, {"audience", "audience"}, {"client_identity_digest", "client_identity_digest"}, {"server_identity_digest", "server_identity_digest"}} {
		*oracleField(t, f.r.cborReference, "ActivationAuthorization", f.proof, pair[1]) = *oracleField(t, f.r.cborReference, "Artifact", f.artifact, pair[0])
	}
	oracleField(t, f.r.cborReference, "ActivationAuthorization", f.proof, "artifact_digest").data = selection.artifactDigest
	winner, err := f.r.derivePool(artifactBytes, []uint64{index}, 1<<16)
	if err != nil {
		t.Fatal(err)
	}
	if source == "live_authority" {
		*oracleField(t, f.r.cborReference, "ActivationAuthorization", f.proof, "candidate_selection") = cborRefValue{major: 2, data: winner.members[0].candidateID}
		oracleField(t, f.r.cborReference, "ActivationAuthorization", f.proof, "route_selection").data = winner.members[0].routeDigest
	} else {
		oracleField(t, f.r.cborReference, "PoolSelectionRef", f.reference, "artifact_digest").data = selection.artifactDigest
		oracleField(t, f.r.cborReference, "PoolSelectionRef", f.reference, "candidate_set_digest").data = selection.candidateSetDigest
		oracleField(t, f.r.cborReference, "PoolSelectionRef", f.reference, "candidate_indices").items = []*cborRefValue{{major: 0, n: 0}, {major: 0, n: 5}, {major: 0, n: 15}}
		oracleField(t, f.r.cborReference, "ActivationAuthorization", f.proof, "route_selection").data = selection.routeSetDigest
	}
	r.proof = signRuntimeFixture(t, "ActivationAuthorization", f.proof.encode(nil), r.context)
	for _, field := range []string{"tenant_id", "issuer_key_id", "lease_id", "session_nonce"} {
		*oracleField(t, f.r.cborReference, "FSB4", f.fsb, field) = *oracleField(t, f.r.cborReference, "Artifact", f.artifact, field)
	}
	oracleField(t, f.r.cborReference, "FSB4", f.fsb, "artifact_digest").data = selection.artifactDigest
	oracleField(t, f.r.cborReference, "FSB4", f.fsb, "candidate_id").data = winner.members[0].candidateID
	oracleField(t, f.r.cborReference, "FSB4", f.fsb, "route_digest").data = winner.members[0].routeDigest
	*oracleField(t, f.r.cborReference, "FSB4", f.fsb, "attempt_id") = *oracleField(t, f.r.cborReference, "ActivationAuthorization", f.proof, "attempt_id")
	proofBytes, _ := r.proof.Bytes()
	certBytes, _ := r.certificate.Bytes()
	oracleField(t, f.r.cborReference, "FSB4", f.fsb, "activation_authorization").data = proofBytes
	oracleField(t, f.r.cborReference, "FSB4", f.fsb, "client_certificate").data = certBytes
	r.fsb = signRuntimeFixture(t, "FSB4", f.fsb.encode(nil), r.context)
	r.workspace, err = NewPoolSelectionWorkspace(1<<16, 4096)
	if err != nil {
		t.Fatal(err)
	}
	r.binding, err = r.workspace.BindActivation(r.artifact, r.proof, source, index)
	if err != nil {
		t.Fatal(err)
	}
	bindRuntimeHellos(t, r)
	return r
}

func (f *runtimeAdmissionFixture) mutate(t *testing.T, m *SignedMap, schema string, change func(*cborRefValue)) *SignedMap {
	t.Helper()
	wire, err := m.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	root, _, err := f.r.decode(wire, schema, nil, 1<<16)
	if err != nil {
		t.Fatal(err)
	}
	change(root)
	return signRuntimeFixture(t, schema, root.encode(nil), f.context)
}

func TestRuntimeActivationAndFSBOriginalBinding(t *testing.T) {
	for _, source := range []string{"live_authority", "preauthorized_pool"} {
		t.Run(source, func(t *testing.T) {
			f := newRuntimeAdmissionFixture(t, source, 5)
			binding, err := f.binding.MatchFSB(f.fsb, f.certificate)
			if err != nil {
				t.Fatal(err)
			}
			wire, _ := f.fsb.Bytes()
			reference, err := cborSingleMapHash("admission_binding", "FSB4", "full", wire)
			if err != nil || binding != [32]byte(reference) {
				t.Fatal("complete original FSB not bound", err)
			}
			f.artifact.Release()
			f.proof.Release()
			// The detached facts retain no parent secrets/decoder aliases.
			again, err := f.binding.MatchFSB(f.fsb, f.certificate)
			if err != nil || again != binding {
				t.Fatal("binding depended on released Artifact storage", err)
			}
			winner := f.binding.Winner()
			winner.CandidateID[0] ^= 1
			if f.binding.Winner() == winner {
				t.Fatal("mutable fact changed retained winner")
			}
		})
	}
}

func TestRuntimeActivationRejectsOtherSignedParentWinnerOrProfile(t *testing.T) {
	f := newRuntimeAdmissionFixture(t, "preauthorized_pool", 5)
	for _, field := range []string{"lease_id", "client_identity_digest", "server_identity_digest", "audience"} {
		t.Run(field, func(t *testing.T) {
			wrong := f.mutate(t, f.proof, "ActivationAuthorization", func(root *cborRefValue) {
				v := oracleField(t, f.r.cborReference, "ActivationAuthorization", root, field)
				v.data = bytes.Clone(v.data)
				v.data[0] ^= 1
			})
			if _, err := f.workspace.BindActivation(f.artifact, wrong, "preauthorized_pool", 5); err == nil {
				t.Fatal("different signed parent binding accepted")
			}
		})
	}
	if _, err := f.workspace.BindActivation(f.artifact, f.proof, "preauthorized_pool", 6); err == nil {
		t.Fatal("unselected winner admitted")
	}
	if _, err := f.workspace.BindActivation(f.artifact, f.proof, "live_authority", 5); err == nil {
		t.Fatal("profile fallback accepted")
	}
	wrong := f.mutate(t, f.proof, "ActivationAuthorization", func(root *cborRefValue) {
		oracleField(t, f.r.cborReference, "ActivationAuthorization", root, "session_not_after_ms").n = ^uint64(0)
	})
	if _, err := f.workspace.BindActivation(f.artifact, wrong, "preauthorized_pool", 5); err != CBORFailure("activation_parent_deadline") {
		t.Fatal("parent deadline extended", err)
	}
	if _, err := f.workspace.BindActivation(f.artifact, f.proof, "preauthorized_pool", 5); err != nil {
		t.Fatal("failed binding retained scratch owner", err)
	}
}

func TestRuntimeFSBRejectsResignedReplacement(t *testing.T) {
	f := newRuntimeAdmissionFixture(t, "preauthorized_pool", 5)
	for _, field := range []string{"session_nonce", "candidate_id", "route_digest", "artifact_digest", "activation_authorization"} {
		t.Run(field, func(t *testing.T) {
			wrong := f.mutate(t, f.fsb, "FSB4", func(root *cborRefValue) {
				v := oracleField(t, f.r.cborReference, "FSB4", root, field)
				v.data = bytes.Clone(v.data)
				v.data[len(v.data)-1] ^= 1
			})
			if _, err := f.binding.MatchFSB(wrong, f.certificate); err == nil {
				t.Fatal("valid FSB signature replaced original authorization")
			}
		})
	}
	otherCert := f.mutate(t, f.certificate, "IdentityCertificate", func(root *cborRefValue) {
		oracleField(t, f.r.cborReference, "IdentityCertificate", root, "subject_id").data = []byte("other-client")
	})
	wrong := f.mutate(t, f.fsb, "FSB4", func(root *cborRefValue) {
		wire, _ := otherCert.Bytes()
		oracleField(t, f.r.cborReference, "FSB4", root, "client_certificate").data = wire
	})
	if _, err := f.binding.MatchFSB(wrong, otherCert); err != CBORFailure("admission_identity_binding") {
		t.Fatal("another issuer-valid certificate substituted", err)
	}
	f.fsb.Release()
	if _, err := f.binding.MatchFSB(f.fsb, f.certificate); err == nil {
		t.Fatal("released FSB reused")
	}
}
