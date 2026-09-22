package protocolv4

import (
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

func namespaceText(value string) *cborRefValue { return &cborRefValue{major: 3, data: []byte(value)} }

func (f *namespaceFixture) activation(t *testing.T, source string) (*SignedMap, *ActivationAuthority, IssuerPermission) {
	t.Helper()
	parent := f.seed(t, "artifact_transport_fields")
	for _, field := range []string{"tenant_id", "revocation_authority_id", "namespace_capacity_digest"} {
		f.set(t, "Artifact", parent, field, oracleField(t, f.r.cborReference, "RevocationState", f.state, field))
	}
	f.set(t, "Artifact", parent, "revocation_authority_generation", oracleField(t, f.r.cborReference, "RevocationState", f.state, "authority_generation"))
	for field, value := range map[string]uint64{"revocation_epoch": 0, "issued_at_ms": 1050, "initiation_not_after_ms": 1500, "session_not_after_ms": 5000} {
		f.set(t, "Artifact", parent, field, namespaceNumber(value))
	}
	artifact := signRuntimeFixture(t, "Artifact", parent.encode(nil), DecodeContext{})
	return f.activationOriginal(t, source, artifact)
}

func (f *namespaceFixture) activationOriginal(t *testing.T, source string, artifact *SignedMap) (*SignedMap, *ActivationAuthority, IssuerPermission) {
	t.Helper()
	wire, _ := artifact.Bytes()
	parent, _, err := f.r.decode(wire, "Artifact", nil, 1<<16)
	if err != nil {
		t.Fatal(err)
	}
	selection, err := f.r.derivePool(wire, []uint64{0}, 1<<16)
	if err != nil {
		t.Fatal(err)
	}
	proofID := "activation_live_fields"
	if source == "preauthorized_pool" {
		proofID = "activation_pool_fields"
	}
	proof := f.seed(t, proofID)
	for _, pair := range [][2]string{{"tenant_id", "tenant_id"}, {"issuer_key_id", "artifact_issuer_key_id"}, {"lease_id", "lease_id"}, {"audience", "audience"}, {"client_identity_digest", "client_identity_digest"}, {"server_identity_digest", "server_identity_digest"}} {
		f.set(t, "ActivationAuthorization", proof, pair[1], oracleField(t, f.r.cborReference, "Artifact", parent, pair[0]))
	}
	f.set(t, "ActivationAuthorization", proof, "artifact_digest", namespaceBytes(selection.artifactDigest))
	for field, value := range map[string]uint64{"issued_at_ms": 1150, "activation_not_after_ms": 1400, "session_not_after_ms": 4000} {
		f.set(t, "ActivationAuthorization", proof, field, namespaceNumber(value))
	}
	once := f.mapValue(t, "OnceAuthorityRef", map[string]*cborRefValue{
		"tenant_id":              oracleField(t, f.r.cborReference, "Artifact", parent, "tenant_id"),
		"artifact_issuer_key_id": oracleField(t, f.r.cborReference, "Artifact", parent, "issuer_key_id"),
		"spend_authority_id":     oracleField(t, f.r.cborReference, "ActivationAuthorization", proof, "authority_id"),
		"winner_authority_id":    namespaceText("winner-1"),
	})
	if source == "live_authority" {
		f.set(t, "ActivationAuthorization", proof, "candidate_selection", namespaceBytes(selection.members[0].candidateID))
		f.set(t, "ActivationAuthorization", proof, "route_selection", namespaceBytes(selection.members[0].routeDigest))
	} else {
		ref := oracleField(t, f.r.cborReference, "ActivationAuthorization", proof, "candidate_selection")
		f.set(t, "PoolSelectionRef", ref, "artifact_digest", namespaceBytes(selection.artifactDigest))
		f.set(t, "PoolSelectionRef", ref, "candidate_indices", namespaceArray(namespaceNumber(0)))
		f.set(t, "PoolSelectionRef", ref, "candidate_set_digest", namespaceBytes(selection.candidateSetDigest))
		f.set(t, "PoolSelectionRef", ref, "once_authority_ref", once)
		f.set(t, "ActivationAuthorization", proof, "route_selection", namespaceBytes(selection.routeSetDigest))
	}
	signedProof := signRuntimeFixture(t, "ActivationAuthorization", proof.encode(nil), DecodeContext{Selectors: map[string]string{"activation_source_profile": source}})
	workspace, err := NewPoolSelectionWorkspace(1<<16, 4096)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := workspace.BindActivation(artifact, signedProof, source, 0)
	if err != nil {
		t.Fatal(err)
	}
	d := f.seed(t, "activation_delegation_fields")
	for _, field := range []string{"tenant_id", "revocation_authority_id", "namespace_capacity_digest", "authority_generation"} {
		f.set(t, "ConnectionActivationDelegation", d, field, oracleField(t, f.r.cborReference, "RevocationState", f.state, field))
	}
	f.set(t, "ConnectionActivationDelegation", d, "artifact_issuer_key_id", namespaceBytes(binding.issuer[:]))
	f.set(t, "ConnectionActivationDelegation", d, "authority_id", namespaceText(binding.authority))
	f.set(t, "ConnectionActivationDelegation", d, "signing_key_id", namespaceText(binding.signingKey))
	f.set(t, "ConnectionActivationDelegation", d, "signer_public_key", namespaceBytes(binding.proofKey[:]))
	for field, value := range map[string]uint64{"signing_not_before_ms": 1100, "signing_not_after_ms": 1250, "max_activation_not_after_ms": 1400, "max_session_not_after_ms": 4000} {
		f.set(t, "ConnectionActivationDelegation", d, field, namespaceNumber(value))
	}
	a, err := f.rules.BindActivationAuthority(binding, artifact, d.encode(nil), once.encode(nil))
	if err != nil {
		t.Fatal(err)
	}
	return artifact, a, IssuerPermission{Schema: "Artifact", Issuer: binding.issuer, Key: binding.artifactKey, SigningStart: 1000, SigningEnd: 1100}
}

func TestRuntimeActivationAuthorityOriginalWindowAndCurrentNamespace(t *testing.T) {
	for _, source := range []string{"live_authority", "preauthorized_pool"} {
		t.Run(source, func(t *testing.T) {
			f := newNamespaceFixture(t)
			f.now = timev4.Interval{LowerMS: 1700, UpperMS: 1800}
			n, _, trust := liveNamespaceFixture(t, f, 4000, false)
			artifact, a, permission := f.activation(t, source)
			trust.activation = a.trust
			if a.parentCohort != 0 || a.binding.issuedAt != 1150 {
				t.Fatal("late activation was assigned another cohort")
			}
			end, err := n.CheckActivation(a, artifact, permission, 5000, f.rules.signerLife, 10000)
			if err != nil || end != 4000 {
				t.Fatal("ended signing/admission window killed the admitted Session", end, err)
			}
			if err := a.CheckAdmission(f.now); err != timev4.ErrExpired {
				t.Fatal("same old proof gained a new admission window", err)
			}
			if err := a.CheckAdmission(timev4.Interval{LowerMS: 1200, UpperMS: 1300}); err != nil {
				t.Fatal(err)
			}
			if err := n.active.CheckActivation(a, timev4.Interval{LowerMS: 3999, UpperMS: 4000}); err != timev4.ErrExpired {
				t.Fatal("original Session deadline extended", err)
			}
			d, _, err := f.r.decode(a.delegation, "ConnectionActivationDelegation", nil, 1<<16)
			if err != nil {
				t.Fatal(err)
			}
			f.set(t, "ConnectionActivationDelegation", d, "max_session_not_after_ms", namespaceNumber(4001))
			replaced, err := f.rules.BindActivationAuthority(a.binding, artifact, d.encode(nil), a.authority)
			if err != nil {
				t.Fatal(err)
			}
			if a.Matches(replaced.delegation, replaced.authority) {
				t.Fatal("changed immutable entry matched")
			}
			if _, err := n.CheckActivation(replaced, artifact, permission, 5000, f.rules.signerLife, 10000); err != CBORFailure("independent_activation_rejected") {
				t.Fatal("same signer ID changed its original authorization", err)
			}

			impact := f.mapValue(t, "IssuerAuthorizationImpact", map[string]*cborRefValue{"authorization_digest": namespaceBytes(a.trust.DelegationDigest[:]), "max_affected_cohorts": namespaceArray(&cborRefValue{major: 7, n: 22}, namespaceNumber(100)), "signing_not_before_ms": namespaceNumber(1100), "signing_not_after_ms": namespaceNumber(1250)})
			issuer := f.mapValue(t, "RevokedIssuerEntry", map[string]*cborRefValue{"issuer_key_id": namespaceBytes(a.trust.Issuer[:]), "authorizations": namespaceArray(impact)})
			f.set(t, "RevocationState", f.state, "revoked_issuers", namespaceArray(issuer))
			head, input := f.bindHead(t, 2, [2]uint64{})
			if err := n.Observe(head); err != nil {
				t.Fatal(err)
			}
			pin, _ := n.Pending()
			if err := pin.Fetch(namespaceRead(input)); err != nil {
				t.Fatal(err)
			}
			if _, err := n.CheckActivation(a, artifact, permission, 5000, f.rules.signerLife, 10000); err != CBORFailure("revocation_issuer_rejected") {
				t.Fatal("activation issuer revocation ignored", err)
			}
		})
	}
}

func TestRuntimeActivationAuthorityRejectsKeyAuthorityAndInfluenceChanges(t *testing.T) {
	f := newNamespaceFixture(t)
	f.bindState(t, 1, [2]uint64{})
	artifact, a, _ := f.activation(t, "preauthorized_pool")
	for _, change := range []struct {
		schema, field string
		value         *cborRefValue
	}{
		{"ConnectionActivationDelegation", "signer_public_key", namespaceBytes(make([]byte, 32))},
		{"ConnectionActivationDelegation", "first_parent_cohort", namespaceNumber(1)},
		{"ConnectionActivationDelegation", "signing_not_after_ms", namespaceNumber(1150)},
		{"ConnectionActivationDelegation", "max_session_not_after_ms", namespaceNumber(3999)},
		{"ConnectionActivationDelegation", "max_activation_not_after_ms", namespaceNumber(1399)},
		{"OnceAuthorityRef", "spend_authority_id", namespaceText("empty-replacement-authority")},
		{"OnceAuthorityRef", "winner_authority_id", namespaceText("empty-replacement-winner")},
	} {
		delegation, authority := a.delegation, a.authority
		input := delegation
		if change.schema == "OnceAuthorityRef" {
			input = authority
		}
		root, _, err := f.r.decode(input, change.schema, nil, 1<<16)
		if err != nil {
			t.Fatal(err)
		}
		f.set(t, change.schema, root, change.field, change.value)
		if change.schema == "OnceAuthorityRef" {
			authority = root.encode(nil)
		} else {
			delegation = root.encode(nil)
		}
		if got, err := f.rules.BindActivationAuthority(a.binding, artifact, delegation, authority); err == nil || got != nil {
			t.Fatal("substituted authority accepted", change.field)
		}
	}
}
