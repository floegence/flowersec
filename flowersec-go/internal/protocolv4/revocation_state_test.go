package protocolv4

import (
	"bytes"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

func (f *namespaceFixture) certificate(t *testing.T) (*SignedMap, IssuerPermission) {
	t.Helper()
	c := f.seed(t, "certificate_fields")
	for _, field := range []string{"tenant_id", "revocation_authority_id", "namespace_capacity_digest"} {
		f.set(t, "IdentityCertificate", c, field, oracleField(t, f.r.cborReference, "RevocationState", f.state, field))
	}
	f.set(t, "IdentityCertificate", c, "revocation_authority_generation", oracleField(t, f.r.cborReference, "RevocationState", f.state, "authority_generation"))
	f.set(t, "IdentityCertificate", c, "revocation_epoch", namespaceNumber(0))
	f.set(t, "IdentityCertificate", c, "issued_at_ms", namespaceNumber(1050))
	f.set(t, "IdentityCertificate", c, "expires_at_ms", namespaceNumber(2000))
	signed := signRuntimeFixture(t, "IdentityCertificate", c.encode(nil), DecodeContext{})
	issuer, _ := signed.Field("issuer_key_id").ByteString()
	return signed, IssuerPermission{Schema: "IdentityCertificate", Issuer: [16]byte(issuer), Key: signed.key, SigningStart: 1000, SigningEnd: 1100}
}

func (f *namespaceFixture) mapValue(t *testing.T, schema string, fields map[string]*cborRefValue) *cborRefValue {
	t.Helper()
	v, err := f.r.namedMap(schema, fields)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestRuntimeNamespaceCredentialClassAndOriginalIssuer(t *testing.T) {
	f := newNamespaceFixture(t)
	state := f.bindState(t, 1, [2]uint64{})
	certificate, permission := f.certificate(t)
	facts, err := state.CheckCredential(certificate, permission, f.now)
	if err != nil || facts.Cohort != 0 || facts.HardDeadlineMS != 2000 || facts.PolicyID == "" {
		t.Fatal("valid original credential rejected", facts, err)
	}
	// The original issuer signing window may have ended; it does not shorten
	// an already issued certificate. Current key retirement is independent.
	for _, wrong := range []IssuerPermission{
		{Schema: "Artifact", Issuer: permission.Issuer, Key: permission.Key, SigningStart: 1000, SigningEnd: 1100},
		{Schema: permission.Schema, Issuer: [16]byte{9}, Key: permission.Key, SigningStart: 1000, SigningEnd: 1100},
		{Schema: permission.Schema, Issuer: permission.Issuer, Key: [32]byte{9}, SigningStart: 1000, SigningEnd: 1100},
		{Schema: permission.Schema, Issuer: permission.Issuer, Key: permission.Key, SigningStart: 1051, SigningEnd: 1100},
	} {
		if _, err := state.CheckCredential(certificate, wrong, f.now); err == nil {
			t.Fatal("substitute issuer purpose/key/window accepted")
		}
	}
	if _, err := state.CheckCredential(certificate, permission, timev4.Interval{LowerMS: 1999, UpperMS: 2000}); err != timev4.ErrExpired {
		t.Fatal("certificate expiry widened", err)
	}
	entry := f.mapValue(t, "RevokedCertificateEntry", map[string]*cborRefValue{"certificate_digest": namespaceBytes(facts.Digest[:]), "cohort": namespaceNumber(0), "expires_at_ms": namespaceNumber(2000)})
	f.set(t, "RevocationState", f.state, "revoked_certificates", namespaceArray(entry))
	revoked := f.bindState(t, 2, [2]uint64{})
	if _, err := revoked.CheckCredential(certificate, permission, f.now); err != CBORFailure("revocation_certificate_rejected") {
		t.Fatal("revoked full certificate accepted", err)
	}
	if err := state.CheckSuccessor(revoked, nil); err != nil {
		t.Fatal("new revocation rejected", err)
	}
	f.set(t, "RevocationState", f.state, "revoked_certificates", namespaceArray())
	missing := f.bindState(t, 3, [2]uint64{})
	if err := revoked.CheckSuccessor(missing, nil); err != CBORFailure("revocation_evidence_missing") {
		t.Fatal("known revocation disappeared", err)
	}
	covered := f.bindState(t, 4, [2]uint64{1, 0})
	if err := revoked.CheckSuccessor(covered, nil); err != nil {
		t.Fatal("covered certificate evidence could not retire", err)
	}
	if _, err := covered.CheckCredential(certificate, permission, timev4.Interval{LowerMS: 2200, UpperMS: 2201}); err != CBORFailure("revocation_floor_rejected") {
		t.Fatal("retired evidence made the certificate usable", err)
	}
}

func TestRuntimeNamespaceIssuerHistoryNeedsAllClassesAndRetirement(t *testing.T) {
	f := newNamespaceFixture(t)
	certificate, permission := f.certificate(t)
	impact := f.mapValue(t, "IssuerAuthorizationImpact", map[string]*cborRefValue{"authorization_digest": namespaceBytes(bytes.Repeat([]byte{2}, 32)), "max_affected_cohorts": namespaceArray(namespaceNumber(1), namespaceNumber(0)), "signing_not_before_ms": namespaceNumber(1000), "signing_not_after_ms": namespaceNumber(1200)})
	issuer := f.mapValue(t, "RevokedIssuerEntry", map[string]*cborRefValue{"issuer_key_id": namespaceBytes(permission.Issuer[:]), "authorizations": namespaceArray(impact)})
	f.set(t, "RevocationState", f.state, "revoked_issuers", namespaceArray(issuer))
	before := f.bindState(t, 1, [2]uint64{})
	if _, err := before.CheckCredential(certificate, permission, f.now); err != CBORFailure("revocation_issuer_rejected") {
		t.Fatal("issuer revocation skipped", err)
	}
	vector := oracleField(t, f.r.cborReference, "IssuerAuthorizationImpact", impact, "max_affected_cohorts")
	vector.items[0] = namespaceNumber(0)
	shrunk := f.bindState(t, 2, [2]uint64{})
	if err := before.CheckSuccessor(shrunk, nil); err != CBORFailure("revocation_issuer_evidence_changed") {
		t.Fatal("original authorization impact shrank", err)
	}
	f.set(t, "RevocationState", f.state, "revoked_issuers", namespaceArray())
	partial := f.bindState(t, 3, [2]uint64{1, 1})
	if err := before.CheckSuccessor(partial, [][16]byte{permission.Issuer}); err != CBORFailure("revocation_evidence_missing") {
		t.Fatal("one class frontier covered cross-class issuer", err)
	}
	covered := f.bindState(t, 4, [2]uint64{2, 1})
	if err := before.CheckSuccessor(covered, nil); err != CBORFailure("revocation_issuer_not_retired") {
		t.Fatal("Head signer retired an independently trusted issuer", err)
	}
	if err := before.CheckSuccessor(covered, [][16]byte{permission.Issuer}); err != nil {
		t.Fatal("fully covered independently retired issuer rejected", err)
	}
}

func TestRuntimeNamespaceLeaseAndSegmentEvidenceCannotChange(t *testing.T) {
	f := newNamespaceFixture(t)
	entry := f.mapValue(t, "RevokedLeaseEntry", map[string]*cborRefValue{"issuer_key_id": namespaceBytes(bytes.Repeat([]byte{2}, 16)), "lease_id": namespaceBytes(bytes.Repeat([]byte{3}, 16)), "artifact_digest": namespaceBytes(bytes.Repeat([]byte{4}, 32)), "cohort": namespaceNumber(0), "latest_impact_not_after_ms": namespaceNumber(10000)})
	f.set(t, "RevocationState", f.state, "revoked_leases", namespaceArray(entry))
	before := f.bindState(t, 1, [2]uint64{})
	f.set(t, "RevokedLeaseEntry", entry, "latest_impact_not_after_ms", namespaceNumber(9000))
	shrunk := f.bindState(t, 2, [2]uint64{})
	if err := before.CheckSuccessor(shrunk, nil); err != CBORFailure("revocation_lease_evidence_changed") {
		t.Fatal("lease influence evidence shrank", err)
	}
	f.set(t, "RevokedLeaseEntry", entry, "latest_impact_not_after_ms", namespaceNumber(11000))
	grown := f.bindState(t, 3, [2]uint64{})
	if err := before.CheckSuccessor(grown, nil); err != nil {
		t.Fatal("conservative bound growth rejected", err)
	}
	f.set(t, "RevocationState", f.state, "revoked_leases", namespaceArray())
	wrongClass := f.bindState(t, 4, [2]uint64{1, 0})
	if err := before.CheckSuccessor(wrongClass, nil); err != CBORFailure("revocation_evidence_missing") {
		t.Fatal("certificate frontier retired a lease", err)
	}
	covered := f.bindState(t, 5, [2]uint64{0, 1})
	if err := before.CheckSuccessor(covered, nil); err != nil {
		t.Fatal(err)
	}
	segment := oracleField(t, f.r.cborReference, "RevocationState", f.state, "cohort_policy_segments").items[0]
	f.set(t, "CohortPolicySegment", segment, "connection_impact_ms", namespaceNumber(9000))
	changed := f.bindState(t, 6, [2]uint64{0, 1})
	if err := before.CheckSuccessor(changed, nil); err != CBORFailure("revocation_segment_retained") {
		t.Fatal("existing cohort policy changed", err)
	}
}
