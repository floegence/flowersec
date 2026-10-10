package protocolv4

import (
	"bytes"
	"math"
	"strings"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

func newRevocationLazyFixture(t *testing.T) (*namespaceFixture, *RevocationWorkspace) {
	t.Helper()
	f := newNamespaceFixture(t)
	capacity, _, err := f.r.decode(f.capacity, "NamespaceCapacity", nil, 1<<16)
	if err != nil {
		t.Fatal(err)
	}
	for field, limit := range map[string]uint64{
		"max_state_encoded_bytes":    4096,
		"max_revoked_issuers":        2,
		"max_revoked_certificates":   4,
		"max_revoked_leases":         3,
		"max_cohort_policy_segments": 2,
	} {
		f.set(t, "NamespaceCapacity", capacity, field, namespaceNumber(limit))
	}
	for _, field := range []string{"tenant_id", "revocation_authority_id"} {
		oracleField(t, f.r.cborReference, "NamespaceCapacity", capacity, field).data = []byte(strings.Repeat("a", 128))
	}
	publication, _, err := f.r.decode(f.publication, "PublicationPolicy", nil, 1<<16)
	if err != nil {
		t.Fatal(err)
	}
	oracleField(t, f.r.cborReference, "PublicationPolicy", publication, "publication_policy_id").data = []byte(strings.Repeat("p", 128))
	f.capacity, f.publication = capacity.encode(nil), publication.encode(nil)
	f.rules, err = NewNamespaceRules(f.capacity, f.publication)
	if err != nil {
		t.Fatal(err)
	}
	f.set(t, "RevocationState", f.state, "namespace_capacity_digest", namespaceBytes(f.rules.capacityDigest[:]))
	for _, field := range []string{"tenant_id", "revocation_authority_id"} {
		f.set(t, "RevocationState", f.state, field, oracleField(t, f.r.cborReference, "NamespaceCapacity", capacity, field))
	}
	f.set(t, "RevocationState", f.state, "publication_policy_id", oracleField(t, f.r.cborReference, "PublicationPolicy", publication, "publication_policy_id"))
	oracleField(t, f.r.cborReference, "RevocationState", f.state, "schema_revision").data = []byte(strings.Repeat("s", 128))
	f.set(t, "RevocationState", f.state, "credential_revocation_floors", namespaceArray(namespaceNumber(0), namespaceNumber(0)))
	cost, err := f.rules.StateCharge()
	if err != nil {
		t.Fatal(err)
	}
	w, err := NewRevocationWorkspace(f.rules, f.reserve(t, cost))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := w.Close(); err != nil {
			t.Error(err)
		}
	})
	return f, w
}

func fillRevocationLazyMaximumState(t *testing.T, f *namespaceFixture) []byte {
	t.Helper()
	issuers := make([]*cborRefValue, int(f.rules.limits["max_revoked_issuers"]))
	for i := range issuers {
		var id [16]byte
		id[15] = byte(i + 1)
		// Multiple original authorizations exercise all nested map/array nodes,
		// in addition to every independently configured State entry maximum.
		authorizations := make([]*cborRefValue, 8)
		for j := range authorizations {
			var digest [32]byte
			digest[31] = byte(j + 1)
			authorizations[j] = f.mapValue(t, "IssuerAuthorizationImpact", map[string]*cborRefValue{
				"authorization_digest": namespaceBytes(digest[:]), "max_affected_cohorts": namespaceArray(namespaceNumber(0), namespaceNumber(0)),
				"signing_not_before_ms": namespaceNumber(1000), "signing_not_after_ms": namespaceNumber(1200),
			})
		}
		issuers[i] = f.mapValue(t, "RevokedIssuerEntry", map[string]*cborRefValue{"issuer_key_id": namespaceBytes(id[:]), "authorizations": namespaceArray(authorizations...)})
	}
	certificates := make([]*cborRefValue, int(f.rules.limits["max_revoked_certificates"]))
	for i := range certificates {
		var digest [32]byte
		digest[31] = byte(i + 1)
		certificates[i] = f.mapValue(t, "RevokedCertificateEntry", map[string]*cborRefValue{
			"certificate_digest": namespaceBytes(digest[:]), "cohort": namespaceNumber(0), "expires_at_ms": namespaceNumber(2000),
		})
	}
	leases := make([]*cborRefValue, int(f.rules.limits["max_revoked_leases"]))
	for i := range leases {
		var id [16]byte
		id[15] = byte(i + 1)
		leases[i] = f.mapValue(t, "RevokedLeaseEntry", map[string]*cborRefValue{
			"issuer_key_id": namespaceBytes(make([]byte, 16)), "lease_id": namespaceBytes(id[:]), "artifact_digest": namespaceBytes(make([]byte, 32)),
			"cohort": namespaceNumber(0), "latest_impact_not_after_ms": namespaceNumber(10000),
		})
	}
	segments := make([]*cborRefValue, int(f.rules.limits["max_cohort_policy_segments"]))
	for i := range segments {
		segments[i] = f.mapValue(t, "CohortPolicySegment", map[string]*cborRefValue{
			"first_cohort": namespaceNumber(uint64(i)), "last_cohort": namespaceNumber(uint64(i)),
			"certificate_impact_ms": namespaceNumber(1000), "connection_impact_ms": namespaceNumber(10000),
		})
	}
	f.set(t, "RevocationState", f.state, "revoked_issuers", namespaceArray(issuers...))
	f.set(t, "RevocationState", f.state, "revoked_certificates", namespaceArray(certificates...))
	f.set(t, "RevocationState", f.state, "revoked_leases", namespaceArray(leases...))
	f.set(t, "RevocationState", f.state, "cohort_policy_segments", namespaceArray(segments...))
	return f.state.encode(nil)
}

func requireRevocationLazyIdle(t *testing.T, w *RevocationWorkspace) {
	t.Helper()
	d := w.decoder
	if w.current != nil || d.input != nil || d.nodes != nil || d.active || d.used != 0 || d.size != 0 {
		t.Fatal("released or failed State retained an active document or private node arena")
	}
	if !bytes.Equal(d.input, make([]byte, len(d.input))) {
		t.Fatal("released or failed State retained original input bytes")
	}
	for i := range d.work {
		if d.work[i] != 0 || d.scratch[i] != 0 {
			t.Fatal("released or failed State retained normalization scratch")
		}
	}
	for _, segments := range w.segments {
		if len(segments) != 0 {
			t.Fatal("released or failed State retained selected cohort indexes")
		}
		for _, segment := range segments[:cap(segments)] {
			if segment != (cohortSegment{}) {
				t.Fatal("released or failed State retained encoded cohort evidence")
			}
		}
	}
	if err := w.reservation.Check(); err != nil {
		t.Fatal("private arena retirement returned the original workspace reservation", err)
	}
}

func TestRuntimeRevocationLazyNodesPreserveMaximumStateAndReservation(t *testing.T) {
	f, w := newRevocationLazyFixture(t)
	maximum := int(f.rules.stateBytes)
	full, err := decoderBackingBytes(maximum, maximum, min(128, maximum))
	if err != nil {
		t.Fatal(err)
	}
	cost, err := f.rules.StateCharge()
	if err != nil || cost[resourcev4.SDKBytes] < full {
		t.Fatal("complete original State allowance is not prepaid", cost, full, err)
	}
	if w.decoder.byteLimit != maximum || w.decoder.nodeLimit != maximum || w.decoder.input != nil || w.decoder.nodes != nil || w.decoder.textCap != 128 {
		t.Fatal("idle State workspace changed original byte/text/node bounds")
	}
	charged := f.resources.Snapshot().Charged
	small, err := w.BindPublicationState(f.state.encode(nil), valueUintFromReference(t, f, "authority_generation"), 1, f.now)
	if err != nil {
		t.Fatal(err)
	}
	oldNodes, oldBytes, oldView := w.decoder.nodes, small.document.Bytes(), small.document.Root()
	small.Release()
	requireRevocationLazyIdle(t, w)
	if !bytes.Equal(oldBytes, make([]byte, len(oldBytes))) {
		t.Fatal("released State left its original input bytes readable")
	}
	for _, node := range oldNodes {
		if node != (cborNode{}) {
			t.Fatal("released State left original node evidence readable")
		}
	}
	wire := fillRevocationLazyMaximumState(t, f)
	original := bytes.Clone(wire)
	context := DecodeContext{Limits: f.rules.limits}
	generic, err := newDecoder(maximum, maximum, min(128, maximum))
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := generic.DecodeMap(original, "RevocationState", context)
	if err != nil {
		t.Fatal("original complete State decoder rejected maximum entries", err)
	}
	defer baseline.Release()
	state, err := w.BindPublicationState(wire, valueUintFromReference(t, f, "authority_generation"), 2, f.now)
	if err != nil {
		t.Fatal("lazy arena rejected original maximum State entries", err)
	}
	clear(wire)
	if !bytes.Equal(state.document.Bytes(), original) || w.decoder.used != generic.used || len(w.decoder.nodes) != generic.used || len(w.decoder.input) != len(original) || oldView.valid() {
		t.Fatal("State reuse changed complete bytes, nested nodes or stale views")
	}
	for field, limit := range map[string]string{
		"revoked_issuers": "max_revoked_issuers", "revoked_certificates": "max_revoked_certificates",
		"revoked_leases": "max_revoked_leases", "cohort_policy_segments": "max_cohort_policy_segments",
	} {
		if state.document.Root().Named("RevocationState", field).Len() != int(f.rules.limits[limit]) {
			t.Fatal("State entry maximum was reduced", field)
		}
	}
	if tenant, _ := state.document.Root().Named("RevocationState", "tenant_id").Text(); len(tenant) != 128 {
		t.Fatal("full legal State text allowance was reduced")
	}
	if _, err := w.Bind(state.head, original); err != CBORFailure("decoder_busy") {
		t.Fatal("a live State arena was replaced", err)
	}
	small.Release()
	if w.current != state || !state.document.Root().valid() {
		t.Fatal("a stale State release reclaimed its successor")
	}
	state.Release()
	requireRevocationLazyIdle(t, w)
	if f.resources.Snapshot().Charged != charged {
		t.Fatal("State Release changed the original full workspace charge")
	}
}

func valueUintFromReference(t *testing.T, f *namespaceFixture, field string) uint64 {
	t.Helper()
	return oracleField(t, f.r.cborReference, "RevocationState", f.state, field).n
}

func TestRuntimeRevocationLazyNodesRetryAfterOriginalRefusals(t *testing.T) {
	f, w := newRevocationLazyFixture(t)
	wire := fillRevocationLazyMaximumState(t, f)
	maximum := int(f.rules.stateBytes)
	generation := valueUintFromReference(t, f, "authority_generation")
	charged := f.resources.Snapshot().Charged
	badCount, _, err := f.r.decode(wire, "RevocationState", f.rules.limits, 1<<16)
	if err != nil {
		t.Fatal(err)
	}
	certificates := oracleField(t, f.r.cborReference, "RevocationState", badCount, "revoked_certificates")
	certificates.items = append(certificates.items, f.mapValue(t, "RevokedCertificateEntry", map[string]*cborRefValue{
		"certificate_digest": namespaceBytes(bytes.Repeat([]byte{255}, 32)), "cohort": namespaceNumber(0), "expires_at_ms": namespaceNumber(2000),
	}))
	badImpact, _, err := f.r.decode(wire, "RevocationState", f.rules.limits, 1<<16)
	if err != nil {
		t.Fatal(err)
	}
	lease := oracleField(t, f.r.cborReference, "RevocationState", badImpact, "revoked_leases").items[0]
	f.set(t, "RevokedLeaseEntry", lease, "latest_impact_not_after_ms", namespaceNumber(math.MaxUint64))
	overBytes := make([]byte, maximum+1)
	copy(overBytes, wire)
	for _, test := range []struct {
		name  string
		input []byte
		late  bool
	}{
		{"truncated", wire[:len(wire)-1], false},
		{"original_byte_limit", overBytes, false},
		{"original_entry_limit", badCount.encode(nil), false},
		{"late_evidence_impact", badImpact.encode(nil), true},
	} {
		t.Run(test.name, func(t *testing.T) {
			generic, err := newDecoder(maximum, maximum, min(128, maximum))
			if err != nil {
				t.Fatal(err)
			}
			original, want := generic.DecodeMap(test.input, "RevocationState", DecodeContext{Limits: f.rules.limits})
			if original != nil {
				original.Release()
			}
			if test.late {
				if want != nil {
					t.Fatal("late failure fixture did not reach contextual State checks", want)
				}
				want = CBORFailure("revocation_evidence_impact")
			} else if want == nil {
				t.Fatal("original decoder accepted a refusal fixture")
			}
			if state, err := w.BindPublicationState(test.input, generation, 3, f.now); err != want || state != nil {
				t.Fatal("lazy State changed an original refusal", state, err, want)
			}
			requireRevocationLazyIdle(t, w)
			state, err := w.BindPublicationState(wire, generation, 4, f.now)
			if err != nil || !bytes.Equal(state.document.Bytes(), wire) {
				t.Fatal("failed State decode lost its original retry capacity", err)
			}
			wrongHead := *state.head
			wrongHead.stateDigest[0] ^= 1
			state.Release()
			if state, err := w.Bind(&wrongHead, wire); err != CBORFailure("revocation_state_digest") || state != nil {
				t.Fatal("lazy State accepted a replacement digest", state, err)
			}
			requireRevocationLazyIdle(t, w)
			state, err = w.BindPublicationState(wire, generation, 5, f.now)
			if err != nil {
				t.Fatal("late digest refusal lost reusable State capacity", err)
			}
			state.Release()
			requireRevocationLazyIdle(t, w)
			if f.resources.Snapshot().Charged != charged {
				t.Fatal("State failure or retry changed its original workspace charge")
			}
		})
	}
}
