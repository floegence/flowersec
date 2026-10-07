package protocolv4

import (
	"math"
	"testing"
)

func TestStoredPublicationFactsHaveNoCurrentAuthorityDependency(t *testing.T) {
	f := newNamespaceFixture(t)
	head, state := f.bindHead(t, 7, [2]uint64{})
	cost, err := f.rules.StateCharge()
	if err != nil {
		t.Fatal(err)
	}
	w, err := NewRevocationWorkspace(f.rules, f.reserve(t, cost))
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	maximum, err := SchemaByteLimit("FreshnessHead")
	if err != nil {
		t.Fatal(err)
	}
	decoder, err := NewDecoder(maximum, maximum)
	if err != nil {
		t.Fatal(err)
	}
	expected := NamespacePublicationVersion{Snapshot: 3, Sequence: 7, StateDigest: head.stateDigest, HeadDigest: head.digest, ThisUpdateMS: head.issued, NextUpdateMS: head.next}
	scope := f.rules.PublicationScope(head.generation)
	if err = w.InspectStoredPublication(state, head.bytes, decoder, scope, expected); err != nil {
		t.Fatal(err)
	}
	if w.current != nil || w.owner != nil {
		t.Fatal("storage inspection restored runtime authority")
	}
	if err = w.InspectStoredPublication(state, nil, decoder, scope, expected); err != nil {
		t.Fatal("unpublished current state refused", err)
	}
	changed := expected
	changed.Sequence++
	if err = w.InspectStoredPublication(state, head.bytes, decoder, scope, changed); err == nil {
		t.Fatal("detached head sequence accepted")
	}
	// Rehash malformed semantic content so this case cannot pass by checking
	// only the digest and CBOR envelope.
	entry := f.mapValue(t, "RevokedLeaseEntry", map[string]*cborRefValue{
		"issuer_key_id": namespaceBytes(make([]byte, 16)), "lease_id": namespaceBytes(make([]byte, 16)), "artifact_digest": namespaceBytes(make([]byte, 32)),
		"cohort": namespaceNumber(1), "latest_impact_not_after_ms": namespaceNumber(math.MaxUint64),
	})
	f.set(t, "RevocationState", f.state, "revoked_leases", namespaceArray(entry))
	state = f.state.encode(nil)
	expected.StateDigest, err = fullMapDigest("revocation_state_digest", "RevocationState", state)
	if err != nil {
		t.Fatal(err)
	}
	if err = w.InspectStoredPublication(state, nil, decoder, scope, expected); err == nil {
		t.Fatal("impossible retained impact accepted")
	}
	if w.current != nil || w.owner != nil {
		t.Fatal("failed inspection retained runtime authority")
	}
}
