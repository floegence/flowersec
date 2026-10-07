package protocolv4

import (
	"bytes"
	"sort"
)

// InspectStoredPublication checks immutable persisted facts in the existing
// State arena. It creates no NamespaceState, NamespaceHead or live authority,
// and deliberately does not consult current trust, signer acceptance or time.
// Empty head bytes select the unpublished current State snapshot.
func (w *RevocationWorkspace) InspectStoredPublication(input, head []byte, decoder *Decoder, scope NamespacePublicationScope, expected NamespacePublicationVersion) error {
	if w == nil || decoder == nil || expected.Snapshot == 0 {
		return CBORFailure("storage_publication")
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.current != nil || w.owner != nil || w.decoder == nil {
		return CBORFailure("storage_publication_owner")
	}
	if err := w.reservation.Check(); err != nil {
		return err
	}
	r := w.rules
	if r.PublicationScope(scope.Generation) != scope {
		return CBORFailure("storage_publication_scope")
	}
	doc, err := w.decoder.DecodeMap(input, "RevocationState", DecodeContext{Limits: r.limits})
	if err != nil {
		return err
	}
	defer doc.Release()
	root := doc.Root()
	if !r.matchesNamespace(root, "RevocationState") || !r.matchesPublication(root, "RevocationState") || valueUint(root, "RevocationState", "authority_generation") != scope.Generation {
		return CBORFailure("storage_publication_scope")
	}
	var floors [2]uint64
	if count, ok := root.Named("RevocationState", "credential_revocation_floors").CopyUints(floors[:]); !ok || count != 2 {
		return CBORFailure("storage_publication_floors")
	}
	for class, floor := range floors {
		if floor != 0 {
			if _, err := r.mature(class, floor-1); err != nil {
				return err
			}
		}
	}
	digest, err := fullMapDigest("revocation_state_digest", "RevocationState", doc.Bytes())
	if err != nil || digest != expected.StateDigest {
		return CBORFailure("storage_publication_digest")
	}
	w.clear()
	defer w.clear()
	segments := root.Named("RevocationState", "cohort_policy_segments")
	for i := 0; i < segments.Len(); i++ {
		segment := segments.Index(i)
		end, e := r.cohortEnd(valueUint(segment, "CohortPolicySegment", "last_cohort"))
		if e != nil {
			return e
		}
		for class, field := range []string{"certificate_impact_ms", "connection_impact_ms"} {
			impact, exists := segment.Named("CohortPolicySegment", field).Uint()
			if !exists {
				continue
			}
			if impact > r.impact[class] {
				return CBORFailure("storage_publication_impact")
			}
			if _, e = namespaceAdd(end, r.impact[class]); e != nil {
				return e
			}
			if len(w.segments[class]) == cap(w.segments[class]) {
				return CBORFailure("configuration_capacity")
			}
			w.segments[class] = append(w.segments[class], segment)
		}
	}
	for _, selected := range w.segments {
		sort.Slice(selected, func(i, j int) bool {
			return valueUint(selected[i], "CohortPolicySegment", "first_cohort") < valueUint(selected[j], "CohortPolicySegment", "first_cohort")
		})
		for i := 1; i < len(selected); i++ {
			if valueUint(selected[i-1], "CohortPolicySegment", "last_cohort") >= valueUint(selected[i], "CohortPolicySegment", "first_cohort") {
				return CBORFailure("storage_publication_overlap")
			}
		}
	}
	for _, group := range []struct {
		field, schema, end string
		class              int
	}{{"revoked_certificates", "RevokedCertificateEntry", "expires_at_ms", 0}, {"revoked_leases", "RevokedLeaseEntry", "latest_impact_not_after_ms", 1}} {
		list := root.Named("RevocationState", group.field)
		for i := 0; i < list.Len(); i++ {
			entry := list.Index(i)
			end, e := r.mature(group.class, valueUint(entry, group.schema, "cohort"))
			if e != nil {
				return e
			}
			if valueUint(entry, group.schema, group.end) > end {
				return CBORFailure("storage_publication_impact")
			}
		}
	}
	if len(head) == 0 {
		return nil
	}
	if uint64(len(head)) > r.headBytes || expected.Sequence == 0 {
		return CBORFailure("storage_publication_head")
	}
	h, err := decoder.DecodeMap(head, "FreshnessHead", DecodeContext{})
	if err != nil {
		return err
	}
	defer h.Release()
	for _, field := range []string{"schema_revision", "tenant_id", "revocation_authority_id", "namespace_capacity_digest", "authority_generation", "credential_revocation_floors", "publication_policy_id", "publication_policy_revision"} {
		if !bytes.Equal(root.Named("RevocationState", field).Encoded(), h.Root().Named("FreshnessHead", field).Encoded()) {
			return CBORFailure("storage_publication_head")
		}
	}
	digest, err = fullMapDigest("freshness_head_digest", "FreshnessHead", h.Bytes())
	if err != nil || digest != expected.HeadDigest || trust32(h.Root(), "FreshnessHead", "state_digest") != expected.StateDigest ||
		valueUint(h.Root(), "FreshnessHead", "state_encoded_bytes") != uint64(len(input)) || valueUint(h.Root(), "FreshnessHead", "head_sequence") != expected.Sequence ||
		valueUint(h.Root(), "FreshnessHead", "this_update_ms") != expected.ThisUpdateMS || valueUint(h.Root(), "FreshnessHead", "next_update_ms") != expected.NextUpdateMS ||
		expected.NextUpdateMS <= expected.ThisUpdateMS || expected.NextUpdateMS-expected.ThisUpdateMS > r.headValidity {
		return CBORFailure("storage_publication_head")
	}
	return nil
}
