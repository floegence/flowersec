package protocolv4

import (
	"bytes"
	"sort"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

// RevocationWorkspace owns one complete State, its decoder and two bounded
// cohort indexes. The namespace owner reserves independent active/candidate
// workspaces and real cleanup overlap before subscription. No State byte view
// or callback escapes, and a released handle cannot reclaim its successor.
type RevocationWorkspace struct {
	mu          sync.Mutex
	rules       *NamespaceRules
	decoder     *Decoder
	segments    [2][]Value
	current     *NamespaceState
	owner       *LiveNamespace
	reservation resourcev4.Reference
}

type NamespaceState struct {
	workspace *RevocationWorkspace
	document  *Document
	head      *NamespaceHead
}

func (r *NamespaceRules) StateBackingBytes() (uint64, error) {
	if r == nil {
		return 0, CBORFailure("revocation_namespace_binding")
	}
	// Each CBOR node consumes at least one input byte. This conservative node
	// arena admits the entire signed envelope, including maximal small entries.
	// All State text is bounded security_id text, with no arbitrary UTF-8 body.
	d, err := decoderBackingBytes(int(r.stateBytes), int(r.stateBytes), min(128, int(r.stateBytes)))
	if err != nil {
		return 0, err
	}
	indexes := r.limits["max_cohort_policy_segments"] * 2 * uint64(unsafe.Sizeof(Value{}))
	headBytes, err := SchemaByteLimit("FreshnessHead")
	if err != nil {
		return 0, err
	}
	headDecoder, err := DecoderBackingBytes(headBytes, headBytes)
	if err != nil {
		return 0, err
	}
	return namespaceAdd(d, indexes+headDecoder+uint64(unsafe.Sizeof(RevocationWorkspace{}))+uint64(unsafe.Sizeof(NamespaceState{})))
}

// StateCharge covers the complete decoder, two indexes and its serial local
// verification work position. Provider buffers and allocator overhead belong
// to the enclosing registered profile and must be reserved in addition.
func (r *NamespaceRules) StateCharge() (resourcev4.Vector, error) {
	bytes, err := r.StateBackingBytes()
	return resourcev4.Vector{resourcev4.SDKBytes: bytes, resourcev4.Items: 1, resourcev4.WorkSlots: 1}, err
}

func NewRevocationWorkspace(rules *NamespaceRules, reservation resourcev4.Reference) (*RevocationWorkspace, error) {
	cost, err := rules.StateCharge()
	if err != nil {
		return nil, err
	}
	owned, err := reservation.Take(cost)
	if err != nil {
		return nil, err
	}
	d, err := newDecoder(int(rules.stateBytes), int(rules.stateBytes), min(128, int(rules.stateBytes)))
	if err != nil {
		owned.Release()
		return nil, err
	}
	w := &RevocationWorkspace{rules: rules, decoder: d, reservation: owned}
	for class := range w.segments {
		w.segments[class] = make([]Value, 0, int(rules.limits["max_cohort_policy_segments"]))
	}
	return w, nil
}

// Close releases an uninstalled workspace. An installed workspace belongs to
// its live namespace; cached State/history cannot be freed by a stale creator.
func (w *RevocationWorkspace) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.owner != nil {
		return CBORFailure("revocation_state_owner")
	}
	w.destroyLocked()
	return nil
}

func (w *RevocationWorkspace) destroyLocked() {
	if w.current != nil {
		w.current.document.Release()
		w.current.document, w.current.head = nil, nil
		w.current = nil
	}
	w.clear()
	w.segments = [2][]Value{}
	w.decoder = nil
	w.reservation.Release()
}

func (w *RevocationWorkspace) clear() {
	for class := range w.segments {
		clear(w.segments[class])
		w.segments[class] = w.segments[class][:0]
	}
}

// Bind validates the full original content against its original selected Head.
// It does not select a newer Head, install active state or prove continuity.
func (w *RevocationWorkspace) Bind(head *NamespaceHead, input []byte) (_ *NamespaceState, err error) {
	return w.bind(nil, head, input)
}

func (w *RevocationWorkspace) bind(owner *LiveNamespace, head *NamespaceHead, input []byte) (_ *NamespaceState, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.owner != owner {
		return nil, CBORFailure("revocation_state_owner")
	}
	if err := w.reservation.Check(); err != nil {
		return nil, err
	}
	if w.current != nil {
		return nil, CBORFailure("decoder_busy")
	}
	if head == nil || head.rules != w.rules || uint64(len(input)) != head.stateBytes {
		return nil, CBORFailure("revocation_state_length")
	}
	doc, err := w.decoder.DecodeMap(input, "RevocationState", DecodeContext{Limits: w.rules.limits})
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			w.clear()
			doc.Release()
		}
	}()
	digest, err := fullMapDigest("revocation_state_digest", "RevocationState", doc.Bytes())
	if err != nil {
		return nil, err
	}
	if digest != head.stateDigest {
		return nil, CBORFailure("revocation_state_digest")
	}
	h, err := boundedMap(head.bytes, "FreshnessHead")
	if err != nil {
		return nil, err
	}
	defer h.Release()
	root := doc.Root()
	for _, field := range []string{"schema_revision", "tenant_id", "revocation_authority_id", "namespace_capacity_digest", "authority_generation", "credential_revocation_floors", "publication_policy_id", "publication_policy_revision"} {
		if !bytes.Equal(root.Named("RevocationState", field).Encoded(), h.Root().Named("FreshnessHead", field).Encoded()) {
			return nil, CBORFailure("revocation_state_binding")
		}
	}
	segments := root.Named("RevocationState", "cohort_policy_segments")
	for i := 0; i < segments.Len(); i++ {
		segment := segments.Index(i)
		last := valueUint(segment, "CohortPolicySegment", "last_cohort")
		end, err := w.rules.cohortEnd(last)
		if err != nil {
			return nil, err
		}
		for class, field := range []string{"certificate_impact_ms", "connection_impact_ms"} {
			impact, exists := segment.Named("CohortPolicySegment", field).Uint()
			if !exists {
				continue
			}
			if impact > w.rules.impact[class] {
				return nil, CBORFailure("revocation_segment_impact")
			}
			if _, err := namespaceAdd(end, w.rules.impact[class]); err != nil {
				return nil, err
			}
			if len(w.segments[class]) == cap(w.segments[class]) {
				return nil, CBORFailure("configuration_capacity")
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
				return nil, CBORFailure("revocation_segment_overlap")
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
			end, err := w.rules.mature(group.class, valueUint(entry, group.schema, "cohort"))
			if err != nil {
				return nil, err
			}
			if valueUint(entry, group.schema, group.end) > end {
				return nil, CBORFailure("revocation_evidence_impact")
			}
		}
	}
	s := &NamespaceState{workspace: w, document: doc, head: head}
	w.current = s
	return s, nil
}

func (s *NamespaceState) Release() {
	s.release(nil)
}

func (s *NamespaceState) release(owner *LiveNamespace) {
	w := s.workspace
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.current == s && w.owner == owner {
		w.clear()
		s.document.Release()
		s.document, s.head = nil, nil
		w.current = nil
	}
}

// searchRevocation uses the first fixed-width identity fields of the canonical
// maps. Their complete-byte order has the same key order; no peer-chosen index,
// hash collision, copy of the member sets or unbounded scan is involved.
func searchRevocation(list Value, schema string, fields []string, keys ...[]byte) Value {
	compare := func(entry Value) int {
		for i, field := range fields {
			key, _ := entry.Named(schema, field).ByteString()
			if order := bytes.Compare(key, keys[i]); order != 0 {
				return order
			}
		}
		return 0
	}
	i := sort.Search(list.Len(), func(i int) bool { return compare(list.Index(i)) >= 0 })
	if i < list.Len() && compare(list.Index(i)) == 0 {
		return list.Index(i)
	}
	return Value{}
}

type cohortWindow struct{ start, end, impact uint64 }

func (s *NamespaceState) cohort(class int, cohort uint64) (cohortWindow, error) {
	if cohort < s.head.floors[class] {
		return cohortWindow{}, CBORFailure("revocation_floor_rejected")
	}
	w := s.workspace
	segments := w.segments[class]
	i := sort.Search(len(segments), func(i int) bool { return valueUint(segments[i], "CohortPolicySegment", "last_cohort") >= cohort })
	if i == len(segments) || valueUint(segments[i], "CohortPolicySegment", "first_cohort") > cohort {
		return cohortWindow{}, CBORFailure("revocation_segment_missing")
	}
	end, err := w.rules.cohortEnd(cohort)
	if err != nil {
		return cohortWindow{}, err
	}
	field := "certificate_impact_ms"
	if class == 1 {
		field = "connection_impact_ms"
	}
	impact, err := namespaceAdd(end, valueUint(segments[i], "CohortPolicySegment", field))
	return cohortWindow{start: end - w.rules.duration, end: end, impact: impact}, err
}

// IssuerPermission is local independent-trust context for one exact credential
// purpose. It is not a serialized trust schema. The trust owner must resolve
// the original key/purpose/tenant/audience permissions and retain their full
// history; the signed credential cannot supply its own permission object.
type IssuerPermission struct {
	Schema                   string
	Issuer                   [16]byte
	Key                      [32]byte
	SigningStart, SigningEnd uint64
}

// CredentialStateFacts do not grant rights. The complete authorization owner
// additionally checks current trust, the role closure, observed known denials,
// exact permissions/bindings and the shared active Head's resolved deadline.
type CredentialStateFacts struct {
	Digest                 [32]byte
	Cohort, HardDeadlineMS uint64
	PolicyID               string
	PolicyRevision         uint64
	class                  int
}

func (s *NamespaceState) CheckCredential(credential *SignedMap, permission IssuerPermission, now timev4.Interval) (facts CredentialStateFacts, err error) {
	detached, err := credential.DetachCredential()
	if err != nil {
		return facts, err
	}
	return s.CheckDetachedCredential(detached, permission, now)
}

func (s *NamespaceState) CheckDetachedCredential(credential *Credential, permission IssuerPermission, now timev4.Interval) (facts CredentialStateFacts, err error) {
	if err := credential.checkPermission(permission); err != nil {
		return facts, err
	}
	w := s.workspace
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.current != s {
		return facts, CBORFailure("revocation_state_owner")
	}
	if err := w.reservation.Check(); err != nil {
		return facts, err
	}
	if err := s.head.CheckTime(now); err != nil {
		return facts, err
	}
	scope := credential.scope
	if scope.Tenant != w.rules.tenant || scope.Authority != w.rules.authority || scope.CapacityDigest != w.rules.capacityDigest || scope.Generation != s.head.generation {
		return facts, CBORFailure("revocation_namespace_binding")
	}
	facts = credential.facts
	cohort, err := s.cohort(facts.class, facts.Cohort)
	if err != nil {
		return facts, err
	}
	issued := scope.IssuedMS
	if issued < cohort.start || issued >= cohort.end || facts.HardDeadlineMS <= issued || facts.HardDeadlineMS > cohort.impact {
		return facts, CBORFailure("revocation_credential_impact")
	}
	if !now.ValidBefore(facts.HardDeadlineMS) {
		return facts, timev4.ErrExpired
	}
	if err := now.LowerBound(issued, true); err != nil {
		return facts, err
	}
	state := s.document.Root()
	if searchRevocation(state.Named("RevocationState", "revoked_issuers"), "RevokedIssuerEntry", []string{"issuer_key_id"}, scope.Issuer[:]).valid() {
		return facts, CBORFailure("revocation_issuer_rejected")
	}
	if facts.class == 0 && searchRevocation(state.Named("RevocationState", "revoked_certificates"), "RevokedCertificateEntry", []string{"certificate_digest"}, facts.Digest[:]).valid() {
		return facts, CBORFailure("revocation_certificate_rejected")
	}
	if scope.Schema == "Artifact" {
		if searchRevocation(state.Named("RevocationState", "revoked_leases"), "RevokedLeaseEntry", []string{"issuer_key_id", "lease_id"}, scope.Issuer[:], credential.lease[:]).valid() {
			return facts, CBORFailure("revocation_lease_rejected")
		}
	}
	return facts, nil
}

// CheckSuccessor retains exact known denials. retired is the bounded, sorted
// set of permanently retired keys established by independent current trust;
// a Head signer cannot supply it. This checks content, not atomic installation.
// Callers must release all real old references before reclaiming old backing.
func (s *NamespaceState) CheckSuccessor(next *NamespaceState, retired [][16]byte) error {
	if next == nil || next == s || next.workspace == s.workspace {
		return CBORFailure("revocation_state_owner")
	}
	// This operation is try-only: opposing continuity checks cannot deadlock or
	// retain an unbounded waiter while a decoder/credential operation is active.
	w, nw := s.workspace, next.workspace
	if !w.mu.TryLock() {
		return CBORFailure("decoder_busy")
	}
	defer w.mu.Unlock()
	if !nw.mu.TryLock() {
		return CBORFailure("decoder_busy")
	}
	defer nw.mu.Unlock()
	if err := w.reservation.CheckSameEnvironment(nw.reservation); err != nil {
		return err
	}
	if w.current != s || nw.current != next || w.rules != nw.rules || s.head.schema != next.head.schema || s.head.generation != next.head.generation || next.head.sequence <= s.head.sequence || len(retired) > int(w.rules.limits["max_revoked_issuers"]) {
		return CBORFailure("revocation_state_owner")
	}
	for i := 1; i < len(retired); i++ {
		if bytes.Compare(retired[i-1][:], retired[i][:]) >= 0 {
			return CBORFailure("revocation_retirement_context")
		}
	}
	for class, floor := range next.head.floors {
		if floor < s.head.floors[class] {
			return CBORFailure("revocation_floor_rollback")
		}
	}
	before, after := s.document.Root(), next.document.Root()
	for _, group := range []struct {
		field, schema string
		keys          []string
		class         int
	}{{"revoked_certificates", "RevokedCertificateEntry", []string{"certificate_digest"}, 0}, {"revoked_leases", "RevokedLeaseEntry", []string{"issuer_key_id", "lease_id"}, 1}, {"revoked_issuers", "RevokedIssuerEntry", []string{"issuer_key_id"}, -1}} {
		oldList, newList := before.Named("RevocationState", group.field), after.Named("RevocationState", group.field)
		for i := 0; i < oldList.Len(); i++ {
			old := oldList.Index(i)
			var keys [2][]byte
			for j, key := range group.keys {
				keys[j], _ = old.Named(group.schema, key).ByteString()
			}
			found := searchRevocation(newList, group.schema, group.keys, keys[:len(group.keys)]...)
			if found.valid() {
				if group.class == -1 {
					oldAuth := old.Named(group.schema, "authorizations")
					newAuth := found.Named(group.schema, "authorizations")
					for j := 0; j < oldAuth.Len(); j++ {
						entry := oldAuth.Index(j)
						digest, _ := entry.Named("IssuerAuthorizationImpact", "authorization_digest").ByteString()
						retained := searchRevocation(newAuth, "IssuerAuthorizationImpact", []string{"authorization_digest"}, digest)
						if !retained.valid() || !bytes.Equal(entry.Encoded(), retained.Encoded()) {
							return CBORFailure("revocation_issuer_evidence_changed")
						}
					}
				} else if group.class == 0 {
					if !bytes.Equal(old.Encoded(), found.Encoded()) {
						return CBORFailure("revocation_certificate_evidence_changed")
					}
				} else {
					if valueUint(old, group.schema, "cohort") != valueUint(found, group.schema, "cohort") || !bytes.Equal(old.Named(group.schema, "artifact_digest").Encoded(), found.Named(group.schema, "artifact_digest").Encoded()) || valueUint(found, group.schema, "latest_impact_not_after_ms") < valueUint(old, group.schema, "latest_impact_not_after_ms") {
						return CBORFailure("revocation_lease_evidence_changed")
					}
				}
				continue
			}
			if group.class >= 0 {
				if valueUint(old, group.schema, "cohort") >= next.head.floors[group.class] {
					return CBORFailure("revocation_evidence_missing")
				}
			} else {
				key := keys[0]
				j := sort.Search(len(retired), func(j int) bool { return bytes.Compare(retired[j][:], key) >= 0 })
				if j == len(retired) || !bytes.Equal(retired[j][:], key) {
					return CBORFailure("revocation_issuer_not_retired")
				}
				entries := old.Named(group.schema, "authorizations")
				for j := 0; j < entries.Len(); j++ {
					vector := entries.Index(j).Named("IssuerAuthorizationImpact", "max_affected_cohorts")
					for class := range 2 {
						if cohort, applies := vector.Index(class).Uint(); applies && cohort >= next.head.floors[class] {
							return CBORFailure("revocation_evidence_missing")
						}
					}
				}
			}
		}
	}
	oldSegments := before.Named("RevocationState", "cohort_policy_segments")
	newSegments := after.Named("RevocationState", "cohort_policy_segments")
	for i := 0; i < oldSegments.Len(); i++ {
		old := oldSegments.Index(i)
		j := sort.Search(newSegments.Len(), func(j int) bool { return bytes.Compare(newSegments.Index(j).Encoded(), old.Encoded()) >= 0 })
		if j < newSegments.Len() && bytes.Equal(newSegments.Index(j).Encoded(), old.Encoded()) {
			continue
		}
		for class, field := range []string{"certificate_impact_ms", "connection_impact_ms"} {
			if _, exists := old.Named("CohortPolicySegment", field).Uint(); exists && valueUint(old, "CohortPolicySegment", "last_cohort") >= next.head.floors[class] {
				return CBORFailure("revocation_segment_retained")
			}
		}
	}
	return nil
}
