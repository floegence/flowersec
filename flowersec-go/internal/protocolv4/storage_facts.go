package protocolv4

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"math"
	"unsafe"
)

// StorageFactsDecoder inspects retained public facts only. It never verifies
// current trust, creates a credential, or restores an original invocation.
// The enclosing storage owner reserves its complete backing before opening.
type StorageFactsDecoder struct {
	decoder *Decoder
	scratch [65536]byte
}

func StorageFactsDecoderBackingBytes() (uint64, error) {
	n, err := DecoderBackingBytes(65536, 4096)
	return n + uint64(unsafe.Sizeof(StorageFactsDecoder{})) + uint64(unsafe.Sizeof(relayParentRecord{})) + 10*RelayParentRecordMaxBytes, err
}

func NewStorageFactsDecoder() (*StorageFactsDecoder, error) {
	d, err := NewDecoder(65536, 4096)
	if err != nil {
		return nil, err
	}
	return &StorageFactsDecoder{decoder: d}, nil
}

// StoredActivationFacts are unauthenticated facts from one local projection.
type StoredActivationFacts struct {
	AdmissionFields
	Budget   PoolAttemptLimits
	RouteSet [32]byte
}

func (d *StorageFactsDecoder) CheckActivation(wire []byte, f StoredActivationFacts) error {
	doc, err := d.decoder.DecodeMap(wire, "ActivationAuthorization", DecodeContext{Selectors: map[string]string{"activation_source_profile": f.Source}})
	if err != nil {
		return err
	}
	defer doc.Release()
	root := doc.Root()
	get := func(name string) Value { return root.Named("ActivationAuthorization", name) }
	for _, pair := range []struct{ name, want string }{{"tenant_id", f.Tenant}, {"authority_id", f.SpendAuthority}, {"signing_key_id", f.SigningKey}, {"audience", f.Audience}} {
		got, _ := get(pair.name).Text()
		if got != pair.want {
			return CBORFailure("storage_activation_binding")
		}
	}
	for _, pair := range []struct {
		name string
		want []byte
	}{
		{"artifact_issuer_key_id", f.Issuer[:]}, {"lease_id", f.Lease[:]}, {"artifact_digest", f.Artifact[:]},
		{"attempt_id", f.Attempt[:]}, {"client_identity_digest", f.ClientIdentity[:]}, {"server_identity_digest", f.ServerIdentity[:]},
	} {
		got, _ := get(pair.name).ByteString()
		if !bytes.Equal(got, pair.want) {
			return CBORFailure("storage_activation_binding")
		}
	}
	for _, pair := range []struct {
		name string
		want uint64
	}{{"issued_at_ms", f.IssuedAt}, {"activation_not_after_ms", f.ActivationEnd}, {"session_not_after_ms", f.SessionEnd}} {
		got, _ := get(pair.name).Uint()
		if got != pair.want {
			return CBORFailure("storage_activation_binding")
		}
	}
	digest, err := fullMapDigest("activation_digest", "ActivationAuthorization", wire)
	if err != nil || digest != f.Proof {
		return CBORFailure("storage_activation_digest")
	}
	routes, _ := get("route_selection").ByteString()
	if f.Source == "live_authority" {
		candidate, _ := get("candidate_selection").ByteString()
		if !bytes.Equal(candidate, f.Candidate[:]) || !bytes.Equal(routes, f.Route[:]) || f.Budget != (PoolAttemptLimits{}) || f.CandidateSet != ([32]byte{}) || f.RouteSet != ([32]byte{}) || f.WinnerAuthority != "" {
			return CBORFailure("storage_activation_selection")
		}
		return nil
	}
	selection := get("candidate_selection")
	set, _ := selection.Named("PoolSelectionRef", "candidate_set_digest").ByteString()
	var indices [16]uint64
	n, ok := selection.Named("PoolSelectionRef", "candidate_indices").CopyUints(indices[:])
	if !ok {
		return CBORFailure("storage_activation_selection")
	}
	found := false
	for _, index := range indices[:n] {
		found = found || index == f.CandidateIndex
	}
	once := selection.Named("PoolSelectionRef", "once_authority_ref")
	winner, _ := once.Named("OnceAuthorityRef", "winner_authority_id").Text()
	spend, _ := once.Named("OnceAuthorityRef", "spend_authority_id").Text()
	budget := selection.Named("PoolSelectionRef", "attempt_budget")
	per := budget.Named("PoolAttemptBudget", "per_candidate")
	want := PoolAttemptLimits{valueUint(per, "CandidateAttemptBudget", "address_attempts"), valueUint(per, "CandidateAttemptBudget", "preauth_bytes"), valueUint(per, "CandidateAttemptBudget", "work_units"), valueUint(budget, "PoolAttemptBudget", "total_address_attempts"), valueUint(budget, "PoolAttemptBudget", "total_preauth_bytes"), valueUint(budget, "PoolAttemptBudget", "total_work_units"), valueUint(budget, "PoolAttemptBudget", "parallel_candidates")}
	if !found || !bytes.Equal(set, f.CandidateSet[:]) || !bytes.Equal(routes, f.RouteSet[:]) || winner != f.WinnerAuthority || spend != f.SpendAuthority || want != f.Budget {
		return CBORFailure("storage_activation_selection")
	}
	return nil
}

func (d *StorageFactsDecoder) CheckRelayParent(wire []byte, f AdmissionFields) error {
	doc, err := d.decoder.DecodeMap(wire, "GrantParentRef", DecodeContext{})
	if err != nil {
		return err
	}
	defer doc.Release()
	root := doc.Root()
	for _, pair := range []struct {
		name string
		want []byte
	}{{"artifact_issuer_key_id", f.Issuer[:]}, {"lease_id", f.Lease[:]}, {"artifact_digest", f.Artifact[:]}} {
		got, _ := root.Named("GrantParentRef", pair.name).ByteString()
		if !bytes.Equal(got, pair.want) {
			return CBORFailure("storage_parent_binding")
		}
	}
	if trustText(root, "GrantParentRef", "tenant_id") != f.Tenant || valueUint(root, "GrantParentRef", "issued_at_ms") > f.IssuedAt || valueUint(root, "GrantParentRef", "initiation_not_after_ms") < f.ActivationEnd || valueUint(root, "GrantParentRef", "session_not_after_ms") < f.SessionEnd {
		return CBORFailure("storage_parent_binding")
	}
	return nil
}

// CheckRelayGrant checks the exact original root, side and selected route. It
// deliberately does not manufacture a RelayClaimFacts possession capability.
func (d *StorageFactsDecoder) CheckRelayGrant(wire, parent []byte, f AdmissionFields, service, audience string, pairing [16]byte, relay, contract [32]byte, side, deadline uint64) error {
	doc, err := d.decoder.DecodeMap(wire, "Grant", DecodeContext{})
	if err != nil {
		return err
	}
	defer doc.Release()
	root := doc.Root()
	get := func(name string) Value { return root.Named("Grant", name) }
	if side > 1 || !bytes.Equal(get("parent_ref").Encoded(), parent) || trustText(root, "Grant", "tenant_id") != f.Tenant || trustText(root, "Grant", "service") != service || trustText(root, "Grant", "audience") != audience || valueUint(root, "Grant", "issued_at_ms") >= deadline || deadline > valueUint(root, "Grant", "not_after_ms") {
		return CBORFailure("storage_grant_binding")
	}
	for _, pair := range []struct {
		name string
		want []byte
	}{{"pairing_id", pairing[:]}, {"attempt_id", f.Attempt[:]}, {"relay_identity_digest", relay[:]}, {"session_contract_digest", contract[:]}} {
		got, _ := get(pair.name).ByteString()
		if !bytes.Equal(got, pair.want) {
			return CBORFailure("storage_grant_binding")
		}
	}
	identities := get("identity_digests")
	client, _ := identities.Index(0).ByteString()
	server, _ := identities.Index(1).ByteString()
	route := get("route_descriptor")
	candidate, _ := route.Named("Route", "candidate_id").ByteString()
	digest, err := fullMapDigest("route_digest", "Route", route.Encoded())
	if err != nil || digest != f.Route || !bytes.Equal(candidate, f.Candidate[:]) || !bytes.Equal(client, f.ClientIdentity[:]) || !bytes.Equal(server, f.ServerIdentity[:]) || valueUint(get("namespace"), "GrantNamespace", "role_mask") != 4|(1<<side) {
		return CBORFailure("storage_grant_binding")
	}
	return nil
}

// InspectRelayRecord returns only a lookup key after inspecting the retained
// JSON and canonical embedded public maps. It cannot restore issuance rights.
func (d *StorageFactsDecoder) InspectRelayRecord(wire []byte) (RelayParentKey, error) {
	var key RelayParentKey
	if len(wire) == 0 || len(wire) > RelayParentRecordMaxBytes {
		return key, CBORFailure("storage_relay_record")
	}
	var r relayParentRecord
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&r); err != nil {
		return key, err
	}
	canonical, err := json.Marshal(r)
	if err != nil || r.Revision != 1 || !bytes.Equal(canonical, wire) {
		return key, CBORFailure("storage_relay_record")
	}
	f, p := r.Activation, r.Parent
	s := p.Scope
	if f.Source != "live_authority" && f.Source != "preauthorized_pool" || f.Winner.Index >= 16 || f.IssuedAt >= f.ActivationEnd || f.ActivationEnd > f.SessionEnd ||
		s.Schema != "Artifact" || s.Tenant != f.Tenant || s.Audience != f.Audience || s.Profile != f.Profile || s.Issuer != f.Issuer || p.Lease != f.Lease || p.Facts.Digest != f.Artifact || p.Key != f.ArtifactKey || s.Cohort != p.Facts.Cohort || s.ExpiresMS != p.Facts.HardDeadlineMS || s.IssuedMS > f.IssuedAt || p.AdmissionEnd < f.ActivationEnd || s.ExpiresMS < f.SessionEnd ||
		f.Authority != r.Trust.SpendAuthority || f.SigningKey != r.Trust.SigningKeyID || f.ProofKey != r.Trust.Key || f.Tenant != r.Trust.Tenant || f.Issuer != r.Trust.ParentIssuer {
		return key, CBORFailure("storage_relay_binding")
	}
	facts := StoredActivationFacts{AdmissionFields: AdmissionFields{Source: f.Source, Tenant: f.Tenant, Audience: f.Audience, Profile: f.Profile, SpendAuthority: f.Authority, WinnerAuthority: f.WinnerAuthority, SigningKey: f.SigningKey, Issuer: f.Issuer, Lease: f.Lease, Attempt: f.Attempt, Candidate: f.Winner.CandidateID, CandidateIndex: f.Winner.Index, Artifact: f.Artifact, Proof: f.Proof, ClientIdentity: f.Client, ServerIdentity: f.Server, Route: f.Winner.RouteDigest, CandidateSet: f.CandidateSet, IssuedAt: f.IssuedAt, ActivationEnd: f.ActivationEnd, SessionEnd: f.SessionEnd}, Budget: f.Budget, RouteSet: f.RouteSet}
	if err := d.CheckActivation(r.Proof, facts); err != nil {
		return key, err
	}
	for _, part := range []struct {
		schema string
		wire   []byte
	}{{"ConnectionActivationDelegation", r.Delegation}, {"OnceAuthorityRef", r.Authority}} {
		doc, err := d.decoder.DecodeMap(part.wire, part.schema, DecodeContext{})
		if err != nil {
			return key, err
		}
		doc.Release()
	}
	digest, err := fullMapDigest("connection_activation_delegation_digest", "ConnectionActivationDelegation", r.Delegation)
	if err != nil || digest != r.Trust.DelegationDigest {
		return key, CBORFailure("storage_relay_binding")
	}
	var pairing [16]byte
	var contract [32]byte
	var parent []byte
	for side, original := range r.GrantBytes {
		doc, err := d.decoder.DecodeMap(original, "Grant", DecodeContext{})
		if err != nil {
			return key, err
		}
		root := doc.Root()
		get := func(name string) Value { return root.Named("Grant", name) }
		g, ns := r.Grants[side], get("namespace")
		if side == 0 {
			pairing, contract = trust16(root, "Grant", "pairing_id"), trust32(root, "Grant", "session_contract_digest")
			parent = bytes.Clone(get("parent_ref").Encoded())
		}
		digest, digestErr := credentialDocumentDigest("grant_digest", "Grant", doc, *d.decoder.registry.Maps["Grant"].SignatureField, d.scratch[:])
		valid := digestErr == nil && digest == g.Facts.Digest && g.Scope.Schema == "Grant" && g.Scope.Tenant == f.Tenant && g.Scope.Audience == trustText(root, "Grant", "audience") && g.Scope.Service == trustText(root, "Grant", "service") && g.Scope.Issuer == trust16(root, "Grant", "issuer_key_id") && g.Scope.Authority == trustText(ns, "GrantNamespace", "revocation_authority_id") && g.Scope.CapacityDigest == trust32(ns, "GrantNamespace", "namespace_capacity_digest") && g.Scope.Generation == valueUint(ns, "GrantNamespace", "generation") && g.Scope.Cohort == valueUint(ns, "GrantNamespace", "revocation_epoch") && g.Scope.Role == 4|(1<<side) && g.Scope.IssuedMS == valueUint(root, "Grant", "issued_at_ms") && g.Scope.ExpiresMS == valueUint(root, "Grant", "not_after_ms") && g.Facts.Cohort == g.Scope.Cohort && g.Facts.HardDeadlineMS == g.Scope.ExpiresMS && g.Facts.PolicyID == trustText(ns, "GrantNamespace", "revocation_policy_id") && g.Facts.PolicyRevision == valueUint(ns, "GrantNamespace", "revocation_policy_revision") && sha256.Sum256(get("parent_ref").Encoded()) == r.ParentReference
		doc.Release()
		if !valid {
			return key, CBORFailure("storage_relay_grant")
		}
		if err := d.CheckRelayGrant(original, parent, facts.AdmissionFields, g.Scope.Service, g.Scope.Audience, pairing, r.RelayIdentity, contract, uint64(side), g.Scope.ExpiresMS); err != nil {
			return key, err
		}
	}
	if err := d.CheckRelayParent(parent, facts.AdmissionFields); err != nil {
		return key, err
	}
	return RelayParentKey{Tenant: f.Tenant, Issuer: f.Issuer, Lease: f.Lease, Candidate: f.Winner.CandidateID, Attempt: f.Attempt}, nil
}

// StoredDirectIssuePolicy contains only immutable facts needed to check local
// obligations. Its fields confer no independent trust or signing permission.
type StoredDirectIssuePolicy struct {
	Scope                                                        CredentialScope
	PolicyID                                                     string
	PolicyRevision                                               uint64
	StateBytes, Leases, Segments, Origin, Duration, Impact       uint64
	SigningStart, SigningEnd, FirstCohort, LastCohort, MaxExpiry uint64
}

func (d *StorageFactsDecoder) InspectDirectIssuePolicy(parts [4][]byte) (p StoredDirectIssuePolicy, err error) {
	for i, schema := range []string{"NamespaceCapacity", "PublicationPolicy", "CredentialIssuerAuthorization", "CredentialRevocationPolicy"} {
		doc, err := d.decoder.DecodeMap(parts[i], schema, DecodeContext{})
		if err != nil {
			return p, err
		}
		root := doc.Root()
		switch i {
		case 0:
			p.Scope.Tenant, p.Scope.Authority = trustText(root, schema, "tenant_id"), trustText(root, schema, "revocation_authority_id")
			p.Scope.CapacityDigest, err = fullMapDigest("namespace_capacity_digest", schema, parts[i])
			p.StateBytes, p.Leases, p.Segments = valueUint(root, schema, "max_state_encoded_bytes"), valueUint(root, schema, "max_revoked_leases"), valueUint(root, schema, "max_cohort_policy_segments")
			p.Origin, p.Duration, p.Impact = valueUint(root, schema, "cohort_time_origin_ms"), valueUint(root, schema, "cohort_duration_ms"), valueUint(root, schema, "max_connection_impact_ms")
		case 2:
			if valueUint(root, schema, "credential_kind") != 1 || trustText(root, schema, "tenant_id") != p.Scope.Tenant || trustText(root, schema, "revocation_authority_id") != p.Scope.Authority || trust32(root, schema, "namespace_capacity_digest") != p.Scope.CapacityDigest {
				err = CBORFailure("storage_issue_policy")
			}
			p.Scope.Schema, p.Scope.Audience, p.Scope.Profile = "Artifact", trustText(root, schema, "audience"), trustText(root, schema, "crypto_profile_id")
			p.Scope.Generation, p.Scope.Issuer = valueUint(root, schema, "authority_generation"), trust16(root, schema, "issuer_key_id")
			p.SigningStart, p.SigningEnd = valueUint(root, schema, "signing_not_before_ms"), valueUint(root, schema, "signing_not_after_ms")
			p.FirstCohort, p.LastCohort, p.MaxExpiry = valueUint(root, schema, "first_cohort"), valueUint(root, schema, "last_cohort"), valueUint(root, schema, "max_credential_not_after_ms")
		case 3:
			p.PolicyID, p.PolicyRevision = trustText(root, schema, "revocation_policy_id"), valueUint(root, schema, "revocation_policy_revision")
		}
		doc.Release()
		if err != nil {
			return p, err
		}
	}
	return p, nil
}

func (d *StorageFactsDecoder) CheckDirectIssue(p StoredDirectIssuePolicy, f DirectIssueFacts, segment []byte) error {
	scope := f.Scope
	scope.Cohort, scope.IssuedMS, scope.ExpiresMS = 0, 0, 0
	if scope != p.Scope || f.LeaseID == ([16]byte{}) || f.ClientIdentity == ([32]byte{}) || f.ServerIdentity == ([32]byte{}) || f.ClientIdentity == f.ServerIdentity || f.RevocationPolicyID != p.PolicyID || f.RevocationPolicyRevision != p.PolicyRevision || f.Scope.IssuedMS >= f.InitiationNotAfterMS || f.InitiationNotAfterMS > f.Scope.ExpiresMS || f.Scope.Cohort < p.FirstCohort || f.Scope.Cohort > p.LastCohort || f.Scope.ExpiresMS > p.MaxExpiry || f.Scope.IssuedMS < p.SigningStart || f.Scope.IssuedMS >= p.SigningEnd || p.Duration == 0 || f.Scope.Cohort == math.MaxUint64 || f.Scope.Cohort+1 > (math.MaxUint64-p.Origin)/p.Duration {
		return CBORFailure("storage_issue_binding")
	}
	end := p.Origin + (f.Scope.Cohort+1)*p.Duration
	if f.Scope.IssuedMS < end-p.Duration || f.Scope.IssuedMS >= end || p.Impact > math.MaxUint64-end || f.Scope.ExpiresMS > end+p.Impact {
		return CBORFailure("storage_issue_time")
	}
	doc, err := d.decoder.DecodeMap(segment, "CohortPolicySegment", DecodeContext{})
	if err != nil {
		return err
	}
	defer doc.Release()
	root := doc.Root()
	impact, ok := root.Named("CohortPolicySegment", "connection_impact_ms").Uint()
	if !ok || impact > p.Impact || valueUint(root, "CohortPolicySegment", "first_cohort") > f.Scope.Cohort || valueUint(root, "CohortPolicySegment", "last_cohort") < f.Scope.Cohort || impact > math.MaxUint64-end || f.Scope.ExpiresMS > end+impact {
		return CBORFailure("storage_issue_segment")
	}
	return nil
}
