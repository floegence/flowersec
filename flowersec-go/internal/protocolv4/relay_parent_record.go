package protocolv4

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

// RelayParentRecordMaxBytes bounds a local durable public record, not an L0
// credential. Its provenance must be the authenticated original issuance
// receipt. Decoding these bytes alone never proves that issuance committed.
const RelayParentRecordMaxBytes = 65536

type relayCredentialRecord struct {
	Scope        CredentialScope
	Key          [32]byte
	Facts        CredentialStateFacts
	Lease        [16]byte
	AdmissionEnd uint64
}

type relayActivationRecord struct {
	Tenant, Audience, Authority, SigningKey, Profile, Source string
	Issuer, Lease, Attempt                                   [16]byte
	Artifact, Proof, Client, Server, ArtifactKey, ProofKey   [32]byte
	Winner                                                   PoolMember
	IssuedAt, ActivationEnd, SessionEnd                      uint64
	Budget                                                   PoolAttemptLimits
	WinnerAuthority                                          string
	CandidateSet, RouteSet                                   [32]byte
}

type relayParentRecord struct {
	Revision                       uint32
	Parent                         relayCredentialRecord
	Grants                         [2]relayCredentialRecord
	Activation                     relayActivationRecord
	Trust                          ActivationTrustBinding
	Delegation, Authority          []byte
	ParentReference, RelayIdentity [32]byte
	Proof                          []byte
	GrantBytes                     [2][]byte
}

func RelayParentRecordBackingBytes() (uint64, error) {
	n := uint64(unsafe.Sizeof(relayParentRecord{})) + 10*RelayParentRecordMaxBytes
	for _, schema := range []string{"Grant", "ActivationAuthorization"} {
		limit, err := SchemaByteLimit(schema)
		if err != nil {
			return 0, err
		}
		codec, err := SignedMapBackingBytes(schema, limit, limit)
		if err != nil {
			return 0, err
		}
		n += codec
	}
	return n, nil
}

func relayCredentialToRecord(c *Credential) relayCredentialRecord {
	return relayCredentialRecord{c.scope, c.key, c.facts, c.lease, c.admissionEnd}
}

func (r relayCredentialRecord) credential() *Credential {
	c := &Credential{scope: r.Scope, key: r.Key, facts: r.Facts, lease: r.Lease, admissionEnd: r.AdmissionEnd}
	c.facts.class = 1
	return c
}

func (p *RelayParentProjection) record() (relayParentRecord, error) {
	if _, err := p.Key(); err != nil {
		return relayParentRecord{}, err
	}
	if len(p.proof) == 0 || len(p.grantBytes[0]) == 0 || len(p.grantBytes[1]) == 0 {
		return relayParentRecord{}, ErrHopAuthContext
	}
	a, b := p.activation, p.activation.binding
	if b.sessionNonce != ([32]byte{}) {
		return relayParentRecord{}, ErrHopAuthContext
	}
	r := relayParentRecord{Revision: 1, Parent: relayCredentialToRecord(p.parent), Trust: a.trust,
		Delegation: a.delegation, Authority: a.authority, ParentReference: p.parentReference, RelayIdentity: p.relayIdentity,
		Proof: p.proof, GrantBytes: p.grantBytes,
		Activation: relayActivationRecord{b.tenant, b.audience, b.authority, b.signingKey, b.profile, b.source, b.issuer, b.lease, b.attempt,
			b.artifactDigest, b.proofDigest, b.clientDigest, b.serverDigest, b.artifactKey, b.proofKey, b.winner, b.issuedAt, b.activationEnd, b.sessionEnd, b.poolBudget, b.winnerAuthority, b.candidateSetDigest, b.routeSetDigest}}
	for side, g := range p.grants {
		r.Grants[side] = relayCredentialToRecord(g)
	}
	return r, nil
}

// CopyPublicRecord preserves exact original signed public material and the
// original checked facts. It contains no Artifact, PSK, Session nonce or owner.
// The enclosing record owner reserves RelayParentRecordBackingBytes first.
func (p *RelayParentProjection) CopyPublicRecord(dst []byte) (int, error) {
	r, err := p.record()
	if err != nil {
		return 0, err
	}
	wire, err := json.Marshal(r)
	if err != nil || len(wire) > RelayParentRecordMaxBytes || len(wire) > len(dst) {
		return 0, CBORFailure("encoder_capacity")
	}
	return copy(dst, wire), nil
}

// RestoreRelayParentProjection is for an independently trusted durable record
// owner only. The store must authenticate the source identities and original
// commit provenance before calling it. Restoring public facts never restores
// an issuance signer, publication guard, admission or relay claim handle.
func RestoreRelayParentProjection(wire []byte, mapping RelayIssuerMapping, parent CredentialValidation, environment resourcev4.Reference) (*RelayParentProjection, error) {
	if len(wire) == 0 || len(wire) > RelayParentRecordMaxBytes || parent.Namespace == nil {
		return nil, ErrHopAuthContext
	}
	var r relayParentRecord
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&r); err != nil {
		return nil, ErrHopAuthContext
	}
	canonical, err := json.Marshal(r)
	if err != nil || r.Revision != 1 || !bytes.Equal(canonical, wire) {
		return nil, ErrHopAuthContext
	}
	f := r.Activation
	if f.Source != "live_authority" && f.Source != "preauthorized_pool" || f.Winner.Index >= 16 || f.IssuedAt >= f.ActivationEnd || f.ActivationEnd > f.SessionEnd {
		return nil, ErrHopAuthContext
	}
	b := &ActivationBinding{tenant: f.Tenant, audience: f.Audience, authority: f.Authority, signingKey: f.SigningKey, profile: f.Profile, source: f.Source,
		issuer: f.Issuer, lease: f.Lease, attempt: f.Attempt, artifactDigest: f.Artifact, proofDigest: f.Proof, clientDigest: f.Client, serverDigest: f.Server,
		artifactKey: f.ArtifactKey, proofKey: f.ProofKey, winner: f.Winner, issuedAt: f.IssuedAt, activationEnd: f.ActivationEnd, sessionEnd: f.SessionEnd,
		poolBudget: f.Budget, winnerAuthority: f.WinnerAuthority, candidateSetDigest: f.CandidateSet, routeSetDigest: f.RouteSet}
	p := &RelayParentProjection{parent: r.Parent.credential(), parentReference: r.ParentReference, relayIdentity: r.RelayIdentity, proof: r.Proof, grantBytes: r.GrantBytes}
	s := p.parent.scope
	if s.Schema != "Artifact" || s.Tenant != b.tenant || s.Audience != b.audience || s.Profile != b.profile || s.Issuer != b.issuer || p.parent.lease != b.lease || p.parent.facts.Digest != b.artifactDigest || p.parent.key != b.artifactKey || s.Cohort != p.parent.facts.Cohort || s.ExpiresMS != p.parent.facts.HardDeadlineMS || s.IssuedMS > b.issuedAt || p.parent.admissionEnd < b.activationEnd || s.ExpiresMS < b.sessionEnd {
		return nil, ErrHopAuthContext
	}
	p.activation = &ActivationAuthority{rules: parent.Namespace.rules, binding: b, trust: r.Trust, delegation: r.Delegation, authority: r.Authority,
		parentCohort: s.Cohort, parentIssued: s.IssuedMS, parentActivation: p.parent.admissionEnd, parentEnd: s.ExpiresMS}
	if b.authority != r.Trust.SpendAuthority || b.signingKey != r.Trust.SigningKeyID || b.proofKey != r.Trust.Key || b.tenant != r.Trust.Tenant || b.issuer != r.Trust.ParentIssuer {
		return nil, ErrHopAuthContext
	}
	delegation, err := fullMapDigest("connection_activation_delegation_digest", "ConnectionActivationDelegation", r.Delegation)
	if err != nil || delegation != r.Trust.DelegationDigest {
		return nil, ErrHopAuthContext
	}
	for side, grant := range r.Grants {
		p.grants[side] = grant.credential()
	}
	if err = p.MatchMapping(mapping); err != nil {
		return nil, err
	}
	// Verify exact retained signatures independently of their stored digests.
	var pairing [16]byte
	var contract [32]byte
	for _, schema := range []string{"Grant", "ActivationAuthorization"} {
		limit, err := SchemaByteLimit(schema)
		if err != nil {
			return nil, err
		}
		codec, err := NewSignedMapCodec(schema, limit, limit)
		if err != nil {
			return nil, err
		}
		count := 2
		if schema == "ActivationAuthorization" {
			count = 1
		}
		for side := 0; side < count; side++ {
			original, key := p.proof, b.proofKey
			context := DecodeContext{Selectors: map[string]string{"activation_source_profile": b.source}}
			if schema == "Grant" {
				original, key, context = p.grantBytes[side], p.grants[side].key, DecodeContext{}
			}
			signed, err := codec.Verify(original, key, context)
			if err != nil {
				return nil, err
			}
			if schema == "Grant" {
				var credential *Credential
				credential, err = signed.DetachCredential()
				if err == nil && *credential != *p.grants[side] {
					err = ErrHopAuthContext
				}
				if err == nil {
					err = p.checkRecordedGrant(signed, side, &pairing, &contract)
				}
			} else {
				err = p.activation.MatchProofBytes(original)
				if err == nil {
					err = p.checkRecordedProof(signed)
				}
			}
			signed.Release()
			if err != nil {
				return nil, err
			}
		}
	}
	if err = p.CheckCurrent(parent, environment); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *RelayParentProjection) checkRecordedGrant(grant *SignedMap, side int, pairing *[16]byte, contract *[32]byte) error {
	b := p.activation.binding
	root := grant.document.Root()
	get := func(name string) Value { return root.Named("Grant", name) }
	id, _ := get("pairing_id").ByteString()
	digest, _ := get("session_contract_digest").ByteString()
	if side == 0 {
		*pairing, *contract = [16]byte(id), [32]byte(digest)
	}
	if *pairing != [16]byte(id) || *contract != [32]byte(digest) || sha256.Sum256(get("parent_ref").Encoded()) != p.parentReference {
		return ErrHopAuthContext
	}
	route := get("route_descriptor")
	routeDigest, err := fullMapDigest("route_digest", "Route", route.Encoded())
	candidate, _ := route.Named("Route", "candidate_id").ByteString()
	if err != nil || routeDigest != b.winner.RouteDigest || !bytes.Equal(candidate, b.winner.CandidateID[:]) {
		return ErrHopAuthContext
	}
	envelope := valueUint(get("limits"), "GrantLimits", "max_envelope_bytes")
	if envelope < uint64(EnvelopePrefixSize) {
		return ErrHopAuthContext
	}
	// Recheck the public cross-object binding without reconstructing an
	// Artifact or manufacturing an endpoint credential/admission object.
	e := EndpointCredentials{role: Direction(side), selection: b.winner, credentials: [5]*Credential{
		p.parent, {facts: CredentialStateFacts{Digest: b.clientDigest}}, {facts: CredentialStateFacts{Digest: b.serverDigest}}, p.grants[side],
		{scope: CredentialScope{Schema: "IdentityCertificate", Role: 2, Tenant: b.tenant}, facts: CredentialStateFacts{Digest: p.relayIdentity}},
	}}
	if err = e.bindGrantFields(root, route.Encoded(), *contract, envelope-uint64(EnvelopePrefixSize)); err != nil {
		return err
	}
	if e.attempt != b.attempt {
		return ErrHopAuthContext
	}
	return nil
}

func (p *RelayParentProjection) checkRecordedProof(proof *SignedMap) error {
	b := p.activation.binding
	for _, pair := range []struct{ name, want string }{{"tenant_id", b.tenant}, {"authority_id", b.authority}, {"signing_key_id", b.signingKey}, {"audience", b.audience}} {
		got, _ := proof.Field(pair.name).Text()
		if got != pair.want {
			return ErrHopAuthContext
		}
	}
	for _, pair := range []struct {
		name string
		want []byte
	}{
		{"artifact_issuer_key_id", b.issuer[:]}, {"lease_id", b.lease[:]}, {"artifact_digest", b.artifactDigest[:]},
		{"attempt_id", b.attempt[:]}, {"client_identity_digest", b.clientDigest[:]}, {"server_identity_digest", b.serverDigest[:]},
	} {
		got, _ := proof.Field(pair.name).ByteString()
		if !bytes.Equal(got, pair.want) {
			return ErrHopAuthContext
		}
	}
	for _, pair := range []struct {
		name string
		want uint64
	}{{"issued_at_ms", b.issuedAt}, {"activation_not_after_ms", b.activationEnd}, {"session_not_after_ms", b.sessionEnd}} {
		got, _ := proof.Field(pair.name).Uint()
		if got != pair.want {
			return ErrHopAuthContext
		}
	}
	routes, _ := proof.Field("route_selection").ByteString()
	if b.source == "live_authority" {
		candidate, _ := proof.Field("candidate_selection").ByteString()
		if !bytes.Equal(candidate, b.winner.CandidateID[:]) || !bytes.Equal(routes, b.winner.RouteDigest[:]) || b.poolBudget != (PoolAttemptLimits{}) || b.candidateSetDigest != ([32]byte{}) || b.routeSetDigest != ([32]byte{}) {
			return ErrHopAuthContext
		}
		return nil
	}
	selection := proof.Field("candidate_selection")
	set, _ := selection.Named("PoolSelectionRef", "candidate_set_digest").ByteString()
	var indices [16]uint64
	n, ok := selection.Named("PoolSelectionRef", "candidate_indices").CopyUints(indices[:])
	if !ok {
		return ErrHopAuthContext
	}
	found := false
	for _, index := range indices[:n] {
		found = found || index == b.winner.Index
	}
	if !ok || !found || !bytes.Equal(set, b.candidateSetDigest[:]) || !bytes.Equal(routes, b.routeSetDigest[:]) || !bytes.Equal(selection.Named("PoolSelectionRef", "once_authority_ref").Encoded(), p.activation.authority) || b.winnerAuthority != p.activation.trust.WinnerAuthority {
		return ErrHopAuthContext
	}
	budget := selection.Named("PoolSelectionRef", "attempt_budget")
	perCandidate := budget.Named("PoolAttemptBudget", "per_candidate")
	want := PoolAttemptLimits{valueUint(perCandidate, "CandidateAttemptBudget", "address_attempts"), valueUint(perCandidate, "CandidateAttemptBudget", "preauth_bytes"), valueUint(perCandidate, "CandidateAttemptBudget", "work_units"),
		valueUint(budget, "PoolAttemptBudget", "total_address_attempts"), valueUint(budget, "PoolAttemptBudget", "total_preauth_bytes"), valueUint(budget, "PoolAttemptBudget", "total_work_units"), valueUint(budget, "PoolAttemptBudget", "parallel_candidates")}
	if want != b.poolBudget {
		return ErrHopAuthContext
	}
	return nil
}
