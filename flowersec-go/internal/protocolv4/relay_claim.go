package protocolv4

import (
	"bytes"
	"crypto/sha256"
	"strings"
	"unsafe"
)

// RelayClaimFacts contains only public, signed grant facts and the verified
// endpoint possession proof. It never contains an Artifact or Session secret.
// Independent trust, parent issuance, namespace freshness, actual transport
// binding and the once-authority mapping remain mandatory claim gates.
type RelayClaimFacts struct {
	fields        RelayClaimFields
	grant, parent []byte
	valid         bool
}

type RelayGrantLimits struct {
	EnvelopeBytes, TotalBytes, DatagramBytes, RateBytesPerSecond             uint64
	QueueBytes, PendingMappings, ResidentMappings, TotalMappings, QueueItems uint64
}

type RelayClaimFields struct {
	Tenant, Audience, EndpointAudience, Profile, Service                      string
	ParentAuthority, ParentPolicy                                             string
	Issuer, Lease, Attempt, Candidate, Pairing, Leg, GrantID                  [16]byte
	Artifact, Route, Contract, ClientIdentity, ServerIdentity, RelayIdentity  [32]byte
	Grant, ParentReference, Possession, Challenge, ParentCapacity             [32]byte
	ParentGeneration, ParentCohort, ParentPolicyRevision                      uint64
	ParentIssuedAt, ParentInitiationEnd, ParentSessionEnd, IssuedAt, NotAfter uint64
	EndpointRole                                                              Direction
	RelayIncarnation                                                          [16]byte
	Limits                                                                    RelayGrantLimits
}

func RelayClaimFactsBackingBytes() (uint64, error) {
	grant, err := SchemaByteLimit("Grant")
	if err != nil {
		return 0, err
	}
	return uint64(unsafe.Sizeof(RelayClaimFacts{})) + 4*uint64(grant), nil
}

// BindRelayClaim verifies the endpoint certificate and role against the exact
// issued Grant and the challenge from this physical hop. It cannot be built
// from detached caller fields, a readback row, or a self-reported grant digest.
func BindRelayClaim(grant, endpoint, relay *SignedMap, challenge HopChallengeContext, proof HopAuthProof) (RelayClaimFacts, error) {
	var result RelayClaimFacts
	if grant == nil || endpoint == nil || relay == nil || proof.Phase != HopAuthEndpointProofPhase {
		return result, ErrHopAuthContext
	}
	g, err := grant.DetachCredential()
	if err != nil {
		return result, err
	}
	e, err := endpoint.DetachCredential()
	if err != nil {
		return result, err
	}
	r, err := relay.DetachCredential()
	if err != nil {
		return result, err
	}
	role := e.scope.Role
	if g.scope.Schema != "Grant" || e.scope.Schema != "IdentityCertificate" || r.scope.Schema != "IdentityCertificate" || role > 1 || r.scope.Role != 2 || g.scope.Role != 4|(1<<role) || g.scope.Tenant != e.scope.Tenant || g.scope.Tenant != r.scope.Tenant || g.scope.Audience != r.scope.Audience || e.scope.Profile != r.scope.Profile {
		return result, ErrHopAuthContext
	}
	var contextBytes [129]byte
	wire, err := EncodeHopChallengeContext(contextBytes[:], challenge)
	if err != nil {
		return result, err
	}
	c := grant.codec
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.current != grant {
		return result, CBORFailure("document_released")
	}
	root := grant.document.Root()
	get := func(name string) Value { return root.Named("Grant", name) }
	read16 := func(value Value) [16]byte { b, _ := value.ByteString(); return [16]byte(b) }
	read32 := func(value Value) [32]byte { b, _ := value.ByteString(); return [32]byte(b) }
	parent, route := get("parent_ref"), get("route_descriptor")
	legName := "client_leg"
	if role == 1 {
		legName = "server_leg"
	}
	leg := route.Named("Route", legName)
	if challenge.LegID != read16(leg.Named("Leg", "leg_id")) || uint64(challenge.DialerRole) != valueUint(leg, "Leg", "dialer_role") || uint64(challenge.ListenerRole) != valueUint(leg, "Leg", "listener_role") || !(challenge.DialerRole == 2 && uint64(challenge.ListenerRole) == role || challenge.ListenerRole == 2 && uint64(challenge.DialerRole) == role) {
		return result, ErrHopAuthContext
	}
	identities := get("identity_digests")
	if read32(identities.Index(int(role))) != e.facts.Digest || read32(get("relay_identity_digest")) != r.facts.Digest {
		return result, ErrHopAuthContext
	}
	key, ok := endpoint.Field("ed25519_public_key").ByteString()
	if !ok || len(key) != 32 {
		return result, ErrHopAuthContext
	}
	input := GrantPossessionInput{GrantDigest: g.facts.Digest, RouteDigest: read32(get("route_digest")), LegID: challenge.LegID, PairingID: read16(get("pairing_id")), Role: uint8(role), HopContext: wire}
	if err = VerifyGrantPossession(input, [32]byte(key), proof.Proof); err != nil {
		return result, err
	}
	text := func(name string) string { s, _ := parent.Named("GrantParentRef", name).Text(); return strings.Clone(s) }
	f := RelayClaimFields{Tenant: strings.Clone(g.scope.Tenant), Audience: strings.Clone(g.scope.Audience), EndpointAudience: strings.Clone(e.scope.Audience), Profile: strings.Clone(e.scope.Profile), Service: strings.Clone(g.scope.Service), ParentAuthority: text("revocation_authority_id"), ParentPolicy: text("revocation_policy_id"),
		Issuer: read16(parent.Named("GrantParentRef", "artifact_issuer_key_id")), Lease: read16(parent.Named("GrantParentRef", "lease_id")), Artifact: read32(parent.Named("GrantParentRef", "artifact_digest")), ParentCapacity: read32(parent.Named("GrantParentRef", "namespace_capacity_digest")),
		Attempt: read16(get("attempt_id")), Candidate: read16(route.Named("Route", "candidate_id")), Pairing: input.PairingID, Leg: input.LegID, GrantID: read16(get("grant_id")), Route: input.RouteDigest, Contract: read32(get("session_contract_digest")),
		ClientIdentity: read32(identities.Index(0)), ServerIdentity: read32(identities.Index(1)), RelayIdentity: r.facts.Digest, Grant: g.facts.Digest,
		ParentReference: sha256.Sum256(parent.Encoded()), Possession: sha256.Sum256(proof.Proof[:]), Challenge: sha256.Sum256(wire),
		ParentGeneration: valueUint(parent, "GrantParentRef", "authority_generation"), ParentCohort: valueUint(parent, "GrantParentRef", "revocation_epoch"), ParentPolicyRevision: valueUint(parent, "GrantParentRef", "revocation_policy_revision"),
		ParentIssuedAt: valueUint(parent, "GrantParentRef", "issued_at_ms"), ParentInitiationEnd: valueUint(parent, "GrantParentRef", "initiation_not_after_ms"), ParentSessionEnd: valueUint(parent, "GrantParentRef", "session_not_after_ms"),
		IssuedAt: g.scope.IssuedMS, NotAfter: g.scope.ExpiresMS, EndpointRole: Direction(role)}
	f.RelayIncarnation = challenge.ListenerIncarnation
	if challenge.DialerRole == 2 {
		f.RelayIncarnation = challenge.DialerIncarnation
	}
	limits := get("limits")
	for i, ptr := range []*uint64{&f.Limits.EnvelopeBytes, &f.Limits.TotalBytes, &f.Limits.DatagramBytes, &f.Limits.RateBytesPerSecond, &f.Limits.QueueBytes, &f.Limits.PendingMappings, &f.Limits.ResidentMappings, &f.Limits.TotalMappings, &f.Limits.QueueItems} {
		*ptr = valueUint(limits, "GrantLimits", []string{"max_envelope_bytes", "max_total_bytes", "max_datagram_bytes", "max_rate_bytes_per_s", "max_queue_bytes", "max_pending_native_mappings", "max_resident_native_mappings", "max_total_native_mappings", "max_queue_items"}[i])
	}
	result.fields, result.valid = f, true
	result.grant, result.parent = bytes.Clone(grant.document.Bytes()), bytes.Clone(parent.Encoded())
	return result, nil
}

func (f RelayClaimFacts) Fields() (RelayClaimFields, error) {
	if !f.valid {
		return RelayClaimFields{}, ErrHopAuthContext
	}
	return f.fields, nil
}

func (f RelayClaimFacts) CopyGrant(dst []byte) (int, error) {
	if !f.valid || len(dst) < len(f.grant) {
		return 0, ErrHopAuthContext
	}
	return copy(dst, f.grant), nil
}

func (f RelayClaimFacts) CopyParentReference(dst []byte) (int, error) {
	if !f.valid || len(dst) < len(f.parent) {
		return 0, ErrHopAuthContext
	}
	return copy(dst, f.parent), nil
}

// Clone retains only public claim evidence. Its backing is charged separately
// when a durable invocation outlives the caller's original decoder/material.
func (f RelayClaimFacts) Clone() RelayClaimFacts {
	if !f.valid {
		return RelayClaimFacts{}
	}
	f.grant, f.parent = bytes.Clone(f.grant), bytes.Clone(f.parent)
	for _, v := range []*string{&f.fields.Tenant, &f.fields.Audience, &f.fields.EndpointAudience, &f.fields.Profile, &f.fields.Service, &f.fields.ParentAuthority, &f.fields.ParentPolicy} {
		*v = strings.Clone(*v)
	}
	return f
}
