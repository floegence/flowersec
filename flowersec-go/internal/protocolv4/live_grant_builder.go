package protocolv4

import (
	"bytes"
	"crypto/rand"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

// LiveGrantPreparationConfig is the authority's fixed issuance envelope. The
// Grant namespace, issuer, cohort and parent association are derived from the
// independent validation owner and the verified parent, not supplied as wire
// fields. Both preparation and original TxA use this exact resulting scope.
type LiveGrantPreparationConfig struct {
	Service, Audience    string
	IssuedAt, NotAfterMS uint64
}

func DeriveLiveGrantPreparation(parent *Credential, role Direction, validation CredentialValidation, c LiveGrantPreparationConfig, environment resourcev4.Reference) (LiveGrantPreparation, error) {
	var result LiveGrantPreparation
	n := validation.Namespace
	if parent == nil || parent.scope.Schema != "Artifact" || role > ServerToClient || n == nil || validation.Policy == nil || c.IssuedAt < parent.scope.IssuedMS || c.NotAfterMS > parent.scope.ExpiresMS {
		return result, CBORFailure("credential_grant_preparation")
	}
	if err := n.reservation.CheckSameEnvironment(environment); err != nil {
		return result, err
	}
	n.mu.Lock()
	r := n.rules
	if err := n.checkAvailable(); err != nil {
		n.mu.Unlock()
		return result, err
	}
	if r == nil || r.duration == 0 || c.IssuedAt < r.origin || parent.scope.Tenant != r.tenant {
		n.mu.Unlock()
		return result, CBORFailure("credential_grant_preparation")
	}
	result = LiveGrantPreparation{Validation: validation, Scope: CredentialScope{
		Schema: "Grant", Tenant: r.tenant, Authority: r.authority, CapacityDigest: r.capacityDigest,
		Issuer: validation.Issuer.Issuer, Generation: n.observed.generation, Cohort: (c.IssuedAt - r.origin) / r.duration,
		IssuedMS: c.IssuedAt, ExpiresMS: c.NotAfterMS, Role: 4 | 1<<uint64(role), Service: c.Service, Audience: c.Audience,
		ParentIssuer: parent.scope.Issuer, ParentAuthority: parent.scope.Authority, ParentCapacityDigest: parent.scope.CapacityDigest,
		ParentGeneration: parent.scope.Generation, ParentCohort: parent.scope.Cohort,
	}}
	n.mu.Unlock()
	if _, err := result.Check(c.NotAfterMS, environment); err != nil {
		return LiveGrantPreparation{}, err
	}
	return result, nil
}

// LiveGrantIssuance stays at the trusted authority. Its Preparation is also the
// public, non-credential expectation supplied to the endpoint. EnvelopeBytes
// may be zero to request derivation; a nonzero value must match the signed
// SessionContract. All other limits remain explicit independent relay policy.
type LiveGrantIssuance struct {
	Preparation LiveGrantPreparation
	Limits      RelayGrantLimits
	Signer      MapSigner
}

// All temporary encoding storage belongs to the containing activation plan's
// reservation. The builder never signs, publishes a SignedMap or retains a
// secret-bearing Artifact. Only the selected signed route is copied.
type liveGrantBuilder struct {
	parent                 *Credential
	fields                 LiveActivationFields
	identity               [2][32]byte
	relay, contract        [32]byte
	pairing                [16]byte
	ids                    [2][16]byte
	nonces                 [2][32]byte
	maxEnvelope            uint64
	backing                []byte
	route, parentRef, legs []byte
	identities, ns, limits []byte
	projectionFields       [19]Field
}

func liveGrantBuilderBackingBytes(limit int) uint64 {
	return uint64(unsafe.Sizeof(liveGrantBuilder{})) + 6*uint64(limit) + 8192
}

func newLiveGrantBuilder(artifact *SignedMap, fields LiveActivationFields, c *LiveTunnelActivationConfig, environment resourcev4.Reference) (_ *liveGrantBuilder, err error) {
	parent, err := artifact.DetachCredential()
	if err != nil {
		return nil, err
	}
	for side, input := range c.Issuance {
		p := input.Preparation
		if input.Signer == nil || p.Validation != c.Bindings[3+side*2] || p.Scope.Role != 4|1<<uint64(side) || p.Scope.IssuedMS != fields.IssuedAt || p.Scope.ExpiresMS < fields.ActivationEnd || p.Scope.ExpiresMS > fields.SessionEnd || !bytes.Equal(input.Signer.PublicKey(), p.Validation.Issuer.Key[:]) {
			return nil, CBORFailure("activation_grant_projection")
		}
		if _, err = p.Check(fields.SessionEnd, environment); err != nil {
			return nil, err
		}
	}
	if c.Issuance[0].Preparation.Scope.Service != c.Issuance[1].Preparation.Scope.Service || c.Issuance[0].Preparation.Scope.Audience != c.Issuance[1].Preparation.Scope.Audience {
		return nil, CBORFailure("activation_grant_projection")
	}
	relay, err := c.Relay.DetachCredential()
	if err != nil {
		return nil, err
	}
	if relay.scope.Schema != "IdentityCertificate" || relay.scope.Role != 2 || relay.scope.Tenant != parent.scope.Tenant || relay.scope.Profile != parent.scope.Profile || relay.scope.Audience != c.Issuance[0].Preparation.Scope.Audience {
		return nil, CBORFailure("credential_grant_identity")
	}
	limit, err := SchemaByteLimit("Grant")
	if err != nil {
		return nil, err
	}
	b := &liveGrantBuilder{parent: parent, fields: fields, identity: [2][32]byte{fields.ClientIdentity, fields.ServerIdentity}, relay: relay.facts.Digest, backing: make([]byte, 6*limit)}
	adopted := false
	defer func() {
		if !adopted {
			b.close()
		}
	}()
	b.route, b.parentRef, b.legs = b.backing[:limit:limit], b.backing[limit:2*limit:2*limit], b.backing[2*limit:3*limit:3*limit]
	b.identities, b.ns, b.limits = b.backing[3*limit:4*limit:4*limit], b.backing[4*limit:5*limit:5*limit], b.backing[5*limit:6*limit:6*limit]
	b.route, _, err = artifact.CopyCandidateRoute(fields.Winner.Index, b.route)
	if err != nil {
		return nil, err
	}
	codec := artifact.codec
	codec.mu.Lock()
	if codec.current != artifact {
		codec.mu.Unlock()
		return nil, CBORFailure("artifact_owner")
	}
	root := artifact.document.Root()
	contract := root.Named("Artifact", "session_contract")
	b.maxEnvelope, err = namespaceAdd(valueUint(contract, "SessionContract", "max_frame"), uint64(EnvelopePrefixSize))
	if err == nil {
		b.contract, err = fullMapDigest("session_contract_digest", "SessionContract", contract.Encoded())
	}
	if err == nil {
		b.legs[0] = 0x82
		n := 1
		candidate := root.Named("Artifact", "candidates").Index(int(fields.Winner.Index))
		for side, name := range []string{"client_leg", "server_leg"} {
			id, _ := candidate.Named("Candidate", name).Named("Leg", "leg_id").ByteString()
			var wire []byte
			wire, err = EncodeMap(b.legs[n:], "GrantLegRef", []Field{{Name: "leg_id", Kind: ByteString, Bytes: id}, {Name: "logical_role", Number: uint64(side)}})
			if err != nil {
				break
			}
			n += len(wire)
		}
		b.legs = b.legs[:n:n]
	}
	codec.mu.Unlock()
	if err != nil {
		return nil, err
	}
	p := parent.scope
	b.parentRef, err = EncodeMap(b.parentRef, "GrantParentRef", []Field{
		{Name: "tenant_id", Kind: TextString, Text: p.Tenant}, {Name: "revocation_authority_id", Kind: TextString, Text: p.Authority},
		{Name: "authority_generation", Number: p.Generation}, {Name: "namespace_capacity_digest", Kind: ByteString, Bytes: p.CapacityDigest[:]},
		{Name: "revocation_policy_id", Kind: TextString, Text: parent.facts.PolicyID}, {Name: "revocation_policy_revision", Number: parent.facts.PolicyRevision},
		{Name: "artifact_issuer_key_id", Kind: ByteString, Bytes: p.Issuer[:]}, {Name: "lease_id", Kind: ByteString, Bytes: parent.lease[:]},
		{Name: "revocation_epoch", Number: p.Cohort}, {Name: "issued_at_ms", Number: p.IssuedMS},
		{Name: "initiation_not_after_ms", Number: parent.admissionEnd}, {Name: "session_not_after_ms", Number: p.ExpiresMS}, {Name: "artifact_digest", Kind: ByteString, Bytes: parent.facts.Digest[:]},
	})
	if err != nil {
		return nil, err
	}
	b.identities[0] = 0x82
	n := 1
	for _, identity := range b.identity {
		b.identities[n], b.identities[n+1] = 0x58, 32
		n += 2 + copy(b.identities[n+2:], identity[:])
	}
	b.identities = b.identities[:n:n]
	for _, dst := range [][]byte{b.pairing[:], b.ids[0][:], b.ids[1][:], b.nonces[0][:], b.nonces[1][:]} {
		if _, err = rand.Read(dst); err != nil {
			return nil, err
		}
		var nonzero byte
		for _, v := range dst {
			nonzero |= v
		}
		if nonzero == 0 {
			return nil, CBORFailure("issuance_entropy")
		}
	}
	if b.ids[0] == b.ids[1] || b.nonces[0] == b.nonces[1] || b.pairing == fields.Attempt || b.pairing == parent.lease {
		return nil, CBORFailure("issuance_entropy")
	}
	adopted = true
	return b, nil
}

func (b *liveGrantBuilder) projection(side int, input LiveGrantIssuance) (LiveGrantProjection, error) {
	s := input.Preparation.Scope
	policy, revision := input.Preparation.Validation.Policy.Reference()
	ns, err := EncodeMap(b.ns, "GrantNamespace", []Field{
		{Name: "tenant_id", Kind: TextString, Text: s.Tenant}, {Name: "revocation_authority_id", Kind: TextString, Text: s.Authority}, {Name: "generation", Number: s.Generation},
		{Name: "namespace_capacity_digest", Kind: ByteString, Bytes: s.CapacityDigest[:]}, {Name: "role_mask", Number: s.Role}, {Name: "revocation_epoch", Number: s.Cohort},
		{Name: "revocation_policy_id", Kind: TextString, Text: policy}, {Name: "revocation_policy_revision", Number: revision},
	})
	if err != nil {
		return LiveGrantProjection{}, err
	}
	l := input.Limits
	if l.EnvelopeBytes != 0 && l.EnvelopeBytes != b.maxEnvelope {
		return LiveGrantProjection{}, CBORFailure("credential_grant_route")
	}
	limits, err := EncodeMap(b.limits, "GrantLimits", []Field{
		{Name: "max_envelope_bytes", Number: b.maxEnvelope}, {Name: "max_total_bytes", Number: l.TotalBytes}, {Name: "max_datagram_bytes", Number: l.DatagramBytes},
		{Name: "max_rate_bytes_per_s", Number: l.RateBytesPerSecond}, {Name: "max_queue_bytes", Number: l.QueueBytes}, {Name: "max_pending_native_mappings", Number: l.PendingMappings},
		{Name: "max_resident_native_mappings", Number: l.ResidentMappings}, {Name: "max_total_native_mappings", Number: l.TotalMappings}, {Name: "max_queue_items", Number: l.QueueItems},
	})
	if err != nil {
		return LiveGrantProjection{}, err
	}
	b.projectionFields = [19]Field{
		{Name: "tenant_id", Kind: TextString, Text: s.Tenant}, {Name: "grant_id", Kind: ByteString, Bytes: b.ids[side][:]}, {Name: "replay_nonce", Kind: ByteString, Bytes: b.nonces[side][:]},
		{Name: "parent_ref", Kind: EncodedMap, Bytes: b.parentRef}, {Name: "route_descriptor", Kind: EncodedMap, Bytes: b.route}, {Name: "route_digest", Kind: ByteString, Bytes: b.fields.Winner.RouteDigest[:]},
		{Name: "attempt_id", Kind: ByteString, Bytes: b.fields.Attempt[:]}, {Name: "pairing_id", Kind: ByteString, Bytes: b.pairing[:]}, {Name: "identity_digests", Kind: EncodedArray, Bytes: b.identities},
		{Name: "legs", Kind: EncodedArray, Bytes: b.legs}, {Name: "service", Kind: TextString, Text: s.Service}, {Name: "audience", Kind: TextString, Text: s.Audience}, {Name: "issuer_key_id", Kind: ByteString, Bytes: s.Issuer[:]},
		{Name: "namespace", Kind: EncodedMap, Bytes: ns}, {Name: "issued_at_ms", Number: s.IssuedMS}, {Name: "not_after_ms", Number: s.ExpiresMS}, {Name: "limits", Kind: EncodedMap, Bytes: limits},
		{Name: "session_contract_digest", Kind: ByteString, Bytes: b.contract[:]}, {Name: "relay_identity_digest", Kind: ByteString, Bytes: b.relay[:]},
	}
	return LiveGrantProjection{Fields: b.projectionFields[:], Signer: input.Signer}, nil
}

func (b *liveGrantBuilder) close() {
	clear(b.backing)
	*b = liveGrantBuilder{}
}
