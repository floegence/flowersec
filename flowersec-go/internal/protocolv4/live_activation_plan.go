package protocolv4

import (
	"bytes"
	"strings"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

// LiveActivationConfig is fixed by the trusted authority before TxA. These
// values are never recomputed from callback completion or confirmation time.
type LiveActivationConfig struct {
	Index                               uint64
	Attempt                             [16]byte
	IssuedAt, ActivationEnd, SessionEnd uint64
}

// LiveActivationFields describes the authority's original unsigned direct
// projection. It is neither a signature nor permission to dispatch policy.
type LiveActivationFields struct {
	Tenant, Authority, SigningKey, Audience, Profile string
	Issuer, Lease, Attempt                           [16]byte
	Artifact, ClientIdentity, ServerIdentity, Signer [32]byte
	Winner                                           PoolMember
	IssuedAt, ActivationEnd, SessionEnd              uint64
}

// LiveActivationPlan freezes the real unsigned proof and delegated signer.
// The sole Issue call is private authority work after its original TxA guard;
// candidate signature bytes must remain private until complete TxB commits.
type LiveActivationPlan struct {
	mu                     sync.Mutex
	fields                 LiveActivationFields
	binding                *ActivationBinding
	authority              *ActivationAuthority
	codec                  *SignedMapCodec
	signer                 MapSigner
	unsigned, message      []byte
	reservation, shared    resourcev4.Reference
	issued, active, closed bool
}

func LiveActivationPlanCharge() (resourcev4.Vector, error) {
	limit, err := SchemaByteLimit("ActivationAuthorization")
	if err != nil {
		return resourcev4.Vector{}, err
	}
	codec, err := SignedMapBackingBytes("ActivationAuthorization", limit, limit)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	authority, err := ActivationAuthorityBackingBytes()
	if err != nil {
		return resourcev4.Vector{}, err
	}
	binding, err := ActivationBindingBackingBytes()
	if err != nil {
		return resourcev4.Vector{}, err
	}
	route, err := SchemaByteLimit("Artifact")
	if err != nil {
		return resourcev4.Vector{}, err
	}
	return resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(LiveActivationPlan{})) + codec + authority + binding + 3*uint64(limit) + uint64(route) + 256, resourcev4.Items: 1, resourcev4.WorkSlots: 1}, nil
}

func NewLiveActivationPlan(artifact *SignedMap, rules *NamespaceRules, delegation, once []byte, signer MapSigner, config LiveActivationConfig, reservation, environment, materialOwner resourcev4.Reference) (_ *LiveActivationPlan, err error) {
	if artifact == nil || rules == nil || signer == nil || config.Attempt == ([16]byte{}) {
		return nil, CBORFailure("activation_owner")
	}
	if err = artifact.CheckDirectListenerCandidate(config.Index); err != nil {
		return nil, err
	}
	if err = reservation.CheckSameEnvironment(environment); err != nil {
		return nil, err
	}
	if err = materialOwner.CheckSameEnvironment(environment); err != nil {
		return nil, err
	}
	charge, err := LiveActivationPlanCharge()
	if err != nil {
		return nil, err
	}
	shared, err := materialOwner.Borrow()
	if err != nil {
		return nil, err
	}
	held, err := reservation.Take(charge)
	if err != nil {
		shared.Release()
		return nil, err
	}
	p := &LiveActivationPlan{reservation: held, shared: shared, signer: signer}
	adopted := false
	defer func() {
		if !adopted {
			_ = p.Close()
		}
	}()
	limit, _ := SchemaByteLimit("ActivationAuthorization")
	p.codec, err = NewSignedMapCodec("ActivationAuthorization", limit, limit)
	if err != nil {
		return nil, err
	}
	d, err := boundedMap(delegation, "ConnectionActivationDelegation")
	if err != nil {
		return nil, err
	}
	entry := d.Root()
	key, ok := entry.Named("ConnectionActivationDelegation", "signer_public_key").ByteString()
	if !ok || len(key) != 32 || !bytes.Equal(key, signer.PublicKey()) {
		d.Release()
		return nil, CBORFailure("activation_delegation_authority")
	}
	b := &ActivationBinding{source: "live_authority", attempt: config.Attempt, issuedAt: config.IssuedAt, activationEnd: config.ActivationEnd, sessionEnd: config.SessionEnd, proofKey: [32]byte(key)}
	b.authority, _ = entry.Named("ConnectionActivationDelegation", "authority_id").Text()
	b.signingKey, _ = entry.Named("ConnectionActivationDelegation", "signing_key_id").Text()
	d.Release()
	routeCap, _ := SchemaByteLimit("Artifact")
	_, route, err := artifact.CopyCandidateRoute(config.Index, make([]byte, routeCap))
	if err != nil {
		return nil, err
	}
	c := artifact.codec
	c.mu.Lock()
	if c.current != artifact || c.schema != "Artifact" {
		c.mu.Unlock()
		return nil, CBORFailure("artifact_owner")
	}
	ar := artifact.document.Root()
	b.artifactDigest, err = artifact.digestLocked("artifact_digest")
	if err == nil {
		b.tenant, _ = ar.Named("Artifact", "tenant_id").Text()
		b.audience, _ = ar.Named("Artifact", "audience").Text()
		b.profile, _ = ar.Named("Artifact", "crypto_profile_id").Text()
		issuer, _ := ar.Named("Artifact", "issuer_key_id").ByteString()
		lease, _ := ar.Named("Artifact", "lease_id").ByteString()
		client, _ := ar.Named("Artifact", "client_identity_digest").ByteString()
		server, _ := ar.Named("Artifact", "server_identity_digest").ByteString()
		nonce, _ := ar.Named("Artifact", "session_nonce").ByteString()
		id, _ := ar.Named("Artifact", "candidates").Index(int(config.Index)).Named("Candidate", "candidate_id").ByteString()
		b.issuer, b.lease, b.artifactKey = [16]byte(issuer), [16]byte(lease), artifact.key
		b.clientDigest, b.serverDigest, b.sessionNonce = [32]byte(client), [32]byte(server), [32]byte(nonce)
		b.winner = PoolMember{Index: config.Index, CandidateID: [16]byte(id), RouteDigest: route}
	}
	c.mu.Unlock()
	if err != nil {
		return nil, err
	}
	for _, text := range []*string{&b.tenant, &b.audience, &b.profile, &b.authority, &b.signingKey} {
		*text = strings.Clone(*text)
	}
	p.authority, err = rules.BindActivationAuthority(b, artifact, delegation, once)
	if err != nil {
		return nil, err
	}
	p.binding = b
	p.fields = LiveActivationFields{Tenant: b.tenant, Authority: b.authority, SigningKey: b.signingKey, Audience: b.audience, Profile: b.profile, Issuer: b.issuer, Lease: b.lease, Attempt: b.attempt, Artifact: b.artifactDigest, ClientIdentity: b.clientDigest, ServerIdentity: b.serverDigest, Signer: b.proofKey, Winner: b.winner, IssuedAt: b.issuedAt, ActivationEnd: b.activationEnd, SessionEnd: b.sessionEnd}
	fields := p.proofFields()
	var complete [17]Field
	copy(complete[:], fields[:])
	var signature [64]byte
	complete[16] = Field{Name: "signature", Kind: ByteString, Bytes: signature[:]}
	wire, err := EncodeMap(p.codec.encoded, "ActivationAuthorization", complete[:])
	if err != nil {
		return nil, err
	}
	doc, err := p.codec.decoder.DecodeShape(wire, "ActivationAuthorization", DecodeContext{Selectors: map[string]string{"activation_source_profile": "live_authority"}})
	if err != nil {
		return nil, err
	}
	defer doc.Release()
	if err = doc.ValidateRules(DecodeContext{Selectors: map[string]string{"activation_source_profile": "live_authority"}}); err != nil {
		return nil, err
	}
	p.unsigned = make([]byte, limit)
	unsigned, err := doc.copyWithout(p.unsigned, p.codec.signatureID)
	if err != nil {
		return nil, err
	}
	p.unsigned = p.unsigned[:len(unsigned):len(unsigned)]
	message, err := p.codec.signingInput(doc)
	if err != nil {
		return nil, err
	}
	p.message = bytes.Clone(message)
	clear(p.codec.message)
	clear(p.codec.encoded)
	adopted = true
	return p, nil
}

func (p *LiveActivationPlan) proofFields() [16]Field {
	f := &p.fields
	return [16]Field{
		{Name: "schema_revision", Number: 1}, {Name: "authority_id", Kind: TextString, Text: f.Authority}, {Name: "signing_key_id", Kind: TextString, Text: f.SigningKey}, {Name: "tenant_id", Kind: TextString, Text: f.Tenant},
		{Name: "artifact_issuer_key_id", Kind: ByteString, Bytes: f.Issuer[:]}, {Name: "lease_id", Kind: ByteString, Bytes: f.Lease[:]}, {Name: "artifact_digest", Kind: ByteString, Bytes: f.Artifact[:]},
		{Name: "candidate_selection", Kind: ByteString, Bytes: f.Winner.CandidateID[:]}, {Name: "route_selection", Kind: ByteString, Bytes: f.Winner.RouteDigest[:]}, {Name: "attempt_id", Kind: ByteString, Bytes: f.Attempt[:]},
		{Name: "client_identity_digest", Kind: ByteString, Bytes: f.ClientIdentity[:]}, {Name: "server_identity_digest", Kind: ByteString, Bytes: f.ServerIdentity[:]}, {Name: "audience", Kind: TextString, Text: f.Audience},
		{Name: "issued_at_ms", Number: f.IssuedAt}, {Name: "activation_not_after_ms", Number: f.ActivationEnd}, {Name: "session_not_after_ms", Number: f.SessionEnd},
	}
}

// CopyProjection copies the whole unsigned proof; a store never substitutes
// only a digest for its original TxA projection.
func (p *LiveActivationPlan) CopyProjection(dst []byte) (LiveActivationFields, int, error) {
	if p == nil {
		return LiveActivationFields{}, 0, CBORFailure("activation_owner")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || len(dst) < len(p.unsigned) {
		return LiveActivationFields{}, 0, CBORFailure("configuration_capacity")
	}
	if err := p.reservation.Check(); err != nil {
		return LiveActivationFields{}, 0, err
	}
	return p.fields, copy(dst, p.unsigned), nil
}

func (p *LiveActivationPlan) CheckEnvironment(environment resourcev4.Reference) error {
	if p == nil {
		return CBORFailure("activation_owner")
	}
	return p.reservation.CheckSameEnvironment(environment)
}

// MatchOriginal binds the still-unissued authority plan to the actual selected
// connection before its consumer begins a durable claim. A valid plan for a
// different candidate/attempt must not consume this lease and fail only at TxB.
func (p *LiveActivationPlan) MatchOriginal(session ArtifactSessionParameters, attempt [16]byte, winner PoolMember) error {
	if p == nil {
		return CBORFailure("activation_owner")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.issued || p.active {
		return CBORFailure("activation_owner")
	}
	if err := p.reservation.Check(); err != nil {
		return err
	}
	if err := p.shared.Check(); err != nil {
		return err
	}
	return p.binding.MatchOriginal(session, attempt, winner)
}

// CheckTrust uses current independent namespace authority, issuer and policy
// checks. The unsigned projection's existence itself grants no authorization.
func (p *LiveActivationPlan) CheckTrust(namespace *LiveNamespace, artifact *Credential, permission IssuerPermission, staleness, signerLifetime, hardEnd uint64, now timev4.Interval) error {
	if p == nil || namespace == nil {
		return CBORFailure("activation_owner")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return CBORFailure("activation_owner")
	}
	if err := p.shared.Check(); err != nil {
		return err
	}
	if err := p.authority.CheckAdmission(now); err != nil {
		return err
	}
	_, err := namespace.CheckDetachedActivation(p.authority, artifact, permission, staleness, signerLifetime, hardEnd)
	return err
}

type originalLiveSigner struct{ plan *LiveActivationPlan }

func (s originalLiveSigner) PublicKey() []byte { return s.plan.fields.Signer[:] }
func (s originalLiveSigner) Sign(message []byte) ([]byte, error) {
	if !bytes.Equal(message, s.plan.message) || !bytes.Equal(s.plan.signer.PublicKey(), s.plan.fields.Signer[:]) {
		return nil, CBORFailure("signature_projection")
	}
	return s.plan.signer.Sign(message)
}

func (p *LiveActivationPlan) Issue(dst []byte, guard func() error) (n int, err error) {
	if p == nil || guard == nil {
		return 0, CBORFailure("activation_owner")
	}
	p.mu.Lock()
	if p.closed || p.issued {
		p.mu.Unlock()
		return 0, CBORFailure("activation_owner")
	}
	p.issued, p.active = true, true
	p.mu.Unlock()
	defer func() { p.mu.Lock(); p.active = false; p.mu.Unlock() }()
	check := func() error {
		p.mu.Lock()
		closed := p.closed
		p.mu.Unlock()
		if closed {
			return CBORFailure("activation_owner")
		}
		if err := p.reservation.Check(); err != nil {
			return err
		}
		if err := p.shared.Check(); err != nil {
			return err
		}
		return guard()
	}
	fields := p.proofFields()
	signed, err := p.codec.SignWith(fields[:], p.fields.Signer, originalLiveSigner{p}, DecodeContext{Selectors: map[string]string{"activation_source_profile": "live_authority"}}, check)
	if err != nil {
		return 0, err
	}
	defer signed.Release()
	wire, err := signed.Bytes()
	if err != nil {
		return 0, err
	}
	if len(dst) < len(wire) {
		return 0, CBORFailure("configuration_capacity")
	}
	if err = check(); err != nil {
		return 0, err
	}
	return copy(dst, wire), nil
}

func (p *LiveActivationPlan) Close() error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	p.reservation.Seal()
	if p.active {
		return resourcev4.ErrCapacity
	}
	clear(p.unsigned)
	clear(p.message)
	p.unsigned, p.message, p.codec, p.signer, p.binding, p.authority = nil, nil, nil, nil, nil, nil
	p.fields = LiveActivationFields{}
	p.reservation.Release()
	p.shared.Release()
	return nil
}
