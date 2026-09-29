package protocolv4

import (
	"bytes"
	"crypto/rand"
	"strings"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// PoolActivationConfig fixes the complete ordered candidate subset and attempt
// policy at issuance. A selected tunnel requires both original leg projections.
// There is no live TxA/TxB, candidate race, server allow or consumer here.
type PoolActivationConfig struct {
	Indices        []uint64
	Budget         PoolAttemptLimits
	Client, Server *SignedMap
	Bindings       [3]CredentialValidation
	Tunnels        [16]*LiveTunnelActivationConfig
}

// PoolActivationPlan owns one immutable issuer projection and signs it once.
// Output is private candidate outbox data: the caller must commit the complete
// pool batch before any endpoint delivery or relay registration.
type PoolActivationPlan struct {
	mu                       sync.Mutex
	reservation, shared      resourcev4.Reference
	parent                   *Credential
	bindings                 [3]CredentialValidation
	directClosures           [16][2]*EndpointCredentials
	authorities              [16]*ActivationAuthority
	tunnels                  [16]*liveTunnelPlan
	count                    int
	codec                    *SignedMapCodec
	document                 *Document
	message                  []byte
	signer                   MapSigner
	key                      [32]byte
	signingStart, signingEnd uint64
	issued, active, closed   bool
}

func PoolActivationPlanCharge(c PoolActivationConfig) (resourcev4.Vector, error) {
	if len(c.Indices) < 1 || len(c.Indices) > 16 || c.Client == nil || c.Server == nil {
		return resourcev4.Vector{}, resourcev4.ErrConfiguration
	}
	for i, index := range c.Indices {
		if index >= 16 || i > 0 && c.Indices[i-1] >= index {
			return resourcev4.Vector{}, resourcev4.ErrConfiguration
		}
	}
	for _, v := range c.Bindings {
		if v.Namespace == nil || v.Policy == nil {
			return resourcev4.Vector{}, resourcev4.ErrConfiguration
		}
	}
	count := uint8(0)
	for i, t := range c.Tunnels {
		if t == nil {
			continue
		}
		found := false
		for _, index := range c.Indices {
			found = found || index == uint64(i)
		}
		if !found || t.Issuance == nil || t.Client != c.Client || t.Server != c.Server {
			return resourcev4.Vector{}, resourcev4.ErrConfiguration
		}
		count++
	}
	return PoolActivationPlanCapacity(count)
}

// PoolActivationPlanCapacity admits the full bounded signing workspace before
// an Artifact is issued. Configuration checks still run during construction.
func PoolActivationPlanCapacity(tunnels uint8) (resourcev4.Vector, error) {
	if tunnels > 16 {
		return resourcev4.Vector{}, resourcev4.ErrConfiguration
	}
	base, err := LiveActivationPlanCharge()
	if err != nil {
		return base, err
	}
	selection, err := PoolSelectionBackingBytes(65536, 4096)
	if err != nil {
		return base, err
	}
	authority, err := ActivationAuthorityBackingBytes()
	if err != nil {
		return base, err
	}
	binding, err := ActivationBindingBackingBytes()
	if err != nil {
		return base, err
	}
	closure, err := EndpointCredentialsBackingBytes()
	if err != nil {
		return base, err
	}
	base, err = base.Add(resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(PoolActivationPlan{})) + selection + 16*(authority+binding) + 32*closure + 16384})
	if err != nil {
		return base, err
	}
	for range tunnels {
		extra, e := liveTunnelPlanCharge()
		if e != nil {
			return base, e
		}
		base, err = base.Add(extra)
		if err != nil {
			return base, err
		}
	}
	return base, nil
}

func NewPoolActivationPlan(artifact *SignedMap, rules *NamespaceRules, delegation, once []byte, signer MapSigner, c PoolActivationConfig, reservation, environment, materialOwner resourcev4.Reference) (_ *PoolActivationPlan, err error) {
	if artifact == nil || rules == nil || signer == nil {
		return nil, resourcev4.ErrConfiguration
	}
	keyBytes := signer.PublicKey()
	if len(keyBytes) != 32 {
		return nil, CBORFailure("signature_key_binding")
	}
	cost, err := PoolActivationPlanCharge(c)
	if err != nil {
		return nil, err
	}
	if err = reservation.CheckSameEnvironment(environment); err != nil {
		return nil, err
	}
	if err = materialOwner.CheckSameEnvironment(environment); err != nil {
		return nil, err
	}
	owned, err := reservation.Take(cost)
	if err != nil {
		return nil, err
	}
	p := &PoolActivationPlan{reservation: owned, bindings: c.Bindings, signer: signer, count: len(c.Indices)}
	defer func() {
		if err != nil {
			_ = p.Close()
		}
	}()
	p.shared, err = materialOwner.Borrow()
	if err != nil {
		return nil, err
	}
	p.parent, err = artifact.DetachCredential()
	if err != nil {
		return nil, err
	}
	if err = c.Bindings[0].CheckLiveActivationSource(rules, p.parent, delegation, once, [32]byte(keyBytes), environment); err != nil {
		return nil, err
	}
	w, err := NewPoolSelectionWorkspace(65536, 4096)
	if err != nil {
		return nil, err
	}
	selection, err := w.Derive(artifact, c.Indices)
	if err != nil {
		return nil, err
	}
	defer selection.Release()
	parentDigest, candidateDigest, routeDigest, err := selection.Digests()
	if err != nil {
		return nil, err
	}
	var members [16]PoolMember
	for i := range c.Indices {
		members[i], err = selection.MemberAt(i)
		if err != nil {
			return nil, err
		}
	}
	var attempt [16]byte
	if _, err = rand.Read(attempt[:]); err != nil {
		return nil, err
	}
	if attempt == ([16]byte{}) || attempt == p.parent.lease {
		return nil, CBORFailure("issuance_entropy")
	}
	d, err := boundedMap(delegation, "ConnectionActivationDelegation")
	if err != nil {
		return nil, err
	}
	defer d.Release()
	o, err := boundedMap(once, "OnceAuthorityRef")
	if err != nil {
		return nil, err
	}
	defer o.Release()
	authority, _ := d.Root().Named("ConnectionActivationDelegation", "authority_id").Text()
	p.signingStart, _ = d.Root().Named("ConnectionActivationDelegation", "signing_not_before_ms").Uint()
	p.signingEnd, _ = d.Root().Named("ConnectionActivationDelegation", "signing_not_after_ms").Uint()
	keyID, _ := d.Root().Named("ConnectionActivationDelegation", "signing_key_id").Text()
	winner, _ := o.Root().Named("OnceAuthorityRef", "winner_authority_id").Text()
	key, _ := d.Root().Named("ConnectionActivationDelegation", "signer_public_key").ByteString()
	if len(key) != 32 || !bytes.Equal(key, signer.PublicKey()) {
		return nil, CBORFailure("signature_key_binding")
	}
	copy(p.key[:], key)
	var identities [2][32]byte
	for side, m := range [2]*SignedMap{c.Client, c.Server} {
		identities[side], err = m.Digest("certificate_digest")
		if err != nil {
			return nil, err
		}
	}
	scope := p.parent.scope
	b := ActivationBinding{source: "preauthorized_pool", attempt: attempt, issuedAt: scope.IssuedMS, activationEnd: p.parent.admissionEnd, sessionEnd: scope.ExpiresMS, proofKey: p.key, artifactKey: artifact.key, artifactDigest: parentDigest,
		tenant: strings.Clone(scope.Tenant), audience: strings.Clone(scope.Audience), profile: strings.Clone(scope.Profile), issuer: scope.Issuer, lease: p.parent.lease, clientDigest: identities[0], serverDigest: identities[1],
		authority: strings.Clone(authority), signingKey: strings.Clone(keyID), winnerAuthority: strings.Clone(winner), poolBudget: c.Budget, candidateSetDigest: candidateDigest, routeSetDigest: routeDigest}
	var namespaceOwners [MaxArtifactIssueNamespaces]*LiveNamespace
	var namespaceScopes [MaxArtifactIssueNamespaces]CredentialScope
	ownerCount := 0
	for i, index := range c.Indices {
		binding := b
		binding.winner = members[i]
		p.authorities[i], err = rules.BindActivationAuthority(&binding, artifact, delegation, once)
		if err != nil {
			return nil, err
		}
		if err = binding.MatchCertificates(c.Client, c.Server); err != nil {
			return nil, err
		}
		var closures [2]*EndpointCredentials
		var checks [2][5]CredentialValidation
		if c.Tunnels[index] != nil {
			t := c.Tunnels[index]
			for k, v := range c.Bindings {
				if t.Bindings[k] != v {
					return nil, CBORFailure("credential_namespace_owner")
				}
			}
			// Share the frozen Grant encoding machinery, without creating a live
			// proof, TxA intent, TxB guard or any live publication owner.
			builder := LiveActivationPlan{reservation: p.reservation, authority: p.authorities[i], fields: LiveActivationFields{Tunnel: true, Tenant: b.tenant, Authority: b.authority, SigningKey: b.signingKey, Audience: b.audience, Profile: b.profile, Issuer: b.issuer, Lease: b.lease, Attempt: b.attempt, Artifact: b.artifactDigest, ClientIdentity: b.clientDigest, ServerIdentity: b.serverDigest, Signer: p.key, Winner: members[i], IssuedAt: b.issuedAt, ActivationEnd: b.activationEnd, SessionEnd: b.sessionEnd}}
			err = builder.freezeTunnel(artifact, t)
			p.tunnels[index] = builder.tunnel
			if err != nil {
				return nil, err
			}
			closures = p.tunnels[index].closures
			checks = p.tunnels[index].bindings
		} else {
			for side := range closures {
				closures[side], err = BindEndpointCredentials(Direction(side), artifact, index, c.Client, c.Server, nil, nil)
				if err != nil {
					return nil, err
				}
				copy(checks[side][:3], c.Bindings[:])
				if err = closures[side].MatchActivation(p.authorities[i]); err != nil {
					return nil, err
				}
			}
			p.directClosures[index] = closures
		}
		for side, closure := range closures {
			for k, credential := range closure.credentials[:closure.count] {
				v := checks[side][k]
				if v.Namespace == nil {
					return nil, CBORFailure("credential_namespace_owner")
				}
				if err = v.Namespace.reservation.CheckSameEnvironment(environment); err != nil {
					return nil, err
				}
				found := false
				for j, old := range namespaceScopes[:ownerCount] {
					if old.Tenant == credential.scope.Tenant && old.Authority == credential.scope.Authority {
						if namespaceOwners[j] != v.Namespace {
							return nil, CBORFailure("credential_namespace_owner")
						}
						found = true
					}
				}
				if !found {
					if ownerCount == len(namespaceOwners) {
						return nil, resourcev4.ErrCapacity
					}
					namespaceScopes[ownerCount], namespaceOwners[ownerCount] = credential.scope, v.Namespace
					ownerCount++
				}
			}
			if _, err = closure.CheckCurrent(checks[side][:closure.count], b.sessionEnd); err != nil {
				return nil, err
			}
		}
	}
	reference, err := poolActivationReference(c.Indices, c.Budget, parentDigest, candidateDigest, once)
	if err != nil {
		return nil, err
	}
	limit, err := SchemaByteLimit("ActivationAuthorization")
	if err != nil {
		return nil, err
	}
	p.codec, err = NewSignedMapCodec("ActivationAuthorization", limit, limit)
	if err != nil {
		return nil, err
	}
	fields := []Field{{Name: "schema_revision", Number: 1}, {Name: "authority_id", Kind: TextString, Text: b.authority}, {Name: "signing_key_id", Kind: TextString, Text: b.signingKey}, {Name: "tenant_id", Kind: TextString, Text: b.tenant},
		{Name: "artifact_issuer_key_id", Kind: ByteString, Bytes: b.issuer[:]}, {Name: "lease_id", Kind: ByteString, Bytes: b.lease[:]}, {Name: "artifact_digest", Kind: ByteString, Bytes: b.artifactDigest[:]},
		{Name: "candidate_selection", Kind: EncodedMap, Bytes: reference}, {Name: "route_selection", Kind: ByteString, Bytes: routeDigest[:]}, {Name: "attempt_id", Kind: ByteString, Bytes: attempt[:]},
		{Name: "client_identity_digest", Kind: ByteString, Bytes: b.clientDigest[:]}, {Name: "server_identity_digest", Kind: ByteString, Bytes: b.serverDigest[:]}, {Name: "audience", Kind: TextString, Text: b.audience},
		{Name: "issued_at_ms", Number: b.issuedAt}, {Name: "activation_not_after_ms", Number: b.activationEnd}, {Name: "session_not_after_ms", Number: b.sessionEnd}, {Name: "signature", Kind: ByteString, Bytes: make([]byte, 64)}}
	wire, err := EncodeMap(p.codec.encoded, "ActivationAuthorization", fields)
	if err != nil {
		return nil, err
	}
	p.document, err = p.codec.decoder.DecodeMap(wire, "ActivationAuthorization", DecodeContext{Selectors: map[string]string{"activation_source_profile": "preauthorized_pool"}})
	clear(p.codec.encoded)
	if err != nil {
		return nil, err
	}
	message, err := p.codec.signingInput(p.document)
	if err != nil {
		return nil, err
	}
	p.message = bytes.Clone(message)
	clear(p.codec.message)
	if err = p.checkTrust(); err != nil {
		return nil, err
	}
	return p, nil
}

func poolActivationReference(indices []uint64, b PoolAttemptLimits, artifact, candidates [32]byte, once []byte) ([]byte, error) {
	var per [128]byte
	candidate, err := EncodeMap(per[:], "CandidateAttemptBudget", []Field{{Name: "address_attempts", Number: b.CandidateAddressAttempts}, {Name: "preauth_bytes", Number: b.CandidatePreauthBytes}, {Name: "work_units", Number: b.CandidateWorkUnits}})
	if err != nil {
		return nil, err
	}
	var total [256]byte
	budget, err := EncodeMap(total[:], "PoolAttemptBudget", []Field{{Name: "per_candidate", Kind: EncodedMap, Bytes: candidate}, {Name: "total_address_attempts", Number: b.TotalAddressAttempts}, {Name: "total_preauth_bytes", Number: b.TotalPreauthBytes}, {Name: "total_work_units", Number: b.TotalWorkUnits}, {Name: "parallel_candidates", Number: b.ParallelCandidates}})
	if err != nil {
		return nil, err
	}
	var indexBytes [17]byte
	indexBytes[0] = 0x80 | byte(len(indices))
	for i, index := range indices {
		indexBytes[i+1] = byte(index)
	}
	return EncodeMap(make([]byte, 4096), "PoolSelectionRef", []Field{{Name: "artifact_digest", Kind: ByteString, Bytes: artifact[:]}, {Name: "candidate_indices", Kind: EncodedArray, Bytes: indexBytes[:len(indices)+1]}, {Name: "candidate_set_digest", Kind: ByteString, Bytes: candidates[:]}, {Name: "attempt_budget", Kind: EncodedMap, Bytes: budget}, {Name: "once_authority_ref", Kind: EncodedMap, Bytes: once}})
}

// MaterialSizes describes the frozen private encoding before signing. The
// enclosing issuer rejects a whole over-capacity bundle without truncating its
// candidate set or dropping a leg. It does not expose signature bytes.
func (p *PoolActivationPlan) MaterialSizes() (int, [16][2]int, error) {
	var sizes [16][2]int
	if p == nil {
		return 0, sizes, resourcev4.ErrOwner
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.active || p.issued {
		return 0, sizes, resourcev4.ErrOwner
	}
	if err := p.reservation.Check(); err != nil {
		return 0, sizes, err
	}
	for i, t := range p.tunnels {
		if t != nil {
			for side := range t.grants {
				sizes[i][side] = len(t.grants[side].document.Bytes())
			}
		}
	}
	return len(p.document.Bytes()), sizes, nil
}

func (p *PoolActivationPlan) checkTrust() error {
	if err := p.reservation.Check(); err != nil {
		return err
	}
	if err := p.shared.Check(); err != nil {
		return err
	}
	v := p.bindings[0]
	now, err := v.Namespace.clock.Sample()
	if err != nil {
		return err
	}
	r := v.Policy.Requirements()
	if err = now.LowerBound(p.signingStart, true); err != nil {
		return err
	}
	if !now.ValidBefore(p.signingEnd) {
		return timev4.ErrExpired
	}
	if _, err = v.CheckMaterialCredential(p.parent, p.parent.scope.ExpiresMS, p.reservation); err != nil {
		return err
	}
	for _, a := range p.authorities[:p.count] {
		if err = a.CheckAdmission(now.Interval); err != nil {
			return err
		}
		if _, err = v.Namespace.CheckDetachedActivation(a, p.parent, v.Issuer, r.StalenessMS, r.SignerLifetimeMS, p.parent.scope.ExpiresMS); err != nil {
			return err
		}
	}
	for _, candidate := range p.directClosures {
		for _, closure := range candidate {
			if closure != nil {
				if _, err = closure.CheckCurrent(p.bindings[:closure.count], p.parent.scope.ExpiresMS); err != nil {
					return err
				}
			}
		}
	}
	for _, t := range p.tunnels {
		if t != nil {
			for side := range t.bindings {
				v := t.bindings[side][3]
				grantNow, e := v.Namespace.clock.Sample()
				if e != nil {
					return e
				}
				if e = grantNow.LowerBound(v.Issuer.SigningStart, true); e != nil {
					return e
				}
				if !grantNow.ValidBefore(v.Issuer.SigningEnd) {
					return timev4.ErrExpired
				}
			}
			if err = t.checkCurrent(p.parent.scope.ExpiresMS); err != nil {
				return err
			}
		}
	}
	return nil
}

// IssueMaterial signs all original projections once. Short buffers are rejected
// before any signer runs. Failure clears all private output; it never permits
// re-signing this plan. The caller's guard checks its original issuance owner.
func (p *PoolActivationPlan) IssueMaterial(proof []byte, grants [16][2][]byte, guard func() error) (proofBytes int, sizes [16][2]int, err error) {
	if p == nil || guard == nil {
		return 0, sizes, resourcev4.ErrConfiguration
	}
	p.mu.Lock()
	if p.closed || p.issued {
		p.mu.Unlock()
		return 0, sizes, resourcev4.ErrOwner
	}
	if len(proof) < len(p.document.Bytes()) {
		p.mu.Unlock()
		return 0, sizes, resourcev4.ErrCapacity
	}
	for i, t := range p.tunnels {
		if t != nil {
			for side := range t.grants {
				if len(grants[i][side]) < len(t.grants[side].document.Bytes()) {
					p.mu.Unlock()
					return 0, sizes, resourcev4.ErrCapacity
				}
			}
		}
	}
	p.issued, p.active = true, true
	p.mu.Unlock()
	success := false
	defer func() {
		if !success {
			clear(proof)
			for _, pair := range grants {
				for _, output := range pair {
					clear(output)
				}
			}
			proofBytes = 0
			sizes = [16][2]int{}
		}
		p.mu.Lock()
		p.active = false
		if p.closed {
			p.cleanupLocked()
		}
		p.mu.Unlock()
	}()
	check := func() error {
		p.mu.Lock()
		closed := p.closed
		p.mu.Unlock()
		if closed {
			return resourcev4.ErrClosed
		}
		if err := guard(); err != nil {
			return err
		}
		return p.checkTrust()
	}
	if err = check(); err != nil {
		return 0, sizes, err
	}
	if !bytes.Equal(p.signer.PublicKey(), p.key[:]) {
		return 0, sizes, CBORFailure("signature_key_binding")
	}
	sig, err := p.signer.Sign(p.message)
	defer clear(sig)
	if err != nil {
		return 0, sizes, err
	}
	if err = check(); err != nil {
		return 0, sizes, err
	}
	if !VerifyEd25519(sig, p.message, p.key[:]) {
		return 0, sizes, errSignatureGeneration
	}
	target, _ := p.document.Root().Field(p.codec.signatureID).ByteString()
	copy(target, sig)
	proofBytes = copy(proof, p.document.Bytes())
	for i, t := range p.tunnels {
		if t != nil {
			for side := range t.grants {
				sizes[i][side], err = t.grants[side].issue(grants[i][side], check)
				if err != nil {
					return 0, sizes, err
				}
			}
		}
	}
	if err = check(); err != nil {
		return 0, sizes, err
	}
	success = true
	return proofBytes, sizes, nil
}

func (p *PoolActivationPlan) Close() error {
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
	p.cleanupLocked()
	return nil
}
func (p *PoolActivationPlan) cleanupLocked() {
	for _, t := range p.tunnels {
		t.close()
	}
	if p.document != nil {
		p.document.Release()
	}
	clear(p.message)
	p.document = nil
	p.message = nil
	p.codec = nil
	p.signer = nil
	p.parent = nil
	p.authorities = [16]*ActivationAuthority{}
	p.tunnels = [16]*liveTunnelPlan{}
	p.directClosures = [16][2]*EndpointCredentials{}
	p.bindings = [3]CredentialValidation{}
	p.shared.Release()
	p.reservation.Release()
	p.shared, p.reservation = resourcev4.Reference{}, resourcev4.Reference{}
}
func (*PoolActivationPlan) String() string   { return "Flowersec.PoolActivationPlan" }
func (*PoolActivationPlan) GoString() string { return "Flowersec.PoolActivationPlan" }
