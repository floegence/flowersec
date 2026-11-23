package protocolv4

import (
	"bytes"
	"unsafe"
)

// ActivationBinding is a detached cross-object signature/binding fact. It is
// not a trust decision, durable spend receipt, ParentWinner or Activate right.
// Its private fields prevent consumers from rewriting the checked projection.
type ActivationBinding struct {
	tenant, audience, authority, signingKey, profile, source              string
	issuer, lease, attempt                                                [16]byte
	sessionNonce, artifactDigest, proofDigest, clientDigest, serverDigest [32]byte
	artifactKey, proofKey                                                 [32]byte
	winner                                                                PoolMember
	issuedAt, activationEnd, sessionEnd                                   uint64
	poolBudget                                                            PoolAttemptLimits
	winnerAuthority                                                       string
	candidateSetDigest, routeSetDigest                                    [32]byte
}

// PoolAttemptLimits is the signed finite attempt policy, not usage or a token.
type PoolAttemptLimits struct {
	CandidateAddressAttempts, CandidatePreauthBytes, CandidateWorkUnits         uint64
	TotalAddressAttempts, TotalPreauthBytes, TotalWorkUnits, ParallelCandidates uint64
}

// ActivationBindingBackingBytes reserves the detached result separately from
// the reusable pool workspace. All retained text except the crypto profile is
// inside the bounded proof; neither Artifact bytes nor PSK are retained.
func ActivationBindingBackingBytes() (uint64, error) {
	proofCap, err := SchemaByteLimit("ActivationAuthorization")
	if err != nil {
		return 0, err
	}
	r, err := runtimeSchema()
	if err != nil {
		return 0, err
	}
	profileBytes := 0
	for profile := range r.Maps["Artifact"].byName["crypto_profile_id"].texts {
		if len(profile) > profileBytes {
			profileBytes = len(profile)
		}
	}
	return uint64(unsafe.Sizeof(ActivationBinding{})) + uint64(proofCap) + uint64(profileBytes), nil
}

// BindActivation checks the original parent, fixed source variant and exact
// selected candidate. All scratch is reserved by this workspace before spend.
// There is no sorting, fallback, online lookup or authorization side effect.
func (w *PoolSelectionWorkspace) BindActivation(artifact, proof *SignedMap, source string, index uint64) (_ *ActivationBinding, err error) {
	if artifact == nil || proof == nil || artifact.codec.schema != "Artifact" || proof.codec.schema != "ActivationAuthorization" {
		return nil, CBORFailure("activation_owner")
	}
	switch source {
	case "live_authority":
		source = "live_authority"
	case "preauthorized_pool":
		source = "preauthorized_pool"
	default:
		return nil, CBORFailure("context_unresolved")
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.current != nil {
		return nil, CBORFailure("decoder_busy")
	}
	defer func() { w.clear(); w.current = nil }()
	a, p := artifact.codec, proof.codec
	// Schema-specific order also excludes taking the same codec twice.
	a.mu.Lock()
	defer a.mu.Unlock()
	p.mu.Lock()
	defer p.mu.Unlock()
	if a.current != artifact || p.current != proof || proof.activationSourceProfile != source {
		return nil, CBORFailure("activation_owner")
	}
	context := DecodeContext{Selectors: map[string]string{"activation_source_profile": source}}
	if err := artifact.document.ValidateRules(context); err != nil {
		return nil, err
	}
	if err := proof.document.ValidateRules(context); err != nil {
		return nil, err
	}
	ar, pr := artifact.document.Root(), proof.document.Root()
	parent := func(name string) Value { return ar.Named("Artifact", name) }
	child := func(name string) Value { return pr.Named("ActivationAuthorization", name) }
	for _, names := range [][2]string{{"tenant_id", "tenant_id"}, {"issuer_key_id", "artifact_issuer_key_id"}, {"lease_id", "lease_id"}, {"client_identity_digest", "client_identity_digest"}, {"server_identity_digest", "server_identity_digest"}, {"audience", "audience"}} {
		if !bytes.Equal(parent(names[0]).Encoded(), child(names[1]).Encoded()) {
			return nil, CBORFailure("activation_parent_binding")
		}
	}
	artifactDigest, err := fullMapDigest("artifact_digest", "Artifact", artifact.document.Bytes())
	if err != nil {
		return nil, err
	}
	if value, _ := child("artifact_digest").ByteString(); !bytes.Equal(value, artifactDigest[:]) {
		return nil, CBORFailure("activation_parent_binding")
	}
	activationEnd, _ := child("activation_not_after_ms").Uint()
	sessionEnd, _ := child("session_not_after_ms").Uint()
	parentActivation, _ := parent("initiation_not_after_ms").Uint()
	parentSession, _ := parent("session_not_after_ms").Uint()
	if activationEnd > parentActivation || sessionEnd > parentSession {
		return nil, CBORFailure("activation_parent_deadline")
	}
	candidates := parent("candidates")
	if index >= uint64(candidates.Len()) {
		return nil, CBORFailure("pool_index_membership")
	}
	candidate := candidates.Index(int(index))
	route, err := projectCandidate(w.route, candidate)
	if err != nil {
		return nil, err
	}
	routeDigest, err := fullMapDigest("route_digest", "Route", route)
	if err != nil {
		return nil, err
	}
	id, _ := candidate.Named("Candidate", "candidate_id").ByteString()
	winner := PoolMember{Index: index, CandidateID: [16]byte(id), RouteDigest: routeDigest}
	var attemptBudget PoolAttemptLimits
	winnerAuthority := ""
	if source == "live_authority" {
		selection, _ := child("candidate_selection").ByteString()
		route, _ := child("route_selection").ByteString()
		if !bytes.Equal(selection, id) || !bytes.Equal(route, routeDigest[:]) {
			return nil, CBORFailure("activation_winner_binding")
		}
	} else {
		reference := child("candidate_selection")
		count, ok := reference.Named("PoolSelectionRef", "candidate_indices").CopyUints(w.indices)
		if !ok {
			return nil, CBORFailure("array_length")
		}
		selection, err := w.deriveLocked(artifact, w.indices[:count])
		if err != nil {
			return nil, err
		}
		if err := selection.matchProofLocked(proof); err != nil {
			return nil, err
		}
		found := false
		for _, member := range w.members[:selection.count] {
			found = found || member == winner
		}
		if !found {
			return nil, CBORFailure("activation_winner_binding")
		}
		budget := reference.Named("PoolSelectionRef", "attempt_budget")
		perCandidate := budget.Named("PoolAttemptBudget", "per_candidate")
		attemptBudget.CandidateAddressAttempts, _ = perCandidate.Named("CandidateAttemptBudget", "address_attempts").Uint()
		attemptBudget.CandidatePreauthBytes, _ = perCandidate.Named("CandidateAttemptBudget", "preauth_bytes").Uint()
		attemptBudget.CandidateWorkUnits, _ = perCandidate.Named("CandidateAttemptBudget", "work_units").Uint()
		attemptBudget.TotalAddressAttempts, _ = budget.Named("PoolAttemptBudget", "total_address_attempts").Uint()
		attemptBudget.TotalPreauthBytes, _ = budget.Named("PoolAttemptBudget", "total_preauth_bytes").Uint()
		attemptBudget.TotalWorkUnits, _ = budget.Named("PoolAttemptBudget", "total_work_units").Uint()
		attemptBudget.ParallelCandidates, _ = budget.Named("PoolAttemptBudget", "parallel_candidates").Uint()
		winnerAuthority, _ = reference.Named("PoolSelectionRef", "once_authority_ref").Named("OnceAuthorityRef", "winner_authority_id").Text()
	}
	proofDigest, err := fullMapDigest("activation_digest", "ActivationAuthorization", proof.document.Bytes())
	if err != nil {
		return nil, err
	}
	result := &ActivationBinding{artifactDigest: artifactDigest, proofDigest: proofDigest, winner: winner, source: source, activationEnd: activationEnd, sessionEnd: sessionEnd, poolBudget: attemptBudget, winnerAuthority: winnerAuthority, artifactKey: artifact.key, proofKey: proof.key}
	if source == "preauthorized_pool" {
		set, _ := child("candidate_selection").Named("PoolSelectionRef", "candidate_set_digest").ByteString()
		routes, _ := child("route_selection").ByteString()
		result.candidateSetDigest, result.routeSetDigest = [32]byte(set), [32]byte(routes)
	}
	result.tenant, _ = parent("tenant_id").Text()
	result.audience, _ = parent("audience").Text()
	result.profile, _ = parent("crypto_profile_id").Text()
	result.authority, _ = child("authority_id").Text()
	result.signingKey, _ = child("signing_key_id").Text()
	result.issuedAt, _ = child("issued_at_ms").Uint()
	issuer, _ := parent("issuer_key_id").ByteString()
	lease, _ := parent("lease_id").ByteString()
	attempt, _ := child("attempt_id").ByteString()
	result.issuer, result.lease, result.attempt = [16]byte(issuer), [16]byte(lease), [16]byte(attempt)
	nonce, _ := parent("session_nonce").ByteString()
	client, _ := parent("client_identity_digest").ByteString()
	server, _ := parent("server_identity_digest").ByteString()
	result.sessionNonce, result.clientDigest, result.serverDigest = [32]byte(nonce), [32]byte(client), [32]byte(server)
	return result, nil
}

func (b *ActivationBinding) Winner() PoolMember { return b.winner }
func (b *ActivationBinding) Digests() (artifact, proof [32]byte) {
	return b.artifactDigest, b.proofDigest
}
func (b *ActivationBinding) Deadlines() (activation, session uint64) {
	return b.activationEnd, b.sessionEnd
}

// MatchCertificates closes the complete material set before irreversible
// consumption. Current trust is checked by the original subscriptions; these
// digests prevent swapping any signed certificate after that check.
func (b *ActivationBinding) MatchCertificates(client, server *SignedMap) error {
	if b == nil || client == nil || server == nil {
		return CBORFailure("activation_owner")
	}
	for i, cert := range []*SignedMap{client, server} {
		if cert.codec.schema != "IdentityCertificate" {
			return CBORFailure("admission_identity_binding")
		}
		digest, err := cert.Digest("certificate_digest")
		if err != nil {
			return err
		}
		want := b.clientDigest
		if i == 1 {
			want = b.serverDigest
		}
		if digest != want {
			return CBORFailure("admission_identity_binding")
		}
	}
	return nil
}

// MatchFSB binds an independently signature-checked client certificate and FSB
// to this exact original authorization. Only after this binding and independent
// current trust/carrier/hello validation may the Acceptor attempt admission CAS.
func (b *ActivationBinding) MatchFSB(fsb, certificate *SignedMap) ([32]byte, error) {
	var zero [32]byte
	if b == nil || fsb == nil || certificate == nil || fsb.codec.schema != "FSB4" || certificate.codec.schema != "IdentityCertificate" {
		return zero, CBORFailure("admission_owner")
	}
	f, c := fsb.codec, certificate.codec
	f.mu.Lock()
	defer f.mu.Unlock()
	c.mu.Lock()
	defer c.mu.Unlock()
	if f.current != fsb || c.current != certificate || fsb.activationSourceProfile != b.source {
		return zero, CBORFailure("admission_owner")
	}
	context := DecodeContext{Selectors: map[string]string{"activation_source_profile": b.source}}
	if err := fsb.document.ValidateRules(context); err != nil {
		return zero, err
	}
	if err := certificate.document.ValidateRules(context); err != nil {
		return zero, err
	}
	root, cert := fsb.document.Root(), certificate.document.Root()
	get := func(name string) Value { return root.Named("FSB4", name) }
	for _, pair := range []struct {
		name string
		want []byte
	}{
		{"artifact_digest", b.artifactDigest[:]}, {"issuer_key_id", b.issuer[:]}, {"lease_id", b.lease[:]}, {"session_nonce", b.sessionNonce[:]}, {"candidate_id", b.winner.CandidateID[:]}, {"route_digest", b.winner.RouteDigest[:]}, {"attempt_id", b.attempt[:]}, {"client_certificate", certificate.document.Bytes()},
	} {
		value, _ := get(pair.name).ByteString()
		if !bytes.Equal(value, pair.want) {
			return zero, CBORFailure("admission_binding")
		}
	}
	tenant, _ := get("tenant_id").Text()
	if tenant != b.tenant {
		return zero, CBORFailure("admission_binding")
	}
	proof, _ := get("activation_authorization").ByteString()
	digest, err := fullMapDigest("activation_digest", "ActivationAuthorization", proof)
	if err != nil {
		return zero, err
	}
	if digest != b.proofDigest {
		return zero, CBORFailure("admission_proof_binding")
	}
	digest, err = fullMapDigest("certificate_digest", "IdentityCertificate", certificate.document.Bytes())
	if err != nil {
		return zero, err
	}
	if digest != b.clientDigest {
		return zero, CBORFailure("admission_identity_binding")
	}
	for _, pair := range []struct{ name, want string }{{"tenant_id", b.tenant}, {"audience", b.audience}, {"crypto_profile_id", b.profile}} {
		value, _ := cert.Named("IdentityCertificate", pair.name).Text()
		if value != pair.want {
			return zero, CBORFailure("admission_identity_binding")
		}
	}
	role, _ := cert.Named("IdentityCertificate", "role").Uint()
	key, _ := cert.Named("IdentityCertificate", "ed25519_public_key").ByteString()
	if role != 0 || !bytes.Equal(key, fsb.key[:]) {
		return zero, CBORFailure("admission_identity_binding")
	}
	return fullMapDigest("admission_binding", "FSB4", fsb.document.Bytes())
}
