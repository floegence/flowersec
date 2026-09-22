package protocolv4

// AdmissionFacts is an immutable, detached projection of the verified original
// FSB/activation/Hello binding. It contains no durable receipt or start guard.
// The Acceptor must independently check current trust, time and actual carrier
// facts before using it at its original AdmissionLedger boundary.
type AdmissionFacts struct {
	fields AdmissionFields
	valid  bool
}

// AdmissionFields is a detached inspection value. Mutating it cannot change
// AdmissionFacts or manufacture a verified original for a ledger constructor.
type AdmissionFields struct {
	Tenant, Audience, Profile, Source, SpendAuthority, WinnerAuthority, SigningKey string
	Issuer, Lease, Attempt, Candidate                                              [16]byte
	Artifact, Proof, SessionNonce, ClientIdentity, ServerIdentity                  [32]byte
	AdmissionBinding, HelloTranscript, TransportContext, AdmissionNonce            [32]byte
	Route                                                                          [32]byte
	CandidateIndex, IssuedAt, ActivationEnd, SessionEnd, Features, BindingMode     uint64
}

func (h *HelloBinding) AdmissionFacts(activation *ActivationBinding, fsb, certificate *SignedMap) (AdmissionFacts, error) {
	digest, err := h.MatchFSB(activation, fsb, certificate)
	if err != nil {
		return AdmissionFacts{}, err
	}
	c := fsb.codec
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.current != fsb {
		return AdmissionFacts{}, CBORFailure("admission_owner")
	}
	nonce, ok := fsb.document.Root().Named("FSB4", "admission_nonce").ByteString()
	if !ok || len(nonce) != 32 {
		return AdmissionFacts{}, CBORFailure("admission_binding")
	}
	b := activation
	return AdmissionFacts{valid: true, fields: AdmissionFields{
		Tenant: b.tenant, Audience: b.audience, Profile: b.profile, Source: b.source,
		SpendAuthority: b.authority, WinnerAuthority: b.winnerAuthority, SigningKey: b.signingKey,
		Issuer: b.issuer, Lease: b.lease, Attempt: b.attempt, Candidate: b.winner.CandidateID,
		Artifact: b.artifactDigest, Proof: b.proofDigest, SessionNonce: b.sessionNonce,
		ClientIdentity: b.clientDigest, ServerIdentity: b.serverDigest,
		AdmissionBinding: digest, HelloTranscript: h.transcript, TransportContext: h.transport,
		AdmissionNonce: [32]byte(nonce), Route: b.winner.RouteDigest,
		CandidateIndex: b.winner.Index, IssuedAt: b.issuedAt, ActivationEnd: b.activationEnd,
		SessionEnd: b.sessionEnd, Features: h.features, BindingMode: h.mode,
	}}, nil
}

func (f AdmissionFacts) Fields() (AdmissionFields, error) {
	if !f.valid {
		return AdmissionFields{}, CBORFailure("admission_owner")
	}
	return f.fields, nil
}
