package protocolv4

// PoolSpendFacts can only be derived from the original signature-checked pool
// projection and independent authority binding. It has no activation right.
type PoolSpendFacts struct {
	fields PoolSpendFields
	valid  bool
}

// PoolSpendFields is a detached inspection copy. The proof digest commits to
// the entire issuance-time selection reference and signed attempt budget.
type PoolSpendFields struct {
	Tenant, Audience, Profile, SpendAuthority, WinnerAuthority, SigningKey string
	Issuer, Lease, Attempt                                                 [16]byte
	Artifact, Proof, SessionNonce, ClientIdentity, ServerIdentity          [32]byte
	CandidateSet, RouteSet                                                 [32]byte
	Winner                                                                 PoolMember
	Budget                                                                 PoolAttemptLimits
	IssuedAt, ActivationEnd, SessionEnd                                    uint64
}

func (a *ActivationAuthority) PoolSpendFacts(proof []byte) (PoolSpendFacts, error) {
	if a == nil || a.binding == nil || a.binding.source != "preauthorized_pool" {
		return PoolSpendFacts{}, CBORFailure("activation_source_profile")
	}
	if err := a.MatchProofBytes(proof); err != nil {
		return PoolSpendFacts{}, err
	}
	b := a.binding
	return PoolSpendFacts{valid: true, fields: PoolSpendFields{
		Tenant: b.tenant, Audience: b.audience, Profile: b.profile,
		SpendAuthority: b.authority, WinnerAuthority: b.winnerAuthority, SigningKey: b.signingKey,
		Issuer: b.issuer, Lease: b.lease, Attempt: b.attempt, Artifact: b.artifactDigest,
		Proof: b.proofDigest, SessionNonce: b.sessionNonce, ClientIdentity: b.clientDigest,
		ServerIdentity: b.serverDigest, CandidateSet: b.candidateSetDigest, RouteSet: b.routeSetDigest,
		Winner: b.winner, Budget: b.poolBudget, IssuedAt: b.issuedAt,
		ActivationEnd: b.activationEnd, SessionEnd: b.sessionEnd,
	}}, nil
}

func (f PoolSpendFacts) Fields() (PoolSpendFields, error) {
	if !f.valid {
		return PoolSpendFields{}, CBORFailure("activation_owner")
	}
	return f.fields, nil
}

// MatchProofBytes verifies the exact original issuance bytes before copying
// them into a durable consume projection. It neither signs nor rebuilds them.
func (f PoolSpendFacts) MatchProofBytes(proof []byte) error {
	if !f.valid {
		return CBORFailure("activation_owner")
	}
	digest, err := fullMapDigest("activation_digest", "ActivationAuthorization", proof)
	if err != nil {
		return err
	}
	if digest != f.fields.Proof {
		return CBORFailure("admission_proof_binding")
	}
	return nil
}
