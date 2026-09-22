package protocolv4

// SessionLimits is a detached view of the complete signed SessionContract.
// Zero streams and zero credit are values, never requests for defaults.
type SessionLimits struct {
	MaxFrame, MaxStreams      uint32
	MaxCredit, IdleDurationMS uint64
	Rekey                     RekeyEnvelope
	ApplicationProfile        string
	RPCMaxGeneralOutstanding  uint16
}

type RekeyEnvelope struct {
	Burst                    uint16
	RefillMS, RequestStartMS uint32
}

// SessionContract retains only validated scalar values and the registered
// digest. It contains no decoder aliases, credentials or admission authority.
// Copies preserve the same immutable contract; Limits returns a value copy.
type SessionContract struct {
	limits SessionLimits
	digest [32]byte
	valid  bool
}

func (c SessionContract) Limits() SessionLimits { return c.limits }
func (c SessionContract) Digest() [32]byte      { return c.digest }
func (c SessionContract) Valid() bool           { return c.valid }

// ArtifactSessionParameters is available before spend/admission. The original
// signed service span is distinct from a later activation/certificate cap.
// This projection does not establish issuer trust, freshness or consumption.
type ArtifactSessionParameters struct {
	Contract                      SessionContract
	ArtifactDigest                [32]byte
	Profile                       string
	IssuedAtMS, SessionNotAfterMS uint64
	Resume                        ResumePolicy
}

// ResumePolicy is the immutable signed issuance/input policy. A later Session
// may restrict new issuance without changing an existing token's expiry.
type ResumePolicy struct {
	Enabled                  bool
	MaxIssuedTokenDurationMS uint64
	MaxTokenBytes            uint32
}

func (m *SignedMap) SessionParameters() (ArtifactSessionParameters, error) {
	if m == nil || m.codec == nil || m.codec.schema != "Artifact" {
		return ArtifactSessionParameters{}, CBORFailure("artifact_owner")
	}
	m.codec.mu.Lock()
	defer m.codec.mu.Unlock()
	if m.codec.current != m {
		return ArtifactSessionParameters{}, CBORFailure("artifact_owner")
	}
	return m.sessionParametersLocked()
}

func (m *SignedMap) sessionParametersLocked() (p ArtifactSessionParameters, err error) {
	if err = m.document.ValidateRules(DecodeContext{}); err != nil {
		return p, err
	}
	parent := func(name string) Value { return m.document.Root().Named("Artifact", name) }
	p.Contract, err = sessionContract(parent("session_contract"))
	if err != nil {
		return p, err
	}
	p.ArtifactDigest, err = fullMapDigest("artifact_digest", "Artifact", m.document.Bytes())
	if err != nil {
		return p, err
	}
	p.Profile, _ = parent("crypto_profile_id").Text()
	p.IssuedAtMS, _ = parent("issued_at_ms").Uint()
	p.SessionNotAfterMS, _ = parent("session_not_after_ms").Uint()
	resume := parent("resume_policy")
	p.Resume.Enabled, _ = resume.Named("ResumePolicy", "enabled").Bool()
	if p.Resume.Enabled {
		p.Resume.MaxIssuedTokenDurationMS, _ = resume.Named("ResumePolicy", "max_issued_token_duration_ms").Uint()
		n, _ := resume.Named("ResumePolicy", "max_token_bytes").Uint()
		p.Resume.MaxTokenBytes = uint32(n)
	}
	return p, nil
}

// SessionContract projects a standalone canonical contract using the same
// generated rules as an Artifact. Parsing alone confers no signing authority.
// The caller retains the Document for this call and may release it afterward.
func (d *Document) SessionContract() (SessionContract, error) {
	if d == nil || d.schema != "SessionContract" || !d.Root().valid() {
		return SessionContract{}, CBORFailure("session_contract_owner")
	}
	if err := d.ValidateRules(DecodeContext{}); err != nil {
		return SessionContract{}, err
	}
	return sessionContract(d.Root())
}

func sessionContract(v Value) (c SessionContract, err error) {
	get := func(name string) uint64 { n, _ := v.Named("SessionContract", name).Uint(); return n }
	c.limits.MaxFrame, c.limits.MaxStreams = uint32(get("max_frame")), uint32(get("max_streams"))
	c.limits.MaxCredit, c.limits.IdleDurationMS = get("max_credit"), get("idle_duration_ms")
	c.limits.RPCMaxGeneralOutstanding = uint16(get("rpc_max_general_outstanding"))
	r, err := runtimeSchema()
	if err != nil {
		return c, err
	}
	for name, value := range r.Maps["SessionContract"].byName["application_profile"].Enum {
		if value == get("application_profile") {
			c.limits.ApplicationProfile = name
		}
	}
	if c.limits.ApplicationProfile == "" {
		return c, CBORFailure("registry_unresolved")
	}
	rekey := v.Named("SessionContract", "rekey_envelope")
	burst, _ := rekey.Named("RekeyEnvelope", "burst_rounds").Uint()
	refill, _ := rekey.Named("RekeyEnvelope", "refill_period_ms").Uint()
	start, _ := rekey.Named("RekeyEnvelope", "request_start_budget_ms").Uint()
	c.limits.Rekey = RekeyEnvelope{uint16(burst), uint32(refill), uint32(start)}
	c.digest, err = fullMapDigest("session_contract_digest", "SessionContract", v.Encoded())
	c.valid = err == nil
	return c, err
}

func SessionMaxStreams() (uint32, error) {
	r, err := runtimeSchema()
	if err != nil {
		return 0, err
	}
	f := r.Maps["SessionContract"].byName["max_streams"]
	if f == nil || f.Max == nil || uint64(*f.Max) > uint64(^uint32(0)) {
		return 0, CBORFailure("field_bound_unresolved")
	}
	return uint32(*f.Max), nil
}
