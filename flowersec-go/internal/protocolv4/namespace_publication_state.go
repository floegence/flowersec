package protocolv4

import (
	"bytes"
	"math"
	"strings"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// PublicationCapacity describes the independently fixed physical envelope.
// It is local configuration, never an authority learned from State bytes.
func (r *NamespaceRules) PublicationCapacity() (stateBytes, headBytes uint64) {
	if r == nil {
		return 0, 0
	}
	return r.stateBytes, r.headBytes
}

func (r *NamespaceRules) PublicationScope(generation uint64) NamespacePublicationScope {
	if r == nil {
		return NamespacePublicationScope{}
	}
	return NamespacePublicationScope{r.tenant, r.authority, r.capacityDigest, generation}
}

// BindPublicationState validates an unsigned authority State for storage. The
// private synthetic Head supplies only the existing State validator's binding
// context; it is never signed, exported or usable for consumer authorization.
// Independent mutation permission and durable CAS remain the authority's job.
func (w *RevocationWorkspace) BindPublicationState(input []byte, generation, version uint64, now timev4.Interval) (*NamespaceState, error) {
	if w == nil || generation == 0 || version == 0 || now.LowerMS > now.UpperMS || now.UpperMS == math.MaxUint64 {
		return nil, CBORFailure("revocation_publication_snapshot")
	}
	r := w.rules
	// Reuse the original decoder for field extraction, then release it before
	// Bind creates the sole retained validation document in the same arena.
	w.mu.Lock()
	if w.current != nil || w.owner != nil || w.decoder == nil {
		w.mu.Unlock()
		return nil, CBORFailure("revocation_state_owner")
	}
	if err := w.reservation.Check(); err != nil {
		w.mu.Unlock()
		return nil, err
	}
	doc, err := w.decoder.DecodeMap(input, "RevocationState", DecodeContext{Limits: r.limits})
	if err != nil {
		w.mu.Unlock()
		return nil, err
	}
	root := doc.Root()
	if !r.matchesNamespace(root, "RevocationState") || !r.matchesPublication(root, "RevocationState") || valueUint(root, "RevocationState", "authority_generation") != generation {
		doc.Release()
		w.mu.Unlock()
		return nil, CBORFailure("revocation_namespace_binding")
	}
	digest, err := fullMapDigest("revocation_state_digest", "RevocationState", doc.Bytes())
	if err != nil {
		doc.Release()
		w.mu.Unlock()
		return nil, err
	}
	head := &NamespaceHead{rules: r, generation: generation, sequence: version, stateBytes: uint64(len(input)), stateDigest: digest, issued: now.LowerMS, next: now.UpperMS + 1, signerEnd: math.MaxUint64, trustEnd: math.MaxUint64}
	head.schema, _ = root.Named("RevocationState", "schema_revision").Text()
	head.schema = strings.Clone(head.schema)
	root.Named("RevocationState", "credential_revocation_floors").CopyUints(head.floors[:])
	fields := publicationHeadFields(root, version, now.LowerMS, now.UpperMS+1, digest, uint64(len(input)), [16]byte{}, [32]byte{})
	var complete [16]Field
	copy(complete[:], fields[:])
	var signature [64]byte
	complete[15] = Field{Name: "signature", Kind: ByteString, Bytes: signature[:]}
	maximum, e := SchemaByteLimit("FreshnessHead")
	if e == nil {
		head.bytes, e = EncodeMap(make([]byte, maximum), "FreshnessHead", complete[:])
	}
	doc.Release()
	w.mu.Unlock()
	if e != nil {
		return nil, e
	}
	if err = head.CheckTime(now); err != nil {
		return nil, err
	}
	head.authorityStateOnly = true
	return w.Bind(head, input)
}

// CheckPublicationScope prevents an authority store from continuing its old
// generation after an independent emergency trust update.
func (t *NamespaceTrustStore) CheckPublicationScope(scope NamespacePublicationScope) error {
	if t == nil {
		return CBORFailure("revocation_trust_binding")
	}
	sample, sampleErr := t.sampleCurrent()
	if sampleErr != nil {
		err := sampleErr
		return err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.checkCurrentLockedAt(sample); err != nil {
		return err
	}
	if t.rules.PublicationScope(t.configurations[t.count-1].generation) != scope {
		return CBORFailure("revocation_trust_binding")
	}
	return nil
}

// CommitPublication serializes a final bounded storage COMMIT with independent
// emergency trust publication. It is called only by the installed authority
// adapter after all external work. commit may not call trust, application code,
// a signer or another owner. No revocation write lock is held during signing.
// A nil Head is restricted to unsigned authority State mutation.
func (t *NamespaceTrustStore) CommitPublication(scope NamespacePublicationScope, head []byte, commit func() error) error {
	if t == nil || commit == nil {
		return CBORFailure("revocation_publication_owner")
	}
	var signer [16]byte
	var digest [32]byte
	if len(head) != 0 {
		d, err := boundedMap(head, "FreshnessHead")
		if err != nil {
			return err
		}
		signer = trust16(d.Root(), "FreshnessHead", "signing_key_id")
		digest = trust32(d.Root(), "FreshnessHead", "signer_delegation_digest")
		d.Release()
	}
	sample, sampleErr := t.sampleCurrent()
	if sampleErr != nil {
		err := sampleErr
		return err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.checkCurrentLockedAt(sample); err != nil {
		return err
	}
	c := &t.configurations[t.count-1]
	if t.rules.PublicationScope(c.generation) != scope {
		return CBORFailure("revocation_trust_binding")
	}
	if len(head) != 0 {
		if includesTrustID(c.rejectedHeads, signer) {
			return CBORFailure("revocation_trust_binding")
		}
		allowed := false
		for _, h := range c.heads {
			if h.signer == signer && h.digest == digest {
				allowed = true
				break
			}
		}
		if !allowed {
			return CBORFailure("revocation_trust_binding")
		}
	}
	return commit()
}

// CopyPublicationTrust copies the complete independently signed current trust
// configuration. Distribution ACL is checked by the authority service, never
// inferred from this local trust reference or a matching namespace identifier.
func (t *NamespaceTrustStore) CopyPublicationTrust(scope NamespacePublicationScope, dst []byte) (int, error) {
	if t == nil {
		return 0, CBORFailure("revocation_trust_binding")
	}
	sample, sampleErr := t.sampleCurrent()
	if sampleErr != nil {
		err := sampleErr
		return 0, err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.checkCurrentLockedAt(sample); err != nil {
		return 0, err
	}
	c := &t.configurations[t.count-1]
	if t.rules.PublicationScope(c.generation) != scope {
		return 0, CBORFailure("revocation_trust_binding")
	}
	wire, err := c.signed.Bytes()
	if err != nil {
		return 0, err
	}
	if len(dst) < len(wire) {
		return 0, CBORFailure("configuration_capacity")
	}
	return copy(dst, wire), nil
}

// CheckPublicationTrust fences a response carrying an older configuration
// when independent trust changes during its original signing/publication work.
func (t *NamespaceTrustStore) CheckPublicationTrust(scope NamespacePublicationScope, original []byte) error {
	if t == nil {
		return CBORFailure("revocation_trust_binding")
	}
	sample, sampleErr := t.sampleCurrent()
	if sampleErr != nil {
		err := sampleErr
		return err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.checkCurrentLockedAt(sample); err != nil {
		return err
	}
	c := &t.configurations[t.count-1]
	if t.rules.PublicationScope(c.generation) != scope {
		return CBORFailure("revocation_trust_binding")
	}
	wire, err := c.signed.Bytes()
	if err != nil {
		return err
	}
	if !bytes.Equal(wire, original) {
		return CBORFailure("revocation_trust_binding")
	}
	return nil
}

// PublicationRoot identifies the separately installed bootstrap authority;
// a Head signer can neither select this key nor manufacture a cold-start proof.
func (t *NamespaceTrustStore) PublicationRoot(scope NamespacePublicationScope) (NamespaceTrustRoot, error) {
	if t == nil {
		return NamespaceTrustRoot{}, CBORFailure("revocation_trust_binding")
	}
	sample, sampleErr := t.sampleCurrent()
	if sampleErr != nil {
		err := sampleErr
		return NamespaceTrustRoot{}, err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.checkCurrentLockedAt(sample); err != nil {
		return NamespaceTrustRoot{}, err
	}
	if t.rules.PublicationScope(t.configurations[t.count-1].generation) != scope {
		return NamespaceTrustRoot{}, CBORFailure("revocation_trust_binding")
	}
	return t.root, nil
}

// CheckPublicationHead rechecks the original already-verified publication's
// current independent signer authority before a delayed service disclosure.
// The containing store has verified the signature and complete matching State.
func (t *NamespaceTrustStore) CheckPublicationHead(scope NamespacePublicationScope, wire []byte) error {
	if t == nil {
		return CBORFailure("revocation_trust_binding")
	}
	d, err := boundedMap(wire, "FreshnessHead")
	if err != nil {
		return err
	}
	defer d.Release()
	signer := trust16(d.Root(), "FreshnessHead", "signing_key_id")
	digest := trust32(d.Root(), "FreshnessHead", "signer_delegation_digest")
	sample, sampleErr := t.sampleCurrent()
	if sampleErr != nil {
		err := sampleErr
		return err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if err = t.checkCurrentLockedAt(sample); err != nil {
		return err
	}
	c := &t.configurations[t.count-1]
	if t.rules.PublicationScope(c.generation) != scope || includesTrustID(c.rejectedHeads, signer) {
		return CBORFailure("revocation_trust_binding")
	}
	for i, h := range c.heads {
		if h.signer != signer || h.digest != digest {
			continue
		}
		delegation := c.signed.Field("head_delegations").Index(i)
		now := sample
		end := min(valueUint(d.Root(), "FreshnessHead", "next_update_ms"), valueUint(delegation, "HeadSignerDelegation", "not_after_ms"), c.end)
		if !now.Interval.ValidBefore(end) {
			return timev4.ErrExpired
		}
		return now.Interval.LowerBound(max(c.issued, valueUint(d.Root(), "FreshnessHead", "this_update_ms"), valueUint(delegation, "HeadSignerDelegation", "issued_at_ms")), true)
	}
	return CBORFailure("revocation_trust_binding")
}

// CheckPublicationSuccessor applies the same retained-evidence/cohort rules as
// consumers, with permanently retired issuers obtained from independent trust.
func (s *NamespaceState) CheckPublicationSuccessor(next *NamespaceState, trust *NamespaceTrustStore) error {
	if trust == nil {
		return CBORFailure("revocation_trust_binding")
	}
	sample, err := trust.sampleCurrent()
	if err != nil {
		return err
	}
	trust.mu.Lock()
	defer trust.mu.Unlock()
	if err := trust.checkCurrentLockedAt(sample); err != nil {
		return err
	}
	current := &trust.configurations[trust.count-1]
	if next == nil || next.head == nil || current.generation != next.head.generation {
		return CBORFailure("revocation_trust_binding")
	}
	return s.CheckSuccessor(next, current.retired)
}

func (s *NamespaceState) PublicationDigest() [32]byte {
	if s == nil || s.workspace == nil {
		return [32]byte{}
	}
	s.workspace.mu.Lock()
	defer s.workspace.mu.Unlock()
	if s.workspace.current != s {
		return [32]byte{}
	}
	return s.head.stateDigest
}

// ValidatePublicationPair reuses current independent delegation verification and
// the complete State validator; storage cannot accept caller-declared digests.
func (t *NamespaceTrustStore) ValidatePublicationPair(codec *SignedMapCodec, decoder *Decoder, workspace *RevocationWorkspace, state, wire []byte, expected NamespacePublicationVersion) error {
	if t == nil || codec == nil || decoder == nil || workspace == nil {
		return CBORFailure("revocation_publication_snapshot")
	}
	head, err := t.bindHead(decoder, codec, nil, wire)
	if err != nil {
		return err
	}
	if head.sequence != expected.Sequence || head.digest != expected.HeadDigest || head.stateDigest != expected.StateDigest || head.issued != expected.ThisUpdateMS || head.next != expected.NextUpdateMS {
		return CBORFailure("revocation_publication_snapshot")
	}
	now, err := t.clock.Sample()
	if err != nil {
		return err
	}
	if err = head.CheckTime(now.Interval); err != nil {
		return err
	}
	bound, err := workspace.Bind(head, state)
	if err != nil {
		return err
	}
	defer bound.Release()
	return t.StateHistory(bound)
}
