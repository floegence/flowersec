package protocolv4

import (
	"bytes"
	"encoding/json"
	"math"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

// NamespaceRules fixes the complete original capacity and publication mapping.
// The Environment must obtain both from its independent trusted namespace
// mapping before construction. Network objects cannot replace that mapping.
// These immutable rules do not authenticate TrustConfig or grant admission.
type NamespaceRules struct {
	tenant, authority, policy string
	policyRevision            uint64
	capacityDigest            [32]byte
	capacity, publication     []byte
	limits                    map[string]uint64
	stateBytes, headBytes     uint64
	trustBytes, trustEntries  uint64
	origin, duration          uint64
	impact                    [2]uint64
	headValidity, signerLife  uint64
}

type namespaceParameter struct {
	CapacityField     string `json:"capacity_field"`
	Divisor           uint64
	ByteCapacityField string `json:"byte_capacity_field"`
	MinimumItemBytes  uint64 `json:"minimum_item_bytes"`
	Unit              string
}

var namespaceParameters = sync.OnceValues(func() (map[string]namespaceParameter, error) {
	var registry struct {
		Parameters map[string]namespaceParameter `json:"validation_parameters"`
	}
	if err := json.Unmarshal([]byte(RevocationRegistryJSON), &registry); err != nil || len(registry.Parameters) == 0 {
		return nil, CBORFailure("registry_unresolved")
	}
	return registry.Parameters, nil
})

func boundedMap(input []byte, schema string) (*Document, error) {
	maximum, err := SchemaByteLimit(schema)
	if err != nil {
		return nil, err
	}
	if len(input) == 0 || len(input) > maximum {
		return nil, CBORFailure("map_size")
	}
	d, err := NewDecoder(maximum, maximum)
	if err != nil {
		return nil, err
	}
	return d.DecodeMap(input, schema, DecodeContext{})
}

func valueUint(v Value, schema, field string) uint64 {
	n, _ := v.Named(schema, field).Uint()
	return n
}

func namespaceAdd(a, b uint64) (uint64, error) {
	if a > math.MaxUint64-b {
		return 0, CBORFailure("revocation_overflow")
	}
	return a + b, nil
}

// NewNamespaceRules copies original bytes. Exact comparison is available for
// trust refreshes; matching names or revisions never permits changed contents.
func NewNamespaceRules(capacity, publication []byte) (*NamespaceRules, error) {
	c, err := boundedMap(capacity, "NamespaceCapacity")
	if err != nil {
		return nil, err
	}
	defer c.Release()
	p, err := boundedMap(publication, "PublicationPolicy")
	if err != nil {
		return nil, err
	}
	defer p.Release()
	root := c.Root()
	number := func(name string) uint64 { return valueUint(root, "NamespaceCapacity", name) }
	if number("max_state_encoded_bytes") > math.MaxUint32 || number("max_state_encoded_bytes") > math.MaxInt {
		return nil, CBORFailure("revocation_parser_capacity")
	}
	r := &NamespaceRules{limits: make(map[string]uint64), stateBytes: number("max_state_encoded_bytes"), headBytes: number("max_head_encoded_bytes"), trustBytes: number("max_trust_proof_bytes"), trustEntries: number("max_trust_proof_entries"), origin: number("cohort_time_origin_ms"), duration: number("cohort_duration_ms"), impact: [2]uint64{number("max_certificate_impact_ms"), number("max_connection_impact_ms")}}
	r.tenant, _ = root.Named("NamespaceCapacity", "tenant_id").Text()
	r.authority, _ = root.Named("NamespaceCapacity", "revocation_authority_id").Text()
	r.policy, _ = p.Root().Named("PublicationPolicy", "publication_policy_id").Text()
	r.policyRevision = valueUint(p.Root(), "PublicationPolicy", "publication_policy_revision")
	r.headValidity = valueUint(p.Root(), "PublicationPolicy", "max_head_validity_ms")
	r.signerLife = valueUint(p.Root(), "PublicationPolicy", "max_signer_lifetime_ms")
	r.capacityDigest, err = fullMapDigest("namespace_capacity_digest", "NamespaceCapacity", c.Bytes())
	if err != nil {
		return nil, err
	}
	parameters, err := namespaceParameters()
	if err != nil {
		return nil, err
	}
	for name, parameter := range parameters {
		if parameter.CapacityField == "" {
			continue
		}
		if parameter.Divisor == 0 || parameter.ByteCapacityField != "" && parameter.MinimumItemBytes == 0 {
			return nil, CBORFailure("registry_unresolved")
		}
		bound := number(parameter.CapacityField) / parameter.Divisor
		if parameter.ByteCapacityField != "" {
			bound = min(bound, number(parameter.ByteCapacityField)/parameter.MinimumItemBytes)
		}
		if bound > math.MaxUint32 || parameter.Unit == "bytes" && bound == 0 {
			return nil, CBORFailure("revocation_parser_capacity")
		}
		r.limits[name] = bound
	}
	r.capacity, r.publication = bytes.Clone(c.Bytes()), bytes.Clone(p.Bytes())
	return r, nil
}

func (r *NamespaceRules) Matches(capacity, publication []byte) bool {
	return r != nil && bytes.Equal(capacity, r.capacity) && bytes.Equal(publication, r.publication)
}

func (r *NamespaceRules) cohortEnd(cohort uint64) (uint64, error) {
	n, err := namespaceAdd(cohort, 1)
	if err != nil || n > math.MaxUint64/r.duration {
		return 0, CBORFailure("revocation_overflow")
	}
	return namespaceAdd(r.origin, n*r.duration)
}

func (r *NamespaceRules) mature(class int, cohort uint64) (uint64, error) {
	end, err := r.cohortEnd(cohort)
	if err != nil {
		return 0, err
	}
	return namespaceAdd(end, r.impact[class])
}

func (r *NamespaceRules) matchesNamespace(root Value, schema string) bool {
	tenant, _ := root.Named(schema, "tenant_id").Text()
	authority, _ := root.Named(schema, "revocation_authority_id").Text()
	digest, _ := root.Named(schema, "namespace_capacity_digest").ByteString()
	return tenant == r.tenant && authority == r.authority && bytes.Equal(digest, r.capacityDigest[:])
}

func (r *NamespaceRules) matchesPublication(root Value, schema string) bool {
	policy, _ := root.Named(schema, "publication_policy_id").Text()
	return policy == r.policy && valueUint(root, schema, "publication_policy_revision") == r.policyRevision
}

// NamespaceHead owns a detached original signed Head and its exact delegation.
// It is a signature/binding fact, never independent trust or a complete State.
// A pending lower-bound result may occupy only the original namespace pin; it
// cannot advance observed or authorize a Session until CheckTime succeeds.
type NamespaceHead struct {
	rules                   *NamespaceRules
	schema                  string
	bytes, delegation       []byte
	digest, stateDigest     [32]byte
	delegationDigest        [32]byte
	signerID                [16]byte
	generation, sequence    uint64
	floors                  [2]uint64
	stateBytes              uint64
	issued, next, signerEnd uint64
	trustIssued, trustEnd   uint64
	delegationIssued        uint64
}

// NamespaceHeadBackingBytes includes both original maps, the detached object
// and the bounded temporary delegation decoder used by BindHead. A containing
// owner must separately reserve the input SignedMapCodec and all live copies.
func NamespaceHeadBackingBytes() (uint64, error) {
	d, err := SchemaByteLimit("HeadSignerDelegation")
	if err != nil {
		return 0, err
	}
	h, err := SchemaByteLimit("FreshnessHead")
	if err != nil {
		return 0, err
	}
	workspace, err := DecoderBackingBytes(d, d)
	// The detached schema text is an additional copy bounded by the Head map.
	return workspace + uint64(d+2*h) + uint64(unsafe.Sizeof(NamespaceHead{})), err
}

// BindHead consumes a verified original signature and an independently
// authenticated original delegation for the selected trust generation. The
// trust owner supplies its original issuance/expiry, never a peer's assertion.
// The actual verified Ed25519 key must equal the delegation's exact public key.
func (r *NamespaceRules) BindHead(head *SignedMap, delegation []byte, generation, trustIssued, trustEnd uint64) (*NamespaceHead, error) {
	if r == nil || head == nil || head.codec.schema != "FreshnessHead" || trustIssued >= trustEnd || uint64(len(delegation)) > r.trustBytes || r.trustEntries == 0 {
		return nil, CBORFailure("revocation_trust_binding")
	}
	d, err := boundedMap(delegation, "HeadSignerDelegation")
	if err != nil {
		return nil, err
	}
	defer d.Release()
	c := head.codec
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.current != head {
		return nil, CBORFailure("revocation_head_owner")
	}
	if err := head.document.ValidateRules(DecodeContext{}); err != nil {
		return nil, err
	}
	h, entry := head.document.Root(), d.Root()
	if !r.matchesNamespace(h, "FreshnessHead") || !r.matchesNamespace(entry, "HeadSignerDelegation") || !r.matchesPublication(h, "FreshnessHead") || !r.matchesPublication(entry, "HeadSignerDelegation") {
		return nil, CBORFailure("revocation_namespace_binding")
	}
	if valueUint(h, "FreshnessHead", "authority_generation") != generation || valueUint(entry, "HeadSignerDelegation", "authority_generation") != generation || !bytes.Equal(h.Named("FreshnessHead", "schema_revision").Encoded(), entry.Named("HeadSignerDelegation", "schema_revision").Encoded()) {
		return nil, CBORFailure("revocation_delegation_binding")
	}
	key, _ := entry.Named("HeadSignerDelegation", "signer_public_key").ByteString()
	if !bytes.Equal(key, head.key[:]) || !bytes.Equal(h.Named("FreshnessHead", "signing_key_id").Encoded(), entry.Named("HeadSignerDelegation", "signer_key_id").Encoded()) {
		return nil, CBORFailure("revocation_signer_key")
	}
	digest, err := fullMapDigest("head_signer_delegation_digest", "HeadSignerDelegation", d.Bytes())
	if err != nil {
		return nil, err
	}
	declared, _ := h.Named("FreshnessHead", "signer_delegation_digest").ByteString()
	if !bytes.Equal(digest[:], declared) {
		return nil, CBORFailure("revocation_delegation_digest")
	}
	issued := valueUint(entry, "HeadSignerDelegation", "issued_at_ms")
	notBefore := valueUint(entry, "HeadSignerDelegation", "not_before_ms")
	notAfter := valueUint(entry, "HeadSignerDelegation", "not_after_ms")
	lifetimeEnd, err := namespaceAdd(issued, r.signerLife)
	if err != nil {
		return nil, err
	}
	if notBefore > issued || issued >= notAfter || notAfter > lifetimeEnd {
		return nil, CBORFailure("revocation_delegation_lifetime")
	}
	result := &NamespaceHead{rules: r, generation: generation, sequence: valueUint(h, "FreshnessHead", "head_sequence"), stateBytes: valueUint(h, "FreshnessHead", "state_encoded_bytes"), issued: valueUint(h, "FreshnessHead", "this_update_ms"), next: valueUint(h, "FreshnessHead", "next_update_ms"), signerEnd: notAfter, trustIssued: trustIssued, trustEnd: trustEnd, delegationIssued: issued}
	if uint64(len(head.document.Bytes())) > r.headBytes || result.stateBytes > r.stateBytes {
		return nil, CBORFailure("revocation_head_capacity")
	}
	if result.issued < issued || result.issued >= notAfter || result.next <= result.issued || result.next-result.issued > r.headValidity {
		return nil, CBORFailure("revocation_head_issuance")
	}
	result.digest, err = fullMapDigest("freshness_head_digest", "FreshnessHead", head.document.Bytes())
	if err != nil {
		return nil, err
	}
	state, _ := h.Named("FreshnessHead", "state_digest").ByteString()
	signer, _ := h.Named("FreshnessHead", "signing_key_id").ByteString()
	copy(result.signerID[:], signer)
	result.delegationDigest = digest
	result.schema, _ = h.Named("FreshnessHead", "schema_revision").Text()
	copy(result.stateDigest[:], state)
	h.Named("FreshnessHead", "credential_revocation_floors").CopyUints(result.floors[:])
	result.bytes, result.delegation = bytes.Clone(head.document.Bytes()), bytes.Clone(d.Bytes())
	return result, nil
}

func (h *NamespaceHead) CheckTime(now timev4.Interval) error {
	if h == nil || !now.ValidBefore(min(h.next, h.signerEnd, h.trustEnd)) {
		return timev4.ErrExpired
	}
	if err := now.LowerBound(max(h.issued, h.delegationIssued, h.trustIssued), true); err != nil {
		return err
	}
	for class, floor := range h.floors {
		if floor == 0 {
			continue
		}
		mature, err := h.rules.mature(class, floor-1)
		if err != nil {
			return err
		}
		if err := now.LowerBound(mature, true); err != nil {
			return err
		}
	}
	return nil
}

// Follows checks the sole same-generation high-water mark. A new generation
// requires an independent trust retirement/bootstrap, not this method.
func (h *NamespaceHead) Follows(previous *NamespaceHead, now timev4.Interval) error {
	if err := h.CheckTime(now); err != nil {
		return err
	}
	return h.follows(previous)
}

func (h *NamespaceHead) follows(previous *NamespaceHead) error {
	if previous == nil {
		return nil
	}
	if h.rules != previous.rules || h.schema != previous.schema || h.generation != previous.generation || h.sequence < previous.sequence {
		return CBORFailure("revocation_head_rollback")
	}
	if h.sequence == previous.sequence && !bytes.Equal(h.bytes, previous.bytes) {
		return CBORFailure("revocation_head_equivocation")
	}
	for class, floor := range h.floors {
		if floor < previous.floors[class] {
			return CBORFailure("revocation_floor_rollback")
		}
	}
	return nil
}

// Deadline applies this authorization's already resolved role-closure numeric
// requirements without changing the shared Head or any subscriber's deadline.
func (h *NamespaceHead) Deadline(staleness, signerLifetime, credentialEnd uint64, now timev4.Interval) (uint64, error) {
	if h == nil || staleness == 0 || signerLifetime == 0 || credentialEnd == 0 {
		return 0, CBORFailure("revocation_requirement")
	}
	if h.rules.signerLife > signerLifetime {
		return 0, CBORFailure("revocation_policy_incompatible")
	}
	if err := h.CheckTime(now); err != nil {
		return 0, err
	}
	end, err := namespaceAdd(h.issued, staleness)
	if err != nil {
		return 0, err
	}
	end = min(end, h.next, h.signerEnd, h.trustEnd, credentialEnd)
	if !now.ValidBefore(end) {
		return 0, timev4.ErrExpired
	}
	return end, nil
}
