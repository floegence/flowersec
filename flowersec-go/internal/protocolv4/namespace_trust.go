package protocolv4

import (
	"bytes"
	"strings"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

// NamespaceTrustRoot is an independently installed control trust anchor. No
// credential, Head, delegation or bootstrap response may select this key or
// change its exact namespace. MaxLifetimeMS is the deployment's finite bound
// on the independent authority's signing lifetime, not a local renewal period.
type NamespaceTrustRoot struct {
	Tenant, Authority string
	KeyID             [16]byte
	PublicKey         [32]byte
	MaxLifetimeMS     uint64
}
type NamespaceTrustLimits struct {
	Configurations        uint32
	ConfigBytes, MapNodes int
	RuntimeBytes          uint64
}

type trustedIssuer struct {
	id                                               [16]byte
	digest                                           [32]byte
	permission                                       IssuerPermission
	scope                                            CredentialScope
	first, last, lastExpiry, firstParent, lastParent uint64
}
type trustedHead struct {
	signer     [16]byte
	digest     [32]byte
	generation uint64
}
type trustedActivation struct{ binding ActivationTrustBinding }
type trustedOnce struct {
	issuer        [16]byte
	spend, winner string
}
type trustConfiguration struct {
	codec                             *SignedMapCodec
	signed                            *SignedMap
	digest                            [32]byte
	revision, generation, issued, end uint64
	encodedBytes, entries             uint64
	issuers                           []trustedIssuer
	heads                             []trustedHead
	activations                       []trustedActivation
	once                              []trustedOnce
	policies                          []*CredentialPolicy
	retired, rejectedHeads            [][16]byte
}

// NamespaceTrustStore is the bounded independent trust/history owner for one
// original namespace. Every accepted revision remains charged and immutable;
// capacity exhaustion refuses refresh instead of evicting security history.
// This local owner does not confer online bootstrap or durable-restore evidence.
// Those adapters must establish their original startup continuity separately.
type NamespaceTrustStore struct {
	mu                             sync.Mutex
	root                           NamespaceTrustRoot
	limits                         NamespaceTrustLimits
	clock                          *timev4.Clock
	configurations                 []trustConfiguration
	count                          int
	rules                          *NamespaceRules
	namespace                      *LiveNamespace
	reservation, dependencies      resourcev4.Reference
	bytes, entries                 uint64
	busy, closed, closing, retired bool
	bootstrap, bootstrapStarted    bool
}

func NamespaceTrustCharge(l NamespaceTrustLimits) (resourcev4.Vector, error) {
	if l.Configurations == 0 || l.Configurations > 64 || l.ConfigBytes < 1024 || l.ConfigBytes > 262144 || l.MapNodes < 1 || l.MapNodes > 1<<20 || l.RuntimeBytes == 0 {
		return resourcev4.Vector{}, CBORFailure("configuration_capacity")
	}
	codec, err := SignedMapBackingBytes("TrustConfig", l.ConfigBytes, l.MapNodes)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	policy, err := CredentialPolicyBackingBytes()
	if err != nil {
		return resourcev4.Vector{}, err
	}
	metadata := uint64(unsafe.Sizeof(trustConfiguration{})) + 64*uint64(unsafe.Sizeof(trustedIssuer{})) + 32*uint64(unsafe.Sizeof(trustedHead{})) + 32*uint64(unsafe.Sizeof(trustedActivation{})) + 32*uint64(unsafe.Sizeof(trustedOnce{})) + 16*uint64(unsafe.Sizeof((*CredentialPolicy)(nil))) + 128*16
	// Detached text/bytes are bounded by their disjoint encoded input fields.
	per := codec + metadata + 2*uint64(l.ConfigBytes) + 16*policy
	total := resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(NamespaceTrustStore{})) + 256 + uint64(l.Configurations)*per, resourcev4.Items: 1 + uint64(l.Configurations)*306, resourcev4.WorkSlots: 1}
	for _, schema := range []string{"NamespaceCapacity", "PublicationPolicy"} {
		limit, err := SchemaByteLimit(schema)
		if err != nil {
			return resourcev4.Vector{}, err
		}
		decoder, err := DecoderBackingBytes(limit, limit)
		if err != nil {
			return resourcev4.Vector{}, err
		}
		total, err = total.Add(resourcev4.Vector{resourcev4.SDKBytes: decoder + 2*uint64(limit)})
		if err != nil {
			return resourcev4.Vector{}, err
		}
	}
	total, err = total.Add(resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(NamespaceRules{}))})
	if err != nil {
		return resourcev4.Vector{}, err
	}
	return total.Add(resourcev4.Vector{resourcev4.SDKBytes: l.RuntimeBytes})
}

// NewNamespaceTrustAnchor admits an independent root before the fresh online
// query. An empty anchor grants no credential or Head authority.
func NewNamespaceTrustAnchor(root NamespaceTrustRoot, limits NamespaceTrustLimits, clock *timev4.Clock, reservation, dependenciesBorrow resourcev4.Reference) (_ *NamespaceTrustStore, err error) {
	if clock == nil || root.Tenant == "" || len(root.Tenant) > 128 || root.Authority == "" || len(root.Authority) > 128 || root.KeyID == ([16]byte{}) || root.PublicKey == ([32]byte{}) || root.MaxLifetimeMS == 0 {
		return nil, CBORFailure("revocation_trust_binding")
	}
	charge, err := NamespaceTrustCharge(limits)
	if err != nil {
		return nil, err
	}
	if err := reservation.CheckSameEnvironment(dependenciesBorrow); err != nil {
		return nil, err
	}
	dependencies, err := dependenciesBorrow.TakeBorrow()
	if err != nil {
		return nil, err
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		dependencies.Release()
		return nil, err
	}
	t := &NamespaceTrustStore{root: root, limits: limits, clock: clock, reservation: owned, dependencies: dependencies, configurations: make([]trustConfiguration, limits.Configurations)}
	t.root.Tenant, t.root.Authority = strings.Clone(root.Tenant), strings.Clone(root.Authority)
	return t, nil
}

func NewNamespaceTrustStore(root NamespaceTrustRoot, limits NamespaceTrustLimits, clock *timev4.Clock, original []byte, reservation, dependenciesBorrow resourcev4.Reference) (*NamespaceTrustStore, error) {
	t, err := NewNamespaceTrustAnchor(root, limits, clock, reservation, dependenciesBorrow)
	if err != nil {
		return nil, err
	}
	if err = t.Update(original); err != nil {
		t.Close()
		_ = t.DestroyEnvironment()
		return nil, err
	}
	return t, nil
}

// Update authenticates one complete independent configuration outside the
// trust gate. Publication checks the original live owner again and only then
// installs its monotonic revision; concurrent checks retain the old immutable
// configuration while verification is running. A signed response is never a
// source of root trust or a rollback/recovery permission.
func (t *NamespaceTrustStore) Update(wire []byte) (err error) {
	t.mu.Lock()
	if t.closed || t.busy {
		t.mu.Unlock()
		return CBORFailure("revocation_trust_owner")
	}
	if err = t.reservation.Check(); err == nil {
		err = t.dependencies.Check()
	}
	if err != nil {
		t.mu.Unlock()
		return err
	}
	if len(wire) == 0 || len(wire) > t.limits.ConfigBytes {
		t.mu.Unlock()
		return CBORFailure("map_size")
	}
	if t.count > 0 {
		previous := &t.configurations[t.count-1]
		original, e := previous.signed.Bytes()
		if e == nil && bytes.Equal(wire, original) {
			err = t.checkCurrentLocked()
			t.mu.Unlock()
			return err
		}
	}
	if t.count == len(t.configurations) {
		t.mu.Unlock()
		return CBORFailure("configuration_capacity")
	}
	t.busy = true
	slot := &t.configurations[t.count]
	t.mu.Unlock()
	var notify *LiveNamespace
	defer func() {
		t.mu.Lock()
		if err != nil {
			if slot.signed != nil {
				slot.signed.Release()
			}
			*slot = trustConfiguration{}
		}
		t.mu.Unlock()
		if notify != nil {
			notify.NotifyTrust()
		}
		t.mu.Lock()
		t.busy = false
		t.mu.Unlock()
	}()
	slot.codec, err = NewSignedMapCodec("TrustConfig", t.limits.ConfigBytes, t.limits.MapNodes)
	if err != nil {
		return err
	}
	slot.signed, err = slot.codec.Verify(wire, t.root.PublicKey, DecodeContext{})
	if err != nil {
		return err
	}
	if err = t.decodeConfiguration(slot); err != nil {
		return err
	}
	// Namespace installation and independent permission extension share the
	// original namespace -> trust lock order. A new permission cannot race an
	// already authenticated issuer revocation into a shorter impact history.
	n := t.lockForPublication()
	defer func() {
		t.mu.Unlock()
		if n != nil {
			n.mu.Unlock()
		}
	}()
	if t.closed {
		return CBORFailure("revocation_trust_owner")
	}
	if err = t.reservation.Check(); err == nil {
		err = t.dependencies.Check()
	}
	if err != nil {
		return err
	}
	if err = t.checkTime(slot); err != nil {
		return err
	}
	if t.count > 0 {
		previous := &t.configurations[t.count-1]
		if slot.revision <= previous.revision || slot.generation < previous.generation || slot.issued < previous.issued {
			return CBORFailure("revocation_trust_rollback")
		}
		if !t.rules.Matches(slot.signed.Field("capacity").Encoded(), slot.signed.Field("publication").Encoded()) {
			return CBORFailure("revocation_namespace_binding")
		}
		if err = t.checkHistory(slot); err != nil {
			return err
		}
	}
	if t.count == 0 {
		t.rules, err = NewNamespaceRules(slot.signed.Field("capacity").Encoded(), slot.signed.Field("publication").Encoded())
		if err != nil {
			return err
		}
	}
	if slot.encodedBytes > t.rules.trustBytes-t.bytes || slot.entries > t.rules.trustEntries-t.entries {
		return CBORFailure("configuration_capacity")
	}
	if err = t.matchConfiguration(slot); err != nil {
		return err
	}
	if err = t.checkPermissionExtensions(slot, n); err != nil {
		return err
	}
	t.bytes += slot.encodedBytes
	t.entries += slot.entries
	t.count++
	notify = t.namespace
	return nil
}

func trustText(v Value, schema, name string) string { s, _ := v.Named(schema, name).Text(); return s }
func trust16(v Value, schema, name string) [16]byte {
	b, _ := v.Named(schema, name).ByteString()
	return [16]byte(b)
}
func trust32(v Value, schema, name string) [32]byte {
	b, _ := v.Named(schema, name).ByteString()
	return [32]byte(b)
}
func (t *NamespaceTrustStore) decodeConfiguration(c *trustConfiguration) error {
	m := c.signed
	if err := m.document.ValidateRules(DecodeContext{}); err != nil {
		return err
	}
	if tenant, _ := m.Field("tenant_id").Text(); tenant != t.root.Tenant {
		return CBORFailure("revocation_namespace_binding")
	}
	if authority, _ := m.Field("revocation_authority_id").Text(); authority != t.root.Authority {
		return CBORFailure("revocation_namespace_binding")
	}
	key, _ := m.Field("signing_key_id").ByteString()
	if !bytes.Equal(key, t.root.KeyID[:]) {
		return CBORFailure("revocation_trust_binding")
	}
	get := func(name string) uint64 { n, _ := m.Field(name).Uint(); return n }
	c.revision, c.generation, c.issued, c.end = get("revision"), get("authority_generation"), get("issued_at_ms"), get("not_after_ms")
	if c.end-c.issued > t.root.MaxLifetimeMS {
		return CBORFailure("revocation_trust_lifetime")
	}
	var err error
	c.digest, err = m.Digest("trust_config_digest")
	if err != nil {
		return err
	}
	raw, err := m.Bytes()
	if err != nil {
		return err
	}
	c.encodedBytes = uint64(len(raw))
	issuers := m.Field("issuer_authorizations")
	c.issuers = make([]trustedIssuer, issuers.Len())
	for i := range c.issuers {
		v := issuers.Index(i)
		schema := "CredentialIssuerAuthorization"
		item := &c.issuers[i]
		kind := valueUint(v, schema, "credential_kind")
		item.id = trust16(v, schema, "authorization_id")
		item.digest, err = fullMapDigest("credential_issuer_authorization_digest", schema, v.Encoded())
		if err != nil {
			return err
		}
		item.permission = IssuerPermission{Schema: [3]string{"IdentityCertificate", "Artifact", "Grant"}[kind], Issuer: trust16(v, schema, "issuer_key_id"), Key: trust32(v, schema, "issuer_public_key"), SigningStart: valueUint(v, schema, "signing_not_before_ms"), SigningEnd: valueUint(v, schema, "signing_not_after_ms")}
		item.scope = CredentialScope{Schema: item.permission.Schema, Tenant: trustText(v, schema, "tenant_id"), Authority: trustText(v, schema, "revocation_authority_id"), CapacityDigest: trust32(v, schema, "namespace_capacity_digest"), Generation: valueUint(v, schema, "authority_generation"), Issuer: item.permission.Issuer, Audience: trustText(v, schema, "audience"), Subject: trustText(v, schema, "subject_id"), Profile: trustText(v, schema, "crypto_profile_id"), Role: valueUint(v, schema, "role"), Service: trustText(v, schema, "service"), ParentIssuer: trust16Optional(v, schema, "parent_artifact_issuer_key_id"), ParentAuthority: trustText(v, schema, "parent_authority_id"), ParentCapacityDigest: trust32Optional(v, schema, "parent_capacity_digest"), ParentGeneration: valueUint(v, schema, "parent_generation")}
		item.first, item.last, item.lastExpiry = valueUint(v, schema, "first_cohort"), valueUint(v, schema, "last_cohort"), valueUint(v, schema, "max_credential_not_after_ms")
		item.firstParent, item.lastParent = valueUint(v, schema, "first_parent_cohort"), valueUint(v, schema, "last_parent_cohort")
	}
	heads := m.Field("head_delegations")
	c.heads = make([]trustedHead, heads.Len())
	for i := range c.heads {
		v := heads.Index(i)
		c.heads[i] = trustedHead{signer: trust16(v, "HeadSignerDelegation", "signer_key_id"), generation: valueUint(v, "HeadSignerDelegation", "authority_generation")}
		c.heads[i].digest, err = fullMapDigest("head_signer_delegation_digest", "HeadSignerDelegation", v.Encoded())
		if err != nil {
			return err
		}
	}
	once := m.Field("once_authorities")
	c.once = make([]trustedOnce, once.Len())
	for i := range c.once {
		v := once.Index(i)
		c.once[i] = trustedOnce{trust16(v, "OnceAuthorityRef", "artifact_issuer_key_id"), trustText(v, "OnceAuthorityRef", "spend_authority_id"), trustText(v, "OnceAuthorityRef", "winner_authority_id")}
	}
	activation := m.Field("activation_delegations")
	c.activations = make([]trustedActivation, activation.Len())
	for i := range c.activations {
		v := activation.Index(i)
		schema := "ConnectionActivationDelegation"
		b := ActivationTrustBinding{Tenant: trustText(v, schema, "tenant_id"), AuthorityNamespace: trustText(v, schema, "revocation_authority_id"), CapacityDigest: trust32(v, schema, "namespace_capacity_digest"), Generation: valueUint(v, schema, "authority_generation"), SigningKeyID: trustText(v, schema, "signing_key_id"), SpendAuthority: trustText(v, schema, "authority_id"), ParentIssuer: trust16(v, schema, "artifact_issuer_key_id"), Issuer: trust16(v, schema, "issuer_key_id"), Key: trust32(v, schema, "signer_public_key")}
		b.DelegationDigest, err = fullMapDigest("connection_activation_delegation_digest", schema, v.Encoded())
		if err != nil {
			return err
		}
		found := false
		for _, mapping := range c.once {
			if mapping.issuer == b.ParentIssuer && mapping.spend == b.SpendAuthority {
				b.WinnerAuthority = mapping.winner
				found = true
				break
			}
		}
		if !found {
			return CBORFailure("activation_delegation_authority")
		}
		c.activations[i].binding = b
	}
	policies := m.Field("credential_policies")
	c.policies = make([]*CredentialPolicy, policies.Len())
	for i := range c.policies {
		c.policies[i], err = NewCredentialPolicy(policies.Index(i).Encoded())
		if err != nil {
			return err
		}
	}
	for _, entry := range []struct {
		name   string
		target *[][16]byte
	}{{"retired_issuers", &c.retired}, {"rejected_head_signers", &c.rejectedHeads}} {
		v := m.Field(entry.name)
		*entry.target = make([][16]byte, v.Len())
		for i := range *entry.target {
			b, _ := v.Index(i).ByteString()
			(*entry.target)[i] = [16]byte(b)
			if i > 0 && bytes.Compare((*entry.target)[i-1][:], b) >= 0 {
				return CBORFailure("revocation_trust_order")
			}
		}
	}
	c.entries = uint64(len(c.issuers) + len(c.heads) + len(c.activations) + len(c.once) + len(c.policies) + len(c.retired) + len(c.rejectedHeads) + 3)
	return nil
}
func trust16Optional(v Value, schema, name string) [16]byte {
	b, ok := v.Named(schema, name).ByteString()
	if !ok {
		return [16]byte{}
	}
	return [16]byte(b)
}
func trust32Optional(v Value, schema, name string) [32]byte {
	b, ok := v.Named(schema, name).ByteString()
	if !ok {
		return [32]byte{}
	}
	return [32]byte(b)
}
func includesTrustID(ids [][16]byte, id [16]byte) bool {
	for _, x := range ids {
		if x == id {
			return true
		}
	}
	return false
}

func (t *NamespaceTrustStore) checkTime(c *trustConfiguration) error {
	sample, err := t.clock.Sample()
	if err != nil {
		return err
	}
	if !sample.Interval.ValidBefore(c.end) {
		return timev4.ErrExpired
	}
	return sample.Interval.LowerBound(c.issued, true)
}
func (t *NamespaceTrustStore) checkCurrentLocked() error {
	if t.closed || t.count == 0 {
		return CBORFailure("revocation_trust_owner")
	}
	if err := t.reservation.Check(); err != nil {
		return err
	}
	if err := t.dependencies.Check(); err != nil {
		return err
	}
	return t.checkTime(&t.configurations[t.count-1])
}
func (t *NamespaceTrustStore) matchConfiguration(c *trustConfiguration) error {
	if err := checkTrustIssuerKeys(c, c); err != nil {
		return err
	}

	for _, issuer := range c.issuers {
		s := issuer.scope
		if s.Tenant != t.root.Tenant || s.Authority != t.root.Authority || s.CapacityDigest != t.rules.capacityDigest || s.Generation != c.generation {
			return CBORFailure("revocation_namespace_binding")
		}
	}
	for _, b := range c.activations {
		if b.binding.Tenant != t.root.Tenant || b.binding.AuthorityNamespace != t.root.Authority || b.binding.CapacityDigest != t.rules.capacityDigest || b.binding.Generation != c.generation {
			return CBORFailure("activation_delegation_namespace")
		}
	}
	heads := c.signed.Field("head_delegations")
	for i := range c.heads {
		v := heads.Index(i)
		if !t.rules.matchesNamespace(v, "HeadSignerDelegation") || !t.rules.matchesPublication(v, "HeadSignerDelegation") || c.heads[i].generation != c.generation {
			return CBORFailure("revocation_delegation_binding")
		}
	}
	once := c.signed.Field("once_authorities")
	for i := range c.once {
		if trustText(once.Index(i), "OnceAuthorityRef", "tenant_id") != t.root.Tenant {
			return CBORFailure("activation_delegation_authority")
		}
	}
	return nil
}
func (t *NamespaceTrustStore) checkHistory(next *trustConfiguration) error {
	for i := 0; i < t.count; i++ {
		previous := &t.configurations[i]
		if err := checkTrustIssuerKeys(previous, next); err != nil {
			return err
		}
		for _, id := range previous.retired {
			if !includesTrustID(next.retired, id) {
				return CBORFailure("revocation_trust_rollback")
			}
		}
		for _, id := range previous.rejectedHeads {
			if !includesTrustID(next.rejectedHeads, id) {
				return CBORFailure("revocation_trust_rollback")
			}
		}
		for _, a := range previous.issuers {
			for _, b := range next.issuers {
				if a.id == b.id && a.digest != b.digest || a.permission.Issuer == b.permission.Issuer && a.permission.Key != b.permission.Key {
					return CBORFailure("revocation_trust_conflict")
				}
			}
		}
		for _, a := range previous.heads {
			for _, b := range next.heads {
				if a.signer == b.signer && a.digest != b.digest {
					return CBORFailure("revocation_trust_conflict")
				}
			}
		}
		for _, a := range previous.activations {
			for _, b := range next.activations {
				if a.binding.SigningKeyID == b.binding.SigningKeyID && a.binding != b.binding {
					return CBORFailure("revocation_trust_conflict")
				}
			}
		}
		for _, a := range previous.once {
			for _, b := range next.once {
				if a.issuer == b.issuer && a != b {
					return CBORFailure("revocation_trust_conflict")
				}
			}
		}
		for _, a := range previous.policies {
			for _, b := range next.policies {
				if a.id == b.id && a.revision == b.revision && !a.Matches(b.bytes) {
					return CBORFailure("revocation_trust_conflict")
				}
			}
		}
	}
	return nil
}

func (t *NamespaceTrustStore) Head(binding NamespaceHeadTrust) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.checkCurrentLocked(); err != nil {
		return err
	}
	current := &t.configurations[t.count-1]
	if binding.Tenant != t.root.Tenant || binding.Authority != t.root.Authority || binding.Capacity != t.rules.capacityDigest || binding.Generation != current.generation || includesTrustID(current.rejectedHeads, binding.Signer) {
		return CBORFailure("revocation_trust_binding")
	}
	allowed := false
	for _, head := range current.heads {
		if head.signer == binding.Signer && head.digest == binding.Delegation {
			allowed = true
			break
		}
	}
	if !allowed {
		return CBORFailure("revocation_trust_binding")
	}
	for i := 0; i < t.count; i++ {
		c := &t.configurations[i]
		if c.generation != binding.Generation || c.issued != binding.TrustIssuedMS || c.end != binding.TrustNotAfterMS {
			continue
		}
		for _, head := range c.heads {
			if head.signer == binding.Signer && head.digest == binding.Delegation {
				return nil
			}
		}
	}
	return CBORFailure("revocation_trust_binding")
}
func (t *NamespaceTrustStore) Issuer(permission IssuerPermission, scope CredentialScope) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.checkCurrentLocked(); err != nil {
		return err
	}
	current := &t.configurations[t.count-1]
	if includesTrustID(current.retired, scope.Issuer) {
		return CBORFailure("revocation_issuer_rejected")
	}
	for _, entry := range current.issuers {
		if trustIssuerMatches(entry, permission, scope) {
			return nil
		}
	}
	return CBORFailure("revocation_issuer_permission")
}
func (t *NamespaceTrustStore) Policy(policy *CredentialPolicy) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.checkCurrentLocked(); err != nil {
		return err
	}
	if policy == nil {
		return CBORFailure("credential_policy_owner")
	}
	for _, p := range t.configurations[t.count-1].policies {
		if p.id == policy.id && p.revision == policy.revision && p.Matches(policy.bytes) {
			return nil
		}
	}
	return CBORFailure("credential_policy_owner")
}
func (t *NamespaceTrustStore) Activation(binding ActivationTrustBinding) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.checkCurrentLocked(); err != nil {
		return err
	}
	c := &t.configurations[t.count-1]
	if includesTrustID(c.retired, binding.Issuer) || includesTrustID(c.retired, binding.ParentIssuer) {
		return CBORFailure("revocation_issuer_rejected")
	}
	for _, a := range c.activations {
		if a.binding == binding {
			return nil
		}
	}
	return CBORFailure("activation_delegation_authority")
}
func (t *NamespaceTrustStore) RetiredIssuer(id [16]byte) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.count > 0 && includesTrustID(t.configurations[t.count-1].retired, id)
}
func (t *NamespaceTrustStore) Rules() (*NamespaceRules, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.checkCurrentLocked(); err != nil {
		return nil, err
	}
	return t.rules, nil
}

// AttachNamespace wires exactly one shared original namespace to trust change
// notifications. The caller owns both dependencies through namespace cleanup.
func (t *NamespaceTrustStore) AttachNamespace(n *LiveNamespace) error {
	if n == nil {
		return CBORFailure("revocation_namespace_owner")
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.checkCurrentLocked(); err != nil {
		return err
	}
	if t.bootstrap || t.namespace != nil || n.rules != t.rules || n.trust != t || n.destroyed {
		return CBORFailure("revocation_namespace_owner")
	}
	if err := t.reservation.CheckSameEnvironment(n.reservation); err != nil {
		return err
	}
	if err := t.stateHistoryLocked(n.active); err != nil {
		return err
	}
	t.namespace = n
	return nil
}
func (t *NamespaceTrustStore) Close() {
	if t == nil {
		return
	}
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return
	}
	t.closed, t.closing = true, true
	n := t.namespace
	t.mu.Unlock()
	if n != nil {
		n.Close(CBORFailure("revocation_trust_owner"))
	}
	t.mu.Lock()
	t.closing = false
	t.mu.Unlock()
}
func (t *NamespaceTrustStore) DestroyEnvironment() error {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	if t.retired {
		t.mu.Unlock()
		return nil
	}
	if !t.closed || t.busy || t.closing || t.bootstrap || t.count != 0 && !t.reservation.EnvironmentClosed() {
		t.mu.Unlock()
		return CBORFailure("revocation_trust_owner")
	}
	t.busy = true
	n := t.namespace
	t.mu.Unlock()
	// Namespace shutdown may itself consult trust. Never invert those locks.
	destroyed := true
	if n != nil {
		destroyed = n.DestroyEnvironment() == nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.busy = false
	if !destroyed {
		return CBORFailure("revocation_trust_owner")
	}
	for i := range t.configurations {
		c := &t.configurations[i]
		if c.signed != nil {
			c.signed.Release()
		}
		*c = trustConfiguration{}
	}
	t.configurations, t.rules, t.namespace, t.clock = nil, nil, nil, nil
	t.count = 0
	t.reservation.Release()
	t.dependencies.Release()
	t.reservation, t.dependencies = resourcev4.Reference{}, resourcev4.Reference{}
	t.retired = true
	return nil
}

func checkTrustIssuerKeys(a, b *trustConfiguration) error {
	for _, x := range a.issuers {
		for _, y := range b.issuers {
			if x.permission.Issuer == y.permission.Issuer && x.permission.Key != y.permission.Key {
				return CBORFailure("revocation_trust_conflict")
			}
		}
		for _, y := range b.activations {
			if x.permission.Issuer == y.binding.Issuer && x.permission.Key != y.binding.Key {
				return CBORFailure("revocation_trust_conflict")
			}
		}
	}
	for _, x := range a.activations {
		for _, y := range b.issuers {
			if x.binding.Issuer == y.permission.Issuer && x.binding.Key != y.permission.Key {
				return CBORFailure("revocation_trust_conflict")
			}
		}
		for _, y := range b.activations {
			if x.binding.Issuer == y.binding.Issuer && x.binding.Key != y.binding.Key {
				return CBORFailure("revocation_trust_conflict")
			}
		}
	}
	return nil
}

// CredentialKey resolves only an independently configured signature key. The
// caller must still verify the actual canonical credential and resolve its
// complete immutable permission/policy before entering a live namespace gate.
func (t *NamespaceTrustStore) CredentialKey(schema string, issuer [16]byte) ([32]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.checkCurrentLocked(); err != nil {
		return [32]byte{}, err
	}
	c := &t.configurations[t.count-1]
	if includesTrustID(c.retired, issuer) {
		return [32]byte{}, CBORFailure("revocation_issuer_rejected")
	}
	for _, entry := range c.issuers {
		if entry.permission.Schema == schema && entry.permission.Issuer == issuer {
			return entry.permission.Key, nil
		}
	}
	return [32]byte{}, CBORFailure("revocation_issuer_permission")
}

// ResolveCredential supplies the original concrete dependencies for material
// construction. It is an inspection of current independent policy, not an
// authorization token: the live State/Head/time gate remains mandatory at each
// original consumption and delivery boundary.
func (t *NamespaceTrustStore) ResolveCredential(credential *Credential) (CredentialValidation, error) {
	if credential == nil {
		return CredentialValidation{}, CBORFailure("credential_owner")
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.checkCurrentLocked(); err != nil {
		return CredentialValidation{}, err
	}
	if t.namespace == nil {
		return CredentialValidation{}, CBORFailure("revocation_namespace_owner")
	}
	c := &t.configurations[t.count-1]
	for _, entry := range c.issuers {
		if entry.permission.Key != credential.key || !trustIssuerMatches(entry, entry.permission, credential.scope) {
			continue
		}
		if includesTrustID(c.retired, credential.scope.Issuer) {
			return CredentialValidation{}, CBORFailure("revocation_issuer_rejected")
		}
		for _, p := range c.policies {
			if p.id == credential.facts.PolicyID && p.revision == credential.facts.PolicyRevision {
				return CredentialValidation{Namespace: t.namespace, Issuer: entry.permission, Policy: p}, nil
			}
		}
	}
	return CredentialValidation{}, CBORFailure("revocation_issuer_permission")
}

func trustIssuerMatches(entry trustedIssuer, permission IssuerPermission, scope CredentialScope) bool {
	if entry.permission != permission || scope.Cohort < entry.first || scope.Cohort > entry.last || scope.ExpiresMS > entry.lastExpiry || scope.IssuedMS < permission.SigningStart || scope.IssuedMS >= permission.SigningEnd {
		return false
	}
	normalized := scope
	normalized.IssuedMS, normalized.ExpiresMS, normalized.Cohort, normalized.ParentCohort = 0, 0, 0, 0
	original := entry.scope
	if scope.Schema == "Grant" {
		if scope.ParentCohort < entry.firstParent || scope.ParentCohort > entry.lastParent || scope.Role == 0 || scope.Role&^original.Role != 0 {
			return false
		}
		normalized.Role = original.Role
	}
	return original == normalized
}
