package sessionv4

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"time"
)

type materialBytesFixture struct {
	*authorityFixture
	trust      *protocolv4.NamespaceTrustStore
	config     ArtifactLeaseBytesConfig
	reserve    func(resourcev4.Vector) resourcev4.Reference
	bootstrap  func([32]byte) ([]byte, []byte)
	rootKeyID  [16]byte
	rootPublic [32]byte
}

// This fixture uses a real independently signed TrustConfig and production
// namespace owner. Its initial complete pair is installed by the test authority;
// fresh online startup is exercised separately by the bootstrap integration.
func authorityMaterialBytesFor(t AuthorityReporter, f *authorityFixture, registries ...*protocolv4.NamespaceRegistry) *materialBytesFixture {
	t.Helper()
	source := f.trust.source
	x := &materialBytesFixture{authorityFixture: f}
	next := uint32(600)
	x.reserve = func(cost resourcev4.Vector) resourcev4.Reference {
		next++
		ref, err := f.root.Reserve(admissionResourceKey(f.owner, next), cost)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(ref.Release)
		return ref
	}
	capacity := admissionMap(t, "NamespaceCapacity", initialFixture(t, "namespace_capacity_fields"), map[string]protocolv4.Field{"max_state_encoded_bytes": {Number: 4096}})
	capacityDigest := admissionDigest(t, "namespace_capacity_digest", capacity)
	publication := initialFixture(t, "publication_policy")
	policy := admissionEncode(t, "CredentialRevocationPolicy", map[string]protocolv4.Field{"revocation_policy_id": admissionText("online"), "revocation_policy_revision": {Number: 1}, "max_staleness_ms": {Number: 5000}, "max_head_signer_lifetime_ms": {Number: 59000}})
	var issuers [][]byte
	entries := make([]engineeringCredentialAuthority, 0, 3+len(f.trust.trust.additional))
	for i, scope := range f.trust.trust.scopes {
		entries = append(entries, engineeringCredentialAuthority{scope: scope, permission: f.trust.trust.permissions[i]})
	}
	entries = append(entries, f.trust.trust.additional...)
	for i, entry := range entries {
		scope, permission := entry.scope, entry.permission
		fields := map[string]protocolv4.Field{
			"authorization_id": admissionBytes([]byte{byte(i + 1), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}),
			"tenant_id":        admissionText(scope.Tenant), "revocation_authority_id": admissionText(scope.Authority), "namespace_capacity_digest": admissionBytes(scope.CapacityDigest[:]), "authority_generation": {Number: scope.Generation},
			"issuer_key_id": admissionBytes(scope.Issuer[:]), "issuer_public_key": admissionBytes(permission.Key[:]), "audience": admissionText(scope.Audience), "crypto_profile_id": admissionText(scope.Profile),
			"signing_not_before_ms": {Number: permission.SigningStart}, "signing_not_after_ms": {Number: permission.SigningEnd}, "first_cohort": {Number: 0}, "last_cohort": {Number: 100}, "max_credential_not_after_ms": {Number: scope.ExpiresMS},
		}
		if scope.Schema == "Artifact" {
			fields["credential_kind"] = protocolv4.Field{Number: 1}
			fields["max_affected_cohorts"] = protocolv4.Field{Kind: protocolv4.EncodedArray, Bytes: []byte{0x82, 0xf6, 0x18, 0x64}}
		} else if scope.Schema == "Grant" {
			fields["credential_kind"] = protocolv4.Field{Number: 2}
			delete(fields, "crypto_profile_id")
			fields["role"] = protocolv4.Field{Number: scope.Role & 3}
			fields["service"] = admissionText(scope.Service)
			fields["parent_authority_id"] = admissionText(scope.ParentAuthority)
			fields["parent_capacity_digest"] = admissionBytes(scope.ParentCapacityDigest[:])
			fields["parent_generation"] = protocolv4.Field{Number: scope.ParentGeneration}
			fields["parent_artifact_issuer_key_id"] = admissionBytes(scope.ParentIssuer[:])
			fields["first_parent_cohort"], fields["last_parent_cohort"] = protocolv4.Field{Number: 0}, protocolv4.Field{Number: 100}
			fields["max_affected_cohorts"] = protocolv4.Field{Kind: protocolv4.EncodedArray, Bytes: []byte{0x82, 0xf6, 0x18, 0x64}}
		} else {
			fields["credential_kind"] = protocolv4.Field{Number: 0}
			fields["subject_id"], fields["role"] = admissionText(scope.Subject), protocolv4.Field{Number: scope.Role}
			fields["max_affected_cohorts"] = protocolv4.Field{Kind: protocolv4.EncodedArray, Bytes: []byte{0x82, 0x18, 0x64, 0xf6}}
		}
		issuers = append(issuers, admissionEncode(t, "CredentialIssuerAuthorization", fields))
	}
	seed := [32]byte{71, 23, 4}
	headKey := ed25519.NewKeyFromSeed(seed[:]).Public().(ed25519.PublicKey)
	headDelegation := admissionMap(t, "HeadSignerDelegation", initialFixture(t, "head_delegation_fields"), map[string]protocolv4.Field{"namespace_capacity_digest": admissionBytes(capacityDigest[:]), "signer_public_key": admissionBytes(headKey)})
	rootSeed, rootID := [32]byte{81, 19, 3}, [16]byte{99}
	rootPublic := [32]byte(ed25519.NewKeyFromSeed(rootSeed[:]).Public().(ed25519.PublicKey))
	x.rootKeyID, x.rootPublic = rootID, rootPublic
	wire := admissionEncode(t, "TrustConfig", map[string]protocolv4.Field{
		"schema_revision": admissionText("4"), "tenant_id": admissionText("tenant-1"), "revocation_authority_id": admissionText("revocation-1"), "authority_generation": {Number: 1}, "revision": {Number: 1}, "issued_at_ms": {Number: 900}, "not_after_ms": {Number: 100000},
		"capacity": {Kind: protocolv4.EncodedMap, Bytes: capacity}, "publication": {Kind: protocolv4.EncodedMap, Bytes: publication},
		"credential_policies": admissionArray(policy), "issuer_authorizations": admissionArray(issuers...), "head_delegations": admissionArray(headDelegation), "activation_delegations": admissionArray(f.trust.delegation), "once_authorities": admissionArray(f.trust.once),
		"retired_issuers": admissionArray(), "rejected_head_signers": admissionArray(), "signing_key_id": admissionBytes(rootID[:]), "signature": admissionBytes(make([]byte, 64)),
	})
	signed := initialSignTemplate(t, "TrustConfig", wire, nil, rootSeed)
	wire, err := signed.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	limits := protocolv4.NamespaceTrustLimits{Configurations: 4, ConfigBytes: 32768, MapNodes: 8192, RuntimeBytes: 65536}
	charge, err := protocolv4.NamespaceTrustCharge(limits)
	if err != nil {
		t.Fatal(err)
	}
	borrow, err := f.preauth.Borrow()
	if err != nil {
		t.Fatal(err)
	}
	rootPin := protocolv4.NamespaceTrustRoot{Tenant: "tenant-1", Authority: "revocation-1", KeyID: rootID, PublicKey: rootPublic, MaxLifetimeMS: authorityDuration(t, 100000)}
	if remote, ok := t.(EngineeringNamespaceRoot); ok && remote.AuthorityNamespaceRoot() != nil {
		rootPin = *remote.AuthorityNamespaceRoot()
	}
	x.trust, err = protocolv4.NewNamespaceTrustAnchor(rootPin, limits, f.trust.clock, x.reserve(charge), borrow)
	if err != nil {
		t.Fatal(err)
	}
	if len(registries) != 0 {
		if err := registries[0].Register(x.trust); err != nil {
			t.Fatal(err)
		}
	} else {
		if err := x.trust.Update(wire); err != nil {
			t.Fatal(err)
		}
	}
	segment := admissionEncode(t, "CohortPolicySegment", map[string]protocolv4.Field{"first_cohort": {Number: 0}, "last_cohort": {Number: 100}, "certificate_impact_ms": {Number: 1000}, "connection_impact_ms": {Number: 10000}})
	state := admissionMap(t, "RevocationState", initialFixture(t, "revocation_state_fields"), map[string]protocolv4.Field{"namespace_capacity_digest": admissionBytes(capacityDigest[:]), "revoked_issuers": admissionArray(), "revoked_certificates": admissionArray(), "revoked_leases": admissionArray(), "cohort_policy_segments": admissionArray(segment)})
	stateDigest, headDelegationDigest := admissionDigest(t, "revocation_state_digest", state), admissionDigest(t, "head_signer_delegation_digest", headDelegation)
	signedHead := initialSignTemplate(t, "FreshnessHead", initialFixture(t, "freshness_head_fields"), map[string]protocolv4.Field{"credential_revocation_floors": {Kind: protocolv4.EncodedArray, Bytes: []byte{0x82, 0, 0}}, "namespace_capacity_digest": admissionBytes(capacityDigest[:]), "signer_delegation_digest": admissionBytes(headDelegationDigest[:]), "state_digest": admissionBytes(stateDigest[:]), "state_encoded_bytes": {Number: uint64(len(state))}}, seed)
	headWire, err := signedHead.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	x.bootstrap = func(nonce [32]byte) ([]byte, []byte) {
		response := admissionEncode(t, "TrustBootstrapResponse", map[string]protocolv4.Field{
			"schema_revision": admissionText("4"), "tenant_id": admissionText("tenant-1"), "revocation_authority_id": admissionText("revocation-1"), "request_nonce": admissionBytes(nonce[:]),
			"issued_at_ms": {Number: authorityBootstrapIssued(t, f.trust.clock)}, "not_after_ms": {Number: authorityTime(t, 5000)}, "trust_config": admissionBytes(wire), "freshness_head": admissionBytes(headWire), "signing_key_id": admissionBytes(rootID[:]), "signature": admissionBytes(make([]byte, 64)),
		})
		signed := initialSignTemplate(t, "TrustBootstrapResponse", response, nil, rootSeed)
		defer signed.Release()
		encoded, err := signed.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		return bytes.Clone(encoded), bytes.Clone(state)
	}
	allocation := protocolv4.NamespaceAllocation{Root: f.root}
	for i := range allocation.Owners {
		next++
		allocation.Owners[i] = admissionResourceKey(f.owner, next)
	}
	subscriberSlots := uint32(8)
	if capacity, ok := t.(EngineeringNamespaceCapacity); ok {
		subscriberSlots = capacity.AuthorityNamespaceSubscribers()
		if subscriberSlots == 0 {
			t.Fatal("invalid engineering namespace subscription capacity")
		}
	}
	var n *protocolv4.LiveNamespace
	if len(registries) != 0 {
		// The independently installed cross-SDK authority profile admits up to
		// 8 KiB of namespace state, including the TypeScript issuer's signed cap.
		bl := protocolv4.NamespaceBootstrapLimits{ResponseBytes: 32768, ResponseNodes: 8192, StateBytes: 8192, DurationMS: 4000, FetchDurationMS: 4000, FetchAttempts: 2, Subscribers: subscriberSlots, RuntimeBytes: 65536}
		cost, err := protocolv4.NamespaceBootstrapCharge(bl)
		if err != nil {
			t.Fatal(err)
		}
		job, err := protocolv4.NewNamespaceOnlineBootstrap(context.Background(), x.trust, bl, allocation, x.reserve(cost))
		if err != nil {
			t.Fatal(err)
		}
		provider := materialBootstrapProvider{query: func(_ context.Context, request protocolv4.NamespaceBootstrapRequest, out []byte) (int, error) {
			if request.Tenant != "tenant-1" || request.Authority != "revocation-1" {
				return 0, protocolv4.CBORFailure("namespace_mismatch")
			}
			response, _ := x.bootstrap(request.Nonce)
			return copy(out, response), nil
		}, state: state}
		var bootstrap protocolv4.NamespaceBootstrapProvider = provider
		if remote, ok := t.(EngineeringBootstrapProvider); ok && remote.AuthorityBootstrapProvider() != nil {
			bootstrap = remote.AuthorityBootstrapProvider()
		}
		n, err = job.Run(context.Background(), bootstrap)
		job.Close()
		if cleanup := job.Retire(); cleanup != nil {
			t.Fatal(cleanup)
		}
		if err != nil {
			t.Fatal(err)
		}
	} else {
		rules, err := x.trust.Rules()
		if err != nil {
			t.Fatal(err)
		}
		head, err := rules.BindHead(signedHead, headDelegation, 1, authorityTime(t, 900), authorityTime(t, 100000))
		if err != nil {
			t.Fatal(err)
		}
		n, err = protocolv4.NewBootstrappedNamespace(context.Background(), f.trust.clock, x.trust, protocolv4.NamespaceBootstrap{Rules: rules, Head: head, State: state}, authorityDuration(t, 4000), 2, subscriberSlots, allocation)
		if err != nil {
			t.Fatal(err)
		}
		if err := x.trust.AttachNamespace(n); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		x.trust.Close()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := n.WaitCleanup(ctx); err != nil {
			t.Error(err)
		}
		f.root.Close()
		if err := x.trust.DestroyEnvironment(); err != nil {
			t.Error(err)
		}
	})
	read := func(m *protocolv4.SignedMap) []byte {
		wire, err := m.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		return bytes.Clone(wire)
	}
	signer := f.trust.activationSigningKeyID
	x.config = ArtifactLeaseBytesConfig{Artifact: read(f.trust.artifact), ClientCertificate: read(f.trust.certificates[0]), ServerCertificate: read(f.trust.certificates[1]), Source: source, ActivationSigningKeyID: signer, Trust: [3]*protocolv4.NamespaceTrustStore{x.trust, x.trust, x.trust}, MapBytes: 65536, MapNodes: 4096, RuntimeBytes: 65536}
	if source == "preauthorized_pool" {
		x.config.Proof = read(f.trust.proof)
	}
	return x
}

// This is an independently signed test authority, not production bootstrap
// freshness evidence. The actual nonce, parser and startup engine are exercised.
type materialBootstrapProvider struct {
	query func(context.Context, protocolv4.NamespaceBootstrapRequest, []byte) (int, error)
	state []byte
}

func (p materialBootstrapProvider) Query(ctx context.Context, r protocolv4.NamespaceBootstrapRequest, dst []byte) (int, error) {
	return p.query(ctx, r, dst)
}
func (p materialBootstrapProvider) Fetch(_ context.Context, _ protocolv4.NamespaceContent, dst []byte) (int, error) {
	return copy(dst, p.state), nil
}

func authorityVerificationRegistry(t AuthorityReporter, f *authorityFixture) *protocolv4.NamespaceRegistry {
	t.Helper()
	c := protocolv4.NamespaceRegistryConfig{Continuity: protocolv4.OnlineBootstrap, Entries: 4, RuntimeBytes: 4096}
	cost, err := protocolv4.NamespaceRegistryCharge(c)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := f.root.Reserve(admissionResourceKey(f.owner, 598), cost)
	if err != nil {
		t.Fatal(err)
	}
	r, err := protocolv4.NewNamespaceRegistry(c, ref)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		r.Close()
		f.root.Close()
		if err := r.DestroyEnvironment(); err != nil {
			t.Error(err)
		}
	})
	return r
}
