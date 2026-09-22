package sessionv4

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

type materialBytesFixture struct {
	*admissionIntegrationFixture
	trust   *protocolv4.NamespaceTrustStore
	config  ArtifactLeaseBytesConfig
	reserve func(resourcev4.Vector) resourcev4.Reference
}

// This fixture uses a real independently signed TrustConfig and production
// namespace owner. Its initial complete pair is installed by the test authority;
// fresh online startup is exercised separately by the bootstrap integration.
func newMaterialBytesFixture(t *testing.T, source string) *materialBytesFixture {
	t.Helper()
	return materialBytesFor(t, admissionIntegration(t, context.Background(), source))
}

func materialBytesFor(t *testing.T, f *admissionIntegrationFixture) *materialBytesFixture {
	t.Helper()
	source := f.trust.source
	x := &materialBytesFixture{admissionIntegrationFixture: f}
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
	for i, scope := range f.trust.trust.scopes {
		permission := f.trust.trust.permissions[i]
		fields := map[string]protocolv4.Field{
			"authorization_id": admissionBytes([]byte{byte(i + 1), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}),
			"tenant_id":        admissionText(scope.Tenant), "revocation_authority_id": admissionText(scope.Authority), "namespace_capacity_digest": admissionBytes(scope.CapacityDigest[:]), "authority_generation": {Number: scope.Generation},
			"issuer_key_id": admissionBytes(scope.Issuer[:]), "issuer_public_key": admissionBytes(permission.Key[:]), "audience": admissionText(scope.Audience), "crypto_profile_id": admissionText(scope.Profile),
			"signing_not_before_ms": {Number: permission.SigningStart}, "signing_not_after_ms": {Number: permission.SigningEnd}, "first_cohort": {Number: 0}, "last_cohort": {Number: 0}, "max_credential_not_after_ms": {Number: scope.ExpiresMS},
		}
		if scope.Schema == "Artifact" {
			fields["credential_kind"] = protocolv4.Field{Number: 1}
			fields["max_affected_cohorts"] = protocolv4.Field{Kind: protocolv4.EncodedArray, Bytes: []byte{0x82, 0xf6, 0}}
		} else {
			fields["credential_kind"] = protocolv4.Field{Number: 0}
			fields["subject_id"], fields["role"] = admissionText(scope.Subject), protocolv4.Field{Number: scope.Role}
			fields["max_affected_cohorts"] = protocolv4.Field{Kind: protocolv4.EncodedArray, Bytes: []byte{0x82, 0, 0xf6}}
		}
		issuers = append(issuers, admissionEncode(t, "CredentialIssuerAuthorization", fields))
	}
	seed := [32]byte{71, 23, 4}
	headKey := ed25519.NewKeyFromSeed(seed[:]).Public().(ed25519.PublicKey)
	headDelegation := admissionMap(t, "HeadSignerDelegation", initialFixture(t, "head_delegation_fields"), map[string]protocolv4.Field{"namespace_capacity_digest": admissionBytes(capacityDigest[:]), "signer_public_key": admissionBytes(headKey)})
	rootSeed, rootID := [32]byte{81, 19, 3}, [16]byte{99}
	rootPublic := [32]byte(ed25519.NewKeyFromSeed(rootSeed[:]).Public().(ed25519.PublicKey))
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
	x.trust, err = protocolv4.NewNamespaceTrustStore(protocolv4.NamespaceTrustRoot{Tenant: "tenant-1", Authority: "revocation-1", KeyID: rootID, PublicKey: rootPublic, MaxLifetimeMS: 100000}, limits, f.trust.clock, wire, x.reserve(charge), borrow)
	if err != nil {
		t.Fatal(err)
	}
	rules, err := x.trust.Rules()
	if err != nil {
		t.Fatal(err)
	}
	segment := admissionEncode(t, "CohortPolicySegment", map[string]protocolv4.Field{"first_cohort": {Number: 0}, "last_cohort": {Number: 100}, "certificate_impact_ms": {Number: 1000}, "connection_impact_ms": {Number: 10000}})
	state := admissionMap(t, "RevocationState", initialFixture(t, "revocation_state_fields"), map[string]protocolv4.Field{"namespace_capacity_digest": admissionBytes(capacityDigest[:]), "revoked_issuers": admissionArray(), "revoked_certificates": admissionArray(), "revoked_leases": admissionArray(), "cohort_policy_segments": admissionArray(segment)})
	stateDigest, headDelegationDigest := admissionDigest(t, "revocation_state_digest", state), admissionDigest(t, "head_signer_delegation_digest", headDelegation)
	signedHead := initialSignTemplate(t, "FreshnessHead", initialFixture(t, "freshness_head_fields"), map[string]protocolv4.Field{"credential_revocation_floors": {Kind: protocolv4.EncodedArray, Bytes: []byte{0x82, 0, 0}}, "namespace_capacity_digest": admissionBytes(capacityDigest[:]), "signer_delegation_digest": admissionBytes(headDelegationDigest[:]), "state_digest": admissionBytes(stateDigest[:]), "state_encoded_bytes": {Number: uint64(len(state))}}, seed)
	head, err := rules.BindHead(signedHead, headDelegation, 1, 900, 100000)
	if err != nil {
		t.Fatal(err)
	}
	allocation := protocolv4.NamespaceAllocation{Root: f.root}
	for i := range allocation.Owners {
		next++
		allocation.Owners[i] = admissionResourceKey(f.owner, next)
	}
	n, err := protocolv4.NewBootstrappedNamespace(context.Background(), f.trust.clock, x.trust, protocolv4.NamespaceBootstrap{Rules: rules, Head: head, State: state}, 4000, 2, 8, allocation)
	if err != nil {
		t.Fatal(err)
	}
	if err := x.trust.AttachNamespace(n); err != nil {
		t.Fatal(err)
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
	signer, _ := f.trust.proof.Field("signing_key_id").Text()
	x.config = ArtifactLeaseBytesConfig{Artifact: read(f.trust.artifact), ClientCertificate: read(f.trust.certificates[0]), ServerCertificate: read(f.trust.certificates[1]), Source: source, ActivationSigningKeyID: signer, Trust: [3]*protocolv4.NamespaceTrustStore{x.trust, x.trust, x.trust}, MapBytes: 65536, MapNodes: 4096, RuntimeBytes: 65536}
	if source == "preauthorized_pool" {
		x.config.Proof = read(f.trust.proof)
	}
	return x
}

func (f *materialBytesFixture) lease(t *testing.T) (*ArtifactLease, error) {
	t.Helper()
	charge, err := ArtifactLeaseCharge(f.config.MapBytes, f.config.MapNodes, f.config.RuntimeBytes)
	if err != nil {
		t.Fatal(err)
	}
	l, err := NewArtifactLeaseFromBytes(f.config, f.reserve(charge), f.preauth)
	if l != nil {
		t.Cleanup(l.Close)
	}
	return l, err
}

func (f *materialBytesFixture) identity(t *testing.T, role protocolv4.Direction) (*ApplicationIdentity, error) {
	t.Helper()
	charge, err := ApplicationIdentityCharge(4096, 8192)
	if err != nil {
		t.Fatal(err)
	}
	certificate := f.config.ClientCertificate
	if role == protocolv4.ServerToClient {
		certificate = f.config.ServerCertificate
	}
	i, err := NewApplicationIdentityFromBytes(ApplicationIdentityBytesConfig{Certificate: certificate, Trust: f.trust, Role: role, Signer: f.admissionIntegrationFixture.trust.signers[role], StaticDH: f.admissionIntegrationFixture.trust.keys[role], MapNodes: 4096, RuntimeBytes: 8192}, f.reserve(charge), f.preauth)
	if i != nil {
		t.Cleanup(i.Close)
	}
	return i, err
}

func TestMaterialBytesCaptureIndependentTrustAndOriginalIdentity(t *testing.T) {
	for _, source := range []string{"preauthorized_pool", "live_authority"} {
		t.Run(source, func(t *testing.T) {
			f := newMaterialBytesFixture(t, source)
			l, err := f.lease(t)
			if err != nil {
				t.Fatal(err)
			}
			for _, role := range []protocolv4.Direction{protocolv4.ClientToServer, protocolv4.ServerToClient} {
				i, err := f.identity(t, role)
				if err != nil {
					t.Fatal(err)
				}
				charge, _ := ConnectionMaterialCharge(8192)
				m, err := NewConnectionMaterial(l, i, MaterialGeneration{Source: [16]byte{1}, Generation: 1}, 8192, f.reserve(charge))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(m.Close)
				i.Close()
				if err := m.identity.identity.check(); err != nil {
					t.Fatal("captured exact original identity lost on advertisement close", err)
				}
			}
			clear(f.config.Artifact)
			clear(f.config.Proof)
			clear(f.config.ClientCertificate)
			clear(f.config.ServerCertificate)
			if err := l.check(); err != nil {
				t.Fatal("material retained caller buffer", err)
			}
		})
	}
}

func TestMaterialBytesRejectInvalidBindingBeforeUse(t *testing.T) {
	for _, mode := range []string{"artifact_signature", "certificate_signature", "proof_signature", "wrong_role", "missing_pool_proof", "proof_in_live", "unknown_activation", "expired", "closed_trust"} {
		t.Run(mode, func(t *testing.T) {
			source := "preauthorized_pool"
			if mode == "proof_in_live" {
				source = "live_authority"
			}
			f := newMaterialBytesFixture(t, source)
			switch mode {
			case "artifact_signature":
				f.config.Artifact[len(f.config.Artifact)-1] ^= 1
			case "certificate_signature":
				f.config.ServerCertificate[len(f.config.ServerCertificate)-1] ^= 1
			case "proof_signature":
				f.config.Proof[len(f.config.Proof)-1] ^= 1
			case "wrong_role":
				f.config.ClientCertificate, f.config.ServerCertificate = f.config.ServerCertificate, f.config.ClientCertificate
			case "missing_pool_proof":
				f.config.Proof = nil
			case "proof_in_live":
				f.config.Proof, _ = f.admissionIntegrationFixture.trust.proof.Bytes()
			case "unknown_activation":
				f.config.ActivationSigningKeyID = "untrusted-key"
			case "expired":
				f.admissionIntegrationFixture.trust.tick.Add(1000)
			case "closed_trust":
				f.trust.Close()
			}
			if _, err := f.lease(t); err == nil {
				t.Fatal("invalid source material accepted")
			}
		})
	}
}

func TestMaterialBytesRejectIdentitySubstitutionAndWrongKey(t *testing.T) {
	for _, mode := range []string{"subject", "issuer", "key"} {
		t.Run(mode, func(t *testing.T) {
			f := newMaterialBytesFixture(t, "preauthorized_pool")
			switch mode {
			case "subject", "issuer":
				changes := map[string]protocolv4.Field{"subject_id": admissionText("other-subject")}
				if mode == "issuer" {
					changes = map[string]protocolv4.Field{"issuer_key_id": admissionBytes(bytes.Repeat([]byte{99}, 16))}
				}
				other := initialSignTemplate(t, "IdentityCertificate", f.config.ClientCertificate, changes, [32]byte{71, 23, 4})
				f.config.ClientCertificate, _ = other.Bytes()
			case "key":
				f.admissionIntegrationFixture.trust.signers[0] = f.admissionIntegrationFixture.trust.signers[1]
			}
			if _, err := f.identity(t, protocolv4.ClientToServer); err == nil {
				t.Fatal("untrusted identity or mismatched key accepted")
			}
		})
	}
}

func TestMaterialBytesSourceThroughDurableAdmissionAndDuplex(t *testing.T) {
	for _, source := range []string{"preauthorized_pool", "live_authority"} {
		t.Run(source, func(t *testing.T) { sessionEstablishmentDuplex(t, source, true, true, true, true, true, true) })
	}
}

type materialIdentitySigner struct {
	bootstrapSigner
	observe func()
}

func (s materialIdentitySigner) PublicKey() []byte {
	s.observe()
	return s.bootstrapSigner.PublicKey()
}

func TestMaterialBytesIdentityRechecksTrustAfterActualKeyProvider(t *testing.T) {
	f := newMaterialBytesFixture(t, "preauthorized_pool")
	charge, _ := ApplicationIdentityCharge(4096, 8192)
	signer := materialIdentitySigner{bootstrapSigner: f.admissionIntegrationFixture.trust.signers[0], observe: f.trust.Close}
	_, err := NewApplicationIdentityFromBytes(ApplicationIdentityBytesConfig{Certificate: f.config.ClientCertificate, Trust: f.trust, Role: protocolv4.ClientToServer, Signer: signer, StaticDH: f.admissionIntegrationFixture.trust.keys[0], MapNodes: 4096, RuntimeBytes: 8192}, f.reserve(charge), f.preauth)
	if err == nil {
		t.Fatal("key provider tail crossed current independent trust rejection")
	}
}
