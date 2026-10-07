package sessionv4

import (
	"crypto/ed25519"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
)

// EngineeringOriginalPoolDeployment selects the actual issuer/outbox path in
// the engineering host. It never supplies a Grant or a committed receipt.
type EngineeringOriginalPoolDeployment interface{ AuthorityOriginalPoolDeployment() bool }

type EngineeringPoolIssueRecipe struct {
	Base                                                               protocolv4.DirectIssuerConfig
	Policy                                                             protocolv4.DirectIssuePolicyConfig
	ActivationSigner                                                   protocolv4.MapSigner
	ActivationSigningKeyID                                             string
	GrantIssuer                                                        [16]byte
	GrantSigner                                                        protocolv4.MapSigner
	RelayAudience                                                      string
	ClientIdentitySeed, ServerIdentitySeed, ClientDHSeed, ServerDHSeed [32]byte
}

func engineeringOriginalPool(t AuthorityReporter) bool {
	owner, ok := t.(EngineeringOriginalPoolDeployment)
	return ok && owner.AuthorityOriginalPoolDeployment()
}

func engineeringInstallOriginalPoolPolicy(t AuthorityReporter, f *authorityFixture, m *engineeringTunnelMaterials) {
	if m == nil {
		return
	}
	// These are independently configured issuer permissions, installed in the
	// signed TrustConfig before any real Artifact/Grant issuance is requested.
	for i := range f.trust.trust.permissions {
		f.trust.trust.permissions[i].SigningEnd = authorityTime(t, 4000)
	}
	f.trust.delegation = admissionMap(t, "ConnectionActivationDelegation", f.trust.delegation, map[string]protocolv4.Field{
		"signing_not_after_ms": {Number: 1400},
	})
	f.trust.trust.activation.DelegationDigest = admissionDigest(t, "connection_activation_delegation_digest", f.trust.delegation)
	parent, err := f.trust.artifact.DetachCredential()
	if err != nil {
		t.Fatal(err)
	}
	p := parent.Scope()
	key := [32]byte(ed25519.NewKeyFromSeed(m.recipe.GrantIssuerSeed[:]).Public().(ed25519.PublicKey))
	for side := range 2 {
		scope := protocolv4.CredentialScope{Schema: "Grant", Tenant: p.Tenant, Authority: p.Authority, Audience: m.recipe.RelayAudience, Service: p.Audience,
			CapacityDigest: p.CapacityDigest, Generation: p.Generation, Issuer: m.recipe.GrantIssuerID, Role: uint64(5 + side), ExpiresMS: p.ExpiresMS,
			ParentIssuer: p.Issuer, ParentAuthority: p.Authority, ParentCapacityDigest: p.CapacityDigest, ParentGeneration: p.Generation, ParentCohort: p.Cohort}
		f.trust.trust.additional = append(f.trust.trust.additional, engineeringCredentialAuthority{scope: scope, permission: protocolv4.IssuerPermission{Schema: "Grant", Issuer: scope.Issuer, Key: key, SigningStart: authorityTime(t, 1000), SigningEnd: authorityTime(t, 4000)}})
	}
	envelope := uint64(f.trust.session.Contract.Limits().MaxFrame) + uint64(protocolv4.EnvelopePrefixSize)
	for side := range m.recipe.Limits {
		m.recipe.Limits[side].EnvelopeBytes = envelope
	}
}

func engineeringPoolIssueRecipe(t AuthorityReporter, q *PublicQUICTestHarness, f *authorityFixture, m *engineeringTunnelMaterials) *EngineeringPoolIssueRecipe {
	p := f.trust.trust.scopes[0]
	artifact := f.trust.artifact
	client, err := f.trust.certificates[0].Bytes()
	if err != nil {
		t.Fatal(err)
	}
	server, err := f.trust.certificates[1].Bytes()
	if err != nil {
		t.Fatal(err)
	}
	seed := [32]byte{71, 23, 4}
	signer := bootstrapSigner{ed25519.NewKeyFromSeed(seed[:])}
	allowed, _ := artifact.Field("allowed_features").Uint()
	required, _ := artifact.Field("required_features").Uint()
	session := append([]byte(nil), artifact.Field("session_contract").Encoded()...)
	resume := append([]byte(nil), artifact.Field("resume_policy").Encoded()...)
	candidates := make([][]byte, artifact.Field("candidates").Len())
	for i := range candidates {
		candidates[i] = append([]byte(nil), artifact.Field("candidates").Index(i).Encoded()...)
	}
	policyID, _ := artifact.Field("revocation_policy_id").Text()
	policyRevision, _ := artifact.Field("revocation_policy_revision").Uint()
	signingID, _ := f.trust.proof.Field("signing_key_id").Text()
	// The durable issuer owns a separate bounded local signing share. It does
	// not include material bootstrap, native preparation or network admission.
	base := protocolv4.DirectIssuerConfig{Clock: q.Clock, Trust: q.Lease.Trust, Signer: signer, IssuerKeyID: p.Issuer, Tenant: p.Tenant, Audience: p.Audience, CryptoProfile: p.Profile,
		RevocationPolicyID: policyID, RevocationPolicyRevision: policyRevision, Generation: p.Generation, ClientCertificate: append([]byte(nil), client...), ServerCertificate: append([]byte(nil), server...),
		Candidates: candidates, SessionContract: session, ResumePolicy: resume, AllowedFeatures: allowed, RequiredFeatures: required,
		InitiationLifetimeMS: max(uint64(30000), engineeringOperationMS(t)), SessionLifetimeMS: max(uint64(60000), engineeringOperationMS(t)+60000), MaxAuthenticationBytes: 16384, WorkMS: 2000, RuntimeBytes: 65536}
	recipe := &EngineeringPoolIssueRecipe{Base: base, Policy: protocolv4.DirectIssuePolicyConfig{Trust: q.Lease.Trust[0], Clock: q.Clock, Issuer: p.Issuer, Audience: p.Audience, CryptoProfile: p.Profile, PolicyID: policyID, PolicyRevision: policyRevision},
		ActivationSigner: f.trust.issueSigner, ActivationSigningKeyID: signingID, GrantIssuer: m.recipe.GrantIssuerID, GrantSigner: bootstrapSigner{ed25519.NewKeyFromSeed(m.recipe.GrantIssuerSeed[:])}, RelayAudience: m.recipe.RelayAudience,
		ClientIdentitySeed: q.BrowserIdentitySeed, ClientDHSeed: q.BrowserDHSeed, ServerIdentitySeed: [32]byte{74, 29, 8}}
	if identity, ok := q.Identity[1].StaticDH.(publicFixtureDH); ok {
		copy(recipe.ServerDHSeed[:], identity.key.Bytes())
	} else {
		t.Fatal("original pool server requires its configured engineering DH owner")
	}
	return recipe
}
