package protocolv4

import (
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

// CredentialScope is detached original issuance context for an independent
// trust decision. Subject/Profile/Role apply to certificates; Service applies
// to grants. Empty inapplicable fields do not mean wildcard authorization.
// Trust must authorize these facts against its original immutable permissions,
// not construct permissions from this peer-supplied claim.
type CredentialScope struct {
	Schema, Tenant, Authority, Audience, Subject, Profile, Service string
	CapacityDigest                                                 [32]byte
	Issuer                                                         [16]byte
	Generation, Cohort, IssuedMS, ExpiresMS, Role                  uint64
	ParentIssuer                                                   [16]byte
	ParentAuthority                                                string
	ParentCapacityDigest                                           [32]byte
	ParentGeneration, ParentCohort                                 uint64
}

// Credential retains only verified public facts, never an original Artifact,
// decoder, PSK or private key. Its fields cannot be supplied by callers. This
// permits the initial secret-bearing owners to be erased after authentication
// while every Session operation still checks current trust and revocation.
type Credential struct {
	scope        CredentialScope
	key          [32]byte
	facts        CredentialStateFacts
	lease        [16]byte
	admissionEnd uint64
}

func CredentialBackingBytes(schema string) (uint64, error) {
	if _, _, _, err := credentialSchema(schema); err != nil {
		return 0, err
	}
	limit, err := SchemaByteLimit(schema)
	if err != nil {
		return 0, err
	}
	// Every detached string is copied from disjoint original text fields.
	return uint64(unsafe.Sizeof(Credential{})) + uint64(limit), nil
}

func credentialSchema(schema string) (class int, domain, expiry string, err error) {
	switch schema {
	case "IdentityCertificate":
		return 0, "certificate_digest", "expires_at_ms", nil
	case "Artifact":
		return 1, "artifact_digest", "session_not_after_ms", nil
	case "Grant":
		return 1, "grant_digest", "not_after_ms", nil
	default:
		return 0, "", "", CBORFailure("revocation_issuer_permission")
	}
}

// DetachCredential validates the complete registered rules before copying
// facts from the signature-checked original. This is not a trust decision.
func (m *SignedMap) DetachCredential() (*Credential, error) {
	if m == nil {
		return nil, CBORFailure("credential_owner")
	}
	c := m.codec
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.current != m {
		return nil, CBORFailure("document_released")
	}
	class, domain, expiry, err := credentialSchema(c.schema)
	if err != nil {
		return nil, err
	}
	if err := m.document.ValidateRules(DecodeContext{}); err != nil {
		return nil, err
	}
	digest, err := m.digestLocked(domain)
	if err != nil {
		return nil, err
	}
	root, schema := m.document.Root(), c.schema
	text := func(v Value, s, field string) string { result, _ := v.Named(s, field).Text(); return result }
	issuer, _ := root.Named(schema, "issuer_key_id").ByteString()
	ns, nsSchema, generation := root, schema, "revocation_authority_generation"
	if schema == "Grant" {
		ns, nsSchema, generation = root.Named(schema, "namespace"), "GrantNamespace", "generation"
	}
	capacity, _ := ns.Named(nsSchema, "namespace_capacity_digest").ByteString()
	credential := &Credential{key: m.key, scope: CredentialScope{
		Schema: schema, Tenant: text(root, schema, "tenant_id"), Audience: text(root, schema, "audience"),
		Authority: text(ns, nsSchema, "revocation_authority_id"), CapacityDigest: [32]byte(capacity), Issuer: [16]byte(issuer),
		Generation: valueUint(ns, nsSchema, generation), Cohort: valueUint(ns, nsSchema, "revocation_epoch"),
		IssuedMS: valueUint(root, schema, "issued_at_ms"), ExpiresMS: valueUint(root, schema, expiry),
	}}
	if text(ns, nsSchema, "tenant_id") != credential.scope.Tenant {
		return nil, CBORFailure("revocation_namespace_binding")
	}
	credential.facts = CredentialStateFacts{Digest: digest, Cohort: credential.scope.Cohort, HardDeadlineMS: credential.scope.ExpiresMS,
		PolicyID: text(ns, nsSchema, "revocation_policy_id"), PolicyRevision: valueUint(ns, nsSchema, "revocation_policy_revision"), class: class}
	switch schema {
	case "Artifact":
		lease, _ := root.Named(schema, "lease_id").ByteString()
		credential.lease = [16]byte(lease)
		credential.admissionEnd = valueUint(root, schema, "initiation_not_after_ms")
		credential.scope.Profile = text(root, schema, "crypto_profile_id")
	case "IdentityCertificate":
		credential.scope.Subject = text(root, schema, "subject_id")
		credential.scope.Profile = text(root, schema, "crypto_profile_id")
		credential.scope.Role = valueUint(root, schema, "role")
	case "Grant":
		credential.scope.Service = text(root, schema, "service")
		credential.scope.Role = valueUint(ns, nsSchema, "role_mask")
		parent := root.Named(schema, "parent_ref")
		parentIssuer, _ := parent.Named("GrantParentRef", "artifact_issuer_key_id").ByteString()
		parentCapacity, _ := parent.Named("GrantParentRef", "namespace_capacity_digest").ByteString()
		credential.scope.ParentIssuer = [16]byte(parentIssuer)
		credential.scope.ParentCapacityDigest = [32]byte(parentCapacity)
		credential.scope.ParentAuthority = text(parent, "GrantParentRef", "revocation_authority_id")
		credential.scope.ParentGeneration = valueUint(parent, "GrantParentRef", "authority_generation")
		credential.scope.ParentCohort = valueUint(parent, "GrantParentRef", "revocation_epoch")
	}
	return credential, nil
}

func (c *Credential) Scope() CredentialScope      { return c.scope }
func (c *Credential) Facts() CredentialStateFacts { return c.facts }

// CheckAdmission is separate from ongoing authorization: an ended initiation
// window cannot kill a Session admitted within its original window.
func (c *Credential) CheckAdmission(now timev4.Interval) error {
	if c == nil || c.scope.Schema != "Artifact" {
		return CBORFailure("credential_owner")
	}
	if !now.ValidBefore(c.admissionEnd) {
		return timev4.ErrExpired
	}
	return now.LowerBound(c.scope.IssuedMS, true)
}

func (c *Credential) checkPermission(p IssuerPermission) error {
	if c == nil || p.Schema == "" || p.Schema != c.scope.Schema || p.Key != c.key || p.Issuer != c.scope.Issuer || p.SigningStart >= p.SigningEnd {
		return CBORFailure("revocation_issuer_permission")
	}
	if c.scope.IssuedMS < p.SigningStart || c.scope.IssuedMS >= p.SigningEnd {
		return CBORFailure("revocation_credential_impact")
	}
	return nil
}
