package protocolv4

import (
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
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
	return detachCredentialDocument(m.document, c.schema, m.key, c.signatureID, c.encoded)
}

// Issuance planning also reads schema-checked fields before a signature exists.
// Such private candidates never leave their plan or enter endpoint admission;
// only DetachCredential exposes facts from a verified SignedMap.
func detachCredentialDocument(document *Document, schema string, key [32]byte, signatureID uint64, scratch []byte) (*Credential, error) {
	class, domain, expiry, err := credentialSchema(schema)
	if err != nil {
		return nil, err
	}
	if err := document.ValidateRules(DecodeContext{}); err != nil {
		return nil, err
	}
	digest, err := credentialDocumentDigest(domain, schema, document, signatureID, scratch)
	if err != nil {
		return nil, err
	}
	root := document.Root()
	text := func(v Value, s, field string) string { result, _ := v.Named(s, field).Text(); return result }
	issuer, _ := root.Named(schema, "issuer_key_id").ByteString()
	ns, nsSchema, generation := root, schema, "revocation_authority_generation"
	if schema == "Grant" {
		ns, nsSchema, generation = root.Named(schema, "namespace"), "GrantNamespace", "generation"
	}
	capacity, _ := ns.Named(nsSchema, "namespace_capacity_digest").ByteString()
	credential := &Credential{key: key, scope: CredentialScope{
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

// credentialDocumentDigest applies the registry's exact credential digest
// projection. Grant digests intentionally omit the signature field, while
// Artifact and IdentityCertificate digests cover the complete map.
func credentialDocumentDigest(name, schema string, document *Document, signatureID uint64, scratch []byte) ([32]byte, error) {
	if document == nil {
		return [32]byte{}, CBORFailure("credential_owner")
	}
	r, err := runtimeSignedMaps()
	if err != nil {
		return [32]byte{}, err
	}
	domain, ok := r.digests[name]
	if !ok || len(domain.Input.Parts) != 1 || domain.Input.Parts[0].Schema != schema {
		return [32]byte{}, CBORFailure("digest_schema")
	}
	wire := document.Bytes()
	if domain.Input.Parts[0].Projection == "without_signature" {
		if len(scratch) < len(wire) {
			return [32]byte{}, CBORFailure("configuration_capacity")
		}
		wire, err = document.copyWithout(scratch, signatureID)
		if err != nil {
			return [32]byte{}, err
		}
		defer clear(scratch[:len(wire)])
	} else if domain.Input.Parts[0].Projection != "full" {
		return [32]byte{}, CBORFailure("digest_schema")
	}
	return hashMapDomain(domain, wire)
}

// credentialWireDigest verifies an already-owned signed credential wire and
// applies its registered digest projection. It is used when a relay matcher
// has only the original detached credential key plus the received bytes.
func credentialWireDigest(name, schema string, wire []byte, key [32]byte) ([32]byte, error) {
	limit, err := SchemaByteLimit(schema)
	if err != nil {
		return [32]byte{}, err
	}
	codec, err := NewSignedMapCodec(schema, limit, limit)
	if err != nil {
		return [32]byte{}, err
	}
	signed, err := codec.Verify(wire, key, DecodeContext{})
	if err != nil {
		return [32]byte{}, err
	}
	defer signed.Release()
	return signed.Digest(name)
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
