package protocolv4

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

// Tests use independent fixture signing keys to exercise the production root
// verification owner. None of the runtime trust methods is replaced by a stub.
type independentTrustFixture struct {
	namespace *namespaceFixture
	owner     *NamespaceTrustStore
	config    *cborRefValue
	seed      [32]byte
}

func (f *independentTrustFixture) wire(t *testing.T) []byte {
	t.Helper()
	wire := f.config.encode(nil)
	decoder, err := NewDecoder(32768, 8192)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := decoder.DecodeMap(wire, "TrustConfig", DecodeContext{})
	if err != nil {
		t.Fatal(err)
	}
	defer doc.Release()
	codec, err := NewSignedMapCodec("TrustConfig", 32768, 8192)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := codec.Sign(unsignedFixtureFields(t, doc, 17), f.seed, DecodeContext{})
	if err != nil {
		t.Fatal(err)
	}
	defer signed.Release()
	result, err := signed.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return bytes.Clone(result)
}
func independentTrust(t *testing.T) *independentTrustFixture {
	t.Helper()
	n := newNamespaceFixture(t)
	f := &independentTrustFixture{namespace: n, config: n.seed(t, "trust_config_fields"), seed: [32]byte{71, 23, 4}}
	clock, _ := namespaceClockFixture(t, n, false)
	codec, err := NewSignedMapCodec("TrustConfig", 32768, 8192)
	if err != nil {
		t.Fatal(err)
	}
	// SignWith is independently tested; use the canonical signer to obtain its
	// public key without importing or trusting any key from the signed config.
	wire := f.wire(t)
	// The same seed is part of this test's explicitly installed root policy.
	pub := testTrustPublic(f.seed)
	signed, err := codec.Verify(wire, pub, DecodeContext{})
	if err != nil {
		t.Fatal(err)
	}
	key, _ := signed.Field("signing_key_id").ByteString()
	id := [16]byte(key)
	signed.Release()
	limits := NamespaceTrustLimits{Configurations: 4, ConfigBytes: 32768, MapNodes: 8192, RuntimeBytes: 65536}
	cost, err := NamespaceTrustCharge(limits)
	if err != nil {
		t.Fatal(err)
	}
	dependencies := n.reserve(t, resourcev4.Vector{resourcev4.SDKBytes: 4096, resourcev4.Items: 1})
	borrow, err := dependencies.Borrow()
	if err != nil {
		t.Fatal(err)
	}
	f.owner, err = NewNamespaceTrustStore(NamespaceTrustRoot{Tenant: "tenant-1", Authority: "revocation-1", KeyID: id, PublicKey: pub, MaxLifetimeMS: 10000}, limits, clock, wire, n.reserve(t, cost), borrow)
	borrow.Release()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		f.owner.Close()
		n.resources.Close()
		if err := f.owner.DestroyEnvironment(); err != nil {
			t.Error(err)
		}
	})
	return f
}
func (f *independentTrustFixture) set(t *testing.T, name string, value *cborRefValue) {
	f.namespace.set(t, "TrustConfig", f.config, name, value)
}
func (f *independentTrustFixture) advance(t *testing.T, revision, end uint64) {
	f.set(t, "revision", namespaceNumber(revision))
	f.set(t, "not_after_ms", namespaceNumber(end))
}

func TestNamespaceTrustOriginalAuthorityAndHistory(t *testing.T) {
	f := independentTrust(t)
	o := f.owner
	first := o.configurations[0]
	issuer := first.issuers[0]
	scope := issuer.scope
	scope.IssuedMS, scope.ExpiresMS, scope.Cohort = 1100, 4000, 1
	if err := o.Issuer(issuer.permission, scope); err != nil {
		t.Fatal(err)
	}
	wrong := scope
	wrong.Subject = "another endpoint"
	if err := o.Issuer(issuer.permission, wrong); err != CBORFailure("revocation_issuer_permission") {
		t.Fatal("subject ignored", err)
	}
	wrong = scope
	wrong.Role = 1
	if err := o.Issuer(issuer.permission, wrong); err != CBORFailure("revocation_issuer_permission") {
		t.Fatal("signed role ignored", err)
	}
	wrong = scope
	wrong.Generation++
	if err := o.Issuer(issuer.permission, wrong); err != CBORFailure("revocation_issuer_permission") {
		t.Fatal("generation ignored", err)
	}
	head := first.heads[0]
	binding := NamespaceHeadTrust{Tenant: o.root.Tenant, Authority: o.root.Authority, Capacity: o.rules.capacityDigest, Delegation: head.digest, Signer: head.signer, Generation: first.generation, TrustIssuedMS: first.issued, TrustNotAfterMS: first.end}
	if err := o.Head(binding); err != nil {
		t.Fatal(err)
	}
	if err := o.Update(f.wire(t)); err != nil || o.count != 1 {
		t.Fatal("same original configuration changed history", err)
	}
	f.advance(t, 2, 5500)
	if err := o.Update(f.wire(t)); err != nil {
		t.Fatal(err)
	}
	if err := o.Head(binding); err != nil {
		t.Fatal("refresh lost original Head trust interval", err)
	}
	binding.TrustNotAfterMS = 5400
	if err := o.Head(binding); err != CBORFailure("revocation_trust_binding") {
		t.Fatal("fabricated original interval accepted", err)
	}
	f.advance(t, 1, 5000)
	if err := o.Update(f.wire(t)); err != CBORFailure("revocation_trust_rollback") {
		t.Fatal(err)
	}
	if o.count != 2 {
		t.Fatal("rejected revision consumed history slot")
	}
	f.advance(t, 3, 6000)
	f.set(t, "retired_issuers", namespaceArray(namespaceBytes(issuer.permission.Issuer[:])))
	if err := o.Update(f.wire(t)); err != nil {
		t.Fatal(err)
	}
	if !o.RetiredIssuer(issuer.permission.Issuer) {
		t.Fatal("lost independent permanent retirement")
	}
	if err := o.Issuer(issuer.permission, scope); err != CBORFailure("revocation_issuer_rejected") {
		t.Fatal("retired issuer still authorized", err)
	}
	f.advance(t, 4, 6500)
	f.set(t, "retired_issuers", namespaceArray())
	if err := o.Update(f.wire(t)); err != CBORFailure("revocation_trust_rollback") {
		t.Fatal("forgot permanent rejection", err)
	}
	o.Close()
	if err := o.DestroyEnvironment(); err != CBORFailure("revocation_trust_owner") {
		t.Fatal("ordinary close erased history", err)
	}
}

func TestNamespaceTrustRejectsChangedOriginalPermissions(t *testing.T) {
	for _, field := range []string{"issuer_key", "issuer_scope", "head_delegation", "credential_policy", "signature"} {
		t.Run(field, func(t *testing.T) {
			f := independentTrust(t)
			f.advance(t, 2, 5500)
			switch field {
			case "issuer_key", "issuer_scope":
				v := oracleField(t, f.namespace.r.cborReference, "TrustConfig", f.config, "issuer_authorizations").items[0]
				if field == "issuer_key" {
					f.namespace.set(t, "CredentialIssuerAuthorization", v, "issuer_public_key", namespaceBytes(bytes.Repeat([]byte{41}, 32)))
				} else {
					f.namespace.set(t, "CredentialIssuerAuthorization", v, "subject_id", &cborRefValue{major: 3, data: []byte("different")})
				}
			case "head_delegation":
				v := oracleField(t, f.namespace.r.cborReference, "TrustConfig", f.config, "head_delegations").items[0]
				f.namespace.set(t, "HeadSignerDelegation", v, "not_after_ms", namespaceNumber(55000))
			case "credential_policy":
				v := oracleField(t, f.namespace.r.cborReference, "TrustConfig", f.config, "credential_policies").items[0]
				f.namespace.set(t, "CredentialRevocationPolicy", v, "max_staleness_ms", namespaceNumber(400000))
			}
			wire := f.wire(t)
			if field == "signature" {
				wire[len(wire)-1] ^= 1
			}
			if err := f.owner.Update(wire); err == nil {
				t.Fatal("changed independently authorized original accepted")
			}
			if f.owner.count != 1 {
				t.Fatal("failed authentication changed current trust")
			}
		})
	}
}

func testTrustPublic(seed [32]byte) [32]byte {
	key := ed25519.NewKeyFromSeed(seed[:])
	defer clear(key)
	return [32]byte(key.Public().(ed25519.PublicKey))
}

func TestNamespaceTrustRequiresRulesAfterAuthenticatingSignature(t *testing.T) {
	for _, invalid := range []string{"issuer_variant", "duplicate_authorization", "impact", "namespace_capacity", "lifetime"} {
		t.Run(invalid, func(t *testing.T) {
			f := independentTrust(t)
			f.advance(t, 2, 5500)
			entries := oracleField(t, f.namespace.r.cborReference, "TrustConfig", f.config, "issuer_authorizations")
			switch invalid {
			case "issuer_variant":
				f.namespace.set(t, "CredentialIssuerAuthorization", entries.items[0], "role", namespaceNumber(3))
			case "duplicate_authorization":
				entries.items = append(entries.items, entries.items[0])
			case "impact":
				f.namespace.set(t, "CredentialIssuerAuthorization", entries.items[0], "max_affected_cohorts", namespaceArray(namespaceNumber(0), namespaceNumber(0)))
			case "namespace_capacity":
				capacity := oracleField(t, f.namespace.r.cborReference, "TrustConfig", f.config, "capacity")
				f.namespace.set(t, "NamespaceCapacity", capacity, "tenant_id", &cborRefValue{major: 3, data: []byte("other")})
			case "lifetime":
				f.set(t, "issued_at_ms", namespaceNumber(5500))
			}
			signed := signRuntimeFixture(t, "TrustConfig", f.config.encode(nil), DecodeContext{})
			wire, err := signed.Bytes()
			if err != nil {
				t.Fatal(err)
			}
			if err := f.owner.Update(wire); err == nil || f.owner.count != 1 {
				t.Fatal("signature bypassed immutable configuration rules", err)
			}
		})
	}
}
