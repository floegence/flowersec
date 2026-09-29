package protocolv4

import (
	"bytes"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// DirectIssueHTTPTestHarness exposes a real independently bootstrapped issuer
// to external HTTP tests without adding an issuance bypass to production code.
type DirectIssueHTTPTestHarness struct {
	f      *directIssuerFixture
	t      *testing.T
	Issuer *DirectIssuer
	Clock  *timev4.Clock
}

func NewDirectIssueHTTPTestHarness(t *testing.T, authority DirectIssueAuthority) *DirectIssueHTTPTestHarness {
	f := directIssuerFixtureFor(t, false, func(f *onlineBootstrapFixture) {
		n := f.namespace
		entry := n.seed(t, "activation_delegation_fields")
		parent := oracleField(t, n.r.cborReference, "TrustConfig", f.config, "issuer_authorizations").items[0]
		issuer := oracleField(t, n.r.cborReference, "CredentialIssuerAuthorization", parent, "issuer_key_id")
		for name, value := range map[string]*cborRefValue{
			"tenant_id": namespaceText("tenant-1"), "revocation_authority_id": namespaceText("revocation-1"), "namespace_capacity_digest": namespaceBytes(n.rules.capacityDigest[:]), "artifact_issuer_key_id": issuer, "issuer_key_id": namespaceBytes(bytes.Repeat([]byte{0x91}, 16)), "authority_generation": namespaceNumber(1), "signing_not_before_ms": namespaceNumber(1000), "signing_not_after_ms": namespaceNumber(5000), "first_parent_cohort": namespaceNumber(0), "last_parent_cohort": namespaceNumber(100), "max_activation_not_after_ms": namespaceNumber(5000), "max_session_not_after_ms": namespaceNumber(6000), "max_affected_cohorts": namespaceArray(&cborRefValue{major: 7, n: 22}, namespaceNumber(100)),
		} {
			n.set(t, "ConnectionActivationDelegation", entry, name, value)
		}
		spend := oracleField(t, n.r.cborReference, "ConnectionActivationDelegation", entry, "authority_id")
		once := n.mapValue(t, "OnceAuthorityRef", map[string]*cborRefValue{"tenant_id": namespaceText("tenant-1"), "artifact_issuer_key_id": issuer, "spend_authority_id": spend, "winner_authority_id": namespaceText("winner-1")})
		f.set(t, "activation_delegations", namespaceArray(entry))
		f.set(t, "once_authorities", namespaceArray(once))
	})
	f.s.c.Authority = authority
	return &DirectIssueHTTPTestHarness{f: f, t: t, Issuer: f.s, Clock: f.c.Clock}
}
func (h *DirectIssueHTTPTestHarness) Reserve(v resourcev4.Vector) resourcev4.Reference {
	return h.f.f.namespace.reserve(h.t, v)
}
func (h *DirectIssueHTTPTestHarness) Verify(wire []byte) error {
	c, err := NewSignedMapCodec("Artifact", 65536, 16384)
	if err != nil {
		return err
	}
	m, err := c.Verify(wire, [32]byte(h.f.signer.PublicKey()), DecodeContext{})
	if err == nil {
		m.Release()
	}
	return err
}

type DirectIssueSourceTestInputs struct {
	Root                                                         *resourcev4.Root
	Owner                                                        resourcev4.OwnerKey
	Trust                                                        [3]*NamespaceTrustStore
	Client, Server                                               []byte
	ClientIdentity                                               [32]byte
	Tenant, Audience, Profile, ActivationKey, ApplicationProfile string
	K                                                            uint16
}

func (h *DirectIssueHTTPTestHarness) SourceInputs() DirectIssueSourceTestInputs {
	f := h.f
	scope := f.s.certificates[0].Scope()
	trust := f.f.owner
	key := trust.configurations[trust.count-1].activations[0].binding.SigningKeyID
	doc, err := boundedMap(f.c.SessionContract, "SessionContract")
	if err != nil {
		h.t.Fatal(err)
	}
	defer doc.Release()
	profile, _ := doc.Root().Named("SessionContract", "application_profile").Uint()
	k, _ := doc.Root().Named("SessionContract", "rpc_max_general_outstanding").Uint()
	return DirectIssueSourceTestInputs{Root: f.f.namespace.resources, Owner: f.f.namespace.resourceOwner(), Trust: f.c.Trust, Client: f.c.ClientCertificate, Server: f.c.ServerCertificate, ClientIdentity: f.s.certificates[0].Facts().Digest, Tenant: scope.Tenant, Audience: scope.Audience, Profile: scope.Profile, ActivationKey: key, ApplicationProfile: []string{"transport", "services", "execution"}[profile], K: uint16(k)}
}
