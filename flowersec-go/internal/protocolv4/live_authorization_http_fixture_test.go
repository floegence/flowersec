package protocolv4

import (
	"bytes"
	"context"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// LiveAuthorizationHTTPTestHarness uses a real issued Artifact, independent
// authenticated TrustConfig, complete State and delegated activation signer.
type LiveAuthorizationHTTPTestHarness struct {
	Plan        *LiveActivationPlan
	Artifact    *Credential
	Trust       *NamespaceTrustStore
	Clock       *timev4.Clock
	Deadline    *timev4.Deadline
	Fields      LiveActivationFields
	Environment resourcev4.Reference
	Reserve     func(resourcev4.Vector) resourcev4.Reference
	f           *directIssuerFixture
}

func NewLiveAuthorizationHTTPTestHarness(t *testing.T) *LiveAuthorizationHTTPTestHarness {
	t.Helper()
	f := directIssuerFixtureFor(t, false)
	wire := make([]byte, 65536)
	size, err := f.s.IssueArtifactBytes(context.Background(), directIssuerRequest(), wire)
	if err != nil {
		t.Fatal(err)
	}
	codec, err := NewSignedMapCodec("Artifact", 65536, 16384)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := codec.Verify(wire[:size], [32]byte(f.signer.PublicKey()), DecodeContext{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(artifact.Release)
	credential, err := artifact.DetachCredential()
	if err != nil {
		t.Fatal(err)
	}
	n := f.f.namespace
	delegation := n.seed(t, "activation_delegation_fields")
	scope := credential.Scope()
	for name, value := range map[string]*cborRefValue{
		"tenant_id": namespaceText(scope.Tenant), "revocation_authority_id": namespaceText(scope.Authority), "namespace_capacity_digest": namespaceBytes(scope.CapacityDigest[:]), "authority_generation": namespaceNumber(scope.Generation), "artifact_issuer_key_id": namespaceBytes(scope.Issuer[:]), "signer_public_key": namespaceBytes(f.signer.PublicKey()), "authority_id": namespaceText("spend-1"), "signing_key_id": namespaceText("activation-1"),
		"signing_not_before_ms": namespaceNumber(1100), "signing_not_after_ms": namespaceNumber(1300), "max_activation_not_after_ms": namespaceNumber(1400), "max_session_not_after_ms": namespaceNumber(1900),
	} {
		n.set(t, "ConnectionActivationDelegation", delegation, name, value)
	}
	once := n.mapValue(t, "OnceAuthorityRef", map[string]*cborRefValue{"tenant_id": namespaceText(scope.Tenant), "artifact_issuer_key_id": namespaceBytes(scope.Issuer[:]), "spend_authority_id": namespaceText("spend-1"), "winner_authority_id": namespaceText("winner-1")})
	f.f.set(t, "activation_delegations", namespaceArray(delegation))
	f.f.set(t, "once_authorities", namespaceArray(once))
	f.f.advance(t, 2, 5000)
	if err = f.f.owner.Update(f.f.wire(t)); err != nil {
		t.Fatal(err)
	}
	rules, err := f.f.owner.Rules()
	if err != nil {
		t.Fatal(err)
	}
	reserve := func(v resourcev4.Vector) resourcev4.Reference { return n.reserve(t, v) }
	environment := reserve(resourcev4.Vector{resourcev4.SDKBytes: 4096})
	charge, err := LiveActivationPlanCharge()
	if err != nil {
		t.Fatal(err)
	}
	plan, err := NewLiveActivationPlan(artifact, rules, delegation.encode(nil), once.encode(nil), f.signer, LiveActivationConfig{Index: 0, Attempt: [16]byte{9}, IssuedAt: 1100, ActivationEnd: 1400, SessionEnd: 1900}, reserve(charge), environment, environment)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := plan.Close(); err != nil {
			t.Error(err)
		}
	})
	fields, _, err := plan.CopyProjection(make([]byte, 4096))
	if err != nil {
		t.Fatal(err)
	}
	deadline, err := timev4.NewDeadline(f.c.Clock, 1400)
	if err != nil {
		t.Fatal(err)
	}
	return &LiveAuthorizationHTTPTestHarness{Plan: plan, Artifact: credential, Trust: f.f.owner, Clock: f.c.Clock, Deadline: deadline, Fields: fields, Environment: environment, Reserve: reserve, f: f}
}
func (h *LiveAuthorizationHTTPTestHarness) Verify(wire []byte) error {
	codec, err := NewSignedMapCodec("ActivationAuthorization", 4096, 4096)
	if err != nil {
		return err
	}
	signed, err := codec.Verify(wire, [32]byte(h.f.signer.PublicKey()), DecodeContext{Selectors: map[string]string{"activation_source_profile": "live_authority"}})
	if err != nil {
		return err
	}
	defer signed.Release()
	projection := make([]byte, 4096)
	_, n, err := h.Plan.CopyProjection(projection)
	if err != nil {
		return err
	}
	return signed.MatchUnsignedProjection(projection[:n])
}
func (h *LiveAuthorizationHTTPTestHarness) RevokeIssuer(t *testing.T) {
	h.f.f.set(t, "retired_issuers", namespaceArray(namespaceBytes(bytes.Repeat([]byte{0x12}, 16))))
	h.f.f.advance(t, 3, 5000)
	if err := h.Trust.Update(h.f.f.wire(t)); err != nil {
		t.Fatal(err)
	}
}
