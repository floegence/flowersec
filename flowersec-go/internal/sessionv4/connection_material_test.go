package sessionv4

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

func materialTestBundle(t *testing.T, f *admissionIntegrationFixture, role protocolv4.Direction, base uint32) (*ConnectionMaterial, *ApplicationIdentity, *ArtifactLease) {
	t.Helper()
	reserve := func(n uint32, cost resourcev4.Vector) resourcev4.Reference {
		ref, err := f.root.Reserve(admissionResourceKey(f.owner, base+n), cost)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(ref.Release)
		return ref
	}
	var validation [3]protocolv4.CredentialValidation
	for j := range validation {
		validation[j] = protocolv4.CredentialValidation{Namespace: f.trust.namespace, Issuer: f.trust.trust.permissions[j], Policy: f.trust.trust.policy}
	}
	identityCharge, err := ApplicationIdentityCharge(4096, 8192)
	if err != nil {
		t.Fatal(err)
	}
	i, err := NewApplicationIdentity(ApplicationIdentityConfig{Certificate: f.trust.certificates[role], Signer: f.trust.signers[role], StaticDH: f.trust.keys[role], Validation: validation[int(role)+1], Role: role, MapNodes: 4096, RuntimeBytes: 8192}, reserve(0, identityCharge), f.preauth)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(i.Close)
	lc := ArtifactLeaseConfig{Artifact: f.trust.artifact, Proof: f.trust.proof, ClientCertificate: f.trust.certificates[0], ServerCertificate: f.trust.certificates[1], Source: f.trust.source, Validation: validation, Verification: LiveProofVerification{Rules: f.trust.rules, Delegation: f.trust.delegation, Once: f.trust.once, Key: f.trust.proof.Key()}, MapBytes: 65536, MapNodes: 4096, RuntimeBytes: 65536}
	if lc.Source == "live_authority" {
		lc.Proof = nil
	}
	leaseCharge, err := ArtifactLeaseCharge(lc.MapBytes, lc.MapNodes, lc.RuntimeBytes)
	if err != nil {
		t.Fatal(err)
	}
	l, err := NewArtifactLease(lc, reserve(1, leaseCharge), f.preauth)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(l.Close)
	materialCharge, err := ConnectionMaterialCharge(8192)
	if err != nil {
		t.Fatal(err)
	}
	m, err := NewConnectionMaterial(l, i, MaterialGeneration{Source: [16]byte{1}, Generation: 1}, 8192, reserve(2, materialCharge))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Close)
	return m, i, l
}

func TestConnectionMaterialCapturesOriginalIdentityAndLocalClaim(t *testing.T) {
	f := admissionIntegration(t, context.Background(), "preauthorized_pool")
	m, i, l := materialTestBundle(t, f, protocolv4.ClientToServer, 280)
	charge, _ := ConnectionMaterialCharge(8192)
	ref, err := f.root.Reserve(admissionResourceKey(f.owner, 285), charge)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ref.Release)
	second, err := NewConnectionMaterial(l, i, MaterialGeneration{Source: [16]byte{2}, Generation: 2}, 8192, ref)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(second.Close)
	i.Close()
	l.Close()
	if _, err := i.capture(f.environment); err == nil {
		t.Fatal("closed advertisement yielded another identity")
	}
	if _, err := l.capture(f.environment); err == nil {
		t.Fatal("closed advertisement yielded another lease")
	}
	f.trust.subscriptions[0].Close()
	limits := EstablishmentLimits{MapBytes: 65536, MapNodes: 4096, Hello: protocolv4.HelloLimits{HelloBytes: 16384, HelloNodes: 4096, RouteBytes: 16384, ContextBytes: 1024}, RuntimeBytes: 65536}
	planCharge, _ := EstablishmentCharge(limits)
	planRef, err := f.root.Reserve(admissionResourceKey(f.owner, 286), planCharge)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(planRef.Release)
	subRef, err := f.root.Reserve(admissionResourceKey(f.owner, 287), protocolv4.CredentialSubscriptionsCharge())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(subRef.Release)
	hello := InitialHello{Index: 0, Attempt: f.trust.attempt, Policy: protocolv4.HelloPolicy{BindingMode: 1}, BindingModes: 2}
	before := f.root.Snapshot()
	if _, _, err := m.Establishment(hello, limits, MaterialGeneration{Source: [16]byte{1}, Generation: 2}, planRef, subRef); err == nil {
		t.Fatal("changed source generation accepted")
	}
	if before != f.root.Snapshot() || m.used || l.claimed {
		t.Fatal("wrong generation consumed material")
	}
	p, subscriptions, err := m.Establishment(hello, limits, MaterialGeneration{Source: [16]byte{1}, Generation: 1}, planRef, subRef)
	if err != nil {
		t.Fatal(err)
	}
	defer subscriptions.Close()
	if _, _, err := second.Establishment(hello, limits, MaterialGeneration{Source: [16]byte{2}, Generation: 2}, p.reservation, subscriptionsTestReference(t, f)); err == nil {
		t.Fatal("another wrapper recovered the same local lease")
	}
	m.Close()
	wait, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := m.WaitCleanup(wait); err == nil {
		t.Fatal("material discarded keys before original plan retired")
	}
	subscriptions.Close()
	if err := p.Retire(); err != nil {
		t.Fatal(err)
	}
	second.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := m.WaitCleanup(ctx); err != nil {
		t.Fatal(err)
	}
	if err := i.WaitCleanup(ctx); err != nil {
		t.Fatal(err)
	}
	if err := l.WaitCleanup(ctx); err != nil {
		t.Fatal(err)
	}
}

func subscriptionsTestReference(t *testing.T, f *admissionIntegrationFixture) resourcev4.Reference {
	t.Helper()
	ref, err := f.root.Reserve(admissionResourceKey(f.owner, 288), protocolv4.CredentialSubscriptionsCharge())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ref.Release)
	return ref
}

func TestConnectionMaterialOpaqueDiagnosticsAndRevocation(t *testing.T) {
	f := admissionIntegration(t, context.Background(), "preauthorized_pool")
	m, i, l := materialTestBundle(t, f, protocolv4.ClientToServer, 280)
	for _, value := range []any{m, i, l} {
		wire, err := json.Marshal(value)
		if err != nil || string(wire) != "{}" {
			t.Fatal("JSON leaked material", err)
		}
		for _, format := range []string{"%v", "%+v", "%#v"} {
			text := fmt.Sprintf(format, value)
			if !strings.HasPrefix(text, "Flowersec.") || len(text) > 40 {
				t.Fatal("debug exposed material")
			}
		}
	}
	f.trust.trust.rejected.Store(true)
	if err := m.check(); err == nil {
		t.Fatal("captured material ignored current revocation")
	}
}

func TestApplicationIdentityRejectsDifferentLocalKeyBeforeMaterial(t *testing.T) {
	f := admissionIntegration(t, context.Background(), "preauthorized_pool")
	key, err := cryptov4.GenerateDHKey(f.trust.session.Profile)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Close()
	charge, err := ApplicationIdentityCharge(4096, 8192)
	if err != nil {
		t.Fatal(err)
	}
	before := f.root.Snapshot()
	ref, err := f.root.Reserve(admissionResourceKey(f.owner, 280), charge)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ref.Release)
	i, err := NewApplicationIdentity(ApplicationIdentityConfig{Certificate: f.trust.certificates[0], Signer: f.trust.signers[0], StaticDH: key, Validation: protocolv4.CredentialValidation{Namespace: f.trust.namespace, Issuer: f.trust.trust.permissions[1], Policy: f.trust.trust.policy}, Role: protocolv4.ClientToServer, MapNodes: 4096, RuntimeBytes: 8192}, ref, f.preauth)
	if i != nil || err == nil {
		t.Fatal("unmatched key acquired certificate identity")
	}
	if f.root.Snapshot() != before {
		t.Fatal("failed immutable identity retained resources")
	}
}
