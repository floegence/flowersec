package sessionv4

import (
	"bytes"
	"context"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
)

func newMaterialBytesFixture(t *testing.T, source string) *materialBytesFixture {
	return materialBytesFor(t, admissionIntegration(t, context.Background(), source))
}
func materialBytesFor(t *testing.T, f *admissionIntegrationFixture, registries ...*protocolv4.NamespaceRegistry) *materialBytesFixture {
	return authorityMaterialBytesFor(t, f.authorityFixture, registries...)
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
	i, err := NewApplicationIdentityFromBytes(ApplicationIdentityBytesConfig{Certificate: certificate, Trust: f.trust, Role: role, Signer: f.authorityFixture.trust.signers[role], StaticDH: f.authorityFixture.trust.keys[role], MapNodes: 4096, RuntimeBytes: 8192}, f.reserve(charge), f.preauth)
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

func TestPoolSpendInspectionPreservesOriginalProof(t *testing.T) {
	f := newMaterialBytesFixture(t, "preauthorized_pool")
	lease, err := f.lease(t)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		facts, err := lease.PoolSpendFacts(0)
		if err != nil {
			t.Fatal("repeat pool preflight", err)
		}
		if err := facts.MatchProofBytes(f.config.Proof); err != nil {
			t.Fatal("preflight changed the original proof", err)
		}
	}
	if err := lease.checkForUse(true); err != nil {
		t.Fatal("inspected material cannot enter Connect", err)
	}
	if lease.claimed {
		t.Fatal("inspection consumed the lease")
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
				f.config.Proof, _ = f.authorityFixture.trust.proof.Bytes()
			case "unknown_activation":
				f.config.ActivationSigningKeyID = "untrusted-key"
			case "expired":
				f.authorityFixture.trust.tick.Add(1000)
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
				f.authorityFixture.trust.signers[0] = f.authorityFixture.trust.signers[1]
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
	signer := materialIdentitySigner{bootstrapSigner: f.authorityFixture.trust.signers[0], observe: f.trust.Close}
	_, err := NewApplicationIdentityFromBytes(ApplicationIdentityBytesConfig{Certificate: f.config.ClientCertificate, Trust: f.trust, Role: protocolv4.ClientToServer, Signer: signer, StaticDH: f.authorityFixture.trust.keys[0], MapNodes: 4096, RuntimeBytes: 8192}, f.reserve(charge), f.preauth)
	if err == nil {
		t.Fatal("key provider tail crossed current independent trust rejection")
	}
}
