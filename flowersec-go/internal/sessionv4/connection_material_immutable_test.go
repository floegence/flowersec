package sessionv4

import (
	"bytes"
	"context"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

func TestImmutableEstablishmentPreservesAbsentPendingFactsAndFullCharge(t *testing.T) {
	for _, source := range []string{"preauthorized_pool", "live_authority"} {
		for _, role := range []protocolv4.Direction{protocolv4.ClientToServer, protocolv4.ServerToClient} {
			t.Run(source+"/"+map[protocolv4.Direction]string{protocolv4.ClientToServer: "client", protocolv4.ServerToClient: "server"}[role], func(t *testing.T) {
				f := admissionIntegration(t, context.Background(), source)
				f.trust.subscriptions[role].Close()
				before := f.root.Snapshot().Charged
				material, identity, lease := materialTestBundle(t, f, role, 280)
				limits := EstablishmentLimits{MapBytes: 65536, MapNodes: 4096, Hello: protocolv4.HelloLimits{HelloBytes: 16384, HelloNodes: 4096, RouteBytes: 16384, ContextBytes: 1024}, RuntimeBytes: 65536}
				charge, err := EstablishmentCharge(limits)
				if err != nil {
					t.Fatal(err)
				}
				reserve := func(serial uint32, cost resourcev4.Vector) resourcev4.Reference {
					ref, err := f.root.Reserve(admissionResourceKey(f.owner, serial), cost)
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(ref.Release)
					return ref
				}
				planRef := reserve(286, charge)
				subscriptionRef := reserve(287, protocolv4.CredentialSubscriptionsCharge())
				held := f.root.Snapshot().Charged
				plan, _, err := material.Establishment(InitialHello{Index: 0, Attempt: f.trust.attempt, Policy: protocolv4.HelloPolicy{BindingMode: 1}, BindingModes: 2}, limits, material.generation, planRef, subscriptionRef)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := plan.Retire(); err != nil {
						t.Error(err)
					}
				})
				for _, slot := range []int{6, 7, 8} {
					if plan.codecs[slot] != nil {
						t.Fatal("absent direct tunnel material allocated a decoder", slot)
					}
				}
				if plan.codecs[1] == nil || plan.codecs[4] == nil || plan.codecs[5] == nil {
					t.Fatal("required proof/admission workspace was omitted")
				}
				localSigning := 4 + int(role)
				if _, err := plan.codecs[localSigning].Verify(nil, [32]byte{}, protocolv4.DecodeContext{}); err != protocolv4.CBORFailure("signature_owner") {
					t.Fatal("local admission slot retained a reusable verification owner", err)
				}
				if plan.mapBytes != limits.MapBytes {
					t.Fatal("private handshake copies lost their complete declared allowance")
				}
				if source == "live_authority" {
					if plan.material.Proof != nil || plan.material.Activation != nil {
						t.Fatal("pending live material manufactured an authorization fact")
					}
					wire, err := f.trust.proof.Bytes()
					if err != nil {
						t.Fatal(err)
					}
					original := bytes.Clone(wire)
					input := bytes.Clone(wire)
					input[len(input)-1] ^= 1
					if err := plan.bindLiveProof(input); err == nil || plan.material.Proof != nil {
						t.Fatal("invalid pending proof was published", err)
					}
					copy(input, wire)
					if err := plan.bindLiveProof(input); err != nil {
						t.Fatal("first valid pending proof lost its original capacity", err)
					}
					clear(input)
					retained, err := plan.material.Proof.Bytes()
					if err != nil || !bytes.Equal(retained, original) {
						t.Fatal("pending proof borrowed the delivery buffer", err)
					}
				}
				identity.Close()
				lease.Close()
				material.Close()
				plan.Close()
				if f.root.Snapshot().Charged != held || plan.reservation.CheckRetained() != nil || plan.shared.CheckRetained() != nil {
					t.Fatal("optional facts or compact maps refunded a captured establishment")
				}
				if _, err := plan.material.Artifact.Bytes(); err != nil {
					t.Fatal("Close discarded the original credential before retirement", err)
				}
				if err := plan.Retire(); err != nil {
					t.Fatal(err)
				}
				for _, wait := range []func(context.Context) error{material.WaitCleanup, identity.WaitCleanup, lease.WaitCleanup} {
					if err := wait(context.Background()); err != nil {
						t.Fatal(err)
					}
				}
				if f.root.Snapshot().Charged != before {
					t.Fatal("actual establishment retirement retained its complete charge")
				}
			})
		}
	}
}

func TestImmutableMaterialRetainsFullChargeThroughCapture(t *testing.T) {
	for _, source := range []string{"preauthorized_pool", "live_authority"} {
		t.Run(source, func(t *testing.T) {
			f := admissionIntegration(t, context.Background(), source)
			before := f.root.Snapshot().Charged
			material, identity, lease := materialTestBundle(t, f, protocolv4.ClientToServer, 280)
			identityCharge, err := ApplicationIdentityCharge(4096, 8192)
			if err != nil {
				t.Fatal(err)
			}
			leaseCharge, err := ArtifactLeaseCharge(65536, 4096, 65536)
			if err != nil {
				t.Fatal(err)
			}
			materialCharge, err := ConnectionMaterialCharge(8192)
			if err != nil {
				t.Fatal(err)
			}
			want, err := before.Add(identityCharge)
			if err == nil {
				want, err = want.Add(leaseCharge)
			}
			if err == nil {
				want, err = want.Add(materialCharge)
			}
			if err != nil || f.root.Snapshot().Charged != want {
				t.Fatal("immutable compaction refunded the complete material charge", err)
			}
			if lease.codecs[4] != nil || lease.codecs[5] != nil || source == "live_authority" && lease.codecs[1] != nil {
				t.Fatal("absent proof or tunnel credential allocated a decoder")
			}
			identity.Close()
			lease.Close()
			if f.root.Snapshot().Charged != want || identity.reservation.CheckRetained() != nil || lease.reservation.CheckRetained() != nil {
				t.Fatal("advertisement Close refunded captured immutable facts")
			}
			if err := material.check(); err != nil {
				t.Fatal("Close invalidated the captured original credential", err)
			}
			material.Close()
			if err := material.WaitCleanup(context.Background()); err != nil {
				t.Fatal(err)
			}
			if err := identity.WaitCleanup(context.Background()); err != nil {
				t.Fatal(err)
			}
			if err := lease.WaitCleanup(context.Background()); err != nil {
				t.Fatal(err)
			}
			if f.root.Snapshot().Charged != before {
				t.Fatal("physical material cleanup retained its original complete charge")
			}
		})
	}
}
