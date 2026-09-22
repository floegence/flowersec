package sessionv4

import (
	"context"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
)

// A second valid signature can keep the same parent/attempt/winner while
// changing the admission deadline. Current trust for the first proof must
// never authorize publication or acceptance of the second one.
func shorterAdmissionProof(t *testing.T, f *sessionAdmissionTrustFixture) {
	t.Helper()
	wire, err := f.proof.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	f.proof = initialSignTemplate(t, "ActivationAuthorization", wire, map[string]protocolv4.Field{"activation_not_after_ms": {Number: 1300}}, [32]byte{71, 23, 4}, f.source)
	w, err := protocolv4.NewPoolSelectionWorkspace(65536, 4096)
	if err != nil {
		t.Fatal(err)
	}
	f.activation, err = w.BindActivation(f.artifact, f.proof, f.source, 0)
	if err != nil {
		t.Fatal(err)
	}
}

func TestAcceptedAdmissionRejectsDifferentAuthorityProofBeforeReservation(t *testing.T) {
	f, e, _, fsb := acceptedVerifiedFlight(t, func(f *sessionAdmissionTrustFixture) { shorterAdmissionProof(t, f) })
	f.trust.tick.Store(75) // Original wire proof expired; supplied authority did not.
	c := f.config
	c.Core.MessageCarrier = false
	c.Initial.Role = protocolv4.ServerToClient
	before := f.root.Snapshot()
	a, err := NewAcceptedSessionAdmissionReservation(context.Background(), c, e, AcceptedAdmissionMaterial{Activation: f.trust.activation, Authority: f.trust.authority, FSB: fsb, ClientCertificate: f.trust.certificates[0], Subscriptions: f.trust.subscriptions[1], Attempt: f.trust.attempt}, f.root, admissionResourceKey(f.owner, 213), f.environment, f.preauth, f.scope)
	if a != nil {
		a.Close()
		_ = a.WaitCleanup(context.Background())
		_ = a.Retire()
		t.Fatal("replacement proof acquired admission ownership", err)
	}
	if err != protocolv4.CBORFailure("admission_proof_binding") {
		t.Fatal(err)
	}
	if f.root.Snapshot() != before {
		t.Fatal("proof mismatch acquired resources")
	}
	if _, err := f.trust.subscriptions[1].CheckOriginalFor(f.environment, f.trust.session, protocolv4.ServerToClient, f.trust.candidate); err != nil {
		t.Fatal("refusal consumed subscriptions", err)
	}
}

func TestSessionAdmissionRejectsDifferentProofBeforeSigningAndPublication(t *testing.T) {
	for _, raw := range []bool{false, true} {
		t.Run(map[bool]string{false: "builder", true: "raw"}[raw], func(t *testing.T) {
			f := admissionIntegration(t, context.Background(), "preauthorized_pool")
			a := f.reserve(t, context.Background())
			x, err := consumeSessionPool(t, f, a)
			if err != nil {
				t.Fatal(err)
			}
			w, err := protocolv4.NewHelloWorkspace(protocolv4.HelloLimits{HelloBytes: 16384, HelloNodes: 4096, RouteBytes: 16384, ContextBytes: 1024})
			if err != nil {
				t.Fatal(err)
			}
			client, err := w.BuildClientHello(make([]byte, 16384), f.trust.artifact, 0, f.trust.attempt, 0, 2, nil)
			if err != nil {
				t.Fatal(err)
			}
			_, h, err := w.BuildServerHello(make([]byte, 16384), f.trust.artifact, 0, f.trust.attempt, client, 0, protocolv4.HelloPolicy{BindingMode: 1}, nil)
			if err != nil {
				t.Fatal(err)
			}
			// Install a completed valid negotiation to isolate the actual FSB
			// publication gate on the original activated admission carrier.
			x.mu.Lock()
			x.hello, x.session, x.phase = h, f.trust.session, 2
			x.mu.Unlock()
			shorterAdmissionProof(t, f.trust)
			codec, err := protocolv4.NewSignedMapCodec("FSB4", 65536, 4096)
			if err != nil {
				t.Fatal(err)
			}
			var result InitialWriteResult
			var signed *protocolv4.SignedMap
			if raw {
				request, buildErr := protocolv4.NewAdmissionRequest(h, f.trust.activation, f.trust.proof, f.trust.certificates[0], codec, f.trust.signers[0], func() error { return nil })
				if buildErr != nil {
					t.Fatal(buildErr)
				}
				defer request.Close()
				signed, buildErr = request.Build()
				if buildErr != nil {
					t.Fatal(buildErr)
				}
				wire, wireErr := signed.Bytes()
				if wireErr != nil {
					t.Fatal(wireErr)
				}
				result, err = x.Send(protocolv4.FrameAdmission, initialCopy(wire))
			} else {
				signed, result, err = x.SendAdmission(f.trust.activation, f.trust.proof, f.trust.certificates[0], codec, f.trust.signers[0], func() error { return nil })
				if signed != nil {
					t.Error("mismatched proof reached signing")
				}
			}
			if signed != nil {
				signed.Release()
			}
			if err != protocolv4.CBORFailure("admission_proof_binding") || result.Submitted || !raw && result.Started || f.provider.writes.Load() != 0 {
				t.Fatal("mismatched proof published", result, err)
			}
		})
	}
}
