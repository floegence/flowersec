package sessionv4

import (
	"context"
	"errors"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

func TestSessionAdmissionReviewDoesNotShareOriginalSubscription(t *testing.T) {
	f := admissionIntegration(t, context.Background(), "preauthorized_pool")
	first := f.reserve(t, context.Background())
	charge, err := PreparedCarrierCharge(8192)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := f.root.Reserve(admissionResourceKey(f.owner, 205), charge)
	if err != nil {
		t.Fatal(err)
	}
	defer ref.Release()
	secondPrepared, err := NewPreparedMessages(context.Background(), PreparedCarrierConfig{Candidate: f.trust.candidate, Attempt: f.trust.attempt, Session: f.trust.session, Role: protocolv4.ClientToServer, Deadline: f.config.Initial.Deadline, Reservation: ref, Environment: f.environment, RuntimeBytes: 8192}, &preparedTestProvider{environment: f.environment})
	if err != nil {
		t.Fatal(err)
	}
	cleanupPreparedTest(t, secondPrepared)
	second, err := NewSessionAdmissionReservation(context.Background(), f.config, secondPrepared, f.trust.subscriptions[0], f.root, admissionResourceKey(f.owner, 206), f.environment, f.preauth, corePlanTestScope(t, f.root, f.root.Snapshot().Limit, 2), nil, nil)
	if err == nil || second != nil {
		t.Fatal("same subscription adopted twice", err)
	}
	if err := secondPrepared.Check(); err != nil {
		t.Fatal("failed adoption consumed second carrier", err)
	}
	f.trust.subscriptions[0].Close()
	if _, err := protocolv4.NewEndpointAuthorization(f.trust.subscriptions[0], f.trust.authority); err == nil {
		t.Fatal("stale subscription bypassed original preparation")
	}
	if _, err := consumeSessionPool(t, f, first); err != nil {
		t.Fatal(err)
	}

}
func TestSessionAdmissionReviewRejectsChangedAttemptBeforeHello(t *testing.T) {
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
	changed := f.trust.attempt
	changed[0] ^= 1
	_, _ = x.NegotiateClient(InitialHello{Artifact: f.trust.artifact, Index: 0, Attempt: changed, Workspace: w, Offered: 0, BindingModes: 2})
	if f.provider.writes.Load() != 0 {
		t.Fatal("mismatched attempt was published on the activated original carrier before admission validation")
	}
}

func TestSessionAdmissionReviewRechecksInitialReservationBeforeClaim(t *testing.T) {
	f := admissionIntegration(t, context.Background(), "preauthorized_pool")
	pool, err := f.root.Account(resourcev4.AccountKey{Kind: resourcev4.PoolAccount, ID: [16]byte{90}}, f.root.Snapshot().Limit)
	if err != nil {
		t.Fatal(err)
	}
	a, err := NewSessionAdmissionReservation(context.Background(), f.config, f.prepared, f.trust.subscriptions[0], f.root, admissionResourceKey(f.owner, 206), f.environment, f.preauth, f.scope, nil, []resourcev4.Account{pool})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		a.Close()
		if err := a.WaitCleanup(context.Background()); err != nil {
			t.Error(err)
		}
		if err := a.Retire(); err != nil {
			t.Error(err)
		}
	}()
	pool.Close()
	claim, err := a.beginClaim()
	if claim != nil {
		_ = a.finishClaim(claim, false)
	}
	if err == nil {
		t.Fatal("closed activated Initial reservation still allowed irreversible spend")
	}
}

func TestSessionAdmissionPreparationRollbackPreservesSubscription(t *testing.T) {
	f := admissionIntegration(t, context.Background(), "preauthorized_pool")
	refused := errors.New("local construction failed")
	if _, err := f.trust.subscriptions[0].AdoptPreparation(f.environment, f.trust.session, protocolv4.ClientToServer, f.trust.candidate, func() error { return refused }); !errors.Is(err, refused) {
		t.Fatal(err)
	}
	if _, err := f.trust.subscriptions[0].CheckOriginalFor(f.environment, f.trust.session, protocolv4.ClientToServer, f.trust.candidate); err != nil {
		t.Fatal("failed construction consumed original subscriptions", err)
	}
	a := f.reserve(t, context.Background())
	copied := *a.subscriptions
	if _, err := copied.CheckOriginalFor(f.environment, f.trust.session, protocolv4.ClientToServer, f.trust.candidate); err == nil {
		t.Fatal("copied preparation retained authority")
	}
	if _, err := copied.Authorize(f.trust.authority); err == nil {
		t.Fatal("copied preparation activated")
	}
	copied.Close()
	if _, err := consumeSessionPool(t, f, a); err != nil {
		t.Fatal(err)
	}
}

func TestSessionAdmissionRejectsChangedWireBeforeProvider(t *testing.T) {
	for _, field := range []string{"attempt", "route", "artifact", "offer", "original"} {
		t.Run(field, func(t *testing.T) {
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
			wire, err := w.BuildClientHello(make([]byte, 16384), f.trust.artifact, 0, f.trust.attempt, 0, 2, nil)
			if err != nil {
				t.Fatal(err)
			}
			decoder, err := protocolv4.NewDecoder(16384, 4096)
			if err != nil {
				t.Fatal(err)
			}
			doc, err := decoder.DecodeMap(wire, "ClientHello", protocolv4.DecodeContext{})
			if err != nil {
				t.Fatal(err)
			}
			var fields []protocolv4.Field
			for _, name := range []string{"protocol_id", "profile_revision", "crypto_profile_id", "artifact_digest", "candidate_id", "route_digest", "attempt_id", "client_nonce", "offered_features", "supported_binding_modes", "client_identity_hint"} {
				value := doc.Root().Named("ClientHello", name)
				if field == "offer" && name == "offered_features" {
					fields = append(fields, protocolv4.Field{Name: name, Number: 1 << 63})
					continue
				}
				if field == "attempt" && name == "attempt_id" || field == "route" && name == "route_digest" || field == "artifact" && name == "artifact_digest" {
					b, _ := value.ByteString()
					b = append([]byte(nil), b...)
					b[0] ^= 1
					fields = append(fields, protocolv4.Field{Name: name, Kind: protocolv4.ByteString, Bytes: b})
					continue
				}
				f := protocolv4.Field{Name: name}
				if b, ok := value.ByteString(); ok {
					f.Kind, f.Bytes = protocolv4.ByteString, b
				} else if text, ok := value.Text(); ok {
					f.Kind, f.Text = protocolv4.TextString, text
				} else if n, ok := value.Uint(); ok {
					f.Number = n
				} else {
					t.Fatal("unexpected hello field", name)
				}
				fields = append(fields, f)
			}
			mutated, err := protocolv4.EncodeMap(make([]byte, 16384), "ClientHello", fields)
			if err != nil {
				t.Fatal(err)
			}
			doc.Release()
			result, err := x.Send(protocolv4.FrameNegotiate, initialCopy(mutated))
			if field == "original" {
				if err != nil || !result.Submitted || f.provider.writes.Load() != 1 {
					t.Fatal("original hello could not publish", result, err)
				}
			} else if err == nil || result.Submitted || f.provider.writes.Load() != 0 {
				t.Fatal("changed original wire reached provider", result, err)
			}
		})
	}
}
