package sessionv4

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

func controllerPreparationPolicy(t *testing.T, f *admissionIntegrationFixture) *protocolv4.CredentialPolicy {
	t.Helper()
	wire := admissionEncode(t, "CredentialRevocationPolicy", map[string]protocolv4.Field{"revocation_policy_id": admissionText("online"), "revocation_policy_revision": {Number: 1}, "max_staleness_ms": {Number: 250}, "max_head_signer_lifetime_ms": {Number: 59000}})
	policy, err := protocolv4.NewCredentialPolicy(wire)
	if err != nil {
		t.Fatal(err)
	}
	f.trust.trust.preparationPolicy.Store(policy)
	return policy
}

func TestControllerVerificationWaitKeepsAttemptAndPreAcquireHeadroom(t *testing.T) {
	for _, stop := range []string{"cancel", "deadline", "trust"} {
		t.Run(stop, func(t *testing.T) {
			f := admissionIntegration(t, context.Background(), "preauthorized_pool")
			unused, identity, _ := materialTestBundle(t, f, protocolv4.ClientToServer, 280)
			unused.Close()
			identity.validation.Policy = controllerPreparationPolicy(t, f)
			e := environmentTestOwner(t, f, 248, 1)
			var acquisitions, preparations atomic.Int32
			config := sourceConnectTestConfig(t, f, identity, materialProviderFunc(func(context.Context, MaterialLeaseRequest) (*ArtifactLease, error) {
				acquisitions.Add(1)
				return nil, errors.New("verification must precede acquisition")
			}), carrierFactoryFunc(func(context.Context, CarrierPreparationRequest) (*PreparedCarrier, error) {
				return nil, errors.New("verification must precede carrier preparation")
			}))
			c := controllerForTest(t, f, e, ControllerConfig{Clock: f.trust.clock, SourceIncarnation: [16]byte{1}, AttemptTimeoutMS: 100, DrainTimeoutMS: 1000, RuntimeBytes: 65536,
				Source: controllerSourceFunc(func(context.Context, ControllerRequest) (*ControllerPreparation, error) {
					preparations.Add(1)
					return &ControllerPreparation{Config: config, Pool: &PoolSessionInput{}}, nil
				})})
			before := f.root.Snapshot()
			f.trust.tick.Store(110)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if err := c.Start(ctx); err != nil {
				t.Fatal(err)
			}
			waitController(t, c, func(s ControllerSnapshot) bool { return s.WaitingVerification || s.LastError != nil })
			if !c.Snapshot().WaitingVerification {
				t.Fatal("verification did not wait", c.Snapshot())
			}
			if during := f.root.Snapshot(); during.Reservations <= before.Reservations {
				t.Fatal("candidate headroom not retained before acquisition", before, during)
			}
			c.mu.Lock()
			a := c.attempt
			cap := a.deadline.Cap()
			c.mu.Unlock()
			switch stop {
			case "cancel":
				cancel()
			case "deadline":
				f.trust.tick.Add(101)
			case "trust":
				f.trust.trust.rejected.Store(true)
			}
			waitController(t, c, func(s ControllerSnapshot) bool { return !s.Pending })
			snapshot := c.Snapshot()
			if snapshot.LastError == nil || snapshot.Current || snapshot.WaitingVerification || snapshot.WaitingRetry || acquisitions.Load() != 0 || preparations.Load() != 1 || a.deadline.Cap() != cap {
				t.Fatal("verification created/replayed work or renewed deadline", snapshot, acquisitions.Load(), preparations.Load())
			}
			if stop == "deadline" && !errors.Is(snapshot.LastError, timev4.ErrExpired) {
				t.Fatal("original deadline lost", snapshot.LastError)
			}
			if after := f.root.Snapshot(); after.Reservations >= before.Reservations {
				t.Fatal("unused workspaces/headroom not returned", before, after)
			}
		})
	}
}

func TestControllerPoolVerificationDoesNotAcquireOrTopUp(t *testing.T) {
	f := newMaterialPoolFixture(t, 1)
	source, control := newPoolSource(t, f)
	ctx := context.Background()
	if err := f.pool.Install(ctx, f.request, f.batch, f.identity); err != nil {
		t.Fatal(err)
	}
	before := f.root.Snapshot()
	for range 3 {
		pending, err := source.controllerVerification(f.environment)
		if err != nil || pending {
			t.Fatal("installed pool verification", pending, err)
		}
	}
	if after := f.root.Snapshot(); after != before {
		t.Fatal("pool peek retained new owner", before, after)
	}
	if control.topUps.Load() != 0 || control.snapshots.Load() != 0 {
		t.Fatal("verification invoked replenishment")
	}
	m, err := f.pool.Acquire(ctx, MaterialRequirements{ApplicationProfile: "transport"})
	if err != nil {
		t.Fatal("verification removed original material", err)
	}
	m.Close()
}
