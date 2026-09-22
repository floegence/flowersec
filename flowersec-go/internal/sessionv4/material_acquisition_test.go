package sessionv4

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

type blockedMaterialProvider struct {
	lease   *ArtifactLease
	entered chan MaterialLeaseRequest
	release chan struct{}
	calls   atomic.Int32
}

type immediateMaterialProvider struct{ lease *ArtifactLease }

func (p immediateMaterialProvider) AcquireLease(context.Context, MaterialLeaseRequest) (*ArtifactLease, error) {
	return p.lease, nil
}

func TestLiveMaterialRejectsInvalidOriginalActivationMapping(t *testing.T) {
	for _, variant := range []string{"malformed", "wrong key", "expired signer"} {
		t.Run(variant, func(t *testing.T) {
			f := admissionIntegration(t, context.Background(), "live_authority")
			m, _, lease := materialTestBundle(t, f, protocolv4.ClientToServer, 280)
			m.Close()
			switch variant {
			case "malformed":
				lease.verification.Delegation = []byte{0xa0}
			case "wrong key":
				lease.verification.Key[0] ^= 1
			case "expired signer":
				f.trust.tick.Add(120)
			}
			if err := lease.checkForUse(true); err == nil {
				t.Fatal("invalid live activation configuration admitted")
			}
			if lease.claimed {
				t.Fatal("configuration check claimed original lease")
			}
		})
	}
}

func TestLiveMaterialVerifierPreservesIssuedProofAfterSigningWindow(t *testing.T) {
	f := admissionIntegration(t, context.Background(), "live_authority")
	consumer, _, _ := materialTestBundle(t, f, protocolv4.ClientToServer, 280)
	server, _, lease := materialTestBundle(t, f, protocolv4.ServerToClient, 290)
	// Current trusted upper time crosses the new-issuance bound (1350),
	// while the original proof's activation bound (1400) remains usable.
	f.trust.tick.Add(120)
	if err := consumer.check(); !errors.Is(err, timev4.ErrExpired) {
		t.Fatal("consumer admitted a new issuance past its signing window", err)
	}
	if err := server.check(); err != nil {
		t.Fatal("verifier required current signing authority for an issued proof", err)
	}
	v := lease.validation[0]
	if _, err := v.Namespace.CheckDetachedActivation(f.trust.authority, lease.credentials[0], v.Issuer, 5000, 59000, 4000); err != nil {
		t.Fatal("original valid proof rejected", err)
	}
	now, err := f.trust.clock.Sample()
	if err != nil {
		t.Fatal(err)
	}
	if err := f.trust.authority.CheckAdmission(now.Interval); err != nil {
		t.Fatal("original proof admission closed early", err)
	}
}

func (p *blockedMaterialProvider) AcquireLease(_ context.Context, r MaterialLeaseRequest) (*ArtifactLease, error) {
	p.calls.Add(1)
	p.entered <- r
	<-p.release
	return p.lease, nil
}

func acquisitionTestOwner(t *testing.T, f *admissionIntegrationFixture, ctx context.Context, identity *ApplicationIdentity, requirements MaterialRequirements) *MaterialAcquisition {
	t.Helper()
	reserve := func(n uint32, v resourcev4.Vector) resourcev4.Reference {
		ref, err := f.root.Reserve(admissionResourceKey(f.owner, n), v)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(ref.Release)
		return ref
	}
	charge, _ := MaterialAcquisitionCharge(8192)
	materialCharge, _ := ConnectionMaterialCharge(8192)
	a, err := NewMaterialAcquisition(ctx, identity, MaterialGeneration{Source: [16]byte{9}, Generation: 7}, f.trust.source, requirements, f.config.Initial.Deadline, 8192, 8192, reserve(289, charge), reserve(288, materialCharge))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	return a
}

func TestMaterialAcquisitionKeepsCapturedIdentityAcrossRotation(t *testing.T) {
	for _, source := range []string{"preauthorized_pool", "live_authority"} {
		t.Run(source, func(t *testing.T) {
			f := admissionIntegration(t, context.Background(), source)
			unused, identity, lease := materialTestBundle(t, f, protocolv4.ClientToServer, 280)
			unused.Close()
			a := acquisitionTestOwner(t, f, context.Background(), identity, MaterialRequirements{ApplicationProfile: "transport"})
			provider := &blockedMaterialProvider{lease: lease, entered: make(chan MaterialLeaseRequest, 1), release: make(chan struct{})}
			type outcome struct {
				m   *ConnectionMaterial
				err error
			}
			done := make(chan outcome, 1)
			go func() { m, err := a.Acquire(provider); done <- outcome{m, err} }()
			request := <-provider.entered
			if request.IdentityDigest != identity.credential.Facts().Digest || request.Role != protocolv4.ClientToServer || request.Profile != f.trust.session.Profile {
				t.Fatal("source request changed captured identity")
			}
			identity.Close()
			close(provider.release)
			got := <-done
			if got.err != nil || got.m == nil {
				t.Fatal("rotation replaced or rejected original captured key", got.err)
			}
			if err := got.m.check(); err != nil {
				t.Fatal("captured original material unavailable", err)
			}
			if got.m.identity.identity != identity || got.m.generation != (MaterialGeneration{Source: [16]byte{9}, Generation: 7}) {
				t.Fatal("late source result changed original binding")
			}
			if _, err := a.Acquire(provider); err == nil || provider.calls.Load() != 1 {
				t.Fatal("source invocation repeated")
			}
			got.m.Close()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := a.WaitCleanup(ctx); err != nil {
				t.Fatal(err)
			}
			if err := identity.WaitCleanup(ctx); err != nil {
				t.Fatal(err)
			}
			if err := lease.WaitCleanup(ctx); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestMaterialAcquisitionCancellationKeepsLateProviderOwner(t *testing.T) {
	f := admissionIntegration(t, context.Background(), "preauthorized_pool")
	unused, identity, lease := materialTestBundle(t, f, protocolv4.ClientToServer, 280)
	unused.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a := acquisitionTestOwner(t, f, ctx, identity, MaterialRequirements{ApplicationProfile: "transport"})
	provider := &blockedMaterialProvider{lease: lease, entered: make(chan MaterialLeaseRequest, 1), release: make(chan struct{})}
	done := make(chan error, 1)
	go func() {
		m, err := a.Acquire(provider)
		if m != nil {
			m.Close()
			done <- ErrSourceContractInvalid
		} else {
			done <- err
		}
	}()
	<-provider.entered
	identity.Close()
	before := f.root.Snapshot()
	cancel()
	a.Close()
	wait, stop := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer stop()
	if err := a.WaitCleanup(wait); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("cancellation refunded original source method", err)
	}
	if f.root.Snapshot() != before {
		t.Fatal("blocked issuer or captured key refunded")
	}
	close(provider.release)
	if err := <-done; err == nil {
		t.Fatal("late source result published after cancellation")
	}
	cleanup, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if err := a.WaitCleanup(cleanup); err != nil {
		t.Fatal(err)
	}
	if err := identity.WaitCleanup(cleanup); err != nil {
		t.Fatal(err)
	}
	if err := lease.WaitCleanup(cleanup); err != nil {
		t.Fatal(err)
	}
}

func TestMaterialAcquisitionRefusesSignedApplicationMismatch(t *testing.T) {
	f := admissionIntegration(t, context.Background(), "preauthorized_pool")
	unused, identity, lease := materialTestBundle(t, f, protocolv4.ClientToServer, 280)
	unused.Close()
	a := acquisitionTestOwner(t, f, context.Background(), identity, MaterialRequirements{ApplicationProfile: "services", RPCMaxGeneralOutstanding: 32})
	provider := &blockedMaterialProvider{lease: lease, entered: make(chan MaterialLeaseRequest, 1), release: make(chan struct{})}
	close(provider.release)
	m, err := a.Acquire(provider)
	if m != nil || !errors.Is(err, ErrSourceContractInvalid) {
		t.Fatal("source silently reduced requested application profile/K", err)
	}
	if lease.claimed {
		t.Fatal("invalid source contract consumed local lease")
	}
}
