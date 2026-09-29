package sessionv4

import (
	"context"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
)

func environmentVerificationRegistry(t *testing.T, f *admissionIntegrationFixture) *protocolv4.NamespaceRegistry {
	t.Helper()
	c := protocolv4.NamespaceRegistryConfig{Continuity: protocolv4.OnlineBootstrap, Entries: 4, RuntimeBytes: 4096}
	cost, err := protocolv4.NamespaceRegistryCharge(c)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := f.root.Reserve(admissionResourceKey(f.owner, 598), cost)
	if err != nil {
		t.Fatal(err)
	}
	r, err := protocolv4.NewNamespaceRegistry(c, ref)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		r.Close()
		f.root.Close()
		if err := r.DestroyEnvironment(); err != nil {
			t.Error(err)
		}
	})
	return r
}

func TestEnvironmentVerificationOriginalBootstrapMaterial(t *testing.T) {
	f := admissionIntegration(t, context.Background(), "preauthorized_pool")
	r := environmentVerificationRegistry(t, f)
	x := materialBytesFor(t, f, r)
	e := materialEnvironment(t, x, r)
	if got, err := e.VerificationNamespace("tenant-1", "revocation-1"); err != nil || got != x.trust {
		t.Fatal("Environment lookup replaced original bootstrap owner", err)
	}
	if _, err := e.VerificationNamespace("other-tenant", "revocation-1"); err == nil {
		t.Fatal("unconfigured tenant resolved to original trust")
	}
	m := unusedMaterial(t, x)
	result, err := e.CreateMaterial(context.Background(), func(context.Context) (*ConnectionMaterial, error) { return m, nil })
	if err != nil || result != m {
		t.Fatal("registered bootstrapped material refused", err)
	}
	r.Close()
	if err := m.check(); err == nil {
		t.Fatal("registry fence did not close existing credential gate")
	}
	if _, err := e.VerificationNamespace("tenant-1", "revocation-1"); err == nil {
		t.Fatal("closed registry still available through Environment")
	}
}

func TestEnvironmentVerificationBootstrapToReadyAndDuplex(t *testing.T) {
	for _, source := range []string{"preauthorized_pool", "live_authority"} {
		for _, static := range []bool{false, true} {
			name := source + "/source"
			if static {
				name = source + "/static"
			}
			t.Run(name, func(t *testing.T) {
				sessionEstablishmentDuplex(t, source, true, true, true, true, false, true, static, true)
			})
		}
	}
}

func TestEnvironmentVerificationRejectsUnregisteredMaterial(t *testing.T) {
	f := admissionIntegration(t, context.Background(), "preauthorized_pool")
	r := environmentVerificationRegistry(t, f)
	// Valid local signatures in a separately initialized owner do not confer
	// this Environment's registered startup/continuity authority.
	x := materialBytesFor(t, f)
	e := materialEnvironment(t, x, r)
	m := unusedMaterial(t, x)
	result, err := e.CreateMaterial(context.Background(), func(context.Context) (*ConnectionMaterial, error) { return m, nil })
	if err == nil || result != nil {
		t.Fatal("unregistered verification graph delivered", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := m.WaitCleanup(ctx); err != nil {
		t.Fatal("refused material lost original cleanup", err)
	}
	waitMaterialPositions(t, e, 0)
}

func TestEnvironmentVerificationRefusesBeforeSpendAndPreservesInputs(t *testing.T) {
	f := admissionIntegration(t, context.Background(), "preauthorized_pool")
	r := environmentVerificationRegistry(t, f)
	a := f.reserve(t, context.Background())
	p := environmentTestEstablishment(t, f)
	c := EnvironmentConfig{Positions: 1, RuntimeBytes: 65536, Verification: r}
	cost, err := EnvironmentCharge(c)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := f.root.Reserve(admissionResourceKey(f.owner, 599), cost)
	if err != nil {
		t.Fatal(err)
	}
	e, err := NewEnvironment(c, ref, f.environment)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		e.Close()
		if err := e.Retire(); err != nil {
			t.Error(err)
		}
	}()
	_, err = e.admit(context.Background(), environmentEstablishment{kind: 1, pool: PoolSessionInput{Establishment: p, Admission: a, Consume: f.environment}})
	if err == nil || a.host != nil || a.claimed || p.host != nil || p.started || e.active != 0 {
		t.Fatal("unregistered closure crossed original admission gate", err)
	}
	if err := a.checkLocked(); err != nil {
		t.Fatal("local refusal consumed caller's original admission", err)
	}
}
