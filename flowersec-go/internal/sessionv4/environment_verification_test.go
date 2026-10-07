package sessionv4

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
)

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

func environmentVerificationRegistry(t *testing.T, f *admissionIntegrationFixture) *protocolv4.NamespaceRegistry {
	return authorityVerificationRegistry(t, f.authorityFixture)
}

type environmentVerificationProvider struct {
	entered, canceled, release, exited chan struct{}
	fetched                            bool
}

func (p *environmentVerificationProvider) Query(ctx context.Context, _ protocolv4.NamespaceBootstrapRequest, _ []byte) (int, error) {
	defer close(p.exited)
	close(p.entered)
	<-ctx.Done()
	close(p.canceled)
	<-p.release
	return 0, ctx.Err()
}
func (p *environmentVerificationProvider) Fetch(context.Context, protocolv4.NamespaceContent, []byte) (int, error) {
	p.fetched = true
	return 0, protocolv4.CBORFailure("fetch_after_canceled_preparation")
}

// A legal host context may block while stopping its original AfterFunc.
// Its Done notification alone does not prove that cancel has returned.
type environmentVerificationStopContext struct {
	context.Context
	done, stopEntered, stopRelease chan struct{}
	release                        sync.Once
}

func (c *environmentVerificationStopContext) Done() <-chan struct{} { return c.done }
func (c *environmentVerificationStopContext) AfterFunc(func()) func() bool {
	return func() bool { close(c.stopEntered); <-c.stopRelease; return true }
}
func (c *environmentVerificationStopContext) releaseStop() {
	c.release.Do(func() { close(c.stopRelease) })
}
func TestEnvironmentCloseCancelsOnlyItsVerificationPreparationAndJoinsProvider(t *testing.T) {
	t.Run("provider_exit", func(t *testing.T) { environmentCloseVerificationPreparation(t, nil) })
	t.Run("host_stop_exit", func(t *testing.T) {
		parent := &environmentVerificationStopContext{Context: context.Background(), done: make(chan struct{}), stopEntered: make(chan struct{}), stopRelease: make(chan struct{})}
		environmentCloseVerificationPreparation(t, parent)
	})
}
func environmentCloseVerificationPreparation(t *testing.T, parent *environmentVerificationStopContext) {
	f := admissionIntegration(t, context.Background(), "preauthorized_pool")
	x := materialBytesFor(t, f)
	config := protocolv4.NamespaceRegistryConfig{Continuity: protocolv4.OnlineBootstrap, Entries: 2, RuntimeBytes: 4096}
	charge, err := protocolv4.NamespaceRegistryCharge(config)
	if err != nil {
		t.Fatal(err)
	}
	r, err := protocolv4.NewNamespaceRegistry(config, x.reserve(charge))
	if err != nil {
		t.Fatal(err)
	}
	provider := &environmentVerificationProvider{entered: make(chan struct{}), canceled: make(chan struct{}), release: make(chan struct{}), exited: make(chan struct{})}
	var releaseOnce sync.Once
	releaseProvider := func() { releaseOnce.Do(func() { close(provider.release) }) }
	allocation := protocolv4.NamespaceAllocation{Root: f.root}
	for i := range allocation.Owners {
		allocation.Owners[i] = admissionResourceKey(f.owner, uint32(1100+i))
	}
	references := []protocolv4.NamespaceReferenceConfig{{
		Root:       protocolv4.NamespaceTrustRoot{Tenant: "tenant-1", Authority: "revocation-1", KeyID: x.rootKeyID, PublicKey: x.rootPublic, MaxLifetimeMS: 100000},
		Trust:      protocolv4.NamespaceTrustLimits{Configurations: 4, ConfigBytes: 32768, MapNodes: 8192, RuntimeBytes: 65536},
		Bootstrap:  protocolv4.NamespaceBootstrapLimits{ResponseBytes: 32768, ResponseNodes: 8192, StateBytes: 4096, DurationMS: 4000, FetchDurationMS: 4000, FetchAttempts: 2, Subscribers: 8, RuntimeBytes: 65536},
		Allocation: allocation, Owner: admissionResourceKey(f.owner, 1110), Provider: provider,
	}}
	charge, err = protocolv4.NamespaceReferenceFactoryCharge(references, 65536)
	if err != nil {
		t.Fatal(err)
	}
	factory, err := protocolv4.NewNamespaceReferenceFactory(context.Background(), r, f.trust.clock, references, 65536, x.reserve(charge))
	if err != nil {
		t.Fatal(err)
	}
	ec := EnvironmentConfig{Positions: 1, RuntimeBytes: 65536, Verification: r}
	charge, err = EnvironmentCharge(ec)
	if err != nil {
		t.Fatal(err)
	}
	e, err := NewEnvironment(ec, x.reserve(charge), f.environment)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if parent != nil {
			parent.releaseStop()
		}
		releaseProvider()
		e.Close()
		factory.Close()
		r.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := e.WaitCleanup(ctx); err != nil {
			t.Error(err)
		}
		if err := e.Retire(); err != nil {
			t.Error(err)
		}
		if err := factory.WaitCleanup(ctx); err != nil {
			t.Error(err)
		}
		f.root.Close()
		if err := r.DestroyEnvironment(); err != nil {
			t.Error(err)
		}
	})
	result := make(chan error, 1)
	var lookupContext context.Context = context.Background()
	if parent != nil {
		lookupContext = parent
	}
	go func() {
		_, err := e.VerificationNamespaceContext(lookupContext, "tenant-1", "revocation-1")
		result <- err
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	select {
	case <-provider.entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	closeReturned := make(chan struct{})
	go func() { e.Close(); close(closeReturned) }()
	if parent != nil {
		select {
		case <-parent.stopEntered:
		case <-ctx.Done():
			t.Fatal("host stop did not start", ctx.Err())
		}
	}
	select {
	case <-provider.canceled:
	case <-ctx.Done():
		t.Fatal("Environment Close did not cancel its original provider", ctx.Err())
	}
	select {
	case <-e.done:
		t.Fatal("Environment refunded a provider that had not exited")
	default:
	}
	releaseProvider()
	if parent != nil {
		select {
		case <-provider.exited:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		// The provider is allowed to return while the original cancel remains in
		// host stop. Neither its observer nor Environment cleanup may refund it.
		select {
		case <-result:
			t.Fatal("preparation returned before host cancellation exited")
		default:
		}
		observer, stopObserver := context.WithTimeout(context.Background(), 25*time.Millisecond)
		cleanupErr := e.WaitCleanup(observer)
		stopObserver()
		if cleanupErr != context.DeadlineExceeded {
			t.Fatal("Environment cleanup did not retain original host stop", cleanupErr)
		}
		if err := e.Retire(); err == nil {
			t.Fatal("Environment retired while original cancellation was active")
		}
		parent.releaseStop()
	}
	select {
	case <-closeReturned:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("closed preparation delivered a namespace")
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if err := e.WaitCleanup(ctx); err != nil {
		t.Fatal(err)
	}
	if provider.fetched {
		t.Fatal("canceled preparation dispatched a later Fetch")
	}
	// Registry closure remains a separate owner's decision.
	pin, err := r.Borrow(f.environment)
	if err != nil {
		t.Fatal("Environment Close closed its shared registry", err)
	}
	pin.Release()
}
