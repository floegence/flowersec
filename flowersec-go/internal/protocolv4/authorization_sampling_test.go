package protocolv4

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

type authorizationClockBlock struct {
	entered, resume chan struct{}
	once            sync.Once
	exit            func()
}

func (b *authorizationClockBlock) release() { b.once.Do(func() { close(b.resume) }) }

type authorizationClockSource struct {
	block atomic.Pointer[authorizationClockBlock]
	tick  atomic.Uint64
}

func (s *authorizationClockSource) read() (timev4.Tick, error) {
	if b := s.block.Swap(nil); b != nil {
		close(b.entered)
		<-b.resume
		if b.exit != nil {
			b.exit()
		}
	}
	return timev4.Tick{Milliseconds: s.tick.Load(), Incarnation: [16]byte{1}}, nil
}

func (s *authorizationClockSource) pause(t *testing.T, exit func()) *authorizationClockBlock {
	t.Helper()
	b := &authorizationClockBlock{entered: make(chan struct{}), resume: make(chan struct{}), exit: exit}
	s.block.Store(b)
	t.Cleanup(b.release)
	return b
}

func awaitAuthorizationSignal(t *testing.T, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(3 * time.Second):
		t.Fatal("ownership gate waited for the blocked clock adapter")
	}
}

// This component fixture has no scheduler. Each sample belongs to the caller
// under test, so the injected blocked read cannot be consumed by a watchdog.
func authorizationSamplingFixture(t *testing.T) (*endpointCredentialFixture, *CredentialSubscriptions, *ActivationAuthority, *LiveNamespace, *testNamespaceTrust, *authorizationClockSource) {
	t.Helper()
	x := newEndpointCredentialFixture(t, false, false)
	x.f.now = timev4.Interval{LowerMS: 1200, UpperMS: 1250}
	source := &authorizationClockSource{}
	clock, err := timev4.NewClock(timev4.Profile{Rate: timev4.Rate{Denominator: 1}, MaxWidthMS: 2000, MaxAgeMS: 100000, MaxRoundTripMS: 1000}, source.read)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(clock.Close)
	mark, err := clock.Monotonic()
	if err != nil {
		t.Fatal(err)
	}
	if err = clock.InstallTrusted(mark, x.f.now); err != nil {
		t.Fatal(err)
	}
	head, content := x.f.bindHead(t, 1, [2]uint64{})
	refs, err := reserveNamespace(x.f.rules, 8, x.f.namespaceAllocation(t))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, ref := range refs {
			ref.Release()
		}
	}()
	trust := &testNamespaceTrust{}
	n, err := newBootstrappedNamespace(context.Background(), clock, trust, NamespaceBootstrap{Rules: x.f.rules, Head: head, State: content}, 4000, 2, 8, refs, true)
	if err != nil {
		t.Fatal(err)
	}
	n.initializing, n.watcherExited = false, true
	t.Cleanup(func() {
		n.Close(nil)
		x.f.resources.Close()
		if err := n.DestroyEnvironment(); err != nil {
			t.Error(err)
		}
	})
	closure, err := x.bind(ClientToServer)
	if err != nil {
		t.Fatal(err)
	}
	policy := x.policy(t, "online", 1, 5000, x.f.rules.signerLife)
	bindings := make([]CredentialValidation, closure.count)
	for i, credential := range closure.credentials[:closure.count] {
		bindings[i] = CredentialValidation{Namespace: n, Issuer: IssuerPermission{Schema: credential.scope.Schema, Issuer: credential.scope.Issuer, Key: credential.key, SigningStart: 1000, SigningEnd: 1100}, Policy: policy}
	}
	s, err := closure.Subscribe(bindings, 10000, x.f.reserve(t, CredentialSubscriptionsCharge()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	_, activation, _ := x.f.activationOriginal(t, "live_authority", x.originals[0])
	trust.activation = activation.trust
	return x, s, activation, n, trust, source
}

func TestAuthorizationCloseFencesBlockedClockAndRetainsBacking(t *testing.T) {
	x, s, activation, n, _, source := authorizationSamplingFixture(t)
	a, err := NewEndpointAuthorization(s, activation)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Close(nil) })
	before := x.f.resources.Snapshot().Charged
	b := source.pause(t, nil)
	checked := make(chan error, 1)
	var published atomic.Bool
	go func() { checked <- a.WithCurrentAuthorization(func() error { published.Store(true); return nil }) }()
	awaitAuthorizationSignal(t, b.entered)
	closed := make(chan struct{})
	cause := errors.New("original endpoint closed")
	go func() { a.Close(cause); close(closed) }()
	awaitAuthorizationSignal(t, closed)
	if n.SubscriptionCount() != 1 || x.f.resources.Snapshot().Charged != before {
		t.Fatal("Close refunded a clock callback that still holds original backing")
	}
	b.release()
	select {
	case err := <-checked:
		if !errors.Is(err, cause) || published.Load() {
			t.Fatal("late read published after Close", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("sampling tail did not exit")
	}
	if n.SubscriptionCount() != 0 {
		t.Fatal("finished sampling retained namespace references")
	}
}

func TestPreparationCloseDoesNotWaitForClock(t *testing.T) {
	x, s, _, n, _, source := authorizationSamplingFixture(t)
	before := x.f.resources.Snapshot().Charged
	b := source.pause(t, nil)
	checked := make(chan error, 1)
	go func() { _, err := s.CheckPreparation(); checked <- err }()
	awaitAuthorizationSignal(t, b.entered)
	closed := make(chan struct{})
	go func() { s.Close(); close(closed) }()
	awaitAuthorizationSignal(t, closed)
	if n.SubscriptionCount() != 1 || x.f.resources.Snapshot().Charged != before {
		t.Fatal("pending preparation read lost its backing")
	}
	b.release()
	select {
	case err := <-checked:
		if err == nil {
			t.Fatal("closed preparation validated")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("preparation did not exit")
	}
	if n.SubscriptionCount() != 0 {
		t.Fatal("preparation sampling tail leaked")
	}
}

func TestLatePreparationSamplerCannotCloseAdoptedAuthorization(t *testing.T) {
	for _, tc := range []struct {
		name string
		exit func()
	}{
		{"return", nil}, {"panic", func() { panic("clock") }}, {"goexit", runtime.Goexit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, s, activation, n, _, source := authorizationSamplingFixture(t)
			b := source.pause(t, tc.exit)
			done := make(chan struct{})
			go func() { defer close(done); defer func() { _ = recover() }(); _, _ = s.CheckPreparation() }()
			awaitAuthorizationSignal(t, b.entered)
			a, err := NewEndpointAuthorization(s, activation)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { a.Close(nil) })
			b.release()
			awaitAuthorizationSignal(t, done)
			s.mu.Lock()
			valid := s.bound == a && !s.closed && !s.cleaned && s.sampling == 0
			s.mu.Unlock()
			if !valid || n.SubscriptionCount() != 1 {
				t.Fatal("stale preparation sampler destroyed its successor")
			}
		})
	}
}

func TestDeliveryTakeWinsAgainstStaleSamplingCreator(t *testing.T) {
	for _, abnormal := range []bool{false, true} {
		t.Run(map[bool]string{false: "return", true: "panic"}[abnormal], func(t *testing.T) {
			x, s, activation, n, _, source := authorizationSamplingFixture(t)
			a, err := NewEndpointAuthorization(s, activation)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { a.Close(nil) })
			d, err := a.ForkDelivery(x.f.reserve(t, CredentialSubscriptionsCharge()))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { d.Close(nil) })
			var exit func()
			if abnormal {
				exit = func() { panic("clock") }
			}
			b := source.pause(t, exit)
			done := make(chan struct{})
			var published atomic.Bool
			go func() {
				defer close(done)
				defer func() { _ = recover() }()
				_ = d.WithCurrentAuthorization(func() error { published.Store(true); return nil })
			}()
			awaitAuthorizationSignal(t, b.entered)
			owned, err := d.Take()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { owned.Close(nil) })
			b.release()
			awaitAuthorizationSignal(t, done)
			owned.owner.mu.Lock()
			valid := owned.validLocked() && !owned.owner.closing
			owned.owner.mu.Unlock()
			if !valid || published.Load() || n.SubscriptionCount() != 2 {
				t.Fatal("stale creator affected adopted delivery")
			}
		})
	}
}

func TestAuthorizationRechecksTrustAfterClockReturns(t *testing.T) {
	_, s, activation, _, trust, source := authorizationSamplingFixture(t)
	a, err := NewEndpointAuthorization(s, activation)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Close(nil) })
	b := source.pause(t, nil)
	checked := make(chan error, 1)
	go func() { checked <- a.Check() }()
	awaitAuthorizationSignal(t, b.entered)
	trust.rejected.Store(true)
	b.release()
	select {
	case err := <-checked:
		if err != CBORFailure("independent_trust_rejected") {
			t.Fatal("sample retained superseded trust", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("authorization did not exit")
	}
}
