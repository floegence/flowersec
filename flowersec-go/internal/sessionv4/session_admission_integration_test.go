package sessionv4

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

type admissionIntegrationFixture struct {
	root                 *resourcev4.Root
	environment, preauth resourcev4.Reference
	owner                resourcev4.OwnerKey
	scope                SessionResourceScope
	trust                *sessionAdmissionTrustFixture
	config               SessionAdmissionConfig
	prepared             *PreparedCarrier
	provider             *preparedTestProvider
}

func admissionIntegration(t *testing.T, ctx context.Context, sources ...string) *admissionIntegrationFixture {
	t.Helper()
	f := &admissionIntegrationFixture{}
	limit := resourcev4.Vector{}
	for i := range limit {
		limit[i] = 1 << 30
	}
	var err error
	f.root, err = resourcev4.NewRoot(resourcev4.Config{ProfileRevision: [32]byte{1}, Limit: limit, AccountSlots: 16, ReservationSlots: 256, ReferenceSlots: 1024})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.root.Close)
	f.owner = resourcev4.OwnerKey{ProfileRevision: [32]byte{1}, Environment: [16]byte{1}, Instance: [16]byte{83}, Backing: [16]byte{1}, Kind: 83}
	f.environment, err = f.root.Reserve(f.owner, resourcev4.Vector{resourcev4.SDKBytes: 1, resourcev4.Items: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.environment.Release)
	source := "live_authority"
	if len(sources) > 0 {
		source = sources[0]
	}
	f.trust = newSessionAdmissionTrustFixture(t, f.root, f.environment, f.owner, source)
	f.scope = corePlanTestScope(t, f.root, limit, 1)
	f.preauth, err = f.root.Reserve(admissionResourceKey(f.owner, 200), resourcev4.Vector{resourcev4.SDKBytes: 4 << 20, resourcev4.Items: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.preauth.Release)
	deadline, err := timev4.NewAge(f.trust.clock, 10000, 4000)
	if err != nil {
		t.Fatal(err)
	}
	c := corePlanUnitConfig(t, false)
	c.Session, c.Clock = f.trust.session, f.trust.clock
	c.MessageCarrier, c.MessageRuntimeBytes = true, 8192
	f.config = SessionAdmissionConfig{Core: c, Features: f.trust.features, Initial: InitialConfig{Role: protocolv4.ClientToServer, Profile: c.Session.Profile, ActivationSourceProfile: source, Limits: InitialLimits{int(c.Session.Contract.Limits().MaxFrame), 4096}, Deadline: deadline}, RuntimeBytes: 32768, InitialRuntimeBytes: 32768}
	charge, err := PreparedCarrierCharge(8192)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := f.root.Reserve(admissionResourceKey(f.owner, 201), charge)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ref.Release)
	f.provider = &preparedTestProvider{environment: f.environment}
	f.prepared, err = NewPreparedMessages(ctx, PreparedCarrierConfig{Candidate: f.trust.candidate, Attempt: f.trust.attempt, Session: f.trust.session, Role: protocolv4.ClientToServer, Deadline: deadline, Reservation: ref, Environment: f.environment, RuntimeBytes: 8192}, f.provider)
	if err != nil {
		t.Fatal(err)
	}
	cleanupPreparedTest(t, f.prepared)
	return f
}

func (f *admissionIntegrationFixture) reserve(t *testing.T, ctx context.Context) *SessionAdmissionReservation {
	t.Helper()
	a, err := NewSessionAdmissionReservation(ctx, f.config, f.prepared, f.trust.subscriptions[0], f.root, admissionResourceKey(f.owner, 202), f.environment, f.preauth, f.scope, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		a.Close()
		cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := a.WaitCleanup(cleanup); err != nil {
			t.Error(err)
			return
		}
		if err := a.Retire(); err != nil {
			t.Error(err)
		}
	})
	return a
}

func TestSessionAdmissionAtomicGraphBeforeOriginalClaim(t *testing.T) {
	f := admissionIntegration(t, context.Background(), "preauthorized_pool")
	before := f.root.Snapshot()
	want, _, err := SessionAdmissionRequirements(f.config)
	if err != nil {
		t.Fatal(err)
	}
	a := f.reserve(t, context.Background())
	expected, _ := before.Charged.Add(want)
	if f.root.Snapshot().Charged != expected {
		t.Fatal("aggregate omitted or duplicated original charge")
	}
	if f.provider.reads.Load() != 0 || f.provider.writes.Load() != 0 {
		t.Fatal("reservation disclosed credentials")
	}
	if _, err := a.activate(f.trust.authority); !errors.Is(err, cryptov4.ErrTransition) {
		t.Fatal("uncommitted owner activated", err)
	}
	x, err := consumeSessionPool(t, f, a)
	if err != nil || x == nil {
		t.Fatal("original definite claim could not activate", err)
	}
	if _, err := a.activate(f.trust.authority); !errors.Is(err, cryptov4.ErrTransition) {
		t.Fatal("duplicate carrier activation", err)
	}
	if _, err := a.beginClaim(); !errors.Is(err, cryptov4.ErrTransition) {
		t.Fatal("duplicate claim", err)
	}
	if f.provider.reads.Load() != 0 || f.provider.writes.Load() != 0 {
		t.Fatal("initial construction sent a credential")
	}
}

func TestSessionAdmissionCanceledOriginalCommitCannotActivate(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f := admissionIntegration(t, ctx)
	a := f.reserve(t, ctx)
	claim, err := a.beginClaim()
	if err != nil {
		t.Fatal(err)
	}
	before := f.root.Snapshot()
	cancel()
	a.Close()
	cleanup, stop := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer stop()
	if err := a.WaitCleanup(cleanup); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("store tail refunded", err)
	}
	if f.root.Snapshot() != before {
		t.Fatal("cancel returned pending Session resources")
	}
	if err := a.finishClaim(claim, true); !errors.Is(err, cryptov4.ErrClosed) {
		t.Fatal("late definite result resumed original", err)
	}
	if _, err := a.activate(f.trust.authority); !errors.Is(err, cryptov4.ErrClosed) {
		t.Fatal("closed claim activated", err)
	}
	if f.provider.reads.Load() != 0 || f.provider.writes.Load() != 0 {
		t.Fatal("closed admission disclosed credentials")
	}
}

func TestSessionAdmissionRefusalPreservesPreparedOwner(t *testing.T) {
	for _, failure := range []string{"zero session capacity", "wrong subscription role", "wrong candidate", "closed core"} {
		t.Run(failure, func(t *testing.T) {
			f := admissionIntegration(t, context.Background())
			if failure == "closed core" {
				a := f.reserve(t, context.Background())
				a.core.Close()
				if _, err := a.beginClaim(); err == nil {
					t.Fatal("closed core allowed spend")
				}
				return
			}
			scope := f.scope
			sub := f.trust.subscriptions[0]
			config := f.config
			if failure == "zero session capacity" {
				limit := f.root.Snapshot().Limit
				limit[resourcev4.Sessions] = 0
				var err error
				scope.Session, err = f.root.Account(resourcev4.AccountKey{Kind: resourcev4.SessionAccount, ID: [16]byte{9}}, limit)
				if err != nil {
					t.Fatal(err)
				}
			}
			if failure == "wrong subscription role" {
				sub = f.trust.subscriptions[1]
			}
			if failure == "wrong candidate" {
				f.prepared.mu.Lock()
				f.prepared.binding.Candidate.RouteDigest[0] ^= 1
				f.prepared.mu.Unlock()
			}
			before := f.root.Snapshot()
			a, err := NewSessionAdmissionReservation(context.Background(), config, f.prepared, sub, f.root, admissionResourceKey(f.owner, 202), f.environment, f.preauth, scope, nil, nil)
			if a != nil || err == nil {
				t.Fatal("invalid admission accepted", err)
			}
			if f.root.Snapshot() != before {
				t.Fatal("refusal retained partial graph")
			}
			if f.provider.closes.Load() != 0 || f.provider.reads.Load() != 0 || f.provider.writes.Load() != 0 {
				t.Fatal("refusal took provider ownership")
			}
			if err := f.prepared.Check(); err != nil {
				t.Fatal("refusal consumed prepared owner", err)
			}
		})
	}
}

func TestSessionAdmissionInitiationWindowEndsBeforeSession(t *testing.T) {
	f := admissionIntegration(t, context.Background())
	f.trust.tick.Store(400)
	before := f.root.Snapshot()
	a, err := NewSessionAdmissionReservation(context.Background(), f.config, f.prepared, f.trust.subscriptions[0], f.root, admissionResourceKey(f.owner, 202), f.environment, f.preauth, f.scope, nil, nil)
	if a != nil || !errors.Is(err, timev4.ErrExpired) {
		t.Fatal("ended initiation window admitted before spend", err)
	}
	// Invalid trust preflight can close its original subscription; it cannot
	// create any core/Initial claim or issue a credential on this prepared owner.
	if f.root.Snapshot().Charged[resourcev4.Sessions] != before.Charged[resourcev4.Sessions] {
		t.Fatal("expired admission acquired a Session")
	}
	if f.provider.reads.Load() != 0 || f.provider.writes.Load() != 0 {
		t.Fatal("expired admission disclosed credentials")
	}
}

func TestSessionAdmissionUnknownCommitHasNoActivationContinuation(t *testing.T) {
	f := admissionIntegration(t, context.Background())
	a := f.reserve(t, context.Background())
	claim, err := a.beginClaim()
	if err != nil {
		t.Fatal(err)
	}
	if err := a.finishClaim(claim, false); !errors.Is(err, ErrAdmissionRejected) {
		t.Fatal("uncertain claim continued", err)
	}
	if _, err := a.beginClaim(); !errors.Is(err, cryptov4.ErrClosed) {
		t.Fatal("unknown claim retried", err)
	}
	if err := a.finishClaim(claim, true); !errors.Is(err, cryptov4.ErrTransition) {
		t.Fatal("readback recreated claim", err)
	}
	if _, err := a.activate(f.trust.authority); !errors.Is(err, cryptov4.ErrClosed) {
		t.Fatal("unknown claim activated", err)
	}
}

func TestSessionAdmissionActivationWindowAndAuthorityLoss(t *testing.T) {
	for _, failure := range []string{"window", "trust"} {
		t.Run(failure, func(t *testing.T) {
			f := admissionIntegration(t, context.Background(), "preauthorized_pool")
			a := f.reserve(t, context.Background())
			if failure == "window" {
				f.trust.tick.Store(200)
			} else {
				f.trust.trust.rejected.Store(true)
				f.trust.namespace.NotifyTrust()
			}
			if x, err := consumeSessionPool(t, f, a); x != nil || err == nil {
				t.Fatal("invalid activation gate admitted", err)
			}
			if f.provider.reads.Load() != 0 || f.provider.writes.Load() != 0 {
				t.Fatal("failed activation disclosed credentials")
			}
		})
	}
}

func TestSessionAdmissionCleanupWaitersShareFinalCompletion(t *testing.T) {
	f := admissionIntegration(t, context.Background())
	a := f.reserve(t, context.Background())
	f.provider.waitEntered = make(chan struct{})
	f.provider.waitRelease = make(chan struct{})
	a.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	first := make(chan error, 1)
	go func() { first <- a.WaitCleanup(ctx) }()
	select {
	case <-f.provider.waitEntered:
	case <-ctx.Done():
		t.Fatal("physical cleanup not reached")
	}
	const observers = 6
	results := make(chan error, observers)
	for range observers {
		go func() { results <- a.WaitCleanup(ctx) }()
	}
	// Release the provider through one original wake. All observers must use
	// the stable completed channel, not consume a single notification token.
	close(f.provider.waitRelease)
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	for range observers {
		if err := <-results; err != nil {
			t.Fatal("cleanup observer missed completion", err)
		}
	}
}
