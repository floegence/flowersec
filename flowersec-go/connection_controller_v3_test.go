package flowersec

import (
	"context"
	"crypto/x509"
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/artifactv3"
)

func TestConnectionControllerPolicyReplacementChangedPinSucceeds(t *testing.T) {
	primary := controllerPolicyArtifact(t, controllerPinPolicy("ERERERERERERERERERERERERERERERERERERERERERE"))
	replacement := controllerPolicyArtifact(t, controllerPinPolicy("gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIA"))
	primaryLease, _ := controllerTrackedLease(t, primary)
	replacementLease, _ := controllerTrackedLease(t, replacement)
	source := &controllerTestSource{results: []controllerAcquireResult{{lease: primaryLease}, {lease: replacementLease}}}
	controller := newControllerForTest(t, source, 0)
	session := newControllerTestSession(SessionClosed)
	var calls atomic.Int32
	controller.connectDetailed = func(_ context.Context, claimed claimedArtifactLease, _ ConnectorOptions, allowed map[transportEndpointKey]struct{}) (Session, controllerConnectOutcome) {
		if calls.Add(1) == 1 {
			return nil, controllerPinTriggerOutcome(claimed.lease.artifact.value)
		}
		candidate := claimed.lease.artifact.value.Path.Candidates[0]
		if _, ok := allowed[endpointKey(claimed.lease.artifact.value.Path.Kind, candidate)]; !ok || len(allowed) != 1 {
			t.Fatalf("replacement allowed endpoints = %v, want changed pin only", allowed)
		}
		return session, controllerConnectOutcome{}
	}

	controller.Start(context.Background())
	waitControllerSession(t, controller, session)
	if source.callCount() != 2 || calls.Load() != 2 {
		t.Fatalf("acquisitions/connects = %d/%d, want 2/2", source.callCount(), calls.Load())
	}
	closeController(t, controller)
}

func TestConnectionControllerUsesInjectedClockForArtifactExpiry(t *testing.T) {
	artifact := mustParseInternalFixtureArtifact(t)
	clock := newTestControllerClock(time.Unix(1_700_000_000, 0), 0)
	artifact.value.Session.InitExpireAtUnixSeconds = clock.wallTime().Unix() - 1
	lease, err := NewArtifactLease(artifact, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	controller, err := NewConnectionController(&controllerTestSource{results: []controllerAcquireResult{{lease: lease}}}, ConnectionControllerOptions{
		Connector: ConnectorOptions{}, MaximumAttempts: 1,
		clock: clock.options(),
	})
	if err != nil {
		t.Fatal(err)
	}
	controller.Start(context.Background())
	waitControllerState(t, controller, ConnectionFailed)
	if got := connectErrorCode(controller.Snapshot().Failure.Error); got != ConnectExpired {
		t.Fatalf("failure code = %q, want %q", got, ConnectExpired)
	}
	closeController(t, controller)
}

func TestConnectionControllerRaceEndExpiryOverridesPolicyRefreshDiagnostics(t *testing.T) {
	artifact := controllerPolicyArtifact(t, controllerPinPolicy("ERERERERERERERERERERERERERERERERERERERERERE"))
	lease, _ := controllerTrackedLease(t, artifact)
	source := &controllerTestSource{results: []controllerAcquireResult{{lease: lease}}}
	controller := newControllerForTest(t, source, 1)
	controller.connectDetailed = func(_ context.Context, claimed claimedArtifactLease, _ ConnectorOptions, _ map[transportEndpointKey]struct{}) (Session, controllerConnectOutcome) {
		candidate := claimed.lease.artifact.value.Path.Candidates[0]
		key := endpointKey(claimed.lease.artifact.value.Path.Kind, candidate)
		return nil, controllerConnectOutcome{
			err:               &ConnectError{code: ConnectExpired},
			securityFailure:   true,
			triggerCandidates: map[transportEndpointKey]artifactv3.Candidate{key: candidate},
			failedEndpoints:   map[transportEndpointKey]struct{}{key: {}},
		}
	}

	controller.Start(context.Background())
	waitControllerState(t, controller, ConnectionFailed)
	if got := connectErrorCode(controller.Snapshot().Failure.Error); got != ConnectExpired {
		t.Fatalf("race-end expiry with stale TLS diagnostics = %q, want %q", got, ConnectExpired)
	}
	if source.callCount() != 1 {
		t.Fatalf("race-end expiry acquired a replacement lease: calls = %d", source.callCount())
	}
	closeController(t, controller)
}

func TestConnectionControllerWaitUsesInjectedWallAndMonotonicClocks(t *testing.T) {
	clock := newTestControllerClock(time.UnixMilli(1_000), 0)
	controller := &ConnectionController{
		retry: make(chan struct{}, 1), changed: make(chan struct{}), done: make(chan struct{}),
		retryNotBeforeUnixMilliseconds: -1, clock: clock.options(),
	}
	result := make(chan bool, 1)
	go func() {
		result <- controller.wait(context.Background(), ConnectionFailureConnect, &ConnectError{code: ConnectConnectionFailed}, retryableDisposition(), 5_000, 250*time.Millisecond, 0)
	}()
	clock.waitForTimer(t, 0)
	clock.advance(1_000, 250)
	clock.fireTimer(0)
	clock.waitForTimer(t, 1)
	clock.advance(4_000, 0)
	clock.fireTimer(1)
	if !<-result {
		t.Fatal("controller wait returned false")
	}
	if got := clock.delays(); !reflect.DeepEqual(got, []time.Duration{250 * time.Millisecond, time.Second}) {
		t.Fatalf("timer delays = %v, want [250ms 1s]", got)
	}
}

func TestConnectionControllerWaitSaturatesNegativeWallRollbackDelta(t *testing.T) {
	clock := newTestControllerClock(time.UnixMilli(-1<<63), 0)
	controller := &ConnectionController{
		retry: make(chan struct{}, 1), changed: make(chan struct{}), done: make(chan struct{}),
		retryNotBeforeUnixMilliseconds: -1, clock: clock.options(),
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan bool, 1)
	go func() {
		result <- controller.wait(ctx, ConnectionFailureConnect, &ConnectError{code: ConnectConnectionFailed}, retryableDisposition(), 0, 0, 0)
	}()
	clock.waitForTimer(t, 0)
	if got := clock.delays()[0]; got != time.Second {
		t.Fatalf("rollback timer delay = %s, want 1s", got)
	}
	cancel()
	if <-result {
		t.Fatal("canceled rollback wait returned success")
	}
}

type testControllerClock struct {
	mu          sync.Mutex
	wall        time.Time
	mono        uint64
	timers      []*testControllerTimer
	delayValues []time.Duration
}

type testControllerTimer struct {
	channel chan time.Time
	stopped bool
}

func newTestControllerClock(wall time.Time, monotonicMilliseconds uint64) *testControllerClock {
	return &testControllerClock{wall: wall, mono: monotonicMilliseconds}
}

func (clock *testControllerClock) options() controllerClock {
	return controllerClock{
		wallNow: func() time.Time {
			clock.mu.Lock()
			defer clock.mu.Unlock()
			return clock.wall
		},
		monotonicNowMilliseconds: func() uint64 {
			clock.mu.Lock()
			defer clock.mu.Unlock()
			return clock.mono
		},
		newTimer: func(delay time.Duration) controllerTimer {
			clock.mu.Lock()
			defer clock.mu.Unlock()
			timer := &testControllerTimer{channel: make(chan time.Time, 1)}
			clock.timers = append(clock.timers, timer)
			clock.delayValues = append(clock.delayValues, delay)
			return controllerTimer{channel: timer.channel, stop: func() bool {
				clock.mu.Lock()
				defer clock.mu.Unlock()
				timer.stopped = true
				return true
			}}
		},
	}
}

func (clock *testControllerClock) advance(wallMilliseconds int64, monotonicMilliseconds int64) {
	clock.mu.Lock()
	clock.wall = clock.wall.Add(time.Duration(wallMilliseconds) * time.Millisecond)
	if monotonicMilliseconds >= 0 {
		clock.mono = saturatingControllerAdd(clock.mono, uint64(monotonicMilliseconds))
	} else {
		clock.mono -= min(clock.mono, uint64(-monotonicMilliseconds))
	}
	clock.mu.Unlock()
}

func (clock *testControllerClock) values() (int64, uint64) {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.wall.UnixMilli(), clock.mono
}

func (clock *testControllerClock) waitForTimer(t *testing.T, index int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		clock.mu.Lock()
		count := len(clock.timers)
		clock.mu.Unlock()
		if count > index {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timer %d was not created", index)
}

func (clock *testControllerClock) fireTimer(index int) {
	clock.mu.Lock()
	timer := clock.timers[index]
	timer.channel <- clock.wall
	clock.mu.Unlock()
}

func (clock *testControllerClock) wallTime() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.wall
}

func (clock *testControllerClock) delays() []time.Duration {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return append([]time.Duration(nil), clock.delayValues...)
}

func TestConnectionControllerRejectsUnchangedOrDowngradedReplacement(t *testing.T) {
	oldPolicy := controllerPinPolicy("ERERERERERERERERERERERERERERERERERERERERERE")
	tests := []struct {
		name   string
		policy artifactv3.TLSPolicy
	}{
		{name: "same-policy", policy: oldPolicy},
		{name: "pin-to-ca", policy: artifactv3.TLSPolicy{Mode: artifactv3.TLSModeCA}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			primaryLease, primaryRetired := controllerTrackedLease(t, controllerPolicyArtifact(t, oldPolicy))
			replacementLease, replacementRetired := controllerTrackedLease(t, controllerPolicyArtifact(t, test.policy))
			source := &controllerTestSource{results: []controllerAcquireResult{{lease: primaryLease}, {lease: replacementLease}}}
			controller := newControllerForTest(t, source, 0)
			var calls atomic.Int32
			controller.connectDetailed = func(_ context.Context, claimed claimedArtifactLease, _ ConnectorOptions, _ map[transportEndpointKey]struct{}) (Session, controllerConnectOutcome) {
				calls.Add(1)
				return nil, controllerPinTriggerOutcome(claimed.lease.artifact.value)
			}

			controller.Start(context.Background())
			waitControllerState(t, controller, ConnectionFailed)
			snapshot := controller.Snapshot()
			if connectErrorCode(snapshot.Failure.Error) != ConnectTransportSecurityFailed ||
				snapshot.Failure.Disposition.Kind != RetryDispositionTerminal {
				t.Fatalf("failure = %+v, want transport_security_failed/terminal", snapshot.Failure)
			}
			if source.callCount() != 2 || calls.Load() != 1 || primaryRetired.Load() != 1 || replacementRetired.Load() != 1 {
				t.Fatalf("acquires/connects/retirements = %d/%d/%d/%d", source.callCount(), calls.Load(), primaryRetired.Load(), replacementRetired.Load())
			}
			closeController(t, controller)
		})
	}
}

func TestConnectionControllerReplacementSourceRetryStaysInReplacementMode(t *testing.T) {
	primaryLease, _ := controllerTrackedLease(t, controllerPolicyArtifact(t, controllerPinPolicy("ERERERERERERERERERERERERERERERERERERERERERE")))
	replacementLease, _ := controllerTrackedLease(t, controllerPolicyArtifact(t, controllerPinPolicy("gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIA")))
	source := &controllerTestSource{results: []controllerAcquireResult{
		{lease: primaryLease},
		{failure: NewRetryableArtifactSourceError(context.DeadlineExceeded)},
		{lease: replacementLease},
	}}
	controller := newControllerForTest(t, source, 0)
	session := newControllerTestSession(SessionClosed)
	var calls atomic.Int32
	controller.connectDetailed = func(_ context.Context, claimed claimedArtifactLease, _ ConnectorOptions, allowed map[transportEndpointKey]struct{}) (Session, controllerConnectOutcome) {
		if calls.Add(1) == 1 {
			return nil, controllerPinTriggerOutcome(claimed.lease.artifact.value)
		}
		if len(allowed) != 1 {
			t.Fatalf("replacement allowed endpoints = %v", allowed)
		}
		return session, controllerConnectOutcome{}
	}

	controller.Start(context.Background())
	waitControllerState(t, controller, ConnectionWaiting)
	if !controller.RetryNow() {
		t.Fatal("RetryNow did not wake replacement-source backoff")
	}
	waitControllerSession(t, controller, session)
	if source.callCount() != 3 || calls.Load() != 2 {
		t.Fatalf("acquisitions/connects = %d/%d, want 3/2", source.callCount(), calls.Load())
	}
	closeController(t, controller)
}

func TestConnectionControllerBlocksOldPinAfterReplacementExpiry(t *testing.T) {
	oldPolicy := controllerPinPolicy("ERERERERERERERERERERERERERERERERERERERERERE")
	newPolicy := controllerPinPolicy("gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIA")
	primary := controllerPolicyArtifact(t, oldPolicy)
	replacement := controllerPolicyArtifact(t, newPolicy)
	nextPrimary := controllerPolicyArtifact(t, oldPolicy)
	caCandidate := mustParseInternalFixtureArtifact(t).value.Path.Candidates[0]
	caCandidate.TLS = artifactv3.TLSPolicy{Mode: artifactv3.TLSModeCA}
	nextPrimary.value.Path.Candidates = append(nextPrimary.value.Path.Candidates, caCandidate)

	primaryLease, _ := controllerTrackedLease(t, primary)
	replacementLease, _ := controllerTrackedLease(t, replacement)
	nextLease, _ := controllerTrackedLease(t, nextPrimary)
	source := &controllerTestSource{results: []controllerAcquireResult{{lease: primaryLease}, {lease: replacementLease}, {lease: nextLease}}}
	controller := newControllerForTest(t, source, 0)
	session := newControllerTestSession(SessionClosed)
	var calls atomic.Int32
	controller.connectDetailed = func(_ context.Context, claimed claimedArtifactLease, _ ConnectorOptions, allowed map[transportEndpointKey]struct{}) (Session, controllerConnectOutcome) {
		switch calls.Add(1) {
		case 1:
			return nil, controllerPinTriggerOutcome(claimed.lease.artifact.value)
		case 2:
			if len(allowed) != 1 {
				t.Fatalf("replacement allowed endpoints = %v", allowed)
			}
			return nil, controllerConnectOutcome{err: &ConnectError{code: ConnectExpired}}
		default:
			oldKey := endpointKey(claimed.lease.artifact.value.Path.Kind, claimed.lease.artifact.value.Path.Candidates[0])
			caKey := endpointKey(claimed.lease.artifact.value.Path.Kind, claimed.lease.artifact.value.Path.Candidates[1])
			if _, oldAllowed := allowed[oldKey]; oldAllowed {
				t.Fatal("old pin digest was eligible after replacement expiry")
			}
			if _, caAllowed := allowed[caKey]; !caAllowed || len(allowed) != 1 {
				t.Fatalf("next primary allowed endpoints = %v, want unrelated CA only", allowed)
			}
			return session, controllerConnectOutcome{}
		}
	}

	controller.Start(context.Background())
	waitControllerState(t, controller, ConnectionWaiting)
	if !controller.RetryNow() {
		t.Fatal("RetryNow did not wake replacement-expiry backoff")
	}
	waitControllerSession(t, controller, session)
	closeController(t, controller)
}

func TestConnectionControllerReplacementPostSpendRetryPreservesQuota(t *testing.T) {
	oldPolicy := controllerPinPolicy("ERERERERERERERERERERERERERERERERERERERERERE")
	newPolicy := controllerPinPolicy("gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIA")
	primaryLease, primaryRetired := controllerTrackedLease(t, controllerPolicyArtifact(t, oldPolicy))

	var replacementSpent atomic.Int32
	var replacementRetired atomic.Int32
	replacementLease, err := NewArtifactLeaseWithRetirement(
		controllerPolicyArtifact(t, newPolicy),
		func(context.Context) error {
			replacementSpent.Add(1)
			return nil
		},
		func(context.Context) error {
			replacementRetired.Add(1)
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	nextLease, nextRetired := controllerTrackedLease(t, controllerPolicyArtifact(t, newPolicy))
	source := &controllerTestSource{results: []controllerAcquireResult{
		{lease: primaryLease},
		{lease: replacementLease},
		{lease: nextLease},
	}}
	controller := newControllerForTest(t, source, 0)
	var calls atomic.Int32
	controller.connectDetailed = func(ctx context.Context, claimed claimedArtifactLease, _ ConnectorOptions, allowed map[transportEndpointKey]struct{}) (Session, controllerConnectOutcome) {
		switch calls.Add(1) {
		case 1:
			return nil, controllerPinTriggerOutcome(claimed.lease.artifact.value)
		case 2:
			if len(allowed) != 1 {
				t.Fatalf("replacement allowed endpoints = %v", allowed)
			}
			if err := claimed.lease.commitSpend(ctx); err != nil {
				t.Fatalf("replacement commitSpend: %v", err)
			}
			return nil, controllerConnectOutcome{
				err:          &ConnectError{code: ConnectConnectionFailed},
				spendStarted: claimed.spendStarted(),
			}
		default:
			return nil, controllerPinTriggerOutcome(claimed.lease.artifact.value)
		}
	}

	controller.Start(context.Background())
	waitControllerState(t, controller, ConnectionWaiting)
	if !controller.RetryNow() {
		t.Fatal("RetryNow did not wake post-spend retry backoff")
	}
	waitControllerState(t, controller, ConnectionFailed)
	snapshot := controller.Snapshot()
	if connectErrorCode(snapshot.Failure.Error) != ConnectTransportSecurityFailed ||
		snapshot.Failure.Disposition.Kind != RetryDispositionTerminal {
		t.Fatalf("failure = %+v, want transport_security_failed/terminal", snapshot.Failure)
	}
	if source.callCount() != 3 || calls.Load() != 3 {
		t.Fatalf("acquisitions/connects = %d/%d, want 3/3", source.callCount(), calls.Load())
	}
	if replacementSpent.Load() != 1 || replacementRetired.Load() != 0 {
		t.Fatalf("replacement spend/retire = %d/%d, want 1/0", replacementSpent.Load(), replacementRetired.Load())
	}
	if primaryRetired.Load() != 1 || nextRetired.Load() != 1 {
		t.Fatalf("primary/next retire = %d/%d, want 1/1", primaryRetired.Load(), nextRetired.Load())
	}
	replacementLease.state.mu.Lock()
	replacementStatus := replacementLease.state.status
	replacementLease.state.mu.Unlock()
	if replacementStatus != artifactLeaseConsumed {
		t.Fatalf("replacement lease state = %d, want consumed", replacementStatus)
	}
	closeController(t, controller)
}

func TestConnectionControllerWeakNetworkRotationPreservesOneShotSecurityState(t *testing.T) {
	conditions := []string{
		"latency",
		"jitter",
		"packet-loss",
		"reordering",
		"temporary-outage",
		"disconnect-reconnect",
	}
	for _, condition := range conditions {
		t.Run(condition, func(t *testing.T) {
			oldPolicy := controllerPinPolicy("ERERERERERERERERERERERERERERERERERERERERERE")
			newPolicy := controllerPinPolicy("gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIA")
			oldArtifact := controllerPolicyArtifact(t, oldPolicy)
			newArtifact := controllerPolicyArtifact(t, newPolicy)
			nextPrimary := controllerPolicyArtifact(t, oldPolicy)
			caCandidate := mustParseInternalFixtureArtifact(t).value.Path.Candidates[0]
			caCandidate.TLS = artifactv3.TLSPolicy{Mode: artifactv3.TLSModeCA}
			nextPrimary.value.Path.Candidates = append(nextPrimary.value.Path.Candidates, caCandidate)

			type leaseCounters struct {
				spent   atomic.Int32
				retired atomic.Int32
			}
			tracked := func(artifact Artifact) (ArtifactLease, *leaseCounters) {
				counters := &leaseCounters{}
				lease, err := NewArtifactLeaseWithRetirement(
					artifact,
					func(context.Context) error {
						counters.spent.Add(1)
						return nil
					},
					func(context.Context) error {
						counters.retired.Add(1)
						return nil
					},
				)
				if err != nil {
					t.Fatal(err)
				}
				return lease, counters
			}

			initialLease, initialCounters := tracked(oldArtifact)
			triggerLease, triggerCounters := tracked(oldArtifact)
			replacementLease, replacementCounters := tracked(newArtifact)
			reconnectLease, reconnectCounters := tracked(nextPrimary)
			source := &controllerTestSource{results: []controllerAcquireResult{
				{lease: initialLease},
				{lease: triggerLease},
				{lease: replacementLease},
				{lease: reconnectLease},
			}}
			controller := newControllerForTest(t, source, 0)
			session := newControllerTestSession(SessionClosed)
			var calls atomic.Int32
			controller.connectDetailed = func(ctx context.Context, claimed claimedArtifactLease, _ ConnectorOptions, allowed map[transportEndpointKey]struct{}) (Session, controllerConnectOutcome) {
				switch calls.Add(1) {
				case 1:
					return nil, controllerConnectOutcome{err: &ConnectError{code: ConnectConnectionFailed}}
				case 2:
					return nil, controllerPinTriggerOutcome(claimed.lease.artifact.value)
				case 3:
					if len(allowed) != 1 {
						t.Fatalf("replacement allowed endpoints = %v, want changed pin only", allowed)
					}
					if err := claimed.lease.commitSpend(ctx); err != nil {
						t.Fatalf("replacement commitSpend: %v", err)
					}
					return nil, controllerConnectOutcome{
						err:          &ConnectError{code: ConnectConnectionFailed},
						spendStarted: claimed.spendStarted(),
					}
				case 4:
					artifact := claimed.lease.artifact.value
					oldKey := endpointKey(artifact.Path.Kind, artifact.Path.Candidates[0])
					caKey := endpointKey(artifact.Path.Kind, artifact.Path.Candidates[1])
					if _, ok := allowed[oldKey]; ok {
						t.Fatal("reconnect made the blocked old pin policy eligible")
					}
					if _, ok := allowed[caKey]; !ok || len(allowed) != 1 {
						t.Fatalf("reconnect allowed endpoints = %v, want unrelated CA only", allowed)
					}
					if err := claimed.lease.commitSpend(ctx); err != nil {
						t.Fatalf("reconnect commitSpend: %v", err)
					}
					return session, controllerConnectOutcome{}
				default:
					t.Fatalf("unexpected connector call %d", calls.Load())
					return nil, controllerConnectOutcome{err: &ConnectError{code: ConnectArtifactInvalid}}
				}
			}

			controller.Start(context.Background())
			waitControllerState(t, controller, ConnectionWaiting)
			if !controller.RetryNow() {
				t.Fatal("RetryNow did not wake the weak-network retry")
			}
			deadline := time.Now().Add(2 * time.Second)
			for calls.Load() < 3 || controller.Snapshot().State != ConnectionWaiting {
				if time.Now().After(deadline) {
					t.Fatalf("replacement did not reach post-spend wait: calls=%d state=%s", calls.Load(), controller.Snapshot().State)
				}
				time.Sleep(time.Millisecond)
			}
			if !controller.RetryNow() {
				t.Fatal("RetryNow did not wake the post-spend reconnect")
			}
			waitControllerSession(t, controller, session)

			if source.callCount() != 4 || calls.Load() != 4 {
				t.Fatalf("acquisitions/connects = %d/%d, want 4/4", source.callCount(), calls.Load())
			}
			if initialCounters.spent.Load() != 0 || initialCounters.retired.Load() != 1 ||
				triggerCounters.spent.Load() != 0 || triggerCounters.retired.Load() != 1 ||
				replacementCounters.spent.Load() != 1 || replacementCounters.retired.Load() != 0 ||
				reconnectCounters.spent.Load() != 1 || reconnectCounters.retired.Load() != 0 {
				t.Fatalf(
					"lease finalization initial=%d/%d trigger=%d/%d replacement=%d/%d reconnect=%d/%d",
					initialCounters.spent.Load(), initialCounters.retired.Load(),
					triggerCounters.spent.Load(), triggerCounters.retired.Load(),
					replacementCounters.spent.Load(), replacementCounters.retired.Load(),
					reconnectCounters.spent.Load(), reconnectCounters.retired.Load(),
				)
			}
			closeController(t, controller)
		})
	}
}

func TestConnectionControllerAttemptBudgetExhaustedWhileAcquiringReplacement(t *testing.T) {
	primaryLease, primaryRetired := controllerTrackedLease(t, controllerPolicyArtifact(t,
		controllerPinPolicy("ERERERERERERERERERERERERERERERERERERERERERE"),
	))
	source := &controllerTestSource{results: []controllerAcquireResult{
		{lease: primaryLease},
		{failure: NewRetryableArtifactSourceError(errors.New("replacement source unavailable"))},
	}}
	controller := newControllerForTest(t, source, 2)
	var calls atomic.Int32
	controller.connectDetailed = func(_ context.Context, claimed claimedArtifactLease, _ ConnectorOptions, _ map[transportEndpointKey]struct{}) (Session, controllerConnectOutcome) {
		calls.Add(1)
		return nil, controllerPinTriggerOutcome(claimed.lease.artifact.value)
	}

	controller.Start(context.Background())
	waitControllerState(t, controller, ConnectionFailed)
	snapshot := controller.Snapshot()
	if connectErrorCode(snapshot.Failure.Error) != ConnectConnectionFailed ||
		snapshot.Failure.Disposition.Kind != RetryDispositionTerminal {
		t.Fatalf("failure = %+v, want replacement source connection_failed/terminal", snapshot.Failure)
	}
	if source.callCount() != 2 || calls.Load() != 1 || primaryRetired.Load() != 1 {
		t.Fatalf("acquisitions/connects/retirements = %d/%d/%d, want 2/1/1", source.callCount(), calls.Load(), primaryRetired.Load())
	}
	closeController(t, controller)
}

func TestArtifactLeaseConcurrentOneShotAndControllerClaimHasOnePublicLoser(t *testing.T) {
	for iteration := 0; iteration < 32; iteration++ {
		artifact := controllerPolicyArtifact(t, controllerPinPolicy("ERERERERERERERERERERERERERERERERERERERERERE"))
		var spent atomic.Int32
		var retired atomic.Int32
		lease, err := NewArtifactLeaseWithRetirement(
			artifact,
			func(context.Context) error {
				spent.Add(1)
				return nil
			},
			func(context.Context) error {
				retired.Add(1)
				return nil
			},
		)
		if err != nil {
			t.Fatal(err)
		}

		gate := make(chan struct{})
		source := &lateLeaseSource{started: make(chan struct{}), release: gate, lease: lease}
		controller := newControllerForTest(t, source, 0)
		session := newControllerTestSession(SessionClosed)
		var controllerCalls atomic.Int32
		controller.connectDetailed = func(ctx context.Context, claimed claimedArtifactLease, _ ConnectorOptions, _ map[transportEndpointKey]struct{}) (Session, controllerConnectOutcome) {
			controllerCalls.Add(1)
			if err := claimed.lease.commitSpend(ctx); err != nil {
				return nil, controllerConnectOutcome{err: &ConnectError{code: ConnectArtifactInvalid}}
			}
			return session, controllerConnectOutcome{}
		}
		controller.Start(context.Background())
		<-source.started

		oneShotReady := make(chan struct{})
		oneShotResult := make(chan error, 1)
		go func() {
			close(oneShotReady)
			<-gate
			_, connectErr := Connect(context.Background(), lease, ConnectorOptions{TrustRoots: x509.NewCertPool()})
			oneShotResult <- connectErr
		}()
		<-oneShotReady
		close(gate)
		oneShotErr := <-oneShotResult

		deadline := time.Now().Add(time.Second)
		for controller.Snapshot().State != ConnectionConnected && controller.Snapshot().State != ConnectionFailed && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		snapshot := controller.Snapshot()
		switch snapshot.State {
		case ConnectionConnected:
			if connectErrorCode(oneShotErr) != ConnectArtifactInvalid || controllerCalls.Load() != 1 {
				t.Fatalf("iteration %d: one-shot error/controller calls = %v/%d, want artifact_invalid/1", iteration, oneShotErr, controllerCalls.Load())
			}
		case ConnectionFailed:
			if snapshot.Failure == nil || connectErrorCode(snapshot.Failure.Error) != ConnectArtifactInvalid ||
				snapshot.Failure.Disposition.Kind != RetryDispositionTerminal {
				t.Fatalf("iteration %d: controller failure = %+v, want artifact_invalid/terminal", iteration, snapshot.Failure)
			}
			if connectErrorCode(oneShotErr) != ConnectArtifactInvalid || controllerCalls.Load() != 0 {
				t.Fatalf("iteration %d: one-shot error/controller calls = %v/%d, want artifact_invalid/0", iteration, oneShotErr, controllerCalls.Load())
			}
		default:
			t.Fatalf("iteration %d: controller state = %s", iteration, snapshot.State)
		}
		if spent.Load()+retired.Load() != 1 {
			t.Fatalf("iteration %d: spend/retire = %d/%d, want exactly one finalization", iteration, spent.Load(), retired.Load())
		}
		closeController(t, controller)
	}
}

func TestConnectionControllerClaimsAndRetiresLeaseReturnedAfterCancellation(t *testing.T) {
	artifact := controllerPolicyArtifact(t, controllerPinPolicy("ERERERERERERERERERERERERERERERERERERERERERE"))
	lease, retired := controllerTrackedLease(t, artifact)
	source := &lateLeaseSource{started: make(chan struct{}), release: make(chan struct{}), lease: lease}
	controller := newControllerForTest(t, source, 0)
	controller.Start(context.Background())
	<-source.started
	closed := make(chan error, 1)
	go func() { closed <- controller.Close(context.Background()) }()
	select {
	case err := <-closed:
		t.Fatalf("Close returned before late lease cleanup: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(source.release)
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	if retired.Load() != 1 {
		t.Fatalf("late lease retire count = %d, want 1", retired.Load())
	}
	lease.state.mu.Lock()
	status := lease.state.status
	lease.state.mu.Unlock()
	if status != artifactLeaseRetired {
		t.Fatalf("late lease state = %d, want retired", status)
	}
}

func TestConnectionControllerSourceOwnershipViolationsFailAtArtifactPhase(t *testing.T) {
	t.Run("empty lease", func(t *testing.T) {
		source := &controllerTestSource{results: []controllerAcquireResult{{}}}
		controller := newControllerForTest(t, source, 0)
		var connects atomic.Int32
		controller.connectDetailed = func(context.Context, claimedArtifactLease, ConnectorOptions, map[transportEndpointKey]struct{}) (Session, controllerConnectOutcome) {
			connects.Add(1)
			return nil, controllerConnectOutcome{}
		}
		controller.Start(context.Background())
		waitControllerState(t, controller, ConnectionFailed)
		snapshot := controller.Snapshot()
		if snapshot.Failure == nil || connectErrorCode(snapshot.Failure.Error) != ConnectArtifactInvalid ||
			snapshot.Failure.Phase() != ConnectionFailureArtifact ||
			snapshot.Failure.Disposition.Kind != RetryDispositionTerminal {
			t.Fatalf("empty lease failure = %+v, want artifact_invalid/artifact/terminal", snapshot.Failure)
		}
		if connects.Load() != 0 || source.callCount() != 1 {
			t.Fatalf("empty lease acquisitions/connects = %d/%d, want 1/0", source.callCount(), connects.Load())
		}
		closeController(t, controller)
	})

	for _, terminalState := range []string{"consumed", "retired"} {
		t.Run("duplicate "+terminalState+" lease", func(t *testing.T) {
			lease, _ := controllerTrackedLease(t, controllerPolicyArtifact(t, controllerPinPolicy("ERERERERERERERERERERERERERERERERERERERERERE")))
			source := &controllerTestSource{results: []controllerAcquireResult{{lease: lease}, {lease: lease}}}
			controller := newControllerForTest(t, source, 2)
			var connects atomic.Int32
			controller.connectDetailed = func(ctx context.Context, claimed claimedArtifactLease, _ ConnectorOptions, _ map[transportEndpointKey]struct{}) (Session, controllerConnectOutcome) {
				connects.Add(1)
				if terminalState == "consumed" {
					if err := claimed.lease.commitSpend(ctx); err != nil {
						t.Fatal(err)
					}
				}
				return nil, controllerConnectOutcome{err: &ConnectError{code: ConnectConnectionFailed}, spendStarted: claimed.spendStarted()}
			}
			controller.Start(context.Background())
			waitControllerState(t, controller, ConnectionWaiting)
			if !controller.RetryNow() {
				t.Fatal("duplicate lease retry was not waiting")
			}
			waitControllerState(t, controller, ConnectionFailed)
			snapshot := controller.Snapshot()
			if snapshot.Failure == nil || connectErrorCode(snapshot.Failure.Error) != ConnectArtifactInvalid ||
				snapshot.Failure.Phase() != ConnectionFailureArtifact ||
				snapshot.Failure.Disposition.Kind != RetryDispositionTerminal {
				t.Fatalf("duplicate lease failure = %+v, want artifact_invalid/artifact/terminal", snapshot.Failure)
			}
			if connects.Load() != 1 || source.callCount() != 2 {
				t.Fatalf("duplicate lease acquisitions/connects = %d/%d, want 2/1", source.callCount(), connects.Load())
			}
			closeController(t, controller)
		})
	}
}

func TestConnectionControllerSurvivesRetireCleanupPanic(t *testing.T) {
	artifact := controllerPolicyArtifact(t, controllerPinPolicy("ERERERERERERERERERERERERERERERERERERERERERE"))
	var retireCalls atomic.Int32
	first, err := NewArtifactLeaseWithRetirement(
		artifact,
		func(context.Context) error { return nil },
		func(context.Context) error {
			retireCalls.Add(1)
			panic("application cleanup panic")
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewArtifactLease(artifact, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	source := &controllerTestSource{results: []controllerAcquireResult{{lease: first}, {lease: second}}}
	controller := newControllerForTest(t, source, 0)
	session := newControllerTestSession(SessionClosed)
	var connects atomic.Int32
	controller.connectDetailed = func(ctx context.Context, claimed claimedArtifactLease, _ ConnectorOptions, _ map[transportEndpointKey]struct{}) (Session, controllerConnectOutcome) {
		if connects.Add(1) == 1 {
			return nil, controllerConnectOutcome{err: &ConnectError{code: ConnectConnectionFailed}}
		}
		if err := claimed.lease.commitSpend(ctx); err != nil {
			t.Fatal(err)
		}
		return session, controllerConnectOutcome{spendStarted: true}
	}
	controller.Start(context.Background())
	waitControllerState(t, controller, ConnectionWaiting)
	if !controller.RetryNow() {
		t.Fatal("retirement cleanup panic prevented retry")
	}
	waitControllerSession(t, controller, session)
	if retireCalls.Load() != 1 || artifactLeaseStatusName(first) != "retired" ||
		source.callCount() != 2 || connects.Load() != 2 {
		t.Fatalf("retire/state/acquires/connects = %d/%s/%d/%d, want 1/retired/2/2",
			retireCalls.Load(), artifactLeaseStatusName(first), source.callCount(), connects.Load())
	}
	closeController(t, controller)
}

func TestArtifactLeaseRetirePanicIsOpaqueAndOneShot(t *testing.T) {
	artifact := controllerPolicyArtifact(t, controllerPinPolicy("ERERERERERERERERERERERERERERERERERERERERERE"))
	var retireCalls atomic.Int32
	lease, err := NewArtifactLeaseWithRetirement(
		artifact,
		func(context.Context) error { return nil },
		func(context.Context) error {
			retireCalls.Add(1)
			panic("secret cleanup detail")
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	claimed, ok := lease.claimArtifact()
	if !ok {
		t.Fatal("claim retirement lease")
	}
	if err := claimed.retire(context.Background()); err == nil ||
		err.Error() != "Flowersec artifact lease retirement cleanup failed" {
		t.Fatalf("retirement panic error = %v, want opaque cleanup failure", err)
	}
	if err := claimed.retire(context.Background()); err != nil {
		t.Fatalf("repeated retirement = %v, want terminal no-op", err)
	}
	if retireCalls.Load() != 1 || artifactLeaseStatusName(lease) != "retired" {
		t.Fatalf("retire/state = %d/%s, want 1/retired", retireCalls.Load(), artifactLeaseStatusName(lease))
	}
}

func TestConnectionControllerRejectsInvalidRetryAfterWithoutScheduling(t *testing.T) {
	source := &controllerTestSource{results: []controllerAcquireResult{
		{failure: &ArtifactSourceError{
			cause: context.DeadlineExceeded,
			disposition: RetryDisposition{
				Kind:                    RetryDispositionRetryAfter,
				RetryAtUnixMilliseconds: 253_402_300_800_000,
			},
		}},
	}}
	controller := newControllerForTest(t, source, 0)
	controller.Start(context.Background())
	waitControllerState(t, controller, ConnectionFailed)
	snapshot := controller.Snapshot()
	if connectErrorCode(snapshot.Failure.Error) != ConnectArtifactInvalid ||
		snapshot.Failure.Disposition.Kind != RetryDispositionTerminal || source.callCount() != 1 || controller.RetryNow() {
		t.Fatalf("invalid retry-after result = %+v, calls=%d", snapshot.Failure, source.callCount())
	}
	closeController(t, controller)
}

func TestControllerNumericBounds(t *testing.T) {
	validDeadline := maximumRetryAfterUnixMilliseconds
	if _, err := NewRetryAfterArtifactSourceError(errors.New("bounded"), validDeadline); err != nil {
		t.Fatalf("maximum retry-after rejected: %v", err)
	}
	for _, invalid := range []int64{
		-1,
		maximumRetryAfterUnixMilliseconds + 1,
	} {
		if _, err := NewRetryAfterArtifactSourceError(errors.New("invalid"), invalid); err == nil {
			t.Fatalf("invalid retry-after %v was accepted", invalid)
		}
	}
	if _, err := NewConnectionController(&controllerTestSource{}, ConnectionControllerOptions{
		MaximumAttempts: maxSafeControllerInteger + 1,
	}); !errors.Is(err, ErrInvalidConnectionController) {
		t.Fatalf("unsafe maximumAttempts error = %v", err)
	}
}

func TestTransportSecurityFailureIsTerminalAtPublicBoundary(t *testing.T) {
	err := &ConnectError{code: ConnectTransportSecurityFailed}
	if got := err.RetryDisposition().Kind; got != RetryDispositionTerminal {
		t.Fatalf("transport security retry disposition = %q, want terminal", got)
	}
}

func controllerPinTriggerOutcome(artifact *artifactv3.Artifact) controllerConnectOutcome {
	candidate := artifact.Path.Candidates[0]
	key := endpointKey(artifact.Path.Kind, candidate)
	return controllerConnectOutcome{
		err:               &ConnectError{code: ConnectTransportSecurityFailed},
		securityFailure:   true,
		triggerCandidates: map[transportEndpointKey]artifactv3.Candidate{key: candidate},
		failedEndpoints:   map[transportEndpointKey]struct{}{key: {}},
	}
}

func controllerPinPolicy(value string) artifactv3.TLSPolicy {
	return artifactv3.TLSPolicy{Mode: artifactv3.TLSModePin, Pins: []artifactv3.CertificatePin{{
		Algorithm: "sha-256", NotAfterUnixS: 4_000_000_000, ValueBase64URL: value,
	}}}
}

func controllerPolicyArtifact(t *testing.T, policy artifactv3.TLSPolicy) Artifact {
	t.Helper()
	original := mustParseInternalFixtureArtifact(t)
	value := *original.value
	value.Path.Candidates = append([]artifactv3.Candidate(nil), original.value.Path.Candidates...)
	candidate := value.Path.Candidates[1]
	candidate.TLS = artifactv3.CloneTLSPolicy(policy)
	value.Path.Candidates = []artifactv3.Candidate{candidate}
	return Artifact{value: &value}
}

func controllerMixedPolicyArtifact(t *testing.T, policy artifactv3.TLSPolicy) Artifact {
	t.Helper()
	original := mustParseInternalFixtureArtifact(t)
	value := *original.value
	value.Path.Candidates = []artifactv3.Candidate{
		original.value.Path.Candidates[0],
		original.value.Path.Candidates[3],
	}
	value.Path.Candidates[1].TLS = artifactv3.CloneTLSPolicy(policy)
	return Artifact{value: &value}
}

func controllerTrackedLease(t *testing.T, artifact Artifact) (ArtifactLease, *atomic.Int32) {
	t.Helper()
	retired := &atomic.Int32{}
	lease, err := NewArtifactLeaseWithRetirement(
		artifact,
		func(context.Context) error { return nil },
		func(context.Context) error {
			retired.Add(1)
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return lease, retired
}

type lateLeaseSource struct {
	once    sync.Once
	started chan struct{}
	release chan struct{}
	lease   ArtifactLease
}

func (source *lateLeaseSource) Acquire(context.Context) (ArtifactLease, *ArtifactSourceError) {
	source.once.Do(func() { close(source.started) })
	<-source.release
	return source.lease, nil
}
