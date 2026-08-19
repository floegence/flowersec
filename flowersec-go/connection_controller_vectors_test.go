package flowersec

import (
	"context"
	"errors"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v3/internal/artifactv3"
)

type controllerVectorObserved struct {
	FinalState              string
	PublicError             *string
	Disposition             *string
	Acquisitions            int
	ConnectAttempts         int
	TransportsCreated       int
	ReplacementAcquisitions int
	ReplacementQuotaUsed    int
	SpendCallbacks          int
	RetireCallbacks         int
	LeaseTerminalStates     []string
	RetryDelaysMS           []int
}

type controllerVectorLease struct {
	lease   ArtifactLease
	spent   atomic.Int32
	retired atomic.Int32
}

func runControllerVectorChangedPin(t *testing.T, scenario controllerVectorScenario) {
	primary := newControllerVectorLease(t, controllerPolicyArtifact(t,
		controllerPinPolicy("ERERERERERERERERERERERERERERERERERERERERERE")))
	replacement := newControllerVectorLease(t, controllerPolicyArtifact(t,
		controllerPinPolicy("gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIA")))
	source := &controllerTestSource{results: []controllerAcquireResult{{lease: primary.lease}, {lease: replacement.lease}}}
	controller := newControllerForTest(t, source, 0)
	session := newControllerTestSession(SessionClosed)
	var connects atomic.Int32
	var transports atomic.Int32
	controller.connectDetailed = func(ctx context.Context, claimed claimedArtifactLease, _ ConnectorOptions, allowed map[transportEndpointKey]struct{}) (Session, controllerConnectOutcome) {
		connects.Add(1)
		transports.Add(1)
		if connects.Load() == 1 {
			return nil, controllerPinTriggerOutcome(claimed.lease.artifact.value)
		}
		candidate := claimed.lease.artifact.value.Path.Candidates[0]
		if _, ok := allowed[endpointKey(claimed.lease.artifact.value.Path.Kind, candidate)]; !ok || len(allowed) != 1 {
			t.Fatalf("replacement allowed endpoints = %v, want changed pin only", allowed)
		}
		if err := claimed.lease.commitSpend(ctx); err != nil {
			t.Fatal(err)
		}
		return session, controllerConnectOutcome{spendStarted: claimed.spendStarted()}
	}

	controller.Start(context.Background())
	waitControllerSession(t, controller, session)
	assertControllerVectorObserved(t, scenario.Expected, controllerVectorObservation(
		controller, source.callCount(), int(connects.Load()), int(transports.Load()), 1,
		[]*controllerVectorLease{primary, replacement}, nil,
	))
	closeController(t, controller)
}

func runControllerVectorSamePin(t *testing.T, scenario controllerVectorScenario) {
	runControllerVectorRejectedReplacement(t, scenario,
		controllerPinPolicy("ERERERERERERERERERERERERERERERERERERERERERE"), false)
}

func runControllerVectorPinToCA(t *testing.T, scenario controllerVectorScenario) {
	if !scenario.Expected.NoModeDowngrade {
		t.Fatal("pin-to-CA vector must require no_mode_downgrade")
	}
	runControllerVectorRejectedReplacement(t, scenario, artifactv3.TLSPolicy{Mode: artifactv3.TLSModeCA}, false)
}

func runControllerVectorBrowserOpaque(t *testing.T, scenario controllerVectorScenario) {
	if scenario.Expected.TLSErrorClaimed == nil || *scenario.Expected.TLSErrorClaimed {
		t.Fatal("browser opaque vector must forbid claiming a TLS error")
	}
	runControllerVectorRejectedReplacement(t, scenario,
		controllerPinPolicy("ERERERERERERERERERERERERERERERERERERERERERE"), true)
}

func runControllerVectorRejectedReplacement(t *testing.T, scenario controllerVectorScenario, replacementPolicy artifactv3.TLSPolicy, opaque bool) {
	oldPolicy := controllerPinPolicy("ERERERERERERERERERERERERERERERERERERERERERE")
	primary := newControllerVectorLease(t, controllerPolicyArtifact(t, oldPolicy))
	replacement := newControllerVectorLease(t, controllerPolicyArtifact(t, replacementPolicy))
	source := &controllerTestSource{results: []controllerAcquireResult{{lease: primary.lease}, {lease: replacement.lease}}}
	controller := newControllerForTest(t, source, 0)
	var connects atomic.Int32
	var transports atomic.Int32
	controller.connectDetailed = func(_ context.Context, claimed claimedArtifactLease, _ ConnectorOptions, _ map[transportEndpointKey]struct{}) (Session, controllerConnectOutcome) {
		connects.Add(1)
		transports.Add(1)
		outcome := controllerPinTriggerOutcome(claimed.lease.artifact.value)
		if opaque {
			outcome.err = &ConnectError{code: ConnectConnectionFailed}
			outcome.securityFailure = false
			outcome.opaqueTrigger = true
		}
		return nil, outcome
	}

	controller.Start(context.Background())
	waitControllerState(t, controller, ConnectionFailed)
	assertControllerVectorObserved(t, scenario.Expected, controllerVectorObservation(
		controller, source.callCount(), int(connects.Load()), int(transports.Load()), 1,
		[]*controllerVectorLease{primary, replacement}, nil,
	))
	closeController(t, controller)
}

func runControllerVectorAllUnsupported(t *testing.T, scenario controllerVectorScenario) {
	if len(scenario.Input.CandidateResults) == 0 {
		t.Fatal("unsupported vector has no candidate results")
	}
	for _, result := range scenario.Input.CandidateResults {
		if result != "tls_unsupported" {
			t.Fatalf("unsupported inputs = %v", scenario.Input.CandidateResults)
		}
	}
	lease := newControllerVectorLease(t, mustParseInternalFixtureArtifact(t))
	source := &controllerTestSource{results: []controllerAcquireResult{{lease: lease.lease}}}
	controller := newControllerForTest(t, source, 0)
	var connects atomic.Int32
	controller.connectDetailed = func(context.Context, claimedArtifactLease, ConnectorOptions, map[transportEndpointKey]struct{}) (Session, controllerConnectOutcome) {
		connects.Add(1)
		return nil, controllerConnectOutcome{err: &ConnectError{code: ConnectTransportSecurityUnsupported}}
	}
	controller.Start(context.Background())
	waitControllerState(t, controller, ConnectionFailed)
	assertControllerVectorObserved(t, scenario.Expected, controllerVectorObservation(
		controller, source.callCount(), int(connects.Load()), 0, 0,
		[]*controllerVectorLease{lease}, nil,
	))
	closeController(t, controller)
}

func runControllerVectorReplacementExpired(t *testing.T, scenario controllerVectorScenario) {
	oldPolicy := controllerPinPolicy("ERERERERERERERERERERERERERERERERERERERERERE")
	newPolicy := controllerPinPolicy("gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIA")
	primary := newControllerVectorLease(t, controllerPolicyArtifact(t, oldPolicy))
	replacement := newControllerVectorLease(t, controllerPolicyArtifact(t, newPolicy))
	nextArtifact := controllerPolicyArtifact(t, oldPolicy)
	caCandidate := mustParseInternalFixtureArtifact(t).value.Path.Candidates[0]
	caCandidate.TLS = artifactv3.TLSPolicy{Mode: artifactv3.TLSModeCA}
	nextArtifact.value.Path.Candidates = append(nextArtifact.value.Path.Candidates, caCandidate)
	nextPrimary := newControllerVectorLease(t, nextArtifact)
	source := &controllerTestSource{results: []controllerAcquireResult{{lease: primary.lease}, {lease: replacement.lease}, {lease: nextPrimary.lease}}}
	controller := newControllerForTest(t, source, 0)
	session := newControllerTestSession(SessionClosed)
	var connects atomic.Int32
	var transports atomic.Int32
	controller.connectDetailed = func(ctx context.Context, claimed claimedArtifactLease, _ ConnectorOptions, allowed map[transportEndpointKey]struct{}) (Session, controllerConnectOutcome) {
		connects.Add(1)
		transports.Add(1)
		switch connects.Load() {
		case 1:
			return nil, controllerPinTriggerOutcome(claimed.lease.artifact.value)
		case 2:
			return nil, controllerConnectOutcome{err: &ConnectError{code: ConnectExpired}}
		default:
			artifact := claimed.lease.artifact.value
			oldKey := endpointKey(artifact.Path.Kind, artifact.Path.Candidates[0])
			caKey := endpointKey(artifact.Path.Kind, artifact.Path.Candidates[1])
			if _, oldAllowed := allowed[oldKey]; oldAllowed {
				t.Fatal("blocked old pin was eligible after replacement expiry")
			}
			if _, caAllowed := allowed[caKey]; !caAllowed || len(allowed) != 1 {
				t.Fatalf("next primary allowed endpoints = %v, want unrelated CA only", allowed)
			}
			if err := claimed.lease.commitSpend(ctx); err != nil {
				t.Fatal(err)
			}
			return session, controllerConnectOutcome{spendStarted: claimed.spendStarted()}
		}
	}

	controller.Start(context.Background())
	waitControllerState(t, controller, ConnectionWaiting)
	assertControllerVectorRetryDelays(t, scenario.Expected.RetryDelaysMS, 2)
	if !scenario.Input.WakeRetryManually || !controller.RetryNow() {
		t.Fatal("replacement-expiry vector did not wake the retry backoff")
	}
	waitControllerSession(t, controller, session)
	if !scenario.Expected.BlockedPolicyRemainsBlocked {
		t.Fatal("replacement-expiry vector must preserve the blocked policy")
	}
	assertControllerVectorObserved(t, scenario.Expected, controllerVectorObservation(
		controller, source.callCount(), int(connects.Load()), int(transports.Load()), 1,
		[]*controllerVectorLease{primary, replacement, nextPrimary}, scenario.Expected.RetryDelaysMS,
	))
	closeController(t, controller)
}

func runControllerVectorPostSpendRetry(t *testing.T, scenario controllerVectorScenario) {
	oldPolicy := controllerPinPolicy("ERERERERERERERERERERERERERERERERERERERERERE")
	newPolicy := controllerPinPolicy("gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIA")
	primary := newControllerVectorLease(t, controllerPolicyArtifact(t, oldPolicy))
	replacement := newControllerVectorLease(t, controllerPolicyArtifact(t, newPolicy))
	nextPrimary := newControllerVectorLease(t, controllerPolicyArtifact(t, newPolicy))
	source := &controllerTestSource{results: []controllerAcquireResult{{lease: primary.lease}, {lease: replacement.lease}, {lease: nextPrimary.lease}}}
	controller := newControllerForTest(t, source, 0)
	var connects atomic.Int32
	var transports atomic.Int32
	controller.connectDetailed = func(ctx context.Context, claimed claimedArtifactLease, _ ConnectorOptions, allowed map[transportEndpointKey]struct{}) (Session, controllerConnectOutcome) {
		connects.Add(1)
		transports.Add(1)
		switch connects.Load() {
		case 1:
			return nil, controllerPinTriggerOutcome(claimed.lease.artifact.value)
		case 2:
			if len(allowed) != 1 {
				t.Fatalf("replacement allowed endpoints = %v", allowed)
			}
			if err := claimed.lease.commitSpend(ctx); err != nil {
				t.Fatal(err)
			}
			return nil, controllerConnectOutcome{err: &ConnectError{code: ConnectConnectionFailed}, spendStarted: true}
		default:
			return nil, controllerPinTriggerOutcome(claimed.lease.artifact.value)
		}
	}

	controller.Start(context.Background())
	waitControllerState(t, controller, ConnectionWaiting)
	assertControllerVectorRetryDelays(t, scenario.Expected.RetryDelaysMS, 2)
	if !scenario.Input.WakeRetryManually || !controller.RetryNow() {
		t.Fatal("post-spend vector did not wake the retry backoff")
	}
	waitControllerState(t, controller, ConnectionFailed)
	assertControllerVectorObserved(t, scenario.Expected, controllerVectorObservation(
		controller, source.callCount(), int(connects.Load()), int(transports.Load()), 1,
		[]*controllerVectorLease{primary, replacement, nextPrimary}, scenario.Expected.RetryDelaysMS,
	))
	closeController(t, controller)
}

func runControllerVectorCancellationFirst(t *testing.T, scenario controllerVectorScenario) {
	tracked := newControllerVectorLease(t, controllerPolicyArtifact(t,
		controllerPinPolicy("ERERERERERERERERERERERERERERERERERERERERERE")))
	source := &lateLeaseSource{started: make(chan struct{}), release: make(chan struct{}), lease: tracked.lease}
	controller := newControllerForTest(t, source, 0)
	controller.Start(context.Background())
	<-source.started
	closed := make(chan error, 1)
	go func() { closed <- controller.Close(context.Background()) }()
	select {
	case err := <-closed:
		t.Fatalf("Close returned before cancellation-first cleanup: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(source.release)
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	assertControllerVectorObserved(t, scenario.Expected, controllerVectorObservation(
		controller, 1, 0, 0, 0, []*controllerVectorLease{tracked}, nil,
	))
}

func runControllerVectorDeliveryFirst(t *testing.T, scenario controllerVectorScenario) {
	tracked := newControllerVectorLease(t, controllerPolicyArtifact(t,
		controllerPinPolicy("ERERERERERERERERERERERERERERERERERERERERERE")))
	source := &controllerTestSource{results: []controllerAcquireResult{{lease: tracked.lease}}}
	controller := newControllerForTest(t, source, 0)
	connectStarted := make(chan struct{})
	var connects atomic.Int32
	controller.connect = func(ctx context.Context, _ ArtifactLease, _ ConnectorOptions) (Session, error) {
		connects.Add(1)
		close(connectStarted)
		<-ctx.Done()
		return nil, context.Cause(ctx)
	}
	controller.Start(context.Background())
	<-connectStarted
	closeController(t, controller)
	assertControllerVectorObserved(t, scenario.Expected, controllerVectorObservation(
		controller, source.callCount(), int(connects.Load()), int(connects.Load()), 0,
		[]*controllerVectorLease{tracked}, nil,
	))
}

func runControllerVectorAttemptExhaustion(t *testing.T, scenario controllerVectorScenario) {
	if scenario.Input.MaximumAttempts == 0 {
		t.Fatal("attempt-exhaustion vector has no maximum_attempts")
	}
	source := &controllerTestSource{results: []controllerAcquireResult{
		{failure: NewRetryableArtifactSourceError(errors.New("temporary-1"))},
		{failure: NewRetryableArtifactSourceError(errors.New("temporary-2"))},
	}}
	controller := newControllerForTest(t, source, scenario.Input.MaximumAttempts)
	controller.Start(context.Background())
	waitControllerState(t, controller, ConnectionWaiting)
	assertControllerVectorRetryDelays(t, scenario.Expected.RetryDelaysMS, 1)
	if !scenario.Input.WakeRetryManually || !controller.RetryNow() {
		t.Fatal("attempt-exhaustion vector did not wake the retry backoff")
	}
	waitControllerState(t, controller, ConnectionFailed)
	assertControllerVectorObserved(t, scenario.Expected, controllerVectorObservation(
		controller, source.callCount(), 0, 0, 0, nil, scenario.Expected.RetryDelaysMS,
	))
	closeController(t, controller)
}

func runControllerVectorRetryAfter(t *testing.T, scenario controllerVectorScenario) {
	assertControllerVectorClock(t, scenario)
	tracked := newControllerVectorLease(t, controllerPolicyArtifact(t,
		controllerPinPolicy("ERERERERERERERERERERERERERERERERERERERERERE")))
	retryAt := time.Now().Add(80 * time.Millisecond).UnixMilli()
	failure, err := NewRetryAfterArtifactSourceError(errors.New("rate limited"), retryAt)
	if err != nil {
		t.Fatal(err)
	}
	source := &controllerTestSource{results: []controllerAcquireResult{{failure: failure}, {lease: tracked.lease}}}
	controller := newControllerForTest(t, source, 0)
	session := newControllerTestSession(SessionClosed)
	var connects atomic.Int32
	controller.connectDetailed = func(ctx context.Context, claimed claimedArtifactLease, _ ConnectorOptions, _ map[transportEndpointKey]struct{}) (Session, controllerConnectOutcome) {
		connects.Add(1)
		if err := claimed.lease.commitSpend(ctx); err != nil {
			t.Fatal(err)
		}
		return session, controllerConnectOutcome{spendStarted: claimed.spendStarted()}
	}
	controller.Start(context.Background())
	waitControllerState(t, controller, ConnectionWaiting)
	wantRetryNow := scenario.Expected.RetryNowAllowedBeforeDeadline != nil && *scenario.Expected.RetryNowAllowedBeforeDeadline
	if got := controller.RetryNow(); got != wantRetryNow {
		t.Fatalf("RetryNow before wall deadline = %v, want %v", got, wantRetryNow)
	}
	waitControllerSession(t, controller, session)
	acquired := source.acquisitionTimes()
	if len(acquired) != 2 || acquired[1].UnixMilli() < retryAt {
		t.Fatalf("retry_after acquisitions = %v, deadline %v", acquired, retryAt)
	}
	assertControllerVectorObserved(t, scenario.Expected, controllerVectorObservation(
		controller, source.callCount(), int(connects.Load()), int(connects.Load()), 0,
		[]*controllerVectorLease{tracked}, scenario.Expected.RetryDelaysMS,
	))
	closeController(t, controller)
}

func runControllerVectorSecurityPriority(t *testing.T, scenario controllerVectorScenario) {
	if !scenario.Expected.OrderIndependent || len(scenario.Input.Permutations) == 0 {
		t.Fatal("security-priority vector must require non-empty order-independent permutations")
	}
	for _, permutation := range scenario.Input.Permutations {
		securityFailure := false
		for _, result := range permutation {
			securityFailure = securityFailure || result == "tls_failed"
		}
		if !securityFailure {
			t.Fatalf("permutation %v has no security failure", permutation)
		}
	}
	lease := newControllerVectorLease(t, controllerPolicyArtifact(t,
		controllerPinPolicy("ERERERERERERERERERERERERERERERERERERERERERE")))
	source := &controllerTestSource{results: []controllerAcquireResult{{lease: lease.lease}}}
	controller := newControllerForTest(t, source, 1)
	var connects atomic.Int32
	controller.connectDetailed = func(context.Context, claimedArtifactLease, ConnectorOptions, map[transportEndpointKey]struct{}) (Session, controllerConnectOutcome) {
		connects.Add(int32(len(scenario.Input.Permutations[0])))
		return nil, controllerConnectOutcome{err: &ConnectError{code: ConnectTransportSecurityFailed}}
	}
	controller.Start(context.Background())
	waitControllerState(t, controller, ConnectionFailed)
	assertControllerVectorObserved(t, scenario.Expected, controllerVectorObservation(
		controller, source.callCount(), int(connects.Load()), int(connects.Load()), 0,
		[]*controllerVectorLease{lease}, nil,
	))
	closeController(t, controller)
}

func runControllerVectorExtended(t *testing.T, scenario controllerVectorScenario) {
	switch scenario.Driver {
	case "failure-ordinal":
		runControllerVectorFailureOrdinal(t, scenario)
	case "expiry-boundary":
		runControllerVectorExpiryBoundary(t, scenario)
	case "cycle-reset":
		runControllerVectorCycleReset(t, scenario)
	case "retry-clock-boundary":
		runControllerVectorClockBoundary(t, scenario)
	case "candidate-security-aggregation":
		runControllerVectorCASecurity(t, scenario)
	case "multi-trigger-replacement":
		runControllerVectorMultiTrigger(t, scenario)
	case "retire-cleanup":
		runControllerVectorRetireCleanup(t, scenario)
	case "quota-preservation":
		runControllerVectorQuotaPreservation(t, scenario)
	case "attempt-saturation":
		runControllerVectorAttemptSaturation(t, scenario)
	case "capability-barrier":
		runControllerVectorCapabilityBarrier(t, scenario)
	case "admission-spend-boundary":
		runControllerVectorAdmissionBoundary(t, scenario)
	case "duplicate-lease-identity":
		runControllerVectorDuplicateLease(t, scenario)
	default:
		t.Fatalf("unsupported extended controller vector driver %q", scenario.Driver)
	}
}

func runControllerVectorFailureOrdinal(t *testing.T, scenario controllerVectorScenario) {
	lease := newControllerVectorLease(t, controllerPolicyArtifact(t,
		controllerPinPolicy("ERERERERERERERERERERERERERERERERERERERERERE")))
	source := &controllerTestSource{results: []controllerAcquireResult{{lease: lease.lease}}}
	controller := newControllerForTest(t, source, 0)
	controller.connectDetailed = func(context.Context, claimedArtifactLease, ConnectorOptions, map[transportEndpointKey]struct{}) (Session, controllerConnectOutcome) {
		return nil, controllerConnectOutcome{err: &ConnectError{code: ConnectConnectionFailed}}
	}
	controller.Start(context.Background())
	waitControllerState(t, controller, ConnectionWaiting)
	if scenario.Expected.FailureOrdinal != 1 {
		t.Fatalf("failure ordinal = %d, want one increment per failed attempt", scenario.Expected.FailureOrdinal)
	}
	assertControllerVectorRetryDelays(t, scenario.Expected.RetryDelaysMS, scenario.Expected.FailureOrdinal)
	assertControllerVectorObserved(t, scenario.Expected, controllerVectorObservation(
		controller, source.callCount(), len(scenario.Input.CandidateResults), len(scenario.Input.CandidateResults), 0,
		[]*controllerVectorLease{lease}, scenario.Expected.RetryDelaysMS,
	))
	closeController(t, controller)
}

func runControllerVectorExpiryBoundary(t *testing.T, scenario controllerVectorScenario) {
	lease := newControllerVectorLease(t, controllerPolicyArtifact(t,
		controllerPinPolicy("ERERERERERERERERERERERERERERERERERERERERERE")))
	source := &controllerTestSource{results: []controllerAcquireResult{{lease: lease.lease}}}
	controller := newControllerForTest(t, source, 0)
	var candidateAttempts atomic.Int32
	controller.connectDetailed = func(ctx context.Context, claimed claimedArtifactLease, _ ConnectorOptions, _ map[transportEndpointKey]struct{}) (Session, controllerConnectOutcome) {
		switch scenario.Input.ExpiryBoundary {
		case "before_race":
		case "race_end", "before_spend":
			candidateAttempts.Add(1)
		case "after_spend":
			candidateAttempts.Add(1)
			if err := claimed.lease.commitSpend(ctx); err != nil {
				t.Fatal(err)
			}
		default:
			t.Fatalf("unknown expiry boundary %q", scenario.Input.ExpiryBoundary)
		}
		return nil, controllerConnectOutcome{err: &ConnectError{code: ConnectExpired}, spendStarted: claimed.spendStarted()}
	}
	controller.Start(context.Background())
	waitControllerState(t, controller, ConnectionWaiting)
	if scenario.Expected.CredentialBytesWritten != 0 {
		t.Fatal("expiry vector must prohibit credential bytes after the observed boundary")
	}
	assertControllerVectorRetryDelays(t, scenario.Expected.RetryDelaysMS, 1)
	assertControllerVectorObserved(t, scenario.Expected, controllerVectorObservation(
		controller, source.callCount(), int(candidateAttempts.Load()), int(candidateAttempts.Load()), 0,
		[]*controllerVectorLease{lease}, scenario.Expected.RetryDelaysMS,
	))
	closeController(t, controller)
}

func runControllerVectorCycleReset(t *testing.T, scenario controllerVectorScenario) {
	leases := []*controllerVectorLease{
		newControllerVectorLease(t, controllerPolicyArtifact(t, controllerPinPolicy("ERERERERERERERERERERERERERERERERERERERERERE"))),
		newControllerVectorLease(t, controllerPolicyArtifact(t, controllerPinPolicy("ERERERERERERERERERERERERERERERERERERERERERE"))),
		newControllerVectorLease(t, controllerPolicyArtifact(t, controllerPinPolicy("ERERERERERERERERERERERERERERERERERERERERERE"))),
	}
	source := &controllerTestSource{results: []controllerAcquireResult{{lease: leases[0].lease}, {lease: leases[1].lease}, {lease: leases[2].lease}}}
	controller := newControllerForTest(t, source, 0)
	firstSession := newControllerTestSession(SessionClosed)
	secondSession := newControllerTestSession(SessionClosed)
	var connects atomic.Int32
	controller.connectDetailed = func(ctx context.Context, claimed claimedArtifactLease, _ ConnectorOptions, _ map[transportEndpointKey]struct{}) (Session, controllerConnectOutcome) {
		switch connects.Add(1) {
		case 1:
			return nil, controllerConnectOutcome{err: &ConnectError{code: ConnectConnectionFailed}}
		case 2:
			if err := claimed.lease.commitSpend(ctx); err != nil {
				t.Fatal(err)
			}
			return firstSession, controllerConnectOutcome{spendStarted: true}
		default:
			if err := claimed.lease.commitSpend(ctx); err != nil {
				t.Fatal(err)
			}
			return secondSession, controllerConnectOutcome{spendStarted: true}
		}
	}
	controller.Start(context.Background())
	waitControllerState(t, controller, ConnectionWaiting)
	if !scenario.Input.WakeRetryManually || !controller.RetryNow() {
		t.Fatal("initial retry was not wakeable")
	}
	waitControllerSession(t, controller, firstSession)
	firstSession.terminate()
	waitControllerState(t, controller, ConnectionWaiting)
	if !controller.RetryNow() {
		t.Fatal("post-session retry was not reset to ordinal one")
	}
	waitControllerSession(t, controller, secondSession)
	assertControllerVectorRetryDelays(t, scenario.Expected.RetryDelaysMS, 1, 1)
	assertControllerVectorObserved(t, scenario.Expected, controllerVectorObservation(
		controller, source.callCount(), int(connects.Load()), int(connects.Load()), 0, leases, scenario.Expected.RetryDelaysMS,
	))
	closeController(t, controller)
}

func runControllerVectorClockBoundary(t *testing.T, scenario controllerVectorScenario) {
	if scenario.Expected.TimerSaturated {
		if scenario.Input.MonotonicStartMS != int64(maxSafeControllerInteger-1) ||
			scenario.Expected.MonotonicEndMS != int64(maxSafeControllerInteger) ||
			!scenario.Expected.CounterSaturated && scenario.Expected.RetryDelaysMS[0] != 1 {
			t.Fatalf("invalid timer saturation vector: %+v", scenario)
		}
		return
	}
	assertControllerVectorClock(t, scenario)
	for _, delay := range scenario.Expected.RetryDelaysMS {
		if delay > scenario.Expected.MaximumWallRereadMS && scenario.Expected.MaximumWallRereadMS != 0 {
			t.Fatalf("wall reread delay %d exceeds %d", delay, scenario.Expected.MaximumWallRereadMS)
		}
		if delay > 1000 {
			t.Fatalf("wall-clock reread delay = %dms, want <=1000ms", delay)
		}
	}
}

func runControllerVectorCASecurity(t *testing.T, scenario controllerVectorScenario) {
	if scenario.Expected.TLSErrorClaimed == nil || !*scenario.Expected.TLSErrorClaimed {
		t.Fatal("CA verification failure must remain a TLS error")
	}
	lease := newControllerVectorLease(t, mustParseInternalFixtureArtifact(t))
	source := &controllerTestSource{results: []controllerAcquireResult{{lease: lease.lease}}}
	controller := newControllerForTest(t, source, 1)
	controller.connectDetailed = func(context.Context, claimedArtifactLease, ConnectorOptions, map[transportEndpointKey]struct{}) (Session, controllerConnectOutcome) {
		return nil, controllerConnectOutcome{err: &ConnectError{code: ConnectTransportSecurityFailed}, securityFailure: true}
	}
	controller.Start(context.Background())
	waitControllerState(t, controller, ConnectionFailed)
	assertControllerVectorObserved(t, scenario.Expected, controllerVectorObservation(
		controller, source.callCount(), len(scenario.Input.CandidateResults), len(scenario.Input.CandidateResults), 0,
		[]*controllerVectorLease{lease}, nil,
	))
	closeController(t, controller)
}

func runControllerVectorMultiTrigger(t *testing.T, scenario controllerVectorScenario) {
	base := mustParseInternalFixtureArtifact(t)
	primaryValue := *base.value
	primaryValue.Path.Candidates = []artifactv3.Candidate{base.value.Path.Candidates[1], base.value.Path.Candidates[3]}
	primary := newControllerVectorLease(t, Artifact{value: &primaryValue})
	replacementValue := primaryValue
	replacementValue.Path.Candidates = append([]artifactv3.Candidate(nil), primaryValue.Path.Candidates...)
	replacement := newControllerVectorLease(t, Artifact{value: &replacementValue})
	source := &controllerTestSource{results: []controllerAcquireResult{{lease: primary.lease}, {lease: replacement.lease}}}
	controller := newControllerForTest(t, source, 0)
	controller.connectDetailed = func(_ context.Context, claimed claimedArtifactLease, _ ConnectorOptions, _ map[transportEndpointKey]struct{}) (Session, controllerConnectOutcome) {
		triggered := make(map[transportEndpointKey]artifactv3.Candidate)
		failed := make(map[transportEndpointKey]struct{})
		for _, candidate := range claimed.lease.artifact.value.Path.Candidates {
			key := endpointKey(claimed.lease.artifact.value.Path.Kind, candidate)
			triggered[key] = candidate
			failed[key] = struct{}{}
		}
		return nil, controllerConnectOutcome{
			err: &ConnectError{code: ConnectTransportSecurityFailed}, securityFailure: true,
			triggerCandidates: triggered, failedEndpoints: failed,
		}
	}
	controller.Start(context.Background())
	waitControllerState(t, controller, ConnectionFailed)
	if !scenario.Expected.NoModeDowngrade {
		t.Fatal("multi-trigger vector must forbid mode downgrade")
	}
	assertControllerVectorObserved(t, scenario.Expected, controllerVectorObservation(
		controller, source.callCount(), len(scenario.Input.CandidateResults), len(scenario.Input.CandidateResults), 1,
		[]*controllerVectorLease{primary, replacement}, nil,
	))
	closeController(t, controller)
}

func runControllerVectorRetireCleanup(t *testing.T, scenario controllerVectorScenario) {
	first := &controllerVectorLease{}
	firstLease, err := NewArtifactLeaseWithRetirement(
		controllerPolicyArtifact(t, controllerPinPolicy("ERERERERERERERERERERERERERERERERERERERERERE")),
		func(context.Context) error { first.spent.Add(1); return nil },
		func(context.Context) error { first.retired.Add(1); return errors.New("cleanup failed") },
	)
	if err != nil {
		t.Fatal(err)
	}
	first.lease = firstLease
	second := newControllerVectorLease(t, controllerPolicyArtifact(t,
		controllerPinPolicy("ERERERERERERERERERERERERERERERERERERERERERE")))
	source := &controllerTestSource{results: []controllerAcquireResult{{lease: first.lease}, {lease: second.lease}}}
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
	if !scenario.Expected.CleanupErrorIgnored || !controller.RetryNow() {
		t.Fatal("cleanup failure prevented a fresh retry")
	}
	waitControllerSession(t, controller, session)
	assertControllerVectorRetryDelays(t, scenario.Expected.RetryDelaysMS, 1)
	assertControllerVectorObserved(t, scenario.Expected, controllerVectorObservation(
		controller, source.callCount(), int(connects.Load()), int(connects.Load()), 0,
		[]*controllerVectorLease{first, second}, scenario.Expected.RetryDelaysMS,
	))
	closeController(t, controller)
}

func runControllerVectorQuotaPreservation(t *testing.T, scenario controllerVectorScenario) {
	oldPolicy := controllerPinPolicy("ERERERERERERERERERERERERERERERERERERERERERE")
	newPolicy := controllerPinPolicy("gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIA")
	leases := []*controllerVectorLease{
		newControllerVectorLease(t, controllerPolicyArtifact(t, oldPolicy)),
		newControllerVectorLease(t, controllerPolicyArtifact(t, oldPolicy)),
		newControllerVectorLease(t, controllerPolicyArtifact(t, newPolicy)),
	}
	source := &controllerTestSource{results: []controllerAcquireResult{{lease: leases[0].lease}, {lease: leases[1].lease}, {lease: leases[2].lease}}}
	controller := newControllerForTest(t, source, 0)
	session := newControllerTestSession(SessionClosed)
	var connects atomic.Int32
	controller.connectDetailed = func(ctx context.Context, claimed claimedArtifactLease, _ ConnectorOptions, _ map[transportEndpointKey]struct{}) (Session, controllerConnectOutcome) {
		switch connects.Add(1) {
		case 1:
			return nil, controllerConnectOutcome{err: &ConnectError{code: ConnectConnectionFailed}}
		case 2:
			return nil, controllerPinTriggerOutcome(claimed.lease.artifact.value)
		default:
			if err := claimed.lease.commitSpend(ctx); err != nil {
				t.Fatal(err)
			}
			return session, controllerConnectOutcome{spendStarted: true}
		}
	}
	controller.Start(context.Background())
	waitControllerState(t, controller, ConnectionWaiting)
	if !controller.RetryNow() {
		t.Fatal("ordinary retry was not wakeable")
	}
	waitControllerSession(t, controller, session)
	assertControllerVectorRetryDelays(t, scenario.Expected.RetryDelaysMS, 1)
	assertControllerVectorObserved(t, scenario.Expected, controllerVectorObservation(
		controller, source.callCount(), int(connects.Load()), int(connects.Load()), 1, leases, scenario.Expected.RetryDelaysMS,
	))
	closeController(t, controller)
}

func runControllerVectorAttemptSaturation(t *testing.T, scenario controllerVectorScenario) {
	if !scenario.Expected.CounterSaturated || scenario.Expected.Attempt != maxSafeControllerInteger ||
		scenario.Input.MaximumAttempts != maxSafeControllerInteger || scenario.Input.InitialAttempt != maxSafeControllerInteger ||
		saturatingControllerIncrement(scenario.Input.InitialAttempt) != scenario.Expected.Attempt {
		t.Fatalf("attempt saturation contract mismatch: input=%d expected=%+v", scenario.Input.MaximumAttempts, scenario.Expected)
	}
}

func runControllerVectorCapabilityBarrier(t *testing.T, scenario controllerVectorScenario) {
	if !scenario.Expected.CapabilityRechecked {
		t.Fatal("capability vector must require the pre-TLS invalidation barrier")
	}
	runControllerVectorAllUnsupported(t, scenario)
}

func runControllerVectorAdmissionBoundary(t *testing.T, scenario controllerVectorScenario) {
	oldPolicy := controllerPinPolicy("ERERERERERERERERERERERERERERERERERERERERERE")
	newPolicy := controllerPinPolicy("gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIA")
	leasses := []*controllerVectorLease{newControllerVectorLease(t, controllerPolicyArtifact(t, oldPolicy))}
	results := []controllerAcquireResult{{lease: leasses[0].lease}}
	if scenario.Input.Phase == "replacement" {
		leasses = append(leasses, newControllerVectorLease(t, controllerPolicyArtifact(t, newPolicy)))
		results = append(results, controllerAcquireResult{lease: leasses[1].lease})
	}
	source := &controllerTestSource{results: results}
	controller := newControllerForTest(t, source, 0)
	var connects atomic.Int32
	controller.connectDetailed = func(ctx context.Context, claimed claimedArtifactLease, _ ConnectorOptions, _ map[transportEndpointKey]struct{}) (Session, controllerConnectOutcome) {
		if scenario.Input.Phase == "replacement" && connects.Add(1) == 1 {
			return nil, controllerPinTriggerOutcome(claimed.lease.artifact.value)
		}
		if scenario.Input.Phase != "replacement" {
			connects.Add(1)
		}
		if err := claimed.lease.commitSpend(ctx); err != nil {
			t.Fatal(err)
		}
		outcome := controllerConnectOutcome{err: &ConnectError{code: ConnectConnectionFailed}, spendStarted: true}
		if scenario.Input.AdmissionResult == "fsa_reject" {
			outcome.retryDisposition = terminalDisposition()
			outcome.hasDisposition = true
		} else {
			outcome.retryDisposition = retryableDisposition()
			outcome.hasDisposition = true
		}
		return nil, outcome
	}
	controller.Start(context.Background())
	if scenario.Expected.FinalState == string(ConnectionFailed) {
		waitControllerState(t, controller, ConnectionFailed)
	} else {
		waitControllerState(t, controller, ConnectionWaiting)
		assertControllerVectorRetryDelays(t, scenario.Expected.RetryDelaysMS, uint64(scenario.Expected.ConnectAttempts))
	}
	assertControllerVectorObserved(t, scenario.Expected, controllerVectorObservation(
		controller, source.callCount(), int(connects.Load()), int(connects.Load()), scenario.Expected.ReplacementAcquisitions,
		leasses, scenario.Expected.RetryDelaysMS,
	))
	closeController(t, controller)
}

func runControllerVectorDuplicateLease(t *testing.T, scenario controllerVectorScenario) {
	tracked := newControllerVectorLease(t, controllerPolicyArtifact(t,
		controllerPinPolicy("ERERERERERERERERERERERERERERERERERERERERERE")))
	source := &controllerTestSource{results: []controllerAcquireResult{{lease: tracked.lease}, {lease: tracked.lease}}}
	controller := newControllerForTest(t, source, 0)
	var connects atomic.Int32
	controller.connectDetailed = func(ctx context.Context, claimed claimedArtifactLease, _ ConnectorOptions, _ map[transportEndpointKey]struct{}) (Session, controllerConnectOutcome) {
		connects.Add(1)
		if scenario.Input.RepeatedTerminal == "consumed" {
			if err := claimed.lease.commitSpend(ctx); err != nil {
				t.Fatal(err)
			}
		}
		return nil, controllerConnectOutcome{err: &ConnectError{code: ConnectConnectionFailed}, spendStarted: claimed.spendStarted()}
	}
	controller.Start(context.Background())
	waitControllerState(t, controller, ConnectionWaiting)
	if !controller.RetryNow() {
		t.Fatal("duplicate-lease vector could not wake initial retry")
	}
	waitControllerState(t, controller, ConnectionFailed)
	assertControllerVectorRetryDelays(t, scenario.Expected.RetryDelaysMS, 1)
	assertControllerVectorObserved(t, scenario.Expected, controllerVectorObservation(
		controller, source.callCount(), int(connects.Load()), int(connects.Load()), 0,
		[]*controllerVectorLease{tracked}, scenario.Expected.RetryDelaysMS,
	))
	closeController(t, controller)
}

func newControllerVectorLease(t *testing.T, artifact Artifact) *controllerVectorLease {
	t.Helper()
	tracked := &controllerVectorLease{}
	lease, err := NewArtifactLeaseWithRetirement(
		artifact,
		func(context.Context) error { tracked.spent.Add(1); return nil },
		func(context.Context) error { tracked.retired.Add(1); return nil },
	)
	if err != nil {
		t.Fatal(err)
	}
	tracked.lease = lease
	return tracked
}

func controllerVectorObservation(
	controller *ConnectionController,
	acquisitions, connects, transports, replacementAcquisitions int,
	leases []*controllerVectorLease,
	retryDelays []int,
) controllerVectorObserved {
	snapshot := controller.Snapshot()
	observed := controllerVectorObserved{
		FinalState: string(snapshot.State), Acquisitions: acquisitions, ConnectAttempts: connects,
		TransportsCreated: transports, ReplacementAcquisitions: replacementAcquisitions,
		ReplacementQuotaUsed: replacementAcquisitions, RetryDelaysMS: append([]int(nil), retryDelays...),
	}
	if snapshot.Failure != nil {
		code := string(connectErrorCode(snapshot.Failure.Error))
		disposition := string(snapshot.Failure.Disposition.Kind)
		observed.PublicError = &code
		observed.Disposition = &disposition
	}
	for _, tracked := range leases {
		observed.SpendCallbacks += int(tracked.spent.Load())
		observed.RetireCallbacks += int(tracked.retired.Load())
		observed.LeaseTerminalStates = append(observed.LeaseTerminalStates, controllerVectorLeaseState(tracked.lease))
	}
	if observed.LeaseTerminalStates == nil {
		observed.LeaseTerminalStates = []string{}
	}
	if observed.RetryDelaysMS == nil {
		observed.RetryDelaysMS = []int{}
	}
	return observed
}

func controllerVectorLeaseState(lease ArtifactLease) string {
	lease.state.mu.Lock()
	defer lease.state.mu.Unlock()
	switch lease.state.status {
	case artifactLeaseConsumed:
		return "consumed"
	case artifactLeaseRetired:
		return "retired"
	case artifactLeaseClaimed:
		return "claimed"
	case artifactLeaseSpending:
		return "spending"
	default:
		return "idle"
	}
}

func assertControllerVectorObserved(t *testing.T, expected controllerVectorExpected, observed controllerVectorObserved) {
	t.Helper()
	want := controllerVectorObserved{
		FinalState: expected.FinalState, PublicError: expected.PublicError, Disposition: expected.Disposition,
		Acquisitions: expected.Acquisitions, ConnectAttempts: expected.ConnectAttempts,
		TransportsCreated: expected.TransportsCreated, ReplacementAcquisitions: expected.ReplacementAcquisitions,
		ReplacementQuotaUsed: expected.ReplacementQuotaUsed, SpendCallbacks: expected.SpendCallbacks,
		RetireCallbacks: expected.RetireCallbacks, LeaseTerminalStates: expected.LeaseTerminalStates,
		RetryDelaysMS: expected.RetryDelaysMS,
	}
	if !reflect.DeepEqual(observed, want) {
		t.Fatalf("controller vector observation = %+v, want %+v", observed, want)
	}
}

func assertControllerVectorRetryDelays(t *testing.T, expected []int, failureOrdinals ...uint64) {
	t.Helper()
	got := make([]int, 0, len(failureOrdinals))
	for _, ordinal := range failureOrdinals {
		got = append(got, int(connectionControllerBackoff(ordinal)/time.Millisecond))
	}
	if !reflect.DeepEqual(got, expected) {
		t.Fatalf("retry delays = %v, want %v", got, expected)
	}
}

func assertControllerVectorClock(t *testing.T, scenario controllerVectorScenario) {
	t.Helper()
	if scenario.Input.FailureOrdinal != 0 &&
		int64(connectionControllerBackoff(scenario.Input.FailureOrdinal)/time.Millisecond) != scenario.Input.BackoffMS {
		t.Fatalf("clock backoff/failure ordinal = %d/%d", scenario.Input.BackoffMS, scenario.Input.FailureOrdinal)
	}
	wall := scenario.Input.WallStartMS
	monotonic := scenario.Input.MonotonicStartMS
	monotonicDeadline := monotonic + scenario.Input.BackoffMS
	observedSleeps := make([]int, 0, len(scenario.Input.WallAdvancesMS))
	for index, wallAdvance := range scenario.Input.WallAdvancesMS {
		remaining := scenario.Input.RetryAfterUnixMS - wall
		if remaining > int64(time.Second/time.Millisecond) {
			remaining = int64(time.Second / time.Millisecond)
		}
		if monotonicRemaining := monotonicDeadline - monotonic; monotonicRemaining > 0 && monotonicRemaining < remaining {
			remaining = monotonicRemaining
		}
		observedSleeps = append(observedSleeps, int(remaining))
		wall += wallAdvance
		if index < len(scenario.Input.MonotonicAdvancesMS) {
			monotonic += scenario.Input.MonotonicAdvancesMS[index]
		}
	}
	if !reflect.DeepEqual(observedSleeps, scenario.Expected.RetryDelaysMS) ||
		wall != scenario.Expected.WallEndMS || monotonic != scenario.Expected.MonotonicEndMS {
		t.Fatalf("clock result sleeps/wall/monotonic = %v/%d/%d, want %v/%d/%d",
			observedSleeps, wall, monotonic, scenario.Expected.RetryDelaysMS,
			scenario.Expected.WallEndMS, scenario.Expected.MonotonicEndMS)
	}
}
