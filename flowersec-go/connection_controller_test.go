package flowersec

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"os"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/defaults"
)

type controllerVectorFile struct {
	Version           int      `json:"version"`
	States            []string `json:"states"`
	RetryDispositions []string `json:"retry_dispositions"`
	Defaults          struct {
		InitialDelayMS int     `json:"initial_delay_ms"`
		MaxDelayMS     int     `json:"max_delay_ms"`
		Factor         uint64  `json:"factor"`
		JitterRatio    float64 `json:"jitter_ratio"`
		AttemptLimit   *uint64 `json:"attempt_limit"`
	} `json:"defaults"`
	BackoffVectors []struct {
		ConsecutiveFailure uint64 `json:"consecutive_failure"`
		DelayMS            int    `json:"delay_ms"`
	} `json:"backoff_vectors"`
	Scenarios []struct {
		Name                 string   `json:"name"`
		Events               []string `json:"events"`
		States               []string `json:"states"`
		Sessions             []string `json:"sessions"`
		Replay               []string `json:"replay"`
		ClockStartUnixMS     *int64   `json:"clock_start_unix_ms"`
		RetryAtUnixMS        *int64   `json:"retry_at_unix_ms"`
		ArtifactAcquisitions *uint64  `json:"artifact_acquisitions"`
		SchedulerCount       *uint64  `json:"scheduler_count"`
		MaxInFlightAttempts  *uint64  `json:"max_in_flight_attempts"`
		RetryNowResults      []bool   `json:"retry_now_results"`
		CloseCalls           *uint64  `json:"close_calls"`
		CleanupCalls         *uint64  `json:"cleanup_calls"`
		Policy               *struct {
			MaxAttempts uint64 `json:"max_attempts"`
		} `json:"policy"`
	} `json:"scenarios"`
	Invariants struct {
		OneShotArtifactController         string   `json:"one_shot_artifact_controller"`
		FreshArtifactPerAttempt           bool     `json:"fresh_artifact_per_attempt"`
		SingleScheduler                   bool     `json:"single_scheduler"`
		SingleInFlightAttempt             bool     `json:"single_in_flight_attempt"`
		StartIdempotent                   bool     `json:"start_idempotent"`
		CloseIdempotent                   bool     `json:"close_idempotent"`
		RetryNowOutsideWaiting            bool     `json:"retry_now_outside_waiting"`
		RetryAfterBypass                  bool     `json:"retry_after_bypass"`
		SubordinateCloseFailurePropagates bool     `json:"subordinate_close_failure_propagates"`
		PublicRetryConfiguration          []string `json:"public_retry_configuration"`
		OldStreamMigration                bool     `json:"old_stream_migration"`
		RPCReplay                         bool     `json:"rpc_replay"`
		WriteReplay                       bool     `json:"write_replay"`
		CrossSessionExactlyOnce           bool     `json:"cross_session_exactly_once"`
	} `json:"invariants"`
}

func TestConnectionControllerSharedLifecycleVectors(t *testing.T) {
	fixture := loadControllerVectors(t)
	if fixture.Version != 2 {
		t.Fatalf("vector version = %d, want 2", fixture.Version)
	}
	if got, want := fixture.States, []string{"idle", "connecting", "connected", "waiting", "failed", "closed"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("states = %v, want %v", got, want)
	}
	if got, want := fixture.RetryDispositions, []string{"terminal", "retryable", "retry_after"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("retry dispositions = %v, want %v", got, want)
	}
	if fixture.Invariants.OneShotArtifactController != "forbidden" ||
		!fixture.Invariants.FreshArtifactPerAttempt || !fixture.Invariants.SingleScheduler ||
		!fixture.Invariants.SingleInFlightAttempt || !fixture.Invariants.StartIdempotent ||
		!fixture.Invariants.CloseIdempotent || fixture.Invariants.RetryNowOutsideWaiting ||
		fixture.Invariants.RetryAfterBypass || fixture.Invariants.SubordinateCloseFailurePropagates ||
		!reflect.DeepEqual(fixture.Invariants.PublicRetryConfiguration, []string{"maximum_attempts"}) ||
		fixture.Invariants.OldStreamMigration || fixture.Invariants.RPCReplay ||
		fixture.Invariants.WriteReplay || fixture.Invariants.CrossSessionExactlyOnce {
		t.Fatalf("invalid controller invariants: %+v", fixture.Invariants)
	}

	if defaults.ConnectionControllerInitialDelay != time.Duration(fixture.Defaults.InitialDelayMS)*time.Millisecond ||
		defaults.ConnectionControllerMaxDelay != time.Duration(fixture.Defaults.MaxDelayMS)*time.Millisecond ||
		defaults.ConnectionControllerBackoffFactor != fixture.Defaults.Factor ||
		fixture.Defaults.JitterRatio != 0 || fixture.Defaults.AttemptLimit != nil {
		t.Fatalf("controller defaults do not match vectors: %+v", fixture.Defaults)
	}
	for _, vector := range fixture.BackoffVectors {
		if got, want := connectionControllerBackoff(vector.ConsecutiveFailure), time.Duration(vector.DelayMS)*time.Millisecond; got != want {
			t.Fatalf("backoff(%d) = %v, want %v", vector.ConsecutiveFailure, got, want)
		}
	}

	scenarios := map[string]func(*testing.T){
		"connect_and_replace_after_termination":   testControllerReplaceAfterTermination,
		"retry_now_wakes_existing_wait":           testControllerRetryNow,
		"repeated_start_is_idempotent":            testControllerRepeatedStart,
		"start_after_close_stays_closed":          testControllerStartAfterClose,
		"retry_now_outside_waiting_returns_false": testControllerRetryNowOutsideWaiting,
		"retry_after_is_authoritative":            testControllerRetryAfter,
		"terminal_failure":                        testControllerTerminalFailure,
		"explicit_attempt_exhaustion":             testControllerAttemptExhaustion,
		"close_cancels_single_attempt":            testControllerCloseCancelsAcquire,
		"repeated_close_is_idempotent":            testControllerRepeatedClose,
		"close_waits_for_owned_cleanup":           testControllerCloseWaitsForOwnedCleanup,
		"subordinate_close_failure_is_ignored":    testControllerSubordinateCloseFailure,
	}
	if len(fixture.Scenarios) != len(scenarios) {
		t.Fatalf("scenario count = %d, want %d", len(fixture.Scenarios), len(scenarios))
	}
	for _, vector := range fixture.Scenarios {
		validateControllerScenarioVector(t, vector.Name, vector.Events, vector.States, vector.Sessions, vector.Replay,
			vector.ClockStartUnixMS, vector.RetryAtUnixMS, vector.ArtifactAcquisitions,
			vector.SchedulerCount, vector.MaxInFlightAttempts, vector.Policy)
		run, ok := scenarios[vector.Name]
		if !ok {
			t.Fatalf("shared scenario %q has no Go executor", vector.Name)
		}
		t.Run(vector.Name, run)
		delete(scenarios, vector.Name)
	}
	if len(scenarios) != 0 {
		t.Fatalf("Go scenario executors missing from shared vectors: %v", reflect.ValueOf(scenarios).MapKeys())
	}
}

func validateControllerScenarioVector(t *testing.T, name string, events, states, sessions, replay []string,
	clockStart, retryAt *int64, acquisitions, schedulers, inFlight *uint64, policy *struct {
		MaxAttempts uint64 `json:"max_attempts"`
	}) {
	t.Helper()
	expectedEvents := map[string][]string{
		"connect_and_replace_after_termination":   {"start", "acquire:artifact-1", "connect:session-1", "terminate:retryable", "timer", "acquire:artifact-2", "connect:session-2"},
		"retry_now_wakes_existing_wait":           {"start", "acquire:error:retryable", "retry_now", "acquire:artifact-1", "connect:session-1"},
		"repeated_start_is_idempotent":            {"start", "start", "acquire:pending"},
		"start_after_close_stays_closed":          {"close", "start"},
		"retry_now_outside_waiting_returns_false": {"retry_now", "start", "acquire:pending", "retry_now", "close", "retry_now"},
		"retry_after_is_authoritative":            {"start", "acquire:error:retry_after:1004000", "retry_now", "timer:1004000", "acquire:artifact-1", "connect:session-1"},
		"terminal_failure":                        {"start", "acquire:error:terminal"},
		"explicit_attempt_exhaustion":             {"start", "acquire:error:retryable", "timer", "acquire:error:retryable"},
		"close_cancels_single_attempt":            {"start", "acquire:pending", "close"},
		"repeated_close_is_idempotent":            {"start", "acquire:pending", "close", "close"},
		"close_waits_for_owned_cleanup":           {"start", "acquire:artifact-1", "connect:pending", "close", "connect:session-1", "close:complete"},
		"subordinate_close_failure_is_ignored":    {"start", "acquire:artifact-1", "connect:session-1", "close", "session_close:error", "close:complete"},
	}
	if !reflect.DeepEqual(events, expectedEvents[name]) || len(states) < 2 {
		t.Fatalf("scenario %q events/states are incomplete: %v / %v", name, events, states)
	}
	switch name {
	case "connect_and_replace_after_termination":
		if !reflect.DeepEqual(sessions, []string{"session-1", "session-2"}) || len(replay) != 0 {
			t.Fatalf("replacement scenario sessions/replay = %v/%v", sessions, replay)
		}
	case "retry_after_is_authoritative":
		if clockStart == nil || retryAt == nil || *clockStart != 1_000_000 || *retryAt != 1_004_000 {
			t.Fatalf("retry_after clock = %v/%v", clockStart, retryAt)
		}
	case "terminal_failure":
		if acquisitions == nil || *acquisitions != 1 {
			t.Fatalf("terminal acquisitions = %v", acquisitions)
		}
	case "explicit_attempt_exhaustion":
		if acquisitions == nil || *acquisitions != 2 || policy == nil || policy.MaxAttempts != 2 {
			t.Fatalf("exhaustion acquisitions/policy = %v/%v", acquisitions, policy)
		}
	case "retry_now_wakes_existing_wait", "repeated_start_is_idempotent":
		if schedulers == nil || *schedulers != 1 || inFlight == nil || *inFlight != 1 {
			t.Fatalf("retry_now scheduler/in-flight = %v/%v", schedulers, inFlight)
		}
	case "close_cancels_single_attempt":
		if inFlight == nil || *inFlight != 1 {
			t.Fatalf("close max in-flight = %v", inFlight)
		}
	case "start_after_close_stays_closed", "retry_now_outside_waiting_returns_false",
		"repeated_close_is_idempotent", "close_waits_for_owned_cleanup",
		"subordinate_close_failure_is_ignored":
	default:
		t.Fatalf("unknown controller scenario %q", name)
	}
}

func testControllerReplaceAfterTermination(t *testing.T) {
	firstLease, secondLease := controllerTestLeases(t)
	source := &controllerTestSource{results: []controllerAcquireResult{{lease: firstLease}, {lease: secondLease}}}
	controller := newControllerForTest(t, source, 0)
	first := newControllerTestSession(SessionClosed)
	second := newControllerTestSession(SessionClosed)
	var connectMu sync.Mutex
	var connected []ArtifactLease
	controller.connect = func(_ context.Context, lease ArtifactLease, _ ConnectorOptions) (Session, error) {
		connectMu.Lock()
		defer connectMu.Unlock()
		connected = append(connected, lease)
		if len(connected) == 1 {
			return first, nil
		}
		return second, nil
	}
	startController(t, controller)
	waitControllerSession(t, controller, first)

	oldRPC := first.RPC()
	oldStream, err := first.OpenStream(context.Background(), "old", StreamMetadata{})
	if err != nil {
		t.Fatal(err)
	}
	if err := oldRPC.Notify(context.Background(), 1, "before termination"); err != nil {
		t.Fatal(err)
	}
	if _, err := oldStream.Write([]byte("before termination")); err != nil {
		t.Fatal(err)
	}
	first.terminate()
	waitControllerSession(t, controller, second)

	connectMu.Lock()
	gotConnected := append([]ArtifactLease(nil), connected...)
	connectMu.Unlock()
	if len(gotConnected) != 2 || gotConnected[0] != firstLease || gotConnected[1] != secondLease {
		t.Fatalf("connection leases = %d, want two fresh leases", len(gotConnected))
	}
	if first.closeCount() != 1 {
		t.Fatalf("terminated session close count = %d, want 1", first.closeCount())
	}
	if err := oldRPC.Notify(context.Background(), 1, "must not replay"); !isSessionCode(err, SessionClosed) {
		t.Fatalf("old RPC after replacement = %v, want SessionClosed", err)
	}
	if _, err := oldStream.Write([]byte("must not migrate")); !isSessionCode(err, SessionClosed) {
		t.Fatalf("old stream write after replacement = %v, want SessionClosed", err)
	}
	if got := second.operationCount(); got != 0 {
		t.Fatalf("replacement session received %d replayed operation(s)", got)
	}
	closeController(t, controller)
}

func testControllerRetryNow(t *testing.T) {
	firstLease, _ := controllerTestLeases(t)
	source := &controllerTestSource{results: []controllerAcquireResult{
		{failure: NewRetryableArtifactSourceError(errors.New("temporary source failure"))},
		{lease: firstLease},
	}}
	controller := newControllerForTest(t, source, 0)
	controller.connect = func(context.Context, ArtifactLease, ConnectorOptions) (Session, error) {
		return newControllerTestSession(SessionClosed), nil
	}
	startController(t, controller)
	waitControllerState(t, controller, ConnectionWaiting)
	if !controller.RetryNow() {
		t.Fatal("RetryNow rejected the active wait")
	}
	waitControllerState(t, controller, ConnectionConnected)
	if source.callCount() != 2 || source.maxInFlightCount() != 1 {
		t.Fatalf("acquisitions = %d, max in-flight = %d, want 2 and 1", source.callCount(), source.maxInFlightCount())
	}
	if controller.RetryNow() {
		t.Fatal("RetryNow started work outside waiting")
	}
	closeController(t, controller)
}

func testControllerRepeatedStart(t *testing.T) {
	started := make(chan struct{})
	source := &controllerTestSource{results: []controllerAcquireResult{{waitForCancel: true, started: started}}}
	controller := newControllerForTest(t, source, 0)
	controller.Start(context.Background())
	controller.Start(context.Background())
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("artifact acquisition did not start")
	}
	if source.callCount() != 1 || source.maxInFlightCount() != 1 {
		t.Fatalf("acquisitions/max in-flight = %d/%d, want 1/1", source.callCount(), source.maxInFlightCount())
	}
	closeController(t, controller)
}

func testControllerStartAfterClose(t *testing.T) {
	source := &controllerTestSource{}
	controller := newControllerForTest(t, source, 0)
	closeController(t, controller)
	controller.Start(context.Background())
	if controller.Snapshot().State != ConnectionClosed || source.callCount() != 0 {
		t.Fatalf("snapshot/acquisitions = %s/%d, want closed/0", controller.Snapshot(), source.callCount())
	}
}

func testControllerRetryNowOutsideWaiting(t *testing.T) {
	started := make(chan struct{})
	source := &controllerTestSource{results: []controllerAcquireResult{{waitForCancel: true, started: started}}}
	controller := newControllerForTest(t, source, 0)
	if controller.RetryNow() {
		t.Fatal("RetryNow accepted idle state")
	}
	controller.Start(context.Background())
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("artifact acquisition did not start")
	}
	if controller.RetryNow() {
		t.Fatal("RetryNow accepted connecting state")
	}
	closeController(t, controller)
	if controller.RetryNow() {
		t.Fatal("RetryNow accepted closed state")
	}
}

func testControllerRetryAfter(t *testing.T) {
	firstLease, _ := controllerTestLeases(t)
	retryAt := time.Now().Add(100 * time.Millisecond)
	failure, err := NewRetryAfterArtifactSourceError(errors.New("source rate limited"), retryAt)
	if err != nil {
		t.Fatal(err)
	}
	source := &controllerTestSource{results: []controllerAcquireResult{{failure: failure}, {lease: firstLease}}}
	controller := newControllerForTest(t, source, 0)
	controller.connect = func(context.Context, ArtifactLease, ConnectorOptions) (Session, error) {
		return newControllerTestSession(SessionClosed), nil
	}
	startController(t, controller)
	waitControllerState(t, controller, ConnectionWaiting)
	if controller.RetryNow() {
		t.Fatal("RetryNow accepted an authoritative retry_after wait")
	}
	time.Sleep(25 * time.Millisecond)
	if got := source.callCount(); got != 1 {
		t.Fatalf("retry_after acquired early: calls = %d", got)
	}
	waitControllerState(t, controller, ConnectionConnected)
	acquired := source.acquisitionTimes()
	if len(acquired) != 2 || acquired[1].Before(retryAt) {
		t.Fatalf("second acquisition at %v, want not before %v", acquired, retryAt)
	}
	closeController(t, controller)
}

func testControllerTerminalFailure(t *testing.T) {
	source := &controllerTestSource{results: []controllerAcquireResult{{
		failure: NewTerminalArtifactSourceError(errors.New("invalid credentials")),
	}}}
	controller := newControllerForTest(t, source, 0)
	startController(t, controller)
	waitControllerState(t, controller, ConnectionFailed)
	status := controller.Snapshot()
	if status.Failure == nil || status.Failure.Disposition.Kind != RetryDispositionTerminal || source.callCount() != 1 {
		t.Fatalf("terminal status = %+v, acquisitions = %d", status, source.callCount())
	}
	closeController(t, controller)
}

func testControllerAttemptExhaustion(t *testing.T) {
	source := &controllerTestSource{results: []controllerAcquireResult{
		{failure: NewRetryableArtifactSourceError(errors.New("temporary-1"))},
		{failure: NewRetryableArtifactSourceError(errors.New("temporary-2"))},
	}}
	controller := newControllerForTest(t, source, 2)
	startController(t, controller)
	waitControllerState(t, controller, ConnectionFailed)
	if source.callCount() != 2 || source.maxInFlightCount() != 1 {
		t.Fatalf("acquisitions = %d, max in-flight = %d, want 2 and 1", source.callCount(), source.maxInFlightCount())
	}
	closeController(t, controller)
}

func testControllerCloseCancelsAcquire(t *testing.T) {
	started := make(chan struct{})
	source := &controllerTestSource{results: []controllerAcquireResult{{waitForCancel: true, started: started}}}
	controller := newControllerForTest(t, source, 0)
	startController(t, controller)
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("artifact acquisition did not start")
	}
	closeController(t, controller)
	if source.maxInFlightCount() != 1 || source.inFlightCount() != 0 {
		t.Fatalf("source max/current in-flight = %d/%d, want 1/0", source.maxInFlightCount(), source.inFlightCount())
	}
}

func testControllerRepeatedClose(t *testing.T) {
	started := make(chan struct{})
	source := &controllerTestSource{results: []controllerAcquireResult{{waitForCancel: true, started: started}}}
	controller := newControllerForTest(t, source, 0)
	controller.Start(context.Background())
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("artifact acquisition did not start")
	}
	closeController(t, controller)
	closeController(t, controller)
	if source.callCount() != 1 || source.inFlightCount() != 0 {
		t.Fatalf("acquisitions/in-flight = %d/%d, want 1/0", source.callCount(), source.inFlightCount())
	}
}

func testControllerCloseWaitsForOwnedCleanup(t *testing.T) {
	firstLease, _ := controllerTestLeases(t)
	source := &controllerTestSource{results: []controllerAcquireResult{{lease: firstLease}}}
	controller := newControllerForTest(t, source, 0)
	connectStarted := make(chan struct{})
	releaseConnect := make(chan struct{})
	late := newControllerTestSession(SessionClosed)
	controller.connect = func(context.Context, ArtifactLease, ConnectorOptions) (Session, error) {
		close(connectStarted)
		<-releaseConnect // Deliberately model a native connector that is slow to honor cancellation.
		return late, nil
	}
	startController(t, controller)
	select {
	case <-connectStarted:
	case <-time.After(time.Second):
		t.Fatal("connection attempt did not start")
	}
	closed := make(chan error, 1)
	go func() { closed <- controller.Close(context.Background()) }()
	select {
	case err := <-closed:
		t.Fatalf("Close returned before late connector settled: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(releaseConnect)
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	if late.closeCount() != 1 || controller.Snapshot().State != ConnectionClosed {
		t.Fatalf("late session close count/state = %d/%s, want 1/closed", late.closeCount(), controller.Snapshot().State)
	}
}

func testControllerSubordinateCloseFailure(t *testing.T) {
	firstLease, _ := controllerTestLeases(t)
	source := &controllerTestSource{results: []controllerAcquireResult{{lease: firstLease}}}
	controller := newControllerForTest(t, source, 0)
	session := newControllerTestSession(SessionClosed)
	session.closeError = errors.New("subordinate close failed")
	controller.connect = func(context.Context, ArtifactLease, ConnectorOptions) (Session, error) {
		return session, nil
	}
	controller.Start(context.Background())
	waitControllerSession(t, controller, session)
	closeController(t, controller)
	if session.closeCount() != 1 || controller.Snapshot().State != ConnectionClosed {
		t.Fatalf("close count/snapshot = %d/%s, want 1/closed", session.closeCount(), controller.Snapshot())
	}
}

func loadControllerVectors(t *testing.T) controllerVectorFile {
	t.Helper()
	raw, err := os.ReadFile("../testdata/transport_v2/connection_controller_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture controllerVectorFile
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func newControllerForTest(t *testing.T, source ArtifactSource, maximumAttempts uint64) *ConnectionController {
	t.Helper()
	trustRoots := x509.NewCertPool()
	trustRoots.AddCert(&x509.Certificate{RawSubject: []byte("controller test root")})
	controller, err := NewConnectionController(source, ConnectionControllerOptions{
		Connector: ConnectorOptions{TrustRoots: trustRoots}, MaximumAttempts: maximumAttempts,
	})
	if err != nil {
		t.Fatal(err)
	}
	return controller
}

func startController(t *testing.T, controller *ConnectionController) {
	t.Helper()
	controller.Start(context.Background())
}

func closeController(t *testing.T, controller *ConnectionController) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := controller.Close(ctx); err != nil {
		t.Fatal(err)
	}
}

func waitControllerState(t *testing.T, controller *ConnectionController, want ConnectionState) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if controller.Snapshot().State == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("controller state = %q, want %q", controller.Snapshot().State, want)
}

func waitControllerSession(t *testing.T, controller *ConnectionController, want Session) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if controller.Snapshot().CurrentSession == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("controller session was not replaced")
}

func controllerTestLeases(t *testing.T) (ArtifactLease, ArtifactLease) {
	t.Helper()
	artifact := mustParseInternalFixtureArtifact(t)
	first, err := NewArtifactLease(artifact, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewArtifactLease(artifact, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	return first, second
}

type controllerAcquireResult struct {
	lease         ArtifactLease
	failure       *ArtifactSourceError
	waitForCancel bool
	started       chan struct{}
}

type controllerTestSource struct {
	mu          sync.Mutex
	results     []controllerAcquireResult
	calls       int
	inFlight    int
	maxInFlight int
	acquiredAt  []time.Time
}

func (source *controllerTestSource) Acquire(ctx context.Context) (ArtifactLease, *ArtifactSourceError) {
	source.mu.Lock()
	index := source.calls
	source.calls++
	source.inFlight++
	if source.inFlight > source.maxInFlight {
		source.maxInFlight = source.inFlight
	}
	source.acquiredAt = append(source.acquiredAt, time.Now())
	var result controllerAcquireResult
	if index < len(source.results) {
		result = source.results[index]
	} else {
		result.failure = NewTerminalArtifactSourceError(ErrInvalidArtifact)
	}
	source.mu.Unlock()
	defer func() {
		source.mu.Lock()
		source.inFlight--
		source.mu.Unlock()
	}()
	if result.started != nil {
		close(result.started)
	}
	if result.waitForCancel {
		<-ctx.Done()
		return ArtifactLease{}, NewTerminalArtifactSourceError(ctx.Err())
	}
	return result.lease, result.failure
}

func (source *controllerTestSource) callCount() int {
	source.mu.Lock()
	defer source.mu.Unlock()
	return source.calls
}

func (source *controllerTestSource) inFlightCount() int {
	source.mu.Lock()
	defer source.mu.Unlock()
	return source.inFlight
}

func (source *controllerTestSource) maxInFlightCount() int {
	source.mu.Lock()
	defer source.mu.Unlock()
	return source.maxInFlight
}

func (source *controllerTestSource) acquisitionTimes() []time.Time {
	source.mu.Lock()
	defer source.mu.Unlock()
	return append([]time.Time(nil), source.acquiredAt...)
}

type controllerTestSession struct {
	terminated chan struct{}
	code       SessionErrorCode
	once       sync.Once
	mu         sync.Mutex
	closed     bool
	closes     int
	operations int
	closeError error
}

func newControllerTestSession(code SessionErrorCode) *controllerTestSession {
	return &controllerTestSession{terminated: make(chan struct{}), code: code}
}

func (session *controllerTestSession) terminate() {
	session.once.Do(func() { close(session.terminated) })
}
func (session *controllerTestSession) RPC() RPCPeer { return controllerTestRPC{session: session} }
func (session *controllerTestSession) UnreliableMessages() (UnreliableMessageChannel, error) {
	return nil, nil
}
func (session *controllerTestSession) OpenStream(context.Context, string, StreamMetadata) (ByteStream, error) {
	if err := session.recordOperation(); err != nil {
		return nil, err
	}
	return &controllerTestStream{session: session}, nil
}
func (session *controllerTestSession) AcceptStream(context.Context) (IncomingStream, error) {
	return IncomingStream{}, session.recordOperation()
}
func (session *controllerTestSession) Rekey(context.Context) error { return session.recordOperation() }
func (session *controllerTestSession) ProbeLiveness(context.Context) (time.Duration, error) {
	return 0, session.recordOperation()
}
func (session *controllerTestSession) WaitTermination(ctx context.Context) (SessionTermination, error) {
	select {
	case <-session.terminated:
		return SessionTermination{Error: SessionError{code: session.code}}, nil
	case <-ctx.Done():
		return SessionTermination{}, ctx.Err()
	}
}
func (session *controllerTestSession) Close() error {
	session.mu.Lock()
	session.closed = true
	session.closes++
	session.mu.Unlock()
	return session.closeError
}
func (session *controllerTestSession) recordOperation() error {
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.closed {
		return &SessionError{code: SessionClosed}
	}
	session.operations++
	return nil
}
func (session *controllerTestSession) closeCount() int {
	session.mu.Lock()
	defer session.mu.Unlock()
	return session.closes
}
func (session *controllerTestSession) operationCount() int {
	session.mu.Lock()
	defer session.mu.Unlock()
	return session.operations
}

type controllerTestRPC struct{ session *controllerTestSession }

func (peer controllerTestRPC) Call(context.Context, uint32, any, any) error {
	return peer.session.recordOperation()
}
func (peer controllerTestRPC) Notify(context.Context, uint32, any) error {
	return peer.session.recordOperation()
}
func (peer controllerTestRPC) OnNotify(uint32, func(context.Context, json.RawMessage)) func() {
	return func() {}
}

type controllerTestStream struct{ session *controllerTestSession }

func (stream *controllerTestStream) Read([]byte) (int, error) {
	if err := stream.session.recordOperation(); err != nil {
		return 0, err
	}
	return 0, io.EOF
}
func (stream *controllerTestStream) Write(payload []byte) (int, error) {
	if err := stream.session.recordOperation(); err != nil {
		return 0, err
	}
	return len(payload), nil
}
func (stream *controllerTestStream) Close() error                 { return nil }
func (stream *controllerTestStream) Kind() string                 { return "controller-test" }
func (stream *controllerTestStream) TerminalError() *SessionError { return nil }
func (stream *controllerTestStream) CloseWrite() error            { return stream.session.recordOperation() }
func (stream *controllerTestStream) Reset() error                 { return stream.session.recordOperation() }

func isSessionCode(err error, code SessionErrorCode) bool {
	var sessionError *SessionError
	return errors.As(err, &sessionError) && sessionError.Code() == code
}
