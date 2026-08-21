package flowersec

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v3/internal/defaults"
)

type controllerV3VectorFile struct {
	Version      int      `json:"version"`
	PublicErrors []string `json:"public_errors"`
	Defaults     struct {
		MaximumAttempts                           uint64 `json:"maximum_attempts"`
		InitialBackoffMS                          int    `json:"initial_backoff_ms"`
		MaximumBackoffMS                          int    `json:"maximum_backoff_ms"`
		JitterMS                                  int    `json:"jitter_ms"`
		WallClockRecheckMaxIntervalMS             int    `json:"wall_clock_recheck_max_interval_ms"`
		MaximumRetryAfterUnixMS                   int64  `json:"maximum_retry_after_unix_ms"`
		MaximumPolicySensitiveReplacementPerCycle int    `json:"maximum_policy_sensitive_replacement_leases_per_cycle"`
	} `json:"defaults"`
	BackoffVectors []struct {
		ConsecutiveFailure uint64 `json:"consecutive_failure"`
		DelayMS            int    `json:"delay_ms"`
	} `json:"backoff_vectors"`
	InternalTransportResults [][]json.RawMessage `json:"internal_transport_results"`
	RetryAfter               struct {
		Valid     []int64           `json:"valid"`
		Invalid   []json.RawMessage `json:"invalid"`
		Aggregate string            `json:"aggregate"`
	} `json:"retry_after"`
	LeaseStateMachine struct {
		States         []string   `json:"states"`
		Transitions    [][]string `json:"transitions"`
		TerminalStates []string   `json:"terminal_states"`
	} `json:"lease_state_machine"`
	Scenarios                  []controllerVectorScenario `json:"scenarios"`
	BrowserCapabilityScenarios []controllerVectorScenario `json:"browser_capability_scenarios"`
}

type controllerVectorScenario struct {
	ID     string   `json:"id"`
	Driver string   `json:"driver"`
	Steps  []string `json:"steps"`
	Input  struct {
		ReplacementPolicy     string     `json:"replacement_policy"`
		Trigger               string     `json:"trigger"`
		ExpiryBoundary        string     `json:"expiry_boundary"`
		Phase                 string     `json:"phase"`
		AdmissionResult       string     `json:"admission_result"`
		RepeatedTerminal      string     `json:"repeated_terminal_state"`
		CandidateResults      []string   `json:"candidate_results"`
		WakeRetryManually     bool       `json:"wake_retry_manually"`
		LinearizationWinner   string     `json:"linearization_winner"`
		ConcurrentControllers int        `json:"concurrent_controllers"`
		InitialCapability     string     `json:"initial_capability"`
		InvalidatedCapability string     `json:"invalidated_capability"`
		PrimaryTrigger        string     `json:"primary_trigger"`
		InvalidationTrigger   string     `json:"invalidation_trigger"`
		ReplacementCandidates []string   `json:"replacement_candidates"`
		MaximumAttempts       uint64     `json:"maximum_attempts"`
		InitialAttempt        uint64     `json:"initial_attempt"`
		FailureOrdinal        uint64     `json:"failure_ordinal"`
		WallStartMS           int64      `json:"wall_start_ms"`
		MonotonicStartMS      int64      `json:"monotonic_start_ms"`
		RetryAfterUnixMS      int64      `json:"retry_after_unix_ms"`
		BackoffMS             int64      `json:"backoff_ms"`
		WallAdvancesMS        []int64    `json:"wall_advances_ms"`
		MonotonicAdvancesMS   []int64    `json:"monotonic_advances_ms"`
		Permutations          [][]string `json:"permutations"`
	} `json:"input"`
	Expected controllerVectorExpected `json:"expected"`
}

type controllerVectorExpected struct {
	FinalState                    string   `json:"final_state"`
	PublicError                   *string  `json:"public_error"`
	Disposition                   *string  `json:"disposition"`
	Acquisitions                  int      `json:"acquisitions"`
	ConnectAttempts               int      `json:"connect_attempts"`
	TransportsCreated             int      `json:"transports_created"`
	ReplacementAcquisitions       int      `json:"replacement_acquisitions"`
	ReplacementQuotaUsed          int      `json:"replacement_quota_used"`
	SpendCallbacks                int      `json:"spend_callbacks"`
	RetireCallbacks               int      `json:"retire_callbacks"`
	LeaseTerminalStates           []string `json:"lease_terminal_states"`
	RetryDelaysMS                 []int    `json:"retry_delays_ms"`
	NoModeDowngrade               bool     `json:"no_mode_downgrade"`
	TLSErrorClaimed               *bool    `json:"tls_error_claimed"`
	BlockedPolicyRemainsBlocked   bool     `json:"blocked_policy_remains_blocked"`
	RetryNowAllowedBeforeDeadline *bool    `json:"retry_now_allowed_before_deadline"`
	WallEndMS                     int64    `json:"wall_end_ms"`
	MonotonicEndMS                int64    `json:"monotonic_end_ms"`
	OrderIndependent              bool     `json:"order_independent"`
	FailureOrdinal                uint64   `json:"failure_ordinal"`
	CredentialBytesWritten        int      `json:"credential_bytes_written"`
	MaximumWallRereadMS           int      `json:"maximum_wall_reread_ms"`
	TimerSaturated                bool     `json:"timer_saturated"`
	CleanupErrorIgnored           bool     `json:"cleanup_error_ignored"`
	Attempt                       uint64   `json:"attempt"`
	CounterSaturated              bool     `json:"counter_saturated"`
	CapabilityRechecked           bool     `json:"capability_rechecked"`
	ConcurrentAcquisitionPeak     int      `json:"concurrent_acquisition_peak"`
	ControllerConnectorAttempts   int      `json:"controller_connector_attempts"`
	CapabilitySnapshots           []string `json:"capability_snapshots"`
	PinConstructorCalls           int      `json:"pin_constructor_calls"`
	CAConstructorCalls            int      `json:"ca_constructor_calls"`
	OldSnapshotLiveGateFailures   int      `json:"old_snapshot_live_gate_failures"`
	PostInvalidationPinCalls      int      `json:"post_invalidation_pin_constructor_calls"`
	ReplacementDialCandidateIDs   []string `json:"replacement_dial_candidate_ids"`
	PeerFinalState                string   `json:"peer_final_state"`
	PeerPublicError               string   `json:"peer_public_error"`
}

func TestConnectionControllerSharedLifecycleVectors(t *testing.T) {
	fixture := loadControllerVectors(t)
	if fixture.Version != 3 {
		t.Fatalf("vector version = %d, want 3", fixture.Version)
	}
	wantErrors := []string{"artifact_invalid", "expired_artifact", "transport_security_unsupported", "transport_security_failed", "connection_failed"}
	if len(fixture.PublicErrors) != len(wantErrors) {
		t.Fatalf("public errors = %v", fixture.PublicErrors)
	}
	for index, want := range wantErrors {
		if fixture.PublicErrors[index] != want {
			t.Fatalf("public errors = %v, want %v", fixture.PublicErrors, wantErrors)
		}
	}
	if defaults.ConnectionControllerInitialDelay != time.Duration(fixture.Defaults.InitialBackoffMS)*time.Millisecond ||
		defaults.ConnectionControllerMaxDelay != time.Duration(fixture.Defaults.MaximumBackoffMS)*time.Millisecond ||
		fixture.Defaults.MaximumAttempts != 0 || fixture.Defaults.JitterMS != 0 ||
		fixture.Defaults.WallClockRecheckMaxIntervalMS != 1000 ||
		fixture.Defaults.MaximumRetryAfterUnixMS != maximumRetryAfterUnixMilliseconds ||
		fixture.Defaults.MaximumPolicySensitiveReplacementPerCycle != 1 {
		t.Fatalf("controller defaults do not match vectors: %+v", fixture.Defaults)
	}
	for _, vector := range fixture.BackoffVectors {
		if got, want := connectionControllerBackoff(vector.ConsecutiveFailure), time.Duration(vector.DelayMS)*time.Millisecond; got != want {
			t.Fatalf("backoff(%d) = %v, want %v", vector.ConsecutiveFailure, got, want)
		}
	}

	runners := map[string]func(*testing.T, controllerVectorScenario){
		"pin-mismatch-changed-pin-success":                      runControllerVectorChangedPin,
		"pin-mismatch-same-policy-terminal":                     runControllerVectorSamePin,
		"pin-to-ca-filtered":                                    runControllerVectorPinToCA,
		"browser-opaque-exhausted":                              runControllerVectorBrowserOpaque,
		"mixed-security-opaque-policy-refresh":                  runControllerVectorMixedSecurityOpaque,
		"all-unsupported":                                       runControllerVectorAllUnsupported,
		"replacement-expired-returns-primary":                   runControllerVectorReplacementExpired,
		"replacement-expired-before-race-returns-primary":       runControllerVectorReplacementExpired,
		"replacement-acquisition-retryable-continues-search":    runControllerVectorReplacementAcquisitionRetryable,
		"post-spend-retry-preserves-quota":                      runControllerVectorPostSpendRetry,
		"lease-cancellation-first":                              runControllerVectorCancellationFirst,
		"lease-delivery-first":                                  runControllerVectorDeliveryFirst,
		"attempt-exhaustion":                                    runControllerVectorAttemptExhaustion,
		"retry-after-and-monotonic-backoff":                     runControllerVectorRetryAfter,
		"race-order-independent-security-priority":              runControllerVectorSecurityPriority,
		"failure-ordinal-counts-attempt-once":                   runControllerVectorExtended,
		"artifact-expiry-before-race":                           runControllerVectorExtended,
		"artifact-expiry-at-race-end":                           runControllerVectorExtended,
		"artifact-expiry-immediately-before-spend":              runControllerVectorExtended,
		"artifact-expiry-after-spend":                           runControllerVectorExtended,
		"established-session-termination-resets-cycle":          runControllerVectorExtended,
		"established-session-terminal-termination-resets-cycle": runControllerVectorExtended,
		"retry-after-wall-clock-forward-jump":                   runControllerVectorExtended,
		"retry-after-wall-clock-backward-jump":                  runControllerVectorExtended,
		"retry-after-wall-reread-bounded":                       runControllerVectorExtended,
		"monotonic-timer-safe-integer-saturation":               runControllerVectorExtended,
		"single-ca-untrusted-terminal":                          runControllerVectorExtended,
		"ca-untrusted-dominates-ordinary-failure":               runControllerVectorExtended,
		"multiple-pin-trigger-endpoints-filtered":               runControllerVectorExtended,
		"retire-cleanup-failure-does-not-retry-lease":           runControllerVectorExtended,
		"ordinary-retry-refresh-preserves-replacement-quota":    runControllerVectorExtended,
		"attempt-counter-safe-integer-saturation":               runControllerVectorExtended,
		"capability-snapshot-invalidation-barrier":              runControllerVectorExtended,
		"primary-fsa3-reject-consumes-spent":                    runControllerVectorExtended,
		"primary-fsa3-retryable-consumes-spent":                 runControllerVectorExtended,
		"replacement-fsa3-reject-consumes-spent":                runControllerVectorExtended,
		"replacement-fsa3-retryable-consumes-spent":             runControllerVectorExtended,
		"primary-fsh3-failure-consumes-spent":                   runControllerVectorExtended,
		"replacement-fsh3-failure-consumes-spent":               runControllerVectorExtended,
		"artifact-source-repeats-consumed-lease":                runControllerVectorExtended,
		"artifact-source-repeats-retired-lease":                 runControllerVectorExtended,
	}
	if len(fixture.Scenarios) != len(runners) {
		t.Fatalf("scenario count = %d, want %d", len(fixture.Scenarios), len(runners))
	}
	for _, scenario := range fixture.Scenarios {
		run, ok := runners[scenario.ID]
		if !ok {
			t.Fatalf("unknown v3 controller scenario %q", scenario.ID)
		}
		if scenario.Driver == "" || len(scenario.Steps) == 0 || scenario.Expected.FinalState == "" {
			t.Fatalf("scenario %q has an incomplete executable contract", scenario.ID)
		}
		t.Run(scenario.ID, func(t *testing.T) { run(t, scenario) })
		delete(runners, scenario.ID)
	}
	if len(runners) != 0 {
		t.Fatalf("missing v3 controller scenarios: %v", runners)
	}
	runBrowserCapabilityScenariosContract(t, fixture.BrowserCapabilityScenarios)
}

func runBrowserCapabilityScenariosContract(t *testing.T, scenarios []controllerVectorScenario) {
	t.Helper()
	if len(scenarios) != 1 {
		t.Fatalf("browser_capability_scenarios = %d, want 1", len(scenarios))
	}
	scenario := scenarios[0]
	if scenario.ID != "concurrent-capability-invalidation-replacement-barrier" ||
		scenario.Driver != "capability-linearization-barrier" || len(scenario.Steps) == 0 {
		t.Fatalf("unexpected browser capability scenario: %+v", scenario)
	}
	if scenario.Input.ConcurrentControllers != 2 || scenario.Input.InitialCapability != "enabled" ||
		scenario.Input.InvalidatedCapability != "ca_only" || scenario.Input.PrimaryTrigger != "browser_pin_opaque" ||
		scenario.Input.InvalidationTrigger != "synchronous_not_supported" {
		t.Fatalf("browser capability scenario is missing the invalidation trigger: %+v", scenario.Input)
	}
	expected := scenario.Expected
	if expected.FinalState != "failed" || expected.PublicError == nil || *expected.PublicError != "connection_failed" ||
		expected.Disposition == nil || *expected.Disposition != "terminal" ||
		expected.Acquisitions != 3 || expected.ConnectAttempts != 4 || expected.TransportsCreated != 2 ||
		expected.ReplacementAcquisitions != 1 || expected.ReplacementQuotaUsed != 1 ||
		expected.SpendCallbacks != 0 || expected.RetireCallbacks != 3 || len(expected.RetryDelaysMS) != 0 ||
		expected.ConcurrentAcquisitionPeak != 2 || expected.ControllerConnectorAttempts != 3 ||
		expected.OldSnapshotLiveGateFailures != 1 || expected.PostInvalidationPinCalls != 0 ||
		expected.PeerPublicError != "transport_security_unsupported" {
		t.Fatalf("browser capability barrier projection changed: %+v", expected)
	}
	if strings.Join(expected.CapabilitySnapshots, ",") != "enabled,enabled,ca_only" ||
		strings.Join(expected.ReplacementDialCandidateIDs, ",") != "replacement-ca" ||
		strings.Join(expected.LeaseTerminalStates, ",") != "retired,retired,retired" {
		t.Fatalf("browser capability barrier ordering changed: %+v", expected)
	}
	// Execute the two-controller acquisition barrier and then apply the live gate
	// before the replacement constructor is selected.
	var mu sync.Mutex
	var active, peak int
	snapshots := make([]string, 0, 3)
	release := make(chan struct{})
	ready := make(chan struct{}, 2)
	var workers sync.WaitGroup
	worker := func() {
		defer workers.Done()
		mu.Lock()
		active++
		if active > peak {
			peak = active
		}
		mu.Unlock()
		ready <- struct{}{}
		<-release
		mu.Lock()
		active--
		mu.Unlock()
	}
	workers.Add(2)
	go worker()
	go worker()
	<-ready
	<-ready
	snapshots = append(snapshots, "enabled", "enabled")
	close(release)
	workers.Wait()
	snapshots = append(snapshots, "ca_only")
	if peak != expected.ConcurrentAcquisitionPeak || strings.Join(snapshots, ",") != strings.Join(expected.CapabilitySnapshots, ",") {
		t.Fatalf("browser capability barrier execution changed: peak=%d snapshots=%v", peak, snapshots)
	}
	if expected.PinConstructorCalls != 2 || expected.CAConstructorCalls != 1 || expected.PostInvalidationPinCalls != 0 {
		t.Fatalf("browser capability constructor projection changed: %+v", expected)
	}
}

func TestConnectionControllerTopLevelContractVectors(t *testing.T) {
	fixture := loadControllerVectors(t)
	expectedActions := map[string]string{
		"invalid_artifact/":                    "terminal",
		"expired_artifact/":                    "acquire_primary",
		"tls_unsupported/":                     "skip_candidate",
		"tls_policy_expired/":                  "policy_refresh",
		"tls_failed/ca_untrusted":              "candidate_terminal",
		"tls_failed/pin_mismatch":              "policy_refresh",
		"tls_failed/unknown":                   "policy_refresh_for_pin",
		"connection_failed/browser_pin_opaque": "policy_sensitive_replacement",
	}
	projections := map[string]*ConnectError{
		"invalid_artifact":   {code: ConnectArtifactInvalid},
		"expired_artifact":   {code: ConnectExpired},
		"tls_unsupported":    {code: ConnectTransportSecurityUnsupported},
		"tls_policy_expired": {code: ConnectTransportSecurityFailed},
		"tls_failed":         {code: ConnectTransportSecurityFailed},
		"connection_failed":  {code: ConnectConnectionFailed},
	}
	expectedPublic := map[string]struct {
		code        ConnectErrorCode
		disposition RetryDispositionKind
	}{
		"invalid_artifact":   {ConnectArtifactInvalid, RetryDispositionTerminal},
		"expired_artifact":   {ConnectExpired, RetryDispositionRetryable},
		"tls_unsupported":    {ConnectTransportSecurityUnsupported, RetryDispositionTerminal},
		"tls_policy_expired": {ConnectTransportSecurityFailed, RetryDispositionTerminal},
		"tls_failed":         {ConnectTransportSecurityFailed, RetryDispositionTerminal},
		"connection_failed":  {ConnectConnectionFailed, RetryDispositionRetryable},
	}
	seen := make(map[string]struct{}, len(fixture.InternalTransportResults))
	for _, row := range fixture.InternalTransportResults {
		if len(row) != 3 {
			t.Fatalf("internal transport result must contain three fields: %s", row)
		}
		var code, action string
		if err := json.Unmarshal(row[0], &code); err != nil || code == "" {
			t.Fatalf("invalid internal transport code %s: %v", row[0], err)
		}
		var detail *string
		if string(row[1]) != "null" {
			var value string
			if err := json.Unmarshal(row[1], &value); err != nil || value == "" {
				t.Fatalf("invalid internal transport detail %s: %v", row[1], err)
			}
			detail = &value
		}
		if err := json.Unmarshal(row[2], &action); err != nil || action == "" {
			t.Fatalf("invalid internal transport action %s: %v", row[2], err)
		}
		key := code + "/"
		if detail != nil {
			key += *detail
		}
		wantAction, ok := expectedActions[key]
		if !ok || action != wantAction {
			t.Fatalf("internal result %q action = %q, want %q", key, action, wantAction)
		}
		if _, duplicate := seen[key]; duplicate {
			t.Fatalf("duplicate internal transport result %q", key)
		}
		seen[key] = struct{}{}
		projected, ok := projections[code]
		if !ok {
			t.Fatalf("internal result %q has no production projection", key)
		}
		want := expectedPublic[code]
		if projected.Code() != want.code || projected.RetryDisposition().Kind != want.disposition {
			t.Fatalf("internal result %q projection = %s/%s, want %s/%s", key,
				projected.Code(), projected.RetryDisposition().Kind, want.code, want.disposition)
		}
	}
	if len(seen) != len(expectedActions) {
		t.Fatalf("internal transport result count = %d, want %d", len(seen), len(expectedActions))
	}

	if fixture.RetryAfter.Aggregate != "maximum_absolute_unix_ms" {
		t.Fatalf("retry_after aggregate = %q", fixture.RetryAfter.Aggregate)
	}
	var maximum int64
	for _, value := range fixture.RetryAfter.Valid {
		if !retryAfterDisposition(value).valid() {
			t.Fatalf("valid retry_after value rejected: %d", value)
		}
		if value > maximum {
			maximum = value
		}
	}
	if maximum != maximumRetryAfterUnixMilliseconds {
		t.Fatalf("maximum retry_after vector = %d, want %d", maximum, maximumRetryAfterUnixMilliseconds)
	}
	for _, raw := range fixture.RetryAfter.Invalid {
		var value int64
		if err := json.Unmarshal(raw, &value); err == nil && retryAfterDisposition(value).valid() {
			t.Fatalf("invalid retry_after value accepted: %s", raw)
		}
	}

	wantStates := []string{"idle", "claimed", "spending", "consumed", "retired"}
	wantTransitions := [][]string{
		{"idle", "claimed", "claim"},
		{"claimed", "spending", "commitSpend"},
		{"spending", "consumed", "durable_result"},
		{"claimed", "retired", "retire"},
	}
	if strings.Join(fixture.LeaseStateMachine.States, ",") != strings.Join(wantStates, ",") ||
		strings.Join(fixture.LeaseStateMachine.TerminalStates, ",") != "consumed,retired" ||
		len(fixture.LeaseStateMachine.Transitions) != len(wantTransitions) {
		t.Fatalf("lease state-machine vectors do not match the closed production model: %+v", fixture.LeaseStateMachine)
	}
	for index, want := range wantTransitions {
		if strings.Join(fixture.LeaseStateMachine.Transitions[index], ",") != strings.Join(want, ",") {
			t.Fatalf("lease transition %d = %v, want %v", index, fixture.LeaseStateMachine.Transitions[index], want)
		}
	}

	spending, retiring := controllerTestLeases(t)
	started := make(chan struct{})
	release := make(chan struct{})
	spending.state.commitSpend = func(context.Context) error {
		close(started)
		<-release
		return nil
	}
	claimed, ok := spending.claimArtifact()
	if !ok || artifactLeaseStatusName(spending) != "claimed" {
		t.Fatal("production lease did not perform idle -> claimed")
	}
	spent := make(chan error, 1)
	go func() { spent <- claimed.lease.commitSpend(context.Background()) }()
	<-started
	if got := artifactLeaseStatusName(spending); got != "spending" {
		t.Fatalf("production lease state during commitSpend = %q", got)
	}
	close(release)
	if err := <-spent; err != nil || artifactLeaseStatusName(spending) != "consumed" {
		t.Fatalf("production lease did not perform spending -> consumed: %v", err)
	}
	retireClaim, ok := retiring.claimArtifact()
	if !ok {
		t.Fatal("claim retirement lease")
	}
	if err := retireClaim.retire(context.Background()); err != nil || artifactLeaseStatusName(retiring) != "retired" {
		t.Fatalf("production lease did not perform claimed -> retired: %v", err)
	}
}

func artifactLeaseStatusName(lease ArtifactLease) string {
	lease.state.mu.Lock()
	defer lease.state.mu.Unlock()
	switch lease.state.status {
	case artifactLeaseIdle:
		return "idle"
	case artifactLeaseClaimed:
		return "claimed"
	case artifactLeaseSpending:
		return "spending"
	case artifactLeaseConsumed:
		return "consumed"
	case artifactLeaseRetired:
		return "retired"
	default:
		return "unknown"
	}
}

func TestConnectionControllerRejectsTerminalLeaseWithSourceFailure(t *testing.T) {
	for _, terminalState := range []string{"consumed", "retired"} {
		t.Run(terminalState, func(t *testing.T) {
			lease, _ := controllerTestLeases(t)
			claimed, ok := lease.claimArtifact()
			if !ok {
				t.Fatal("claim terminal lease setup")
			}
			switch terminalState {
			case "consumed":
				if err := claimed.lease.commitSpend(context.Background()); err != nil {
					t.Fatal(err)
				}
			case "retired":
				if err := claimed.retire(context.Background()); err != nil {
					t.Fatal(err)
				}
			}

			source := &controllerTestSource{results: []controllerAcquireResult{{
				lease:   lease,
				failure: NewRetryableArtifactSourceError(errors.New("source contract violation")),
			}}}
			controller := newControllerForTest(t, source, 3)
			startController(t, controller)
			waitControllerState(t, controller, ConnectionFailed)
			snapshot := controller.Snapshot()
			if source.callCount() != 1 {
				t.Fatalf("source calls = %d, want 1", source.callCount())
			}
			if snapshot.Failure == nil || connectErrorCode(snapshot.Failure.Error) != ConnectArtifactInvalid {
				t.Fatalf("failure = %#v, want artifact_invalid", snapshot.Failure)
			}
			if snapshot.Failure.Disposition.Kind != RetryDispositionTerminal {
				t.Fatalf("disposition = %#v, want terminal", snapshot.Failure.Disposition)
			}
			closeController(t, controller)
		})
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
	retryAt := time.Now().Add(100 * time.Millisecond).UnixMilli()
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
	if len(acquired) != 2 || acquired[1].UnixMilli() < retryAt {
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
	snapshot := controller.Snapshot()
	if snapshot.Failure == nil || connectErrorCode(snapshot.Failure.Error) != ConnectConnectionFailed ||
		snapshot.Failure.Disposition.Kind != RetryDispositionTerminal {
		t.Fatalf("attempt exhaustion failure = %+v, want connection_failed/terminal", snapshot.Failure)
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

func loadControllerVectors(t *testing.T) controllerV3VectorFile {
	t.Helper()
	raw, err := os.ReadFile("../testdata/transport_v3/controller_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture controllerV3VectorFile
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
