package flowersec

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v3/internal/artifactv3"
	"github.com/floegence/flowersec/flowersec-go/v3/internal/defaults"
)

var (
	ErrInvalidConnectionController = errors.New("invalid Flowersec connection controller")
)

const maxSafeControllerInteger uint64 = 9_007_199_254_740_991

// ConnectionState is the complete lifecycle of a long-lived connection
// intent. Each connected state contains a newly established one-shot Session.
type ConnectionState string

const (
	ConnectionIdle       ConnectionState = "idle"
	ConnectionConnecting ConnectionState = "connecting"
	ConnectionConnected  ConnectionState = "connected"
	ConnectionWaiting    ConnectionState = "waiting"
	ConnectionFailed     ConnectionState = "failed"
	ConnectionClosed     ConnectionState = "closed"
)

// ConnectionControllerOptions configures the one-shot connector and the only
// portable retry limit. Backoff timing is fixed by the Flowersec contract.
type ConnectionControllerOptions struct {
	Connector       ConnectorOptions
	MaximumAttempts uint64
	// clock is package-internal so deterministic scheduler tests can exercise
	// wall-clock expiry and retry timing without weakening the public API.
	clock controllerClock
}

type controllerClock struct {
	wallNow                  func() time.Time
	monotonicNowMilliseconds func() uint64
	newTimer                 func(time.Duration) controllerTimer
}

type controllerTimer struct {
	channel <-chan time.Time
	stop    func() bool
}

func realControllerClock() controllerClock {
	origin := time.Now()
	return controllerClock{
		wallNow: time.Now,
		monotonicNowMilliseconds: func() uint64 {
			elapsed := time.Since(origin) / time.Millisecond
			if elapsed <= 0 {
				return 0
			}
			return min(uint64(elapsed), maxSafeControllerInteger)
		},
		newTimer: func(delay time.Duration) controllerTimer {
			timer := time.NewTimer(delay)
			return controllerTimer{channel: timer.C, stop: timer.Stop}
		},
	}
}

// ArtifactSource supplies one fresh, single-use lease for every controller
// attempt. A bare ArtifactLease cannot construct a ConnectionController.
type ArtifactSource interface {
	Acquire(context.Context) (ArtifactLease, *ArtifactSourceError)
}

// ArtifactSourceError carries the source-owned structured retry decision.
// The controller never parses Cause text to decide whether to retry.
type ArtifactSourceError struct {
	cause       error
	disposition RetryDisposition
}

func (err *ArtifactSourceError) Error() string {
	if err == nil {
		return "<nil>"
	}
	return "Flowersec artifact acquisition failed (disposition=" + string(err.disposition.Kind) + ")"
}

func (err *ArtifactSourceError) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.cause
}

func (err *ArtifactSourceError) RetryDisposition() RetryDisposition {
	if err == nil || !err.disposition.valid() {
		return terminalDisposition()
	}
	return err.disposition
}

func (err *ArtifactSourceError) valid() bool {
	return err != nil && err.disposition.valid()
}

// NewTerminalArtifactSourceError constructs a non-retryable source failure.
func NewTerminalArtifactSourceError(cause error) *ArtifactSourceError {
	return newArtifactSourceError(cause, terminalDisposition())
}

// NewRetryableArtifactSourceError constructs a source failure governed by the
// controller's deterministic backoff policy.
func NewRetryableArtifactSourceError(cause error) *ArtifactSourceError {
	return newArtifactSourceError(cause, retryableDisposition())
}

// NewRetryAfterArtifactSourceError constructs a source failure with an
// authoritative not-before deadline.
func NewRetryAfterArtifactSourceError(cause error, retryAtUnixMilliseconds int64) (*ArtifactSourceError, error) {
	if !validRetryAfterUnixMilliseconds(retryAtUnixMilliseconds) {
		return nil, ErrInvalidConnectionController
	}
	return newArtifactSourceError(cause, retryAfterDisposition(retryAtUnixMilliseconds)), nil
}

func newArtifactSourceError(cause error, disposition RetryDisposition) *ArtifactSourceError {
	if cause == nil {
		cause = ErrInvalidArtifact
	}
	return &ArtifactSourceError{cause: cause, disposition: disposition}
}

// ConnectionFailure is the current terminal or retrying controller failure.
type ConnectionFailure struct {
	Error       error
	Disposition RetryDisposition
}

// ConnectionSnapshot is an immutable controller snapshot.
type ConnectionSnapshot struct {
	State          ConnectionState
	Attempt        uint64
	CurrentSession Session
	Failure        *ConnectionFailure
	revision       uint64
}

type connectionAttempt func(context.Context, ArtifactLease, ConnectorOptions) (Session, error)
type controllerConnectionAttempt func(context.Context, claimedArtifactLease, ConnectorOptions, map[transportEndpointKey]struct{}) (Session, controllerConnectOutcome)

type controllerAcquisitionMode uint8

const (
	controllerAcquirePrimary controllerAcquisitionMode = iota
	controllerAcquireReplacement
)

type blockedPinPolicy struct {
	endpoint transportEndpointKey
	digest   [32]byte
}

type controllerCycle struct {
	attempts            uint64
	consecutiveFailures uint64
	mode                controllerAcquisitionMode
	replacementUsed     bool
	blocked             map[blockedPinPolicy]struct{}
	replacementBasis    map[transportEndpointKey]artifactv3.Candidate
	replacementFailed   map[transportEndpointKey]struct{}
	triggered           map[transportEndpointKey]artifactv3.Candidate
	securityTrigger     bool
	opaqueTrigger       bool
	lastFailure         error
}

// ConnectionController is the sole Flowersec session reconnect scheduler. It
// never migrates streams or replays RPC calls, writes, or application work.
type ConnectionController struct {
	source          ArtifactSource
	options         ConnectorOptions
	maximumAttempts uint64
	connect         connectionAttempt
	connectDetailed controllerConnectionAttempt

	mu                             sync.Mutex
	snapshot                       ConnectionSnapshot
	changed                        chan struct{}
	retry                          chan struct{}
	retryNotBeforeUnixMilliseconds int64
	cancel                         context.CancelFunc
	done                           chan struct{}
	started                        bool
	closing                        bool
	doneClosed                     bool
	currentSession                 Session
	closingSession                 Session
	clock                          controllerClock
	// beforeAcquireAdmission is a test-only scheduler hook. Production leaves
	// it nil; tests use it to stop exactly before the lifecycle admission check.
	beforeAcquireAdmission func()
	// afterTerminationContextCheck is a test-only scheduler hook. Production
	// leaves it nil; tests use it to expose Close racing session settlement.
	afterTerminationContextCheck func()
}

// NewConnectionController creates an idle controller over a refreshable
// ArtifactSource.
func NewConnectionController(source ArtifactSource, options ConnectionControllerOptions) (*ConnectionController, error) {
	if source == nil || !validConnectorPolicy(options.Connector) || options.MaximumAttempts > maxSafeControllerInteger {
		return nil, ErrInvalidConnectionController
	}
	if options.Connector.RPCHandlers != nil {
		options.Connector.RPCHandlers.freeze()
	}
	clock := options.clock
	if clock.wallNow == nil || clock.monotonicNowMilliseconds == nil || clock.newTimer == nil {
		clock = realControllerClock()
	}
	return &ConnectionController{
		source: source, options: options.Connector, maximumAttempts: options.MaximumAttempts,
		snapshot: ConnectionSnapshot{State: ConnectionIdle}, retryNotBeforeUnixMilliseconds: -1,
		changed: make(chan struct{}), retry: make(chan struct{}, 1), done: make(chan struct{}),
		clock: clock,
	}, nil
}

// Start launches the controller's single scheduler. Canceling ctx closes the
// controller and its current session.
func (controller *ConnectionController) Start(ctx context.Context) {
	if controller == nil {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	controller.mu.Lock()
	if controller.started || controller.snapshot.State != ConnectionIdle {
		controller.mu.Unlock()
		return
	}
	controller.started = true
	lifecycle, cancel := context.WithCancel(ctx)
	controller.cancel = cancel
	controller.setSnapshotLocked(ConnectionSnapshot{State: ConnectionConnecting, Attempt: 1})
	controller.mu.Unlock()
	go controller.run(lifecycle)
}

// Snapshot returns the current immutable snapshot.
func (controller *ConnectionController) Snapshot() ConnectionSnapshot {
	if controller == nil {
		return ConnectionSnapshot{State: ConnectionClosed}
	}
	controller.mu.Lock()
	defer controller.mu.Unlock()
	return copyConnectionSnapshot(controller.snapshot)
}

// CurrentSession returns the currently established one-shot Session, or nil.
func (controller *ConnectionController) CurrentSession() Session {
	return controller.Snapshot().CurrentSession
}

// WaitForSnapshotChange blocks until the controller advances beyond after.
func (controller *ConnectionController) WaitForSnapshotChange(ctx context.Context, after ConnectionSnapshot) (ConnectionSnapshot, error) {
	if controller == nil {
		return ConnectionSnapshot{}, ErrInvalidConnectionController
	}
	if ctx == nil {
		ctx = context.Background()
	}
	for {
		controller.mu.Lock()
		if controller.snapshot.revision != after.revision {
			snapshot := copyConnectionSnapshot(controller.snapshot)
			controller.mu.Unlock()
			return snapshot, nil
		}
		changed := controller.changed
		controller.mu.Unlock()
		select {
		case <-ctx.Done():
			return ConnectionSnapshot{}, ctx.Err()
		case <-changed:
		}
	}
}

// RetryNow wakes the current waiting period. It never creates another
// scheduler or connection attempt.
func (controller *ConnectionController) RetryNow() bool {
	if controller == nil {
		return false
	}
	controller.mu.Lock()
	waiting := controller.snapshot.State == ConnectionWaiting &&
		(controller.retryNotBeforeUnixMilliseconds < 0 || controller.clock.wallNow().UnixMilli() >= controller.retryNotBeforeUnixMilliseconds)
	if waiting {
		select {
		case controller.retry <- struct{}{}:
		default:
		}
	}
	controller.mu.Unlock()
	return waiting
}

// Close atomically cancels acquisition, connection, waiting, and the current
// session, then waits for the controller to reach closed.
func (controller *ConnectionController) Close(ctx context.Context) error {
	if controller == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	controller.mu.Lock()
	if !controller.started {
		controller.closing = true
		if controller.snapshot.State != ConnectionClosed {
			controller.retryNotBeforeUnixMilliseconds = -1
			controller.setSnapshotLocked(ConnectionSnapshot{State: ConnectionClosed, Attempt: controller.snapshot.Attempt})
		}
		controller.closeDoneLocked()
		controller.mu.Unlock()
		return nil
	}
	if controller.closing {
		done := controller.done
		controller.mu.Unlock()
		select {
		case <-done:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	// Mark closing and detach the current session under the same lock that
	// publishes the closed state. This is the lifecycle linearization point:
	// no later scheduler step may begin an acquisition, even if cancellation
	// itself is temporarily blocked by an underlying runtime.
	controller.closing = true
	cancel := controller.cancel
	done := controller.done
	controller.closingSession = controller.currentSession
	controller.currentSession = nil
	controller.retryNotBeforeUnixMilliseconds = -1
	controller.setSnapshotLocked(ConnectionSnapshot{State: ConnectionClosed, Attempt: controller.snapshot.Attempt})
	if cancel != nil {
		cancel()
	}
	controller.mu.Unlock()
	select {
	case <-done:
		controller.mu.Lock()
		if controller.snapshot.State != ConnectionClosed {
			controller.setSnapshotLocked(ConnectionSnapshot{State: ConnectionClosed, Attempt: controller.snapshot.Attempt})
		}
		controller.mu.Unlock()
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type controllerSourceAcquireResult struct {
	lease   ArtifactLease
	failure *ArtifactSourceError
}

// acquire gives source delivery and controller cancellation one shared
// linearization point. A cancellation winner keeps ownership of any late
// lease, drains the source result, and performs the only legal claim/retire
// cleanup before the scheduler can finish closing.
func (controller *ConnectionController) acquire(ctx context.Context) (ArtifactLease, *ArtifactSourceError) {
	result := make(chan controllerSourceAcquireResult, 1)
	var gate atomic.Uint32 // 0 pending, 1 delivered, 2 cancellation
	go func() {
		var acquired controllerSourceAcquireResult
		if controller.beforeAcquireAdmission != nil {
			controller.beforeAcquireAdmission()
		}
		controller.mu.Lock()
		if controller.closing || controller.snapshot.State == ConnectionClosed || ctx.Err() != nil {
			controller.mu.Unlock()
			result <- acquired
			return
		}
		// Admission under the lifecycle lock is the acquisition start
		// linearization point. Close cannot publish closed before this decision;
		// once admitted, the source call belongs to the closing controller and
		// done remains open until its result and cleanup settle.
		controller.mu.Unlock()
		func() {
			defer func() {
				if recover() != nil {
					acquired.failure = NewTerminalArtifactSourceError(ErrInvalidArtifact)
				}
			}()
			acquired.lease, acquired.failure = controller.source.Acquire(ctx)
		}()
		if gate.CompareAndSwap(0, 1) {
			result <- acquired
			return
		}
		// Cancellation won. The source still owns the result and must drain it;
		// late errors are intentionally not exposed to the Controller.
		if acquired.lease.present() {
			if claimed, ok := acquired.lease.claimArtifact(); ok {
				_ = claimed.retire(ctx)
			}
		}
		result <- controllerSourceAcquireResult{}
	}()

	select {
	case acquired := <-result:
		return acquired.lease, acquired.failure
	case <-ctx.Done():
		if gate.CompareAndSwap(0, 2) {
			// Wait for source settlement and source-side cleanup so Close's done
			// channel is a complete ownership barrier.
			<-result
			return ArtifactLease{}, nil
		}
		// Delivery linearized first. The Controller owns the result and the
		// normal run loop will claim and retire it after observing cancellation.
		acquired := <-result
		return acquired.lease, acquired.failure
	}
}

func (controller *ConnectionController) run(ctx context.Context) {
	defer controller.finishRun()

	cycle := newControllerCycle()
	for {
		if ctx.Err() != nil || controller.isClosing() {
			controller.finishClosed()
			return
		}
		if controller.maximumAttempts != 0 && cycle.attempts >= controller.maximumAttempts {
			controller.fail(cycle.failureOrDefault(), terminalDisposition())
			return
		}
		cycle.attempts = saturatingControllerIncrement(cycle.attempts)
		controller.beginNextAttempt(cycle.attempts)
		lease, sourceFailure := controller.acquire(ctx)
		if sourceFailure != nil && lease.present() {
			claimed, claimedOK := lease.claimArtifact()
			if claimedOK {
				_ = claimed.retire(ctx)
			}
			if ctx.Err() != nil || controller.isClosing() {
				controller.finishClosed()
				return
			}
			controller.fail(&ConnectError{code: ConnectArtifactInvalid}, terminalDisposition())
			return
		}
		claimed, claimedOK := lease.claimArtifact()
		if ctx.Err() != nil || controller.isClosing() {
			if claimedOK {
				_ = claimed.retire(ctx)
			}
			controller.finishClosed()
			return
		}
		if sourceFailure != nil {
			cycle.consecutiveFailures = saturatingControllerIncrement(cycle.consecutiveFailures)
			cycle.lastFailure = projectArtifactSourceFailure(sourceFailure)
			disposition := sourceFailure.RetryDisposition()
			if !sourceFailure.valid() {
				cycle.lastFailure = &ConnectError{code: ConnectArtifactInvalid}
				disposition = terminalDisposition()
			}
			if !controller.handleFailure(ctx, cycle.lastFailure, disposition, cycle.consecutiveFailures, cycle.attempts) {
				return
			}
			continue
		}
		if !claimedOK || !claimed.valid() {
			controller.fail(&ConnectError{code: ConnectArtifactInvalid}, terminalDisposition())
			return
		}
		if cycle.mode == controllerAcquireReplacement {
			cycle.replacementUsed = true
		}
		if claimed.lease.artifact.value.Session.InitExpireAtUnixSeconds <= controller.clock.wallNow().Unix() {
			_ = claimed.retire(ctx)
			cycle.consecutiveFailures = saturatingControllerIncrement(cycle.consecutiveFailures)
			cycle.lastFailure = &ConnectError{code: ConnectExpired}
			cycle.mode = controllerAcquirePrimary
			if !controller.handleFailure(ctx, cycle.lastFailure, retryableDisposition(), cycle.consecutiveFailures, cycle.attempts) {
				return
			}
			continue
		}

		allowed, eligibilityErr := cycle.eligibleCandidates(claimed.lease.artifact.value)
		if eligibilityErr != nil {
			_ = claimed.retire(ctx)
			cycle.consecutiveFailures = saturatingControllerIncrement(cycle.consecutiveFailures)
			cycle.lastFailure = eligibilityErr
			controller.fail(eligibilityErr, terminalDisposition())
			return
		}

		var session Session
		var outcome controllerConnectOutcome
		if controller.connect != nil {
			session, outcome.err = controller.connect(ctx, claimed.lease, controller.options)
			outcome.spendStarted = claimed.spendStarted()
			if outcome.err != nil && !outcome.spendStarted {
				_ = claimed.retire(ctx)
			}
		} else if controller.connectDetailed != nil {
			session, outcome = controller.connectDetailed(ctx, claimed, controller.options, allowed)
			if outcome.err != nil && !outcome.spendStarted {
				_ = claimed.retire(ctx)
			}
		} else {
			session, outcome = connectForController(ctx, claimed, controller.options, allowed)
		}
		if ctx.Err() != nil {
			controller.finishClosed(session)
			return
		}
		if outcome.err != nil {
			cycle.consecutiveFailures = saturatingControllerIncrement(cycle.consecutiveFailures)
			cycle.lastFailure = outcome.err
			code := connectErrorCode(outcome.err)
			// The mandatory race-end expiry check is authoritative over any
			// candidate diagnostic collected before that boundary. In particular,
			// stale TLS diagnostics cannot turn an expired artifact into a policy
			// replacement attempt.
			if code == ConnectExpired {
				cycle.mode = controllerAcquirePrimary
			}
			if code != ConnectExpired && len(outcome.triggerCandidates) != 0 && !outcome.spendStarted {
				cycle.recordTriggers(claimed.lease.artifact.value, outcome)
				if cycle.mode == controllerAcquirePrimary && !cycle.replacementUsed &&
					(controller.maximumAttempts == 0 || cycle.attempts < controller.maximumAttempts) {
					cycle.mode = controllerAcquireReplacement
					continue
				}
				controller.fail(cycle.triggerFailure(), terminalDisposition())
				return
			}
			switch code {
			case ConnectArtifactInvalid:
				controller.fail(outcome.err, terminalDisposition())
				return
			}
			if outcome.spendStarted {
				cycle.mode = controllerAcquirePrimary
			}
			if cycle.mode == controllerAcquireReplacement && !outcome.spendStarted && code != ConnectExpired {
				controller.fail(cycle.triggerFailure(), terminalDisposition())
				return
			}
			switch code {
			case ConnectTransportSecurityUnsupported:
				controller.fail(outcome.err, terminalDisposition())
				return
			case ConnectTransportSecurityFailed:
				controller.fail(outcome.err, terminalDisposition())
				return
			}
			disposition := connectErrorDisposition(outcome.err)
			if outcome.hasDisposition {
				disposition = outcome.retryDisposition
			}
			if !controller.handleFailure(ctx, outcome.err, disposition, cycle.consecutiveFailures, cycle.attempts) {
				return
			}
			continue
		}
		if session == nil {
			controller.fail(&ConnectError{code: ConnectConnectionFailed}, terminalDisposition())
			return
		}

		cycle = newControllerCycle()
		if !controller.publishConnected(session) {
			_ = session.Close()
			controller.finishClosed()
			return
		}
		termination, waitErr := session.WaitTermination(ctx)
		if ctx.Err() != nil {
			controller.finishClosed()
			return
		}
		if controller.afterTerminationContextCheck != nil {
			controller.afterTerminationContextCheck()
		}
		controller.closeCurrentSession()
		var terminalError error
		var disposition RetryDisposition
		if waitErr != nil {
			terminalError = waitErr
			disposition = sessionErrorDisposition(waitErr)
		} else {
			terminalError = &termination.Error
			disposition = termination.Error.RetryDisposition()
		}
		cycle.consecutiveFailures = 1
		cycle.lastFailure = terminalError
		if !controller.handleFailure(ctx, terminalError, disposition, cycle.consecutiveFailures, cycle.attempts) {
			return
		}
	}
}

// finishRun settles every session still owned by the scheduler before it
// publishes done. Close may transfer currentSession to closingSession while the
// run loop is between its cancellation check and normal session settlement.
func (controller *ConnectionController) finishRun() {
	for {
		controller.mu.Lock()
		current := controller.closingSession
		if current == nil {
			current = controller.currentSession
		}
		controller.closingSession = nil
		controller.currentSession = nil
		if current == nil {
			controller.closeDoneLocked()
			controller.mu.Unlock()
			return
		}
		controller.mu.Unlock()
		_ = current.Close()
	}
}

func newControllerCycle() controllerCycle {
	return controllerCycle{
		mode:    controllerAcquirePrimary,
		blocked: make(map[blockedPinPolicy]struct{}),
	}
}

func (cycle *controllerCycle) failureOrDefault() error {
	if cycle != nil && cycle.lastFailure != nil {
		return cycle.lastFailure
	}
	return &ConnectError{code: ConnectConnectionFailed}
}

func (cycle *controllerCycle) triggerFailure() error {
	if cycle != nil && cycle.securityTrigger {
		return &ConnectError{code: ConnectTransportSecurityFailed}
	}
	return &ConnectError{code: ConnectConnectionFailed}
}

func (cycle *controllerCycle) recordTriggers(artifact *artifactv3.Artifact, outcome controllerConnectOutcome) {
	if cycle == nil || artifact == nil {
		return
	}
	cycle.replacementBasis = make(map[transportEndpointKey]artifactv3.Candidate, len(artifact.Path.Candidates))
	for _, candidate := range artifact.Path.Candidates {
		cycle.replacementBasis[endpointKey(artifact.Path.Kind, candidate)] = candidate
	}
	cycle.replacementFailed = make(map[transportEndpointKey]struct{}, len(outcome.failedEndpoints))
	for key := range outcome.failedEndpoints {
		cycle.replacementFailed[key] = struct{}{}
	}
	cycle.triggered = make(map[transportEndpointKey]artifactv3.Candidate, len(outcome.triggerCandidates))
	for key, candidate := range outcome.triggerCandidates {
		digest, err := artifactv3.TLSPolicyDigest(candidate.TLS)
		if err != nil {
			continue
		}
		cycle.triggered[key] = candidate
		cycle.blocked[blockedPinPolicy{endpoint: key, digest: digest}] = struct{}{}
	}
	cycle.securityTrigger = cycle.securityTrigger || outcome.securityFailure
	cycle.opaqueTrigger = cycle.opaqueTrigger || outcome.opaqueTrigger
}

func (cycle *controllerCycle) eligibleCandidates(artifact *artifactv3.Artifact) (map[transportEndpointKey]struct{}, error) {
	if cycle == nil || artifact == nil {
		return nil, &ConnectError{code: ConnectArtifactInvalid}
	}
	if cycle.mode == controllerAcquirePrimary {
		if len(cycle.blocked) == 0 {
			return nil, nil
		}
		allowed := make(map[transportEndpointKey]struct{}, len(artifact.Path.Candidates))
		for _, candidate := range artifact.Path.Candidates {
			key := endpointKey(artifact.Path.Kind, candidate)
			if cycle.candidateAllowed(key, candidate) {
				allowed[key] = struct{}{}
			}
		}
		if len(allowed) == 0 {
			return nil, cycle.triggerFailure()
		}
		return allowed, nil
	}

	allowed := make(map[transportEndpointKey]struct{}, len(artifact.Path.Candidates))
	changedPin := false
	for _, candidate := range artifact.Path.Candidates {
		key := endpointKey(artifact.Path.Kind, candidate)
		old, existed := cycle.replacementBasis[key]
		_, failed := cycle.replacementFailed[key]
		_, wasTriggered := cycle.triggered[key]
		changed := false
		if wasTriggered && candidate.TLS.Mode == artifactv3.TLSModePin {
			oldDigest, oldErr := artifactv3.TLSPolicyDigest(old.TLS)
			newDigest, newErr := artifactv3.TLSPolicyDigest(candidate.TLS)
			changed = oldErr == nil && newErr == nil && oldDigest != newDigest
			changedPin = changedPin || changed
		}
		inReplacementSet := changed || !existed || (existed && !failed)
		if inReplacementSet && cycle.candidateAllowed(key, candidate) {
			allowed[key] = struct{}{}
		}
	}
	if !changedPin || len(allowed) == 0 {
		return nil, cycle.triggerFailure()
	}
	return allowed, nil
}

func (cycle *controllerCycle) candidateAllowed(key transportEndpointKey, candidate artifactv3.Candidate) bool {
	triggeredEndpoint := false
	for blocked := range cycle.blocked {
		if blocked.endpoint != key {
			continue
		}
		triggeredEndpoint = true
		if candidate.TLS.Mode == artifactv3.TLSModeCA {
			return false
		}
		digest, err := artifactv3.TLSPolicyDigest(candidate.TLS)
		if err != nil || digest == blocked.digest {
			return false
		}
	}
	return !triggeredEndpoint || candidate.TLS.Mode == artifactv3.TLSModePin
}

func saturatingControllerIncrement(value uint64) uint64 {
	if value >= maxSafeControllerInteger {
		return maxSafeControllerInteger
	}
	return value + 1
}

func saturatingControllerAdd(value, delta uint64) uint64 {
	if value >= maxSafeControllerInteger || delta >= maxSafeControllerInteger-value {
		return maxSafeControllerInteger
	}
	return value + delta
}

func projectArtifactSourceFailure(sourceFailure *ArtifactSourceError) error {
	if sourceFailure == nil {
		return &ConnectError{code: ConnectArtifactInvalid}
	}
	var connectError *ConnectError
	if errors.As(sourceFailure.cause, &connectError) {
		return &ConnectError{code: connectError.Code()}
	}
	if errors.Is(sourceFailure.cause, ErrInvalidArtifact) {
		return &ConnectError{code: ConnectArtifactInvalid}
	}
	return &ConnectError{code: ConnectConnectionFailed}
}

func connectErrorCode(err error) ConnectErrorCode {
	var connectError *ConnectError
	if errors.As(err, &connectError) {
		return connectError.Code()
	}
	return ConnectConnectionFailed
}

func (controller *ConnectionController) handleFailure(
	ctx context.Context,
	err error,
	disposition RetryDisposition,
	failureOrdinal uint64,
	attemptsSinceConnected uint64,
) bool {
	if !disposition.valid() {
		err = &ConnectError{code: ConnectArtifactInvalid}
		disposition = terminalDisposition()
	}
	if disposition.Kind == RetryDispositionTerminal ||
		(controller.maximumAttempts != 0 && attemptsSinceConnected >= controller.maximumAttempts) {
		controller.failAtAttempt(err, terminalDisposition(), attemptsSinceConnected)
		return false
	}
	notBeforeUnixMilliseconds := int64(-1)
	if disposition.Kind == RetryDispositionRetryAfter {
		notBeforeUnixMilliseconds = disposition.RetryAtUnixMilliseconds
	}
	if !controller.wait(ctx, err, disposition, notBeforeUnixMilliseconds, connectionControllerBackoff(failureOrdinal), attemptsSinceConnected) {
		controller.finishClosed()
		return false
	}
	return true
}

func connectionControllerBackoff(failureOrdinal uint64) time.Duration {
	delay := defaults.ConnectionControllerInitialDelay
	for ordinal := uint64(1); ordinal < failureOrdinal && delay < defaults.ConnectionControllerMaxDelay; ordinal++ {
		if delay > defaults.ConnectionControllerMaxDelay/time.Duration(defaults.ConnectionControllerBackoffFactor) {
			return defaults.ConnectionControllerMaxDelay
		}
		delay *= time.Duration(defaults.ConnectionControllerBackoffFactor)
	}
	if delay > defaults.ConnectionControllerMaxDelay {
		return defaults.ConnectionControllerMaxDelay
	}
	return delay
}

func (controller *ConnectionController) wait(
	ctx context.Context,
	err error,
	disposition RetryDisposition,
	notBeforeUnixMilliseconds int64,
	backoff time.Duration,
	attempt uint64,
) bool {
	for {
		select {
		case <-controller.retry:
		default:
			goto drained
		}
	}
drained:
	controller.mu.Lock()
	controller.retryNotBeforeUnixMilliseconds = notBeforeUnixMilliseconds
	controller.setSnapshotLocked(ConnectionSnapshot{
		State: ConnectionWaiting, Attempt: attempt,
		Failure: connectionFailure(err, disposition),
	})
	controller.mu.Unlock()
	backoffMilliseconds := uint64(max(backoff/time.Millisecond, 0))
	monotonicDeadline := saturatingControllerAdd(
		controller.clock.monotonicNowMilliseconds(), backoffMilliseconds,
	)
	bypassBackoff := false
	for {
		monotonicNow := controller.clock.monotonicNowMilliseconds()
		wallNow := controller.clock.wallNow()
		backoffSatisfied := bypassBackoff || monotonicNow >= monotonicDeadline
		wallSatisfied := notBeforeUnixMilliseconds < 0 || wallNow.UnixMilli() >= notBeforeUnixMilliseconds
		if backoffSatisfied && wallSatisfied {
			controller.mu.Lock()
			controller.retryNotBeforeUnixMilliseconds = -1
			controller.mu.Unlock()
			return true
		}
		delayMilliseconds := uint64(0)
		if !backoffSatisfied {
			delayMilliseconds = monotonicDeadline - monotonicNow
		}
		delay := time.Duration(delayMilliseconds) * time.Millisecond
		if !wallSatisfied {
			wallDelayMilliseconds := controllerWallDelayMilliseconds(notBeforeUnixMilliseconds, wallNow.UnixMilli())
			wallDelay := time.Second
			if wallDelayMilliseconds < uint64(time.Second/time.Millisecond) {
				wallDelay = time.Duration(wallDelayMilliseconds) * time.Millisecond
			}
			if delay == 0 || wallDelay < delay {
				delay = wallDelay
			}
			if delay > time.Second {
				delay = time.Second
			}
		}
		timer := controller.clock.newTimer(delay)
		select {
		case <-ctx.Done():
			timer.stop()
			return false
		case <-controller.retry:
			timer.stop()
			if notBeforeUnixMilliseconds < 0 || controller.clock.wallNow().UnixMilli() >= notBeforeUnixMilliseconds {
				bypassBackoff = true
			}
		case <-timer.channel:
		}
	}
}

// controllerWallDelayMilliseconds computes a non-negative deadline delta
// without overflowing when an injected wall clock rolls back to a negative
// Unix-millisecond value.
func controllerWallDelayMilliseconds(deadline, now int64) uint64 {
	if now >= 0 {
		return uint64(deadline - now)
	}
	return uint64(deadline) + uint64(-(now + 1)) + 1
}

func (controller *ConnectionController) beginNextAttempt(attempt uint64) {
	controller.mu.Lock()
	controller.retryNotBeforeUnixMilliseconds = -1
	controller.setSnapshotLocked(ConnectionSnapshot{State: ConnectionConnecting, Attempt: attempt})
	controller.mu.Unlock()
}

func (controller *ConnectionController) publishConnected(session Session) bool {
	controller.mu.Lock()
	defer controller.mu.Unlock()
	if controller.closing || controller.snapshot.State == ConnectionClosed {
		return false
	}
	controller.currentSession = session
	controller.setSnapshotLocked(ConnectionSnapshot{State: ConnectionConnected, Attempt: controller.snapshot.Attempt, CurrentSession: session})
	return true
}

func (controller *ConnectionController) fail(err error, disposition RetryDisposition) {
	controller.mu.Lock()
	defer controller.mu.Unlock()
	controller.setFailureLocked(err, disposition, controller.snapshot.Attempt)
}

func (controller *ConnectionController) failAtAttempt(err error, disposition RetryDisposition, attempt uint64) {
	controller.mu.Lock()
	defer controller.mu.Unlock()
	controller.setFailureLocked(err, disposition, attempt)
}

func (controller *ConnectionController) setFailureLocked(err error, disposition RetryDisposition, attempt uint64) {
	controller.setSnapshotLocked(ConnectionSnapshot{
		State: ConnectionFailed, Attempt: attempt,
		Failure: connectionFailure(err, disposition),
	})
}

func (controller *ConnectionController) finishClosed(late ...Session) {
	controller.mu.Lock()
	current := controller.closingSession
	if current == nil {
		current = controller.currentSession
	}
	if current == nil && len(late) != 0 {
		current = late[0]
	}
	controller.closingSession = nil
	controller.currentSession = nil
	controller.retryNotBeforeUnixMilliseconds = -1
	controller.setSnapshotLocked(ConnectionSnapshot{State: ConnectionClosed, Attempt: controller.snapshot.Attempt})
	controller.mu.Unlock()
	if current != nil {
		_ = current.Close()
	}
}

func (controller *ConnectionController) closeCurrentSession() {
	controller.mu.Lock()
	current := controller.currentSession
	controller.currentSession = nil
	controller.mu.Unlock()
	if current != nil {
		_ = current.Close()
	}
}

func (controller *ConnectionController) isClosing() bool {
	controller.mu.Lock()
	defer controller.mu.Unlock()
	return controller.closing || controller.snapshot.State == ConnectionClosed
}

func (controller *ConnectionController) setSnapshotLocked(snapshot ConnectionSnapshot) {
	if controller.snapshot.State == ConnectionClosed {
		return
	}
	snapshot.revision = controller.snapshot.revision + 1
	controller.snapshot = snapshot
	close(controller.changed)
	controller.changed = make(chan struct{})
}

func (controller *ConnectionController) closeDoneLocked() {
	if !controller.doneClosed {
		close(controller.done)
		controller.doneClosed = true
	}
}

func copyConnectionSnapshot(snapshot ConnectionSnapshot) ConnectionSnapshot {
	copy := snapshot
	if snapshot.Failure != nil {
		failure := *snapshot.Failure
		copy.Failure = &failure
	}
	return copy
}

func connectionFailure(err error, disposition RetryDisposition) *ConnectionFailure {
	if err == nil {
		err = ErrConnectionFailed
	}
	return &ConnectionFailure{Error: err, Disposition: disposition}
}

func connectErrorDisposition(err error) RetryDisposition {
	var connectError *ConnectError
	if errors.As(err, &connectError) {
		return connectError.RetryDisposition()
	}
	return terminalDisposition()
}

func sessionErrorDisposition(err error) RetryDisposition {
	var sessionError *SessionError
	if errors.As(err, &sessionError) {
		return sessionError.RetryDisposition()
	}
	return terminalDisposition()
}

func (snapshot ConnectionSnapshot) String() string {
	return fmt.Sprintf("Flowersec.ConnectionSnapshot(state=%s, attempt=%d)", snapshot.State, snapshot.Attempt)
}
