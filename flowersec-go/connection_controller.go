package flowersec

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/defaults"
)

var (
	ErrInvalidConnectionController = errors.New("invalid Flowersec connection controller")
)

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
func NewRetryAfterArtifactSourceError(cause error, retryAt time.Time) (*ArtifactSourceError, error) {
	if retryAt.IsZero() {
		return nil, ErrInvalidConnectionController
	}
	return newArtifactSourceError(cause, retryAfterDisposition(retryAt)), nil
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

// ConnectionController is the sole Flowersec session reconnect scheduler. It
// never migrates streams or replays RPC calls, writes, or application work.
type ConnectionController struct {
	source          ArtifactSource
	options         ConnectorOptions
	maximumAttempts uint64
	connect         connectionAttempt

	mu             sync.Mutex
	snapshot       ConnectionSnapshot
	changed        chan struct{}
	retry          chan struct{}
	retryNotBefore time.Time
	cancel         context.CancelFunc
	done           chan struct{}
	started        bool
	doneClosed     bool
}

// NewConnectionController creates an idle controller over a refreshable
// ArtifactSource.
func NewConnectionController(source ArtifactSource, options ConnectionControllerOptions) (*ConnectionController, error) {
	if source == nil || !validConnectorPolicy(options.Connector) {
		return nil, ErrInvalidConnectionController
	}
	if options.Connector.RPCHandlers != nil {
		options.Connector.RPCHandlers.freeze()
	}
	return &ConnectionController{
		source: source, options: options.Connector, maximumAttempts: options.MaximumAttempts, connect: Connect,
		snapshot: ConnectionSnapshot{State: ConnectionIdle},
		changed:  make(chan struct{}), retry: make(chan struct{}, 1), done: make(chan struct{}),
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
		(controller.retryNotBefore.IsZero() || !time.Now().Before(controller.retryNotBefore))
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
		if controller.snapshot.State != ConnectionClosed {
			controller.setSnapshotLocked(ConnectionSnapshot{State: ConnectionClosed, Attempt: controller.snapshot.Attempt})
		}
		controller.closeDoneLocked()
		controller.mu.Unlock()
		return nil
	}
	cancel := controller.cancel
	done := controller.done
	controller.mu.Unlock()
	if cancel != nil {
		cancel()
	}
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

func (controller *ConnectionController) run(ctx context.Context) {
	defer func() {
		controller.mu.Lock()
		controller.closeDoneLocked()
		controller.mu.Unlock()
	}()

	var consecutiveFailures uint64
	attemptsSinceConnected := uint64(1)
	for {
		if ctx.Err() != nil {
			controller.finishClosed()
			return
		}
		lease, sourceFailure := controller.source.Acquire(ctx)
		if ctx.Err() != nil {
			controller.finishClosed()
			return
		}
		if sourceFailure != nil {
			consecutiveFailures++
			if !controller.handleFailure(ctx, sourceFailure, sourceFailure.RetryDisposition(), consecutiveFailures, attemptsSinceConnected) {
				return
			}
			attemptsSinceConnected++
			controller.beginNextAttempt(attemptsSinceConnected)
			continue
		}
		if lease.artifact.value == nil || lease.state == nil {
			controller.fail(NewTerminalArtifactSourceError(ErrInvalidArtifact), terminalDisposition())
			return
		}
		if !lease.claimForConnectionController() {
			controller.fail(NewTerminalArtifactSourceError(errArtifactLeaseConsumed), terminalDisposition())
			return
		}

		session, err := controller.connect(ctx, lease, controller.options)
		if ctx.Err() != nil {
			if session != nil {
				_ = session.Close()
			}
			controller.finishClosed()
			return
		}
		if err != nil {
			consecutiveFailures++
			disposition := connectErrorDisposition(err)
			if !controller.handleFailure(ctx, err, disposition, consecutiveFailures, attemptsSinceConnected) {
				return
			}
			attemptsSinceConnected++
			controller.beginNextAttempt(attemptsSinceConnected)
			continue
		}
		if session == nil {
			controller.fail(&ConnectError{code: ConnectConnectionFailed}, terminalDisposition())
			return
		}

		consecutiveFailures = 0
		attemptsSinceConnected = 0
		controller.publishConnected(session)
		termination, waitErr := session.WaitTermination(ctx)
		if ctx.Err() != nil {
			controller.finishClosed()
			return
		}
		_ = session.Close()
		consecutiveFailures = 1
		var terminalError error
		var disposition RetryDisposition
		if waitErr != nil {
			terminalError = waitErr
			disposition = sessionErrorDisposition(waitErr)
		} else {
			terminalError = &termination.Error
			disposition = termination.Error.RetryDisposition()
		}
		if !controller.handleFailure(ctx, terminalError, disposition, consecutiveFailures, attemptsSinceConnected) {
			return
		}
		controller.beginNextAttempt(1)
		attemptsSinceConnected = 1
	}
}

func (controller *ConnectionController) handleFailure(
	ctx context.Context,
	err error,
	disposition RetryDisposition,
	failureOrdinal uint64,
	attemptsSinceConnected uint64,
) bool {
	if !disposition.valid() {
		disposition = terminalDisposition()
	}
	if disposition.Kind == RetryDispositionTerminal ||
		(controller.maximumAttempts != 0 && attemptsSinceConnected >= controller.maximumAttempts) {
		controller.fail(err, disposition)
		return false
	}
	now := time.Now()
	retryAt := now.Add(connectionControllerBackoff(failureOrdinal))
	var notBefore time.Time
	if disposition.Kind == RetryDispositionRetryAfter {
		notBefore = disposition.RetryAt
		if notBefore.After(retryAt) {
			retryAt = notBefore
		}
	}
	delay := retryAt.Sub(now)
	if delay < 0 {
		delay = 0
	}
	if !controller.wait(ctx, err, disposition, retryAt, notBefore, delay) {
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
	retryAt time.Time,
	notBefore time.Time,
	delay time.Duration,
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
	controller.retryNotBefore = notBefore
	controller.setSnapshotLocked(ConnectionSnapshot{
		State: ConnectionWaiting, Attempt: controller.snapshot.Attempt,
		Failure: connectionFailure(err, disposition),
	})
	controller.mu.Unlock()
	for {
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return false
		case <-controller.retry:
			timer.Stop()
			if notBefore.IsZero() || !time.Now().Before(notBefore) {
				return true
			}
			retryAt = notBefore
			delay = time.Until(notBefore)
			if delay < 0 {
				delay = 0
			}
		case <-timer.C:
			controller.mu.Lock()
			controller.retryNotBefore = time.Time{}
			controller.mu.Unlock()
			return true
		}
	}
}

func (controller *ConnectionController) beginNextAttempt(attempt uint64) {
	controller.mu.Lock()
	controller.retryNotBefore = time.Time{}
	controller.setSnapshotLocked(ConnectionSnapshot{State: ConnectionConnecting, Attempt: attempt})
	controller.mu.Unlock()
}

func (controller *ConnectionController) publishConnected(session Session) {
	controller.mu.Lock()
	controller.setSnapshotLocked(ConnectionSnapshot{State: ConnectionConnected, Attempt: controller.snapshot.Attempt, CurrentSession: session})
	controller.mu.Unlock()
}

func (controller *ConnectionController) fail(err error, disposition RetryDisposition) {
	controller.mu.Lock()
	controller.setSnapshotLocked(ConnectionSnapshot{
		State: ConnectionFailed, Attempt: controller.snapshot.Attempt,
		Failure: connectionFailure(err, disposition),
	})
	controller.mu.Unlock()
}

func (controller *ConnectionController) finishClosed() {
	controller.mu.Lock()
	current := controller.snapshot.CurrentSession
	controller.retryNotBefore = time.Time{}
	controller.setSnapshotLocked(ConnectionSnapshot{State: ConnectionClosed, Attempt: controller.snapshot.Attempt})
	controller.mu.Unlock()
	if current != nil {
		_ = current.Close()
	}
}

func (controller *ConnectionController) setSnapshotLocked(snapshot ConnectionSnapshot) {
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
