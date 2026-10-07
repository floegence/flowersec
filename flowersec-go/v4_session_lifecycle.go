package flowersec

import (
	"context"
	"errors"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

type SessionInfo = protocolv4.V4SessionInfo

const (
	SessionRekeyInProgress SessionErrorCode = "rekey_in_progress"
	SessionTimeUnavailable SessionErrorCode = "time_unavailable"
)

// Info is the detached snapshot produced by the original authenticated READY
// transition. It remains available after Close and physical cleanup.
func (s *Session) Info() SessionInfo {
	if s == nil || s.info == nil {
		return SessionInfo{}
	}
	return s.info()
}

type DrainOutcome string

const (
	DrainPending         DrainOutcome = "pending"
	Drained              DrainOutcome = "drained"
	DrainDeadlineAborted DrainOutcome = "deadline_aborted"
	DrainFailed          DrainOutcome = "failed"
)

// DrainResult reports communication completion independently of cleanup.
type DrainResult struct {
	Outcome DrainOutcome
	Cause   *SessionError
}

func publicDrainResult(result sessionv4.DrainResult) DrainResult {
	outcome := DrainPending
	switch result.Outcome {
	case sessionv4.Drained:
		outcome = Drained
	case sessionv4.DrainDeadlineAborted:
		outcome = DrainDeadlineAborted
	case sessionv4.DrainFailed:
		outcome = DrainFailed
	}
	return DrainResult{Outcome: outcome, Cause: redactLifecycleError(result.Cause)}
}

// Drain starts the original Session operation once. Zero selects the admitted
// local policy; a positive timeout can only shorten that policy. Repeated calls
// keep the original boundary/deadline, including after communication finishes.
func (s *Session) Drain(timeoutMilliseconds uint64) error {
	if s == nil || s.drain == nil {
		return ErrTransportUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.drainOperation != nil {
		return nil
	}
	operation, err := s.drain(timeoutMilliseconds, 0)
	if err != nil {
		return redactLifecycleError(err)
	}
	s.drainOperation = operation
	return nil
}

// WaitDrain observes the existing Drain. Canceling this wait leaves the
// original operation, accepted work, deadline, and physical tails untouched.
func (s *Session) WaitDrain(ctx context.Context) (DrainResult, error) {
	if s == nil || ctx == nil {
		return DrainResult{}, ErrTransportUnavailable
	}
	s.mu.Lock()
	operation := s.drainOperation
	s.mu.Unlock()
	if operation == nil {
		return DrainResult{}, ErrOperationClosed
	}
	result, err := operation.Wait(ctx)
	if err != nil {
		return publicDrainResult(operation.Result()), redactLifecycleError(err)
	}
	return publicDrainResult(result), nil
}

// Rekey joins one bounded caller reference to the existing Session rekey
// owner. Canceling the wait does not cancel another caller or a submitted,
// peer-requested, or security-required round.
func (s *Session) Rekey(ctx context.Context) error {
	if s == nil || s.rekey == nil || ctx == nil {
		return ErrTransportUnavailable
	}
	return lifecycleError(s.rekey(ctx))
}

// LivenessResult preserves the original sample's submission and elapsed
// facts. ElapsedMilliseconds includes local queueing and is not a network RTT.
// A false ElapsedAvailable means no continuous monotonic interval was proven.
type LivenessResult struct {
	Submitted, Complete, ElapsedAvailable bool
	ElapsedMilliseconds                   uint64
	Cause                                 *SessionError
}

func (s *Session) ProbeLiveness(ctx context.Context, timeoutMilliseconds uint64) (LivenessResult, error) {
	if s == nil || s.probeLiveness == nil || ctx == nil {
		return LivenessResult{}, ErrTransportUnavailable
	}
	result, err := s.probeLiveness(ctx, timeoutMilliseconds)
	return LivenessResult{Submitted: result.Submitted, Complete: result.Complete, ElapsedAvailable: result.ElapsedAvailable,
		ElapsedMilliseconds: result.ElapsedMS, Cause: redactLifecycleError(result.Cause)}, lifecycleError(err)
}

// WaitTermination waits on the original Session's terminal notification. It
// does not start Close, Drain, replacement connection, or cleanup work.
func (s *Session) WaitTermination(ctx context.Context) error {
	if s == nil || s.waitTermination == nil || ctx == nil {
		return ErrTransportUnavailable
	}
	return lifecycleError(s.waitTermination(ctx))
}

func lifecycleError(err error) error {
	if err == nil {
		return nil
	}
	return redactLifecycleError(err)
}

func redactLifecycleError(err error) *SessionError {
	if err == nil {
		return nil
	}
	code := SessionOperationFailed
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, sessionv4.ErrRekeyCancelled):
		code = SessionCanceled
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, timev4.ErrExpired), errors.Is(err, cryptov4.ErrExpired), errors.Is(err, sessionv4.ErrDrainDeadline):
		code = SessionTimeout
	case errors.Is(err, cryptov4.ErrClosed), errors.Is(err, resourcev4.ErrClosed), errors.Is(err, sessionv4.ErrPeerClosed):
		code = SessionClosed
	case errors.Is(err, sessionv4.ErrSessionDraining):
		code = SessionGoingAway
	case errors.Is(err, cryptov4.ErrCapacity), errors.Is(err, resourcev4.ErrCapacity):
		code = SessionResourceExhausted
	case errors.Is(err, sessionv4.ErrProbeRekey):
		code = SessionRekeyInProgress
	case errors.Is(err, timev4.ErrUnavailable), errors.Is(err, timev4.ErrContinuity):
		code = SessionTimeUnavailable
	case errors.Is(err, cryptov4.ErrRekey):
		code = SessionRekeyFailed
	case errors.Is(err, sessionv4.ErrLivenessPathUnresponsive), errors.Is(err, sessionv4.ErrProbeLocalStall):
		code = SessionLivenessFailed
	}
	return &SessionError{code: code}
}
