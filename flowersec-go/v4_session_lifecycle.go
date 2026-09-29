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

type V4SessionInfo = protocolv4.V4SessionInfo

const (
	V4SessionRekeyInProgress SessionErrorCode = "rekey_in_progress"
	V4SessionTimeUnavailable SessionErrorCode = "time_unavailable"
)

// Info is the detached snapshot produced by the original authenticated READY
// transition. It remains available after Close and physical cleanup.
func (s *V4Session) Info() V4SessionInfo {
	if s == nil || s.info == nil {
		return V4SessionInfo{}
	}
	return s.info()
}

type V4DrainOutcome string

const (
	V4DrainPending         V4DrainOutcome = "pending"
	V4Drained              V4DrainOutcome = "drained"
	V4DrainDeadlineAborted V4DrainOutcome = "deadline_aborted"
	V4DrainFailed          V4DrainOutcome = "failed"
)

// V4DrainResult reports communication completion independently of cleanup.
type V4DrainResult struct {
	Outcome V4DrainOutcome
	Cause   *SessionError
}

func publicV4DrainResult(result sessionv4.DrainResult) V4DrainResult {
	outcome := V4DrainPending
	switch result.Outcome {
	case sessionv4.Drained:
		outcome = V4Drained
	case sessionv4.DrainDeadlineAborted:
		outcome = V4DrainDeadlineAborted
	case sessionv4.DrainFailed:
		outcome = V4DrainFailed
	}
	return V4DrainResult{Outcome: outcome, Cause: redactV4LifecycleError(result.Cause)}
}

// Drain starts the original Session operation once. Zero selects the admitted
// local policy; a positive timeout can only shorten that policy. Repeated calls
// keep the original boundary/deadline, including after communication finishes.
func (s *V4Session) Drain(timeoutMilliseconds uint64) error {
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
		return redactV4LifecycleError(err)
	}
	s.drainOperation = operation
	return nil
}

// WaitDrain observes the existing Drain. Canceling this wait leaves the
// original operation, accepted work, deadline, and physical tails untouched.
func (s *V4Session) WaitDrain(ctx context.Context) (V4DrainResult, error) {
	if s == nil || ctx == nil {
		return V4DrainResult{}, ErrTransportUnavailable
	}
	s.mu.Lock()
	operation := s.drainOperation
	s.mu.Unlock()
	if operation == nil {
		return V4DrainResult{}, ErrOperationClosed
	}
	result, err := operation.Wait(ctx)
	if err != nil {
		return publicV4DrainResult(operation.Result()), redactV4LifecycleError(err)
	}
	return publicV4DrainResult(result), nil
}

// Rekey joins one bounded caller reference to the existing Session rekey
// owner. Canceling the wait does not cancel another caller or a submitted,
// peer-requested, or security-required round.
func (s *V4Session) Rekey(ctx context.Context) error {
	if s == nil || s.rekey == nil || ctx == nil {
		return ErrTransportUnavailable
	}
	return lifecycleError(s.rekey(ctx))
}

// V4LivenessResult preserves the original sample's submission and elapsed
// facts. ElapsedMilliseconds includes local queueing and is not a network RTT.
// A false ElapsedAvailable means no continuous monotonic interval was proven.
type V4LivenessResult struct {
	Submitted, Complete, ElapsedAvailable bool
	ElapsedMilliseconds                   uint64
	Cause                                 *SessionError
}

func (s *V4Session) ProbeLiveness(ctx context.Context, timeoutMilliseconds uint64) (V4LivenessResult, error) {
	if s == nil || s.probeLiveness == nil || ctx == nil {
		return V4LivenessResult{}, ErrTransportUnavailable
	}
	result, err := s.probeLiveness(ctx, timeoutMilliseconds)
	return V4LivenessResult{Submitted: result.Submitted, Complete: result.Complete, ElapsedAvailable: result.ElapsedAvailable,
		ElapsedMilliseconds: result.ElapsedMS, Cause: redactV4LifecycleError(result.Cause)}, lifecycleError(err)
}

// WaitTermination waits on the original Session's terminal notification. It
// does not start Close, Drain, replacement connection, or cleanup work.
func (s *V4Session) WaitTermination(ctx context.Context) error {
	if s == nil || s.waitTermination == nil || ctx == nil {
		return ErrTransportUnavailable
	}
	return lifecycleError(s.waitTermination(ctx))
}

func lifecycleError(err error) error {
	if err == nil {
		return nil
	}
	return redactV4LifecycleError(err)
}

func redactV4LifecycleError(err error) *SessionError {
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
		code = V4SessionRekeyInProgress
	case errors.Is(err, timev4.ErrUnavailable), errors.Is(err, timev4.ErrContinuity):
		code = V4SessionTimeUnavailable
	case errors.Is(err, cryptov4.ErrRekey):
		code = SessionRekeyFailed
	case errors.Is(err, sessionv4.ErrLivenessPathUnresponsive), errors.Is(err, sessionv4.ErrProbeLocalStall):
		code = SessionLivenessFailed
	}
	return &SessionError{code: code}
}
