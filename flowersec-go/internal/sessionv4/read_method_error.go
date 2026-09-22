package sessionv4

import (
	"context"
	"errors"
	"io"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

var ErrReadAuthorizationDenied = errors.New("sessionv4: read delivery authorization denied")
var ErrReadOwnerUnavailable = errors.New("sessionv4: read owner unavailable")

// A detached method error retains only finite SDK identities. It never keeps a
// provider error chain (which could retain arbitrary backing or the Session).
var readMethodIdentities = [...]error{
	ErrCursorTarget, ErrCursorFrozen, ErrCursorClosed, ErrAlreadyDelivered, ErrReadInProgress,
	ErrFlowClosed, ErrReadAuthorizationDenied, ErrReadOwnerUnavailable,
	ErrStreamOwned, ErrStreamOwnershipBusy, ErrNativeTCPClosed, ErrNativeTCPFailure,
	resourcev4.ErrClosed, resourcev4.ErrOwner, resourcev4.ErrCapacity, resourcev4.ErrConfiguration,
	timev4.ErrPending, timev4.ErrUnavailable, timev4.ErrExpired, timev4.ErrContinuity,
	cryptov4.ErrClosed, cryptov4.ErrExpired, cryptov4.ErrNotReady, cryptov4.ErrTransition,
	ErrAbandoned, ErrStreamData, ErrCredit, ErrTerminal,
	cryptov4.ErrAuthentication, cryptov4.ErrSequence, cryptov4.ErrEpoch,
	cryptov4.ErrScope, cryptov4.ErrUsage, cryptov4.ErrCapacity, cryptov4.ErrConfiguration,
	cryptov4.ErrRekey, cryptov4.ErrIdle, cryptov4.ErrInputPending,
	io.ErrUnexpectedEOF, io.EOF, io.ErrClosedPipe, io.ErrNoProgress,
	context.Canceled, context.DeadlineExceeded,
	protocolv4.ErrTruncated, protocolv4.ErrPayloadTooLarge, protocolv4.ErrInvalidFlags,
	protocolv4.ErrUnknownFrame, protocolv4.ErrRecordScope, protocolv4.ErrRecordDirection,
}

// sourceReadError preserves the finite SDK identity of an already committed
// direction failure. Arbitrary provider/application chains are not retained in
// a detached cursor or returned payload owner.
type sourceReadError uint64

func (e sourceReadError) Error() string { return "sessionv4: read direction terminated" }
func (e sourceReadError) Is(target error) bool {
	return (&ReadMethodError{identities: uint64(e)}).Is(target)
}

func boundedReadCause(err error) error {
	if err == nil {
		return nil
	}
	bits := methodIdentities(err)
	if bits == 0 {
		bits = methodIdentities(ErrReadOwnerUnavailable)
	}
	return sourceReadError(bits)
}

// ReadMethodError means this invocation did not produce a ReadResult. The value
// result is zero and must not be serialized as an empty read. Metadata reports
// the original cursor's facts without another payload alias or wait status.
type ReadMethodError struct {
	metadata   protocolv4.V4ReadMethodFailure
	identities uint64
}

func (e *ReadMethodError) Error() string {
	return "sessionv4: read method " + string(e.metadata.Reason)
}
func (e *ReadMethodError) Is(target error) bool {
	for i, identity := range readMethodIdentities {
		if target == identity && e.identities&(uint64(1)<<i) != 0 {
			return true
		}
	}
	return false
}

func (e *ReadMethodError) Metadata() protocolv4.V4ReadMethodFailure {
	m := e.metadata
	if m.Cursor != nil {
		snapshot := *m.Cursor
		if snapshot.TargetCause != nil {
			cause := *snapshot.TargetCause
			snapshot.TargetCause = &cause
		}
		if snapshot.StreamError != nil {
			cause := *snapshot.StreamError
			snapshot.StreamError = &cause
		}
		m.Cursor = &snapshot
	}
	return m
}

func methodIdentities(err error) uint64 {
	// This runs under original owner gates. Unknown provider Is/Unwrap methods
	// are application code and must never execute here, even to classify errors.
	switch owned := err.(type) {
	case sourceReadError:
		return uint64(owned)
	case *ReadMethodError:
		return owned.identities
	}
	var bits uint64
	for i, identity := range readMethodIdentities {
		if err == identity {
			bits |= uint64(1) << i
		}
	}
	return bits
}

func cursorConstructionError(err error) error {
	reason := protocolv4.V4ReadMethodFailureReasonOwnerUnavailable
	if errors.Is(err, ErrCursorTarget) {
		reason = protocolv4.V4ReadMethodFailureReasonInvalidArgument
	}
	if errors.Is(err, ErrReadInProgress) {
		reason = protocolv4.V4ReadMethodFailureReasonReadInProgress
	}
	return &ReadMethodError{metadata: protocolv4.V4ReadMethodFailure{Reason: reason}, identities: methodIdentities(err)}
}

func methodFailureReason(err error) protocolv4.V4ReadMethodFailureReason {
	switch {
	case errors.Is(err, timev4.ErrPending):
		return protocolv4.V4ReadMethodFailureReasonTimePending
	case errors.Is(err, timev4.ErrUnavailable):
		return protocolv4.V4ReadMethodFailureReasonTimeUnavailable
	case errors.Is(err, ErrCursorClosed):
		return protocolv4.V4ReadMethodFailureReasonClosed
	case errors.Is(err, resourcev4.ErrClosed), errors.Is(err, resourcev4.ErrOwner), errors.Is(err, resourcev4.ErrCapacity), errors.Is(err, ErrFlowClosed), errors.Is(err, ErrStreamOwned), errors.Is(err, ErrStreamOwnershipBusy), errors.Is(err, cryptov4.ErrClosed), errors.Is(err, cryptov4.ErrNotReady), errors.Is(err, cryptov4.ErrTransition):
		return protocolv4.V4ReadMethodFailureReasonOwnerUnavailable
	default:
		return protocolv4.V4ReadMethodFailureReasonAuthorizationDenied
	}
}

func (c *ReaderCursor) snapshotLocked() protocolv4.V4ReaderCursorSnapshot {
	s := protocolv4.V4ReaderCursorSnapshot{Offset: c.start + c.filled, TransferredBytes: c.filled, Target: c.target.limit, StreamStatus: c.status, Complete: c.complete, Frozen: c.frozen, Delivered: c.delivered, Closed: c.closed}
	if c.cause != "" {
		cause := c.cause
		s.TargetCause = &cause
	}
	return s
}

func (c *ReaderCursor) methodFailureLocked(reason protocolv4.V4ReadMethodFailureReason, err error) (protocolv4.V4ReadResult, error) {
	s := c.snapshotLocked()
	bits := methodIdentities(err)
	if reason == protocolv4.V4ReadMethodFailureReasonAuthorizationDenied {
		bits |= methodIdentities(ErrReadAuthorizationDenied)
	}
	if reason == protocolv4.V4ReadMethodFailureReasonOwnerUnavailable {
		bits |= methodIdentities(ErrReadOwnerUnavailable)
	}
	if c.closed {
		bits |= c.closeIdentities
	}
	return protocolv4.V4ReadResult{}, &ReadMethodError{metadata: protocolv4.V4ReadMethodFailure{Reason: reason, Cursor: &s}, identities: bits}
}
