package protocolv4

import (
	"bytes"
	"errors"
	"math"
)

// ErrInvalidAPIResult is returned when a generated v4 result violates the
// cross-field matrix from the public API schema. Validation is intentionally
// pure: it does not inspect transport state or infer missing ownership facts.
var ErrInvalidAPIResult = errors.New("protocolv4: invalid API result")

func validReadCause(cause V4ReadCause) bool {
	return cause == V4ReadCauseDelimiterNotFound || cause == V4ReadCauseUnexpectedEof
}

func validTypedError(err *V4TypedError) bool {
	if err == nil {
		return true
	}
	if err.RetryDisposition != V4RetryDispositionPreserveFacts {
		return false
	}
	switch err.Code {
	case V4ErrorCodeProtocolViolation, V4ErrorCodeFramingError,
		V4ErrorCodeAuthenticationFailed, V4ErrorCodeSequenceError,
		V4ErrorCodeReplayDetected, V4ErrorCodeCryptoFailure,
		V4ErrorCodeRekeyFailed, V4ErrorCodeResourceExhausted:
		return err.Scope == V4ErrorScopeSession
	case V4ErrorCodeStreamSequenceError, V4ErrorCodeStreamDataInvalid:
		return err.Scope == V4ErrorScopeStream
	default:
		return false
	}
}

func validStreamStatus(status V4StreamStatus) bool {
	return status == V4StreamStatusOpen || status == V4StreamStatusEof ||
		status == V4StreamStatusAborted || status == V4StreamStatusError
}

func (err V4TypedError) Validate() error {
	if !validTypedError(&err) {
		return ErrInvalidAPIResult
	}
	return nil
}

func (progress V4ReadProgress) Validate() error {
	if progress.Filled > progress.Offset || progress.Target != nil && progress.Filled > *progress.Target {
		return ErrInvalidAPIResult
	}
	return nil
}

// ReadResultContext contains private facts established at the original read
// owner's handoff gate. It is neither a public result nor peer-supplied input.
// Method and CursorKind use the closed enums in api_schema.contexts.
type ReadResultContext struct {
	Method, CursorKind       string
	StartOffset, Transferred uint64
	StreamStatus             V4StreamStatus
	StreamError              *V4TypedError
	MaxBytes, Target         *uint64
	Delimiter                []byte
	TargetCause              *V4ReadCause
}

func (c ReadResultContext) validate() (ordinary bool, err error) {
	if !validStreamStatus(c.StreamStatus) || c.Transferred > math.MaxUint64-c.StartOffset || c.TargetCause != nil && !validReadCause(*c.TargetCause) {
		return false, ErrInvalidAPIResult
	}
	ordinary = c.Method == "read" || c.Method == "read_chunk"
	if ordinary {
		if c.MaxBytes == nil || *c.MaxBytes == 0 || c.Transferred > *c.MaxBytes || c.CursorKind != "" || c.Target != nil || c.Delimiter != nil || c.TargetCause != nil {
			return false, ErrInvalidAPIResult
		}
		return true, nil
	}
	if c.MaxBytes != nil || c.Target == nil || c.Transferred > *c.Target || c.Method != "take_prefix" && c.TargetCause != nil {
		return false, ErrInvalidAPIResult
	}
	switch c.CursorKind {
	case "exact":
		if c.Delimiter != nil || c.Method != "read_exactly" && c.Method != "take_prefix" {
			return false, ErrInvalidAPIResult
		}
	case "until":
		if c.Method != "read_until" && c.Method != "read_line" && c.Method != "take_prefix" || len(c.Delimiter) == 0 || len(c.Delimiter) > 32 || uint64(len(c.Delimiter)) > *c.Target || c.Method == "read_line" && !bytes.Equal(c.Delimiter, []byte{'\n'}) {
			return false, ErrInvalidAPIResult
		}
	default:
		return false, ErrInvalidAPIResult
	}
	if c.TargetCause != nil {
		if *c.TargetCause == V4ReadCauseDelimiterNotFound && (c.CursorKind != "until" || c.Transferred != *c.Target) || *c.TargetCause == V4ReadCauseUnexpectedEof && (c.StreamStatus != V4StreamStatusEof || c.Transferred >= *c.Target) {
			return false, ErrInvalidAPIResult
		}
	}
	return false, nil
}

func sameReadCause(a, b *V4ReadCause) bool {
	return a == nil && b == nil || a != nil && b != nil && *a == *b
}

// Validate checks both the result matrix and its binding to the original read
// method, target and transfer frontier. It does not perform an ownership handoff.
func (result V4ReadResult) Validate(context ReadResultContext) error {
	ordinary, err := context.validate()
	if err != nil {
		return err
	}
	if !validStreamStatus(result.StreamStatus) ||
		result.Progress.Filled > result.Progress.Offset ||
		(result.Progress.Target != nil && result.Progress.Filled > *result.Progress.Target) ||
		uint64(len(result.Data)) != result.Progress.Filled || !validTypedError(result.Error) ||
		result.Progress.Offset != context.StartOffset+context.Transferred || result.StreamStatus != context.StreamStatus {
		return ErrInvalidAPIResult
	}
	if (result.Error != nil) != (result.StreamStatus == V4StreamStatusError) || !sameTypedError(result.Error, context.StreamError) {
		return ErrInvalidAPIResult
	}
	if ordinary && result.Progress.Target != nil || !ordinary && (result.Progress.Target == nil || *result.Progress.Target != *context.Target) {
		return ErrInvalidAPIResult
	}
	if (ordinary || result.WaitStatus == V4WaitStatusReady) && result.Progress.Filled != context.Transferred {
		return ErrInvalidAPIResult
	}
	if result.Cause != nil && (ordinary || !validReadCause(*result.Cause)) {
		return ErrInvalidAPIResult
	}
	switch result.WaitStatus {
	case V4WaitStatusReady:
		emptyGoal := !ordinary && (context.Method == "take_prefix" || context.CursorKind == "exact" && *context.Target == 0)
		if len(result.Data) == 0 && result.StreamStatus == V4StreamStatusOpen && !emptyGoal {
			return ErrInvalidAPIResult
		}
		if !ordinary {
			return result.validateGoal(context)
		}
	case V4WaitStatusBlocked, V4WaitStatusWaitCanceled:
		if len(result.Data) != 0 || result.StreamStatus != V4StreamStatusOpen || result.Cause != nil {
			return ErrInvalidAPIResult
		}
	default:
		return ErrInvalidAPIResult
	}
	return nil
}

func (result V4ReadResult) validateGoal(c ReadResultContext) error {
	completed := c.CursorKind == "exact" && c.Transferred == *c.Target
	if c.CursorKind == "until" {
		if i := bytes.Index(result.Data, c.Delimiter); i >= 0 {
			if i+len(c.Delimiter) != len(result.Data) {
				return ErrInvalidAPIResult
			}
			completed = true
		}
	}
	if !completed && c.CursorKind == "until" && c.Transferred == *c.Target && (result.Cause == nil || *result.Cause != V4ReadCauseDelimiterNotFound) {
		return ErrInvalidAPIResult
	}
	var expected *V4ReadCause
	switch {
	case c.Method == "take_prefix":
		expected = c.TargetCause
	case completed:
	case c.Transferred == *c.Target:
		cause := V4ReadCauseDelimiterNotFound
		expected = &cause
	case result.StreamStatus == V4StreamStatusEof:
		cause := V4ReadCauseUnexpectedEof
		expected = &cause
	case result.StreamStatus != V4StreamStatusAborted && result.StreamStatus != V4StreamStatusError:
		return ErrInvalidAPIResult
	}
	if !sameReadCause(result.Cause, expected) {
		return ErrInvalidAPIResult
	}
	if result.Cause != nil {
		if completed || *result.Cause == V4ReadCauseDelimiterNotFound && (c.CursorKind != "until" || c.Transferred != *c.Target) || *result.Cause == V4ReadCauseUnexpectedEof && (result.StreamStatus != V4StreamStatusEof || c.Transferred >= *c.Target) {
			return ErrInvalidAPIResult
		}
	}
	return nil
}

// Validate checks actual cleanup facts independently of the owner's lifecycle.
func (status V4CleanupStatus) Validate() error {
	if status.CoreCleanup != V4CoreCleanupPending && status.CoreCleanup != V4CoreCleanupComplete {
		return ErrInvalidAPIResult
	}
	if status.Status != V4CleanupStatePending && status.Status != V4CleanupStateComplete && status.Status != V4CleanupStateCleanupIncomplete {
		return ErrInvalidAPIResult
	}
	complete := status.CoreCleanup == V4CoreCleanupComplete && status.PendingCallbacks == 0
	if (status.Status == V4CleanupStateComplete) != complete {
		return ErrInvalidAPIResult
	}
	return nil
}

// Validate checks the bounded write progress projection independently from the
// actual provider tail. Accepted bytes may never exceed the request, and a
// terminal reason is only present after the operation reaches terminal phase.
func (progress V4WriteProgress) Validate() error {
	if progress.AcceptedBytes > progress.RequestedBytes || progress.CleanupStatus.Validate() != nil {
		return ErrInvalidAPIResult
	}
	switch progress.Phase {
	case V4WritePhasePrepared, V4WritePhaseRunning:
		if progress.TerminalReason != V4WriteTerminalReasonNone {
			return ErrInvalidAPIResult
		}
	case V4WritePhaseTerminal:
		switch progress.TerminalReason {
		case V4WriteTerminalReasonComplete, V4WriteTerminalReasonCanceled,
			V4WriteTerminalReasonDeadlineExceeded, V4WriteTerminalReasonQueueFull,
			V4WriteTerminalReasonStreamTerminated, V4WriteTerminalReasonFailed:
		default:
			return ErrInvalidAPIResult
		}
	default:
		return ErrInvalidAPIResult
	}
	if (progress.Phase == V4WritePhasePrepared || progress.TerminalReason == V4WriteTerminalReasonQueueFull) && progress.AcceptedBytes != 0 ||
		progress.TerminalReason == V4WriteTerminalReasonComplete && progress.AcceptedBytes != progress.RequestedBytes ||
		progress.Phase != V4WritePhaseTerminal && progress.CleanupStatus.Status == V4CleanupStateComplete {
		return ErrInvalidAPIResult
	}
	return nil
}

// Validate checks the current native close projection. Cleanup completion and
// directional proof facts are independent; neither a local close nor an error
// implies send_drained or invents a read terminal.
func (result V4CloseResult) Validate() error {
	if result.Direction != V4DirectionC2s && result.Direction != V4DirectionS2c {
		return ErrInvalidAPIResult
	}
	switch result.ReadTerminal {
	case V4ReadTerminalOpen, V4ReadTerminalEof, V4ReadTerminalAbandoned, V4ReadTerminalUnknown:
	default:
		return ErrInvalidAPIResult
	}
	if result.CleanupStatus.Validate() != nil || !validTypedError(result.FirstError) {
		return ErrInvalidAPIResult
	}
	return nil
}
