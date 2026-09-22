package protocolv4

import "math"

func sameTypedError(a, b *V4TypedError) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

// Validate checks a copied cursor snapshot, not a payload handoff. Transferred
// bytes remain historical facts after private backing has left this owner.
func (s V4ReaderCursorSnapshot) Validate() error {
	if s.TransferredBytes > s.Target || s.TransferredBytes > s.Offset || !validStreamStatus(s.StreamStatus) || !validTypedError(s.StreamError) || (s.StreamError != nil) != (s.StreamStatus == V4StreamStatusError) {
		return ErrInvalidAPIResult
	}
	if s.Delivered && (s.Closed || !s.Complete && !s.Frozen) {
		return ErrInvalidAPIResult
	}
	if s.TargetCause != nil {
		switch *s.TargetCause {
		case V4ReadCauseUnexpectedEof:
			if !s.Complete || s.StreamStatus != V4StreamStatusEof || s.TransferredBytes >= s.Target {
				return ErrInvalidAPIResult
			}
		case V4ReadCauseDelimiterNotFound:
			if !s.Complete || s.TransferredBytes != s.Target || s.Target == 0 {
				return ErrInvalidAPIResult
			}
		default:
			return ErrInvalidAPIResult
		}
	}
	return nil
}

// ReadMethodFailureContext is captured by the original method gate, separately
// from public metadata. It permits rejected method/argument combinations that
// are deliberately invalid ReadResultContext inputs. Reason is that gate's
// selected refusal; validation never rechecks authority or changes lifecycle.
type ReadMethodFailureContext struct {
	Reason                                       V4ReadMethodFailureReason
	CursorExists                                 bool
	StartOffset, TransferredBytes, Target        uint64
	StreamStatus                                 V4StreamStatus
	TargetCause                                  *V4ReadCause
	StreamError                                  *V4TypedError
	Complete, Frozen, Delivered, Closed, Waiting bool
}

func (f V4ReadMethodFailure) Validate(c ReadMethodFailureContext) error {
	// Native typed input still needs the enum/optional-value checks performed
	// by the reference schema before selecting its no-cursor branch.
	if !validStreamStatus(c.StreamStatus) || !validTypedError(c.StreamError) || c.TargetCause != nil && !validReadCause(*c.TargetCause) {
		return ErrInvalidAPIResult
	}
	switch f.Reason {
	case V4ReadMethodFailureReasonInvalidArgument, V4ReadMethodFailureReasonTargetMismatch,
		V4ReadMethodFailureReasonReadInProgress, V4ReadMethodFailureReasonPrefixFrozen,
		V4ReadMethodFailureReasonAlreadyDelivered, V4ReadMethodFailureReasonClosed,
		V4ReadMethodFailureReasonTimePending, V4ReadMethodFailureReasonTimeUnavailable,
		V4ReadMethodFailureReasonAuthorizationDenied, V4ReadMethodFailureReasonOwnerUnavailable:
	default:
		return ErrInvalidAPIResult
	}
	if f.Reason != c.Reason || (f.Cursor != nil) != c.CursorExists {
		return ErrInvalidAPIResult
	}
	if !c.CursorExists {
		if f.Reason != V4ReadMethodFailureReasonInvalidArgument && f.Reason != V4ReadMethodFailureReasonReadInProgress && f.Reason != V4ReadMethodFailureReasonOwnerUnavailable {
			return ErrInvalidAPIResult
		}
		return nil
	}
	s := f.Cursor
	if s.Validate() != nil || c.TransferredBytes > math.MaxUint64-c.StartOffset || s.Offset != c.StartOffset+c.TransferredBytes || s.TransferredBytes != c.TransferredBytes || s.Target != c.Target || s.StreamStatus != c.StreamStatus || !sameReadCause(s.TargetCause, c.TargetCause) || !sameTypedError(s.StreamError, c.StreamError) || s.Complete != c.Complete || s.Frozen != c.Frozen || s.Delivered != c.Delivered || s.Closed != c.Closed {
		return ErrInvalidAPIResult
	}
	switch f.Reason {
	case V4ReadMethodFailureReasonAlreadyDelivered:
		if !c.Delivered {
			return ErrInvalidAPIResult
		}
	case V4ReadMethodFailureReasonClosed:
		if !c.Closed || c.Delivered {
			return ErrInvalidAPIResult
		}
	case V4ReadMethodFailureReasonPrefixFrozen:
		if !c.Frozen || c.Closed || c.Delivered {
			return ErrInvalidAPIResult
		}
	case V4ReadMethodFailureReasonReadInProgress:
		if !c.Waiting || c.Delivered {
			return ErrInvalidAPIResult
		}
	case V4ReadMethodFailureReasonTimePending, V4ReadMethodFailureReasonTimeUnavailable:
		if c.Closed || c.Delivered {
			return ErrInvalidAPIResult
		}
	case V4ReadMethodFailureReasonAuthorizationDenied:
		if !c.Closed || c.Delivered {
			return ErrInvalidAPIResult
		}
	}
	return nil
}
