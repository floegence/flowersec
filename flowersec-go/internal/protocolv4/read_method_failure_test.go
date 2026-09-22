package protocolv4

import "testing"

func TestReadMethodFailureBindsOriginalMetadata(t *testing.T) {
	cause := V4ReadCauseUnexpectedEof
	s := V4ReaderCursorSnapshot{Offset: 103, TransferredBytes: 3, Target: 8, StreamStatus: V4StreamStatusEof, TargetCause: &cause, Complete: true}
	c := ReadMethodFailureContext{Reason: V4ReadMethodFailureReasonTimePending, CursorExists: true, StartOffset: 100, TransferredBytes: 3, Target: 8, StreamStatus: V4StreamStatusEof, TargetCause: &cause, Complete: true}
	f := V4ReadMethodFailure{Reason: c.Reason, Cursor: &s}
	if err := f.Validate(c); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*V4ReaderCursorSnapshot){
		func(s *V4ReaderCursorSnapshot) { s.Offset = 3 },
		func(s *V4ReaderCursorSnapshot) { s.Target = 9 },
		func(s *V4ReaderCursorSnapshot) { s.TransferredBytes = 2 },
		func(s *V4ReaderCursorSnapshot) { s.StreamStatus = V4StreamStatusOpen },
		func(s *V4ReaderCursorSnapshot) { s.TargetCause = nil },
		func(s *V4ReaderCursorSnapshot) { s.Complete = false },
		func(s *V4ReaderCursorSnapshot) { s.Frozen = true },
		func(s *V4ReaderCursorSnapshot) { s.Delivered = true },
		func(s *V4ReaderCursorSnapshot) { s.Closed = true },
	} {
		changed := s
		mutate(&changed)
		if err := (V4ReadMethodFailure{Reason: c.Reason, Cursor: &changed}).Validate(c); err == nil {
			t.Fatal("changed original fact accepted", changed)
		}
	}
	c.StartOffset = ^uint64(0)
	if f.Validate(c) == nil {
		t.Fatal("offset overflow accepted")
	}
}

func TestReadResultCannotSubstituteAnotherRegisteredError(t *testing.T) {
	original := V4TypedError{Code: V4ErrorCodeStreamDataInvalid, Scope: V4ErrorScopeStream, RetryDisposition: V4RetryDispositionPreserveFacts}
	other := original
	other.Code = V4ErrorCodeStreamSequenceError
	maximum := uint64(1)
	c := ReadResultContext{Method: "read", Transferred: 1, MaxBytes: &maximum, StreamStatus: V4StreamStatusError, StreamError: &original}
	r := V4ReadResult{Data: []byte("x"), Progress: V4ReadProgress{Offset: 1, Filled: 1}, WaitStatus: V4WaitStatusReady, StreamStatus: V4StreamStatusError, Error: &original}
	if err := r.Validate(c); err != nil {
		t.Fatal(err)
	}
	r.Error = &other
	if r.Validate(c) == nil {
		t.Fatal("registered but unrelated error substituted")
	}
}
