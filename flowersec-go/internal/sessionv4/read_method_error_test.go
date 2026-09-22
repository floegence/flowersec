package sessionv4

import (
	"context"
	"errors"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"io"
	"reflect"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

func validateCursorFailure(t *testing.T, c *ReaderCursor, result protocolv4.V4ReadResult, err error, reason protocolv4.V4ReadMethodFailureReason) protocolv4.V4ReadMethodFailure {
	t.Helper()
	if !reflect.DeepEqual(result, protocolv4.V4ReadResult{}) {
		t.Fatal("method failure produced a phantom ReadResult", result)
	}
	var failure *ReadMethodError
	if !errors.As(err, &failure) {
		t.Fatal("missing bounded native failure", err)
	}
	m := failure.Metadata()
	c.mu.Lock()
	context := protocolv4.ReadMethodFailureContext{Reason: reason, CursorExists: true, StartOffset: c.start, TransferredBytes: c.filled, Target: c.target.limit, StreamStatus: c.status, Complete: c.complete, Frozen: c.frozen, Delivered: c.delivered, Closed: c.closed, Waiting: c.waiting}
	if c.cause != "" {
		cause := c.cause
		context.TargetCause = &cause
	}
	c.mu.Unlock()
	if err := m.Validate(context); err != nil {
		t.Fatal("native method failure violates shared schema", m, context, err)
	}
	return m
}

func TestReadMethodFailurePreservesNonzeroEOFAndOneTimePayload(t *testing.T) {
	f := readFlow(t)
	wire := newFlowTransport(t)
	if err := wire.data(t, f, 0, false, "lead"); err != nil {
		t.Fatal(err)
	}
	var lead [4]byte
	if n, _, err := f.TryRead(lead[:]); n != 4 || err != nil {
		t.Fatal(n, err)
	}
	target, _ := exactCursorTarget(8, 8)
	guard := &cursorTestAuthorization{wake: make(chan struct{}, 1)}
	c, _ := testReaderCursor(t, f, target, guard)
	if err := wire.data(t, f, 4, true, "abc"); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	_, err := c.advanceLocked(true)
	c.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	guard.status.Store(1)
	r, err := c.ReadExactly(context.Background())
	m := validateCursorFailure(t, c, r, err, protocolv4.V4ReadMethodFailureReasonTimePending)
	if m.Cursor.Offset != 7 || m.Cursor.TransferredBytes != 3 || m.Cursor.StreamStatus != protocolv4.V4StreamStatusEof {
		t.Fatal(m)
	}
	// Returned snapshots are independent metadata; mutating one cannot alter
	// the error owner, retained candidate or later delivery.
	m.Cursor.Offset = 0
	*m.Cursor.TargetCause = protocolv4.V4ReadCauseDelimiterNotFound
	guard.status.Store(0)
	r, err = c.ReadExactly(context.Background())
	if err != nil || string(r.Data) != "abc" {
		t.Fatal(r, err)
	}
	k := uint64(8)
	if err := r.Validate(protocolv4.ReadResultContext{Method: "read_exactly", CursorKind: "exact", StartOffset: 4, Transferred: 3, Target: &k, StreamStatus: protocolv4.V4StreamStatusEof}); err != nil {
		t.Fatal(r, err)
	}
	again, err := c.TakePrefix(context.Background())
	m = validateCursorFailure(t, c, again, err, protocolv4.V4ReadMethodFailureReasonAlreadyDelivered)
	if !m.Cursor.Delivered || m.Cursor.Offset != 7 || !errors.Is(err, ErrAlreadyDelivered) {
		t.Fatal(m, err)
	}
	if string(r.Data) != "abc" {
		t.Fatal("method failure changed delivered payload")
	}
}

func TestReadMethodFailureCloseDoesNotRewriteEOFOrResetTransferredBytes(t *testing.T) {
	f := readFlow(t)
	wire := newFlowTransport(t)
	target, _ := exactCursorTarget(8, 8)
	c, _ := testReaderCursor(t, f, target, testAuthorization{})
	if err := wire.data(t, f, 0, true, "abc"); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	_, err := c.advanceLocked(true)
	c.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	r, err := c.ReadExactly(context.Background())
	m := validateCursorFailure(t, c, r, err, protocolv4.V4ReadMethodFailureReasonClosed)
	if !errors.Is(err, ErrCursorClosed) || m.Cursor.StreamStatus != protocolv4.V4StreamStatusEof || m.Cursor.TransferredBytes != 3 || c.storage != nil {
		t.Fatal(m, err)
	}
	if p := c.Progress(); p.Validate() != nil || p.Offset != 3 || p.TransferredBytes != 3 {
		t.Fatal(p)
	}
}

func TestReadMethodFailureInvalidMethodAndOwnerLossDoNotInventStreamErrors(t *testing.T) {
	f := readFlow(t)
	wire := newFlowTransport(t)
	target, _ := exactCursorTarget(8, 8)
	c, root := testReaderCursor(t, f, target, testAuthorization{})
	if err := wire.data(t, f, 0, false, "abc"); err != nil {
		t.Fatal(err)
	}
	r, err := c.ReadUntil(context.Background())
	m := validateCursorFailure(t, c, r, err, protocolv4.V4ReadMethodFailureReasonTargetMismatch)
	if m.Cursor.TransferredBytes != 0 || !errors.Is(err, ErrCursorTarget) {
		t.Fatal(m, err)
	}
	r, err = c.ReadExactly(nil)
	validateCursorFailure(t, c, r, err, protocolv4.V4ReadMethodFailureReasonInvalidArgument)
	root.Close()
	r, err = c.ReadExactly(context.Background())
	m = validateCursorFailure(t, c, r, err, protocolv4.V4ReadMethodFailureReasonOwnerUnavailable)
	if m.Cursor.StreamStatus != protocolv4.V4StreamStatusOpen || m.Cursor.StreamError != nil || !errors.Is(err, resourcev4.ErrClosed) || !m.Cursor.Closed {
		t.Fatal(m, err)
	}
	if n, _, err := f.TryRead(make([]byte, 3)); n != 3 || err != nil {
		t.Fatal("failed cursor method consumed source", n, err)
	}
}

func TestReadMethodFailureAuthorizationDenialHasOnlyFiniteDetachedMetadata(t *testing.T) {
	f := readFlow(t)
	wire := newFlowTransport(t)
	target, _ := exactCursorTarget(8, 8)
	guard := &cursorTestAuthorization{wake: make(chan struct{}, 1)}
	c, root := testReaderCursor(t, f, target, guard)
	if err := wire.data(t, f, 0, true, "abc"); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	c.advanceLocked(true)
	c.mu.Unlock()
	guard.status.Store(3)
	r, err := c.TakePrefix(context.Background())
	m := validateCursorFailure(t, c, r, err, protocolv4.V4ReadMethodFailureReasonAuthorizationDenied)
	if !errors.Is(err, ErrReadAuthorizationDenied) || errors.Is(err, errAuthorizationRejected) || m.Cursor.TransferredBytes != 3 || m.Cursor.StreamStatus != protocolv4.V4StreamStatusEof || c.failure != nil || root.Snapshot().Reservations != 0 {
		t.Fatal(m, err)
	}
	guard.status.Store(0)
	r, err = c.TakePrefix(context.Background())
	validateCursorFailure(t, c, r, err, protocolv4.V4ReadMethodFailureReasonAuthorizationDenied)
}

func TestReadMethodFailureConstructionHasNoInventedCursor(t *testing.T) {
	_, err := NewExactReaderCursor(nil, 9, 8, resourcev4.Reference{}, nil)
	var failure *ReadMethodError
	if !errors.As(err, &failure) || !errors.Is(err, ErrCursorTarget) {
		t.Fatal(err)
	}
	m := failure.Metadata()
	if m.Cursor != nil || m.Validate(protocolv4.ReadMethodFailureContext{Reason: protocolv4.V4ReadMethodFailureReasonInvalidArgument, StreamStatus: protocolv4.V4StreamStatusOpen}) != nil {
		t.Fatal(m)
	}
}

type retainingReadError struct {
	backing []byte
	owner   *ReceiveFlow
}

func (*retainingReadError) Error() string { return "provider detail must remain private" }
func (*retainingReadError) Unwrap() error { return ErrStreamData }

func TestReaderCursorDetachedSourceFailureDropsProviderGraph(t *testing.T) {
	for _, closeBeforeDelivery := range []bool{false, true} {
		f := readFlow(t)
		target, _ := exactCursorTarget(8, 8)
		c, root := testReaderCursor(t, f, target, testAuthorization{})
		providerError := &retainingReadError{backing: make([]byte, 4096), owner: f}
		f.termination.start(true, providerError)
		f.Fence()
		c.mu.Lock()
		_, err := c.advanceLocked(false)
		c.mu.Unlock()
		if err != nil || c.flow != nil {
			t.Fatal("direction candidate did not detach", err)
		}
		if _, ok := c.failure.(sourceReadError); !ok || !errors.Is(c.failure, ErrReadOwnerUnavailable) {
			t.Fatal("candidate retained raw provider error or lost SDK identity", c.failure)
		}
		var retained *retainingReadError
		if errors.As(c.failure, &retained) {
			t.Fatal("detached candidate still reaches provider graph")
		}
		if closeBeforeDelivery {
			c.Close()
			r, err := c.TakePrefix(context.Background())
			m := validateCursorFailure(t, c, r, err, protocolv4.V4ReadMethodFailureReasonClosed)
			if m.Cursor.StreamStatus != protocolv4.V4StreamStatusAborted || !errors.Is(c.failure, ErrReadOwnerUnavailable) {
				t.Fatal("method Close overwrote original direction facts", m)
			}
		} else {
			r, err := c.ReadExactly(context.Background())
			if !errors.Is(err, ErrReadOwnerUnavailable) || errors.As(err, &retained) || r.StreamStatus != protocolv4.V4StreamStatusAborted {
				t.Fatal(r, err)
			}
			limit := uint64(8)
			if err := r.Validate(protocolv4.ReadResultContext{Method: "read_exactly", CursorKind: "exact", Target: &limit, StreamStatus: protocolv4.V4StreamStatusAborted}); err != nil {
				t.Fatal(err)
			}
		}
		if root.Snapshot().Reservations != 0 {
			t.Fatal("completed cursor retained resource references")
		}
	}
}

type callbackReadError struct{}

func (callbackReadError) Error() string { panic("provider Error callback under core gate") }
func (callbackReadError) Is(error) bool { panic("provider Is callback under core gate") }
func (callbackReadError) Unwrap() error { panic("provider Unwrap callback under core gate") }

func TestReaderCursorBoundsSourceErrorsWithoutCallingProviderMethods(t *testing.T) {
	if len(readMethodIdentities) > 64 {
		t.Fatal("finite reason mask overflow")
	}
	for _, cause := range []error{callbackReadError{}, cryptov4.ErrAuthentication, cryptov4.ErrSequence, cryptov4.ErrEpoch, cryptov4.ErrScope, cryptov4.ErrUsage, io.ErrUnexpectedEOF} {
		f := readFlow(t)
		target, _ := exactCursorTarget(8, 8)
		c, _ := testReaderCursor(t, f, target, testAuthorization{})
		f.termination.start(true, cause)
		f.Fence()
		r, err := c.ReadExactly(context.Background())
		want := cause
		if _, unknown := cause.(callbackReadError); unknown {
			want = ErrReadOwnerUnavailable
		}
		if !errors.Is(err, want) || r.StreamStatus != protocolv4.V4StreamStatusAborted {
			t.Fatal("bounded source identity changed", err, r)
		}
	}
}
