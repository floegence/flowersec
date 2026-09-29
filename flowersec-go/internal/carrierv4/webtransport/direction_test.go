package webtransport

import (
	"context"
	"errors"
	"testing"

	carrierlife "github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/internal/lifecycle"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/native"
	quic "github.com/quic-go/quic-go"
	wt "github.com/quic-go/webtransport-go"
)

type stoppedNativeStream struct {
	context    context.Context
	closeError error
	closes     int
}

func (s *stoppedNativeStream) Context() context.Context    { return s.context }
func (*stoppedNativeStream) StreamID() quic.StreamID       { return 4 }
func (*stoppedNativeStream) Read([]byte) (int, error)      { panic("unexpected read") }
func (*stoppedNativeStream) Write([]byte) (int, error)     { panic("unexpected write") }
func (*stoppedNativeStream) CancelRead(wt.StreamErrorCode) {}
func (*stoppedNativeStream) CancelWrite(wt.StreamErrorCode) {
	panic("unexpected send reset")
}
func (s *stoppedNativeStream) Close() error {
	s.closes++
	return s.closeError
}

func TestCloseWriteRecordsOnlyNativeDirectionCompletion(t *testing.T) {
	for _, tc := range []struct {
		name  string
		cause error
		ended bool
	}{
		{"webtransport drained", &wt.StreamError{ErrorCode: wt.StreamErrorCode(native.NormalDrainedCode)}, true},
		{"webtransport reset", &wt.StreamError{ErrorCode: streamResetCode}, true},
		{"quic drained", &quic.StreamError{ErrorCode: nativeResetCode(wt.StreamErrorCode(native.NormalDrainedCode))}, true},
		{"quic reset", &quic.StreamError{ErrorCode: nativeResetCode(streamResetCode)}, true},
		{"connection failure", errors.New("connection lost"), false},
		{"no native stop", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancelCause(context.Background())
			defer cancel(nil)
			if tc.cause != nil {
				cancel(tc.cause)
			}
			closeError := errors.New("close called for canceled stream")
			actual := &stoppedNativeStream{context: ctx, closeError: closeError}
			stream := &Stream{inner: actual, lifecycle: carrierlife.NewStream(context.Background())}
			defer stream.lifecycle.Terminate(nil)
			for range 2 {
				if err := stream.CloseWrite(); !errors.Is(err, closeError) {
					t.Fatal("changed the native close result", err)
				}
			}
			if actual.closes != 1 {
				t.Fatal("repeated native close", actual.closes)
			}
			if tc.ended && stream.Context().Err() != nil {
				t.Fatal("send stop terminated the live reverse direction", stream.Context().Err())
			}
			if !tc.ended && stream.Context().Err() == nil {
				t.Fatal("unrelated native failure was suppressed")
			}
			if err := stream.StopSending(); err != nil {
				t.Fatal(err)
			}
			if ended := stream.lifecycle.DirectionsEnded(); ended != tc.ended {
				t.Fatal("incorrect native direction completion", ended)
			}
		})
	}
}
