package flowersec

import (
	"context"
	"errors"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

func TestV4OperationHandoffRejectsCloseAndCancellation(t *testing.T) {
	for _, closeSession := range []bool{false, true} {
		t.Run(map[bool]string{false: "canceled", true: "closed"}[closeSession], func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			owner := &sessionv4.UnaryOperation{}
			session := &V4Session{}
			session.prepareUnary = func(context.Context, sessionv4.UnaryMethodDefinition, []byte, rpcv4.UnaryPreparation) (*sessionv4.UnaryOperation, error) {
				if closeSession {
					_ = session.Close()
				} else {
					cancel()
				}
				return owner, nil
			}
			handle, err := session.PrepareUnary(ctx, V4UnaryMethod{}, nil, V4OperationOptions{})
			want := error(context.Canceled)
			if closeSession {
				want = ErrOperationClosed
			}
			if handle != nil || !errors.Is(err, want) || !owner.Snapshot().Closed {
				t.Fatal(handle, err, owner.Snapshot())
			}
		})
	}
}

func TestV4ShapePreparationProjectsOriginalMethod(t *testing.T) {
	ctx := context.Background()
	digest := [32]byte{11}
	streamOwner := &sessionv4.StreamOperation{}
	notifyOwner := &sessionv4.NotifyOperation{}
	calls := 0
	session := &V4Session{
		prepareStreaming: func(got context.Context, method sessionv4.UnaryMethodDefinition, kind string, metadata, input []byte, options rpcv4.UnaryPreparation) (*sessionv4.StreamOperation, error) {
			calls++
			if got != ctx || method.Contract != digest || kind != "example/events" || len(metadata) != 0 || string(input) != "request" || options.ResponseLimitBytes != 1024 {
				t.Error("changed streaming preparation")
			}
			return streamOwner, nil
		},
		prepareNotify: func(got context.Context, method sessionv4.UnaryMethodDefinition, input []byte, options rpcv4.UnaryPreparation) (*sessionv4.NotifyOperation, error) {
			calls++
			if got != ctx || method.Contract != digest || method.Decode != nil || options.ResponseLimitBytes != 0 || string(input) != "event" {
				t.Error("notification acquired response configuration")
			}
			return notifyOwner, nil
		},
	}
	stream, err := session.PrepareStreaming(ctx, V4StreamingMethod{Method: V4UnaryMethod{Contract: digest}, Kind: "example/events"}, []byte("request"), V4OperationOptions{ResponseLimitBytes: 1024})
	if err != nil || stream.inner != streamOwner {
		t.Fatal(stream, err)
	}
	notify, err := session.PrepareNotify(ctx, V4NotifyMethod{Contract: digest}, []byte("event"), V4OperationOptions{})
	if err != nil || notify.inner != notifyOwner || calls != 2 {
		t.Fatal(notify, err, calls)
	}
}
