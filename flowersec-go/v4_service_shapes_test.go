package flowersec

import (
	"context"
	"errors"
	"runtime"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

type handoffContext struct {
	context.Context
	err func() error
}

func (c handoffContext) Err() error { return c.err() }

func TestOperationHandoffContextRunsOutsideSessionGate(t *testing.T) {
	owner, session := &sessionv4.UnaryOperation{}, &Session{}
	session.prepareUnary = func(context.Context, sessionv4.UnaryMethodDefinition, []byte, rpcv4.UnaryPreparation) (*sessionv4.UnaryOperation, error) {
		return owner, nil
	}
	ctx := handoffContext{Context: context.Background(), err: func() error {
		if !session.mu.TryLock() {
			t.Error("caller context invoked under Session gate")
			return context.Canceled
		}
		session.mu.Unlock()
		_ = session.Close()
		return nil
	}}
	handle, err := session.PrepareUnary(ctx, UnaryMethod{}, nil, OperationOptions{})
	if handle != nil || !errors.Is(err, ErrOperationClosed) || !owner.Snapshot().Closed {
		t.Fatal(handle, err, owner.Snapshot())
	}
}

func TestOperationHandoffRetiresOwnerOnContextFailure(t *testing.T) {
	for _, mode := range []string{"panic", "goexit"} {
		t.Run(mode, func(t *testing.T) {
			owner, session := &sessionv4.UnaryOperation{}, &Session{}
			session.prepareUnary = func(context.Context, sessionv4.UnaryMethodDefinition, []byte, rpcv4.UnaryPreparation) (*sessionv4.UnaryOperation, error) {
				return owner, nil
			}
			ctx := handoffContext{Context: context.Background(), err: func() error {
				if mode == "panic" {
					panic("context failure")
				}
				runtime.Goexit()
				return nil
			}}
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer func() { _ = recover() }()
				_, _ = session.PrepareUnary(ctx, UnaryMethod{}, nil, OperationOptions{})
			}()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("context failure blocked handoff")
			}
			if !owner.Snapshot().Closed {
				t.Error("context failure orphaned prepared operation")
			}
			if !session.mu.TryLock() {
				t.Error("context failure orphaned Session gate")
			} else {
				session.mu.Unlock()
			}
		})
	}
}

func TestOperationHandoffRejectsCloseAndCancellation(t *testing.T) {
	for _, closeSession := range []bool{false, true} {
		t.Run(map[bool]string{false: "canceled", true: "closed"}[closeSession], func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			owner := &sessionv4.UnaryOperation{}
			session := &Session{}
			session.prepareUnary = func(context.Context, sessionv4.UnaryMethodDefinition, []byte, rpcv4.UnaryPreparation) (*sessionv4.UnaryOperation, error) {
				if closeSession {
					_ = session.Close()
				} else {
					cancel()
				}
				return owner, nil
			}
			handle, err := session.PrepareUnary(ctx, UnaryMethod{}, nil, OperationOptions{})
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

func TestShapePreparationProjectsOriginalMethod(t *testing.T) {
	ctx := context.Background()
	digest := [32]byte{11}
	streamOwner := &sessionv4.StreamOperation{}
	notifyOwner := &sessionv4.NotifyOperation{}
	calls := 0
	session := &Session{
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
	stream, err := session.PrepareStreaming(ctx, StreamingMethod{Method: UnaryMethod{Contract: digest}, Kind: "example/events"}, []byte("request"), OperationOptions{ResponseLimitBytes: 1024})
	if err != nil || stream.inner != streamOwner {
		t.Fatal(stream, err)
	}
	notify, err := session.PrepareNotify(ctx, NotifyMethod{Contract: digest}, []byte("event"), OperationOptions{})
	if err != nil || notify.inner != notifyOwner || calls != 2 {
		t.Fatal(notify, err, calls)
	}
}
