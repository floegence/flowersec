package assemblyv4

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestCarrierPreparationJoinsOriginalParentCancellation(t *testing.T) {
	parent, stopParent := context.WithCancelCause(context.Background())
	defer stopParent(context.Canceled)
	pause := newNativeIngressPause(t, nil)
	opaque := nativeIngressContext{Context: parent, pause: pause}
	ctx, cancel := newCarrierPreparationContext(opaque)
	defer cancel(context.Canceled)
	stop, stopped := make(chan struct{}), make(chan struct{})
	go watchCarrierPreparation(opaque, ctx, cancel, nil, stop, stopped)
	awaitNativeIngress(t, pause.entered)
	cause := errors.New("original cancellation")
	stopParent(cause)
	close(stop)
	requireNativeIngressPending(t, stopped)
	pause.release()
	awaitNativeIngress(t, stopped)
	if !errors.Is(context.Cause(ctx), cause) {
		t.Fatal("lost original cancellation", context.Cause(ctx))
	}
}

func TestCarrierPreparationPreservesValuesDeadlineAndDescendantCancellation(t *testing.T) {
	type key struct{}
	deadline := time.Now().Add(time.Minute)
	original, stop := context.WithDeadline(context.WithValue(context.Background(), key{}, "original"), deadline)
	defer stop()
	ctx, cancel := newCarrierPreparationContext(original)
	child, stopChild := context.WithCancel(ctx)
	defer stopChild()
	if got, ok := ctx.Deadline(); !ok || got != deadline {
		t.Fatal("lost original deadline", got)
	}
	if child.Value(key{}) != "original" {
		t.Fatal("lost original value")
	}
	cancel(context.Canceled)
	select {
	case <-child.Done():
	default:
		t.Fatal("descendant cancellation was detached from the original preparation")
	}
}
