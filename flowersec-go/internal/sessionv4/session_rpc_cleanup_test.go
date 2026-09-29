package sessionv4

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
)

func requireUnaryCleanupPending(t *testing.T, o *UnaryOperation) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := o.WaitCleanup(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("actual call tail reported cleaned", err)
	}
}

func TestUnaryWaitCleanupJoinsCanceledDecoder(t *testing.T) {
	f, r, route := shortCallerFixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	var borrowed []byte
	o, err := r.PrepareUnary(route, []byte("request"), rpcv4.UnaryPreparation{DeadlineAtMS: 2000, ResponseLimitBytes: 1024}, ApplicationShort, true, func(input rpcv4.InputBorrow) error {
		close(entered)
		<-release
		body, _, e := input.Bytes()
		borrowed = append(borrowed, body...)
		return e
	})
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if started := o.Start(ctx); started.Error != nil {
		t.Fatal(started.Error)
	}
	finishShortResponse(t, f, o.header, 1, []byte("original response"))
	r.AdvanceCalls()
	awaitApplicationTask(t, entered)
	cancel()
	o.Close()
	if _, err := o.Wait(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	r.AdvanceCalls()
	requireUnaryCleanupPending(t, o)
	once.Do(func() { close(release) })
	finishShortDecode(t, r)
	if err := o.WaitCleanup(resultTestContext(t)); err != nil {
		t.Fatal(err)
	}
	if string(borrowed) != "original response" {
		t.Fatal("late decoder lost original response", string(borrowed))
	}
}

func TestUnaryWaitCleanupJoinsPublicationAfterResult(t *testing.T) {
	f, r, route := shortCallerFixture(t)
	o := prepareCallerOperation(t, r, route, rpcv4.UnaryPreparation{DeadlineAtMS: 2000, ResponseLimitBytes: 1024}, []byte("request"))
	if started := o.Start(context.Background()); started.Error != nil {
		t.Fatal(started.Error)
	}
	for range 2 {
		if _, err := f.publisher.Step(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	f.sink.held.Store(true)
	receiveShortResponse(t, f, o.header, 1, []byte("result"))
	finishShortDecode(t, r)
	if outcome, err := o.Wait(resultTestContext(t)); err != nil || outcome.Error != nil {
		t.Fatal(outcome, err)
	}
	o.Close()
	requireUnaryCleanupPending(t, o)
	f.sink.held.Store(false)
	if _, err := f.publisher.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	r.AdvanceCalls()
	if err := o.WaitCleanup(resultTestContext(t)); err != nil {
		t.Fatal(err)
	}
}

func TestUnaryWaitCleanupUnstartedClose(t *testing.T) {
	_, r, route := shortCallerFixture(t)
	o := prepareCallerOperation(t, r, route, rpcv4.UnaryPreparation{DeadlineAtMS: 2000, ResponseLimitBytes: 1024}, []byte("request"))
	requireUnaryCleanupPending(t, o)
	o.Close()
	if err := o.WaitCleanup(resultTestContext(t)); err != nil {
		t.Fatal(err)
	}
}
