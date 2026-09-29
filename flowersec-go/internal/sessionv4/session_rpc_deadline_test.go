package sessionv4

import (
	"context"
	"errors"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

func TestPreparedUnaryStartKeepsOriginalDeadlineProjection(t *testing.T) {
	f, r, route := shortCallerFixture(t)
	op := prepareCallerOperation(t, r, route, rpcv4.UnaryPreparation{DeadlineAtMS: 2000, ResponseLimitBytes: 1024}, nil)
	mark, err := f.trust.clock.Monotonic()
	if err != nil {
		t.Fatal(err)
	}
	if err = f.trust.clock.InstallTrusted(mark, timev4.Interval{LowerMS: 1200, UpperMS: 1200}); err != nil {
		t.Fatal(err)
	}
	started := op.Start(context.Background())
	if started.Error != nil {
		t.Fatal(started.Error)
	}
	i := started.Call.invocation
	publication := i.publication
	if remaining, err := i.deadline.RemainingMS(); err != nil || remaining != 750 {
		t.Fatal("Start renewed the original request deadline", remaining, err)
	}
	f.trust.tick.Store(750)
	if _, err := f.publisher.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	r.AdvanceCalls()
	if progress := publication.Progress(); progress.HeaderAccepted || !progress.Terminal {
		t.Fatal("expired prepared header was published", progress)
	}
	if outcome, err := started.Call.Wait(resultTestContext(t)); err != nil || !errors.Is(outcome.Error, timev4.ErrExpired) {
		t.Fatal(outcome, err)
	}
}

func TestPreparedUnaryCompletionKeepsSeparateOriginalGraceProjection(t *testing.T) {
	f, r, route, _ := deferredCallerFixture(t)
	op, err := r.PrepareUnaryResult(context.Background(), route, nil, rpcv4.UnaryPreparation{DeadlineAtMS: 2000, ResponseLimitBytes: 1024}, ApplicationShort, synchronousResult)
	if err != nil {
		t.Fatal(err)
	}
	defer op.Close()
	mark, _ := f.trust.clock.Monotonic()
	if err = f.trust.clock.InstallTrusted(mark, timev4.Interval{LowerMS: 1200, UpperMS: 1200}); err != nil {
		t.Fatal(err)
	}
	started := op.Start(context.Background())
	if started.Error != nil {
		t.Fatal(started.Error)
	}
	i := started.Call.invocation
	for range 3 {
		if _, err := f.publisher.Step(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if !i.publication.Progress().HeaderAccepted {
		t.Fatal("request did not enter its original publisher")
	}
	f.trust.tick.Store(750)
	if err := i.completion.Expire(); err != nil {
		t.Fatal("request deadline erased the separately reserved receive grace", err)
	}
	f.trust.tick.Store(5750)
	if err := i.completion.Expire(); !errors.Is(err, timev4.ErrExpired) {
		t.Fatal("Start renewed the original completion deadline", err)
	}
	r.AdvanceCalls()
	if s := op.Snapshot(); !s.Result.Complete || !errors.Is(s.Result.Outcome.Error, timev4.ErrExpired) {
		t.Fatal(s)
	}
}
