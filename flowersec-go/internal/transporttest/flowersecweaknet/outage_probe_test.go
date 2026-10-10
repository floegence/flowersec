package flowersecweaknet

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	flowersec "github.com/floegence/flowersec/flowersec-go/v6"
)

func TestOutageObservationStopsAddingProbesAfterBothDirectionsQualify(t *testing.T) {
	started := time.Unix(100, 0)
	now := started
	calls, intervals := 0, 0
	observation, err := observeOutageWindow(context.Background(), func(context.Context) [2]outageProbeOutcome {
		calls++
		if calls > 2 {
			t.Fatal("already qualified outage added expired PINGs ahead of the recovery probe")
		}
		outcomes := [2]outageProbeOutcome{}
		outcomes[calls-1].qualified = true
		return outcomes
	}, func() time.Time { return now }, func(context.Context) error {
		intervals++
		now = now.Add(time.Second)
		return nil
	})
	if err != nil || !observation.qualified[0] || !observation.qualified[1] || calls != 2 || observation.samples != 2 {
		t.Fatalf("outage observation = %+v, calls=%d, error=%v", observation, calls, err)
	}
	if intervals != 4 || now.Sub(started) < 3500*time.Millisecond {
		t.Fatalf("qualification shortened the original fault window: intervals=%d elapsed=%s", intervals, now.Sub(started))
	}
}

func TestOutageObservationStillRequiresTheOtherDirectionAndOriginalWait(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		t.Run(map[bool]string{false: "one direction", true: "canceled wait"}[canceled], func(t *testing.T) {
			now := time.Unix(100, 0)
			calls, intervals := 0, 0
			observation, err := observeOutageWindow(context.Background(), func(context.Context) [2]outageProbeOutcome {
				calls++
				return [2]outageProbeOutcome{{qualified: true}, {qualified: canceled}}
			}, func() time.Time { return now }, func(context.Context) error {
				intervals++
				if canceled {
					return context.Canceled
				}
				now = now.Add(time.Second)
				return nil
			})
			if canceled {
				if !errors.Is(err, context.Canceled) || calls != 1 || intervals != 1 {
					t.Fatalf("qualified evidence erased the canceled original wait: observation=%+v calls=%d intervals=%d error=%v", observation, calls, intervals, err)
				}
			} else if err != nil || observation.qualified[1] || calls != 4 || intervals != 4 {
				t.Fatalf("missing direction stopped fault observation: observation=%+v calls=%d intervals=%d error=%v", observation, calls, intervals, err)
			}
		})
	}
}

func TestOutageProbeDirectionsStartIndependentlyAndJoinBothCalls(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	entered := make(chan int, 2)
	returned := make(chan int, 2)
	release := [2]chan struct{}{make(chan struct{}), make(chan struct{})}
	var probes [2]func(context.Context, uint64) (flowersec.LivenessResult, error)
	for direction := range probes {
		probes[direction] = func(probeCtx context.Context, timeoutMS uint64) (flowersec.LivenessResult, error) {
			deadline, ok := probeCtx.Deadline()
			if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > 300*time.Millisecond || timeoutMS != 250 {
				return flowersec.LivenessResult{}, errors.New("probe lost its original operation or caller deadline")
			}
			entered <- direction
			select {
			case <-release[direction]:
			case <-probeCtx.Done():
				return flowersec.LivenessResult{}, context.Cause(probeCtx)
			}
			returned <- direction
			return flowersec.LivenessResult{Submitted: true, Complete: true, ElapsedAvailable: true, ElapsedMilliseconds: uint64(direction + 1)}, nil
		}
	}
	done := make(chan [2]outageProbeOutcome, 1)
	go func() { done <- probeOutageDirections(ctx, probes, 250, 300*time.Millisecond) }()
	for range probes {
		select {
		case <-entered:
		case <-ctx.Done():
			t.Fatal("the two directions waited for each other's PONG instead of issuing independent PINGs")
		}
	}
	close(release[0])
	select {
	case <-returned:
	case <-ctx.Done():
		t.Fatal("first probe did not exit")
	}
	select {
	case <-done:
		t.Fatal("outage probing returned while the reverse-direction call still owned work")
	case <-time.After(20 * time.Millisecond):
	}
	close(release[1])
	select {
	case outcomes := <-done:
		for direction, outcome := range outcomes {
			if outcome.err != nil || !outcome.result.Complete || outcome.result.ElapsedMilliseconds != uint64(direction+1) || outcome.qualified {
				t.Fatalf("direction %d outcome = %+v", direction, outcome)
			}
		}
	case <-ctx.Done():
		t.Fatal("outage probes did not join after both calls returned")
	}
}

func TestOutageProbeDirectionsCancellationJoinsBothOriginalOwners(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered := make(chan struct{}, 2)
	var active atomic.Int32
	probe := func(probeCtx context.Context, _ uint64) (flowersec.LivenessResult, error) {
		active.Add(1)
		defer active.Add(-1)
		entered <- struct{}{}
		<-probeCtx.Done()
		return flowersec.LivenessResult{Submitted: true}, context.Cause(probeCtx)
	}
	done := make(chan [2]outageProbeOutcome, 1)
	go func() {
		done <- probeOutageDirections(ctx, [2]func(context.Context, uint64) (flowersec.LivenessResult, error){probe, probe}, 250, 300*time.Millisecond)
	}()
	for range 2 {
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("both original probes did not start")
		}
	}
	cancel()
	select {
	case outcomes := <-done:
		if active.Load() != 0 {
			t.Fatal("cancellation left original probe work running")
		}
		for direction, outcome := range outcomes {
			if !errors.Is(outcome.err, context.Canceled) || outcome.qualified || !outcome.result.Submitted {
				t.Fatalf("direction %d cancellation lost its original facts: %+v", direction, outcome)
			}
		}
	case <-time.After(time.Second):
		t.Fatal("canceled outage probes did not join")
	}
}
