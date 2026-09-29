package sessionv4

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
)

func lifecycleAPICorePair(t *testing.T, profile string, configure ...func(*SessionCoreConfig)) ([2]*SessionCore, *[2]initialCoreFixture, context.Context) {
	t.Helper()
	var fixtures [2]initialCoreFixture
	pair, configs := initialTestPairPrepared(t, profile, "stream", 4, initialCorePrepareConfig(t, &fixtures, false, func(c *SessionCoreConfig) {
		for _, apply := range configure {
			apply(c)
		}
	}))
	results := startInitialCorePair(pair, configs, &fixtures)
	var cores [2]*SessionCore
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	done := make(chan error, 2)
	for role := range cores {
		result := waitInitialCoreOutcome(t, results[role])
		if result.err != nil {
			cancel()
			t.Fatal(result.err)
		}
		cores[role] = result.core
		if err := pair[role].WaitCleanup(ctx); err != nil {
			cancel()
			t.Fatal(err)
		}
		go func() { done <- cores[role].Runtime().Run(ctx) }()
	}
	t.Cleanup(func() {
		for _, core := range cores {
			core.Close()
		}
		cancel()
		for range cores {
			_ = waitRuntime(t, done)
		}
	})
	return cores, &fixtures, ctx
}

func TestSessionLifecycleAPIUsesOriginalRekeyAndProbe(t *testing.T) {
	for _, profile := range []string{protocolv4.DHProfileX25519, protocolv4.DHProfileP256} {
		t.Run(profile, func(t *testing.T) {
			cores, _, ctx := lifecycleAPICorePair(t, profile)
			for role, core := range cores {
				probe, err := core.ProbeLiveness(ctx, 5000)
				if err != nil || !probe.Submitted || !probe.ElapsedAvailable || probe.Cause != nil {
					t.Fatal("authenticated PONG did not complete original probe", role, probe, err)
				}
				before, err := core.Engine().ScopeFrontier(0, protocolv4.Direction(role))
				if err != nil {
					t.Fatal(err)
				}
				if err := core.Rekey(ctx); err != nil {
					t.Fatal("original rekey failed", role, err)
				}
				after, err := core.Engine().ScopeFrontier(0, protocolv4.Direction(role))
				if err != nil || after.Epoch != before.Epoch+1 {
					t.Fatal("rekey did not advance the actual record engine", before, after, err)
				}
				if probe, err = core.ProbeLiveness(ctx, 5000); err != nil || !probe.Submitted {
					t.Fatal("new epoch probe failed", probe, err)
				}
			}
		})
	}
}

func TestSessionLifecycleAPIProbeCancellationRetainsPublisher(t *testing.T) {
	cores, fixtures, ctx := lifecycleAPICorePair(t, protocolv4.DHProfileX25519)
	core := cores[0]
	entered, release := make(chan struct{}), make(chan struct{})
	stop := sync.OnceFunc(func() { close(release) })
	defer stop()
	writer := core.plan.writer
	writer.mu.Lock()
	original := writer.writer
	writer.writer = idleWriterFunc(func(data []byte) (int, error) {
		close(entered)
		<-release
		return original.Write(data)
	})
	writer.mu.Unlock()
	before := fixtures[0].root.Snapshot().Charged
	probeCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	type outcome struct {
		result ProbeResult
		err    error
	}
	done := make(chan outcome, 1)
	go func() {
		r, err := core.ProbeLiveness(probeCtx, 5000)
		done <- outcome{r, err}
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	cancel()
	select {
	case result := <-done:
		if !errors.Is(result.err, context.Canceled) || !result.result.Submitted {
			t.Fatal("canceled wait lost actual PING ticket", result)
		}
	case <-ctx.Done():
		t.Fatal("cancellation waited for blocked provider")
	}
	if fixtures[0].root.Snapshot().Charged == before {
		t.Fatal("canceled observer refunded actual publisher tail")
	}
	core.plan.mu.Lock()
	pins := core.plan.streamMethods
	core.plan.mu.Unlock()
	if pins != 1 {
		t.Fatal("provider tail lost original core pin", pins)
	}
	stop()
	for {
		core.plan.mu.Lock()
		pins = core.plan.streamMethods
		core.plan.mu.Unlock()
		if pins == 0 {
			break
		}
		if ctx.Err() != nil {
			t.Fatal("actual publication did not release core", ctx.Err())
		}
		runtime.Gosched()
	}
	if got := fixtures[0].root.Snapshot().Charged; got != before {
		t.Fatal("physical publication retained lifecycle charge", got, before)
	}
}

func TestSessionLifecycleAPIProbeWaitsForOriginalPublisher(t *testing.T) {
	for _, cancelWait := range []bool{false, true} {
		t.Run(map[bool]string{false: "two_samples", true: "cancel_before_ticket"}[cancelWait], func(t *testing.T) {
			cores, _, ctx := lifecycleAPICorePair(t, protocolv4.DHProfileX25519, func(c *SessionCoreConfig) { c.ProbeSlots = 3 })
			core := cores[0]
			writer := core.plan.writer
			claim, err := writer.claimPublication()
			if err != nil {
				t.Fatal(err)
			}
			defer writer.releasePublication(claim)
			probeCtx, cancel := context.WithCancel(ctx)
			defer cancel()
			type outcome struct {
				result ProbeResult
				err    error
			}
			done := make(chan outcome, 2)
			for range 2 {
				go func() { result, err := core.ProbeLiveness(probeCtx, 5000); done <- outcome{result, err} }()
			}
			liveness := core.plan.admission.liveness
			for {
				liveness.mu.Lock()
				pending := 0
				for _, slot := range liveness.slots {
					if slot.owner != nil && slot.owner.scheduling && !slot.owner.attempted {
						pending++
					}
				}
				liveness.mu.Unlock()
				if pending == 2 {
					break
				}
				select {
				case result := <-done:
					t.Fatal("busy writer prematurely ended sample", result)
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				default:
					runtime.Gosched()
				}
			}
			if cancelWait {
				cancel()
			} else {
				writer.releasePublication(claim)
			}
			for range 2 {
				select {
				case result := <-done:
					if cancelWait {
						if !errors.Is(result.err, context.Canceled) || result.result.Submitted {
							t.Fatal(result)
						}
					} else if result.err != nil || !result.result.Submitted || !result.result.ElapsedAvailable {
						t.Fatal(result)
					}
				case <-ctx.Done():
					t.Fatal("publication hint lost original waiter", ctx.Err())
				}
			}
			liveness.mu.Lock()
			nonces := liveness.lo
			liveness.mu.Unlock()
			if nonces != 2 {
				t.Fatal("waiting generated replacement sample", nonces)
			}
		})
	}
}
