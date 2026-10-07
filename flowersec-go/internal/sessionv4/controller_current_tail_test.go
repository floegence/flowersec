package sessionv4

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/native"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
)

func TestControllerCurrentFailureWaitsForPublishedAttemptTail(t *testing.T) {
	for _, exited := range []bool{false, true} {
		for _, stop := range []string{"retry", "close", "parent_cancel", "initialization_failure", "newer_attempt"} {
			t.Run(fmt.Sprintf("exited_%v/%s", exited, stop), func(t *testing.T) {
				f := admissionIntegration(t, context.Background(), "preauthorized_pool")
				e := environmentTestOwner(t, f, 248, 1)
				var acquisitions atomic.Int32
				c := controllerForTest(t, f, e, ControllerConfig{Clock: f.trust.clock, SourceIncarnation: [16]byte{1}, AttemptTimeoutMS: 1000, DrainTimeoutMS: 1000, RuntimeBytes: 65536,
					Source: controllerSourceFunc(func(_ context.Context, request ControllerRequest) (*ControllerPreparation, error) {
						if request.Attempt != 2 {
							t.Error("retry did not acquire a new attempt", request.Attempt)
						}
						acquisitions.Add(1)
						return nil, cryptov4.ErrConfiguration
					})})
				parent, cancel := context.WithCancel(context.Background())
				defer cancel()
				finished := make(chan struct{})
				close(finished)
				// Seed the two exact coordinator interleavings after original
				// publication and physical Session cleanup. Source calls below
				// use the actual controller acquisition and retry machinery.
				current := &EnvironmentSession{done: finished, closed: true, cleaned: true, delivered: true,
					result: native.ErrConnectionLost, controllerTransportFailure: true, controllerDiagnosticAttempt: 1}
				attemptContext, stopAttempt := context.WithCancelCause(parent)
				defer stopAttempt(nil)
				a := &controllerAttempt{serial: 1, ctx: attemptContext, cancel: stopAttempt, candidate: current, finished: true, exited: exited, automatic: true, done: finished,
					result: ControllerReplaceResult{CurrentSwitched: true, Current: current}}
				t.Cleanup(func() {
					c.mu.Lock()
					a.exited = true
					c.signalLocked()
					c.mu.Unlock()
				})
				c.mu.Lock()
				c.started, c.automatic, c.serial, c.retryContext = true, true, 1, parent
				c.current, c.attempt = current, a
				if stop == "parent_cancel" {
					cancel()
				}
				if stop == "initialization_failure" || stop == "newer_attempt" {
					// The failed newer generation must never borrow old current's
					// network provenance to retry its own terminal failure.
					c.serial, a.serial = 2, 2
					a.result, a.candidate = ControllerReplaceResult{}, nil
					a.err, c.lastError = cryptov4.ErrConfiguration, cryptov4.ErrConfiguration
					if stop == "initialization_failure" {
						a.entered, c.blocked = true, true
						a.err, c.lastError = ErrControllerInitialization, ErrControllerInitialization
					}
				}
				c.signalLocked()
				advanced := c.changed
				c.mu.Unlock()
				if stop == "close" {
					c.Close()
				}
				if !exited {
					awaitApplicationTask(t, advanced)
					c.mu.Lock()
					retained := c.attempt == a && (stop == "initialization_failure" || stop == "newer_attempt" || c.current == current)
					waiting := c.retryWindow != nil || c.retryPending
					c.mu.Unlock()
					if !retained || waiting || acquisitions.Load() != 0 {
						t.Fatal("published attempt tail lost its current or started fresh acquisition", retained, waiting, acquisitions.Load())
					}
					c.mu.Lock()
					a.exited = true
					c.signalLocked()
					c.mu.Unlock()
				}
				if stop == "retry" {
					waitController(t, c, func(s ControllerSnapshot) bool { return s.WaitingRetry && !s.Pending })
					if acquisitions.Load() != 0 {
						t.Fatal("retry bypassed original backoff")
					}
					if err := c.RetryNow(context.Background()); err != nil {
						t.Fatal("original current failure lost its retry window", err)
					}
					waitController(t, c, func(s ControllerSnapshot) bool { return s.Attempts == 1 && !s.Pending })
					if acquisitions.Load() != 1 {
						t.Fatal("current interruption did not acquire exactly one fresh attempt", acquisitions.Load())
					}
				} else {
					waitController(t, c, func(s ControllerSnapshot) bool { return !s.Pending && !s.Current })
					if c.Snapshot().WaitingRetry || acquisitions.Load() != 0 {
						t.Fatal("terminal generation acquired new material", acquisitions.Load(), c.Snapshot())
					}
				}
			})
		}
	}
}
