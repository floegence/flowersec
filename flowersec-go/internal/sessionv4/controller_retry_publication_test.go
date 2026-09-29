package sessionv4

import (
	"context"
	"sync"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/native"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

func TestControllerRetryWindowPreparationRemainsPendingUntilPublication(t *testing.T) {
	for _, cancel := range []bool{false, true} {
		name := "publish"
		if cancel {
			name = "close"
		}
		t.Run(name, func(t *testing.T) {
			entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
			resume := sync.OnceFunc(func() { close(release) })
			defer func() { resume(); <-done }()
			clock, err := timev4.NewClock(sessionTestClock(t).Profile(), func() (timev4.Tick, error) {
				close(entered)
				<-release
				return timev4.Tick{Milliseconds: 1, Incarnation: [16]byte{1}}, nil
			})
			if err != nil {
				// No scheduling worker was created.
				close(done)
				t.Fatal(err)
			}
			c := &ConnectionController{config: ControllerConfig{Clock: clock, MaximumAttempts: 2}, started: true, automatic: true,
				serial: 1, cycleAttempts: 1, retryPending: true, retryContext: context.Background(), lastError: native.ErrConnectionLost,
				changed: make(chan struct{}), wake: make(chan struct{}, 1)}
			go func() { defer close(done); c.scheduleRetry(1, 0) }()
			awaitApplicationTask(t, entered)
			if snapshot := c.Snapshot(); !snapshot.Pending || snapshot.WaitingRetry || snapshot.LastError != native.ErrConnectionLost {
				t.Fatal("clock tail appeared as a terminal connection failure", snapshot)
			}
			if err := c.RetryNow(context.Background()); err != ErrControllerBusy {
				t.Fatal("RetryNow bypassed the original window publication", err)
			}
			if cancel {
				c.Close()
				if snapshot := c.Snapshot(); !snapshot.Closed || !snapshot.Pending {
					t.Fatal("Close erased the still-running original clock tail", snapshot)
				}
			}
			resume()
			awaitApplicationTask(t, done)
			if snapshot := c.Snapshot(); snapshot.Pending || snapshot.WaitingRetry == cancel {
				t.Fatal("retry publication lost the original close fence", snapshot)
			}
		})
	}
}
