package sessionv4

import (
	"context"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
)

// WaitCleanup joins only this original call's actual network and decoder tails.
// It never closes the shared Session or runs a new request. The waiting caller
// owns one finite observation timer; cancellation detaches only that observer.
// Owners that lend request/response buffers use Close then join with their own
// cleanup context before reusing those buffers, even if Wait returned early.
func (o *UnaryOperation) WaitCleanup(ctx context.Context) error {
	if o == nil || ctx == nil {
		return cryptov4.ErrConfiguration
	}
	if m := o.resumeMessages(); m != nil {
		if err := m.checkReadDependency(ctx); err != nil {
			return err
		}
		if err := m.waitCleanup(ctx); err != nil {
			return err
		}
	}
	var timer *time.Timer
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	for {
		complete := o.Snapshot().CleanupComplete
		if complete {
			return nil
		}
		if timer == nil {
			timer = time.NewTimer(10 * time.Millisecond)
		} else {
			timer.Reset(10 * time.Millisecond)
		}
		select {
		case <-timer.C:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}
