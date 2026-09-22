package sessionv4

import (
	"context"
	"math"
	"sync/atomic"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
)

// IdleWatchdog merges idle, authorization and root expiry into one reserved
// worker and one reusable host timer per Session.
// It is constructed before READY and run by the Session's admitted task. No
// record, Stream, refresh or rekey allocates another timer or waiting queue.
type IdleWatchdog struct {
	admission *OpenAdmission
	started   atomic.Bool
}

func NewIdleWatchdog(a *OpenAdmission) (*IdleWatchdog, error) {
	if a == nil {
		return nil, cryptov4.ErrConfiguration
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed || a.runtime != nil {
		return nil, cryptov4.ErrClosed
	}
	if a.idleWatchdog != nil {
		return nil, cryptov4.ErrCapacity
	}
	w := &IdleWatchdog{admission: a}
	a.idleWatchdog = w
	return w, nil
}

// idleTimerChunk converts only a bounded wakeup chunk. It never narrows the
// signed uint64 duration or replaces the original monotonic activity anchor.
func idleTimerChunk(ms uint64) time.Duration {
	return time.Duration(min(ms, uint64(math.MaxInt64/int64(time.Millisecond)))) * time.Millisecond
}

// Run's context belongs to the Session lifetime, not an individual caller's
// wait timeout. Cancellation seals the original Session. Timer expiry only
// causes a recheck; a late wakeup cannot grant another full idle duration.
func (w *IdleWatchdog) Run(ctx context.Context) (err error) {
	if !w.started.CompareAndSwap(false, true) {
		return cryptov4.ErrCapacity
	}
	a := w.admission
	defer func() { a.closeWithCause(err) }()
	var timer *time.Timer
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	for {
		remaining, armed, err := a.engine.IdleRemainingMS()
		if err != nil {
			return err
		}
		authorized, err := a.engine.AuthorizationRemainingMS()
		if err != nil {
			return err
		}
		if !armed || authorized < remaining {
			remaining = authorized
		}
		delay := idleTimerChunk(remaining)
		if timer == nil {
			timer = time.NewTimer(delay)
		} else {
			timer.Reset(delay)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-a.engine.Done():
			return cryptov4.ErrClosed
		case <-a.engine.IdleWake():
			if timer != nil {
				timer.Stop()
			}
		case <-timer.C:
		case <-a.engine.AuthorizationWake():
			timer.Stop()
		}
	}
}
