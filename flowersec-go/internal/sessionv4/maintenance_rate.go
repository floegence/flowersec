package sessionv4

import "github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"

// maintenanceRefill measures cumulative proven elapsed time from one original
// monotonic mark. Charging quantization again for every record would reduce the
// admitted rate and eventually reject a legal sustained maintenance workload.
// Catch-up uses constant work and never retains more than the admitted burst.
// The enclosing owner serializes calls; clock sampling precedes its lock.
type maintenanceRefill struct {
	origin   timev4.Mark
	periods  uint64
	started  bool
	terminal error
}

func (r *maintenanceRefill) consume(now timev4.Mark, rate timev4.Rate, period uint64, burst uint32, tokens *uint32) error {
	if r.terminal != nil {
		return r.terminal
	}
	if period == 0 || burst == 0 || tokens == nil || *tokens > burst {
		return timev4.ErrRate
	}
	if !r.started {
		if !now.SameEra(now) {
			return timev4.ErrContinuity
		}
		r.origin, r.started = now, true
	} else {
		if !now.SameEra(r.origin) || now.Milliseconds < r.origin.Milliseconds {
			r.terminal = timev4.ErrContinuity
			return r.terminal
		}
		elapsed, _, err := rate.Elapsed(now.Milliseconds - r.origin.Milliseconds)
		if err != nil {
			r.terminal = err
			return err
		}
		periods := elapsed / period
		if periods < r.periods {
			r.terminal = timev4.ErrContinuity
			return r.terminal
		}
		*tokens += uint32(min(periods-r.periods, uint64(burst-*tokens)))
		r.periods = periods
	}
	if *tokens == burst {
		// Discard time accrued while full. It cannot fund another burst.
		r.origin, r.periods = now, 0
	}
	if *tokens == 0 {
		return ErrMaintenanceRate
	}
	*tokens--
	return nil
}
