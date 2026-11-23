package timev4

import "sync"

// Delay proves a minimum elapsed duration, unlike Window's maximum work limit.
// It uses elapsed_lower, so a fast clock cannot shorten a receive protection
// pause. The owner keeps one wakeup and must recheck after actual scheduling.
type Delay struct {
	mu       sync.Mutex
	clock    *Clock
	start    Mark
	until    uint64
	terminal error
}

func NewDelay(c *Clock, duration uint64) (*Delay, error) {
	if c == nil {
		return nil, ErrUnavailable
	}
	start, err := c.Monotonic()
	if err != nil {
		return nil, err
	}
	delta, err := c.profile.Rate.ProveDelta(0, duration)
	if err != nil {
		return nil, err
	}
	until, err := add(start.Milliseconds, delta)
	if err != nil {
		return nil, err
	}
	return &Delay{clock: c, start: start, until: until}, nil
}

func (d *Delay) RemainingMS() (uint64, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.terminal != nil {
		return 0, d.terminal
	}
	now, err := d.clock.Monotonic()
	if err != nil || !now.SameEra(d.start) || now.Milliseconds < d.start.Milliseconds {
		d.terminal = ErrContinuity
		return 0, d.terminal
	}
	if now.Milliseconds >= d.until {
		return 0, nil
	}
	return d.until - now.Milliseconds, ErrPending
}

func (d *Delay) Check() error { _, err := d.RemainingMS(); return err }
