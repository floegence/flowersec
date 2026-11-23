package timev4

import "sync"

// Idle retains the actual last qualifying activity on the original continuous
// monotonic clock. It never uses wall-clock width or creates an absolute age
// from a later callback. Loss of continuity ends this owner rather than giving
// it another full duration after a clock repair.
type Idle struct {
	mu       sync.Mutex
	clock    *Clock
	delta    uint64
	enabled  bool
	started  bool
	last     Mark
	terminal error
}

// NewIdle fixes the signed policy and any explicitly admitted local tightening
// before READY. Local zero means no extra local policy, not a default timeout.
func NewIdle(c *Clock, signedMS, localMS uint64) (*Idle, error) {
	if c == nil {
		return nil, ErrUnavailable
	}
	if signedMS != 0 && localMS > signedMS {
		return nil, ErrInterval
	}
	duration := signedMS
	if localMS != 0 {
		duration = localMS
	}
	i := &Idle{clock: c, enabled: duration != 0}
	if !i.enabled {
		return i, nil
	}
	delta, err := c.profile.Rate.DeadlineDelta(0, duration)
	if err != nil {
		return nil, err
	}
	if delta == 0 {
		return nil, ErrUnrepresentable
	}
	i.delta = delta
	return i, nil
}

// Start runs exactly once at the real dual-READY publication gate. Private
// authenticated input before this transition cannot arm or refresh the timer.
func (i *Idle) Start() error {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.terminal != nil {
		return i.terminal
	}
	if i.started {
		return ErrOwner
	}
	if i.enabled {
		mark, err := i.clock.Monotonic()
		if err != nil {
			i.terminal = err
			return err
		}
		i.last = mark
	}
	i.started = true
	return nil
}

func (i *Idle) remaining() (uint64, Mark, error) {
	if i.terminal != nil {
		return 0, Mark{}, i.terminal
	}
	if !i.enabled || !i.started {
		return 0, Mark{}, nil
	}
	now, err := i.clock.Monotonic()
	if err != nil || !now.SameEra(i.last) || now.Milliseconds < i.last.Milliseconds {
		i.terminal = ErrContinuity
		return 0, now, i.terminal
	}
	elapsed := now.Milliseconds - i.last.Milliseconds
	if elapsed >= i.delta {
		i.terminal = ErrExpired
		return 0, now, i.terminal
	}
	return i.delta - elapsed, now, nil
}

// RemainingMS is a wakeup hint, not a timer-derived authorization. Subtraction
// preserves the full uint64 duration even when last+duration would overflow.
func (i *Idle) RemainingMS() (milliseconds uint64, armed bool, err error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	milliseconds, _, err = i.remaining()
	return milliseconds, i.enabled && i.started, err
}

func (i *Idle) Check() error { _, _, err := i.RemainingMS(); return err }

// Refresh first checks the old deadline at the very same sample. Activity at
// or after expiry cannot revive the Session, even if the timer ran late.
func (i *Idle) Refresh() error {
	i.mu.Lock()
	defer i.mu.Unlock()
	_, now, err := i.remaining()
	if err == nil && i.enabled && i.started {
		i.last = now
	}
	return err
}
