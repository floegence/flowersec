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
	starting bool
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
	if i.terminal != nil {
		err := i.terminal
		i.mu.Unlock()
		return err
	}
	if i.started || i.starting {
		i.mu.Unlock()
		return ErrOwner
	}
	if !i.enabled {
		i.started = true
		i.mu.Unlock()
		return nil
	}
	i.starting = true
	i.mu.Unlock()
	returned := false
	defer func() {
		i.mu.Lock()
		i.starting = false
		if !returned && i.terminal == nil {
			i.terminal = ErrContinuity
		}
		i.mu.Unlock()
	}()
	mark, err := i.clock.Monotonic()
	i.mu.Lock()
	defer i.mu.Unlock()
	returned = true
	if err == nil {
		err = i.clock.checkMark(mark)
	}
	if err != nil {
		i.terminal = err
		return err
	}
	i.last, i.started = mark, true
	return nil
}

func (i *Idle) remaining(refresh bool) (uint64, bool, error) {
	i.mu.Lock()
	if i.terminal != nil {
		err, armed := i.terminal, i.enabled && i.started
		i.mu.Unlock()
		return 0, armed, err
	}
	if !i.enabled || !i.started {
		i.mu.Unlock()
		return 0, false, nil
	}
	i.mu.Unlock()
	now, err := i.clock.Monotonic()
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.terminal != nil {
		return 0, true, i.terminal
	}
	if err != nil || !now.SameEra(i.last) || i.clock.checkMark(now) != nil {
		i.terminal = ErrContinuity
		return 0, true, i.terminal
	}
	if now.Milliseconds < i.last.Milliseconds {
		// Another qualifying activity completed while this sample was in
		// flight. Preserve that later real activity; do not move it back.
		now = i.last
	}
	elapsed := now.Milliseconds - i.last.Milliseconds
	if elapsed >= i.delta {
		i.terminal = ErrExpired
		return 0, true, i.terminal
	}
	if refresh {
		i.last = now
	}
	return i.delta - elapsed, true, nil
}

// RemainingMS is a wakeup hint, not a timer-derived authorization. Subtraction
// preserves the full uint64 duration even when last+duration would overflow.
func (i *Idle) RemainingMS() (milliseconds uint64, armed bool, err error) {
	return i.remaining(false)
}

func (i *Idle) Check() error { _, _, err := i.RemainingMS(); return err }

// Refresh first checks the old deadline at the very same sample. Activity at
// or after expiry cannot revive the Session, even if the timer ran late.
func (i *Idle) Refresh() error {
	_, _, err := i.remaining(true)
	return err
}

// CheckAt checks the original idle owner against an already sampled clock.
// Refreshing its local frontier invokes no host adapter and cannot revive an
// expired owner or a retired clock era.
func (i *Idle) CheckAt(sample Sample) error {
	current, err := i.clock.RefreshSample(sample)
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.terminal != nil {
		return i.terminal
	}
	if !i.enabled || !i.started {
		return nil
	}
	if err != nil || !current.Mark.SameEra(i.last) {
		i.terminal = ErrContinuity
		return i.terminal
	}
	if current.Milliseconds >= i.last.Milliseconds && current.Milliseconds-i.last.Milliseconds >= i.delta {
		i.terminal = ErrExpired
	}
	return i.terminal
}

// RefreshAt recognizes qualifying activity at an existing continuous sample.
// It checks the previous idle limit before advancing it and calls no host code.
func (i *Idle) RefreshAt(sample Sample) error {
	current, err := i.clock.RefreshSample(sample)
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.terminal != nil {
		return i.terminal
	}
	if !i.enabled || !i.started {
		return nil
	}
	if err != nil || !current.Mark.SameEra(i.last) {
		i.terminal = ErrContinuity
		return i.terminal
	}
	if current.Milliseconds >= i.last.Milliseconds {
		if current.Milliseconds-i.last.Milliseconds >= i.delta {
			i.terminal = ErrExpired
			return i.terminal
		}
		i.last = current.Mark
	}
	return nil
}

// RemainingMSAt projects the original idle limit at the caller's local gate.
func (i *Idle) RemainingMSAt(sample Sample) (uint64, bool, error) {
	current, err := i.clock.RefreshSample(sample)
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.terminal != nil {
		return 0, i.enabled && i.started, i.terminal
	}
	if !i.enabled || !i.started {
		return 0, false, nil
	}
	if err != nil || !current.Mark.SameEra(i.last) {
		i.terminal = ErrContinuity
		return 0, true, i.terminal
	}
	elapsed := uint64(0)
	if current.Milliseconds >= i.last.Milliseconds {
		elapsed = current.Milliseconds - i.last.Milliseconds
	}
	if elapsed >= i.delta {
		i.terminal = ErrExpired
		return 0, true, i.terminal
	}
	return i.delta - elapsed, true, nil
}
