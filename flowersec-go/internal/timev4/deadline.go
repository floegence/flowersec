package timev4

import "sync"

// Window is a non-recoverable local work limit. It needs no wall-clock anchor,
// but loss of the original continuous bounded monotonic clock ends it forever.
type Window struct {
	mu       sync.Mutex
	clock    *Clock
	start    Mark
	duration uint64
	terminal error
}

func NewWindow(c *Clock, duration uint64) (*Window, error) {
	if c == nil {
		return nil, ErrUnavailable
	}
	now, err := c.Monotonic()
	if err != nil {
		return nil, err
	}
	return NewWindowAt(c, now, duration)
}

func NewWindowAt(c *Clock, start Mark, duration uint64) (*Window, error) {
	if c == nil || start.owner != c {
		return nil, ErrOwner
	}
	if err := c.checkMark(start); err != nil {
		return nil, err
	}
	_, uncertainty, err := c.profile.Rate.Elapsed(0)
	if err != nil {
		return nil, err
	}
	if duration <= uncertainty {
		return nil, ErrExpired
	}
	return &Window{clock: c, start: start, duration: duration}, nil
}

func (w *Window) check(now Mark, sampleErr error) error {
	if w.terminal != nil {
		return w.terminal
	}
	if sampleErr != nil || !now.SameEra(w.start) || now.Milliseconds < w.start.Milliseconds || w.clock.checkMark(now) != nil {
		w.terminal = ErrContinuity
		return w.terminal
	}
	_, elapsed, err := w.clock.profile.Rate.Elapsed(now.Milliseconds - w.start.Milliseconds)
	if err != nil {
		w.terminal = err
	} else if elapsed >= w.duration {
		w.terminal = ErrExpired
	}
	return w.terminal
}

func (w *Window) Check() error {
	now, err := w.clock.Monotonic()
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.check(now, err)
}

func (w *Window) CheckAt(now Mark) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.check(now, nil)
}

// RemainingMS gives the original owner's bounded wakeup without resetting the
// window. Outward rounding may schedule a final one-millisecond recheck before
// the strict elapsed_upper predicate proves expiry.
func (w *Window) RemainingMS() (uint64, error) {
	now, err := w.clock.Monotonic()
	w.mu.Lock()
	defer w.mu.Unlock()
	if err = w.check(now, err); err != nil {
		return 0, err
	}
	delta, err := w.clock.profile.Rate.DeadlineDelta(0, w.duration)
	if err != nil {
		return 0, err
	}
	elapsed := now.Milliseconds - w.start.Milliseconds
	if elapsed >= delta {
		return 1, nil
	}
	return delta - elapsed, nil
}

// RemainingMSAt shares an existing local mark without calling the host adapter.
func (w *Window) RemainingMSAt(now Mark) (uint64, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.check(now, nil); err != nil {
		return 0, err
	}
	delta, err := w.clock.profile.Rate.DeadlineDelta(0, w.duration)
	if err != nil {
		return 0, err
	}
	elapsed := now.Milliseconds - w.start.Milliseconds
	if elapsed >= delta {
		return 1, nil
	}
	return delta - elapsed, nil
}

func (w *Window) Cancel() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.terminal == nil {
		w.terminal = ErrCancelled
	}
}

// Deadline retains a fixed original absolute cap and the earliest projection
// installed in each continuous clock era. Revalidation after an incarnation
// change can only use this same cap; it cannot restore a terminal owner. The
// caller must separately prove that its protocol memory has not rolled back.
type Deadline struct {
	mu                sync.Mutex
	clock             *Clock
	cap               uint64
	projection        Mark
	monotonicDeadline uint64
	terminal          error
}

func (d *Deadline) BelongsTo(c *Clock) bool { return d != nil && d.clock == c }

func NewDeadline(c *Clock, cap uint64) (*Deadline, error) {
	if c == nil {
		return nil, ErrUnavailable
	}
	sample, err := c.Sample()
	if err != nil {
		return nil, err
	}
	return newDeadlineAt(c, sample, cap)
}

// NewDeadlineAt fixes an independent absolute deadline at the owner's original
// sample. Callers charge its backing before creating it. A later Start cannot
// improve this first conservative projection by obtaining a narrower anchor.
func NewDeadlineAt(c *Clock, sample Sample, cap uint64) (*Deadline, error) {
	if c == nil || sample.owner != c || !sample.valid {
		return nil, ErrOwner
	}
	return newDeadlineAt(c, sample, cap)
}

func newDeadlineAt(c *Clock, sample Sample, cap uint64) (*Deadline, error) {
	d := &Deadline{clock: c, cap: cap}
	if err := d.check(sample, nil); err != nil {
		return nil, err
	}
	return d, nil
}

func NewAge(c *Clock, duration, parentCap uint64) (*Deadline, error) {
	if c == nil {
		return nil, ErrUnavailable
	}
	sample, err := c.Sample()
	if err != nil {
		return nil, err
	}
	return NewAgeAt(c, sample, duration, parentCap)
}

// NewAgeAt pins the actual start_lower, never a later installation timestamp.
// parentCap is mandatory; callers without an earlier parent use MaxUint64.
func NewAgeAt(c *Clock, start Sample, duration, parentCap uint64) (*Deadline, error) {
	if c == nil || start.owner != c || !start.valid {
		return nil, ErrUnavailable
	}
	cap, err := add(start.LowerMS, duration)
	if err != nil {
		return nil, err
	}
	return newDeadlineAt(c, start, min(cap, parentCap))
}

func (d *Deadline) check(sample Sample, sampleErr error) error {
	if d.terminal != nil {
		return d.terminal
	}
	if sample.Mark.SameEra(d.projection) && sample.Milliseconds >= d.monotonicDeadline {
		d.terminal = ErrExpired
		return d.terminal
	}
	if sampleErr != nil {
		return sampleErr
	}
	if sample.owner != d.clock || !sample.valid {
		return ErrUnavailable
	}
	if err := d.clock.checkSample(sample); err != nil {
		return err
	}
	if !sample.ValidBefore(d.cap) {
		d.terminal = ErrExpired
		return d.terminal
	}
	delta, err := d.clock.profile.Rate.DeadlineDelta(sample.UpperMS, d.cap)
	if err != nil {
		d.terminal = err
		return err
	}
	until, err := add(sample.Milliseconds, delta)
	if err != nil {
		d.terminal = err
		return err
	}
	if sample.Mark.SameEra(d.projection) {
		until = min(until, d.monotonicDeadline)
	}
	d.projection, d.monotonicDeadline = sample.Mark, until
	if sample.Milliseconds >= until {
		d.terminal = ErrExpired
	}
	return d.terminal
}

// Sample checks the original gate and returns exactly the sample used there.
// An unavailable wall anchor suspends a live recoverable owner; a known
// original monotonic expiry still terminates it even while wall time is absent.
func (d *Deadline) Sample() (Sample, error) {
	sample, err := d.clock.Sample()
	d.mu.Lock()
	defer d.mu.Unlock()
	return sample, d.check(sample, err)
}

func (d *Deadline) Check() error { _, err := d.Sample(); return err }

// CheckAt consumes the actual immutable gate sample shared with an adjacent
// accounting operation. It does not sample a second, later timestamp.
func (d *Deadline) CheckAt(sample Sample) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.check(sample, nil)
}

func (d *Deadline) Cap() uint64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.cap
}

func (d *Deadline) Tighten(cap uint64) error {
	d.mu.Lock()
	if cap > d.cap {
		d.mu.Unlock()
		return ErrOwner
	}
	d.cap = cap
	d.mu.Unlock()
	sample, err := d.clock.Sample()
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.check(sample, err)
}

// TightenAt applies an adjacent owner's actual sample without calling the
// adapter inside its publication gate. The original cap can only decrease.
func (d *Deadline) TightenAt(cap uint64, sample Sample) error {
	if d == nil || !sample.BelongsTo(d.clock) {
		return ErrOwner
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if cap > d.cap {
		return ErrOwner
	}
	d.cap = cap
	return d.check(sample, nil)
}

// TightenAgeAt anchors a run limit at the first actual application entry.
// Both the original wall cap and the earliest monotonic projection survive;
// repeated items cannot extend this owner or allocate replacement deadlines.
func (d *Deadline) TightenAgeAt(start Sample, duration uint64) error {
	if d == nil || start.owner != d.clock || !start.valid || duration == 0 {
		return ErrOwner
	}
	cap, err := add(start.LowerMS, duration)
	if err != nil {
		return err
	}
	now, sampleErr := d.clock.Sample()
	d.mu.Lock()
	defer d.mu.Unlock()
	child := Deadline{clock: d.clock, cap: min(cap, d.cap)}
	if err := child.check(start, nil); err != nil {
		return err
	}
	if err = d.check(now, sampleErr); err != nil {
		return err
	}
	if child.projection.SameEra(d.projection) {
		child.monotonicDeadline = min(child.monotonicDeadline, d.monotonicDeadline)
	}
	if err := child.check(now, nil); err != nil {
		return err
	}
	d.cap, d.projection, d.monotonicDeadline = child.cap, child.projection, child.monotonicDeadline
	return nil
}

// Fork creates a separately cancellable owner of this exact original cap and
// earliest monotonic projection. It cannot turn an improved wall-clock anchor
// into additional time. The caller reserves the new deadline before this call.
func (d *Deadline) Fork(cap uint64) (*Deadline, error) {
	if d == nil {
		return nil, ErrOwner
	}
	sample, err := d.clock.Sample()
	d.mu.Lock()
	defer d.mu.Unlock()
	if cap > d.cap {
		return nil, ErrOwner
	}
	if err = d.check(sample, err); err != nil {
		return nil, err
	}
	child := &Deadline{clock: d.clock, cap: cap, projection: d.projection, monotonicDeadline: d.monotonicDeadline}
	if err := child.check(sample, nil); err != nil {
		return nil, err
	}
	return child, nil
}

// ForkAt preserves the original projection when an already admitted adjacent
// owner supplies the same clock's current sample at its ownership gate.
func (d *Deadline) ForkAt(cap uint64, sample Sample) (*Deadline, error) {
	if d == nil || !sample.BelongsTo(d.clock) {
		return nil, ErrOwner
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if cap > d.cap {
		return nil, ErrOwner
	}
	if err := d.check(sample, nil); err != nil {
		return nil, err
	}
	child := &Deadline{clock: d.clock, cap: cap, projection: d.projection, monotonicDeadline: d.monotonicDeadline}
	if err := child.check(sample, nil); err != nil {
		return nil, err
	}
	return child, nil
}

// ForkAgeAt fixes a separately cancellable child's age from the actual original
// start sample. Both that age projection and the parent's earlier projection
// survive a subsequently improved wall anchor. Only one child is allocated.
func (d *Deadline) ForkAgeAt(start Sample, duration uint64) (*Deadline, error) {
	if d == nil || start.owner != d.clock || !start.valid {
		return nil, ErrOwner
	}
	cap, err := add(start.LowerMS, duration)
	if err != nil {
		return nil, err
	}
	now, sampleErr := d.clock.Sample()
	d.mu.Lock()
	defer d.mu.Unlock()
	child, err := newDeadlineAt(d.clock, start, min(cap, d.cap))
	if err != nil {
		return nil, err
	}
	if err = d.check(now, sampleErr); err != nil {
		return nil, err
	}
	if child.projection.SameEra(d.projection) {
		child.monotonicDeadline = min(child.monotonicDeadline, d.monotonicDeadline)
	}
	if err := child.check(now, nil); err != nil {
		return nil, err
	}
	return child, nil
}

// ForkAgeUsingSample begins a child at an adjacent authorization gate's exact
// current sample. It invokes no host adapter; the child retains both this age
// bound and the parent's earlier absolute/monotonic projection.
func (d *Deadline) ForkAgeUsingSample(start Sample, duration uint64) (*Deadline, error) {
	if d == nil || !start.BelongsTo(d.clock) {
		return nil, ErrOwner
	}
	cap, err := add(start.LowerMS, duration)
	if err != nil {
		return nil, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.check(start, nil); err != nil {
		return nil, err
	}
	child := &Deadline{clock: d.clock, cap: min(d.cap, cap), projection: d.projection, monotonicDeadline: d.monotonicDeadline}
	if err := child.check(start, nil); err != nil {
		return nil, err
	}
	return child, nil
}

// RemainingMS is for the owner's single merged wakeup. Host timer adapters may
// clamp it to a representable chunk; every actual action must still call Check.
// No uint64 millisecond deadline is narrowed into a nanosecond duration here.
func (d *Deadline) RemainingMS() (uint64, error) {
	sample, err := d.clock.Sample()
	d.mu.Lock()
	defer d.mu.Unlock()
	if err = d.check(sample, err); err != nil {
		return 0, err
	}
	return d.monotonicDeadline - sample.Milliseconds, nil
}

// RemainingMSAt shares the owner's immutable gate sample with a bounded table
// sweep. It preserves the original cap and earliest projection without invoking
// a clock callback under the table's gate or resampling once per row.
func (d *Deadline) RemainingMSAt(sample Sample) (uint64, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.check(sample, nil); err != nil {
		return 0, err
	}
	return d.monotonicDeadline - sample.Milliseconds, nil
}

func (d *Deadline) Cancel() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.terminal == nil {
		d.terminal = ErrCancelled
	}
}

// TightenFrom intersects two original owners without choosing a new start.
// Their absolute caps and earliest projection in the current continuous era
// both survive. It is used when one already admitted execution lends its exact
// run deadline to the transport that publishes its stream items.
func (d *Deadline) TightenFrom(original *Deadline) error {
	if d == nil || original == nil || d.clock != original.clock {
		return ErrOwner
	}
	if d == original {
		return d.Check()
	}
	sample, err := original.clock.Sample()
	if err != nil {
		return err
	}
	return d.TightenFromAt(original, sample)
}

// TightenFromAt intersects original projections using an already obtained
// sample, without calling the host clock while an admission gate is held.
func (d *Deadline) TightenFromAt(original *Deadline, sample Sample) error {
	if d == nil || original == nil || d.clock != original.clock {
		return ErrOwner
	}
	if d == original {
		return d.CheckAt(sample)
	}
	original.mu.Lock()
	err := original.check(sample, nil)
	cap, projection, until := original.cap, original.projection, original.monotonicDeadline
	original.mu.Unlock()
	if err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.cap = min(d.cap, cap)
	if projection.SameEra(d.projection) {
		d.monotonicDeadline = min(d.monotonicDeadline, until)
	} else if projection.era > d.projection.era {
		d.projection, d.monotonicDeadline = projection, until
	}
	return d.check(sample, nil)
}

// CheckUsingSample advances an existing observation to the current local
// frontier, without calling the host clock under a finite ownership gate.
func (d *Deadline) CheckUsingSample(sample Sample) error {
	current, err := d.clock.RefreshSample(sample)
	if err != nil {
		return err
	}
	return d.CheckAt(current)
}
