package timev4

import (
	"crypto/rand"
	"math"
	"sync"
)

type Profile struct {
	Rate                                 Rate
	MaxWidthMS, MaxAgeMS, MaxRoundTripMS uint64
}

func (p Profile) Validate() error {
	if err := p.Rate.Validate(); err != nil {
		return err
	}
	if p.MaxWidthMS == 0 || p.MaxAgeMS == 0 || p.MaxRoundTripMS == 0 {
		return ErrUnavailable
	}
	delta, err := p.Rate.ProveDelta(0, p.MaxWidthMS)
	if err != nil {
		return err
	}
	_, _, err = p.Rate.Elapsed(delta)
	return err
}

// Tick comes only from the Environment's admitted local adapter. The adapter
// must report loss of its sleep/migration/rate guarantee, even when its raw OS
// counter keeps increasing. An OS timestamp alone does not establish this.
type Tick struct {
	Milliseconds uint64
	Incarnation  [16]byte
}

// Mark adds the clock's original continuity generation. An observed source
// failure cannot be hidden by subsequently returning the old incarnation.
type Mark struct {
	Tick
	owner *Clock
	era   uint64
}

func (m Mark) SameEra(other Mark) bool {
	return m.owner != nil && m.owner == other.owner && m.era == other.era && m.Incarnation == other.Incarnation
}

type Sample struct {
	Mark
	Interval
	valid bool
	trust uint64
}

// BelongsTo validates an immutable gate sample without invoking a host clock.
func (s Sample) BelongsTo(c *Clock) bool { return s.valid && s.owner == c && c != nil }

// CheckSample validates a previously obtained sample at a local ownership
// gate. It invokes no host adapter and cannot revive an old clock/trust era.
func (c *Clock) CheckSample(sample Sample) error {
	if c == nil || sample.owner != c {
		return ErrOwner
	}
	return c.checkSampleAt(sample, true)
}

// RefreshSample advances an in-flight sample to the latest published clock
// frontier without calling the host adapter under an ownership gate. Ordinary
// concurrent reads do not break continuity, but retired clock/trust eras and
// unavailable anchors still fail closed. Callers must use the returned bounds.
func (c *Clock) RefreshSample(sample Sample) (Sample, error) {
	if c == nil || sample.owner != c {
		return Sample{}, ErrOwner
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.checkMarkLocked(sample.Mark); err != nil {
		return Sample{}, err
	}
	if !sample.valid || sample.trust != c.trust || c.anchor == nil {
		return Sample{}, ErrUnavailable
	}
	now := Mark{Tick: c.last, owner: c, era: c.era}
	interval, err := c.interval(now)
	return Sample{Mark: now, Interval: interval, valid: err == nil, trust: c.trust}, err
}

type anchor struct {
	at, origin Mark
	interval   Interval
}

// Clock owns one anchor and one original refresh. sample is a bounded local
// read, safe for concurrent calls, never I/O or application code. The adapter
// runs outside the state gate; publication orders its original continuity era.
// Source authentication and deployment
// qualification belong to the trusted host/control adapter that installs an
// envelope; peer timestamps must never call InstallTrusted directly.
type Clock struct {
	mu                      sync.Mutex
	profile                 Profile
	sample                  func() (Tick, error)
	last                    Tick
	era                     uint64
	trust                   uint64
	hasLast, failed, closed bool
	anchor                  *anchor
	pending                 *NetworkRequest
}

func NewClock(profile Profile, sample func() (Tick, error)) (*Clock, error) {
	if err := profile.Validate(); err != nil {
		return nil, err
	}
	if sample == nil {
		return nil, ErrUnavailable
	}
	return &Clock{profile: profile, sample: sample, era: 1, trust: 1}, nil
}

func (c *Clock) Profile() Profile { return c.profile }

func (c *Clock) breakContinuity() {
	c.anchor = nil
	if c.era == math.MaxUint64 {
		c.closed = true
	} else {
		c.era++
	}
}

func (c *Clock) read() (Mark, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return Mark{}, ErrUnavailable
	}
	era, before, hadLast := c.era, c.last, c.hasLast
	c.mu.Unlock()
	returned := false
	defer func() {
		if !returned {
			// A panic or Goexit cannot leave the former anchor usable. This
			// task owns only its captured era, never a newer installation.
			c.mu.Lock()
			if c.era == era && !c.closed {
				if !c.failed {
					c.breakContinuity()
				}
				c.failed = true
			}
			c.mu.Unlock()
		}
	}()
	tick, err := c.sample()
	returned = true
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return Mark{}, ErrUnavailable
	}
	if c.era != era {
		return Mark{}, ErrContinuity
	}
	if err != nil || tick.Incarnation == ([16]byte{}) {
		if !c.failed {
			c.breakContinuity()
		}
		c.failed = true
		return Mark{}, ErrUnavailable
	}
	c.failed = false
	if c.hasLast && tick.Incarnation != c.last.Incarnation {
		c.breakContinuity()
	} else if hadLast && tick.Milliseconds < before.Milliseconds {
		c.breakContinuity()
		c.last = tick
		return Mark{}, ErrContinuity
	} else if c.hasLast && tick.Milliseconds < c.last.Milliseconds {
		// A concurrent read may have published after this call began. Its
		// real later mark is already available at this publication gate.
		// Only a value below the pre-call frontier proves counter rollback.
		tick = c.last
	}
	c.last, c.hasLast = tick, true
	if c.closed {
		return Mark{}, ErrUnavailable
	}
	return Mark{Tick: tick, owner: c, era: c.era}, nil
}

func (c *Clock) Monotonic() (Mark, error) {
	return c.read()
}

// This gate invokes no adapter. An older in-flight sample cannot reinstall an
// anchor or move a Deadline back into a continuity era already retired here.
func (c *Clock) checkMarkLocked(mark Mark) error {
	if c.closed {
		return ErrUnavailable
	}
	if mark.owner != c || !c.hasLast || mark.era != c.era || mark.Incarnation != c.last.Incarnation || mark.Milliseconds > c.last.Milliseconds {
		return ErrContinuity
	}
	return nil
}

func (c *Clock) checkMark(mark Mark) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.checkMarkLocked(mark)
}

func (c *Clock) checkSample(sample Sample) error {
	return c.checkSampleAt(sample, false)
}

func (c *Clock) checkSampleAt(sample Sample, requireFrontier bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.checkMarkLocked(sample.Mark); err != nil {
		return err
	}
	// The exported gate requires the captured envelope to still be the latest
	// published frontier. Once another monotonic read has advanced it, an
	// older envelope could authorize a gate using an arbitrarily stale upper
	// bound. Internal deadline construction may explicitly retain an original
	// sample to preserve its fixed age/cap; that path sets requireFrontier=false
	// and still checks era, owner and trust generation here.
	if requireFrontier && sample.Milliseconds != c.last.Milliseconds {
		return ErrContinuity
	}
	if !sample.valid || sample.trust != c.trust || c.anchor == nil {
		return ErrUnavailable
	}
	return nil
}

func (c *Clock) currentMarkLocked(mark Mark) (Mark, error) {
	if err := c.checkMarkLocked(mark); err != nil {
		return Mark{}, err
	}
	return Mark{Tick: c.last, owner: c, era: c.era}, nil
}

func (c *Clock) interval(now Mark) (Interval, error) {
	a := c.anchor
	if a == nil || !now.SameEra(a.origin) || now.Milliseconds < a.at.Milliseconds {
		return Interval{}, ErrUnavailable
	}
	_, age, err := c.profile.Rate.Elapsed(now.Milliseconds - a.origin.Milliseconds)
	if err != nil || age > c.profile.MaxAgeMS {
		return Interval{}, ErrUnavailable
	}
	i, err := c.profile.Rate.Advance(a.interval, now.Milliseconds-a.at.Milliseconds, c.profile.MaxAgeMS, c.profile.MaxWidthMS)
	if err != nil {
		return Interval{}, ErrUnavailable
	}
	return i, nil
}

func (c *Clock) Sample() (Sample, error) {
	now, err := c.read()
	if err != nil {
		return Sample{}, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now, err = c.currentMarkLocked(now)
	if err != nil {
		return Sample{}, err
	}
	i, err := c.interval(now)
	// Return the real mark even without a wall envelope, so an existing owner
	// can still observe that its original monotonic deadline has expired.
	return Sample{Mark: now, Interval: i, valid: err == nil, trust: c.trust}, err
}

func (c *Clock) install(now, origin Mark, interval Interval) error {
	if err := interval.validate(c.profile.MaxWidthMS); err != nil {
		return err
	}
	if previous, err := c.interval(now); err == nil {
		if interval.UpperMS < previous.LowerMS || previous.UpperMS < interval.LowerMS {
			c.anchor = nil
			// Previously issued wall envelopes cannot authorize another
			// action after an observed contradiction, even after repair.
			// Monotonic-only local windows keep their separate continuity.
			if c.trust == math.MaxUint64 {
				c.closed = true
			} else {
				c.trust++
			}
			return ErrContradiction
		}
		interval.LowerMS = max(interval.LowerMS, previous.LowerMS)
		interval.UpperMS = min(interval.UpperMS, previous.UpperMS)
	}
	c.anchor = &anchor{at: now, origin: origin, interval: interval}
	return nil
}

// InstallTrusted consumes an independently authenticated host envelope at its
// actual original sample mark. Verification delay and the original anchor age
// remain charged. It cannot silently extend an old anchor by reinstalling it.
func (c *Clock) InstallTrusted(at Mark, interval Interval) error {
	now, err := c.read()
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now, err = c.currentMarkLocked(now)
	if err != nil {
		return err
	}
	if !at.SameEra(now) || at.Milliseconds > now.Milliseconds {
		return ErrContinuity
	}
	current, err := c.profile.Rate.Advance(interval, now.Milliseconds-at.Milliseconds, c.profile.MaxAgeMS, c.profile.MaxWidthMS)
	if err != nil {
		return err
	}
	return c.install(now, at, current)
}

// NetworkRequest denotes one original, nonce-bound control query. Cancel
// revokes installation but retains the single refresh position until the real
// task calls CompleteVerified or Release. No late result can replace a newer
// request or free its reservation.
type NetworkRequest struct {
	clock                           *Clock
	start                           Mark
	nonce                           [32]byte
	cancelled, finished, completing bool
}

func (r *NetworkRequest) Nonce() [32]byte { return r.nonce }

func (c *Clock) BeginNetwork() (*NetworkRequest, error) {
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, ErrUnavailable
	}
	c.mu.Lock()
	if c.closed || c.pending != nil {
		closed := c.closed
		c.mu.Unlock()
		if closed {
			return nil, ErrUnavailable
		}
		return nil, ErrCapacity
	}
	r := &NetworkRequest{clock: c, nonce: nonce}
	c.pending = r
	c.mu.Unlock()
	adopted := false
	defer func() {
		if !adopted {
			_ = r.Release()
		}
	}()
	now, err := c.read()
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if r.cancelled || r.finished || c.pending != r {
		return nil, ErrCancelled
	}
	now, err = c.currentMarkLocked(now)
	if err != nil {
		return nil, err
	}
	r.start, adopted = now, true
	return r, nil
}

func (r *NetworkRequest) Cancel() {
	c := r.clock
	c.mu.Lock()
	defer c.mu.Unlock()
	r.cancelled = true
}

func (r *NetworkRequest) release() error {
	if r.finished || r.clock.pending != r {
		return ErrOwner
	}
	r.finished = true
	r.clock.pending = nil
	return nil
}

func (r *NetworkRequest) Release() error {
	r.clock.mu.Lock()
	defer r.clock.mu.Unlock()
	if r.completing {
		return ErrCapacity
	}
	return r.release()
}

// CompleteVerified is called by the trusted control adapter only after it
// authenticates the source, nonce, timestamp and source error bound using its
// independently configured trust. This is not a peer-facing verifier or a
// replacement time wire protocol. The complete round trip, including source
// processing and local verification, contributes to the upper bound.
func (r *NetworkRequest) CompleteVerified(nonce [32]byte, timestamp, sourceError uint64) error {
	c := r.clock
	c.mu.Lock()
	if r.finished || r.completing || c.pending != r {
		c.mu.Unlock()
		return ErrOwner
	}
	r.completing = true
	cancelled := r.cancelled
	c.mu.Unlock()
	// The same refresh position survives adapter calls, cancellation and
	// abnormal exit. No new refresh may overlap its installation attempt.
	defer func() {
		c.mu.Lock()
		r.completing = false
		_ = r.release()
		c.mu.Unlock()
	}()
	if cancelled {
		return ErrCancelled
	}
	if nonce != r.nonce {
		return ErrOwner
	}
	now, err := c.read()
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if r.cancelled {
		return ErrCancelled
	}
	now, err = c.currentMarkLocked(now)
	if err != nil {
		return err
	}
	if !now.SameEra(r.start) {
		return ErrContinuity
	}
	i, err := c.profile.Rate.NetworkAnchor(timestamp, sourceError, now.Milliseconds-r.start.Milliseconds, c.profile.MaxRoundTripMS, c.profile.MaxWidthMS)
	if err != nil {
		return err
	}
	return c.install(now, now, i)
}

func (c *Clock) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed, c.anchor = true, nil
	if c.pending != nil {
		c.pending.cancelled = true
	}
}
