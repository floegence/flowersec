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
}
type anchor struct {
	at, origin Mark
	interval   Interval
}

// Clock owns one anchor and one original refresh. sample is a bounded local
// read, never I/O or application code. Source authentication and deployment
// qualification belong to the trusted host/control adapter that installs an
// envelope; peer timestamps must never call InstallTrusted directly.
type Clock struct {
	mu                      sync.Mutex
	profile                 Profile
	sample                  func() (Tick, error)
	last                    Tick
	era                     uint64
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
	return &Clock{profile: profile, sample: sample, era: 1}, nil
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
	if c.closed {
		return Mark{}, ErrUnavailable
	}
	tick, err := c.sample()
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
	} else if c.hasLast && tick.Milliseconds < c.last.Milliseconds {
		c.breakContinuity()
		c.last = tick
		return Mark{}, ErrContinuity
	}
	c.last, c.hasLast = tick, true
	if c.closed {
		return Mark{}, ErrUnavailable
	}
	return Mark{Tick: tick, owner: c, era: c.era}, nil
}

func (c *Clock) Monotonic() (Mark, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.read()
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
	c.mu.Lock()
	defer c.mu.Unlock()
	now, err := c.read()
	if err != nil {
		return Sample{}, err
	}
	i, err := c.interval(now)
	// Return the real mark even without a wall envelope, so an existing owner
	// can still observe that its original monotonic deadline has expired.
	return Sample{Mark: now, Interval: i, valid: err == nil}, err
}

func (c *Clock) install(now, origin Mark, interval Interval) error {
	if err := interval.validate(c.profile.MaxWidthMS); err != nil {
		return err
	}
	if previous, err := c.interval(now); err == nil {
		if interval.UpperMS < previous.LowerMS || previous.UpperMS < interval.LowerMS {
			c.anchor = nil
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
	c.mu.Lock()
	defer c.mu.Unlock()
	now, err := c.read()
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
	clock               *Clock
	start               Mark
	nonce               [32]byte
	cancelled, finished bool
}

func (r *NetworkRequest) Nonce() [32]byte { return r.nonce }

func (c *Clock) BeginNetwork() (*NetworkRequest, error) {
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, ErrUnavailable
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pending != nil {
		return nil, ErrCapacity
	}
	now, err := c.read()
	if err != nil {
		return nil, err
	}
	r := &NetworkRequest{clock: c, start: now, nonce: nonce}
	c.pending = r
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
	defer c.mu.Unlock()
	if err := r.release(); err != nil {
		return err
	}
	if r.cancelled {
		return ErrCancelled
	}
	if nonce != r.nonce {
		return ErrOwner
	}
	now, err := c.read()
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
