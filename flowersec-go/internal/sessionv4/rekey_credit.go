package sessionv4

import (
	"encoding/json"
	"errors"
	"math/big"
	"sync"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

var (
	ErrRekeyCredit    = errors.New("sessionv4: rekey credit unavailable")
	ErrTimeContinuity = errors.New("sessionv4: original clock continuity lost")
)

// RekeyClockSample comes from the original admitted TimeProfile adapter. Its
// incarnation changes on continuity loss; wall-clock timestamps are not ticks.
type RekeyClockSample = timev4.Tick
type RekeyClockRate = timev4.Rate
type RekeyEnvelope = protocolv4.RekeyEnvelope
type RekeyServiceBound struct{ ServiceMS, ErrorMS, PeriodMS, Capacity, MaxRounds, RequiredEpochs uint64 }

func wide(v uint64) *big.Int { return new(big.Int).SetUint64(v) }
func wideProduct(a, b *big.Int) (*big.Int, error) {
	p := new(big.Int).Mul(a, b)
	if p.Sign() < 0 || p.BitLen() > 128 {
		return nil, cryptov4.ErrConfiguration
	}
	return p, nil
}
func wideCeil(a, b *big.Int) *big.Int {
	q, rem := new(big.Int), new(big.Int)
	q.QuoRem(a, b, rem)
	if rem.Sign() != 0 {
		q.Add(q, big.NewInt(1))
	}
	return q
}

// elapsedCredit uses bounded (at most 128-bit) integer products and outward
// rounding. No float or language-dependent duration conversion enters credit.
func elapsedCredit(rate RekeyClockRate, delta uint64) (lower, upper uint64, err error) {
	if rate.Validate() != nil {
		return 0, 0, cryptov4.ErrConfiguration
	}
	lower, upper, err = rate.Elapsed(delta)
	if err != nil {
		return 0, 0, ErrTimeContinuity
	}
	return lower, upper, nil
}

// AdmitRekeyService runs before Session spend/admission. Its finite cumulative
// response bound includes the initial epoch and the whole signed service span.
// Passing this arithmetic does not qualify a clock, provider or work reserve.
func AdmitRekeyService(profile string, envelope RekeyEnvelope, rate RekeyClockRate, issued, expires uint64) (RekeyServiceBound, error) {
	var result RekeyServiceBound
	var usage struct {
		Profiles map[string]struct {
			Epochs uint64 `json:"max_epochs,string"`
		}
	}
	if json.Unmarshal([]byte(protocolv4.CryptoUsageRegistryJSON), &usage) != nil {
		return result, cryptov4.ErrConfiguration
	}
	epochs, ok := usage.Profiles[profile]
	if !ok || envelope.Burst == 0 || envelope.RefillMS == 0 || envelope.RequestStartMS == 0 || uint64(envelope.Burst) >= epochs.Epochs || rate.Denominator == 0 || rate.Numerator >= rate.Denominator || expires <= issued {
		return result, cryptov4.ErrConfiguration
	}
	B, R := uint64(envelope.Burst), uint64(envelope.RefillMS)
	minus := wide(rate.Denominator - rate.Numerator)
	// Reject incompatible error before multiplication; this also bounds the
	// actual temporary arithmetic to the registry's 128-bit intermediate cap.
	maxError := (R - 1) / B
	if maxError == 0 {
		return result, cryptov4.ErrConfiguration
	}
	numerator, _ := wideProduct(wide(maxError-1), minus)
	divisor := new(big.Int).Lsh(wide(rate.Denominator), 1)
	if wide(rate.QuantizationMS).Cmp(new(big.Int).Quo(numerator, divisor)) > 0 {
		return result, cryptov4.ErrConfiguration
	}
	errorProduct, err := wideProduct(wide(rate.QuantizationMS), divisor)
	if err != nil {
		return result, err
	}
	errorBound := wideCeil(errorProduct, minus)
	errorBound.Add(errorBound, big.NewInt(1))
	if !errorBound.IsUint64() {
		return result, cryptov4.ErrConfiguration
	}
	allowance := errorBound.Uint64()
	if allowance >= R || B > (R-1)/allowance {
		return result, cryptov4.ErrConfiguration
	}
	period := R - B*allowance
	capacity := B * R
	denominator, err := wideProduct(wide(period), minus)
	if err != nil {
		return result, err
	}
	initial, err := wideProduct(wide(capacity), minus)
	if err != nil {
		return result, err
	}
	plus := new(big.Int).Add(wide(rate.Denominator), wide(rate.Numerator))
	refill, err := wideProduct(wide(B), plus)
	if err != nil {
		return result, err
	}
	refill, err = wideProduct(refill, wide(expires-issued))
	if err != nil {
		return result, err
	}
	total := new(big.Int).Add(initial, refill)
	if total.BitLen() > 128 {
		return result, cryptov4.ErrConfiguration
	}
	rounds := new(big.Int).Quo(total, denominator)
	if !rounds.IsUint64() || rounds.Sign() == 0 || rounds.Uint64() >= epochs.Epochs {
		return result, cryptov4.ErrConfiguration
	}
	return RekeyServiceBound{expires - issued, allowance, period, capacity, rounds.Uint64(), rounds.Uint64() + 1}, nil
}

// RekeyCredit survives every round and owns the only base balance and causal
// ACK anchor. All tickets use the Environment's same original trusted clock
// and absolute authorization cap, including after an anchor refresh.
type RekeyCredit struct {
	mu                sync.Mutex
	envelope          RekeyEnvelope
	rate              RekeyClockRate
	role              protocolv4.Direction
	bound             RekeyServiceBound
	clock             *timev4.Clock
	authorization     *timev4.Deadline
	last, anchor      timev4.Sample
	hasAnchor, broken bool
	base              uint64
	epoch             uint32
	active            *RekeyCharge
	admission         *OpenAdmission
}

type RekeyCharge struct {
	credit                        *RekeyCredit
	epoch                         uint32
	charged, cancelled, completed bool
	post                          uint64
}

func NewRekeyCredit(a *OpenAdmission, envelope RekeyEnvelope, issued, expires uint64, clock *timev4.Clock) (*RekeyCredit, error) {
	if a == nil || clock == nil || a.engine.Clock() != clock {
		return nil, cryptov4.ErrConfiguration
	}
	// A handshake-backed engine fixes the original signed service envelope.
	// Lower-level record fixtures have no Artifact projection; their trusted
	// constructor still supplies these inputs explicitly.
	if session := a.engine.SessionParameters(); session.Contract.Valid() &&
		(envelope != session.Contract.Limits().Rekey || issued != session.IssuedAtMS || expires != session.SessionNotAfterMS) {
		return nil, cryptov4.ErrConfiguration
	}
	rate := clock.Profile().Rate
	_, profile := a.engine.SessionBinding()
	bound, err := AdmitRekeyService(profile, envelope, rate, issued, expires)
	if err != nil {
		return nil, err
	}
	authorization, err := timev4.NewDeadline(clock, expires)
	if err != nil {
		return nil, rekeyTimeError(err)
	}
	first, err := authorization.Sample()
	if err != nil {
		return nil, rekeyTimeError(err)
	}
	if err = first.LowerBound(issued, true); err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed || a.runtime != nil || a.rekeyCredit != nil {
		return nil, cryptov4.ErrTransition
	}
	epoch, err := a.engine.ServiceInitializationEpoch()
	if err != nil {
		return nil, err
	}
	if epoch != 0 {
		return nil, cryptov4.ErrTransition
	}
	c := &RekeyCredit{envelope: envelope, rate: rate, role: a.direction, bound: bound, clock: clock, authorization: authorization, last: first, base: bound.Capacity, admission: a}
	a.rekeyCredit = c
	return c, nil
}

func rekeyTimeError(err error) error {
	if errors.Is(err, timev4.ErrExpired) {
		return cryptov4.ErrExpired
	}
	if errors.Is(err, timev4.ErrContinuity) {
		return ErrTimeContinuity
	}
	return err
}

func (c *RekeyCredit) now() (timev4.Sample, error) {
	if c.broken {
		return timev4.Sample{}, ErrTimeContinuity
	}
	now, err := c.authorization.Sample()
	if !now.Mark.SameEra(c.last.Mark) || now.Milliseconds < c.last.Milliseconds {
		c.broken = true
		return timev4.Sample{}, ErrTimeContinuity
	}
	if err != nil {
		return timev4.Sample{}, rekeyTimeError(err)
	}
	c.last = now
	return now, nil
}

func (c *RekeyCredit) available(now timev4.Sample) (uint64, error) {
	if !c.hasAnchor {
		return c.bound.Capacity, nil
	}
	if now.Incarnation != c.anchor.Incarnation || now.Milliseconds < c.anchor.Milliseconds {
		return 0, ErrTimeContinuity
	}
	lo, hi, err := elapsedCredit(c.rate, now.Milliseconds-c.anchor.Milliseconds)
	if err != nil {
		return 0, err
	}
	u := lo
	if c.role == protocolv4.ServerToClient {
		u = hi
	}
	if u >= uint64(c.envelope.RefillMS) {
		return c.bound.Capacity, nil
	}
	refill := uint64(c.envelope.Burst) * u
	if refill >= c.bound.Capacity-c.base {
		return c.bound.Capacity, nil
	}
	return c.base + refill, nil
}

func (c *RekeyCredit) Available() (uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now, err := c.now()
	if err != nil {
		return 0, err
	}
	if c.active != nil && c.active.charged {
		return c.active.post, nil
	}
	return c.available(now)
}

// Prepare acquires no balance. The client checks affordability before freezing;
// a responder checks and consumes credit only for its actual authenticated INIT.
func (c *RekeyCredit) Prepare(epoch uint32) (*RekeyCharge, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now, err := c.now()
	if err != nil {
		return nil, err
	}
	if c.active != nil || epoch != c.epoch || uint64(epoch) >= c.bound.MaxRounds {
		return nil, cryptov4.ErrTransition
	}
	if c.role == protocolv4.ClientToServer {
		available, err := c.available(now)
		if err != nil {
			return nil, err
		}
		if available < uint64(c.envelope.RefillMS) {
			return nil, ErrRekeyCredit
		}
	}
	r := &RekeyCharge{credit: c, epoch: epoch}
	c.active = r
	return r, nil
}

// Init is invoked at the unique client INIT ticket or original server INIT
// acceptance. Repeated calls cannot re-charge, refresh or create a new anchor.
func (r *RekeyCharge) Init() error {
	c := r.credit
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.active != r || r.charged || r.cancelled || r.completed || r.epoch != c.epoch {
		return cryptov4.ErrTransition
	}
	now, err := c.now()
	if err != nil {
		return err
	}
	available, err := c.available(now)
	if err != nil {
		return err
	}
	if available < uint64(c.envelope.RefillMS) {
		return ErrRekeyCredit
	}
	r.post = available - uint64(c.envelope.RefillMS)
	r.charged = true
	return nil
}

// Ack preserves post-charge exactly; time spent inside the round earns nothing.
func (r *RekeyCharge) Ack() error {
	c := r.credit
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.active != r || !r.charged || r.completed || r.cancelled {
		return cryptov4.ErrTransition
	}
	now, err := c.now()
	if err != nil {
		return err
	}
	c.base = r.post
	c.anchor = now
	c.hasAnchor = true
	c.epoch++
	c.active = nil
	r.completed = true
	return nil
}

func (r *RekeyCharge) Cancel() error {
	c := r.credit
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.active != r || r.charged || r.completed || r.cancelled {
		return cryptov4.ErrTransition
	}
	c.active = nil
	r.cancelled = true
	return nil
}
