// Package timev4 implements the original trusted time and deadline owners.
// A host/control adapter must independently establish its source and rate bounds;
// these calculations do not qualify a clock or authenticate a network response.
package timev4

import (
	"math"
	"math/big"
)

type Error string

func (e Error) Error() string { return string(e) }

const (
	ErrRate            Error = "time_rate"
	ErrOverflow        Error = "time_overflow"
	ErrInterval        Error = "time_interval"
	ErrWidth           Error = "time_width"
	ErrRoundTrip       Error = "time_round_trip"
	ErrAnchorAge       Error = "time_anchor_age"
	ErrExpired         Error = "time_expired"
	ErrUnrepresentable Error = "time_deadline_unrepresentable"
	ErrUnavailable     Error = "time_unavailable"
	ErrContinuity      Error = "time_continuity"
	ErrContradiction   Error = "time_contradiction"
	ErrPending         Error = "time_pending"
	ErrFutureTimestamp Error = "future_timestamp"
	ErrCancelled       Error = "time_cancelled"
	ErrCapacity        Error = "time_capacity"
	ErrOwner           Error = "time_owner"
)

// Rate is the immutable admitted rho and observed-difference quantization
// bound. All quantities retain the registry's full unsigned millisecond range.
type Rate struct{ Numerator, Denominator, QuantizationMS uint64 }
type Interval struct{ LowerMS, UpperMS uint64 }

func (r Rate) Validate() error {
	if r.Denominator == 0 || r.Numerator >= r.Denominator {
		return ErrRate
	}
	return nil
}

func integer(n uint64) *big.Int { return new(big.Int).SetUint64(n) }

func quotient(product, denominator *big.Int, ceiling bool) (uint64, error) {
	// Inputs and intermediates have the generated contract's finite 64/128-bit
	// bounds. No floating-point or host duration conversion enters a decision.
	if product.Sign() < 0 || product.BitLen() > 128 {
		return 0, ErrOverflow
	}
	q, rem := new(big.Int), new(big.Int)
	q.QuoRem(product, denominator, rem)
	if ceiling && rem.Sign() != 0 {
		q.Add(q, big.NewInt(1))
	}
	if !q.IsUint64() {
		return 0, ErrOverflow
	}
	return q.Uint64(), nil
}

func add(a, b uint64) (uint64, error) {
	if b > math.MaxUint64-a {
		return 0, ErrOverflow
	}
	return a + b, nil
}

func (r Rate) Elapsed(delta uint64) (lower, upper uint64, err error) {
	if err = r.Validate(); err != nil {
		return
	}
	hi, err := add(delta, r.QuantizationMS)
	if err != nil {
		return 0, 0, err
	}
	lo := uint64(0)
	if delta > r.QuantizationMS {
		lo = delta - r.QuantizationMS
	}
	den := integer(r.Denominator)
	plus := new(big.Int).Add(den, integer(r.Numerator))
	lower, err = quotient(new(big.Int).Mul(integer(lo), den), plus, false)
	if err != nil {
		return 0, 0, err
	}
	upper, err = quotient(new(big.Int).Mul(integer(hi), den), integer(r.Denominator-r.Numerator), true)
	return
}

func (i Interval) validate(maxWidth uint64) error {
	if i.LowerMS > i.UpperMS {
		return ErrInterval
	}
	if maxWidth == 0 || i.UpperMS-i.LowerMS > maxWidth {
		return ErrWidth
	}
	return nil
}

func (r Rate) NetworkAnchor(timestamp, sourceError, delta, maxRoundTrip, maxWidth uint64) (Interval, error) {
	_, elapsed, err := r.Elapsed(delta)
	if err != nil {
		return Interval{}, err
	}
	if maxRoundTrip == 0 || elapsed > maxRoundTrip {
		return Interval{}, ErrRoundTrip
	}
	if timestamp < sourceError {
		return Interval{}, ErrOverflow
	}
	upper, err := add(timestamp, sourceError)
	if err != nil {
		return Interval{}, err
	}
	upper, err = add(upper, elapsed)
	if err != nil {
		return Interval{}, err
	}
	i := Interval{timestamp - sourceError, upper}
	return i, i.validate(maxWidth)
}

func (r Rate) Advance(i Interval, delta, maxAge, maxWidth uint64) (Interval, error) {
	if i.LowerMS > i.UpperMS {
		return Interval{}, ErrInterval
	}
	lo, hi, err := r.Elapsed(delta)
	if err != nil {
		return Interval{}, err
	}
	if maxAge == 0 || hi > maxAge {
		return Interval{}, ErrAnchorAge
	}
	lo, err = add(i.LowerMS, lo)
	if err != nil {
		return Interval{}, err
	}
	hi, err = add(i.UpperMS, hi)
	if err != nil {
		return Interval{}, err
	}
	result := Interval{lo, hi}
	return result, result.validate(maxWidth)
}

func (r Rate) DeadlineDelta(upper, deadline uint64) (uint64, error) {
	if err := r.Validate(); err != nil {
		return 0, err
	}
	if upper >= deadline {
		return 0, ErrExpired
	}
	n, err := quotient(new(big.Int).Mul(integer(deadline-upper), integer(r.Denominator-r.Numerator)), integer(r.Denominator), false)
	if err != nil {
		return 0, err
	}
	if n < r.QuantizationMS {
		return 0, ErrUnrepresentable
	}
	return n - r.QuantizationMS, nil
}

func (r Rate) ProveDelta(lower, bound uint64) (uint64, error) {
	if err := r.Validate(); err != nil {
		return 0, err
	}
	if bound <= lower {
		return 0, nil
	}
	plus := new(big.Int).Add(integer(r.Denominator), integer(r.Numerator))
	n, err := quotient(new(big.Int).Mul(integer(bound-lower), plus), integer(r.Denominator), true)
	if err != nil {
		return 0, err
	}
	return add(n, r.QuantizationMS)
}

// LowerBound distinguishes a pending proof from a claimed past event beyond
// the entire trusted envelope. A future not_before is permitted to wait.
func (i Interval) LowerBound(bound uint64, claimedPast bool) error {
	if i.LowerMS > i.UpperMS {
		return ErrUnavailable
	}
	if bound <= i.LowerMS {
		return nil
	}
	if claimedPast && bound > i.UpperMS {
		return ErrFutureTimestamp
	}
	return ErrPending
}

func (i Interval) ValidBefore(deadline uint64) bool {
	return i.LowerMS <= i.UpperMS && i.UpperMS < deadline
}
func (i Interval) RetainedThrough(deadline uint64) bool {
	return i.LowerMS <= i.UpperMS && i.LowerMS >= deadline
}
