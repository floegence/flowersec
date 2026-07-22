// Package weaknet provides deterministic userspace network-fault relays for tests.
package weaknet

import (
	"errors"
	"fmt"
	"time"
)

var (
	ErrInvalidProfile       = errors.New("invalid weak-network profile")
	ErrByteFidelity         = errors.New("byte relay cannot model packet loss, reorder, duplicate, or MTU")
	ErrFaultNotExercised    = errors.New("configured weak-network fault was not exercised")
	ErrCounterMismatch      = errors.New("weak-network expected and actual counters differ")
	ErrConservation         = errors.New("weak-network conservation check failed")
	ErrBackpressure         = errors.New("weak-network byte relay is backpressured")
	ErrInvalidAcknowledge   = errors.New("invalid weak-network acknowledgement")
	ErrRelayNotDrained      = errors.New("weak-network relay has pending delivery state")
	ErrInvalidPump          = errors.New("invalid weak-network pump")
	ErrPumpClosed           = errors.New("weak-network pump is closed")
	ErrPumpAlreadyRun       = errors.New("weak-network pump can only run once")
	ErrHalfCloseUnsupported = errors.New("weak-network destination does not support half-close")
)

type Direction string

const (
	ClientToServer Direction = "client_to_server"
	ServerToClient Direction = "server_to_client"
)

func (d Direction) valid() bool {
	return d == ClientToServer || d == ServerToClient
}

type OrdinalRange struct {
	First uint64
	Last  uint64
}

func (r OrdinalRange) valid() bool {
	return r.First > 0 && r.Last >= r.First
}

func (r OrdinalRange) contains(ordinal uint64) bool {
	return ordinal >= r.First && ordinal <= r.Last
}

func (r OrdinalRange) count() uint64 {
	if !r.valid() {
		return 0
	}
	return r.Last - r.First + 1
}

type TimedOutage struct {
	Ordinals OrdinalRange
	Duration time.Duration
}

type RateLimit struct {
	BytesPerSecond int64
	BurstBytes     int64
}

func (r RateLimit) enabled() bool {
	return r.BytesPerSecond > 0 || r.BurstBytes > 0
}

func (r RateLimit) validate() error {
	if !r.enabled() {
		return nil
	}
	if r.BytesPerSecond <= 0 || r.BurstBytes <= 0 {
		return fmt.Errorf("%w: rate and burst must both be positive", ErrInvalidProfile)
	}
	return nil
}

// Counters are exact per-phase, per-direction observations. Unit counters mean
// datagrams for UDP and accepted writes/deliveries for byte relays.
type Counters struct {
	InputUnits         uint64
	InputBytes         uint64
	OutputUnits        uint64
	OutputBytes        uint64
	CanceledUnits      uint64
	CanceledBytes      uint64
	DroppedUnits       uint64
	DroppedBytes       uint64
	OrdinalLossUnits   uint64
	BurstLossUnits     uint64
	RandomLossUnits    uint64
	OutageUnits        uint64
	MTUDropUnits       uint64
	DelayUnits         uint64
	JitterUnits        uint64
	ReorderedUnits     uint64
	DuplicateUnits     uint64
	DuplicateBytes     uint64
	RateLimitedUnits   uint64
	NATRebinds         uint64
	FragmentUnits      uint64
	CoalescedUnits     uint64
	BackpressureUnits  uint64
	HalfCloses         uint64
	QueueOverflowUnits uint64
	QueueOverflowBytes uint64
}

func (c Counters) CheckUDPConservation() error {
	if c.InputUnits+c.DuplicateUnits != c.OutputUnits+c.DroppedUnits+c.CanceledUnits ||
		c.InputBytes+c.DuplicateBytes != c.OutputBytes+c.DroppedBytes+c.CanceledBytes {
		return fmt.Errorf("%w: UDP counters %+v", ErrConservation, c)
	}
	return nil
}

func (c Counters) CheckByteConservation() error {
	if c.DroppedUnits != 0 || c.DroppedBytes != 0 || c.DuplicateUnits != 0 ||
		c.DuplicateBytes != 0 || c.InputBytes != c.OutputBytes+c.CanceledBytes {
		return fmt.Errorf("%w: byte counters %+v", ErrConservation, c)
	}
	return nil
}

type Report struct {
	Phase     string
	Direction Direction
	Seed      int64
	Expected  Counters
	Actual    Counters
}

// UDPProfile is fully scripted by one-based datagram ordinals. Seed is required
// and preserved in reports so a future stochastic extension cannot become
// unrepeatable; this first slice does not invent random loss from that seed.
// JitterScript is applied cyclically by ordinal.
type UDPProfile struct {
	Phase        string
	Direction    Direction
	Seed         int64
	LossOrdinals []uint64
	LossBursts   []OrdinalRange
	// RandomLossBasisPoints applies a deterministic 0..9999 draw derived from
	// Seed and the one-based datagram ordinal. Zero disables stochastic loss.
	RandomLossBasisPoints uint32
	Delay                 time.Duration
	JitterScript          []time.Duration
	ReorderOrdinals       []uint64
	DuplicateOrdinals     []uint64
	Rate                  RateLimit
	Outages               []OrdinalRange
	MTU                   int
	NATRebindOrdinals     []uint64
	QueueUnits            int
	QueueBytes            int
	Expected              *Counters
}

func (p UDPProfile) Validate() error {
	if err := validateBase(p.Phase, p.Direction, p.Seed, p.Expected); err != nil {
		return err
	}
	if p.Delay < 0 || p.MTU < 0 || p.QueueUnits < 0 || p.QueueBytes < 0 {
		return fmt.Errorf("%w: negative delay, MTU, or queue limit", ErrInvalidProfile)
	}
	if p.RandomLossBasisPoints > 10_000 {
		return fmt.Errorf("%w: random loss basis points exceed 10000", ErrInvalidProfile)
	}
	if (p.QueueUnits == 0) != (p.QueueBytes == 0) {
		return fmt.Errorf("%w: queue unit and byte limits must be enabled together", ErrInvalidProfile)
	}
	for _, jitter := range p.JitterScript {
		if p.Delay+jitter < 0 {
			return fmt.Errorf("%w: jitter makes delay negative", ErrInvalidProfile)
		}
	}
	if err := p.Rate.validate(); err != nil {
		return err
	}
	if p.Rate.enabled() && p.MTU > 0 && int64(p.MTU) > p.Rate.BurstBytes {
		return fmt.Errorf("%w: token bucket burst must cover MTU", ErrInvalidProfile)
	}
	if err := validateOrdinals(p.LossOrdinals); err != nil {
		return err
	}
	if err := validateOrdinals(p.ReorderOrdinals); err != nil {
		return err
	}
	if err := validateOrdinals(p.DuplicateOrdinals); err != nil {
		return err
	}
	if err := validateOrdinals(p.NATRebindOrdinals); err != nil {
		return err
	}
	if err := validateRanges(p.LossBursts); err != nil {
		return err
	}
	return validateRanges(p.Outages)
}

// ByteProfile models only effects visible at a reliable byte-stream boundary.
// Outages delay bytes rather than discarding them, and JitterScript cycles by
// accepted write ordinal.
type ByteProfile struct {
	Phase             string
	Direction         Direction
	Seed              int64
	Delay             time.Duration
	JitterScript      []time.Duration
	Rate              RateLimit
	Outages           []TimedOutage
	FragmentPattern   []int
	CoalesceBytes     int
	BackpressureBytes int
	RequireHalfClose  bool
	Expected          *Counters

	// These fields exist only so declarative profiles fail closed instead of
	// silently pretending that a byte-stream relay can inject packet faults.
	LossOrdinals      []uint64
	ReorderOrdinals   []uint64
	DuplicateOrdinals []uint64
	MTU               int
}

func (p ByteProfile) Validate() error {
	if err := validateBase(p.Phase, p.Direction, p.Seed, p.Expected); err != nil {
		return err
	}
	if len(p.LossOrdinals) > 0 || len(p.ReorderOrdinals) > 0 ||
		len(p.DuplicateOrdinals) > 0 || p.MTU != 0 {
		return ErrByteFidelity
	}
	if p.Delay < 0 || p.CoalesceBytes < 0 || p.BackpressureBytes < 0 {
		return fmt.Errorf("%w: negative byte relay setting", ErrInvalidProfile)
	}
	for _, jitter := range p.JitterScript {
		if p.Delay+jitter < 0 {
			return fmt.Errorf("%w: jitter makes delay negative", ErrInvalidProfile)
		}
	}
	if err := p.Rate.validate(); err != nil {
		return err
	}
	if p.Rate.enabled() && p.CoalesceBytes > 0 && int64(p.CoalesceBytes) > p.Rate.BurstBytes {
		return fmt.Errorf("%w: token bucket burst must cover coalesced write", ErrInvalidProfile)
	}
	if p.BackpressureBytes > 0 && p.CoalesceBytes > p.BackpressureBytes {
		return fmt.Errorf("%w: coalesce threshold exceeds backpressure budget", ErrInvalidProfile)
	}
	for _, size := range p.FragmentPattern {
		if size <= 0 {
			return fmt.Errorf("%w: fragment sizes must be positive", ErrInvalidProfile)
		}
	}
	for _, outage := range p.Outages {
		if !outage.Ordinals.valid() || outage.Duration <= 0 {
			return fmt.Errorf("%w: invalid timed outage", ErrInvalidProfile)
		}
	}
	return nil
}

func validateBase(phase string, direction Direction, seed int64, expected *Counters) error {
	if phase == "" || !direction.valid() || seed == 0 || expected == nil {
		return fmt.Errorf("%w: phase, direction, seed, and expected counters are required", ErrInvalidProfile)
	}
	return nil
}

func validateOrdinals(ordinals []uint64) error {
	seen := make(map[uint64]struct{}, len(ordinals))
	for _, ordinal := range ordinals {
		if ordinal == 0 {
			return fmt.Errorf("%w: ordinals are one-based", ErrInvalidProfile)
		}
		if _, exists := seen[ordinal]; exists {
			return fmt.Errorf("%w: duplicate ordinal %d", ErrInvalidProfile, ordinal)
		}
		seen[ordinal] = struct{}{}
	}
	return nil
}

func validateRanges(ranges []OrdinalRange) error {
	for _, interval := range ranges {
		if !interval.valid() {
			return fmt.Errorf("%w: invalid ordinal range %+v", ErrInvalidProfile, interval)
		}
	}
	return nil
}

func containsOrdinal(ordinals []uint64, want uint64) bool {
	for _, ordinal := range ordinals {
		if ordinal == want {
			return true
		}
	}
	return false
}

func matchingRange(ranges []OrdinalRange, ordinal uint64) bool {
	for _, interval := range ranges {
		if interval.contains(ordinal) {
			return true
		}
	}
	return false
}

func rangeCount(ranges []OrdinalRange) uint64 {
	var count uint64
	for _, interval := range ranges {
		count += interval.count()
	}
	return count
}

func anyNonzero(durations []time.Duration) bool {
	for _, duration := range durations {
		if duration != 0 {
			return true
		}
	}
	return false
}
