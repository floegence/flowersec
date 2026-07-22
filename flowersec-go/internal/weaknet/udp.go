package weaknet

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

type Datagram struct {
	At      time.Duration
	Payload []byte
	Target  net.Addr
}

type UDPDelivery struct {
	Ordinal   uint64
	ReadyAt   time.Duration
	Payload   []byte
	Duplicate bool
	Target    net.Addr
}

type RebindEvent struct {
	Phase     string
	Direction Direction
	Seed      int64
	Ordinal   uint64
}

type NATRebindFunc func(context.Context, RebindEvent) error

type UDPOptions struct {
	NATRebind NATRebindFunc
}

type UDPRelay struct {
	mu sync.Mutex

	profile          UDPProfile
	options          UDPOptions
	rate             tokenBucket
	ordinal          uint64
	actual           Counters
	pending          []UDPDelivery
	pendingReorders  uint64
	outstandingUnits uint64
	outstandingBytes uint64
	outstandingSizes map[int]uint64
}

func NewUDPRelay(profile UDPProfile, options UDPOptions) (*UDPRelay, error) {
	if err := profile.Validate(); err != nil {
		return nil, err
	}
	if len(profile.NATRebindOrdinals) > 0 && options.NATRebind == nil {
		return nil, fmt.Errorf("%w: NAT rebind seam is required", ErrInvalidProfile)
	}
	profile = cloneUDPProfile(profile)
	return &UDPRelay{
		profile: profile,
		options: options,
		rate:    newTokenBucket(profile.Rate),
	}, nil
}

func cloneUDPProfile(profile UDPProfile) UDPProfile {
	expected := *profile.Expected
	profile.Expected = &expected
	profile.LossOrdinals = append([]uint64(nil), profile.LossOrdinals...)
	profile.LossBursts = append([]OrdinalRange(nil), profile.LossBursts...)
	profile.JitterScript = append([]time.Duration(nil), profile.JitterScript...)
	profile.ReorderOrdinals = append([]uint64(nil), profile.ReorderOrdinals...)
	profile.DuplicateOrdinals = append([]uint64(nil), profile.DuplicateOrdinals...)
	profile.Outages = append([]OrdinalRange(nil), profile.Outages...)
	profile.NATRebindOrdinals = append([]uint64(nil), profile.NATRebindOrdinals...)
	return profile
}

// Process assigns the next one-based ordinal and returns writes in relay order.
// Calls for a single direction must be serialized when payload-to-ordinal identity matters.
func (r *UDPRelay) Process(ctx context.Context, datagram Datagram) ([]UDPDelivery, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if datagram.At < 0 {
		return nil, fmt.Errorf("%w: negative arrival time", ErrInvalidProfile)
	}

	r.ordinal++
	ordinal := r.ordinal
	payload := append([]byte(nil), datagram.Payload...)
	r.actual.InputUnits++
	r.actual.InputBytes += uint64(len(payload))

	if containsOrdinal(r.profile.NATRebindOrdinals, ordinal) {
		event := RebindEvent{
			Phase: r.profile.Phase, Direction: r.profile.Direction,
			Seed: r.profile.Seed, Ordinal: ordinal,
		}
		if err := r.options.NATRebind(ctx, event); err != nil {
			r.cancel(payload, 1)
			return nil, fmt.Errorf("NAT rebind at ordinal %d: %w", ordinal, err)
		}
		r.actual.NATRebinds++
	}

	switch {
	case matchingRange(r.profile.Outages, ordinal):
		r.drop(payload)
		r.actual.OutageUnits++
		return nil, nil
	case containsOrdinal(r.profile.LossOrdinals, ordinal):
		r.drop(payload)
		r.actual.OrdinalLossUnits++
		return nil, nil
	case matchingRange(r.profile.LossBursts, ordinal):
		r.drop(payload)
		r.actual.BurstLossUnits++
		return nil, nil
	case seededRandomLoss(r.profile.Seed, ordinal, r.profile.RandomLossBasisPoints):
		r.drop(payload)
		r.actual.RandomLossUnits++
		return nil, nil
	case r.profile.MTU > 0 && len(payload) > r.profile.MTU:
		r.drop(payload)
		r.actual.MTUDropUnits++
		return nil, nil
	}

	copies := 1
	if containsOrdinal(r.profile.DuplicateOrdinals, ordinal) {
		copies++
		r.actual.DuplicateUnits++
		r.actual.DuplicateBytes += uint64(len(payload))
	}
	deliveries := make([]UDPDelivery, 0, copies)
	for copyIndex := 0; copyIndex < copies; copyIndex++ {
		if r.queueFullLocked(len(payload)) {
			r.drop(payload)
			r.actual.QueueOverflowUnits++
			r.actual.QueueOverflowBytes += uint64(len(payload))
			continue
		}
		ready := datagram.At
		if r.profile.Delay > 0 {
			ready += r.profile.Delay
			r.actual.DelayUnits++
		}
		if len(r.profile.JitterScript) > 0 {
			jitter := r.profile.JitterScript[(ordinal-1)%uint64(len(r.profile.JitterScript))]
			ready += jitter
			if jitter != 0 {
				r.actual.JitterUnits++
			}
		}
		var limited bool
		var err error
		nextRate := r.rate
		ready, limited, err = nextRate.schedule(ready, len(payload))
		if err != nil {
			for _, admitted := range deliveries {
				r.unadmitLocked(len(admitted.Payload))
			}
			r.cancel(payload, uint64(len(deliveries)+copies-copyIndex))
			return nil, err
		}
		r.rate = nextRate
		if limited {
			r.actual.RateLimitedUnits++
		}
		delivery := UDPDelivery{
			Ordinal: ordinal, ReadyAt: ready,
			Payload: append([]byte(nil), payload...), Duplicate: copyIndex > 0, Target: datagram.Target,
		}
		r.admitLocked(delivery)
		deliveries = append(deliveries, delivery)
	}

	if containsOrdinal(r.profile.ReorderOrdinals, ordinal) {
		r.pending = append(r.pending, deliveries...)
		r.pendingReorders++
		return nil, nil
	}
	if len(r.pending) == 0 {
		return deliveries, nil
	}

	lastReady := datagram.At
	for _, delivery := range deliveries {
		if delivery.ReadyAt > lastReady {
			lastReady = delivery.ReadyAt
		}
	}
	for index := range r.pending {
		if r.pending[index].ReadyAt <= lastReady {
			lastReady++
			r.pending[index].ReadyAt = lastReady
		} else {
			lastReady = r.pending[index].ReadyAt
		}
	}
	deliveries = append(deliveries, r.pending...)
	r.actual.ReorderedUnits += r.pendingReorders
	r.pending = nil
	r.pendingReorders = 0
	return deliveries, nil
}

func (r *UDPRelay) queueFullLocked(size int) bool {
	if r.profile.QueueUnits == 0 {
		return false
	}
	return r.outstandingUnits+1 > uint64(r.profile.QueueUnits) ||
		r.outstandingBytes+uint64(size) > uint64(r.profile.QueueBytes)
}

func (r *UDPRelay) admitLocked(delivery UDPDelivery) {
	size := len(delivery.Payload)
	r.outstandingUnits++
	r.outstandingBytes += uint64(size)
	if r.outstandingSizes == nil {
		r.outstandingSizes = make(map[int]uint64)
	}
	r.outstandingSizes[size]++
}

func (r *UDPRelay) unadmitLocked(size int) {
	r.outstandingUnits--
	r.outstandingBytes -= uint64(size)
	r.outstandingSizes[size]--
	if r.outstandingSizes[size] == 0 {
		delete(r.outstandingSizes, size)
	}
}

// Acknowledge releases one successfully written datagram from the modeled queue.
func (r *UDPRelay) Acknowledge(bytes int) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if bytes < 0 {
		return ErrInvalidAcknowledge
	}
	if r.outstandingUnits == 0 || r.outstandingSizes[bytes] == 0 {
		return ErrInvalidAcknowledge
	}
	r.outstandingUnits--
	r.outstandingBytes -= uint64(bytes)
	r.outstandingSizes[bytes]--
	if r.outstandingSizes[bytes] == 0 {
		delete(r.outstandingSizes, bytes)
	}
	r.actual.OutputUnits++
	r.actual.OutputBytes += uint64(bytes)
	return nil
}

func (r *UDPRelay) drop(payload []byte) {
	r.actual.DroppedUnits++
	r.actual.DroppedBytes += uint64(len(payload))
}

func (r *UDPRelay) cancel(payload []byte, units uint64) {
	r.actual.CanceledUnits += units
	r.actual.CanceledBytes += units * uint64(len(payload))
}

// Flush returns held datagrams without claiming that an uncompleted reorder hit.
func (r *UDPRelay) Flush() []UDPDelivery {
	r.mu.Lock()
	defer r.mu.Unlock()
	output := append([]UDPDelivery(nil), r.pending...)
	r.pending = nil
	r.pendingReorders = 0
	return output
}

func (r *UDPRelay) Report() Report {
	r.mu.Lock()
	defer r.mu.Unlock()
	return Report{
		Phase: r.profile.Phase, Direction: r.profile.Direction, Seed: r.profile.Seed,
		Expected: *r.profile.Expected, Actual: r.actual,
	}
}

func (r *UDPRelay) discardPending() {
	r.mu.Lock()
	r.actual.CanceledUnits += r.outstandingUnits
	r.actual.CanceledBytes += r.outstandingBytes
	r.pending = nil
	r.pendingReorders = 0
	r.outstandingUnits = 0
	r.outstandingBytes = 0
	r.outstandingSizes = nil
	r.mu.Unlock()
}

func (r *UDPRelay) verifyDrained() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.verifyDrainedLocked()
}

func (r *UDPRelay) verifyDrainedLocked() error {
	if len(r.pending) != 0 || r.pendingReorders != 0 || r.outstandingUnits != 0 ||
		r.outstandingBytes != 0 || len(r.outstandingSizes) != 0 {
		return fmt.Errorf("%w: pending=%d reorders=%d outstanding=%d/%d", ErrRelayNotDrained,
			len(r.pending), r.pendingReorders, r.outstandingUnits, r.outstandingBytes)
	}
	return nil
}

func (r *UDPRelay) Verify() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.verifyDrainedLocked(); err != nil {
		return err
	}
	if r.actual != *r.profile.Expected {
		return fmt.Errorf("%w: expected %+v, actual %+v", ErrCounterMismatch, *r.profile.Expected, r.actual)
	}
	if err := r.actual.CheckUDPConservation(); err != nil {
		return err
	}
	checks := []struct {
		name string
		want uint64
		got  uint64
	}{
		{"ordinal loss", uint64(len(r.profile.LossOrdinals)), r.actual.OrdinalLossUnits},
		{"burst loss", rangeCount(r.profile.LossBursts), r.actual.BurstLossUnits},
		{"outage", rangeCount(r.profile.Outages), r.actual.OutageUnits},
		{"reorder", uint64(len(r.profile.ReorderOrdinals)), r.actual.ReorderedUnits},
		{"duplicate", uint64(len(r.profile.DuplicateOrdinals)), r.actual.DuplicateUnits},
		{"NAT rebind", uint64(len(r.profile.NATRebindOrdinals)), r.actual.NATRebinds},
	}
	if r.profile.RandomLossBasisPoints > 0 && r.actual.RandomLossUnits == 0 {
		return fmt.Errorf("%w: random loss", ErrFaultNotExercised)
	}
	for _, check := range checks {
		if check.want != check.got {
			return fmt.Errorf("%w: %s hits=%d, want=%d", ErrFaultNotExercised, check.name, check.got, check.want)
		}
	}
	if r.profile.MTU > 0 && r.actual.MTUDropUnits == 0 {
		return fmt.Errorf("%w: MTU ceiling", ErrFaultNotExercised)
	}
	if r.profile.Delay > 0 && r.actual.DelayUnits == 0 {
		return fmt.Errorf("%w: delay", ErrFaultNotExercised)
	}
	if anyNonzero(r.profile.JitterScript) && r.actual.JitterUnits == 0 {
		return fmt.Errorf("%w: jitter", ErrFaultNotExercised)
	}
	if r.profile.Rate.enabled() && r.actual.RateLimitedUnits == 0 {
		return fmt.Errorf("%w: rate limit", ErrFaultNotExercised)
	}
	if r.profile.QueueUnits > 0 && r.actual.QueueOverflowUnits == 0 {
		return fmt.Errorf("%w: queue overflow", ErrFaultNotExercised)
	}
	return nil
}

// seededRandomLoss uses SplitMix64 as a stateless, reproducible sampler. The
// result depends only on the frozen seed and packet ordinal, so cancellation or
// unrelated traffic cannot shift the random-loss sequence.
func seededRandomLoss(seed int64, ordinal uint64, basisPoints uint32) bool {
	if basisPoints == 0 {
		return false
	}
	value := uint64(seed) ^ (ordinal * 0x9e3779b97f4a7c15)
	value += 0x9e3779b97f4a7c15
	value = (value ^ (value >> 30)) * 0xbf58476d1ce4e5b9
	value = (value ^ (value >> 27)) * 0x94d049bb133111eb
	value ^= value >> 31
	return value%10_000 < uint64(basisPoints)
}
