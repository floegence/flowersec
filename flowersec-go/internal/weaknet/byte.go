package weaknet

import (
	"fmt"
	"io"
	"sync"
	"time"
)

type ByteChunk struct {
	At      time.Duration
	Payload []byte
}

type ByteDelivery struct {
	Ordinal   uint64
	ReadyAt   time.Duration
	Payload   []byte
	HalfClose bool
}

type ByteRelay struct {
	mu sync.Mutex

	profile ByteProfile
	rate    tokenBucket
	ordinal uint64
	actual  Counters

	buffer           []byte
	bufferReadyAt    time.Duration
	bufferOrdinal    uint64
	bufferPieces     []int
	fragmentedWrites uint64
	outstanding      uint64
	outstandingSizes []uint64
	writeClosed      bool
}

func NewByteRelay(profile ByteProfile) (*ByteRelay, error) {
	if err := profile.Validate(); err != nil {
		return nil, err
	}
	profile = cloneByteProfile(profile)
	return &ByteRelay{profile: profile, rate: newTokenBucket(profile.Rate)}, nil
}

// Write accepts bytes or returns ErrBackpressure without consuming an ordinal.
func (r *ByteRelay) Write(chunk ByteChunk) ([]ByteDelivery, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.writeClosed {
		return nil, io.ErrClosedPipe
	}
	if chunk.At < 0 || len(chunk.Payload) == 0 {
		return nil, fmt.Errorf("%w: byte writes require non-empty payload and non-negative time", ErrInvalidProfile)
	}
	buffered := r.outstanding + uint64(len(r.buffer))
	if r.profile.BackpressureBytes > 0 &&
		buffered+uint64(len(chunk.Payload)) > uint64(r.profile.BackpressureBytes) {
		r.actual.BackpressureUnits++
		return nil, ErrBackpressure
	}

	r.ordinal++
	ordinal := r.ordinal
	r.actual.InputUnits++
	r.actual.InputBytes += uint64(len(chunk.Payload))
	ready := chunk.At
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
	for _, outage := range r.profile.Outages {
		if outage.Ordinals.contains(ordinal) {
			ready += outage.Duration
			r.actual.OutageUnits++
			break
		}
	}

	fragments := fragment(chunk.Payload, r.profile.FragmentPattern)
	if len(r.profile.FragmentPattern) > 0 {
		r.actual.FragmentUnits += uint64(len(fragments))
		if len(fragments) > 1 {
			r.fragmentedWrites++
		}
	}
	var output []ByteDelivery
	for fragmentIndex, part := range fragments {
		r.buffer = append(r.buffer, part...)
		r.bufferPieces = append(r.bufferPieces, len(part))
		r.bufferOrdinal = ordinal
		if ready > r.bufferReadyAt {
			r.bufferReadyAt = ready
		}
		if r.profile.CoalesceBytes == 0 {
			delivery, err := r.emitLocked(len(r.buffer))
			if err != nil {
				r.appendPendingFragmentsLocked(fragments[fragmentIndex+1:])
				return nil, err
			}
			output = append(output, delivery)
			continue
		}
		for len(r.buffer) >= r.profile.CoalesceBytes {
			delivery, err := r.emitLocked(r.profile.CoalesceBytes)
			if err != nil {
				r.appendPendingFragmentsLocked(fragments[fragmentIndex+1:])
				return nil, err
			}
			output = append(output, delivery)
		}
	}
	return output, nil
}

func (r *ByteRelay) appendPendingFragmentsLocked(fragments [][]byte) {
	for _, part := range fragments {
		r.buffer = append(r.buffer, part...)
		r.bufferPieces = append(r.bufferPieces, len(part))
	}
}

func cloneByteProfile(profile ByteProfile) ByteProfile {
	expected := *profile.Expected
	profile.Expected = &expected
	profile.JitterScript = append([]time.Duration(nil), profile.JitterScript...)
	profile.Outages = append([]TimedOutage(nil), profile.Outages...)
	profile.FragmentPattern = append([]int(nil), profile.FragmentPattern...)
	profile.LossOrdinals = append([]uint64(nil), profile.LossOrdinals...)
	profile.ReorderOrdinals = append([]uint64(nil), profile.ReorderOrdinals...)
	profile.DuplicateOrdinals = append([]uint64(nil), profile.DuplicateOrdinals...)
	return profile
}

func fragment(payload []byte, pattern []int) [][]byte {
	if len(pattern) == 0 {
		return [][]byte{append([]byte(nil), payload...)}
	}
	var output [][]byte
	for offset, index := 0, 0; offset < len(payload); index++ {
		size := pattern[index%len(pattern)]
		if remaining := len(payload) - offset; size > remaining {
			size = remaining
		}
		output = append(output, append([]byte(nil), payload[offset:offset+size]...))
		offset += size
	}
	return output
}

func (r *ByteRelay) emitLocked(size int) (ByteDelivery, error) {
	payload := append([]byte(nil), r.buffer[:size]...)
	nextRate := r.rate
	ready, limited, err := nextRate.schedule(r.bufferReadyAt, len(payload))
	if err != nil {
		return ByteDelivery{}, err
	}
	r.rate = nextRate
	r.buffer = append(r.buffer[:0], r.buffer[size:]...)
	pieceCount := r.consumePiecesLocked(size)
	if limited {
		r.actual.RateLimitedUnits++
	}
	if pieceCount > 1 {
		r.actual.CoalescedUnits++
	}
	if len(r.buffer) == 0 {
		r.bufferReadyAt = 0
	}
	r.outstanding += uint64(len(payload))
	r.outstandingSizes = append(r.outstandingSizes, uint64(len(payload)))
	return ByteDelivery{
		Ordinal: r.bufferOrdinal, ReadyAt: ready, Payload: payload,
	}, nil
}

func (r *ByteRelay) consumePiecesLocked(size int) int {
	pieces := 0
	remaining := size
	for remaining > 0 {
		pieces++
		piece := r.bufferPieces[0]
		if piece <= remaining {
			remaining -= piece
			r.bufferPieces = r.bufferPieces[1:]
			continue
		}
		r.bufferPieces[0] = piece - remaining
		remaining = 0
	}
	return pieces
}

// Acknowledge releases modeled downstream capacity after bytes are consumed.
func (r *ByteRelay) Acknowledge(bytes uint64) error {
	return r.acknowledgeWrite(bytes, true)
}

func (r *ByteRelay) acknowledgeWrite(bytes uint64, complete bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.outstandingSizes) == 0 {
		return ErrInvalidAcknowledge
	}
	deliveryBytes := r.outstandingSizes[0]
	if bytes > deliveryBytes || deliveryBytes > r.outstanding || complete && bytes != deliveryBytes {
		return ErrInvalidAcknowledge
	}
	r.outstanding -= deliveryBytes
	r.outstandingSizes = r.outstandingSizes[1:]
	r.actual.OutputBytes += bytes
	if complete {
		r.actual.OutputUnits++
	} else {
		r.actual.CanceledUnits++
		r.actual.CanceledBytes += deliveryBytes - bytes
	}
	return nil
}

// readCapacity bounds a real Conn read before bytes leave the kernel stream.
// A zero result means delivery acknowledgements must release capacity first.
func (r *ByteRelay) readCapacity(max int) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.profile.BackpressureBytes == 0 {
		return max
	}
	used := r.outstanding + uint64(len(r.buffer))
	limit := uint64(r.profile.BackpressureBytes)
	if used >= limit {
		return 0
	}
	available := int(limit - used)
	if available < max {
		return available
	}
	return max
}

func (r *ByteRelay) recordBackpressure() {
	r.mu.Lock()
	r.actual.BackpressureUnits++
	r.mu.Unlock()
}

// CloseWrite faithfully forwards a byte-stream half-close after buffered bytes.
func (r *ByteRelay) CloseWrite(at time.Duration) ([]ByteDelivery, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.writeClosed {
		return nil, io.ErrClosedPipe
	}
	if at < 0 {
		return nil, fmt.Errorf("%w: negative half-close time", ErrInvalidProfile)
	}
	r.writeClosed = true
	r.actual.HalfCloses++
	if len(r.buffer) == 0 {
		ready, limited, err := r.rate.schedule(at, 0)
		if err != nil {
			return nil, err
		}
		if limited {
			r.actual.RateLimitedUnits++
		}
		r.outstandingSizes = append(r.outstandingSizes, 0)
		return []ByteDelivery{{Ordinal: r.ordinal, ReadyAt: ready, HalfClose: true}}, nil
	}
	if at > r.bufferReadyAt {
		r.bufferReadyAt = at
	}
	delivery, err := r.emitLocked(len(r.buffer))
	if err != nil {
		return nil, err
	}
	delivery.HalfClose = true
	return []ByteDelivery{delivery}, nil
}

// Flush emits remaining coalesced bytes without inventing a half-close.
func (r *ByteRelay) Flush() []ByteDelivery {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.buffer) == 0 {
		return nil
	}
	delivery, err := r.emitLocked(len(r.buffer))
	if err != nil {
		panic(fmt.Sprintf("validated byte profile failed during flush: %v", err))
	}
	return []ByteDelivery{delivery}
}

func (r *ByteRelay) Report() Report {
	r.mu.Lock()
	defer r.mu.Unlock()
	return Report{
		Phase: r.profile.Phase, Direction: r.profile.Direction, Seed: r.profile.Seed,
		Expected: *r.profile.Expected, Actual: r.actual,
	}
}

func (r *ByteRelay) discardPending() {
	r.mu.Lock()
	r.actual.CanceledUnits += uint64(len(r.outstandingSizes))
	if len(r.buffer) > 0 {
		r.actual.CanceledUnits++
	}
	r.actual.CanceledBytes += r.outstanding + uint64(len(r.buffer))
	r.buffer = nil
	r.bufferPieces = nil
	r.bufferReadyAt = 0
	r.outstanding = 0
	r.outstandingSizes = nil
	r.mu.Unlock()
}

func (r *ByteRelay) verifyDrained() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.verifyDrainedLocked()
}

func (r *ByteRelay) verifyDrainedLocked() error {
	if len(r.buffer) != 0 || len(r.bufferPieces) != 0 || r.outstanding != 0 || len(r.outstandingSizes) != 0 {
		return fmt.Errorf("%w: buffer=%d pieces=%d outstanding=%d deliveries=%d", ErrRelayNotDrained,
			len(r.buffer), len(r.bufferPieces), r.outstanding, len(r.outstandingSizes))
	}
	return nil
}

func (r *ByteRelay) Verify() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.verifyDrainedLocked(); err != nil {
		return err
	}
	if r.actual != *r.profile.Expected {
		return fmt.Errorf("%w: expected %+v, actual %+v", ErrCounterMismatch, *r.profile.Expected, r.actual)
	}
	if err := r.actual.CheckByteConservation(); err != nil {
		return err
	}
	wantOutages := uint64(0)
	for _, outage := range r.profile.Outages {
		wantOutages += outage.Ordinals.count()
	}
	if r.actual.OutageUnits != wantOutages {
		return fmt.Errorf("%w: outage hits=%d, want=%d", ErrFaultNotExercised, r.actual.OutageUnits, wantOutages)
	}
	checks := []struct {
		configured bool
		name       string
		got        uint64
	}{
		{r.profile.Delay > 0, "delay", r.actual.DelayUnits},
		{anyNonzero(r.profile.JitterScript), "jitter", r.actual.JitterUnits},
		{r.profile.Rate.enabled(), "rate limit", r.actual.RateLimitedUnits},
		{len(r.profile.FragmentPattern) > 0, "fragmentation", r.fragmentedWrites},
		{r.profile.CoalesceBytes > 0, "coalescing", r.actual.CoalescedUnits},
		{r.profile.BackpressureBytes > 0, "backpressure", r.actual.BackpressureUnits},
		{r.profile.RequireHalfClose, "half-close", r.actual.HalfCloses},
	}
	for _, check := range checks {
		if check.configured && check.got == 0 {
			return fmt.Errorf("%w: %s", ErrFaultNotExercised, check.name)
		}
	}
	return nil
}
