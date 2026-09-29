package sessionv4

import (
	"math"
	"sync"
	"time"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// relayByteBudget is the same original hop meter before and after claim. Both
// directions share one signed total. An outstanding read reserves capacity,
// but only actual bytes burn it. Unknown write completion burns the complete
// intended range; a later callback cannot refund or account that range twice.
// Fixed receipt positions are admitted before I/O, with no waiter queue.
type relayByteBudget struct {
	mu                              sync.Mutex
	reservation                     resourcev4.Reference
	clock                           *timev4.Clock
	origin                          timev4.Mark
	rate, tokens, burst, creditedMS uint64
	limit, used, reserved, next     uint64
	slots                           []relayByteSlot
	wake, done                      chan struct{}
	users                           uint32
	closed, cleaned                 bool
}

type relayByteSlot struct {
	generation, bytes uint64
	active            bool
}
type relayByteReservation struct {
	owner      *relayByteBudget
	index      int
	generation uint64
}

func relayByteBudgetCharge(slots uint32) (resourcev4.Vector, error) {
	if slots == 0 || slots > 65536 {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	return resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(relayByteBudget{})) + uint64(slots)*(uint64(unsafe.Sizeof(relayByteSlot{}))+uint64(unsafe.Sizeof(time.Timer{}))+128) + 256, resourcev4.Items: uint64(slots) + 1, resourcev4.Timers: uint64(slots)}, nil
}

func newRelayByteBudget(limit, rate, envelope uint64, clock *timev4.Clock, slots uint32, reservation resourcev4.Reference) (*relayByteBudget, error) {
	if limit == 0 || rate == 0 || envelope < 8 || envelope > 1048584 || clock == nil {
		return nil, cryptov4.ErrConfiguration
	}
	charge, err := relayByteBudgetCharge(slots)
	if err != nil {
		return nil, err
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		return nil, err
	}
	origin, err := clock.Monotonic()
	if err != nil {
		owned.Release()
		return nil, err
	}
	return &relayByteBudget{limit: limit, rate: rate, burst: 2 * envelope * 1000, tokens: 2 * envelope * 1000, clock: clock, origin: origin, reservation: owned, slots: make([]relayByteSlot, slots), wake: make(chan struct{}), done: make(chan struct{})}, nil
}

// Waiting occupies the original read/write call, never an extra worker or
// queue. The carrier's original watchdog seals this same meter on cancellation
// or deadline. In-flight reservations are not mistaken for consumed quota.
func (b *relayByteBudget) reserveWait(bytes uint64) (relayByteReservation, error) {
	if b == nil {
		return relayByteReservation{}, cryptov4.ErrConfiguration
	}
	b.mu.Lock()
	if b.closed || uint64(b.users) >= uint64(len(b.slots)) {
		b.mu.Unlock()
		return relayByteReservation{}, cryptov4.ErrCapacity
	}
	b.users++
	b.mu.Unlock()
	defer func() { b.mu.Lock(); b.users--; b.cleanupLocked(); b.mu.Unlock() }()
	var timer *time.Timer
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	for {
		if err := b.refill(); err != nil {
			return relayByteReservation{}, err
		}
		b.mu.Lock()
		wake := b.wake
		b.mu.Unlock()
		receipt, err := b.reserve(bytes)
		if err == nil {
			return receipt, nil
		}
		b.mu.Lock()
		pending := !b.closed && bytes <= b.limit-b.used && bytes <= b.burst/1000 && (b.reserved != 0 || bytes*1000 > b.tokens)
		rateWait := !b.closed && bytes <= b.burst/1000 && bytes*1000 > b.tokens
		changed := wake != b.wake
		b.mu.Unlock()
		if changed {
			continue
		}
		if !pending {
			return relayByteReservation{}, err
		}
		var tick <-chan time.Time
		if rateWait {
			if timer == nil {
				timer = time.NewTimer(50 * time.Millisecond)
			} else {
				timer.Reset(50 * time.Millisecond)
			}
			tick = timer.C
		}
		select {
		case <-wake:
		case <-b.done:
		case <-tick:
		}
		if timer != nil {
			timer.Stop()
		}
	}
}

func (b *relayByteBudget) reserve(bytes uint64) (relayByteReservation, error) {
	if b == nil || bytes == 0 {
		return relayByteReservation{}, cryptov4.ErrConfiguration
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed || b.next == math.MaxUint64 {
		return relayByteReservation{}, cryptov4.ErrClosed
	}
	if err := b.reservation.Check(); err != nil {
		return relayByteReservation{}, err
	}
	if bytes > b.limit-b.used-b.reserved || bytes > b.burst/1000 || bytes*1000 > b.tokens {
		return relayByteReservation{}, cryptov4.ErrCapacity
	}
	for i := range b.slots {
		if b.slots[i].active {
			continue
		}
		b.next++
		b.slots[i] = relayByteSlot{generation: b.next, bytes: bytes, active: true}
		b.reserved += bytes
		b.tokens -= bytes * 1000
		return relayByteReservation{owner: b, index: i, generation: b.next}, nil
	}
	return relayByteReservation{}, cryptov4.ErrCapacity
}

// settle belongs to the real I/O completion, including after logical Close.
// A canceled read with zero bytes settles zero. Writes with an unknowable
// submitted prefix pass uncertain=true and can never retry the charged range.
func (r relayByteReservation) settle(actual uint64, uncertain bool) error {
	b := r.owner
	if b == nil {
		return resourcev4.ErrOwner
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.cleaned || r.index < 0 || r.index >= len(b.slots) {
		return resourcev4.ErrOwner
	}
	slot := &b.slots[r.index]
	if !slot.active || slot.generation != r.generation || actual > slot.bytes {
		return resourcev4.ErrOwner
	}
	if uncertain {
		actual = slot.bytes
	}
	b.reserved -= slot.bytes
	b.used += actual
	b.tokens = min(b.burst, b.tokens+(slot.bytes-actual)*1000)
	*slot = relayByteSlot{}
	// Wake every original finite waiter: a large reservation must not consume
	// the sole notification while smaller eligible I/O remains asleep. Each
	// previous channel is retained only by its already charged waiter positions.
	close(b.wake)
	b.wake = make(chan struct{})
	b.cleanupLocked()
	return nil
}

// claim checks the existing meter and worst-case remaining handshake bound;
// it neither resets the counter nor grants a new budget for forwarding.
func (b *relayByteBudget) claim(required uint64) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return cryptov4.ErrClosed
	}
	if err := b.reservation.Check(); err != nil {
		return err
	}
	if required > b.limit-b.used-b.reserved {
		return cryptov4.ErrCapacity
	}
	return nil
}

func (b *relayByteBudget) close() {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.closed {
		b.closed = true
		close(b.done)
	}
	b.cleanupLocked()
}

func (b *relayByteBudget) cleanupLocked() {
	if !b.closed || b.reserved != 0 || b.users != 0 || b.cleaned {
		return
	}
	clear(b.slots)
	b.slots = nil
	b.reservation.Release()
	b.cleaned = true
}

// Refill uses elapsed_lower from the original monotonic era. Wall-clock jumps
// cannot mint rate capacity; arithmetic saturates before any multiplication.
func (b *relayByteBudget) refill() error {
	now, err := b.clock.Monotonic()
	if err != nil {
		return err
	}
	if !now.SameEra(b.origin) || now.Milliseconds < b.origin.Milliseconds {
		return timev4.ErrContinuity
	}
	elapsed, _, err := b.clock.Profile().Rate.Elapsed(now.Milliseconds - b.origin.Milliseconds)
	if err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return cryptov4.ErrClosed
	}
	if elapsed < b.creditedMS {
		return nil
	}
	delta := elapsed - b.creditedMS
	missing := b.burst - b.tokens
	threshold := missing / b.rate
	if missing%b.rate != 0 {
		threshold++
	}
	if delta >= threshold {
		b.tokens = b.burst
	} else {
		b.tokens += delta * b.rate
	}
	b.creditedMS = elapsed
	return nil
}
