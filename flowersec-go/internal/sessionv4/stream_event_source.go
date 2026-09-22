package sessionv4

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

var ErrSourceOverflow = errors.New("sessionv4: source_overflow")
var ErrSourceSetup = errors.New("sessionv4: event source setup failed")

// The trusted registration fixes real input costs, independently of the wire
// item bound. A declared largest input must fit even in an otherwise empty
// queue. Profiles may choose a larger finite queue for a legal 1 MiB event.
type streamEventSourceConfig struct {
	Identity                        [16]byte
	Encoding, Task                  resourcev4.Vector
	Root                            *resourcev4.Root
	Owner                           resourcev4.OwnerKey
	Accounts                        []resourcev4.Account
	Pending                         uint8
	InputBytes                      uint64
	MaxInputBytes                   uint32
	MaxInputCharge                  resourcev4.Vector
	InputRuntimeBytes, RuntimeBytes uint64
}

// EventPublisher grants only publication and source completion. It exposes no
// Session, service client, executor, stream I/O or implicit acquisition path.
// The SDK's source adapter holds this capability for one original operation.
type EventPublisher struct{ source *streamEventSource }

type streamEventSource struct {
	cleanupOwner              *streamSourceCleanup
	serial                    uint64
	accounts                  [resourcev4.MaxAccountsPerCharge]resourcev4.Account
	accountCount              int
	mu                        sync.Mutex
	config                    streamEventSourceConfig
	stream                    atomic.Pointer[StreamMessages]
	reservation               resourcev4.Reference
	publisher                 EventPublisher
	changed                   chan struct{}
	queue                     [8]*OwnedEventInput
	current                   *OwnedEventInput
	head, tail, queued, held  uint8
	bytes                     uint64
	setupDone, sealed, closed bool
	failure                   error
}

func streamEventSourceCharge(c streamEventSourceConfig) (resourcev4.Vector, error) {
	if c.Identity == ([16]byte{}) || c.Encoding == (resourcev4.Vector{}) || c.Task == (resourcev4.Vector{}) || c.Root == nil || len(c.Accounts) > resourcev4.MaxAccountsPerCharge || c.Pending == 0 || c.Pending > 8 || c.RuntimeBytes == 0 || c.InputBytes == 0 {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	maximum, err := EventInputCharge(c.MaxInputBytes, c.InputRuntimeBytes)
	if err != nil || !c.MaxInputCharge.Contains(maximum) || c.InputBytes < c.MaxInputCharge[resourcev4.SDKBytes] {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	return (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(streamEventSource{})), resourcev4.Items: uint64(c.Pending) + 2}).Add(resourcev4.Vector{resourcev4.SDKBytes: c.RuntimeBytes})
}

// Prepared before subscription setup. Empty sources own only their fixed
// metadata, not every possible event's maximum payload allocation.
func prepareStreamEventSource(m *StreamMessages, c streamEventSourceConfig, reservation resourcev4.Reference) (*streamEventSource, error) {
	charge, err := streamEventSourceCharge(c)
	if err != nil {
		return nil, err
	}
	if m == nil || !m.server {
		return nil, cryptov4.ErrConfiguration
	}
	if err := reservation.CheckAllocationScope(c.Root, c.Owner, c.Accounts); err != nil {
		return nil, err
	}
	if err := reservation.CheckSameEnvironment(m.reservation); err != nil {
		return nil, err
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		return nil, err
	}
	s := &streamEventSource{config: c, reservation: owned, changed: make(chan struct{}, 1), accountCount: len(c.Accounts)}
	s.stream.Store(m)
	copy(s.accounts[:], c.Accounts)
	s.config.Accounts = nil
	s.publisher.source = s
	return s, nil
}

// TryPublish never waits for queue space or application execution. It moves
// the complete input only when all gates win. Overflow seals future admission
// and records one terminal cause; the rejected input remains producer-owned.
func (p EventPublisher) TryPublish(input *OwnedEventInput) error {
	s := p.source
	if s == nil || input == nil {
		return cryptov4.ErrConfiguration
	}
	m := s.stream.Load()
	if m == nil {
		return cryptov4.ErrClosed
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.checkLocked(context.Background()); err != nil {
		return cryptov4.ErrClosed
	}
	return m.withCurrentAuthorization(func() error {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.sealed || s.closed {
			return cryptov4.ErrClosed
		}
		input.mu.Lock()
		defer input.mu.Unlock()
		if input.closed || input.transferred || input.source != nil {
			return cryptov4.ErrClosed
		}
		if uint64(len(input.bytes)) > uint64(s.config.MaxInputBytes) || !s.config.MaxInputCharge.Contains(input.charge) {
			return cryptov4.ErrConfiguration
		}
		expected, err := EventInputCharge(uint32(len(input.bytes)), s.config.InputRuntimeBytes)
		if err != nil || input.charge != expected {
			return cryptov4.ErrConfiguration
		}
		if err := input.reservation.CheckAllocationScope(s.config.Root, s.config.Owner, s.accounts[:s.accountCount]); err != nil {
			return err
		}
		amount := input.charge[resourcev4.SDKBytes]
		if s.held == s.config.Pending || amount > s.config.InputBytes-s.bytes {
			s.sealed, s.failure = true, ErrSourceOverflow
			if s.cleanupOwner != nil {
				s.cleanupOwner.request()
			}
			s.discardQueuedLocked()
			s.signalLocked()
			return ErrSourceOverflow
		}
		if err := s.reserveProcessingLocked(input); err != nil {
			s.sealed, s.failure = true, ErrSourceOverflow
			if s.cleanupOwner != nil {
				s.cleanupOwner.request()
			}
			s.discardQueuedLocked()
			s.signalLocked()
			return ErrSourceOverflow
		}
		input.source, input.transferred = s, true
		s.queue[s.tail] = input
		s.tail = (s.tail + 1) % s.config.Pending
		s.queued++
		s.held++
		s.bytes += amount
		s.signalLocked()
		return nil
	})
}

// Complete seals source publication, while already accepted inputs drain in
// order after setup's real return. It cannot publish an early normal terminal.
func (p EventPublisher) Complete() error {
	s := p.source
	if s == nil {
		return cryptov4.ErrConfiguration
	}
	m := s.stream.Load()
	if m == nil {
		return cryptov4.ErrClosed
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.checkLocked(context.Background()); err != nil {
		return cryptov4.ErrClosed
	}
	return m.withCurrentAuthorization(func() error {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.closed || s.sealed {
			return cryptov4.ErrClosed
		}
		s.sealed = true
		if s.cleanupOwner != nil {
			s.cleanupOwner.request()
		}
		s.signalLocked()
		return nil
	})
}

func (s *streamEventSource) signalLocked() {
	// Wake the already admitted lifetime supervisor as well as the pump.
	// Cleanup deadlines must advance during blocked output or application code.
	if m := s.stream.Load(); m != nil {
		select {
		case m.changed <- struct{}{}:
		default:
		}
	}
	select {
	case s.changed <- struct{}{}:
	default:
	}
}

// Only the original pump calls setupExited, after setup and all its real
// defers have returned. No mapper can run concurrently with pending setup.
func (s *streamEventSource) setupExited(failure error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.setupDone {
		return
	}
	s.setupDone = true
	if failure != nil && s.failure == nil {
		s.failure = ErrSourceSetup
	}
	if failure != nil || s.closed {
		s.sealed = true
		s.discardQueuedLocked()
	}
	s.signalLocked()
}

// next lends one exact input to SDK dispatch. The item/byte charge remains in
// held until the actual mapper/encoder exits, including cancellation tails.
func (s *streamEventSource) next() (*OwnedEventInput, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.setupDone || s.current != nil {
		return nil, false, nil
	}
	if s.closed {
		return nil, true, cryptov4.ErrClosed
	}
	if s.failure != nil {
		return nil, true, s.failure
	}
	if s.queued == 0 {
		return nil, s.sealed, nil
	}
	input := s.queue[s.head]
	s.queue[s.head] = nil
	s.head = (s.head + 1) % s.config.Pending
	s.queued--
	s.current = input
	return input, false, nil
}

func (s *streamEventSource) finishCurrent(input *OwnedEventInput) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if input == nil || s.current != input {
		return
	}
	s.current = nil
	s.releaseInputLocked(input)
	s.signalLocked()
}

func (s *streamEventSource) releaseInputLocked(input *OwnedEventInput) {
	input.mu.Lock()
	defer input.mu.Unlock()
	s.held--
	s.bytes -= input.charge[resourcev4.SDKBytes]
	input.releaseLocked()
}

func (s *streamEventSource) discardQueuedLocked() {
	for s.queued != 0 {
		input := s.queue[s.head]
		s.queue[s.head] = nil
		s.head = (s.head + 1) % s.config.Pending
		s.queued--
		s.releaseInputLocked(input)
	}
}

func (s *streamEventSource) close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed, s.sealed = true, true
	if s.cleanupOwner != nil {
		s.cleanupOwner.request()
	}
	s.discardQueuedLocked()
	s.signalLocked()
}

// Cleanup cannot refund an input still lent to application code. The enclosing
// original operation also joins subscription detach and every callback tail.
func (s *streamEventSource) cleanup() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed || !s.setupDone || s.held != 0 {
		return false
	}
	s.stream.Store(nil)
	s.config = streamEventSourceConfig{}
	clear(s.accounts[:])
	s.accountCount = 0
	s.reservation.Release()
	s.reservation = resourcev4.Reference{}
	return true
}

// A mapper/setup failure and normal source completion compete at the original
// source gate. Current work keeps its input until its real exit; later queued
// inputs are retired without application entry or a retry.
func (s *streamEventSource) fail(cause error) {
	if cause == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.failure != nil {
		return
	}
	s.sealed, s.failure = true, cause
	if s.cleanupOwner != nil {
		s.cleanupOwner.request()
	}
	s.discardQueuedLocked()
	s.signalLocked()
}

// Complete per-event codec/task and alias responsibility precedes the single
// publication transfer. No ready/running position is acquired for queued data.
func (s *streamEventSource) reserveProcessingLocked(input *OwnedEventInput) error {
	if s.serial == math.MaxUint64 {
		return cryptov4.ErrCapacity
	}
	s.serial++
	var requests [2]resourcev4.Request
	for index, charge := range [2]resourcev4.Vector{s.config.Encoding, s.config.Task} {
		var seed [41]byte
		copy(seed[:16], "stream-event/v4/")
		copy(seed[16:32], s.config.Identity[:])
		binary.BigEndian.PutUint64(seed[32:40], s.serial)
		seed[40] = byte(index)
		digest := sha256.Sum256(seed[:])
		owner := s.config.Owner
		copy(owner.Instance[:], digest[:16])
		copy(owner.Backing[:], digest[16:])
		requests[index] = resourcev4.Request{Owner: owner, Charge: charge, Accounts: s.accounts[:s.accountCount]}
	}
	if err := s.config.Root.ReserveBatch(requests[:], input.processing[:]); err != nil {
		return err
	}
	borrow, err := input.processing[0].Borrow()
	if err != nil {
		for _, ref := range input.processing {
			ref.Release()
		}
		input.processing = [2]resourcev4.Reference{}
		return err
	}
	input.processingBorrow = borrow
	return nil
}

// The original output acceptance gate orders the first actual item byte with
// source termination. An already accepted item retains its exact remaining
// byte responsibility; source failure cannot replace or replay that prefix.
func (s *streamEventSource) acceptItem(started *atomic.Bool, transfer func() error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !started.Load() {
		if s.closed {
			return cryptov4.ErrClosed
		}
		if s.failure != nil {
			return s.failure
		}
	}
	if err := transfer(); err != nil {
		return err
	}
	started.Store(true)
	return nil
}
