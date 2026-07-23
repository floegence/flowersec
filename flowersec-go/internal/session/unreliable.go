package session

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/protocolv2"
)

const unreliableSendBudget = 64

type unreliableChannel struct {
	session   *engineSession
	transport carrier.UnreliableTransport
	sendSlots chan struct{}
	recvSlot  chan struct{}

	sendMu        sync.Mutex
	nextSequence  uint64
	sendExhausted bool
	replayMu      sync.Mutex
	replay        map[uint32]*unreliableReplayWindow
}

type unreliableReplayWindow struct {
	initialized bool
	highest     uint64
	bits        uint64
}

func newUnreliableChannel(session *engineSession, transport carrier.UnreliableTransport) *unreliableChannel {
	return &unreliableChannel{
		session: session, transport: transport,
		sendSlots: make(chan struct{}, unreliableSendBudget), recvSlot: make(chan struct{}, 1),
		nextSequence: 1, replay: make(map[uint32]*unreliableReplayWindow),
	}
}

func (*unreliableChannel) MaxMessageBytes() int { return protocolv2.MaxUnreliableMessageBytes }

func (channel *unreliableChannel) Send(ctx context.Context, payload []byte, options UnreliableSendOptions) (UnreliableSendStatus, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if len(payload) == 0 || len(payload) > protocolv2.MaxUnreliableMessageBytes {
		return "", ErrUnreliableMessageTooLarge
	}
	expiresAtMS, status, err := validateUnreliableExpiry(options.ExpiresAt)
	if err != nil || status != "" {
		return status, err
	}
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case <-channel.session.ctx.Done():
		return "", channel.session.sessionError()
	case channel.sendSlots <- struct{}{}:
	default:
		return UnreliableDroppedBudget, nil
	}
	defer func() { <-channel.sendSlots }()
	if time.Now().UnixMilli() >= int64(expiresAtMS) {
		return UnreliableDroppedExpired, nil
	}

	epoch, roots, err := channel.session.unreliableSendRoots()
	if err != nil {
		return "", err
	}
	sequence, err := channel.takeSequence()
	if err != nil {
		return "", err
	}
	header := protocolv2.UnreliableHeader{
		Epoch: epoch, Sequence: sequence, ExpiresAtUnixMS: expiresAtMS,
		CiphertextLength: uint32(len(payload) + protocolv2.AEADTagBytes),
	}
	material, err := protocolv2.DeriveUnreliableMaterial(roots.EpochSecret, channel.session.h3, channel.session.sendDir, epoch)
	if err != nil {
		return "", err
	}
	ciphertext, err := protocolv2.SealUnreliable(channel.session.config.Suite, material, channel.session.h3, channel.session.sendDir, header, payload)
	if err != nil {
		return "", err
	}
	rawHeader, err := header.MarshalBinary()
	if err != nil {
		return "", err
	}
	wire := make([]byte, 0, len(rawHeader)+len(ciphertext))
	wire = append(wire, rawHeader...)
	wire = append(wire, ciphertext...)
	if err := channel.transport.SendUnreliable(wire); err != nil {
		if errors.Is(err, carrier.ErrUnreliableTooLarge) {
			return "", ErrUnreliableMessageTooLarge
		}
		return UnreliableDroppedCarrier, fmt.Errorf("%w: %v", ErrUnreliableDropped, err)
	}
	channel.session.touchActivity()
	return UnreliableAccepted, nil
}

func (channel *unreliableChannel) Receive(ctx context.Context) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-channel.session.ctx.Done():
		return nil, channel.session.sessionError()
	case channel.recvSlot <- struct{}{}:
	}
	defer func() { <-channel.recvSlot }()
	for {
		wire, err := channel.transport.ReceiveUnreliable(ctx)
		if err != nil {
			channel.session.openMu.Lock()
			closing := channel.session.closing
			channel.session.openMu.Unlock()
			if closing {
				return nil, ErrSessionClosed
			}
			select {
			case <-channel.session.ctx.Done():
				return nil, channel.session.sessionError()
			default:
			}
			return nil, err
		}
		plaintext, accepted := channel.open(wire, time.Now())
		if !accepted {
			continue
		}
		channel.session.touchActivity()
		return plaintext, nil
	}
}

func (channel *unreliableChannel) open(wire []byte, now time.Time) ([]byte, bool) {
	if len(wire) < protocolv2.UnreliableHeaderSize || len(wire) > protocolv2.MaxUnreliableWireBytes {
		return nil, false
	}
	header, err := protocolv2.ParseUnreliableHeader(wire[:protocolv2.UnreliableHeaderSize])
	if err != nil || len(wire) != protocolv2.UnreliableHeaderSize+int(header.CiphertextLength) ||
		header.ExpiresAtUnixMS <= uint64(now.UnixMilli()) {
		return nil, false
	}
	roots, ok := channel.session.unreliableReceiveRoots(header.Epoch)
	if !ok {
		return nil, false
	}
	material, err := protocolv2.DeriveUnreliableMaterial(roots.EpochSecret, channel.session.h3, channel.session.recvDir, header.Epoch)
	if err != nil {
		return nil, false
	}
	plaintext, err := protocolv2.OpenUnreliable(channel.session.config.Suite, material, channel.session.h3, channel.session.recvDir, header, wire[protocolv2.UnreliableHeaderSize:])
	if err != nil || !channel.acceptSequence(header.Epoch, header.Sequence) {
		return nil, false
	}
	return plaintext, true
}

func validateUnreliableExpiry(expiresAt time.Time) (uint64, UnreliableSendStatus, error) {
	if expiresAt.IsZero() || expiresAt.UnixMilli() < 0 {
		return 0, "", ErrUnreliableInvalidExpiry
	}
	milliseconds := expiresAt.UnixMilli()
	if milliseconds <= time.Now().UnixMilli() {
		return uint64(milliseconds), UnreliableDroppedExpired, nil
	}
	return uint64(milliseconds), "", nil
}

func (channel *unreliableChannel) takeSequence() (uint64, error) {
	channel.sendMu.Lock()
	defer channel.sendMu.Unlock()
	if channel.sendExhausted {
		return 0, protocolv2.ErrCounterExhausted
	}
	sequence := channel.nextSequence
	if sequence == math.MaxUint64 {
		channel.sendExhausted = true
	} else {
		channel.nextSequence++
	}
	return sequence, nil
}

func (channel *unreliableChannel) acceptSequence(epoch uint32, sequence uint64) bool {
	channel.replayMu.Lock()
	defer channel.replayMu.Unlock()
	window := channel.replay[epoch]
	if window == nil {
		window = &unreliableReplayWindow{}
		channel.replay[epoch] = window
		for candidate := range channel.replay {
			if candidate < epoch && epoch-candidate > 1 {
				delete(channel.replay, candidate)
			}
		}
	}
	if !window.initialized {
		window.initialized, window.highest, window.bits = true, sequence, 1
		return true
	}
	if sequence > window.highest {
		shift := sequence - window.highest
		if shift >= 64 {
			window.bits = 1
		} else {
			window.bits = window.bits<<shift | 1
		}
		window.highest = sequence
		return true
	}
	delta := window.highest - sequence
	if delta >= 64 || window.bits&(uint64(1)<<delta) != 0 {
		return false
	}
	window.bits |= uint64(1) << delta
	return true
}

func (s *engineSession) unreliableSendRoots() (uint32, protocolv2.EpochRoots, error) {
	s.cryptoMu.RLock()
	defer s.cryptoMu.RUnlock()
	roots, ok := s.sendRoots[s.sendEpoch]
	if !ok {
		return 0, protocolv2.EpochRoots{}, ErrSessionProtocol
	}
	return s.sendEpoch, roots, nil
}

func (s *engineSession) unreliableReceiveRoots(epoch uint32) (protocolv2.EpochRoots, bool) {
	s.cryptoMu.RLock()
	defer s.cryptoMu.RUnlock()
	if epoch > s.recvSessionEpoch {
		return protocolv2.EpochRoots{}, false
	}
	roots, ok := s.recvRoots[epoch]
	return roots, ok
}
