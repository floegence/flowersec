package session

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/protocolv2"
)

var errPeerSessionClose = errors.New("peer closed Flowersec v2 session")

func (s *engineSession) sendControl(typ protocolv2.InnerType, payload []byte) error {
	return s.commitControl(typ, payload, nil)
}

func (s *engineSession) initControlActor() {
	s.controlWake = make(chan struct{}, 1)
	s.controlIdle = make(chan struct{})
	close(s.controlIdle)
	s.controlCriticalCap = 2*int(s.config.MaxInboundStreams) + 8
	if s.controlCriticalCap < 8 {
		s.controlCriticalCap = 8
	}
	s.controlNormalCap = 8
}

func (s *engineSession) startControlWriter() {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.controlWriterLoop()
	}()
}

func (s *engineSession) commitControl(typ protocolv2.InnerType, payload []byte, publish func() error) error {
	inner, err := protocolv2.MarshalInnerRecord(typ, payload)
	if err != nil {
		return err
	}
	critical := typ != protocolv2.InnerPing && typ != protocolv2.InnerPong

	s.controlActorMu.Lock()
	defer s.controlActorMu.Unlock()
	if critical {
		if s.controlCriticalCount >= s.controlCriticalCap {
			return protocolv2.ErrControlQueueFull
		}
	} else if s.controlNormalCount >= s.controlNormalCap {
		return protocolv2.ErrControlQueueFull
	}

	s.cryptoMu.RLock()
	epoch := s.controlSendEpoch
	sequence := s.controlSendSeq
	exhausted := s.controlSendExhausted
	roots, ok := s.sendRoots[epoch]
	s.cryptoMu.RUnlock()
	if exhausted {
		return protocolv2.ErrCounterExhausted
	}
	if !ok {
		return ErrSessionProtocol
	}
	material, err := protocolv2.DeriveControlMaterial(roots.ControlRoot, s.h3, s.sendDir, epoch)
	if err != nil {
		return err
	}
	header := protocolv2.RecordHeader{
		Epoch: epoch, Sequence: sequence,
		CiphertextLength: uint32(len(inner) + protocolv2.AEADTagBytes),
	}
	ciphertext, err := protocolv2.SealRecord(s.config.Suite, material.RecordKey, material.NoncePrefix, s.h3, 0, s.sendDir, header, inner)
	if err != nil {
		return err
	}
	rawHeader, err := header.MarshalBinary()
	if err != nil {
		return err
	}
	raw := make([]byte, 0, len(rawHeader)+len(ciphertext))
	raw = append(raw, rawHeader...)
	raw = append(raw, ciphertext...)
	if publish != nil {
		if err := publish(); err != nil {
			return err
		}
	}
	if len(s.controlQueue) == 0 {
		s.controlIdle = make(chan struct{})
	}
	s.controlQueue = append(s.controlQueue, queuedControlRecord{
		typ: typ, epoch: epoch, sequence: sequence, raw: raw, critical: critical,
	})
	if critical {
		s.controlCriticalCount++
	} else {
		s.controlNormalCount++
	}
	if sequence == math.MaxUint64 {
		s.controlSendExhausted = true
	} else {
		s.controlSendSeq++
	}
	select {
	case s.controlWake <- struct{}{}:
	default:
	}
	return nil
}

func (s *engineSession) controlWriterLoop() {
	for {
		select {
		case <-s.controlWake:
		case <-s.ctx.Done():
			return
		}
		for {
			s.controlActorMu.Lock()
			if len(s.controlQueue) == 0 {
				s.controlActorMu.Unlock()
				break
			}
			record := s.controlQueue[0]
			s.controlActorMu.Unlock()

			if err := writeAll(s.control, record.raw); err != nil {
				if s.ctx.Err() == nil {
					s.fail(fmt.Errorf("%w: control write: %v", ErrSessionProtocol, err))
				}
				return
			}
			s.touchActivity()

			s.controlActorMu.Lock()
			s.controlQueue[0] = queuedControlRecord{}
			s.controlQueue = s.controlQueue[1:]
			if record.critical {
				s.controlCriticalCount--
			} else {
				s.controlNormalCount--
			}
			if len(s.controlQueue) == 0 {
				close(s.controlIdle)
			}
			s.controlActorMu.Unlock()
		}
	}
}

func (s *engineSession) flushControl(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	s.controlActorMu.Lock()
	idle := s.controlIdle
	s.controlActorMu.Unlock()
	select {
	case <-idle:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-s.ctx.Done():
		return s.sessionError()
	}
}

func (s *engineSession) readControl() (protocolv2.InnerType, []byte, error) {
	rawHeader := make([]byte, protocolv2.RecordHeaderSize)
	if _, err := io.ReadFull(s.control, rawHeader); err != nil {
		return 0, nil, err
	}
	header, err := protocolv2.ParseRecordHeader(rawHeader)
	if err != nil {
		return 0, nil, err
	}
	ciphertext := make([]byte, int(header.CiphertextLength))
	if _, err := io.ReadFull(s.control, ciphertext); err != nil {
		return 0, nil, err
	}

	s.cryptoMu.Lock()
	cutover := false
	if header.Epoch == s.controlRecvEpoch {
		if s.controlRecvExhausted {
			s.cryptoMu.Unlock()
			return 0, nil, protocolv2.ErrCounterExhausted
		}
		if header.Sequence != s.controlRecvSeq {
			s.cryptoMu.Unlock()
			return 0, nil, protocolv2.ErrControlSequence
		}
	} else if s.controlRecvEpoch != math.MaxUint32 && header.Epoch == s.controlRecvEpoch+1 && header.Epoch <= s.recvSessionEpoch && header.Sequence == 0 {
		cutover = true
	} else {
		s.cryptoMu.Unlock()
		return 0, nil, protocolv2.ErrFutureControlEpoch
	}
	roots, ok := s.recvRoots[header.Epoch]
	if !ok {
		s.cryptoMu.Unlock()
		return 0, nil, protocolv2.ErrFutureControlEpoch
	}
	material, err := protocolv2.DeriveControlMaterial(roots.ControlRoot, s.h3, s.recvDir, header.Epoch)
	if err != nil {
		s.cryptoMu.Unlock()
		return 0, nil, err
	}
	plaintext, err := protocolv2.OpenRecord(s.config.Suite, material.RecordKey, material.NoncePrefix, s.h3, 0, s.recvDir, header, ciphertext)
	if err != nil {
		s.cryptoMu.Unlock()
		return 0, nil, err
	}
	if cutover {
		s.controlRecvEpoch = header.Epoch
		s.controlRecvSeq = 1
		s.controlRecvExhausted = false
	} else {
		if s.controlRecvSeq == math.MaxUint64 {
			s.controlRecvExhausted = true
		} else {
			s.controlRecvSeq++
		}
	}
	s.cryptoMu.Unlock()
	if cutover {
		defer s.cleanupEpochRoots()
	}
	typ, payload, err := protocolv2.ParseInnerRecord(plaintext)
	if err == nil {
		s.touchActivity()
	}
	return typ, payload, err
}

func (s *engineSession) controlLoop() {
	for {
		typ, payload, err := s.readControl()
		if err != nil {
			if s.ctx.Err() == nil {
				s.fail(fmt.Errorf("%w: control read: %v", ErrSessionProtocol, err))
			}
			return
		}
		if err := s.handleControl(typ, payload); err != nil {
			if errors.Is(err, errPeerSessionClose) {
				s.fail(ErrSessionClosed)
			} else {
				s.fail(fmt.Errorf("%w: %v", ErrSessionProtocol, err))
			}
			return
		}
	}
}

func (s *engineSession) handleControl(typ protocolv2.InnerType, payload []byte) error {
	switch typ {
	case protocolv2.InnerPing:
		return s.sendControl(protocolv2.InnerPong, payload)
	case protocolv2.InnerPong:
		nonce := binary.BigEndian.Uint64(payload)
		s.pingsMu.Lock()
		waiter := s.pings[nonce]
		if waiter != nil {
			delete(s.pings, nonce)
			close(waiter)
		}
		s.pingsMu.Unlock()
		return nil
	case protocolv2.InnerStreamReset:
		return s.handleStreamReset(payload)
	case protocolv2.InnerSessionKeyUpdate:
		return s.handleSessionUpdate(payload)
	case protocolv2.InnerSessionKeyUpdateACK:
		return s.handleSessionUpdateACK(payload)
	case protocolv2.InnerGoAway:
		lastAccepted, reason, err := parseIDReason(payload)
		if err != nil || reason == 0 {
			return ErrSessionProtocol
		}
		s.openMu.Lock()
		if !validGoAwayBoundary(s.role, lastAccepted, s.localOpenHighWatermarkLocked()) {
			s.openMu.Unlock()
			return ErrSessionProtocol
		}
		if s.receivedGoAway && s.goAwayLastAccepted != lastAccepted {
			s.openMu.Unlock()
			return ErrSessionProtocol
		}
		s.goingAway = true
		s.receivedGoAway = true
		s.goAwayLastAccepted = lastAccepted
		s.openMu.Unlock()
		return nil
	case protocolv2.InnerSessionClose:
		if len(payload) != 2 || binary.BigEndian.Uint16(payload) == 0 {
			return ErrSessionProtocol
		}
		return errPeerSessionClose
	default:
		return fmt.Errorf("unexpected control type %d", typ)
	}
}

func (s *engineSession) ProbeLiveness(ctx context.Context) (time.Duration, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	s.pingsMu.Lock()
	nonce := s.nextPing
	for {
		if _, exists := s.pings[nonce]; !exists {
			break
		}
		nonce++
	}
	s.nextPing = nonce + 1
	waiter := make(chan struct{})
	s.pings[nonce] = waiter
	s.pingsMu.Unlock()
	var payload [8]byte
	binary.BigEndian.PutUint64(payload[:], nonce)
	started := time.Now()
	if err := s.sendControl(protocolv2.InnerPing, payload[:]); err != nil {
		s.removePing(nonce)
		return 0, fmt.Errorf("%w: %v", ErrLivenessProbe, err)
	}
	select {
	case <-waiter:
		return time.Since(started), nil
	case <-ctx.Done():
		s.removePing(nonce)
		return 0, ctx.Err()
	case <-s.ctx.Done():
		s.removePing(nonce)
		return 0, s.sessionError()
	}
}

func (s *engineSession) removePing(nonce uint64) {
	s.pingsMu.Lock()
	delete(s.pings, nonce)
	s.pingsMu.Unlock()
}

func (s *engineSession) Rekey(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.ctx.Err() != nil {
		return s.sessionError()
	}
	if !s.rekeyMu.TryLock() {
		if err := ctx.Err(); err != nil {
			return err
		}
		return ErrRekeyInProgress
	}
	defer s.rekeyMu.Unlock()
	prepareContext, cancelPrepare := context.WithTimeout(ctx, s.config.RekeyPrepareTimeout)
	defer cancelPrepare()
	if err := s.freezeOpens(); err != nil {
		return err
	}
	opensFrozen := true
	defer func() {
		if opensFrozen {
			s.unfreezeOpens()
		}
	}()
	watermark := s.localOpenHighWatermark()
	if err := s.waitOutboundFrontier(prepareContext, watermark); err != nil {
		return err
	}
	if err := s.freezeResponders(prepareContext, false); err != nil {
		s.unfreezeResponders(false)
		return err
	}
	respondersFrozen := true
	defer func() {
		if respondersFrozen {
			s.unfreezeResponders(false)
		}
	}()

	s.cryptoMu.RLock()
	currentEpoch := s.sendEpoch
	currentRoots := s.sendRoots[currentEpoch]
	s.cryptoMu.RUnlock()
	if currentEpoch == math.MaxUint32 {
		return s.exhaustRekeyCounter()
	}
	nextEpoch := currentEpoch + 1
	nextSecret, err := protocolv2.DeriveNextEpoch(currentRoots.RekeyRoot, s.h3, s.sendDir, nextEpoch)
	if err != nil {
		return err
	}
	nextRoots, err := protocolv2.DeriveEpochRoots(nextSecret)
	if err != nil {
		return err
	}
	s.cryptoMu.Lock()
	s.sendRoots[nextEpoch] = nextRoots
	s.cryptoMu.Unlock()
	s.pendingRekeyMu.Lock()
	transition := s.nextTransition
	if transition == 0 || s.transitionExhausted {
		s.pendingRekeyMu.Unlock()
		return s.exhaustRekeyCounter()
	}
	if transition == math.MaxUint64 {
		s.transitionExhausted = true
	} else {
		s.nextTransition++
	}
	pending := &pendingRekey{done: make(chan struct{}), next: nextRoots, epoch: nextEpoch}
	binary.BigEndian.PutUint64(pending.payload[0:8], transition)
	binary.BigEndian.PutUint32(pending.payload[8:12], nextEpoch)
	binary.BigEndian.PutUint64(pending.payload[12:20], watermark)
	s.pendingRekey = pending
	s.pendingRekeyMu.Unlock()

	for _, stream := range s.snapshotStreams() {
		streamPending := stream.startSendRekey(transition, nextEpoch)
		if streamPending != nil {
			pending.streams = append(pending.streams, streamPending)
			go func(stream *encryptedStream, streamPending *pendingStreamRekey) {
				if err := stream.awaitSendRekeyACK(s.ctx, streamPending); err != nil && s.ctx.Err() == nil {
					s.fail(err)
				}
			}(stream, streamPending)
		}
	}
	for _, streamPending := range pending.streams {
		if err := s.waitRekeySignal(prepareContext, streamPending.armed); err != nil {
			s.clearPendingRekey(pending)
			s.fail(fmt.Errorf("%w: %v", ErrRekey, err))
			return err
		}
	}
	if err := s.sendControl(protocolv2.InnerSessionKeyUpdate, pending.payload[:]); err != nil {
		s.clearPendingRekey(pending)
		s.fail(fmt.Errorf("%w: %v", ErrRekey, err))
		return fmt.Errorf("%w: %v", ErrRekey, err)
	}
	cancelPrepare()
	completionContext, cancelCompletion := context.WithTimeout(s.ctx, s.config.RekeyCompletionTimeout)
	defer cancelCompletion()
	select {
	case <-pending.done:
	case <-completionContext.Done():
		err := completionContext.Err()
		s.clearPendingRekey(pending)
		s.fail(fmt.Errorf("%w: %w", ErrRekey, err))
		return fmt.Errorf("%w: %w", ErrRekey, err)
	case <-s.ctx.Done():
		return s.sessionError()
	}
	for _, streamPending := range pending.streams {
		if err := s.waitRekeySignal(completionContext, streamPending.done); err != nil {
			s.clearPendingRekey(pending)
			s.fail(fmt.Errorf("%w: %w", ErrRekey, err))
			return fmt.Errorf("%w: %w", ErrRekey, err)
		}
	}
	s.clearPendingRekey(pending)
	s.cleanupEpochRoots()
	s.unfreezeOpens()
	opensFrozen = false
	s.unfreezeResponders(false)
	respondersFrozen = false
	return nil
}

func (s *engineSession) handleSessionUpdate(payload []byte) error {
	if len(payload) != 20 {
		return ErrSessionProtocol
	}
	transition := binary.BigEndian.Uint64(payload[0:8])
	nextEpoch := binary.BigEndian.Uint32(payload[8:12])
	watermark := binary.BigEndian.Uint64(payload[12:20])
	if transition == 0 || s.recvTransition == math.MaxUint64 || transition != s.recvTransition+1 {
		return ErrSessionProtocol
	}
	s.cryptoMu.RLock()
	currentEpoch := s.recvSessionEpoch
	currentRoots := s.recvRoots[currentEpoch]
	s.cryptoMu.RUnlock()
	if currentEpoch == math.MaxUint32 || nextEpoch != currentEpoch+1 {
		return ErrSessionProtocol
	}
	nextSecret, err := protocolv2.DeriveNextEpoch(currentRoots.RekeyRoot, s.h3, s.recvDir, nextEpoch)
	if err != nil {
		return err
	}
	nextRoots, err := protocolv2.DeriveEpochRoots(nextSecret)
	if err != nil {
		return err
	}
	s.cryptoMu.Lock()
	s.recvRoots[nextEpoch] = nextRoots
	s.cryptoMu.Unlock()
	completionContext, cancelCompletion := context.WithTimeout(s.ctx, s.config.RekeyCompletionTimeout)
	stopDeadlineWatch := s.watchReceivedRekeyDeadline(completionContext)
	defer func() {
		stopDeadlineWatch()
		cancelCompletion()
	}()
	if err := s.freezeResponders(completionContext, true); err != nil {
		s.unfreezeResponders(true)
		return receivedRekeyWaitError(completionContext, err)
	}
	peerFrozen := true
	defer func() {
		if peerFrozen {
			s.unfreezeResponders(true)
		}
	}()
	if frontier := s.peerResolvedFrontier(); frontier != watermark {
		return ErrSessionProtocol
	}
	streams := s.snapshotStreams()
	for _, stream := range streams {
		if err := stream.awaitReceiveRekey(completionContext, transition, nextEpoch); err != nil {
			return receivedRekeyWaitError(completionContext, err)
		}
		if err := stream.validateReceiveRekeyCommit(transition, nextEpoch); err != nil {
			return err
		}
	}
	if err := s.commitControl(protocolv2.InnerSessionKeyUpdateACK, payload, func() error {
		s.cryptoMu.Lock()
		s.recvSessionEpoch = nextEpoch
		s.cryptoMu.Unlock()
		s.recvTransition = transition
		for _, stream := range streams {
			stream.publishReceiveRekey(transition, nextEpoch)
		}
		s.unfreezeResponders(true)
		peerFrozen = false
		return nil
	}); err != nil {
		return err
	}
	return nil
}

func (s *engineSession) watchReceivedRekeyDeadline(ctx context.Context) func() {
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		select {
		case <-ctx.Done():
		case <-stop:
		}
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			s.fail(fmt.Errorf("%w: %w", ErrRekey, context.DeadlineExceeded))
		}
	}()
	return func() {
		close(stop)
		<-done
	}
}

func receivedRekeyWaitError(ctx context.Context, err error) error {
	if contextErr := ctx.Err(); contextErr != nil {
		return contextErr
	}
	return err
}

func (s *engineSession) handleSessionUpdateACK(payload []byte) error {
	if len(payload) != 20 {
		return ErrSessionProtocol
	}
	s.pendingRekeyMu.Lock()
	pending := s.pendingRekey
	if pending == nil {
		duplicate := s.hasLastRekeyACK && bytes.Equal(payload, s.lastRekeyACK[:])
		s.pendingRekeyMu.Unlock()
		if duplicate {
			return nil
		}
		return ErrSessionProtocol
	}
	if !bytes.Equal(payload, pending.payload[:]) {
		s.pendingRekeyMu.Unlock()
		return ErrSessionProtocol
	}
	s.controlActorMu.Lock()
	s.cryptoMu.Lock()
	s.sendEpoch = pending.epoch
	s.controlSendEpoch = pending.epoch
	s.controlSendSeq = 0
	s.controlSendExhausted = false
	s.cryptoMu.Unlock()
	select {
	case <-pending.done:
	default:
		close(pending.done)
	}
	s.lastRekeyACK = pending.payload
	s.hasLastRekeyACK = true
	s.controlActorMu.Unlock()
	s.pendingRekeyMu.Unlock()
	return nil
}

func (s *engineSession) waitRekeySignal(ctx context.Context, signal <-chan struct{}) error {
	select {
	case <-signal:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-s.ctx.Done():
		return s.sessionError()
	}
}

func (s *engineSession) clearPendingRekey(pending *pendingRekey) {
	s.pendingRekeyMu.Lock()
	if s.pendingRekey == pending {
		s.pendingRekey = nil
	}
	s.pendingRekeyMu.Unlock()
}

func (s *engineSession) freezeOpens() error {
	s.openMu.Lock()
	defer s.openMu.Unlock()
	if s.ctx.Err() != nil {
		return s.sessionError()
	}
	if s.goingAway {
		return ErrGoingAway
	}
	if !s.openFrozen {
		s.openFrozen = true
		s.openChanged = make(chan struct{})
	}
	return nil
}

func (s *engineSession) unfreezeOpens() {
	s.openMu.Lock()
	if s.openFrozen {
		s.openFrozen = false
		close(s.openChanged)
	}
	s.openMu.Unlock()
}

func (s *engineSession) waitOpenGate(ctx context.Context) error {
	for {
		s.openMu.Lock()
		if s.ctx.Err() != nil {
			s.openMu.Unlock()
			return s.sessionError()
		}
		if s.goingAway {
			s.openMu.Unlock()
			return ErrGoingAway
		}
		if !s.openFrozen {
			s.openMu.Unlock()
			return nil
		}
		changed := s.openChanged
		s.openMu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			return ctx.Err()
		case <-s.ctx.Done():
			return s.sessionError()
		}
	}
}

func (s *engineSession) handleStreamReset(payload []byte) error {
	id, reason, err := parseIDReason(payload)
	if err != nil || id == 0 || reason == 0 {
		return ErrSessionProtocol
	}
	if stream := s.lookupStream(id); stream != nil {
		stream.peerReset(protocolv2.ErrStreamReset)
	}
	if validPeerLogicalID(s.role, id) {
		s.ledgerMu.Lock()
		err = s.ledger.PeerReset(id)
		s.ledgerMu.Unlock()
		if err != nil && !errors.Is(err, protocolv2.ErrInvalidLedgerState) {
			return err
		}
	} else if validLocalLogicalID(s.role, id) {
		s.ledgerMu.Lock()
		err = s.outboundLedger.PeerReset(id)
		s.notifyLedgerChangedLocked()
		s.ledgerMu.Unlock()
		if err != nil && !errors.Is(err, protocolv2.ErrInvalidLedgerState) {
			return err
		}
	}
	return nil
}

func validPeerLogicalID(localRole protocolv2.Role, id uint64) bool {
	if localRole == protocolv2.RoleClient {
		return id != 0 && id%2 == 0
	}
	return id%2 == 1
}

func validLocalLogicalID(localRole protocolv2.Role, id uint64) bool {
	return id != 0 && !validPeerLogicalID(localRole, id)
}

func validGoAwayBoundary(localRole protocolv2.Role, lastAccepted, localHighWatermark uint64) bool {
	if lastAccepted == 0 {
		return true
	}
	if lastAccepted > localHighWatermark {
		return false
	}
	if localRole == protocolv2.RoleClient {
		return lastAccepted%2 == 1
	}
	return lastAccepted%2 == 0
}

func marshalIDReason(id uint64, reason uint16) []byte {
	payload := make([]byte, 10)
	binary.BigEndian.PutUint64(payload[0:8], id)
	binary.BigEndian.PutUint16(payload[8:10], reason)
	return payload
}

func parseIDReason(payload []byte) (uint64, uint16, error) {
	if len(payload) != 10 {
		return 0, 0, ErrSessionProtocol
	}
	return binary.BigEndian.Uint64(payload[0:8]), binary.BigEndian.Uint16(payload[8:10]), nil
}
