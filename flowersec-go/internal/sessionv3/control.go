package sessionv3

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v3/internal/protocolv3"
)

var errPeerSessionClose = errors.New("peer closed Flowersec v3 session")

func (s *engineSession) sendControl(typ protocolv3.InnerType, payload []byte) error {
	priority := controlPriorityCritical
	if typ == protocolv3.InnerPing {
		priority = controlPriorityNormal
	} else if typ == protocolv3.InnerPong {
		priority = controlPriorityLiveness
	}
	return s.commitControlPriority(typ, payload, nil, priority)
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
	s.controlLivenessCap = s.controlNormalCap + 2
	s.controlCapacityChanged = make(chan struct{})
}

func (s *engineSession) startControlWriter() {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.controlWriterLoop()
	}()
}

func (s *engineSession) commitControl(typ protocolv3.InnerType, payload []byte, publish func() error) error {
	priority := controlPriorityCritical
	if typ == protocolv3.InnerPing || typ == protocolv3.InnerPong {
		priority = controlPriorityNormal
	}
	return s.commitControlPriority(typ, payload, publish, priority)
}

func (s *engineSession) commitControlPriority(typ protocolv3.InnerType, payload []byte, publish func() error, priority controlPriority) error {
	s.controlActorMu.Lock()
	defer s.controlActorMu.Unlock()
	return s.commitControlPriorityLocked(typ, payload, publish, priority, false, nil)
}

func (s *engineSession) commitControlPriorityDelivery(
	typ protocolv3.InnerType,
	payload []byte,
	publish func() error,
	priority controlPriority,
) (<-chan error, error) {
	delivery := make(chan error, 1)
	s.controlActorMu.Lock()
	err := s.commitControlPriorityLocked(typ, payload, publish, priority, false, delivery)
	s.controlActorMu.Unlock()
	if err != nil {
		return nil, err
	}
	return delivery, nil
}

func (s *engineSession) commitControlPriorityLocked(typ protocolv3.InnerType, payload []byte, publish func() error, priority controlPriority, terminal bool, delivery chan error) error {
	if s.controlTerminalSealed || (s.controlClosing && !terminal && typ != protocolv3.InnerStreamReset) {
		return ErrSessionClosed
	}
	inner, err := protocolv3.MarshalInnerRecord(typ, payload)
	if err != nil {
		return err
	}
	switch priority {
	case controlPriorityCritical:
		if !terminal && s.controlCriticalCount >= s.controlCriticalCap {
			return protocolv3.ErrControlQueueFull
		}
	case controlPriorityNormal:
		if s.controlNormalCount >= s.controlNormalCap {
			return protocolv3.ErrControlQueueFull
		}
	case controlPriorityLiveness:
		if s.controlLivenessCount >= s.controlLivenessCap {
			return protocolv3.ErrControlQueueFull
		}
	default:
		return ErrSessionProtocol
	}

	s.cryptoMu.RLock()
	epoch := s.controlSendEpoch
	sequence := s.controlSendSeq
	exhausted := s.controlSendExhausted
	roots, ok := s.sendRoots[epoch]
	s.cryptoMu.RUnlock()
	if exhausted {
		return protocolv3.ErrCounterExhausted
	}
	if !ok {
		return ErrSessionProtocol
	}
	material, err := protocolv3.DeriveControlMaterial(roots.ControlRoot, s.h3, s.sendDir, epoch)
	if err != nil {
		return err
	}
	header := protocolv3.RecordHeader{
		Epoch: epoch, Sequence: sequence,
		CiphertextLength: uint32(len(inner) + protocolv3.AEADTagBytes),
	}
	ciphertext, err := protocolv3.SealRecord(s.config.Suite, material.RecordKey, material.NoncePrefix, s.h3, 0, s.sendDir, header, inner)
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
		typ: typ, epoch: epoch, sequence: sequence, raw: raw, priority: priority, delivery: delivery,
	})
	switch priority {
	case controlPriorityCritical:
		s.controlCriticalCount++
	case controlPriorityNormal:
		s.controlNormalCount++
	case controlPriorityLiveness:
		s.controlLivenessCount++
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

func (s *engineSession) closeControlTerminal(ctx context.Context, goAwayPayload []byte) error {
	if ctx == nil {
		ctx = context.Background()
	}
	s.controlActorMu.Lock()
	if s.controlTerminalSealed {
		idle := s.controlIdle
		s.controlActorMu.Unlock()
		return errors.Join(waitForControlIdle(ctx, s.ctx, idle, s.sessionError), s.control.CloseWrite())
	}
	s.controlClosing = true
	var protocolErr error
	if goAwayPayload != nil {
		protocolErr = s.commitControlPriorityLocked(protocolv3.InnerGoAway, goAwayPayload, nil, controlPriorityCritical, true, nil)
	}
	protocolErr = errors.Join(protocolErr, s.commitControlPriorityLocked(protocolv3.InnerSessionClose, []byte{0, 1}, nil, controlPriorityCritical, true, nil))
	s.controlTerminalSealed = true
	close(s.controlCapacityChanged)
	s.controlCapacityChanged = make(chan struct{})
	idle := s.controlIdle
	s.controlActorMu.Unlock()
	protocolErr = errors.Join(protocolErr, waitForControlIdle(ctx, s.ctx, idle, s.sessionError))
	protocolErr = errors.Join(protocolErr, s.control.CloseWrite())
	return protocolErr
}

func (s *engineSession) sealControl() {
	s.controlActorMu.Lock()
	if !s.controlTerminalSealed {
		s.controlClosing = true
		s.controlTerminalSealed = true
		close(s.controlCapacityChanged)
		s.controlCapacityChanged = make(chan struct{})
	}
	s.controlActorMu.Unlock()
}

func waitForControlIdle(ctx, sessionCtx context.Context, idle <-chan struct{}, sessionError func() error) error {
	select {
	case <-idle:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-sessionCtx.Done():
		return sessionError()
	}
}

func (s *engineSession) commitControlPriorityWait(ctx context.Context, typ protocolv3.InnerType, payload []byte, priority controlPriority) error {
	for {
		err := s.commitControlPriority(typ, payload, nil, priority)
		if !errors.Is(err, protocolv3.ErrControlQueueFull) {
			return err
		}
		s.controlActorMu.Lock()
		if s.controlPriorityHasCapacityLocked(priority) {
			s.controlActorMu.Unlock()
			continue
		}
		changed := s.controlCapacityChanged
		s.controlActorMu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			return ctx.Err()
		case <-s.ctx.Done():
			return s.sessionError()
		}
	}
}

func (s *engineSession) controlPriorityHasCapacityLocked(priority controlPriority) bool {
	switch priority {
	case controlPriorityCritical:
		return s.controlCriticalCount < s.controlCriticalCap
	case controlPriorityNormal:
		return s.controlNormalCount < s.controlNormalCap
	case controlPriorityLiveness:
		return s.controlLivenessCount < s.controlLivenessCap
	default:
		return false
	}
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
				if record.delivery != nil {
					record.delivery <- err
					close(record.delivery)
				}
				return
			}
			s.touchActivity()
			if record.delivery != nil {
				record.delivery <- nil
				close(record.delivery)
			}

			s.controlActorMu.Lock()
			s.controlQueue[0] = queuedControlRecord{}
			s.controlQueue = s.controlQueue[1:]
			switch record.priority {
			case controlPriorityCritical:
				s.controlCriticalCount--
			case controlPriorityNormal:
				s.controlNormalCount--
			case controlPriorityLiveness:
				s.controlLivenessCount--
			}
			close(s.controlCapacityChanged)
			s.controlCapacityChanged = make(chan struct{})
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
	return waitForControlIdle(ctx, s.ctx, idle, s.sessionError)
}

func (s *engineSession) readControl() (protocolv3.InnerType, []byte, error) {
	rawHeader := make([]byte, protocolv3.RecordHeaderSize)
	if _, err := io.ReadFull(s.control, rawHeader); err != nil {
		return 0, nil, err
	}
	header, err := protocolv3.ParseRecordHeader(rawHeader)
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
			return 0, nil, protocolv3.ErrCounterExhausted
		}
		if header.Sequence != s.controlRecvSeq {
			s.cryptoMu.Unlock()
			return 0, nil, protocolv3.ErrControlSequence
		}
	} else if s.controlRecvEpoch != math.MaxUint32 && header.Epoch == s.controlRecvEpoch+1 && header.Epoch <= s.recvSessionEpoch && header.Sequence == 0 {
		cutover = true
	} else {
		s.cryptoMu.Unlock()
		return 0, nil, protocolv3.ErrFutureControlEpoch
	}
	roots, ok := s.recvRoots[header.Epoch]
	if !ok {
		s.cryptoMu.Unlock()
		return 0, nil, protocolv3.ErrFutureControlEpoch
	}
	material, err := protocolv3.DeriveControlMaterial(roots.ControlRoot, s.h3, s.recvDir, header.Epoch)
	if err != nil {
		s.cryptoMu.Unlock()
		return 0, nil, err
	}
	plaintext, err := protocolv3.OpenRecord(s.config.Suite, material.RecordKey, material.NoncePrefix, s.h3, 0, s.recvDir, header, ciphertext)
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
	typ, payload, err := protocolv3.ParseInnerRecord(plaintext)
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
				if s.isClosing() {
					s.signalPeerSessionClose()
				} else {
					s.fail(fmt.Errorf("%w: control read: %v", ErrSessionProtocol, err))
				}
			}
			return
		}
		if err := s.handleControl(typ, payload); err != nil {
			if errors.Is(err, errPeerSessionClose) {
				s.handlePeerSessionClose()
			} else {
				s.fail(fmt.Errorf("%w: %v", ErrSessionProtocol, err))
			}
			return
		}
	}
}

func (s *engineSession) handleControl(typ protocolv3.InnerType, payload []byte) error {
	switch typ {
	case protocolv3.InnerPing:
		if s.isClosing() {
			return nil
		}
		err := s.commitControlPriorityWait(s.ctx, protocolv3.InnerPong, payload, controlPriorityLiveness)
		if errors.Is(err, ErrSessionClosed) && s.isClosing() {
			return nil
		}
		return err
	case protocolv3.InnerPong:
		nonce := binary.BigEndian.Uint64(payload)
		s.pingsMu.Lock()
		waiter := s.pings[nonce]
		if waiter != nil {
			delete(s.pings, nonce)
			close(waiter)
		}
		s.pingsMu.Unlock()
		return nil
	case protocolv3.InnerStreamReset:
		return s.handleStreamReset(payload)
	case protocolv3.InnerSessionKeyUpdate:
		return s.handleSessionUpdate(payload)
	case protocolv3.InnerSessionKeyUpdateACK:
		return s.handleSessionUpdateACK(payload)
	case protocolv3.InnerGoAway:
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
	case protocolv3.InnerSessionClose:
		if len(payload) != 2 || binary.BigEndian.Uint16(payload) == 0 {
			return ErrSessionProtocol
		}
		return errPeerSessionClose
	default:
		return fmt.Errorf("unexpected control type %d", typ)
	}
}

func (s *engineSession) ProbeLiveness(ctx context.Context) (time.Duration, error) {
	return s.probeLiveness(ctx, false)
}

func (s *engineSession) registerResetConfirmation() uint64 {
	s.resetConfirmMu.Lock()
	s.resetConfirmNext++
	target := s.resetConfirmNext
	s.resetConfirmMu.Unlock()
	return target
}

func (s *engineSession) confirmResetDelivery(target uint64) error {
	for {
		s.resetConfirmMu.Lock()
		if s.resetConfirmComplete >= target {
			s.resetConfirmMu.Unlock()
			return nil
		}
		flight := s.resetConfirmFlight
		if flight == nil {
			flight = &resetConfirmationFlight{target: s.resetConfirmNext, done: make(chan struct{})}
			s.resetConfirmFlight = flight
			s.resetConfirmMu.Unlock()

			ctx, cancel := context.WithTimeout(context.Background(), resetControlConfirmTimeout)
			_, err := s.probeLiveness(ctx, true)
			cancel()

			s.resetConfirmMu.Lock()
			flight.err = err
			if err == nil && s.resetConfirmComplete < flight.target {
				s.resetConfirmComplete = flight.target
			}
			if s.resetConfirmFlight == flight {
				s.resetConfirmFlight = nil
			}
			close(flight.done)
			s.resetConfirmMu.Unlock()
			if err != nil {
				return err
			}
			continue
		}
		s.resetConfirmMu.Unlock()
		select {
		case <-flight.done:
			if flight.err != nil {
				return flight.err
			}
		case <-s.ctx.Done():
			return s.sessionError()
		}
	}
}

func (s *engineSession) probeLiveness(ctx context.Context, critical bool) (time.Duration, error) {
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
	priority := controlPriorityNormal
	if critical {
		priority = controlPriorityLiveness
	}
	var err error
	if critical {
		err = s.commitControlPriorityWait(ctx, protocolv3.InnerPing, payload[:], priority)
	} else {
		err = s.commitControlPriority(protocolv3.InnerPing, payload[:], nil, priority)
	}
	if err != nil {
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
	rekeyOwned := true
	defer func() {
		if rekeyOwned {
			s.rekeyMu.Unlock()
		}
	}()
	prepareContext, cancelPrepare := context.WithTimeout(ctx, s.config.RekeyPrepareTimeout)
	defer cancelPrepare()
	s.cryptoMu.RLock()
	currentEpoch := s.sendEpoch
	currentRoots := s.sendRoots[currentEpoch]
	s.cryptoMu.RUnlock()
	s.pendingRekeyMu.Lock()
	transition := s.nextTransition
	transitionExhausted := s.transitionExhausted
	s.pendingRekeyMu.Unlock()
	if currentEpoch == math.MaxUint32 || transition == 0 || transitionExhausted {
		return s.exhaustRekeyCounter(prepareContext, ctx)
	}
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

	nextEpoch := currentEpoch + 1
	nextSecret, err := protocolv3.DeriveNextEpoch(currentRoots.RekeyRoot, s.h3, s.sendDir, nextEpoch)
	if err != nil {
		return err
	}
	nextRoots, err := protocolv3.DeriveEpochRoots(nextSecret)
	if err != nil {
		return err
	}
	s.cryptoMu.Lock()
	s.sendRoots[nextEpoch] = nextRoots
	s.cryptoMu.Unlock()
	s.pendingRekeyMu.Lock()
	transition = s.nextTransition
	if transition == 0 || s.transitionExhausted {
		s.pendingRekeyMu.Unlock()
		s.cryptoMu.Lock()
		delete(s.sendRoots, nextEpoch)
		s.cryptoMu.Unlock()
		return s.exhaustRekeyCounter(prepareContext, ctx)
	}
	s.nextTransition, s.transitionExhausted = advanceSessionTransition(transition)
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
		if err := s.waitStreamRekeyCommit(prepareContext, streamPending.armed); err != nil {
			s.clearPendingRekey(pending)
			s.fail(fmt.Errorf("%w: %v", ErrRekey, err))
			return fmt.Errorf("%w: %v", ErrRekey, err)
		}
	}
	if err := s.sendControl(protocolv3.InnerSessionKeyUpdate, pending.payload[:]); err != nil {
		s.clearPendingRekey(pending)
		s.fail(fmt.Errorf("%w: %v", ErrRekey, err))
		return fmt.Errorf("%w: %v", ErrRekey, err)
	}
	cancelPrepare()
	completion := make(chan error, 1)
	rekeyOwned = false
	opensFrozen = false
	respondersFrozen = false
	go func() {
		completion <- s.completeOwnedRekey(pending)
		close(completion)
	}()
	select {
	case err := <-completion:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *engineSession) completeOwnedRekey(pending *pendingRekey) error {
	defer s.rekeyMu.Unlock()
	defer s.unfreezeOpens()
	defer s.unfreezeResponders(false)
	completionContext, cancelCompletion := context.WithTimeout(s.ctx, s.config.RekeyCompletionTimeout)
	defer cancelCompletion()
	select {
	case <-pending.done:
	case <-completionContext.Done():
		return s.failOwnedRekeyCompletion(pending, completionContext.Err())
	case <-s.ctx.Done():
		s.clearPendingRekey(pending)
		return s.sessionError()
	}
	for _, streamPending := range pending.streams {
		if err := s.waitRekeySignal(completionContext, streamPending.done); err != nil {
			return s.failOwnedRekeyCompletion(pending, err)
		}
	}
	s.clearPendingRekey(pending)
	s.cleanupEpochRoots()
	return nil
}

func (s *engineSession) failOwnedRekeyCompletion(pending *pendingRekey, err error) error {
	s.clearPendingRekey(pending)
	if s.ctx.Err() != nil {
		return s.sessionError()
	}
	if errors.Is(err, context.DeadlineExceeded) {
		s.fail(context.DeadlineExceeded)
		return fmt.Errorf("%w: rekey completion deadline", ErrRekey)
	}
	operationErr := fmt.Errorf("%w: %w", ErrRekey, err)
	s.fail(operationErr)
	return operationErr
}

func advanceSessionTransition(current uint64) (next uint64, exhausted bool) {
	if current == math.MaxUint64 {
		return 0, true
	}
	return current + 1, false
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
	nextSecret, err := protocolv3.DeriveNextEpoch(currentRoots.RekeyRoot, s.h3, s.recvDir, nextEpoch)
	if err != nil {
		return err
	}
	nextRoots, err := protocolv3.DeriveEpochRoots(nextSecret)
	if err != nil {
		return err
	}
	insertedNextRoots := false
	receiveRekeyCommitted := false
	s.cryptoMu.Lock()
	if existing, exists := s.recvRoots[nextEpoch]; exists {
		if existing != nextRoots {
			s.cryptoMu.Unlock()
			return ErrSessionProtocol
		}
	} else {
		s.recvRoots[nextEpoch] = nextRoots
		insertedNextRoots = true
	}
	s.cryptoMu.Unlock()
	defer func() {
		if !insertedNextRoots || receiveRekeyCommitted {
			return
		}
		s.cryptoMu.Lock()
		if existing, exists := s.recvRoots[nextEpoch]; exists && existing == nextRoots {
			delete(s.recvRoots, nextEpoch)
		}
		s.cryptoMu.Unlock()
	}()
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
	if s.isClosing() {
		return nil
	}
	if err := s.commitControl(protocolv3.InnerSessionKeyUpdateACK, payload, func() error {
		s.cryptoMu.Lock()
		s.recvSessionEpoch = nextEpoch
		s.cryptoMu.Unlock()
		receiveRekeyCommitted = true
		s.recvTransition = transition
		for _, stream := range streams {
			stream.publishReceiveRekey(transition, nextEpoch)
		}
		s.unfreezeResponders(true)
		peerFrozen = false
		return nil
	}); err != nil {
		if errors.Is(err, ErrSessionClosed) && s.isClosing() {
			return nil
		}
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

func (s *engineSession) waitStreamRekeyCommit(ctx context.Context, signal <-chan error) error {
	select {
	case err := <-signal:
		return err
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
		stream.peerReset(protocolv3.ErrStreamReset)
	}
	if validPeerLogicalID(s.role, id) {
		s.ledgerMu.Lock()
		err = s.ledger.PeerReset(id)
		s.ledgerMu.Unlock()
		if err != nil && !errors.Is(err, protocolv3.ErrInvalidLedgerState) {
			return err
		}
	} else if validLocalLogicalID(s.role, id) {
		s.ledgerMu.Lock()
		err = s.outboundLedger.PeerReset(id)
		s.notifyLedgerChangedLocked()
		s.ledgerMu.Unlock()
		if err != nil && !errors.Is(err, protocolv3.ErrInvalidLedgerState) {
			return err
		}
	}
	return nil
}

func validPeerLogicalID(localRole protocolv3.Role, id uint64) bool {
	if localRole == protocolv3.RoleClient {
		return id != 0 && id%2 == 0
	}
	return id%2 == 1
}

func validLocalLogicalID(localRole protocolv3.Role, id uint64) bool {
	return id != 0 && !validPeerLogicalID(localRole, id)
}

func validGoAwayBoundary(localRole protocolv3.Role, lastAccepted, localHighWatermark uint64) bool {
	if lastAccepted == 0 {
		return true
	}
	if lastAccepted > localHighWatermark {
		return false
	}
	if localRole == protocolv3.RoleClient {
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
