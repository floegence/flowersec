package sessionv3

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v3/internal/carrier"
	"github.com/floegence/flowersec/flowersec-go/v3/internal/protocolv3"
)

type encryptedStream struct {
	session *engineSession
	carrier carrier.Stream
	id      uint64
	kind    string

	stateMu sync.Mutex
	state   *protocolv3.LogicalStreamState

	sendMu                  sync.Mutex
	sendEpoch               uint32
	sendSeq                 uint64
	sendExhausted           bool
	sendRekeyMu             sync.Mutex
	sendRekey               *pendingStreamRekey
	lastSendRekeyTransition uint64
	lastSendRekeyEpoch      uint32
	sendRootNeed            atomic.Uint64

	readMu            sync.Mutex
	readOwnerMu       sync.Mutex
	readOwner         uint8
	readOwnerChanged  chan struct{}
	recvEpoch         uint32
	recvSeq           uint64
	recvExhausted     bool
	recvPriorEpoch    uint32
	recvPriorSeq      uint64
	recvPriorACK      bool
	readBuf           []byte
	remoteEOF         bool
	recvUpdateMu      sync.Mutex
	recvUpdateID      uint64
	recvUpdateEpoch   uint32
	recvUpdateAcked   bool
	recvUpdateChanged chan struct{}
	recvRootNeed      atomic.Uint64

	terminalMu  sync.RWMutex
	terminalErr error
	releaseOnce sync.Once
	release     func()
}

type openResponse struct {
	rejected bool
	err      error
}

const (
	reservedRPCStreamKind      = "flowersec.rpc.v3"
	maxCoalescedWriteBytes     = 4 * protocolv3.MaxDataBytes
	resetControlConfirmTimeout = 2 * time.Second
)

func (s *engineSession) OpenStream(ctx context.Context, kind string, metadata Metadata) (ByteStream, error) {
	if kind == reservedRPCStreamKind {
		return nil, ErrOpenRejected
	}
	return s.openStream(ctx, kind, metadata, false)
}

func (s *engineSession) openStream(ctx context.Context, kind string, metadata Metadata, internal bool) (ByteStream, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	metadataRaw, err := encodeMetadata(metadata)
	if err != nil {
		return nil, err
	}
	if _, err := protocolv3.MarshalOpenPayload(protocolv3.OpenPayload{
		LogicalStreamID: 1, Kind: kind, Metadata: metadataRaw,
	}); err != nil {
		return nil, err
	}
	if err := s.waitOpenGate(ctx); err != nil {
		return nil, err
	}
	if !internal {
		select {
		case s.outboundPermits <- struct{}{}:
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-s.ctx.Done():
			return nil, s.sessionError()
		}
	}
	releasePermit := true
	defer func() {
		if releasePermit && !internal {
			<-s.outboundPermits
		}
	}()

	var logicalID uint64
	var sendEpoch, receiveEpoch uint32
	var setupRoot [32]byte
	for {
		if err := s.waitOpenGate(ctx); err != nil {
			return nil, err
		}
		s.openMu.Lock()
		if s.openFrozen {
			s.openMu.Unlock()
			continue
		}
		if s.goingAway || s.ctx.Err() != nil {
			s.openMu.Unlock()
			if s.ctx.Err() != nil {
				return nil, s.sessionError()
			}
			return nil, ErrGoingAway
		}
		logicalID = s.nextID
		if logicalID == 0 {
			s.openMu.Unlock()
			return nil, protocolv3.ErrCounterExhausted
		}
		if logicalID > protocolv3.MaxLogicalStreamID(s.role) {
			s.openMu.Unlock()
			if err := s.sendGoAway(5); err != nil {
				s.fail(err)
				return nil, err
			}
			return nil, ErrResourceExhausted
		}
		s.nextID += 2
		s.ledgerMu.Lock()
		ledgerErr := s.outboundLedger.ValidFSS3(logicalID)
		s.notifyLedgerChangedLocked()
		s.ledgerMu.Unlock()
		if ledgerErr != nil {
			s.openMu.Unlock()
			return nil, ledgerErr
		}
		s.cryptoMu.RLock()
		sendEpoch = s.sendEpoch
		receiveEpoch = s.recvSessionEpoch
		setupRoot = s.sendRoots[sendEpoch].SetupMACRoot
		s.cryptoMu.RUnlock()
		s.openMu.Unlock()
		break
	}

	carrierStream, err := s.carrier.OpenStream(ctx)
	if err != nil {
		_ = s.commitOutboundReset(logicalID)
		return nil, err
	}
	stopSetupWatch := watchStreamContext(ctx, carrierStream)
	defer stopSetupWatch()
	if !s.localOpeningAllowedAfterGoAway(logicalID) {
		_ = carrierStream.Reset()
		_ = s.commitOutboundReset(logicalID)
		return nil, ErrGoingAway
	}
	preface := protocolv3.SetupPreface{
		OpenerRole: s.role, LogicalStreamID: logicalID, InitialEpoch: sendEpoch,
	}
	preface.SetupMAC, err = protocolv3.ComputeSetupMAC(setupRoot, s.h3, preface)
	if err != nil {
		_ = carrierStream.Reset()
		return nil, err
	}
	rawPreface, err := preface.MarshalBinary()
	if err != nil {
		_ = carrierStream.Reset()
		return nil, err
	}
	if err := writeAll(carrierStream, rawPreface); err != nil {
		_ = carrierStream.Reset()
		_ = s.commitOutboundReset(logicalID)
		if !s.localOpeningAllowedAfterGoAway(logicalID) {
			return nil, ErrGoingAway
		}
		return nil, preferOpenContextError(ctx, err)
	}
	if !s.localOpeningAllowedAfterGoAway(logicalID) {
		_ = carrierStream.Reset()
		_ = s.commitOutboundReset(logicalID)
		return nil, ErrGoingAway
	}
	fss2Hash, err := protocolv3.ComputeFSS3Hash(rawPreface)
	if err != nil {
		_ = carrierStream.Reset()
		return nil, err
	}
	openRaw, err := protocolv3.MarshalOpenPayload(protocolv3.OpenPayload{
		LogicalStreamID: logicalID, FSS3Hash: fss2Hash, Kind: kind, Metadata: metadataRaw,
	})
	if err != nil {
		_ = carrierStream.Reset()
		return nil, err
	}
	state, err := protocolv3.NewOutboundLogicalStreamState(logicalID, fss2Hash)
	if err != nil {
		_ = carrierStream.Reset()
		return nil, err
	}
	stream := &encryptedStream{
		session: s, carrier: carrierStream, id: logicalID, kind: kind, state: state,
		sendEpoch: sendEpoch, recvEpoch: receiveEpoch,
		readOwnerChanged: make(chan struct{}), recvUpdateChanged: make(chan struct{}),
	}
	stream.setSendRootEpoch(sendEpoch)
	stream.setReceiveRootEpoch(receiveEpoch)
	stream.release = func() {
		s.unregisterStream(logicalID)
		if !internal {
			<-s.outboundPermits
		}
	}
	s.registerStream(stream)
	if err := stream.sendOpen(openRaw); err != nil {
		stream.localReset(err)
		releasePermit = false
		return nil, preferOpenContextError(ctx, err)
	}

	responseCh := make(chan openResponse, 1)
	go func() {
		rejected, err := stream.receiveOpenResponse()
		responseCh <- openResponse{rejected: rejected, err: err}
	}()
	select {
	case response := <-responseCh:
		if response.err != nil {
			stream.localReset(response.err)
			releasePermit = false
			if !s.localOpeningAllowedAfterGoAway(logicalID) {
				return nil, ErrGoingAway
			}
			return nil, response.err
		}
		if err := s.resolveOutboundOpen(logicalID); err != nil {
			stream.localReset(err)
			releasePermit = false
			return nil, err
		}
		if response.rejected {
			stream.finish(ErrOpenRejected, true)
			releasePermit = false
			return nil, ErrOpenRejected
		}
		if !s.localOpeningAllowedAfterGoAway(logicalID) {
			stream.localReset(ErrGoingAway)
			releasePermit = false
			return nil, ErrGoingAway
		}
		releasePermit = false
		return stream, nil
	case <-ctx.Done():
		stream.localReset(ctx.Err())
		releasePermit = false
		return nil, ctx.Err()
	case <-s.ctx.Done():
		stream.peerReset(s.sessionError())
		releasePermit = false
		return nil, s.sessionError()
	}
}

func preferOpenContextError(ctx context.Context, err error) error {
	if contextErr := ctx.Err(); contextErr != nil {
		return contextErr
	}
	return err
}

func (s *engineSession) acceptCarrierStreams() {
	for {
		stream, err := s.carrier.AcceptStream(s.ctx)
		if err != nil {
			if s.ctx.Err() == nil {
				s.fail(err)
			}
			return
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.acceptCarrierStream(stream)
		}()
	}
}

func (s *engineSession) acceptCarrierStream(carrierStream carrier.Stream) {
	rawPreface := make([]byte, protocolv3.SetupPrefaceSize)
	if _, err := io.ReadFull(carrierStream, rawPreface); err != nil {
		_ = carrierStream.Reset()
		return
	}
	preface, err := protocolv3.ParseSetupPreface(rawPreface)
	if err != nil || !validPeerLogicalID(s.role, preface.LogicalStreamID) {
		_ = carrierStream.Reset()
		return
	}
	if err := s.enterResponder(); err != nil {
		_ = carrierStream.Reset()
		return
	}
	responderHeld := true
	defer func() {
		if responderHeld {
			s.leaveResponder()
		}
	}()
	if !s.acceptsPeerStreamAfterGoAway(preface.LogicalStreamID) {
		_ = carrierStream.Reset()
		return
	}
	s.cryptoMu.RLock()
	receiveEpoch := s.recvSessionEpoch
	roots, ok := s.recvRoots[preface.InitialEpoch]
	s.cryptoMu.RUnlock()
	if !ok || preface.InitialEpoch != receiveEpoch || !protocolv3.VerifySetupMAC(roots.SetupMACRoot, s.h3, preface) {
		_ = carrierStream.Reset()
		return
	}

	s.ledgerMu.Lock()
	ledgerState := s.ledger.State(preface.LogicalStreamID)
	if ledgerState == protocolv3.LedgerAbandonedNoFSS3 {
		_, err = s.ledger.ValidFSS3ForAbandoned(preface.LogicalStreamID)
		s.ledgerMu.Unlock()
		_ = carrierStream.Reset()
		if err != nil {
			s.fail(err)
		}
		return
	}
	err = s.ledger.ValidFSS3(preface.LogicalStreamID)
	s.ledgerMu.Unlock()
	if err != nil {
		_ = carrierStream.Reset()
		if errors.Is(err, protocolv3.ErrDuplicateStreamID) {
			s.fail(err)
		}
		return
	}

	fss2Hash, err := protocolv3.ComputeFSS3Hash(rawPreface)
	if err != nil {
		_ = carrierStream.Reset()
		return
	}
	typ, openRaw, header, err := s.readStreamRecord(carrierStream, preface.LogicalStreamID, preface.InitialEpoch, 0)
	if err != nil || typ != protocolv3.InnerOpen {
		s.resetInboundBeforeDelivery(preface.LogicalStreamID, carrierStream)
		return
	}
	s.ledgerMu.Lock()
	state, err := protocolv3.NewInboundLogicalStreamState(s.ledger, preface.LogicalStreamID, fss2Hash)
	if err != nil {
		s.ledgerMu.Unlock()
		s.resetInboundBeforeDelivery(preface.LogicalStreamID, carrierStream)
		return
	}
	err = state.ReceiveOpen(openRaw)
	s.ledgerMu.Unlock()
	if err != nil {
		s.resetInboundBeforeDelivery(preface.LogicalStreamID, carrierStream)
		return
	}
	open, err := protocolv3.ParseOpenPayload(openRaw)
	if err != nil {
		s.resetInboundBeforeDelivery(preface.LogicalStreamID, carrierStream)
		return
	}
	metadata, err := decodeMetadata(open.Metadata)
	if err != nil {
		s.resetInboundBeforeDelivery(preface.LogicalStreamID, carrierStream)
		return
	}

	internal := open.Kind == reservedRPCStreamKind
	if internal && len(metadata) != 0 {
		s.rejectInbound(carrierStream, state, preface.LogicalStreamID, openRaw, protocolv3.OpenRejectInvalidMetadata)
		return
	}
	if !internal {
		select {
		case s.inboundPermits <- struct{}{}:
		default:
			s.rejectInbound(carrierStream, state, preface.LogicalStreamID, openRaw, protocolv3.OpenRejectResourceExhausted)
			return
		}
	}
	s.cryptoMu.RLock()
	sendEpoch := s.sendEpoch
	s.cryptoMu.RUnlock()
	stream := &encryptedStream{
		session: s, carrier: carrierStream, id: preface.LogicalStreamID,
		kind: open.Kind, state: state, sendEpoch: sendEpoch,
		recvEpoch: header.Epoch, recvSeq: 1,
		readOwnerChanged: make(chan struct{}), recvUpdateChanged: make(chan struct{}),
	}
	stream.setSendRootEpoch(sendEpoch)
	stream.setReceiveRootEpoch(header.Epoch)
	stream.release = func() {
		s.unregisterStream(stream.id)
		if !internal {
			<-s.inboundPermits
		}
	}
	s.registerStream(stream)
	openHash, err := protocolv3.ComputeOpenHash(openRaw)
	if err != nil {
		stream.localReset(err)
		return
	}
	if err := stream.sendOpenACK(protocolv3.MarshalOpenACK(openHash)); err != nil {
		stream.localReset(err)
		return
	}
	// The responder barrier covers validation and the ordered ACK commit, not
	// the lifetime of an accepted stream. Long-lived reserved streams (RPC) must
	// not keep session rekey permanently frozen.
	s.leaveResponder()
	responderHeld = false
	incoming := IncomingStream{ID: stream.id, Kind: stream.kind, Metadata: metadata, Stream: stream}
	if !s.acceptsPeerStreamAfterGoAway(stream.id) {
		stream.localReset(ErrGoingAway)
		return
	}
	if internal {
		s.serveRPCStream(stream)
		return
	}
	select {
	case s.acceptCh <- incoming:
	case <-s.ctx.Done():
		stream.peerReset(s.sessionError())
	}
}

func (s *engineSession) resetInboundBeforeDelivery(id uint64, stream carrier.Stream) {
	_ = stream.Reset()
	if err := s.commitControl(protocolv3.InnerStreamReset, marshalIDReason(id, 3), func() error {
		s.ledgerMu.Lock()
		defer s.ledgerMu.Unlock()
		return s.ledger.LocalResetCommitted(id)
	}); err != nil {
		s.fail(err)
	}
}

func (s *engineSession) rejectInbound(carrierStream carrier.Stream, state *protocolv3.LogicalStreamState, id uint64, openRaw []byte, reason protocolv3.OpenRejectReason) {
	openHash, err := protocolv3.ComputeOpenHash(openRaw)
	if err != nil {
		s.resetInboundBeforeDelivery(id, carrierStream)
		return
	}
	payload, err := protocolv3.MarshalOpenReject(openHash, reason)
	if err != nil {
		s.resetInboundBeforeDelivery(id, carrierStream)
		return
	}
	s.cryptoMu.RLock()
	sendEpoch := s.sendEpoch
	s.cryptoMu.RUnlock()
	stream := &encryptedStream{
		session: s, carrier: carrierStream, id: id, state: state, sendEpoch: sendEpoch,
		readOwnerChanged: make(chan struct{}), recvUpdateChanged: make(chan struct{}),
	}
	if err := stream.sendOpenReject(payload); err == nil {
		_ = stream.CloseWrite()
	}
	_ = carrierStream.Close()
}

func (s *engineSession) readStreamRecord(stream carrier.Stream, logicalID uint64, epoch uint32, sequence uint64) (protocolv3.InnerType, []byte, protocolv3.RecordHeader, error) {
	typ, payload, header, err := s.readStreamRecordAny(stream, logicalID)
	if err != nil {
		return 0, nil, protocolv3.RecordHeader{}, err
	}
	if header.Epoch != epoch || header.Sequence != sequence {
		return 0, nil, protocolv3.RecordHeader{}, ErrSessionProtocol
	}
	return typ, payload, header, nil
}

func (s *engineSession) readStreamRecordAny(stream carrier.Stream, logicalID uint64) (protocolv3.InnerType, []byte, protocolv3.RecordHeader, error) {
	rawHeader := make([]byte, protocolv3.RecordHeaderSize)
	if _, err := io.ReadFull(stream, rawHeader); err != nil {
		return 0, nil, protocolv3.RecordHeader{}, err
	}
	header, err := protocolv3.ParseRecordHeader(rawHeader)
	if err != nil {
		return 0, nil, protocolv3.RecordHeader{}, ErrSessionProtocol
	}
	ciphertext := make([]byte, int(header.CiphertextLength))
	if _, err := io.ReadFull(stream, ciphertext); err != nil {
		return 0, nil, protocolv3.RecordHeader{}, err
	}
	s.cryptoMu.RLock()
	roots, ok := s.recvRoots[header.Epoch]
	s.cryptoMu.RUnlock()
	if !ok {
		return 0, nil, protocolv3.RecordHeader{}, ErrSessionProtocol
	}
	material, err := protocolv3.DeriveStreamMaterial(roots.StreamRoot, s.h3, logicalID, s.recvDir, header.Epoch)
	if err != nil {
		return 0, nil, protocolv3.RecordHeader{}, err
	}
	plaintext, err := protocolv3.OpenRecord(s.config.Suite, material.RecordKey, material.NoncePrefix, s.h3, logicalID, s.recvDir, header, ciphertext)
	if err != nil {
		return 0, nil, protocolv3.RecordHeader{}, err
	}
	typ, payload, err := protocolv3.ParseInnerRecord(plaintext)
	return typ, payload, header, err
}

func (s *encryptedStream) sendOpen(payload []byte) error {
	s.stateMu.Lock()
	err := s.state.SendOpen(payload)
	s.stateMu.Unlock()
	if err != nil {
		return err
	}
	return s.writeRecord(protocolv3.InnerOpen, payload)
}

func (s *encryptedStream) sendOpenACK(payload []byte) error {
	s.stateMu.Lock()
	err := s.state.SendOpenACK(payload)
	s.stateMu.Unlock()
	if err != nil {
		return err
	}
	return s.writeRecord(protocolv3.InnerOpenACK, payload)
}

func (s *encryptedStream) sendOpenReject(payload []byte) error {
	s.stateMu.Lock()
	err := s.state.SendOpenReject(payload)
	s.stateMu.Unlock()
	if err != nil {
		return err
	}
	return s.writeRecord(protocolv3.InnerOpenReject, payload)
}

func (s *encryptedStream) receiveOpenResponse() (bool, error) {
	typ, payload, header, err := s.session.readStreamRecord(s.carrier, s.id, s.recvEpoch, 0)
	if err != nil {
		return false, err
	}
	s.readMu.Lock()
	s.recvEpoch = header.Epoch
	s.recvSeq = 1
	s.readMu.Unlock()
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	switch typ {
	case protocolv3.InnerOpenACK:
		return false, s.state.ReceiveOpenACK(payload)
	case protocolv3.InnerOpenReject:
		return true, s.state.ReceiveOpenReject(payload)
	default:
		return false, ErrSessionProtocol
	}
}

func (s *encryptedStream) ID() uint64   { return s.id }
func (s *encryptedStream) Kind() string { return s.kind }

func (s *encryptedStream) Write(payload []byte) (int, error) {
	if len(payload) == 0 {
		return 0, nil
	}
	written := 0
	for len(payload) != 0 {
		batch := payload
		if len(batch) > maxCoalescedWriteBytes {
			batch = batch[:maxCoalescedWriteBytes]
		}
		if err := s.lockSendReady(); err != nil {
			return written, err
		}
		wire := make([]byte, 0, len(batch)+4*(protocolv3.RecordHeaderSize+protocolv3.InnerHeaderSize+protocolv3.AEADTagBytes))
		remaining := batch
		for len(remaining) != 0 {
			chunk := remaining
			if len(chunk) > protocolv3.MaxDataBytes {
				chunk = chunk[:protocolv3.MaxDataBytes]
			}
			s.stateMu.Lock()
			err := s.state.SendRecord(protocolv3.InnerData)
			s.stateMu.Unlock()
			if err != nil {
				s.sendMu.Unlock()
				return written, err
			}
			wire, err = s.appendRecordLocked(wire, protocolv3.InnerData, chunk)
			if err != nil {
				s.sendMu.Unlock()
				s.localReset(err)
				return written, err
			}
			remaining = remaining[len(chunk):]
		}
		if err := writeAll(s.carrier, wire); err != nil {
			s.sendMu.Unlock()
			s.localReset(err)
			return written, err
		}
		s.session.touchActivity()
		s.sendMu.Unlock()
		written += len(batch)
		payload = payload[len(batch):]
	}
	return written, nil
}

func (s *encryptedStream) Read(payload []byte) (int, error) {
	if len(payload) == 0 {
		return 0, nil
	}
	if err := s.acquireReadOwner(1); err != nil {
		return 0, err
	}
	defer s.releaseReadOwner(1)
	s.readMu.Lock()
	defer s.readMu.Unlock()
	for {
		if len(s.readBuf) != 0 {
			n := copy(payload, s.readBuf)
			s.readBuf = s.readBuf[n:]
			return n, nil
		}
		if s.remoteEOF {
			return 0, io.EOF
		}
		if err := s.TerminalError(); err != nil {
			return 0, err
		}
		if s.recvExhausted {
			s.localReset(protocolv3.ErrCounterExhausted)
			return 0, protocolv3.ErrStreamReset
		}
		if err := s.readNextRecordLocked(); err != nil {
			s.localReset(err)
			return 0, protocolv3.ErrStreamReset
		}
	}
}

func (s *encryptedStream) readNextRecordLocked() error {
	typ, data, header, err := s.session.readStreamRecordAny(s.carrier, s.id)
	if err != nil {
		return err
	}
	s.session.touchActivity()
	priorACK := s.recvPriorACK && header.Epoch == s.recvPriorEpoch && header.Sequence == s.recvPriorSeq
	if priorACK {
		if typ != protocolv3.InnerStreamKeyUpdateACK {
			return ErrSessionProtocol
		}
		s.recvPriorACK = false
		s.setReceiveRootEpoch(s.recvEpoch)
	} else {
		if header.Epoch != s.recvEpoch || header.Sequence != s.recvSeq {
			return ErrSessionProtocol
		}
		s.recvPriorACK = false
		if s.recvSeq == math.MaxUint64 {
			s.recvExhausted = true
		} else {
			s.recvSeq++
		}
	}
	if typ != protocolv3.InnerStreamKeyUpdateACK {
		s.stateMu.Lock()
		err = s.state.ReceiveRecord(typ)
		s.stateMu.Unlock()
		if err != nil {
			return err
		}
	}
	switch typ {
	case protocolv3.InnerData:
		s.readBuf = append(s.readBuf, data...)
	case protocolv3.InnerFIN:
		s.remoteEOF = true
		s.clearReceiveRootEpoch()
		s.releaseIfClean()
	case protocolv3.InnerStreamKeyUpdate:
		return s.receiveStreamKeyUpdateLocked(data)
	case protocolv3.InnerStreamKeyUpdateACK:
		return s.receiveStreamKeyUpdateACK(data)
	default:
		return ErrSessionProtocol
	}
	return nil
}

func (s *encryptedStream) acquireReadOwner(owner uint8) error {
	for {
		s.readOwnerMu.Lock()
		if s.readOwner == 0 {
			s.readOwner = owner
			s.notifyReadOwnerChangedLocked()
			s.readOwnerMu.Unlock()
			return nil
		}
		changed := s.readOwnerChanged
		s.readOwnerMu.Unlock()
		select {
		case <-changed:
		case <-s.session.ctx.Done():
			return s.session.sessionError()
		}
	}
}

func (s *encryptedStream) releaseReadOwner(owner uint8) {
	s.readOwnerMu.Lock()
	if s.readOwner == owner {
		s.readOwner = 0
		s.notifyReadOwnerChangedLocked()
	}
	s.readOwnerMu.Unlock()
}

func (s *encryptedStream) notifyReadOwnerChangedLocked() {
	close(s.readOwnerChanged)
	s.readOwnerChanged = make(chan struct{})
}

func (s *encryptedStream) awaitReceiveRekey(ctx context.Context, transition uint64, epoch uint32) error {
	for {
		done, pendingACK, err := s.receiveRekeyStatus(transition, epoch)
		if done || err != nil {
			return err
		}
		if pendingACK {
			s.recvUpdateMu.Lock()
			changed := s.recvUpdateChanged
			s.recvUpdateMu.Unlock()
			select {
			case <-changed:
			case <-ctx.Done():
				return ctx.Err()
			case <-s.session.ctx.Done():
				return s.session.sessionError()
			}
			continue
		}

		s.readOwnerMu.Lock()
		if s.readOwner == 0 {
			s.readOwner = 2
			s.notifyReadOwnerChangedLocked()
			s.readOwnerMu.Unlock()
			s.readMu.Lock()
			for {
				done, pendingACK, err = s.receiveRekeyStatus(transition, epoch)
				if done || err != nil {
					break
				}
				if pendingACK {
					break
				}
				if err = s.readNextRecordLocked(); err != nil {
					s.localReset(err)
					break
				}
			}
			s.readMu.Unlock()
			s.releaseReadOwner(2)
			if err != nil {
				return err
			}
			continue
		}
		ownerChanged := s.readOwnerChanged
		s.readOwnerMu.Unlock()
		s.recvUpdateMu.Lock()
		updateChanged := s.recvUpdateChanged
		s.recvUpdateMu.Unlock()
		select {
		case <-ownerChanged:
		case <-updateChanged:
		case <-ctx.Done():
			return ctx.Err()
		case <-s.session.ctx.Done():
			return s.session.sessionError()
		}
	}
}

func (s *encryptedStream) awaitSendRekeyACK(ctx context.Context, pending *pendingStreamRekey) error {
	for {
		select {
		case <-pending.done:
			return nil
		default:
		}

		s.readOwnerMu.Lock()
		if s.readOwner == 0 {
			s.readOwner = 3
			s.notifyReadOwnerChangedLocked()
			s.readOwnerMu.Unlock()
			s.readMu.Lock()
			var err error
			for {
				select {
				case <-pending.done:
					s.readMu.Unlock()
					s.releaseReadOwner(3)
					return nil
				default:
				}
				if err = s.readNextRecordLocked(); err != nil {
					s.localReset(err)
					break
				}
			}
			s.readMu.Unlock()
			s.releaseReadOwner(3)
			return err
		}
		ownerChanged := s.readOwnerChanged
		s.readOwnerMu.Unlock()
		select {
		case <-pending.done:
			return nil
		case <-ownerChanged:
		case <-ctx.Done():
			return ctx.Err()
		case <-s.session.ctx.Done():
			return s.session.sessionError()
		}
	}
}

func (s *encryptedStream) receiveRekeyStatus(transition uint64, epoch uint32) (bool, bool, error) {
	s.recvUpdateMu.Lock()
	receivedTransition := s.recvUpdateID
	receivedEpoch := s.recvUpdateEpoch
	acked := s.recvUpdateAcked
	s.recvUpdateMu.Unlock()
	if receivedTransition != 0 {
		if receivedTransition != transition || receivedEpoch != epoch {
			return false, false, ErrSessionProtocol
		}
		return acked, !acked, nil
	}
	if s.TerminalError() != nil {
		return true, false, nil
	}
	s.stateMu.Lock()
	remoteDone := s.state.RemoteHalfClosed()
	s.stateMu.Unlock()
	return remoteDone, false, nil
}

func (s *encryptedStream) validateReceiveRekeyCommit(transition uint64, epoch uint32) error {
	s.recvUpdateMu.Lock()
	defer s.recvUpdateMu.Unlock()
	if s.recvUpdateID == 0 {
		return nil
	}
	if s.recvUpdateID != transition || s.recvUpdateEpoch != epoch || !s.recvUpdateAcked {
		return ErrSessionProtocol
	}
	return nil
}

func (s *encryptedStream) publishReceiveRekey(transition uint64, epoch uint32) {
	s.recvUpdateMu.Lock()
	if s.recvUpdateID == transition && s.recvUpdateEpoch == epoch && s.recvUpdateAcked {
		s.recvUpdateID = 0
		s.recvUpdateEpoch = 0
		s.recvUpdateAcked = false
		close(s.recvUpdateChanged)
		s.recvUpdateChanged = make(chan struct{})
	}
	s.recvUpdateMu.Unlock()
}

func (s *encryptedStream) CloseWrite() error {
	if err := s.lockSendReady(); err != nil {
		return err
	}
	s.stateMu.Lock()
	err := s.state.SendRecord(protocolv3.InnerFIN)
	s.stateMu.Unlock()
	if err != nil {
		s.sendMu.Unlock()
		return err
	}
	if err := s.writeRecordLocked(protocolv3.InnerFIN, nil); err != nil {
		s.sendMu.Unlock()
		s.localReset(err)
		return err
	}
	s.sendMu.Unlock()
	s.clearSendRootEpoch()
	s.session.cleanupEpochRoots()
	if err := s.carrier.CloseWrite(); err != nil {
		s.localReset(err)
		return err
	}
	s.releaseIfClean()
	return nil
}

func (s *encryptedStream) lockSendReady() error {
	for {
		s.sendRekeyMu.Lock()
		pending := s.sendRekey
		s.sendRekeyMu.Unlock()
		if pending != nil {
			select {
			case <-pending.done:
			case <-s.session.ctx.Done():
				return s.session.sessionError()
			}
			continue
		}
		s.sendMu.Lock()
		s.sendRekeyMu.Lock()
		pending = s.sendRekey
		s.sendRekeyMu.Unlock()
		if pending == nil {
			return nil
		}
		s.sendMu.Unlock()
	}
}

func (s *encryptedStream) startSendRekey(transition uint64, epoch uint32) *pendingStreamRekey {
	if !s.canRekeySend() {
		return nil
	}
	pending := &pendingStreamRekey{
		transition: transition,
		epoch:      epoch,
		armed:      make(chan struct{}),
		done:       make(chan struct{}),
	}
	s.sendRekeyMu.Lock()
	if s.sendRekey != nil {
		s.sendRekeyMu.Unlock()
		pending.complete()
		s.session.fail(ErrSessionProtocol)
		return pending
	}
	// Publish the pending send transition before the writer goroutine runs. A
	// peer may initiate the same transition concurrently, and its old-epoch ACK
	// must remain readable even if its key-update record arrives first.
	s.sendRekey = pending
	s.sendRekeyMu.Unlock()
	go s.runSendRekey(pending)
	return pending
}

func (s *encryptedStream) canRekeySend() bool {
	if s.TerminalError() != nil {
		return false
	}
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	phase := s.state.State()
	return (phase == protocolv3.LogicalStreamActive || phase == protocolv3.LogicalStreamHalfClosed) && !s.state.LocalHalfClosed()
}

func (s *encryptedStream) runSendRekey(pending *pendingStreamRekey) {
	s.sendMu.Lock()
	if !s.canRekeySend() {
		s.sendRekeyMu.Lock()
		if s.sendRekey == pending {
			s.sendRekey = nil
		}
		s.sendRekeyMu.Unlock()
		s.sendMu.Unlock()
		close(pending.armed)
		pending.complete()
		return
	}
	s.sendRekeyMu.Lock()
	if s.sendRekey != pending {
		s.sendRekeyMu.Unlock()
		s.sendMu.Unlock()
		close(pending.armed)
		pending.complete()
		s.session.fail(ErrSessionProtocol)
		return
	}
	s.sendRekey = pending
	s.sendRekeyMu.Unlock()
	close(pending.armed)

	var payload [12]byte
	binary.BigEndian.PutUint64(payload[0:8], pending.transition)
	binary.BigEndian.PutUint32(payload[8:12], pending.epoch)
	s.stateMu.Lock()
	err := s.state.SendRecord(protocolv3.InnerStreamKeyUpdate)
	s.stateMu.Unlock()
	if err == nil {
		err = s.writeRecordLocked(protocolv3.InnerStreamKeyUpdate, payload[:])
	}
	s.sendMu.Unlock()
	if err != nil {
		s.sendRekeyMu.Lock()
		if s.sendRekey == pending {
			s.sendRekey = nil
		}
		s.sendRekeyMu.Unlock()
		pending.complete()
		s.session.fail(err)
	}
}

func (p *pendingStreamRekey) complete() {
	if p != nil {
		p.once.Do(func() { close(p.done) })
	}
}

func (s *encryptedStream) receiveStreamKeyUpdateLocked(payload []byte) error {
	if len(payload) != 12 || s.recvEpoch == math.MaxUint32 {
		return ErrSessionProtocol
	}
	transition := binary.BigEndian.Uint64(payload[0:8])
	nextEpoch := binary.BigEndian.Uint32(payload[8:12])
	if transition == 0 || nextEpoch != s.recvEpoch+1 {
		return ErrSessionProtocol
	}
	s.recvUpdateMu.Lock()
	if s.recvUpdateID != 0 {
		s.recvUpdateMu.Unlock()
		return ErrSessionProtocol
	}
	s.recvUpdateMu.Unlock()

	s.session.cryptoMu.RLock()
	currentRoots, ok := s.session.recvRoots[s.recvEpoch]
	s.session.cryptoMu.RUnlock()
	if !ok {
		return ErrSessionProtocol
	}
	nextSecret, err := protocolv3.DeriveNextEpoch(currentRoots.RekeyRoot, s.session.h3, s.session.recvDir, nextEpoch)
	if err != nil {
		return err
	}
	nextRoots, err := protocolv3.DeriveEpochRoots(nextSecret)
	if err != nil {
		return err
	}
	s.session.cryptoMu.Lock()
	if existing, exists := s.session.recvRoots[nextEpoch]; exists && existing != nextRoots {
		s.session.cryptoMu.Unlock()
		return ErrSessionProtocol
	}
	s.session.recvRoots[nextEpoch] = nextRoots
	s.session.cryptoMu.Unlock()

	s.recvPriorEpoch = s.recvEpoch
	s.recvPriorSeq = s.recvSeq
	s.sendRekeyMu.Lock()
	pendingSend := s.sendRekey
	s.recvPriorACK = pendingSend != nil && pendingSend.transition == transition && pendingSend.epoch == nextEpoch
	s.sendRekeyMu.Unlock()
	s.recvEpoch = nextEpoch
	if s.recvPriorACK {
		s.setReceiveRootEpoch(s.recvPriorEpoch)
	} else {
		s.setReceiveRootEpoch(s.recvEpoch)
	}
	s.recvSeq = 0
	s.recvExhausted = false
	s.recvUpdateMu.Lock()
	s.recvUpdateID = transition
	s.recvUpdateEpoch = nextEpoch
	s.recvUpdateAcked = false
	close(s.recvUpdateChanged)
	s.recvUpdateChanged = make(chan struct{})
	s.recvUpdateMu.Unlock()
	ack := marshalStreamKeyUpdateACK(s.id, transition, nextEpoch)
	go s.sendStreamKeyUpdateACK(transition, nextEpoch, ack)
	return nil
}

func (s *encryptedStream) sendStreamKeyUpdateACK(transition uint64, nextEpoch uint32, ack [20]byte) {
	s.sendMu.Lock()
	err := s.writeRecordLocked(protocolv3.InnerStreamKeyUpdateACK, ack[:])
	s.sendMu.Unlock()
	if err != nil {
		s.localReset(err)
		return
	}
	s.recvUpdateMu.Lock()
	if s.recvUpdateID != transition || s.recvUpdateEpoch != nextEpoch {
		s.recvUpdateMu.Unlock()
		s.localReset(ErrSessionProtocol)
		return
	}
	s.recvUpdateAcked = true
	close(s.recvUpdateChanged)
	s.recvUpdateChanged = make(chan struct{})
	s.recvUpdateMu.Unlock()
}

func (s *encryptedStream) receiveStreamKeyUpdateACK(payload []byte) error {
	logicalID, transition, epoch, err := parseStreamKeyUpdateACK(payload)
	if err != nil || logicalID != s.id {
		return ErrSessionProtocol
	}
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	s.sendRekeyMu.Lock()
	pending := s.sendRekey
	if pending == nil {
		duplicate := s.lastSendRekeyTransition == transition && s.lastSendRekeyEpoch == epoch
		s.sendRekeyMu.Unlock()
		if duplicate {
			return nil
		}
		return ErrSessionProtocol
	}
	if pending.transition != transition || pending.epoch != epoch {
		s.sendRekeyMu.Unlock()
		return ErrSessionProtocol
	}
	s.sendEpoch = epoch
	s.setSendRootEpoch(epoch)
	s.sendSeq = 0
	s.sendExhausted = false
	s.sendRekey = nil
	s.lastSendRekeyTransition = transition
	s.lastSendRekeyEpoch = epoch
	s.sendRekeyMu.Unlock()
	pending.complete()
	return nil
}

func marshalStreamKeyUpdateACK(logicalID, transition uint64, epoch uint32) [20]byte {
	var payload [20]byte
	binary.BigEndian.PutUint64(payload[0:8], logicalID)
	binary.BigEndian.PutUint64(payload[8:16], transition)
	binary.BigEndian.PutUint32(payload[16:20], epoch)
	return payload
}

func parseStreamKeyUpdateACK(payload []byte) (logicalID, transition uint64, epoch uint32, err error) {
	if len(payload) != 20 {
		return 0, 0, 0, ErrSessionProtocol
	}
	return binary.BigEndian.Uint64(payload[0:8]), binary.BigEndian.Uint64(payload[8:16]), binary.BigEndian.Uint32(payload[16:20]), nil
}

func (s *encryptedStream) Reset() error {
	s.localReset(protocolv3.ErrStreamReset)
	return nil
}

func (s *encryptedStream) Close() error { return s.Reset() }

func (s *encryptedStream) TerminalError() error {
	s.terminalMu.RLock()
	err := s.terminalErr
	s.terminalMu.RUnlock()
	return err
}

func (s *encryptedStream) writeRecord(typ protocolv3.InnerType, payload []byte) error {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	return s.writeRecordLocked(typ, payload)
}

func (s *encryptedStream) writeRecordLocked(typ protocolv3.InnerType, payload []byte) error {
	raw, err := s.appendRecordLocked(nil, typ, payload)
	if err != nil {
		return err
	}
	if err := writeAll(s.carrier, raw); err != nil {
		return err
	}
	s.session.touchActivity()
	return nil
}

func (s *encryptedStream) appendRecordLocked(destination []byte, typ protocolv3.InnerType, payload []byte) ([]byte, error) {
	inner, err := protocolv3.MarshalInnerRecord(typ, payload)
	if err != nil {
		return nil, err
	}
	if s.sendExhausted {
		return nil, protocolv3.ErrCounterExhausted
	}
	s.session.cryptoMu.RLock()
	roots, ok := s.session.sendRoots[s.sendEpoch]
	s.session.cryptoMu.RUnlock()
	if !ok {
		return nil, ErrSessionProtocol
	}
	material, err := protocolv3.DeriveStreamMaterial(roots.StreamRoot, s.session.h3, s.id, s.session.sendDir, s.sendEpoch)
	if err != nil {
		return nil, err
	}
	header := protocolv3.RecordHeader{
		Epoch: s.sendEpoch, Sequence: s.sendSeq,
		CiphertextLength: uint32(len(inner) + protocolv3.AEADTagBytes),
	}
	ciphertext, err := protocolv3.SealRecord(s.session.config.Suite, material.RecordKey, material.NoncePrefix, s.session.h3, s.id, s.session.sendDir, header, inner)
	if err != nil {
		return nil, err
	}
	rawHeader, err := header.MarshalBinary()
	if err != nil {
		return nil, err
	}
	if s.sendSeq == math.MaxUint64 {
		s.sendExhausted = true
	} else {
		s.sendSeq++
	}
	destination = append(destination, rawHeader...)
	destination = append(destination, ciphertext...)
	return destination, nil
}

func (s *encryptedStream) localReset(cause error) {
	s.terminalMu.Lock()
	if s.terminalErr != nil {
		s.terminalMu.Unlock()
		return
	}
	s.terminalErr = cause
	s.terminalMu.Unlock()
	s.stateMu.Lock()
	confirmControl := s.state.RemoteHalfClosed()
	s.state.Reset()
	s.stateMu.Unlock()
	controlErr := s.session.commitControl(protocolv3.InnerStreamReset, marshalIDReason(s.id, 6), func() error {
		if !validLocalLogicalID(s.session.role, s.id) {
			return nil
		}
		s.session.ledgerMu.Lock()
		defer s.session.ledgerMu.Unlock()
		err := s.session.outboundLedger.LocalResetCommitted(s.id)
		s.session.notifyLedgerChangedLocked()
		return err
	})
	var confirmationTarget uint64
	if controlErr == nil && confirmControl {
		confirmationTarget = s.session.registerResetConfirmation()
	}
	s.completeSendRekeyTerminal()
	cleanup := func() {
		if confirmationTarget != 0 {
			confirmErr := s.session.confirmResetDelivery(confirmationTarget)
			if confirmErr != nil && s.session.ctx.Err() == nil {
				s.session.fail(fmt.Errorf("%w: reset control confirmation: %v", ErrSessionProtocol, confirmErr))
			}
		}
		_ = s.carrier.Reset()
		s.clearRootEpochs()
		s.finish(cause, false)
		s.session.cleanupEpochRoots()
	}
	if !s.session.startOwnedWorker(cleanup) {
		s.clearRootEpochs()
		s.finish(cause, false)
		s.session.cleanupEpochRoots()
	}
	if controlErr != nil {
		s.session.fail(controlErr)
	}
}

func (s *engineSession) commitOutboundReset(id uint64) error {
	return s.commitControl(protocolv3.InnerStreamReset, marshalIDReason(id, 6), func() error {
		s.ledgerMu.Lock()
		defer s.ledgerMu.Unlock()
		err := s.outboundLedger.LocalResetCommitted(id)
		s.notifyLedgerChangedLocked()
		return err
	})
}

func (s *engineSession) resolveOutboundOpen(id uint64) error {
	s.ledgerMu.Lock()
	defer s.ledgerMu.Unlock()
	err := s.outboundLedger.ValidOpen(id)
	s.notifyLedgerChangedLocked()
	return err
}

func (s *encryptedStream) peerReset(cause error) {
	s.terminalMu.Lock()
	if s.terminalErr != nil {
		s.terminalMu.Unlock()
		return
	}
	s.terminalErr = cause
	s.terminalMu.Unlock()
	s.stateMu.Lock()
	s.state.Reset()
	s.stateMu.Unlock()
	_ = s.carrier.Reset()
	s.completeSendRekeyTerminal()
	s.clearRootEpochs()
	s.finish(cause, false)
	s.session.cleanupEpochRoots()
}

func (s *encryptedStream) completeSendRekeyTerminal() {
	s.sendRekeyMu.Lock()
	pending := s.sendRekey
	s.sendRekey = nil
	s.sendRekeyMu.Unlock()
	pending.complete()
}

func (s *encryptedStream) finish(cause error, closeCarrier bool) {
	if closeCarrier {
		_ = s.carrier.Close()
	}
	s.releaseOnce.Do(func() {
		if s.release != nil {
			s.release()
		}
	})
}

func (s *encryptedStream) releaseIfClean() {
	s.stateMu.Lock()
	clean := s.state.CleanClosed()
	s.stateMu.Unlock()
	if clean {
		s.finish(nil, false)
	}
}

func (s *encryptedStream) setSendRootEpoch(epoch uint32) {
	s.sendRootNeed.Store(uint64(epoch) + 1)
}

func (s *encryptedStream) clearSendRootEpoch() {
	s.sendRootNeed.Store(0)
}

func (s *encryptedStream) minimumSendRootEpoch() (uint32, bool) {
	encoded := s.sendRootNeed.Load()
	if encoded == 0 {
		return 0, false
	}
	return uint32(encoded - 1), true
}

func (s *encryptedStream) setReceiveRootEpoch(epoch uint32) {
	s.recvRootNeed.Store(uint64(epoch) + 1)
}

func (s *encryptedStream) clearReceiveRootEpoch() {
	s.recvRootNeed.Store(0)
}

func (s *encryptedStream) minimumReceiveRootEpoch() (uint32, bool) {
	encoded := s.recvRootNeed.Load()
	if encoded == 0 {
		return 0, false
	}
	return uint32(encoded - 1), true
}

func (s *encryptedStream) clearRootEpochs() {
	s.clearSendRootEpoch()
	s.clearReceiveRootEpoch()
}

var _ ByteStream = (*encryptedStream)(nil)

func (s *encryptedStream) String() string {
	return fmt.Sprintf("flowersec-v3-stream(%d,%s)", s.id, s.kind)
}

func encodeUint64(value uint64) []byte {
	var out [8]byte
	binary.BigEndian.PutUint64(out[:], value)
	return out[:]
}
