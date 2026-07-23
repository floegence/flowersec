package protocolv2

import (
	"errors"
	"fmt"
)

var (
	ErrStreamProtocol      = errors.New("logical stream protocol violation")
	ErrOpenNotAcknowledged = errors.New("logical stream OPEN is not acknowledged")
	ErrWriteAfterFIN       = errors.New("logical stream write after FIN")
	ErrOpenRejected        = errors.New("logical stream OPEN rejected")
	ErrStreamReset         = errors.New("logical stream reset")
	ErrStreamTruncated     = errors.New("logical stream carrier EOF without encrypted FIN")
	ErrStreamClosed        = errors.New("logical stream closed")
)

type LogicalStreamPhase uint8

const (
	LogicalStreamOpening LogicalStreamPhase = iota + 1
	LogicalStreamActive
	LogicalStreamRejected
	LogicalStreamHalfClosed
	LogicalStreamCleanClosed
	LogicalStreamResetTerminal
)

type LogicalStreamState struct {
	logicalID     uint64
	fss2Hash      [32]byte
	localOpener   bool
	ledger        *StreamLedger
	openSeen      bool
	openHash      [32]byte
	localFirst    bool
	remoteFirst   bool
	acknowledged  bool
	rejected      bool
	localFIN      bool
	remoteFIN     bool
	terminalSet   bool
	terminalError error
}

func NewOutboundLogicalStreamState(logicalID uint64, fss2Hash [32]byte) (*LogicalStreamState, error) {
	if logicalID == 0 {
		return nil, ErrInvalidOpenPayload
	}
	return &LogicalStreamState{logicalID: logicalID, fss2Hash: fss2Hash, localOpener: true}, nil
}

func NewInboundLogicalStreamState(ledger *StreamLedger, logicalID uint64, fss2Hash [32]byte) (*LogicalStreamState, error) {
	if ledger == nil || logicalID == 0 || ledger.State(logicalID) != LedgerOpenSeen {
		return nil, ErrInvalidLedgerState
	}
	return &LogicalStreamState{logicalID: logicalID, fss2Hash: fss2Hash, ledger: ledger}, nil
}

func (s *LogicalStreamState) SendOpen(raw []byte) error {
	if err := s.localOperationAllowed(); err != nil {
		return err
	}
	if !s.localOpener || s.openSeen || s.localFirst {
		return s.failProtocol("OPEN is not the first opener record")
	}
	open, err := ParseOpenPayload(raw)
	if err != nil || open.LogicalStreamID != s.logicalID || open.FSS2Hash != s.fss2Hash {
		return ErrInvalidOpenPayload
	}
	hash, err := ComputeOpenHash(raw)
	if err != nil {
		return err
	}
	s.openSeen = true
	s.openHash = hash
	s.localFirst = true
	return nil
}

func (s *LogicalStreamState) ReceiveOpen(raw []byte) error {
	if err := s.peerOperationAllowed(); err != nil {
		return err
	}
	if s.localOpener || s.openSeen || s.remoteFirst {
		return s.failProtocol("duplicate or misplaced OPEN")
	}
	open, err := ParseOpenPayload(raw)
	if err != nil || open.LogicalStreamID != s.logicalID || open.FSS2Hash != s.fss2Hash {
		return s.failProtocol("invalid OPEN payload")
	}
	hash, err := ComputeOpenHash(raw)
	if err != nil {
		return s.failProtocol("invalid OPEN hash preimage")
	}
	if err := s.ledger.ValidOpen(s.logicalID); err != nil {
		return err
	}
	s.openSeen = true
	s.openHash = hash
	s.remoteFirst = true
	return nil
}

func (s *LogicalStreamState) SendOpenACK(raw []byte) error {
	if err := s.localOperationAllowed(); err != nil {
		return err
	}
	if s.localOpener || !s.openSeen || s.localFirst {
		return s.failProtocol("misplaced OPEN_ACK")
	}
	hash, err := ParseOpenACK(raw)
	if err != nil || openHashMismatch(hash, s.openHash) != nil {
		return s.failProtocol("OPEN_ACK hash mismatch")
	}
	s.localFirst = true
	s.acknowledged = true
	return nil
}

func (s *LogicalStreamState) ReceiveOpenACK(raw []byte) error {
	if err := s.peerOperationAllowed(); err != nil {
		return err
	}
	if !s.localOpener || !s.openSeen || s.remoteFirst {
		return s.failProtocol("misplaced OPEN_ACK")
	}
	hash, err := ParseOpenACK(raw)
	if err != nil || openHashMismatch(hash, s.openHash) != nil {
		return s.failProtocol("OPEN_ACK hash mismatch")
	}
	s.remoteFirst = true
	s.acknowledged = true
	return nil
}

func (s *LogicalStreamState) SendOpenReject(raw []byte) error {
	if err := s.localOperationAllowed(); err != nil {
		return err
	}
	if s.localOpener || !s.openSeen || s.localFirst {
		return s.failProtocol("misplaced OPEN_REJECT")
	}
	reject, err := ParseOpenReject(raw)
	if err != nil || openHashMismatch(reject.OpenHash, s.openHash) != nil {
		return s.failProtocol("OPEN_REJECT hash mismatch")
	}
	s.localFirst = true
	s.rejected = true
	return nil
}

func (s *LogicalStreamState) ReceiveOpenReject(raw []byte) error {
	if err := s.peerOperationAllowed(); err != nil {
		return err
	}
	if !s.localOpener || !s.openSeen || s.remoteFirst {
		return s.failProtocol("misplaced OPEN_REJECT")
	}
	reject, err := ParseOpenReject(raw)
	if err != nil || openHashMismatch(reject.OpenHash, s.openHash) != nil {
		return s.failProtocol("OPEN_REJECT hash mismatch")
	}
	s.remoteFirst = true
	s.rejected = true
	return nil
}

func (s *LogicalStreamState) SendRecord(typ InnerType) error {
	if err := s.localOperationAllowed(); err != nil {
		return err
	}
	switch typ {
	case InnerData, InnerStreamKeyUpdate:
		if s.localFIN {
			return ErrWriteAfterFIN
		}
		if s.rejected {
			return ErrOpenRejected
		}
		if !s.acknowledged {
			return ErrOpenNotAcknowledged
		}
		return nil
	case InnerFIN:
		if s.localFIN {
			return ErrWriteAfterFIN
		}
		if !s.acknowledged && !(s.rejected && !s.localOpener) {
			return ErrOpenNotAcknowledged
		}
		s.localFIN = true
		s.finishIfBothFIN()
		return nil
	case InnerOpen, InnerOpenACK, InnerOpenReject:
		return s.failProtocol("OPEN family requires exact payload validation")
	default:
		return s.failProtocol("invalid data-stream inner type")
	}
}

func (s *LogicalStreamState) ReceiveRecord(typ InnerType) error {
	if err := s.peerOperationAllowed(); err != nil {
		return err
	}
	switch typ {
	case InnerData, InnerStreamKeyUpdate:
		if !s.acknowledged || s.rejected {
			return s.failProtocol("peer data before OPEN_ACK or after OPEN_REJECT")
		}
		if s.remoteFIN {
			return s.failProtocol("peer record after FIN")
		}
		return nil
	case InnerFIN:
		if s.remoteFIN {
			return s.failProtocol("duplicate FIN")
		}
		if !s.acknowledged && !(s.rejected && s.localOpener) {
			return s.failProtocol("FIN before OPEN response")
		}
		s.remoteFIN = true
		s.finishIfBothFIN()
		return nil
	case InnerOpen:
		return s.failProtocol("duplicate or unvalidated OPEN")
	case InnerOpenACK, InnerOpenReject:
		return s.failProtocol("OPEN response requires exact payload validation")
	default:
		return s.failProtocol("invalid data-stream inner type")
	}
}

func (s *LogicalStreamState) Reset() bool {
	if s == nil || s.terminalSet {
		return false
	}
	s.terminalSet = true
	s.terminalError = ErrStreamReset
	return true
}

func (s *LogicalStreamState) CarrierReset() bool {
	return s.Reset()
}

func (s *LogicalStreamState) CarrierEOF() error {
	if s == nil {
		return ErrStreamClosed
	}
	if s.terminalSet {
		return s.terminalError
	}
	if s.remoteFIN {
		return nil
	}
	s.terminalSet = true
	s.terminalError = ErrStreamTruncated
	return ErrStreamTruncated
}

func (s *LogicalStreamState) State() LogicalStreamPhase {
	if s == nil {
		return LogicalStreamResetTerminal
	}
	if s.terminalSet {
		if s.terminalError == nil {
			return LogicalStreamCleanClosed
		}
		return LogicalStreamResetTerminal
	}
	if s.rejected {
		return LogicalStreamRejected
	}
	if s.localFIN || s.remoteFIN {
		return LogicalStreamHalfClosed
	}
	if s.acknowledged {
		return LogicalStreamActive
	}
	return LogicalStreamOpening
}

func (s *LogicalStreamState) LocalHalfClosed() bool {
	return s != nil && s.localFIN
}

func (s *LogicalStreamState) RemoteHalfClosed() bool {
	return s != nil && s.remoteFIN
}

func (s *LogicalStreamState) CleanClosed() bool {
	return s != nil && s.terminalSet && s.terminalError == nil
}

func (s *LogicalStreamState) OpenRejected() bool {
	return s != nil && s.rejected
}

func (s *LogicalStreamState) TerminalError() error {
	if s == nil {
		return ErrStreamClosed
	}
	return s.terminalError
}

func (s *LogicalStreamState) finishIfBothFIN() {
	if s.localFIN && s.remoteFIN && !s.terminalSet {
		s.terminalSet = true
		s.terminalError = nil
	}
}

func (s *LogicalStreamState) localOperationAllowed() error {
	if s == nil || s.terminalSet {
		if s != nil && s.terminalError != nil {
			return s.terminalError
		}
		return ErrStreamClosed
	}
	return nil
}

func (s *LogicalStreamState) peerOperationAllowed() error {
	return s.localOperationAllowed()
}

func (s *LogicalStreamState) failProtocol(detail string) error {
	if s != nil && !s.terminalSet {
		s.terminalSet = true
		s.terminalError = ErrStreamReset
	}
	return fmt.Errorf("%w: %s", ErrStreamProtocol, detail)
}
