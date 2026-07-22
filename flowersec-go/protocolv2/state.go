package protocolv2

import (
	"encoding/binary"
	"errors"
	"math"
)

var (
	ErrControlSequence    = errors.New("invalid control sequence")
	ErrLateControlEpoch   = errors.New("late control epoch")
	ErrFutureControlEpoch = errors.New("future control epoch")
	ErrControlUpdateState = errors.New("invalid control update state")
	ErrDuplicateStreamID  = errors.New("duplicate logical stream id")
	ErrInvalidLedgerState = errors.New("invalid stream ledger state")
	ErrLedgerCapacity     = errors.New("stream ledger capacity exceeded")
	ErrControlQueueFull   = errors.New("critical control queue full")
	ErrCounterExhausted   = errors.New("counter exhausted")
)

const (
	// MaxStreamLedgerSlots is the per-opener-role lifetime cap.
	MaxStreamLedgerSlots  uint64 = 1_048_576
	streamLedgerByteCount        = MaxStreamLedgerSlots / 4
)

type ControlReceiveState struct {
	sessionEpoch uint32
	controlEpoch uint32
	expectedSeq  uint64
	exhausted    bool
	pending      bool
	pendingEpoch uint32
}

func NewControlReceiveState(epoch uint32, expectedSequence uint64) *ControlReceiveState {
	return &ControlReceiveState{
		sessionEpoch: epoch,
		controlEpoch: epoch,
		expectedSeq:  expectedSequence,
	}
}

func (s *ControlReceiveState) SessionEpoch() uint32     { return s.sessionEpoch }
func (s *ControlReceiveState) ControlEpoch() uint32     { return s.controlEpoch }
func (s *ControlReceiveState) ExpectedSequence() uint64 { return s.expectedSeq }

func (s *ControlReceiveState) CommitSessionUpdate(nextEpoch uint32) error {
	if s == nil || s.pending || s.sessionEpoch == math.MaxUint32 || nextEpoch != s.sessionEpoch+1 {
		return ErrControlUpdateState
	}
	s.sessionEpoch = nextEpoch
	s.pendingEpoch = nextEpoch
	s.pending = true
	return nil
}

// Accept validates one record from the reliable ordered control direction. It
// reports true exactly when epoch+1, sequence zero performs the key cutover.
func (s *ControlReceiveState) Accept(epoch uint32, sequence uint64) (bool, error) {
	if s == nil {
		return false, ErrControlUpdateState
	}
	if epoch == s.controlEpoch {
		if s.exhausted {
			return false, ErrCounterExhausted
		}
		if sequence != s.expectedSeq {
			return false, ErrControlSequence
		}
		if s.expectedSeq == math.MaxUint64 {
			s.exhausted = true
			return false, nil
		}
		s.expectedSeq++
		return false, nil
	}
	if epoch < s.controlEpoch {
		return false, ErrLateControlEpoch
	}
	if s.pending && epoch == s.pendingEpoch {
		if sequence != 0 {
			return false, ErrControlSequence
		}
		s.controlEpoch = epoch
		s.expectedSeq = 1
		s.exhausted = false
		s.pending = false
		return true, nil
	}
	return false, ErrFutureControlEpoch
}

type LedgerState uint8

const (
	LedgerUnseen LedgerState = iota
	LedgerAbandonedNoFSS2
	LedgerOpenSeen
	LedgerUsedOrTerminal
)

type LateSetupAction uint8

const (
	LateSetupReset LateSetupAction = 1
)

type StreamLedger struct {
	role     Role
	maxSlots uint64
	states   []byte
	frontier uint64
}

func NewStreamLedger(role Role, maxSlots uint64) *StreamLedger {
	if maxSlots > MaxStreamLedgerSlots {
		maxSlots = MaxStreamLedgerSlots
	}
	return &StreamLedger{
		role:     role,
		maxSlots: maxSlots,
		states:   make([]byte, (maxSlots+3)/4),
	}
}

func (l *StreamLedger) State(id uint64) LedgerState {
	if l == nil {
		return LedgerUnseen
	}
	index, ok := l.slotIndex(id)
	if !ok {
		return LedgerUnseen
	}
	return l.stateAt(index)
}

func (l *StreamLedger) Frontier() uint64 {
	if l == nil {
		return 0
	}
	return l.frontier
}

func (l *StreamLedger) PeerReset(id uint64) error {
	if err := l.validateID(id); err != nil {
		return err
	}
	switch l.State(id) {
	case LedgerUnseen:
		l.setState(id, LedgerAbandonedNoFSS2)
	case LedgerAbandonedNoFSS2, LedgerUsedOrTerminal:
		// Repeated authenticated reset is idempotent.
	case LedgerOpenSeen:
		l.setState(id, LedgerUsedOrTerminal)
	default:
		return ErrInvalidLedgerState
	}
	l.advanceFrontier()
	return nil
}

func (l *StreamLedger) ValidFSS2(id uint64) error {
	if err := l.validateID(id); err != nil {
		return err
	}
	if l.State(id) != LedgerUnseen {
		return ErrDuplicateStreamID
	}
	l.setState(id, LedgerOpenSeen)
	return nil
}

func (l *StreamLedger) ValidFSS2ForAbandoned(id uint64) (LateSetupAction, error) {
	if err := l.validateID(id); err != nil {
		return 0, err
	}
	state := l.State(id)
	if state != LedgerAbandonedNoFSS2 {
		if state == LedgerOpenSeen || state == LedgerUsedOrTerminal {
			return 0, ErrDuplicateStreamID
		}
		return 0, ErrInvalidLedgerState
	}
	l.setState(id, LedgerUsedOrTerminal)
	l.advanceFrontier()
	return LateSetupReset, nil
}

func (l *StreamLedger) ValidOpen(id uint64) error {
	if err := l.validateID(id); err != nil {
		return err
	}
	if l.State(id) != LedgerOpenSeen {
		return ErrInvalidLedgerState
	}
	l.setState(id, LedgerUsedOrTerminal)
	l.advanceFrontier()
	return nil
}

// LocalTerminalBeforeOpen intentionally leaves OPEN_SEEN unresolved. A local
// ordered reset must commit before the frontier can advance.
func (l *StreamLedger) LocalTerminalBeforeOpen(id uint64) {
	if l == nil || l.State(id) != LedgerOpenSeen {
		return
	}
}

func (l *StreamLedger) LocalResetCommitted(id uint64) error {
	if err := l.validateID(id); err != nil {
		return err
	}
	switch l.State(id) {
	case LedgerOpenSeen:
		l.setState(id, LedgerUsedOrTerminal)
	case LedgerUsedOrTerminal:
		return nil
	default:
		return ErrInvalidLedgerState
	}
	l.advanceFrontier()
	return nil
}

func (l *StreamLedger) validateID(id uint64) error {
	if _, ok := l.slotIndex(id); !ok {
		return ErrLedgerCapacity
	}
	return nil
}

func (l *StreamLedger) slotIndex(id uint64) (uint64, bool) {
	if l == nil || l.maxSlots == 0 || !validLogicalID(l.role, id) {
		return 0, false
	}
	var ordinal uint64
	if l.role == RoleClient {
		ordinal = id/2 + 1
	} else {
		ordinal = id / 2
	}
	if ordinal == 0 || ordinal > l.maxSlots {
		return 0, false
	}
	return ordinal - 1, true
}

func (l *StreamLedger) stateAt(index uint64) LedgerState {
	shift := (index % 4) * 2
	return LedgerState((l.states[index/4] >> shift) & 0x03)
}

func (l *StreamLedger) setState(id uint64, state LedgerState) {
	index, ok := l.slotIndex(id)
	if !ok {
		return
	}
	shift := (index % 4) * 2
	mask := byte(0x03 << shift)
	l.states[index/4] = (l.states[index/4] &^ mask) | byte(state<<shift)
}

func (l *StreamLedger) advanceFrontier() {
	next := l.frontier + 2
	if l.frontier == 0 && l.role == RoleClient {
		next = 1
	}
	for {
		index, ok := l.slotIndex(next)
		if !ok {
			return
		}
		state := l.stateAt(index)
		if state != LedgerAbandonedNoFSS2 && state != LedgerUsedOrTerminal {
			return
		}
		l.frontier = next
		if next > math.MaxUint64-2 {
			return
		}
		next += 2
	}
}

// MaxLogicalStreamID returns the final permitted logical ID for an opener role.
func MaxLogicalStreamID(role Role) uint64 {
	switch role {
	case RoleClient:
		return MaxStreamLedgerSlots*2 - 1
	case RoleServer:
		return MaxStreamLedgerSlots * 2
	default:
		return 0
	}
}

type ControlRecord struct {
	Type      InnerType
	Header    RecordHeader
	Plaintext []byte
}

type ControlActor struct {
	epoch     uint32
	nextSeq   uint64
	exhausted bool
	capacity  int
	queue     []ControlRecord
}

func NewControlActor(epoch uint32, nextSequence uint64, maxInboundStreams int) *ControlActor {
	capacity := 2*maxInboundStreams + 8
	if capacity < 8 {
		capacity = 8
	}
	return &ControlActor{epoch: epoch, nextSeq: nextSequence, capacity: capacity}
}

func (a *ControlActor) CommitStreamReset(logicalStreamID uint64) error {
	payload := make([]byte, 10)
	binary.BigEndian.PutUint64(payload[0:8], logicalStreamID)
	binary.BigEndian.PutUint16(payload[8:10], 6)
	return a.commit(InnerStreamReset, payload)
}

func (a *ControlActor) CommitSessionUpdate(transitionID uint64, nextEpoch uint32, watermark uint64) error {
	payload := make([]byte, 20)
	binary.BigEndian.PutUint64(payload[0:8], transitionID)
	binary.BigEndian.PutUint32(payload[8:12], nextEpoch)
	binary.BigEndian.PutUint64(payload[12:20], watermark)
	return a.commit(InnerSessionKeyUpdate, payload)
}

func (a *ControlActor) commit(typ InnerType, payload []byte) error {
	if a == nil || len(a.queue) >= a.capacity {
		return ErrControlQueueFull
	}
	if a.exhausted {
		return ErrCounterExhausted
	}
	inner, err := MarshalInnerRecord(typ, payload)
	if err != nil {
		return err
	}
	record := ControlRecord{
		Type: typ,
		Header: RecordHeader{
			Epoch:            a.epoch,
			Sequence:         a.nextSeq,
			CiphertextLength: uint32(len(inner) + AEADTagBytes),
		},
		Plaintext: inner,
	}
	if a.nextSeq == math.MaxUint64 {
		a.exhausted = true
	} else {
		a.nextSeq++
	}
	a.queue = append(a.queue, record)
	return nil
}

func (a *ControlActor) Pop() (ControlRecord, bool) {
	if a == nil || len(a.queue) == 0 {
		return ControlRecord{}, false
	}
	record := a.queue[0]
	copy(a.queue, a.queue[1:])
	a.queue = a.queue[:len(a.queue)-1]
	return record, true
}
