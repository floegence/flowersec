package sessionv4

import "github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"

// Recent proof storage is already charged by the original finite admission
// table. It must not pin a complete send queue or a reusable service floor
// until RETIRE_ACK. Real owners, publishers, barriers and provider tails still
// prevent detachment; compaction neither retires the ID nor frees its proof.
func (a *OpenAdmission) compactRecentFlow(s *openSlot) {
	if s.phase != openRecent && s.phase != openHeld || !s.accepted || s.flow == nil || !s.coreCleaned ||
		s.owner != nil || s.cleanupBusy || s.terminalPublishing || s.retirementReferences != 0 || s.barrierReferences != 0 {
		return
	}
	f := s.flow
	shared := s.carrier != nil && s.carrier.shared != nil && s.carrier.shared == a.sharedIngress && f.nativeReceive == nil
	if !s.carrierDone && !shared {
		return // Native closure is reported only by its actual provider owner.
	}
	f.receive.pool.mu.Lock()
	receiveClean := f.receive.cleaned
	f.receive.pool.mu.Unlock()
	if !receiveClean {
		return
	}
	if f.nativeReceive != nil && f.nativeReceive.retire() != nil {
		return
	}
	f.send.mu.Lock()
	ack, limit := f.send.ack, f.send.limit
	f.send.mu.Unlock()
	if err := f.send.retire(); err != nil {
		return
	}
	// A shared-carrier association has no separate per-Stream native object.
	// Both authenticated terminal directions, actual flow cleanup and the last
	// callback/queue/provider tail above close that original logical association.
	// Waiting for an external native close would permanently occupy its floor.
	s.carrierDone = true
	if s.activeCharged {
		a.active--
		a.byOpener[(s.scope+1)%2][s.class]--
		s.activeCharged = false
		a.notifyDecisionOpportunityLocked()
	}
	s.recentAck, s.recentLimit = ack, limit
	s.flow = nil
}

func (s *openSlot) compactRecent() bool {
	return s.phase == openRecent && s.accepted && s.coreCleaned && s.flow == nil
}

// Only authenticated scope-zero maintenance reaches this exact original
// scope. Duplicate terminal claims must match its immutable evidence; credit
// can add monotonic knowledge but cannot restore a key, window or Stream.
func (a *OpenAdmission) applyCompactRecent(s *openSlot, f *protocolv4.Frame) error {
	direction, ok := f.Field("direction").Uint()
	if !ok {
		return ErrStreamData
	}
	switch f.Schema {
	case "STREAM_ACK_CREDIT":
		if direction != uint64(a.direction) {
			return ErrStreamData
		}
		ack, yes := f.Field("ack_offset").Uint()
		limit, valid := f.Field("receive_limit").Uint()
		if !yes || !valid || ack < s.recentAck || ack > s.terminal[a.direction].Terminal.Offset || limit < s.recentLimit || limit < ack {
			return ErrCredit
		}
		s.recentAck, s.recentLimit = ack, limit
	case "STREAM_ACK_STOP":
		if direction != uint64(a.direction) {
			return ErrStreamData
		}
		s.stoppedDirty = true
	case "STREAM_ACK_STOPPED":
		if direction != uint64(1-a.direction) {
			return ErrStreamData
		}
		epoch, e := f.Field("final_epoch").Uint()
		sequence, q := f.Field("final_next_sequence").Uint()
		offset, o := f.Field("final_offset").Uint()
		if !e || !q || !o || epoch > uint64(^uint32(0)) || (TerminalTuple{Epoch: uint32(epoch), NextSequence: sequence, Offset: offset}) != s.terminal[1-a.direction].Terminal {
			return ErrTerminal
		}
	case "STREAM_ACK_DRAINED":
		if direction != uint64(a.direction) {
			return ErrStreamData
		}
		terminal, err := tupleValue(f.Field("terminal_tuple"))
		if err != nil {
			return err
		}
		observed, err := tupleValue(f.Field("observed_tuple"))
		if err != nil {
			return err
		}
		outcome, yes := f.Field("outcome").Uint()
		aborted, err := protocolv4.EnumValue(f.Schema, "outcome", "aborted")
		if err != nil || !yes || (DrainProof{Terminal: terminal, Observed: observed, Aborted: outcome == aborted}) != s.terminal[a.direction] {
			return ErrTerminal
		}
	default:
		return ErrStreamData
	}
	if a.termination != nil {
		a.termination.notify()
	}
	return nil
}
