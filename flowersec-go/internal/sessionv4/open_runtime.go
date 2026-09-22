package sessionv4

import (
	"bytes"
	"context"
	"errors"
	"io"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

// StreamReservation transfers actual storage, receive promise capacity and the
// original carrier writer to one OPEN owner. Admission of their physical cost
// belongs to the Session reservation; successful construction is not provider
// qualification. OpenStorage covers the initiator's immutable OPEN snapshot.
type StreamReservation struct {
	Pool                *ReceivePool
	ReceiveProtection   *ReceiveProtection
	OpenStorage         []byte
	SendCapacity        uint64
	SendReservation     resourcev4.Reference
	ReceiveCapacity     uint64
	Writer              io.Writer
	MaxPlaintext        int
	InitialReceiveLimit uint64
	SendQueue           *SendQueueReservation
	// NativeReceive reserves H_DATA and the native reader before publishing
	// OPEN/accepted. Shared carriers retain their separate ingress ownership.
	NativeReceive resourcev4.Reference
}

// SendQueueReservation is part of the original complete Stream admission,
// not a queue allocated after accepted has already been published.
type SendQueueReservation struct {
	Capacity    uint64
	Waiters     uint32
	Chunk       int
	Reservation resourcev4.Reference
}

func (a *OpenAdmission) newFlow(scope, peerLimit uint64, class StreamClass, reservation StreamReservation) (*StreamFlow, error) {
	if a.receivePool != nil && reservation.Pool != a.receivePool {
		return nil, cryptov4.ErrConfiguration
	}
	if a.termination != nil {
		if reservation.Pool == nil {
			return nil, cryptov4.ErrConfiguration
		}
		if err := a.termination.reservation.CheckSameEnvironment(reservation.Pool.reservation); err != nil {
			return nil, err
		}
	}
	if a.sendService != nil && reservation.SendQueue == nil {
		return nil, cryptov4.ErrConfiguration
	}
	if a.nativeAuth != nil && reservation.NativeReceive == (resourcev4.Reference{}) {
		return nil, cryptov4.ErrConfiguration
	}
	rx, err := a.engine.ScopeFrontier(scope, 1-a.direction)
	if err == cryptov4.ErrNotReady {
		if spec, enabled := a.engine.BootstrapSpec(); enabled && scope == spec.Scope {
			rx, err = a.engine.BootstrapFrontier(1 - a.direction)
		}
	}
	if err != nil {
		return nil, err
	}
	tx, err := a.engine.ScopeFrontier(scope, a.direction)
	if err == cryptov4.ErrNotReady {
		if spec, enabled := a.engine.BootstrapSpec(); enabled && scope == spec.Scope {
			tx, err = a.engine.BootstrapFrontier(a.direction)
		}
	}
	if err != nil {
		// Pending incoming OPEN has only a receive key. Its first send key is
		// installed in Resolve at the same epoch, with a real zero frontier.
		if err != cryptov4.ErrScope {
			return nil, err
		}
		tx = protocolv4.RecordHeader{Epoch: rx.Epoch, Scope: scope}
	}
	writer, err := NewRecordWriter(a.engine, scope, reservation.Writer)
	if err != nil {
		return nil, err
	}
	send, err := NewSendFlow(writer, a.direction, peerLimit, TerminalTuple{Epoch: tx.Epoch, NextSequence: tx.Sequence}, reservation.SendCapacity, reservation.MaxPlaintext, reservation.SendReservation)
	if err != nil {
		return nil, err
	}
	frontier := TerminalTuple{Epoch: rx.Epoch, NextSequence: rx.Sequence}
	var receive *ReceiveFlow
	if guard := reservation.ReceiveProtection; guard != nil {
		if guard.pool != reservation.Pool {
			err = cryptov4.ErrConfiguration
		} else {
			receive, err = guard.newFlow(scope, 1-a.direction, reservation.InitialReceiveLimit, frontier, reservation.ReceiveCapacity)
		}
	} else {
		receive, err = NewReceiveFlow(reservation.Pool, scope, 1-a.direction, reservation.InitialReceiveLimit, frontier, reservation.ReceiveCapacity)
	}
	if err != nil {
		send.Stop()
		_ = send.WaitCleanup(context.Background()) // Never published or started.
		_ = send.retire()
		return nil, err
	}
	flow, err := NewStreamFlow(send, receive)
	if err == nil && reservation.NativeReceive != (resourcev4.Reference{}) {
		flow.nativeReceive, err = newNativeDataAssembly(receive, reservation.NativeReceive)
	}
	if err == nil && reservation.SendQueue != nil {
		r := reservation.SendQueue
		var queue *SendQueue
		queue, err = NewSendQueue(send, r.Capacity, r.Waiters, r.Chunk, r.Reservation)
		if err == nil && a.sendService != nil {
			err = a.sendService.attach(scope, class, queue)
		}
	}
	if err == nil && a.nativeAuth != nil {
		err = a.nativeAuth.attach(flow.nativeReceive)
	}
	if err == nil && a.termination != nil {
		flow.send.termination.service, flow.receive.termination.service = a.termination, a.termination
		a.termination.references.Add(2)
	}
	if err != nil {
		send.Stop()
		_ = send.WaitCleanup(context.Background())
		_ = send.retire()
		_ = receive.releaseUnpublished(false)
	}
	return flow, err
}

// releaseUnpublished returns only a never-published receive promise, or one
// explicitly cancelled by an authenticated OPEN rejection. Any received DATA
// makes a rejected dynamic OPEN contradictory, even if its payload was empty.
func (f *ReceiveFlow) releaseUnpublished(requireEmptySequence bool) (err error) {
	var native *NativeDataAssembly
	f.pool.mu.Lock()
	defer func() {
		f.pool.mu.Unlock()
		if native != nil {
			err = native.retire()
		}
	}()
	if f.cleaned {
		return nil
	}
	if f.assembly != nil && f.assembly.phase != nativeDataPrepared || f.readPending || f.readTails != 0 {
		return ErrReadInProgress
	}
	if f.size != 0 || f.observed.Offset != 0 || requireEmptySequence && f.observed.NextSequence != 0 {
		return ErrOpenAssociation
	}
	if f.assembly != nil {
		native = f.assembly
		native.closed = true
		native.cleanupLocked()
	}
	f.pool.used -= f.limit - f.released
	f.limit = f.released
	f.releaseBackingLocked()
	f.abandoned, f.fenced = true, true
	return nil
}

// OpenLocal reserves the real proof, positive slot and receive promise before
// the first OPEN ticket. It never returns a writable Stream before acceptance.
// A pre-ticket failure may release private resources, but burns its allocated
// ordinal; a post-ticket failure ends the Session instead of retrying OPEN.
func (a *OpenAdmission) OpenLocal(ctx context.Context, class StreamClass, kind string, metadata []byte, carrier *CarrierAssociation, reservation StreamReservation, deadline *timev4.Deadline) (h OpenHandle, result RecordWriteResult, err error) {
	if carrier == nil {
		return h, result, ErrOpenAssociation
	}
	if err = ctx.Err(); err != nil {
		return h, result, err
	}
	a.mu.Lock()
	if a.closed || a.draining || a.peerGoAway.set {
		a.mu.Unlock()
		return h, result, cryptov4.ErrClosed
	}
	if err = a.checkDeadline(deadline); err != nil {
		a.mu.Unlock()
		return h, result, err
	}
	if !a.positiveAvailable(a.direction, class) || a.opening >= a.limits.Opening || a.nextOrdinal > a.roleOrdinals[a.direction] {
		a.mu.Unlock()
		return h, result, cryptov4.ErrCapacity
	}
	// A server gives already authenticated client business contenders the
	// next real capacity opportunity. No local submitted OPEN is cancelled.
	if class == BusinessStream && a.direction == protocolv4.ServerToClient {
		for i := int(a.limits.Terminal); i < len(a.slots); i++ {
			if a.slots[i].phase == openPending && a.slots[i].contender {
				a.mu.Unlock()
				return h, result, ErrOpenPending
			}
		}
	}
	scope := 2*a.nextOrdinal - 1 + uint64(a.direction)
	sizeHeader := protocolv4.RecordHeader{Scope: scope, Epoch: ^uint32(0)}
	input, _, err := protocolv4.EncodeOpen(a.encode, sizeHeader, a.direction, kind, metadata, reservation.InitialReceiveLimit)
	if err == nil {
		var frame *protocolv4.Frame
		frame, err = a.decoder.DecodeRecordBody(input, protocolv4.FrameOpenStream, sizeHeader, a.direction, protocolv4.DecodeContext{})
		if err == nil {
			frame.Release()
		}
	}
	if err != nil || len(reservation.OpenStorage) < len(kind)+len(metadata) {
		a.mu.Unlock()
		if err == nil {
			err = cryptov4.ErrConfiguration
		}
		return h, result, err
	}
	carrier.mu.Lock()
	if carrier.bound != nil {
		carrier.mu.Unlock()
		a.mu.Unlock()
		return h, result, ErrOpenAssociation
	}
	i := a.freeSlot(false, false)
	if i < 0 {
		carrier.mu.Unlock()
		a.mu.Unlock()
		return h, result, cryptov4.ErrCapacity
	}
	a.nextOrdinal++
	a.lifetime[a.direction][class]++
	copy(reservation.OpenStorage, kind)
	copy(reservation.OpenStorage[len(kind):], metadata)
	snapshot := reservation.OpenStorage[:len(kind)+len(metadata)]
	// Keep the aggregate pin through snapshot clearing and all failure tails.
	a.beginTailLocked()
	defer a.endTail()
	defer clear(snapshot)
	carrier.bound, carrier.scope = a, scope
	carrier.mu.Unlock()
	a.slots[i] = openSlot{scope: scope, phase: openReserved, class: class, local: true, activeCharged: true, carrier: carrier, deadline: deadline, localLimit: reservation.InitialReceiveLimit}
	a.insert(scope, i)
	a.active++
	a.opening++
	a.positiveProofs++
	a.byOpener[a.direction][class]++
	h = OpenHandle{a, scope}
	a.mu.Unlock()
	// Keep the original positive/proof/ordinal owner while bounded key work
	// runs without holding either Session admission or carrier association.
	err = a.engine.OpenLocalScope(scope)
	keysPrepared := err == nil
	a.mu.Lock()
	if err == nil && (a.closed || a.draining || a.peerGoAway.set) {
		err = cryptov4.ErrClosed
	}
	if err == nil {
		err = a.checkDeadline(deadline)
	}
	var flow *StreamFlow
	if err == nil {
		flow, err = a.newFlow(scope, 0, class, reservation)
	}
	if err == nil {
		a.slots[i].phase, a.slots[i].flow = openOpening, flow
		if a.termination != nil {
			a.termination.notify()
		}
	}
	a.mu.Unlock()
	if err != nil {
		a.discardLocalPreparation(h, keysPrepared)
		return h, result, err
	}
	result, err = flow.send.writer.WriteBuildGuard(ctx, protocolv4.FrameOpenStream, len(input), func(header protocolv4.RecordHeader, dst []byte) (int, error) {
		a.mu.Lock()
		defer a.mu.Unlock()
		s, lookupErr := a.slot(h)
		if lookupErr != nil {
			return 0, lookupErr
		}
		// Retain the actual ticket even when cancellation/deadline wins after
		// precharge. The caller closes this Session on a failed publication.
		s.header, s.submitted = header, true
		if a.closed || s.cancelled {
			return 0, cryptov4.ErrClosed
		}
		if err := a.checkDeadline(s.deadline); err != nil {
			return 0, err
		}
		wire, digest, encodeErr := protocolv4.EncodeOpen(dst, header, a.direction, string(snapshot[:len(kind)]), snapshot[len(kind):], s.localLimit)
		if encodeErr != nil {
			return 0, encodeErr
		}
		s.digest = digest
		flow.send.mu.Lock()
		flow.send.frontier = TerminalTuple{Epoch: header.Epoch, NextSequence: header.Sequence + 1}
		flow.send.mu.Unlock()
		return len(wire), nil
	}, nil, &a.openGate)
	if err != nil {
		if result.Submitted {
			a.closeWithCause(err)
		} else {
			a.discardLocalPreparation(h, true)
		}
	}
	return h, result, err
}

func (a *OpenAdmission) discardLocalPreparation(h OpenHandle, keysPrepared bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	s, err := a.slot(h)
	if err != nil || s.submitted || !s.local || s.phase != openReserved && s.phase != openOpening {
		return
	}
	if s.flow != nil {
		s.flow.send.Stop()
		_ = s.flow.send.retire()
		_ = s.flow.receive.releaseUnpublished(true)
	}
	if keysPrepared {
		a.engine.RetireScope(s.scope)
	}
	a.active--
	a.opening--
	a.positiveProofs--
	a.byOpener[a.direction][s.class]--
	a.remove(s.scope)
	*s = openSlot{}
	a.notifyDecisionOpportunityLocked()
}

// Decide selects the peer OPEN's sole outcome. A nonempty rejection label must
// be a registered reason. Empty means a trusted authorization decision already
// succeeded; resource arbitration may still select resource_exhausted. No user
// callback is invoked, and missing proof capacity preserves the same pending.
func (a *OpenAdmission) Decide(ctx context.Context, h OpenHandle, class StreamClass, rejection string, reservation StreamReservation, maintenance *RecordWriter) (result RecordWriteResult, err error) {
	return a.decideWithGate(ctx, h, class, rejection, reservation, maintenance, nil)
}

// acceptanceGate is reserved for the SDK's fixed registry commit check. It
// must not allocate, block, or invoke application code. The original admission
// gate orders that check with Resolve and publication of accepted.
func (a *OpenAdmission) decideWithGate(ctx context.Context, h OpenHandle, class StreamClass, rejection string, reservation StreamReservation, maintenance *RecordWriter, acceptanceGate func() error) (result RecordWriteResult, err error) {
	if maintenance == nil || maintenance.engine != a.engine || maintenance.scope != 0 || class > ManagementStream {
		return result, ErrOpenAssociation
	}
	if err = ctx.Err(); err != nil {
		return result, err
	}
	a.mu.Lock()
	s, err := a.slot(h)
	if err != nil {
		a.mu.Unlock()
		return result, err
	}
	if a.closed {
		a.mu.Unlock()
		return result, cryptov4.ErrClosed
	}
	if s.phase != openPending || s.deciding {
		a.mu.Unlock()
		return result, ErrOpenAssociation
	}
	if err := a.engine.ApplicationInputReady(s.header.Epoch); err != nil {
		a.mu.Unlock()
		return result, err
	}
	if err := a.checkDeadline(s.deadline); err != nil {
		a.mu.Unlock()
		return result, err
	}
	prepared := s.preparationTarget != 0
	if acceptanceGate != nil && !prepared {
		a.mu.Unlock()
		return result, cryptov4.ErrConfiguration
	}
	if s.cancelled && rejection == "" {
		rejection = "application_rejected"
	}
	s.class = class
	s.contender = false
	role := 1 - a.direction
	if a.draining && rejection == "" {
		rejection = "draining"
	}
	if rejection == "" && !a.positiveAvailableWithProof(role, class, prepared) {
		if class == BusinessStream && a.businessConflict() {
			s.contender = true
			a.mu.Unlock()
			return result, ErrOpenPending
		}
		rejection = "resource_exhausted"
	}
	accepted := rejection == ""
	reason := uint64(0)
	if !accepted {
		reason, err = protocolv4.EnumValue("OPEN_ACCEPT", "reason", rejection)
		if err != nil {
			a.mu.Unlock()
			return result, err
		}
	}
	target := s.preparationTarget - 1
	if !prepared {
		target = a.freeSlot(false, !accepted)
	}
	if target < 0 {
		a.mu.Unlock()
		return result, ErrOpenPending
	}
	// Claim only after proof/arbitration can advance. A pending refusal must
	// not manufacture a publication-release event and wake its own retry.
	publication, err := maintenance.claimPublication()
	if err != nil {
		a.mu.Unlock()
		return result, err
	}
	defer maintenance.releasePublication(publication)
	var flow *StreamFlow
	if accepted {
		flow, err = a.newFlow(s.scope, s.peerLimit, class, reservation)
		if err != nil {
			a.mu.Unlock()
			return result, err
		}
		a.active++
		a.byOpener[role][class]++
		if !prepared {
			a.positiveProofs++
		}
	} else if !prepared {
		a.rejectionProofs++
	}
	a.slots[target] = openSlot{phase: openReserved, flow: flow}
	s.deciding = true
	s.retirementReferences++
	a.beginTailLocked()
	defer a.endTail()
	defer func() {
		a.mu.Lock()
		if original, lookupErr := a.slot(h); lookupErr == nil {
			original.retirementReferences--
			a.collect(original)
		}
		a.mu.Unlock()
	}()
	incoming := s.incoming
	a.mu.Unlock()
	if accepted {
		err = incoming.PrepareAccept()
	}
	if err == nil {
		result, err = maintenance.writeBuildClaimed(ctx, publication, protocolv4.FrameStreamAck, 192, func(_ protocolv4.RecordHeader, dst []byte) (int, error) {
			a.mu.Lock()
			defer a.mu.Unlock()
			s, lookupErr := a.slot(h)
			if lookupErr != nil {
				return 0, lookupErr
			}
			if a.closed {
				return 0, cryptov4.ErrClosed
			}
			if err := a.checkDeadline(s.deadline); err != nil {
				return 0, err
			}
			wire, encodeErr := encodeOpenOutcome(dst, s.header, s.digest, accepted, reservation.InitialReceiveLimit, reason)
			if encodeErr != nil {
				return 0, encodeErr
			}
			if accepted {
				refusal := ""
				if a.draining {
					refusal = "draining"
				} else if s.cancelled {
					refusal = "application_rejected"
				} else if acceptanceGate != nil && acceptanceGate() != nil {
					refusal = "application_rejected"
				}
				if refusal != "" {
					// A registration can close after authorization while this
					// outcome waits for its maintenance ticket. The same
					// prepared proof can still publish a local rejection.
					// Never turn that ordinary race into a Session failure.
					accepted = false
					reason, encodeErr = protocolv4.EnumValue("OPEN_ACCEPT", "reason", refusal)
					if encodeErr != nil {
						return 0, encodeErr
					}
					wire, encodeErr = encodeOpenOutcome(dst, s.header, s.digest, false, 0, reason)
					if encodeErr != nil {
						return 0, encodeErr
					}
					flow.send.Stop()
					if err := flow.receive.releaseUnpublished(false); err != nil {
						return 0, err
					}
					// The original send worker may still hold this empty queue.
					// Retain that physical tail on the rejected slot, just as
					// a locally opened Stream retains it after peer rejection.
					// Authenticated retirement/closed cleanup joins it later.
					a.active--
					a.byOpener[role][class]--
					a.notifyDecisionOpportunityLocked()
				}
			}
			if err := s.incoming.Resolve(accepted); err != nil {
				return 0, err
			}
			a.releaseMetadata(s)
			source := a.find(s.scope)
			a.outcomeWake[source], a.outcomeWake[target] = a.outcomeWake[target], a.outcomeWake[source]
			a.remove(s.scope)
			a.slots[target] = *s
			*s = openSlot{}
			s = &a.slots[target]
			s.incoming, s.deciding = nil, false
			// A late refusal transfers the original positive proof. It does
			// not borrow a rejection-reserve token at the commit gate.
			s.accepted, s.rejectionToken, s.reason = accepted, !accepted, reason
			s.rejectionOrdinary = !accepted && flow != nil
			s.activeCharged, s.flow = accepted, flow
			if accepted {
				s.phase, s.localLimit = openLive, reservation.InitialReceiveLimit
				a.highestAccepted[role] = max(a.highestAccepted[role], s.scope)
				a.lifetime[role][class]++
			} else {
				s.phase = openRecent
				s.rejectProof()
				if a.retirement != nil {
					a.retirement.notify()
				}
			}
			a.pending--
			a.insert(s.scope, target)
			a.notifyOutcomeLocked(s)
			return len(wire), nil
		})
	}
	if err != nil {
		if result.Submitted {
			a.closeWithCause(err)
		} else {
			a.mu.Lock()
			if s, lookupErr := a.slot(h); lookupErr == nil {
				s.deciding = false
				a.notifyPendingLocked()
			}
			a.slots[target] = openSlot{}
			if prepared {
				a.slots[target].phase = openReserved
			}
			if accepted {
				flow.send.Stop()
				_ = flow.send.retire()
				_ = flow.receive.releaseUnpublished(false)
				a.active--
				a.byOpener[role][class]--
				if !prepared {
					a.positiveProofs--
				}
			} else if !prepared {
				a.rejectionProofs--
			}
			a.notifyDecisionOpportunityLocked()
			a.mu.Unlock()
		}
	}
	return result, err
}

func encodeOpenOutcome(dst []byte, open protocolv4.RecordHeader, digest [32]byte, accepted bool, limit, reason uint64) ([]byte, error) {
	variant, err := protocolv4.ConstantField("OPEN_ACCEPT", "variant")
	if err != nil {
		return nil, err
	}
	label := "accepted"
	if !accepted {
		label, limit = "rejected", 0
	}
	result, err := protocolv4.EnumValue("OPEN_ACCEPT", "result", label)
	if err != nil {
		return nil, err
	}
	fields := [...]protocolv4.Field{
		{Name: "stream_id", Number: open.Scope}, {Name: "direction", Number: (open.Scope + 1) % 2},
		{Name: "result", Number: result}, {Name: "open_epoch", Number: uint64(open.Epoch)},
		{Name: "open_sequence", Number: open.Sequence}, {Name: "open_digest", Kind: protocolv4.ByteString, Bytes: digest[:]},
		{Name: "initial_receive_limit", Number: limit}, variant,
		{Name: "final_epoch", Number: uint64(open.Epoch)}, {Name: "final_next_sequence", Number: 1},
		{Name: "final_offset", Number: 0}, {Name: "reason", Number: reason},
	}
	count := len(fields)
	if accepted {
		count -= 4
	}
	return protocolv4.EncodeMap(dst, "OPEN_ACCEPT", fields[:count])
}

func (s *openSlot) rejectProof() {
	for direction := range 2 {
		tuple := TerminalTuple{Epoch: s.header.Epoch}
		if uint64(direction) == (s.scope+1)%2 {
			tuple.NextSequence = 1
		}
		s.terminal[direction] = DrainProof{Terminal: tuple, Observed: tuple}
	}
}

// ApplyOutcome authenticates the original OPEN association even when the
// maintenance record arrives in a later epoch. It cannot release native work
// or invent peer receipt of application bytes.
func (a *OpenAdmission) ApplyOutcome(record *ReceivedRecord) (err error) {
	if record == nil || record.receiver.engine != a.engine || record.receiver.direction != 1-a.direction {
		return ErrOpenAssociation
	}
	defer record.acceptOnSuccess(&err)
	f, err := record.Body()
	if err != nil {
		return err
	}
	if f.Schema != "OPEN_ACCEPT" {
		return ErrOpenAssociation
	}
	scope, _ := f.Field("stream_id").Uint()
	direction, _ := f.Field("direction").Uint()
	epoch, _ := f.Field("open_epoch").Uint()
	sequence, _ := f.Field("open_sequence").Uint()
	digest, _ := f.Field("open_digest").ByteString()
	limit, _ := f.Field("initial_receive_limit").Uint()
	result, _ := f.Field("result").Uint()
	acceptedCode, _ := protocolv4.EnumValue("OPEN_ACCEPT", "result", "accepted")
	accepted := result == acceptedCode
	reason, _ := f.Field("reason").Uint()
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return cryptov4.ErrClosed
	}
	if spec, enabled := a.engine.BootstrapSpec(); enabled && scope == spec.Scope {
		return ErrOpenAssociation
	}
	if a.isStable(scope) {
		if direction != (scope+1)%2 {
			return ErrOpenAssociation
		}
		return nil
	}
	s, err := a.slot(OpenHandle{a, scope})
	if err != nil {
		return err
	}
	if !s.local || !s.submitted || direction != uint64(a.direction) || epoch != uint64(s.header.Epoch) || sequence != s.header.Sequence || !bytes.Equal(digest, s.digest[:]) {
		return ErrOpenAssociation
	}
	if s.phase != openOpening {
		if s.accepted == accepted && s.peerLimit == limit && s.reason == reason {
			return nil
		}
		return ErrOpenAssociation
	}
	if err := a.checkDeadline(s.deadline); err != nil {
		return err
	}
	if accepted {
		if a.peerGoAway.set && scope > a.peerGoAway.ceiling {
			return ErrGoAwayConflict
		}
		if err := a.engine.AcceptLocalScope(scope); err != nil {
			return err
		}
		if err := s.flow.send.ApplyCredit(0, limit); err != nil {
			return err
		}
		s.phase = openLive
		a.highestAccepted[a.direction] = max(a.highestAccepted[a.direction], scope)
		if s.cancelled {
			s.flow.send.Stop()
			s.flow.receive.Abandon()
		}
	} else {
		if err := s.flow.receive.releaseUnpublished(true); err != nil {
			return err
		}
		s.flow.send.Stop()
		a.engine.RetireScope(scope)
		s.phase = openRecent
		s.rejectProof()
		if a.retirement != nil {
			a.retirement.notify()
		}
		if s.carrierDone && s.activeCharged {
			a.active--
			a.byOpener[a.direction][s.class]--
			s.activeCharged = false
		}
	}
	s.accepted, s.peerLimit, s.reason = accepted, limit, reason
	a.notifyOutcomeLocked(s)
	a.opening--
	a.notifyDecisionOpportunityLocked()
	return nil
}

// ApplyData stages reverse DATA on the original opening's reserved receive
// ring, while Flow withholds application access until authenticated accepted.
func (a *OpenAdmission) ApplyData(h OpenHandle, carrier *CarrierAssociation, record *ReceivedRecord) (err error) {
	if record == nil || record.receiver.engine != a.engine {
		return ErrOpenAssociation
	}
	defer record.acceptOnSuccess(&err)
	f, err := record.Body()
	if err != nil {
		return err
	}
	readyErr := a.engine.ApplicationInputReady(f.Header.Epoch)
	a.mu.Lock()
	defer a.mu.Unlock()
	s, err := a.slot(h)
	if err != nil {
		return err
	}
	if a.closed {
		return cryptov4.ErrClosed
	}
	if readyErr != nil && !(s.bootstrap && readyErr == cryptov4.ErrNotReady) {
		return readyErr
	}
	if carrier == nil || carrier != s.carrier || f.Header.Scope != s.scope || s.flow == nil || s.phase != openLive && !(s.phase == openOpening && s.local && s.submitted) && !(s.bootstrap && s.phase == openReserved && s.submitted) {
		return ErrOpenAssociation
	}
	return s.flow.receive.ApplyData(f)
}

func (a *OpenAdmission) Flow(h OpenHandle) (*StreamFlow, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	s, err := a.slot(h)
	if err != nil {
		return nil, err
	}
	if a.closed {
		return nil, cryptov4.ErrClosed
	}
	if s.bootstrap {
		if s.phase == openReserved || !s.submitted || s.carrier == nil || !a.bootstrap.materialized {
			return nil, ErrOpenPending
		}
		if err := a.engine.ApplicationInputReady(0); err != nil {
			return nil, err
		}
	}
	if s.phase == openOpening || s.phase == openPending || s.pendingRejection() {
		return nil, ErrOpenPending
	}
	if !s.accepted {
		return nil, ErrOpenRejected
	}
	if s.cancelled {
		return nil, ErrAbandoned
	}
	if s.phase != openLive && s.phase != openRecent && s.phase != openHeld {
		return nil, ErrFlowClosed
	}
	return s.flow, nil
}

func (a *OpenAdmission) Cancel(h OpenHandle) error {
	return a.cancelOwned(h, nil)
}

func (a *OpenAdmission) cancelOwned(h OpenHandle, owner *StreamOwnership) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	s, err := a.slot(h)
	if err != nil {
		return err
	}
	if s.owner != owner {
		return ErrStreamOwned
	}
	a.cancelStreamLocked(s)
	return nil
}

// cancelStream is reserved for the original transport's stream-local failure
// path. Application capability checks cannot suppress a real provider failure.
func (a *OpenAdmission) cancelStream(h OpenHandle) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	s, err := a.slot(h)
	if err != nil {
		return err
	}
	a.cancelStreamLocked(s)
	return nil
}

func (a *OpenAdmission) cancelStreamLocked(s *openSlot) {
	s.cancelled = true
	a.notifyOutcomeLocked(s)
	a.notifyPendingLocked()
	if s.phase == openLive || s.bootstrap {
		s.flow.send.Stop()
		s.flow.receive.Abandon()
	}
	s.owner.notify()
}

// AdvanceEpoch follows the original rekey coordinator's successful barrier
// transition. OPEN identity/deadline and rejected terminal tuples never move.
func (a *OpenAdmission) AdvanceEpoch(epoch uint32) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	for i := range a.slots {
		s := &a.slots[i]
		if s.phase == openOpening || s.phase == openLive {
			if err := s.flow.send.AdvanceEpoch(epoch); err != nil {
				return err
			}
			if err := s.flow.receive.AdvanceEpoch(epoch); err != nil {
				return err
			}
		}
	}
	if a.nativeAuth != nil {
		a.nativeAuth.available(true)
	}
	return nil
}

func (a *OpenAdmission) Close() { a.closeWithCause(nil) }

// closeWithCause seals the first known failure before waking peer services.
// Cleanup-induced errors cannot replace that original fact.
func (a *OpenAdmission) closeWithCause(cause error) {
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return
	}
	if cause != nil && !errors.Is(cause, context.Canceled) && !errors.Is(cause, cryptov4.ErrClosed) {
		a.failure = cause
	}
	a.closed = true
	a.openGate.close()
	if a.lifecycle != nil {
		a.lifecycle.closeLocked(cause)
	}
	a.notifyPendingLocked()
	for _, wake := range a.outcomeWake {
		notifyOpenWait(wake)
	}
	a.beginTailLocked()
	defer a.endTail()
	if a.termination != nil {
		a.termination.sealed.Store(true)
	}
	for i := range a.slots {
		s := &a.slots[i]
		if s.flow != nil {
			s.flow.send.Stop()
			if s.flow.nativeReceive != nil {
				s.flow.nativeReceive.Close()
			}
			s.flow.receive.pool.Close()
			s.flow.receive.Fence()
		}
		// Provider/flow aliases remain charged until their actual cleanup.
		s.owner.notify()
		a.releaseMetadata(s)
	}
	causes := a.rekeyCauses
	rekeyService := a.rekeyService
	retirementService := a.retirementService
	bootstrap := a.bootstrap
	liveness := a.liveness
	maintenance := a.maintenanceMessages
	sendService := a.sendService
	nativeAuth := a.nativeAuth
	termination := a.termination
	maintenanceIngress := a.maintenanceIngress
	sharedIngress := a.sharedIngress
	a.mu.Unlock()
	if maintenanceIngress != nil {
		maintenanceIngress.Close()
	}
	if sharedIngress != nil {
		sharedIngress.Close()
	}
	if termination != nil {
		termination.Close()
	}
	if nativeAuth != nil {
		nativeAuth.Close()
	}
	if sendService != nil {
		sendService.Close()
	}
	liveness.Close()
	if maintenance != nil {
		maintenance.Close()
	}
	if bootstrap != nil && bootstrap.reader != nil {
		bootstrap.reader.Close()
	}
	if retirementService != nil {
		retirementService.Close()
	}
	if rekeyService != nil {
		rekeyService.Close()
	}
	if causes != nil {
		causes.Close()
	}
	a.engine.Close()
}
