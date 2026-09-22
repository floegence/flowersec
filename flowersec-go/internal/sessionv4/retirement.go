package sessionv4

import (
	"bytes"
	"context"
	"math"
	"slices"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

type retirementBatch struct {
	ids                            []uint64
	count                          int
	sequence                       uint64
	digest                         [32]byte
	deadline                       *timev4.Deadline
	live, submitted, writing, done bool
}

// Retirement has one outbound batch and one pending inbound batch, plus one
// explicitly reserved inbound publication tail. All arrays are fixed at Bind.
// The tail lets a peer submit its next batch after seeing an ACK while that
// ACK's original provider callback still owns the previous proof references.
type Retirement struct {
	wake                               chan struct{}
	admission                          *OpenAdmission
	writer                             *RecordWriter
	out                                retirementBatch
	in                                 [2]retirementBatch
	batchBytes, arrayBytes             []byte
	lastSent, lastReceived             uint64
	lastSentDigest, lastReceivedDigest [32]byte
	repeatAck, repeating               bool
	handshake                          [32]byte
	profile                            string
}

func NewRetirement(a *OpenAdmission, maintenance *RecordWriter) (*Retirement, error) {
	if a == nil || maintenance == nil || maintenance.engine != a.engine || maintenance.scope != 0 {
		return nil, cryptov4.ErrConfiguration
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed || a.runtime != nil || a.retirement != nil {
		return nil, cryptov4.ErrConfiguration
	}
	count, err := protocolv4.FieldItemLimit("STREAM_ACK_RETIRE_BATCH", "scope_ids")
	if err != nil {
		return nil, err
	}
	maximum, err := protocolv4.SchemaByteLimit("STREAM_ACK_RETIRE_BATCH")
	if err != nil {
		return nil, err
	}
	r := &Retirement{admission: a, writer: maintenance, batchBytes: make([]byte, maximum), arrayBytes: make([]byte, maximum)}
	r.handshake, r.profile = a.engine.SessionBinding()
	r.out.ids = make([]uint64, count)
	for i := range r.in {
		r.in[i].ids = make([]uint64, count)
	}
	a.retirement = r
	return r, nil
}

// Start captures only locally allocated complete proofs. A frozen unpublished
// barrier returns pending before reserving any maintenance ticket or output.
func (r *Retirement) Start(ctx context.Context, maxItems int, deadline *timev4.Deadline) (result RecordWriteResult, err error) {
	a := r.admission
	if err = ctx.Err(); err != nil {
		return result, err
	}
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return result, cryptov4.ErrClosed
	}
	if r.out.live || r.lastSent == math.MaxUint64 {
		a.mu.Unlock()
		return result, ErrOpenPending
	}
	if maxItems < 1 || maxItems > len(r.out.ids) {
		a.mu.Unlock()
		return result, cryptov4.ErrConfiguration
	}
	if err = a.checkDeadline(deadline); err != nil {
		a.mu.Unlock()
		return result, err
	}
	b := &r.out
	for i := 0; i < int(a.limits.Terminal) && b.count < maxItems; i++ {
		s := &a.slots[i]
		if s.phase == openRecent && protocolv4.Direction((s.scope+1)%2) == a.direction && s.barrierUnpublished == 0 {
			b.ids[b.count] = s.scope
			b.count++
		}
	}
	if b.count == 0 {
		a.mu.Unlock()
		return result, ErrOpenPending
	}
	slices.Sort(b.ids[:b.count])
	array, err := protocolv4.EncodeScopeArray(r.arrayBytes, b.ids[:b.count])
	if err != nil {
		b.count = 0
		a.mu.Unlock()
		return result, err
	}
	variant, err := protocolv4.ConstantField("STREAM_ACK_RETIRE_BATCH", "variant")
	if err != nil {
		b.count = 0
		a.mu.Unlock()
		return result, err
	}
	b.sequence, b.deadline = r.lastSent+1, deadline
	wire, err := protocolv4.EncodeMap(r.batchBytes, "STREAM_ACK_RETIRE_BATCH", []protocolv4.Field{variant, {Name: "batch_seq", Number: b.sequence}, {Name: "scope_ids", Kind: protocolv4.EncodedArray, Bytes: array}})
	if err == nil {
		b.digest, err = protocolv4.RetirementDigest(r.handshake, r.profile, a.direction, wire)
	}
	if err != nil {
		b.count = 0
		a.mu.Unlock()
		return result, err
	}
	if !a.beginTailLocked() {
		b.count = 0
		a.mu.Unlock()
		return result, cryptov4.ErrClosed
	}
	defer a.endTail()
	for _, id := range b.ids[:b.count] {
		a.slots[a.find(id)].retirementReferences++
	}
	b.live, b.writing = true, true
	a.mu.Unlock()
	result, err = r.writer.WriteBuild(ctx, protocolv4.FrameStreamAck, len(wire), func(_ protocolv4.RecordHeader, dst []byte) (int, error) {
		a.mu.Lock()
		defer a.mu.Unlock()
		if a.closed {
			return 0, cryptov4.ErrClosed
		}
		if err := a.checkDeadline(b.deadline); err != nil {
			return 0, err
		}
		for _, id := range b.ids[:b.count] {
			s := &a.slots[a.find(id)]
			if s.phase != openRecent || s.barrierUnpublished != 0 {
				return 0, ErrTerminal
			}
		}
		b.submitted = true
		return copy(dst, wire), nil
	})
	a.mu.Lock()
	b.writing = false
	if b.done || err != nil && !result.Submitted {
		r.release(b)
	}
	a.mu.Unlock()
	if err != nil && result.Submitted {
		a.closeWithCause(err)
	}
	return result, err
}

func (r *Retirement) release(b *retirementBatch) {
	a := r.admission
	for _, id := range b.ids[:b.count] {
		i := a.find(id)
		if i >= 0 {
			s := &a.slots[i]
			s.retirementReferences--
			a.collect(s)
		}
	}
	clear(b.ids)
	ids := b.ids
	*b = retirementBatch{ids: ids}
}

// disposeClosedLocked relinquishes only local proof references after every
// admitted method has returned. Closing a Session cannot manufacture an ACK
// or make an unresolved scope stable. The admission gate protects all fields.
func (r *Retirement) disposeClosedLocked() bool {
	a := r.admission
	if !a.closed || a.methodTails != 0 || r.repeating || r.out.writing || r.in[0].writing || r.in[1].writing {
		return false
	}
	r.release(&r.out)
	r.out.ids = nil
	for i := range r.in {
		r.release(&r.in[i])
		r.in[i].ids = nil
	}
	clear(r.batchBytes)
	clear(r.arrayBytes)
	r.batchBytes, r.arrayBytes = nil, nil
	r.repeatAck = false
	r.handshake, r.lastSentDigest, r.lastReceivedDigest = [32]byte{}, [32]byte{}, [32]byte{}
	r.profile = ""
	r.writer = nil
	return true
}

func (r *Retirement) Receive(record *ReceivedRecord, deadline *timev4.Deadline) (err error) {
	a := r.admission
	if !a.beginTail() {
		return cryptov4.ErrClosed
	}
	defer a.endTail()
	defer r.notify()
	if record == nil || record.receiver.engine != a.engine || record.receiver.direction != 1-a.direction {
		return ErrOpenAssociation
	}
	defer record.acceptOnSuccess(&err)
	f, err := record.Body()
	if err != nil {
		return err
	}
	switch f.Schema {
	case "STREAM_ACK_RETIRE_ACK":
		return r.receiveAck(f)
	case "STREAM_ACK_RETIRE_BATCH":
	default:
		return ErrOpenAssociation
	}
	sequence, _ := f.Field("batch_seq").Uint()
	digest, err := protocolv4.RetirementDigest(r.handshake, r.profile, 1-a.direction, f.Document.Bytes())
	if err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return cryptov4.ErrClosed
	}
	if sequence < r.lastReceived {
		return nil
	}
	if sequence == r.lastReceived {
		if digest != r.lastReceivedDigest {
			return ErrTerminal
		}
		r.repeatAck = true
		return nil
	}
	if r.lastReceived == math.MaxUint64 || sequence != r.lastReceived+1 {
		return ErrTerminal
	}
	var b *retirementBatch
	for i := range r.in {
		current := &r.in[i]
		if current.live && !current.done {
			if current.sequence == sequence && current.digest == digest {
				return nil
			}
			return ErrTerminal
		}
		if !current.live {
			b = current
		}
	}
	if b == nil {
		return cryptov4.ErrCapacity
	}
	if err := a.checkDeadline(deadline); err != nil {
		return err
	}
	count, ok := f.Field("scope_ids").CopyUints(b.ids)
	if !ok || count == 0 {
		return ErrTerminal
	}
	for _, id := range b.ids[:count] {
		if protocolv4.Direction((id+1)%2) != 1-a.direction || a.isStable(id) {
			return ErrTerminal
		}
		i := a.find(id)
		if i < 0 {
			return ErrTerminal
		}
	}
	b.live, b.count, b.sequence, b.digest, b.deadline = true, count, sequence, digest, deadline
	for _, id := range b.ids[:count] {
		a.slots[a.find(id)].retirementReferences++
	}
	return nil
}

func (r *Retirement) receiveAck(f *protocolv4.Frame) error {
	a := r.admission
	sequence, _ := f.Field("batch_seq").Uint()
	digest, _ := f.Field("batch_digest").ByteString()
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return cryptov4.ErrClosed
	}
	if sequence < r.lastSent {
		return nil
	}
	if sequence == r.lastSent {
		if !bytes.Equal(digest, r.lastSentDigest[:]) {
			return ErrTerminal
		}
		return nil
	}
	b := &r.out
	if !b.live || !b.submitted || b.sequence != sequence || !bytes.Equal(digest, b.digest[:]) {
		return ErrTerminal
	}
	if err := a.checkDeadline(b.deadline); err != nil {
		return err
	}
	for _, id := range b.ids[:b.count] {
		s := &a.slots[a.find(id)]
		if s.phase != openRecent {
			return ErrTerminal
		}
	}
	b.done = true
	r.lastSent, r.lastSentDigest = sequence, b.digest
	for _, id := range b.ids[:b.count] {
		a.makeStable(&a.slots[a.find(id)])
	}
	if !b.writing {
		r.release(b)
	}
	return nil
}

// Acknowledge never waits holding the maintenance writer, decoder or owner
// lock. An incomplete proof/barrier/tail returns pending for the Session to
// revisit after actual progress, so required STOP/rekey messages can run.
func (r *Retirement) Acknowledge(ctx context.Context) (result RecordWriteResult, err error) {
	a := r.admission
	if err = ctx.Err(); err != nil {
		return result, err
	}
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return result, cryptov4.ErrClosed
	}
	var b *retirementBatch
	free := 0
	for i := range r.in {
		if !r.in[i].live {
			free++
		} else if !r.in[i].done {
			b = &r.in[i]
		}
	}
	if r.repeating || b != nil && b.writing || b != nil && free == 0 {
		a.mu.Unlock()
		return result, ErrOpenPending
	}
	sequence, digest := r.lastReceived, r.lastReceivedDigest
	if b == nil {
		if !r.repeatAck {
			a.mu.Unlock()
			return result, ErrOpenPending
		}
		r.repeating = true
	} else {
		if err := a.checkDeadline(b.deadline); err != nil {
			a.mu.Unlock()
			return result, err
		}
		for _, id := range b.ids[:b.count] {
			s := &a.slots[a.find(id)]
			if s.phase != openRecent || s.barrierUnpublished != 0 {
				a.mu.Unlock()
				return result, ErrOpenPending
			}
		}
		sequence, digest, b.writing = b.sequence, b.digest, true
	}
	if !a.beginTailLocked() {
		if b != nil {
			b.writing = false
		} else {
			r.repeating = false
		}
		a.mu.Unlock()
		return result, cryptov4.ErrClosed
	}
	defer a.endTail()
	a.mu.Unlock()
	maximum, err := protocolv4.SchemaByteLimit("STREAM_ACK_RETIRE_ACK")
	if err == nil {
		result, err = r.writer.WriteBuild(ctx, protocolv4.FrameStreamAck, maximum, func(_ protocolv4.RecordHeader, dst []byte) (int, error) {
			a.mu.Lock()
			defer a.mu.Unlock()
			if a.closed {
				return 0, cryptov4.ErrClosed
			}
			variant, err := protocolv4.ConstantField("STREAM_ACK_RETIRE_ACK", "variant")
			if err != nil {
				return 0, err
			}
			wire, err := protocolv4.EncodeMap(dst, "STREAM_ACK_RETIRE_ACK", []protocolv4.Field{variant, {Name: "batch_seq", Number: sequence}, {Name: "batch_digest", Kind: protocolv4.ByteString, Bytes: digest[:]}})
			if err != nil {
				return 0, err
			}
			if b != nil {
				if err := a.checkDeadline(b.deadline); err != nil {
					return 0, err
				}
				for _, id := range b.ids[:b.count] {
					s := &a.slots[a.find(id)]
					if s.phase != openRecent || s.barrierUnpublished != 0 {
						return 0, ErrTerminal
					}
				}
				b.submitted, b.done = true, true
				r.lastReceived, r.lastReceivedDigest = sequence, digest
				for _, id := range b.ids[:b.count] {
					a.makeStable(&a.slots[a.find(id)])
				}
			}
			return len(wire), nil
		})
	}
	a.mu.Lock()
	if b != nil {
		b.writing = false
		if b.done {
			r.release(b)
		}
	} else {
		r.repeating = false
		if err == nil {
			r.repeatAck = false
		}
	}
	a.mu.Unlock()
	if err != nil && result.Submitted {
		a.closeWithCause(err)
	}
	return result, err
}

func (r *Retirement) CheckDeadlines() error {
	a := r.admission
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, b := range []*retirementBatch{&r.out, &r.in[0], &r.in[1]} {
		if b.live && !b.done {
			if err := a.checkDeadline(b.deadline); err != nil {
				return err
			}
		}
	}
	return nil
}

// ackReadyLocked checks the same original publication prerequisites as
// Acknowledge. Merely retaining a peer batch never outranks sendable work.
func (r *Retirement) ackReadyLocked() bool {
	if r.repeating {
		return false
	}
	free := 0
	var b *retirementBatch
	for i := range r.in {
		if !r.in[i].live {
			free++
		} else if !r.in[i].done {
			b = &r.in[i]
		}
	}
	if b == nil {
		return r.repeatAck
	}
	if b.writing || free == 0 {
		return false
	}
	for _, id := range b.ids[:b.count] {
		index := r.admission.find(id)
		if index < 0 {
			return false
		}
		s := &r.admission.slots[index]
		if s.phase != openRecent || s.barrierUnpublished != 0 {
			return false
		}
	}
	return true
}
