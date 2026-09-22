// Package sessionv4 coordinates the Flowersec v4 Session's original I/O owners.
package sessionv4

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"sync"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
)

var ErrRecordWriter = errors.New("sessionv4: record writer failed")

// This local refusal owns no ticket and can wait for the original publisher.
// Preserve the existing capacity identity for lower-level callers.
var errRecordWriterBusy = errors.Join(cryptov4.ErrCapacity, errors.New("sessionv4: record publisher busy"))

// RecordWriteResult keeps irreversible submission separate from actual provider
// progress. An error or cancelled waiter never turns a consumed ticket back
// into an unsubmitted record.
type RecordWriteResult struct {
	Submitted     bool
	Header        protocolv4.RecordHeader
	EnvelopeBytes int
	Complete      bool
}

// RecordWriter serializes one reliable scope's original provider publication.
// It admits one operation and no waiting queue. Close seals admission promptly;
// the original provider call keeps its buffer and cleanup responsibility.
type RecordWriter struct {
	maintenanceOwner             *OpenAdmission
	mu                           sync.Mutex
	engine                       *cryptov4.Engine
	writer                       io.Writer
	scope                        uint64
	closed, active               bool
	publication, nextPublication uint64
	// idle is a coalesced hint for the one admitted liveness scheduler.
	// cleanup is the lifetime broadcast for all cancellation-aware waiters.
	idle, cleanup   chan struct{}
	cleanupSignaled bool
}

// An OPEN claims the original publication position before consuming its flow
// reservations. A busy writer therefore cannot destroy a prepared Stream's
// one-use backing and force a fresh allocation on retry.
type recordPublication struct{ generation uint64 }

func (w *RecordWriter) claimPublication() (recordPublication, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return recordPublication{}, cryptov4.ErrClosed
	}
	if w.active {
		return recordPublication{}, errRecordWriterBusy
	}
	if w.nextPublication == math.MaxUint64 {
		return recordPublication{}, cryptov4.ErrCapacity
	}
	w.nextPublication++
	w.active, w.publication = true, w.nextPublication
	return recordPublication{w.publication}, nil
}

func (w *RecordWriter) releasePublication(claim recordPublication) {
	w.mu.Lock()
	if claim.generation == 0 || w.publication != claim.generation {
		w.mu.Unlock()
		return
	}
	w.active, w.publication = false, 0
	w.notifyLocked()
	w.mu.Unlock()
	w.notifyDecisionOpportunity()
}

func (w *RecordWriter) notifyDecisionOpportunity() {
	if a := w.maintenanceOwner; a != nil {
		a.mu.Lock()
		a.notifyDecisionOpportunityLocked()
		a.mu.Unlock()
	}
}

func (w *RecordWriter) writeBuildClaimed(ctx context.Context, claim recordPublication, frame protocolv4.FrameType, maxPlaintext int, build func(protocolv4.RecordHeader, []byte) (int, error)) (RecordWriteResult, error) {
	return w.writeClaimed(ctx, func() (*cryptov4.Packet, error) {
		return w.engine.SealBuildGuard(frame, w.scope, maxPlaintext, build, nil, nil)
	}, nil, nil, false, claim)
}

func NewRecordWriter(engine *cryptov4.Engine, scope uint64, writer io.Writer) (*RecordWriter, error) {
	if engine == nil || writer == nil || scope == protocolv4.DatagramScope() {
		return nil, ErrRecordWriter
	}
	return &RecordWriter{engine: engine, writer: writer, scope: scope, idle: make(chan struct{}, 1), cleanup: make(chan struct{})}, nil
}
func (w *RecordWriter) Write(ctx context.Context, frame protocolv4.FrameType, plaintext []byte) (result RecordWriteResult, err error) {
	return w.WriteBuild(ctx, frame, len(plaintext), func(_ protocolv4.RecordHeader, dst []byte) (int, error) { return copy(dst, plaintext), nil })
}

// WriteBuild is reserved for SDK frame builders. Application callbacks never
// run under a publication ticket or borrow an authenticated record workspace.
func (w *RecordWriter) WriteBuild(ctx context.Context, frame protocolv4.FrameType, maxPlaintext int, build func(protocolv4.RecordHeader, []byte) (int, error)) (result RecordWriteResult, err error) {
	return w.WriteBuildTicket(ctx, frame, maxPlaintext, build, nil)
}

func (w *RecordWriter) WriteBuildTicket(ctx context.Context, frame protocolv4.FrameType, maxPlaintext int, build func(protocolv4.RecordHeader, []byte) (int, error), ticket func() error) (result RecordWriteResult, err error) {
	return w.WriteBuildGuard(ctx, frame, maxPlaintext, build, ticket, nil)
}

func (w *RecordWriter) WriteBuildGuard(ctx context.Context, frame protocolv4.FrameType, maxPlaintext int, build func(protocolv4.RecordHeader, []byte) (int, error), ticket func() error, guard cryptov4.TicketGuard) (result RecordWriteResult, err error) {
	return w.writeBuildPublished(ctx, frame, maxPlaintext, build, ticket, guard, nil)
}

// published is bounded SDK accounting at complete provider handoff. It runs
// before returning the original publication slot, never under the Engine lock.
func (w *RecordWriter) writeBuildPublished(ctx context.Context, frame protocolv4.FrameType, maxPlaintext int, build func(protocolv4.RecordHeader, []byte) (int, error), ticket func() error, guard cryptov4.TicketGuard, published func()) (result RecordWriteResult, err error) {
	if build == nil || maxPlaintext < 0 {
		return result, cryptov4.ErrConfiguration
	}
	return w.write(ctx, func() (*cryptov4.Packet, error) {
		return w.engine.SealBuildGuard(frame, w.scope, maxPlaintext, build, ticket, guard)
	}, nil, published, frame == protocolv4.FramePing || frame == protocolv4.FramePong)
}

// WriteRekeyMarker uses the same original publisher as every old maintenance
// record. ticketed is an internal completion hook, never an application callback.
func (w *RecordWriter) WriteRekeyMarker(ctx context.Context, round *cryptov4.RekeyRound, ticket func() error, ticketed func() error) (RecordWriteResult, error) {
	if w.scope != 0 || round == nil || !round.BelongsTo(w.engine) {
		return RecordWriteResult{}, cryptov4.ErrConfiguration
	}
	return w.write(ctx, func() (*cryptov4.Packet, error) { return round.SealMarkerTicket(ticket) }, ticketed, nil, false)
}

func (w *RecordWriter) write(ctx context.Context, seal func() (*cryptov4.Packet, error), ticketed func() error, published func(), ordinary bool) (result RecordWriteResult, err error) {
	return w.writeClaimed(ctx, seal, ticketed, published, ordinary, recordPublication{})
}

func (w *RecordWriter) writeClaimed(ctx context.Context, seal func() (*cryptov4.Packet, error), ticketed func() error, published func(), ordinary bool, claim recordPublication) (result RecordWriteResult, err error) {
	if err = ctx.Err(); err != nil {
		return result, err
	}
	var owner *OpenAdmission
	if ordinary {
		owner = w.maintenanceOwner
	}
	if owner != nil {
		owner.mu.Lock()
		allowed, gateErr := owner.ordinaryMaintenanceReadyLocked()
		if gateErr != nil || !allowed {
			owner.mu.Unlock()
			if gateErr != nil {
				return result, gateErr
			}
			return result, cryptov4.ErrCapacity
		}
	}
	w.mu.Lock()
	if owner != nil {
		owner.mu.Unlock()
	}
	if w.closed {
		w.mu.Unlock()
		return result, cryptov4.ErrClosed
	}
	if w.active && (claim.generation == 0 || w.publication != claim.generation) {
		w.mu.Unlock()
		return result, errRecordWriterBusy
	}
	if claim.generation != 0 && (!w.active || w.publication != claim.generation) {
		w.mu.Unlock()
		return result, cryptov4.ErrTransition
	}
	w.active = true
	w.mu.Unlock()
	defer func() {
		w.mu.Lock()
		w.active, w.publication = false, 0
		if err != nil && result.Submitted {
			w.closed = true
		}
		w.notifyLocked()
		w.mu.Unlock()
		// Do not acquire admission under the writer gate: the original
		// maintenance priority path orders those locks in the other direction.
		w.notifyDecisionOpportunity()
	}()
	packet, err := seal()
	if err != nil {
		var ticket *cryptov4.TicketError
		result.Submitted = errors.As(err, &ticket)
		if result.Submitted {
			result.Header = ticket.Header
		}
		return result, err
	}
	result.Submitted = true
	defer packet.Release()
	w.mu.Lock()
	closed := w.closed
	w.mu.Unlock()
	if closed {
		return result, cryptov4.ErrClosed
	}
	data, err := packet.Bytes()
	if err != nil {
		return result, err
	}
	_, profile := w.engine.SessionBinding()
	_, result.Header, _, err = protocolv4.ParseRecord(data, profile, protocolv4.MaxPayloadLength)
	if err != nil {
		return result, err
	}
	if ticketed != nil {
		if err = ticketed(); err != nil {
			return result, err
		}
	}
	for result.EnvelopeBytes < len(data) {
		w.mu.Lock()
		closed = w.closed
		w.mu.Unlock()
		if closed {
			return result, cryptov4.ErrClosed
		}
		// A partial record continues only its original suffix. Cancellation after
		// the ticket does not replay a prefix or transfer publication to a waiter.
		if _, err = packet.Bytes(); err != nil {
			return result, err
		}
		n, writeErr := w.writer.Write(data[result.EnvelopeBytes:])
		if n < 0 || n > len(data)-result.EnvelopeBytes {
			return result, ErrRecordWriter
		}
		result.EnvelopeBytes += n
		result.Complete = result.EnvelopeBytes == len(data)
		if writeErr != nil {
			return result, writeErr
		}
		if result.Complete {
			// Count only the complete successful provider handoff. The result
			// retains actual bytes/submission even if idle expired during I/O.
			if err = packet.Published(); err != nil {
				return result, err
			}
			if published != nil {
				published()
			}
		}
		if n == 0 {
			return result, io.ErrNoProgress
		}
	}
	return result, nil
}

// WriteData emits the actual ticket in both the authenticated body and header.
// offset/credit/FIN admission belongs to the original Stream send owner.
func (w *RecordWriter) WriteData(ctx context.Context, direction protocolv4.Direction, offset uint64, fin bool, payload []byte, maxPlaintext int) (RecordWriteResult, error) {
	if direction > protocolv4.ServerToClient {
		return RecordWriteResult{}, cryptov4.ErrConfiguration
	}
	return w.WriteBuild(ctx, protocolv4.FrameStreamData, maxPlaintext, func(header protocolv4.RecordHeader, dst []byte) (int, error) {
		encoded, err := protocolv4.EncodeStreamData(dst, header, direction, offset, fin, payload)
		return len(encoded), err
	})
}
func (w *RecordWriter) Close() {
	w.mu.Lock()
	w.closed = true
	w.notifyLocked()
	w.mu.Unlock()
}

func (w *RecordWriter) notifyLocked() {
	select {
	case w.idle <- struct{}{}:
	default:
	}
	if w.closed && !w.active && !w.cleanupSignaled {
		w.cleanupSignaled = true
		close(w.cleanup)
	}
}

func (w *RecordWriter) isIdle() bool { w.mu.Lock(); defer w.mu.Unlock(); return !w.active }
func (w *RecordWriter) waitIdle(ctx context.Context) error {
	w.mu.Lock()
	closed, cleanup := w.closed, w.cleanup
	w.mu.Unlock()
	if !closed {
		return ErrRecordWriter
	}
	select {
	case <-cleanup:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (w *RecordWriter) WaitCleanup(ctx context.Context) error { return w.waitIdle(ctx) }

// RecordPrefix is small enough to retain while waiting for the caller's real
// codec/body reservation. It carries no authentication or logical owner claim.
type RecordPrefix struct {
	bytes     [protocolv4.EnvelopePrefixSize]byte
	bodyBytes uint32
}

func ReadRecordPrefix(reader io.Reader, maxFrame uint32) (RecordPrefix, error) {
	var prefix RecordPrefix
	if maxFrame == 0 || maxFrame > protocolv4.MaxPayloadLength {
		return prefix, cryptov4.ErrConfiguration
	}
	if _, err := io.ReadFull(reader, prefix.bytes[:]); err != nil {
		return RecordPrefix{}, err
	}
	prefix.bodyBytes = binary.BigEndian.Uint32(prefix.bytes[:4])
	if prefix.bodyBytes > maxFrame {
		return RecordPrefix{}, protocolv4.ErrPayloadTooLarge
	}
	if prefix.bytes[5] != 0 || binary.BigEndian.Uint16(prefix.bytes[6:8]) != 0 {
		return RecordPrefix{}, protocolv4.ErrInvalidFlags
	}
	frame := protocolv4.FrameType(prefix.bytes[4])
	if frame < protocolv4.FrameNegotiate || frame > protocolv4.FrameHopAuth {
		return RecordPrefix{}, protocolv4.ErrUnknownFrame
	}
	return prefix, nil
}
func (p RecordPrefix) RequiredBytes() int { return protocolv4.EnvelopePrefixSize + int(p.bodyBytes) }

// ReadBody uses caller-owned, already reserved storage and never allocates from
// a peer length. The caller keeps that reservation until the complete record is
// authenticated/processed or the original I/O owner actually exits.
func (p RecordPrefix) ReadBody(reader io.Reader, storage []byte) ([]byte, error) {
	if len(storage) < p.RequiredBytes() {
		return nil, cryptov4.ErrCapacity
	}
	copy(storage, p.bytes[:])
	_, err := io.ReadFull(reader, storage[protocolv4.EnvelopePrefixSize:p.RequiredBytes()])
	if err != nil {
		return nil, err
	}
	return storage[:p.RequiredBytes()], nil
}
