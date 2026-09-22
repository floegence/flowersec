package sessionv4

import (
	"context"
	"errors"
	"io"
	"math"
	"strings"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

// RecordReceiver owns one reserved read/decode slot. It makes no unbounded
// reader goroutines, queues or waiters. The Session consumes the frame and
// releases it before admitting the next record into this slot.
type RecordReceiver struct {
	mu              sync.Mutex
	engine          *cryptov4.Engine
	decoder         *protocolv4.Decoder
	direction       protocolv4.Direction
	context         protocolv4.DecodeContext
	maxFrame        uint32
	storage         []byte
	reservation     resourcev4.Reference
	closed, active  bool
	idle            chan struct{}
	stop            chan struct{}
	cleanupSignaled bool
}

// RecordReceiverCharge includes the original decoder, envelope storage, one
// authenticated frame owner and owned context strings/entries. Map buckets,
// allocator/channel/runtime overhead and crypto/provider costs are additionally
// admitted by the selected profile; this minimum is not an RSS qualification.
func RecordReceiverCharge(maxFrame uint32, nodeCap int, decodeContext protocolv4.DecodeContext) (resourcev4.Vector, error) {
	if maxFrame == 0 || maxFrame > protocolv4.MaxPayloadLength {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	decoder, err := protocolv4.RecordDecoderBackingBytes(int(maxFrame), nodeCap)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	bytes := decoder + uint64(protocolv4.EnvelopePrefixSize) + uint64(maxFrame) + uint64(unsafe.Sizeof(RecordReceiver{})) + uint64(unsafe.Sizeof(ReceivedRecord{}))
	add := func(n uint64) bool {
		if n > math.MaxUint64-bytes {
			return false
		}
		bytes += n
		return true
	}
	// The exact crypto selector is inserted by the original engine. Reserve
	// its complete maximum entry even when the caller supplied none.
	if !add(uint64(2*unsafe.Sizeof("") + uintptr(len("crypto_profile_id")) + uintptr(max(len(protocolv4.DHProfileX25519), len(protocolv4.DHProfileP256))))) {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	for key := range decodeContext.Limits {
		if !add(uint64(len(key)) + uint64(unsafe.Sizeof("")) + 8) {
			return resourcev4.Vector{}, cryptov4.ErrConfiguration
		}
	}
	for key, value := range decodeContext.Selectors {
		if key == "crypto_profile_id" {
			continue
		}
		if !add(uint64(len(key)) + uint64(len(value)) + uint64(2*unsafe.Sizeof(""))) {
			return resourcev4.Vector{}, cryptov4.ErrConfiguration
		}
	}
	return resourcev4.Vector{resourcev4.SDKBytes: bytes, resourcev4.Items: 1, resourcev4.Tasks: 1, resourcev4.WorkSlots: 1}, nil
}

func NewRecordReceiver(engine *cryptov4.Engine, direction protocolv4.Direction, maxFrame uint32, nodeCap int, decodeContext protocolv4.DecodeContext, reservation resourcev4.Reference) (*RecordReceiver, error) {
	if engine == nil || direction > protocolv4.ServerToClient || maxFrame < engine.MaxFrame() || maxFrame > protocolv4.MaxPayloadLength {
		return nil, cryptov4.ErrConfiguration
	}
	_, _, sender := engine.ScopeLimits()
	if direction != 1-sender {
		return nil, cryptov4.ErrConfiguration
	}
	_, profile := engine.SessionBinding()
	if configured := decodeContext.Selectors["crypto_profile_id"]; configured != "" && configured != profile {
		return nil, cryptov4.ErrConfiguration
	}
	charge, err := RecordReceiverCharge(maxFrame, nodeCap, decodeContext)
	if err != nil {
		return nil, err
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		return nil, err
	}
	decoder, err := protocolv4.NewRecordDecoder(int(maxFrame), nodeCap)
	if err != nil {
		owned.Release()
		return nil, err
	}
	// Capture immutable local limits; callers cannot change admission bounds
	// while a record is being authenticated or a returned frame is still owned.
	captured := protocolv4.DecodeContext{Limits: make(map[string]uint64, len(decodeContext.Limits)), Selectors: make(map[string]string, len(decodeContext.Selectors))}
	for k, v := range decodeContext.Limits {
		captured.Limits[strings.Clone(k)] = v
	}
	for k, v := range decodeContext.Selectors {
		if k != "crypto_profile_id" {
			captured.Selectors[strings.Clone(k)] = strings.Clone(v)
		}
	}
	captured.Selectors["crypto_profile_id"] = strings.Clone(profile)
	idle := make(chan struct{})
	return &RecordReceiver{engine: engine, decoder: decoder, direction: direction, maxFrame: maxFrame, context: captured, storage: make([]byte, protocolv4.EnvelopePrefixSize+int(maxFrame)), reservation: owned, idle: idle, stop: make(chan struct{})}, nil
}

type ReceivedRecord struct {
	receiver           *RecordReceiver
	packet             *cryptov4.Packet
	frame              *protocolv4.Frame
	incoming           *cryptov4.IncomingScope
	mu                 sync.Mutex
	released           bool
	maintenanceHandled bool
	dataApplied        bool
}

// claimMaintenance prevents a retained authenticated input from manufacturing
// additional response obligations. The record/schema checks precede this call.
func (r *ReceivedRecord) claimMaintenance() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.released || r.maintenanceHandled {
		return cryptov4.ErrTransition
	}
	r.maintenanceHandled = true
	return nil
}

// accepted is deliberately separate from authentication. Only the bounded
// Session handler that completed the applicable protocol checks may call it.
func (r *ReceivedRecord) accepted() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.released {
		return cryptov4.ErrClosed
	}
	r.receiver.mu.Lock()
	defer r.receiver.mu.Unlock()
	if err := r.receiver.checkLocked(); err != nil {
		return err
	}
	return r.packet.Accepted()
}

func (r *ReceivedRecord) acceptOnSuccess(err *error) {
	if *err == nil {
		*err = r.accepted()
	}
}

// AcceptMessage admits messages whose complete legality is established by the
// record/schema/epoch/replay gates. PONG activity is not a ProbeLiveness result.
// Stream and rekey messages must instead pass their original state owners.
func (r *ReceivedRecord) AcceptMessage() error {
	f, err := r.Body()
	if err != nil {
		return err
	}
	switch f.Type {
	case protocolv4.FramePing, protocolv4.FramePong, protocolv4.FrameDatagram:
		return r.accepted()
	default:
		return cryptov4.ErrConfiguration
	}
}

// Body only exposes plaintext while the original engine and receiver remain
// live. Application callbacks receive Stream data after the Session's own gate,
// never this decoder reservation or its maps.
func (r *ReceivedRecord) Body() (*protocolv4.Frame, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.released {
		return nil, cryptov4.ErrClosed
	}
	r.receiver.mu.Lock()
	err := r.receiver.checkLocked()
	r.receiver.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if _, err := r.packet.Bytes(); err != nil {
		return nil, err
	}
	return r.frame, nil
}
func (r *ReceivedRecord) Release() {
	r.mu.Lock()
	if r.released {
		r.mu.Unlock()
		return
	}
	r.released = true
	r.frame.Release()
	r.packet.Release()
	r.frame, r.packet, r.incoming = nil, nil, nil
	r.mu.Unlock()
	r.receiver.finish()
}
func (r *RecordReceiver) begin(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.checkLocked(); err != nil {
		return err
	}
	if r.active {
		return cryptov4.ErrCapacity
	}
	r.active = true
	return nil
}
func (r *RecordReceiver) finish() {
	r.mu.Lock()
	defer r.mu.Unlock()
	clear(r.storage)
	r.active = false
	r.signalCleanupLocked()
}

func (r *RecordReceiver) Read(ctx context.Context, reader io.Reader) (_ *ReceivedRecord, err error) {
	return r.read(ctx, reader, false)
}

func (r *RecordReceiver) ReadOpen(ctx context.Context, reader io.Reader) (_ *ReceivedRecord, err error) {
	return r.read(ctx, reader, true)
}

// ReadShared is the one-reader path for a shared carrier such as WebSocket.
// The fixed envelope family is inspected before authentication: an OPEN uses
// the bounded unbound incoming owner, while every other frame must authenticate
// against an already installed logical scope. It never guesses a scope from a
// native stream identifier and never starts a per-frame task.
func (r *RecordReceiver) readShared(ctx context.Context, reader io.Reader, gate *SharedIngress) (_ *ReceivedRecord, err error) {
	if reader == nil {
		return nil, cryptov4.ErrConfiguration
	}
	if err = r.begin(ctx); err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			r.finish()
		}
	}()
	prefix, err := ReadRecordPrefix(reader, r.maxFrame)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	err = r.checkLocked()
	r.mu.Unlock()
	if err != nil {
		return nil, err
	}
	wire, err := prefix.ReadBody(reader, r.storage)
	if err != nil {
		return nil, err
	}
	frame, header, _, err := protocolv4.ParseRecord(wire, r.context.Selectors["crypto_profile_id"], r.maxFrame)
	if err != nil {
		return nil, err
	}
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := gate.rejectClosedData(frame, header, uint64(len(wire))); err != nil {
			return nil, err
		}
		record, err := r.authenticateShared(wire, frame, header, gate)
		if !errors.Is(err, cryptov4.ErrCapacity) {
			return record, err
		}
		// No AEAD attempt has occurred. This reader retains the exact ciphertext
		// and its original backing while the reserved crypto position is busy.
		select {
		case <-r.engine.ReceiveWake():
		case <-r.engine.MaintenanceReceiveWake():
		case <-r.engine.Done():
			return nil, cryptov4.ErrClosed
		case <-r.stop:
			return nil, cryptov4.ErrClosed
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func (r *RecordReceiver) authenticateShared(wire []byte, frame protocolv4.FrameType, header protocolv4.RecordHeader, gate *SharedIngress) (*ReceivedRecord, error) {
	commit := sharedDataCommit{admission: gate.admission}
	defer commit.release()
	validated := false
	record, err := r.authenticateDecoded(wire, frame == protocolv4.FrameOpenStream, func(kind protocolv4.FrameType, header protocolv4.RecordHeader, body *protocolv4.Frame, decodeErr error) error {
		validated = true
		return gate.validateData(&commit, kind, header, body, decodeErr)
	})
	if err != nil && !errors.Is(err, errSharedDiscarded) {
		commit.release()
		// Permanent termination may win after the initial envelope check and
		// delete the key before or during authentication. Reconcile against that
		// same proof; do not turn a late DATA candidate into a Session failure.
		if discard := gate.rejectClosedData(frame, header, uint64(len(wire))); discard != nil {
			return nil, discard
		}
		if validated && errors.Is(err, cryptov4.ErrCapacity) {
			// A body/ownership refusal after AEAD is never a workspace retry.
			return nil, ErrSharedIngress
		}
	}
	if err == nil && commit.flow != nil {
		err = commit.flow.applyDataLocked(record.frame, nil, true, true)
		if err == nil {
			err = record.accepted()
		}
		if err != nil {
			record.Release()
			return nil, err
		}
		record.dataApplied = true
	}
	return record, err
}

func (r *RecordReceiver) read(ctx context.Context, reader io.Reader, incoming bool) (_ *ReceivedRecord, err error) {
	if reader == nil {
		return nil, cryptov4.ErrConfiguration
	}
	if err = r.begin(ctx); err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			r.finish()
		}
	}()
	prefix, err := ReadRecordPrefix(reader, r.maxFrame)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	err = r.checkLocked()
	r.mu.Unlock()
	if err != nil {
		return nil, err
	}
	wire, err := prefix.ReadBody(reader, r.storage)
	if err != nil {
		return nil, err
	}
	return r.authenticateMode(wire, incoming)
}
func (r *RecordReceiver) Receive(ctx context.Context, wire []byte) (_ *ReceivedRecord, err error) {
	if err = r.begin(ctx); err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			r.finish()
		}
	}()
	return r.authenticate(wire)
}

// receiveMaintenance is reachable only through the original designated native
// maintenance association. A foreign header is rejected before selecting any
// ordinary key or spending an AEAD attempt.
func (r *RecordReceiver) receiveMaintenance(ctx context.Context, wire []byte) (_ *ReceivedRecord, err error) {
	if err = r.begin(ctx); err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			r.finish()
		}
	}()
	if len(wire) > len(r.storage) {
		return nil, protocolv4.ErrPayloadTooLarge
	}
	n := copy(r.storage, wire)
	_, header, _, err := protocolv4.ParseRecord(r.storage[:n], r.context.Selectors["crypto_profile_id"], r.maxFrame)
	if err != nil {
		return nil, err
	}
	if header.Scope != 0 {
		return nil, protocolv4.ErrRecordScope
	}
	return r.authenticate(r.storage[:n])
}

// receiveNativeSegments borrows a complete original native candidate only for the
// bounded copy into this admitted authentication input. No partial native Read
// occupies this receiver or a crypto workspace.
func (r *RecordReceiver) receiveNativeSegments(ctx context.Context, scope uint64, first, second, third []byte, check func(*protocolv4.Frame) error) (_ *ReceivedRecord, err error) {
	if err = r.begin(ctx); err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			r.finish()
		}
	}()
	size := 0
	for _, part := range [][]byte{first, second, third} {
		if len(part) > len(r.storage)-size {
			return nil, protocolv4.ErrPayloadTooLarge
		}
		size += copy(r.storage[size:], part)
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	frame, header, _, err := protocolv4.ParseRecord(r.storage[:size], r.context.Selectors["crypto_profile_id"], r.maxFrame)
	if err != nil {
		return nil, err
	}
	if frame != protocolv4.FrameStreamData || header.Scope != scope {
		return nil, protocolv4.ErrRecordScope
	}
	if err := r.engine.NativeDataInputReady(header); err != nil {
		return nil, err
	}
	return r.authenticateChecked(r.storage[:size], false, check)
}

// ReceiveOpen uses the already reserved unbound-carrier ingress slot. After
// success the Session must transfer the authenticated incoming owner into its
// pending index before releasing the record; Release does not undo that fact.
func (r *RecordReceiver) ReceiveOpen(ctx context.Context, wire []byte) (_ *ReceivedRecord, err error) {
	if err = r.begin(ctx); err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			r.finish()
		}
	}()
	return r.authenticateMode(wire, true)
}

func (r *RecordReceiver) authenticate(wire []byte) (*ReceivedRecord, error) {
	return r.authenticateMode(wire, false)
}

func (r *RecordReceiver) authenticateMode(wire []byte, incoming bool) (*ReceivedRecord, error) {
	return r.authenticateChecked(wire, incoming, nil)
}

func (r *RecordReceiver) authenticateChecked(wire []byte, incoming bool, check func(*protocolv4.Frame) error) (*ReceivedRecord, error) {
	return r.authenticateDecoded(wire, incoming, func(_ protocolv4.FrameType, _ protocolv4.RecordHeader, body *protocolv4.Frame, err error) error {
		if err == nil && check != nil {
			return check(body)
		}
		return err
	})
}

// decoded executes only after the original expected-sequence AEAD succeeds.
// Its rejection prevents the crypto frontier from committing, including when
// required inner fields fail to decode.
func (r *RecordReceiver) authenticateDecoded(wire []byte, incoming bool, decoded func(protocolv4.FrameType, protocolv4.RecordHeader, *protocolv4.Frame, error) error) (*ReceivedRecord, error) {
	r.mu.Lock()
	err := r.checkLocked()
	r.mu.Unlock()
	if err != nil {
		return nil, err
	}
	var body *protocolv4.Frame
	validate := func(frame protocolv4.FrameType, header protocolv4.RecordHeader, plain []byte) error {
		var err error
		body, err = r.decoder.DecodeRecordBody(plain, frame, header, r.direction, r.context)
		if err == nil && frame == protocolv4.FrameOpenStream {
			if spec, enabled := r.engine.BootstrapSpec(); enabled && header.Scope == spec.Scope && !spec.ValidatePrefix(body) {
				return ErrOpenAssociation
			}
		}
		return decoded(frame, header, body, err)
	}
	var packet *cryptov4.Packet
	var owner *cryptov4.IncomingScope
	if incoming {
		packet, owner, err = r.engine.OpenIncoming(wire, validate)
	} else {
		frame, header, _, parseErr := protocolv4.ParseRecord(wire, r.context.Selectors["crypto_profile_id"], r.maxFrame)
		if parseErr != nil {
			return nil, parseErr
		}
		if frame == protocolv4.FrameRekey && header.Epoch > 0 && header.Scope == 0 && header.Sequence == 0 {
			packet, body, err = r.engine.OpenRekeyMarker(wire, func(frame protocolv4.FrameType, header protocolv4.RecordHeader, plain []byte) (*protocolv4.Frame, error) {
				return r.decoder.DecodeRecordBody(plain, frame, header, r.direction, r.context)
			})
		} else {
			packet, _, _, err = r.engine.Open(wire, validate)
		}
	}
	if err != nil {
		if body != nil {
			body.Release()
		}
		return nil, err
	}
	r.mu.Lock()
	err = r.checkLocked()
	r.mu.Unlock()
	if err != nil {
		body.Release()
		packet.Release()
		return nil, err
	}
	return &ReceivedRecord{receiver: r, packet: packet, frame: body, incoming: owner}, nil
}
func (r *RecordReceiver) signalCleanupLocked() {
	if r.closed && !r.active && !r.cleanupSignaled {
		clear(r.storage)
		r.storage, r.decoder = nil, nil
		r.context = protocolv4.DecodeContext{}
		r.cleanupSignaled = true
		close(r.idle)
	}
}

func (r *RecordReceiver) Close() {
	r.mu.Lock()
	if !r.closed {
		r.closed = true
		close(r.stop)
	}
	r.reservation.Seal()
	r.signalCleanupLocked()
	r.mu.Unlock()
}

func (r *RecordReceiver) checkLocked() error {
	if r.closed {
		return cryptov4.ErrClosed
	}
	return r.reservation.Check()
}

// The enclosing original Session/ingress owner retires the receiver after its
// real read/plaintext/cleanup aliases exit. Close alone does not refund the
// still-retained receiver metadata or its original slot.
func (r *RecordReceiver) retire() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.cleanupSignaled || r.active {
		return cryptov4.ErrCapacity
	}
	r.reservation.Release()
	return nil
}
func (r *RecordReceiver) WaitCleanup(ctx context.Context) error {
	r.mu.Lock()
	closed, idle := r.closed, r.idle
	r.mu.Unlock()
	if !closed {
		return cryptov4.ErrTransition
	}
	select {
	case <-idle:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
