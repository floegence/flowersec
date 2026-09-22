package sessionv4

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

var (
	ErrSessionMessageFraming  = errors.New("sessionv4: invalid carrier message envelope")
	ErrSessionMessageProvider = errors.New("sessionv4: message provider failed")
)

// SessionMessageInputOptions reserves one runtime message and the original
// concurrent writer positions. WriteSlots includes ordinary and maintenance
// Engine positions; callers do not acquire an extra task while waiting here.
// RuntimeBytes admits context/channel/allocator and lifecycle-worker overhead.
// Provider reassembly, extensions, binary-message validation and physical
// provider cleanup have their own qualified owner and reservation.
type SessionMessageInputOptions struct {
	MaxFrame, WriteSlots uint32
	RuntimeBytes         uint64
}

func SessionMessageInputCharge(options SessionMessageInputOptions) (resourcev4.Vector, error) {
	if options.MaxFrame == 0 || options.MaxFrame > protocolv4.MaxPayloadLength || options.WriteSlots == 0 || options.WriteSlots > 130 || options.RuntimeBytes == 0 {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	bytes := uint64(unsafe.Sizeof(SessionMessageInput{})) + uint64(unsafe.Sizeof(sessionMessageInput{})) + uint64(options.MaxFrame) + uint64(protocolv4.EnvelopePrefixSize)
	bytes += (uint64(options.WriteSlots) + 1) * uint64(unsafe.Sizeof(sessionMessageCallContext{}))
	if options.RuntimeBytes > math.MaxUint64-bytes {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	return resourcev4.Vector{resourcev4.SDKBytes: bytes + options.RuntimeBytes, resourcev4.Items: 1, resourcev4.WorkSlots: uint64(options.WriteSlots) + 2, resourcev4.Tasks: 1}, nil
}

// SessionMessageInput keeps a single canonical message/close owner even when
// its handle is copied. Install it before the initial exchange starts, and use
// the same handle after READY. Initial and runtime operations never overlap.
type SessionMessageInput struct{ *sessionMessageInput }

type sessionMessageInput struct {
	mu                              sync.Mutex
	provider                        InitialMessages
	options                         SessionMessageInputOptions
	reservation, environment        resourcev4.Reference
	parent, lifetime                context.Context
	cancel                          context.CancelCauseFunc
	readContext, writeContext       context.Context
	readGeneration, writeGeneration uint64
	buffer                          []byte
	offset, length                  int
	reading                         bool
	writers                         uint32
	closed, worker, complete        bool
	retired                         bool
	cause                           error
	writeToken, wake, stop, done    chan struct{}
}

// A provider may retain its call context only under its own lifecycle charge.
// This view points to the original caller and independent cancellation state,
// never back to the adapter, its buffer, or its resource owner. Cancellation
// propagation is owned by the sole lifecycle worker, not a goroutine per call.
type sessionMessageCallContext struct {
	context.Context
	lifetime context.Context
}

func (c *sessionMessageCallContext) Done() <-chan struct{} { return c.lifetime.Done() }
func (c *sessionMessageCallContext) Err() error            { return c.lifetime.Err() }
func (c *sessionMessageCallContext) Value(key any) any {
	if value := c.lifetime.Value(key); value != nil {
		return value
	}
	return c.Context.Value(key)
}

// NewSessionMessageInput takes ownership only after all preadmission checks.
// ctx is the Session lifetime, not the initial exchange's READY-canceled child.
// InitialMessages must reject oversized/nonbinary messages before any uncharged
// reassembly or copy. The adapter never falls back to ReadMessage allocating a
// returned slice. A successful constructor owns the provider's one Close call.
func NewSessionMessageInput(ctx context.Context, messages InitialMessages, options SessionMessageInputOptions, reservation, environment resourcev4.Reference) (*SessionMessageInput, error) {
	return newSessionMessageInput(ctx, messages, options, reservation, environment, false)
}

// NewSessionMessageInputWithEnvironmentBorrow consumes a borrow preadmitted by
// the Session plan before credential spend. It uses no new reference slot.
// Failure before TakeBorrow preserves that caller-owned borrow; after transfer
// the adapter retains it through original provider cleanup and retirement.
func NewSessionMessageInputWithEnvironmentBorrow(ctx context.Context, messages InitialMessages, options SessionMessageInputOptions, reservation, environmentBorrow resourcev4.Reference) (*SessionMessageInput, error) {
	return newSessionMessageInput(ctx, messages, options, reservation, environmentBorrow, true)
}

func newSessionMessageInput(ctx context.Context, messages InitialMessages, options SessionMessageInputOptions, reservation, environment resourcev4.Reference, preborrowed bool) (*SessionMessageInput, error) {
	if ctx == nil || messages == nil || reservation == environment {
		return nil, cryptov4.ErrConfiguration
	}
	charge, err := SessionMessageInputCharge(options)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := reservation.CheckSameEnvironment(environment); err != nil {
		return nil, err
	}
	var shared, owned resourcev4.Reference
	if preborrowed {
		owned, err = reservation.Take(charge)
		if err != nil {
			return nil, err
		}
		shared, err = environment.TakeBorrow()
		if err != nil {
			owned.Release()
			return nil, err
		}
	} else {
		shared, err = environment.Borrow()
		if err != nil {
			return nil, err
		}
		owned, err = reservation.Take(charge)
		if err != nil {
			shared.Release()
			return nil, err
		}
	}
	lifetime, cancel := context.WithCancelCause(context.Background())
	m := &sessionMessageInput{provider: messages, options: options, reservation: owned, environment: shared, parent: ctx, lifetime: lifetime, cancel: cancel,
		buffer: make([]byte, int(options.MaxFrame)+protocolv4.EnvelopePrefixSize), worker: true,
		writeToken: make(chan struct{}, 1), wake: make(chan struct{}, 1), stop: make(chan struct{}), done: make(chan struct{})}
	m.writeToken <- struct{}{}
	go m.lifecycle()
	return &SessionMessageInput{m}, nil
}

func messageFailure(err error) error {
	switch err {
	case nil:
		return cryptov4.ErrClosed
	case context.Canceled, context.DeadlineExceeded, io.EOF, cryptov4.ErrClosed, ErrSessionMessageFraming:
		return err
	case io.ErrShortBuffer, protocolv4.ErrPayloadTooLarge:
		return protocolv4.ErrPayloadTooLarge
	default:
		return ErrSessionMessageProvider
	}
}

func (m *sessionMessageInput) sealLocked(cause error) {
	if !m.closed {
		m.closed = true
		m.cause = messageFailure(cause)
		m.reservation.Seal()
		close(m.stop)
	}
}

func (m *sessionMessageInput) checkLocked(ctx context.Context) error {
	if m.closed {
		return m.cause
	}
	if ctx == nil {
		return cryptov4.ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		m.sealLocked(err)
		return m.cause
	}
	if err := m.reservation.Check(); err != nil {
		m.sealLocked(err)
		return err
	}
	if err := m.environment.Check(); err != nil {
		m.sealLocked(err)
		return err
	}
	return nil
}

func (m *sessionMessageInput) signalLocked() {
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

func (m *sessionMessageInput) lifecycle() {
	defer func() {
		m.mu.Lock()
		m.worker = false
		m.cleanupLocked()
		m.mu.Unlock()
	}()
	for {
		m.mu.Lock()
		parent := m.parent
		var readDone, writeDone <-chan struct{}
		read, write := m.readContext, m.writeContext
		readGeneration, writeGeneration := m.readGeneration, m.writeGeneration
		if read != nil {
			readDone = read.Done()
		}
		if write != nil {
			writeDone = write.Done()
		}
		m.mu.Unlock()
		var cause error
		var observed uint8
		select {
		case <-m.stop:
		case <-parent.Done():
			cause = parent.Err()
		case <-readDone:
			cause = read.Err()
			observed = 1
		case <-writeDone:
			cause = write.Err()
			observed = 2
		case <-m.wake:
			continue
		}
		m.mu.Lock()
		// READY cancels the initial context after its calls have returned.
		// An old observation must not close the transferred runtime owner.
		if observed == 1 && (!m.reading || m.readGeneration != readGeneration) || observed == 2 && (m.writeContext == nil || m.writeGeneration != writeGeneration) {
			m.mu.Unlock()
			continue
		}
		m.sealLocked(cause)
		cause, provider, cancel := m.cause, m.provider, m.cancel
		m.mu.Unlock()
		cancel(cause)
		_ = provider.Close()
		return
	}
}

func (m *sessionMessageInput) cleanupLocked() {
	if !m.closed || m.worker || m.reading || m.writers != 0 || m.complete {
		return
	}
	clear(m.buffer)
	m.buffer = nil
	m.offset, m.length = 0, 0
	m.provider, m.parent, m.lifetime, m.cancel = nil, nil, nil, nil
	m.complete = true
	close(m.done)
}

func (m *sessionMessageInput) beginRead(ctx context.Context) (InitialMessages, context.Context, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.checkLocked(ctx); err != nil {
		return nil, nil, err
	}
	if m.reading {
		return nil, nil, cryptov4.ErrCapacity
	}
	if m.readGeneration == math.MaxUint64 {
		return nil, nil, cryptov4.ErrCapacity
	}
	m.readGeneration++
	m.reading, m.readContext = true, ctx
	m.signalLocked()
	return m.provider, &sessionMessageCallContext{ctx, m.lifetime}, nil
}

func (m *sessionMessageInput) endRead() {
	m.mu.Lock()
	m.reading, m.readContext = false, nil
	m.signalLocked()
	m.cleanupLocked()
	m.mu.Unlock()
}

// ReadMessage uses the initial exchange's already reserved destination and cap.
// Its original phase/credential decoder validates those initial envelope bytes.
func (m *SessionMessageInput) ReadMessage(ctx context.Context, dst []byte) (int, error) {
	if m == nil || m.sessionMessageInput == nil || len(dst) < protocolv4.EnvelopePrefixSize {
		return 0, cryptov4.ErrConfiguration
	}
	provider, call, err := m.beginRead(ctx)
	if err != nil {
		return 0, err
	}
	defer m.endRead()
	n, err := provider.ReadMessage(call, dst)
	m.mu.Lock()
	defer m.mu.Unlock()
	if n < 0 || n > len(dst) {
		err = ErrSessionMessageFraming
	}
	if err != nil {
		m.sealLocked(err)
	}
	if err := m.checkLocked(ctx); err != nil {
		return 0, err
	}
	return n, nil
}

// Read validates the complete source message before exposing its prefix to the
// shared record reader. Subsequent reads consume only this validated message;
// one call never joins messages, and a fragmented envelope cannot borrow bytes
// from the next message. There is no read-ahead beyond the original caller.
func (m *SessionMessageInput) Read(dst []byte) (int, error) {
	if m == nil || m.sessionMessageInput == nil {
		return 0, cryptov4.ErrConfiguration
	}
	m.mu.Lock()
	ctx := m.parent
	m.mu.Unlock()
	provider, call, err := m.beginRead(ctx)
	if err != nil {
		return 0, err
	}
	defer m.endRead()
	if len(dst) == 0 {
		return 0, nil
	}
	if m.length == 0 {
		n, err := provider.ReadMessage(call, m.buffer)
		if err == nil {
			if n < 0 || n > len(m.buffer) {
				err = ErrSessionMessageFraming
			} else {
				err = m.validate(m.buffer[:n])
			}
		}
		m.mu.Lock()
		if err != nil {
			m.sealLocked(err)
		} else {
			m.length = n
		}
		m.mu.Unlock()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.checkLocked(ctx); err != nil {
		return 0, err
	}
	n := copy(dst, m.buffer[m.offset:m.length])
	m.offset += n
	if m.offset == m.length {
		clear(m.buffer[:m.length])
		m.offset, m.length = 0, 0
	}
	return n, nil
}

func (m *sessionMessageInput) validate(wire []byte) error {
	if len(wire) < protocolv4.EnvelopePrefixSize || uint64(len(wire)) > uint64(m.options.MaxFrame)+uint64(protocolv4.EnvelopePrefixSize) {
		return ErrSessionMessageFraming
	}
	length := uint64(binary.BigEndian.Uint32(wire[:4]))
	if length > uint64(m.options.MaxFrame) || length+uint64(protocolv4.EnvelopePrefixSize) != uint64(len(wire)) || wire[5] != 0 || wire[6] != 0 || wire[7] != 0 {
		return ErrSessionMessageFraming
	}
	switch protocolv4.FrameType(wire[4]) {
	case protocolv4.FrameRekey, protocolv4.FrameOpenStream, protocolv4.FrameStreamData, protocolv4.FrameStreamAck, protocolv4.FrameDatagram, protocolv4.FrameError, protocolv4.FrameClose, protocolv4.FrameGoAway, protocolv4.FramePing, protocolv4.FramePong:
		return nil
	default:
		return ErrSessionMessageFraming
	}
}

func (m *sessionMessageInput) write(ctx context.Context, wire []byte, runtime bool) (int, error) {
	m.mu.Lock()
	if err := m.checkLocked(ctx); err != nil {
		m.mu.Unlock()
		return 0, err
	}
	if len(wire) == 0 && runtime {
		m.mu.Unlock()
		return 0, nil
	}
	if len(wire) == 0 || runtime && m.validate(wire) != nil {
		m.sealLocked(ErrSessionMessageFraming)
		m.mu.Unlock()
		return 0, ErrSessionMessageFraming
	}
	if m.writers >= m.options.WriteSlots {
		m.mu.Unlock()
		return 0, cryptov4.ErrCapacity
	}
	m.writers++
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		m.writers--
		m.cleanupLocked()
		m.mu.Unlock()
	}()
	select {
	case <-m.stop:
		m.mu.Lock()
		err := m.cause
		m.mu.Unlock()
		return 0, err
	case <-ctx.Done():
		m.mu.Lock()
		m.sealLocked(ctx.Err())
		err := m.cause
		m.mu.Unlock()
		return 0, err
	case <-m.writeToken:
	}
	defer func() { m.writeToken <- struct{}{} }()
	m.mu.Lock()
	if err := m.checkLocked(ctx); err != nil {
		m.mu.Unlock()
		return 0, err
	}
	if m.writeGeneration == math.MaxUint64 {
		m.mu.Unlock()
		return 0, cryptov4.ErrCapacity
	}
	m.writeGeneration++
	m.writeContext = ctx
	m.signalLocked()
	provider, lifetime := m.provider, m.lifetime
	m.mu.Unlock()
	err := provider.WriteMessage(&sessionMessageCallContext{ctx, lifetime}, wire)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.writeContext = nil
	m.signalLocked()
	n := 0
	if err != nil {
		m.sealLocked(err)
	} else {
		n = len(wire) // Preserve a complete physical handoff even after Close.
	}
	if err := m.checkLocked(ctx); err != nil {
		return n, err
	}
	return n, nil
}

func (m *SessionMessageInput) WriteMessage(ctx context.Context, wire []byte) error {
	if m == nil || m.sessionMessageInput == nil {
		return cryptov4.ErrConfiguration
	}
	_, err := m.write(ctx, wire, false)
	return err
}

func (m *SessionMessageInput) Write(wire []byte) (int, error) {
	if m == nil || m.sessionMessageInput == nil {
		return 0, cryptov4.ErrConfiguration
	}
	m.mu.Lock()
	ctx := m.parent
	m.mu.Unlock()
	return m.write(ctx, wire, true)
}

// InterruptRead and Close only seal/signal. The one admitted lifecycle worker
// cancels provider contexts before making the original potentially blocking
// Close call. Neither method waits for a provider or starts replacement work.
func (m *SessionMessageInput) InterruptRead() { _ = m.Close() }

func (m *SessionMessageInput) Close() error {
	if m == nil || m.sessionMessageInput == nil {
		return cryptov4.ErrConfiguration
	}
	m.mu.Lock()
	m.sealLocked(nil)
	m.mu.Unlock()
	return nil
}

func (m *SessionMessageInput) WaitCleanup(ctx context.Context) error {
	if m == nil || m.sessionMessageInput == nil || ctx == nil {
		return cryptov4.ErrConfiguration
	}
	select {
	case <-m.done:
		return nil
	default:
	}
	select {
	case <-m.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (m *SessionMessageInput) Retire() error {
	if m == nil || m.sessionMessageInput == nil {
		return cryptov4.ErrConfiguration
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.complete {
		return cryptov4.ErrCapacity
	}
	if !m.retired {
		m.reservation.Release()
		m.environment.Release()
		m.reservation, m.environment = resourcev4.Reference{}, resourcev4.Reference{}
		m.retired = true
	}
	return nil
}

var _ RuntimeInput = (*SessionMessageInput)(nil)
var _ io.Writer = (*SessionMessageInput)(nil)
var _ InitialMessages = (*SessionMessageInput)(nil)
