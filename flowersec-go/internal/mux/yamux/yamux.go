package yamux

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/defaults"
	libyamux "github.com/libp2p/go-yamux/v5"
)

// ErrResourceExhausted indicates a configured multiplexing resource limit was reached.
var ErrResourceExhausted = errors.New("yamux resource exhausted")

// ErrLivenessTimeout indicates that an automatic acknowledged probe failed.
var ErrLivenessTimeout = errors.New("yamux liveness timeout")

// ErrStreamReset identifies a Yamux stream terminated by RST.
var ErrStreamReset = libyamux.ErrStreamReset

const (
	DefaultMaxActiveStreams            = defaults.YamuxMaxActiveStreams
	DefaultMaxInboundStreams           = defaults.YamuxMaxInboundStreams
	DefaultMaxFrameBytes               = defaults.YamuxMaxFrameBytes
	DefaultPreferredOutboundFrameBytes = defaults.YamuxPreferredOutboundFrameBytes
	DefaultMaxStreamWriteQueueBytes    = defaults.YamuxMaxStreamWriteQueueBytes
	DefaultMaxStreamReceiveBytes       = defaults.YamuxMaxStreamReceiveBytes
	DefaultMaxSessionReceiveBytes      = defaults.YamuxMaxSessionReceiveBytes
	disabledRTTMeasureInterval         = time.Duration(1<<63 - 1)
)

// YamuxLimits bounds multiplexing concurrency, frame sizes, and buffered memory.
type YamuxLimits struct {
	MaxActiveStreams            uint32
	MaxInboundStreams           uint32
	MaxFrameBytes               int
	PreferredOutboundFrameBytes int
	MaxStreamWriteQueueBytes    int
	MaxStreamReceiveBytes       int
	MaxSessionReceiveBytes      int
}

// LivenessOptions configures ACK-based session probes. A zero value disables automatic probes.
type LivenessOptions struct {
	Interval time.Duration
	Timeout  time.Duration
}

// DefaultLimits returns the hardened high-level session limits.
func DefaultLimits() YamuxLimits {
	return YamuxLimits{
		MaxActiveStreams:            DefaultMaxActiveStreams,
		MaxInboundStreams:           DefaultMaxInboundStreams,
		MaxFrameBytes:               DefaultMaxFrameBytes,
		PreferredOutboundFrameBytes: DefaultPreferredOutboundFrameBytes,
		MaxStreamWriteQueueBytes:    DefaultMaxStreamWriteQueueBytes,
		MaxStreamReceiveBytes:       DefaultMaxStreamReceiveBytes,
		MaxSessionReceiveBytes:      DefaultMaxSessionReceiveBytes,
	}
}

// ValidateLimits fills omitted fields with defaults and validates the result.
func ValidateLimits(limits YamuxLimits) (YamuxLimits, error) {
	return normalizeLimits(limits)
}

// Session is Flowersec's multiplexed session. Its implementation is intentionally private.
type Session struct {
	inner                    *libyamux.Session
	maxStreamWriteQueueBytes int
	writeTracker             *sessionWriteTracker
	probeMu                  sync.Mutex
	probe                    *probeCall
	livenessFailures         chan error
	livenessMu               sync.Mutex
	livenessTimer            *time.Timer
	livenessDone             bool
}

// Stream is a multiplexed byte stream.
type Stream struct {
	inner       *libyamux.Stream
	writeMu     sync.Mutex
	writeBudget *streamWriteBudget
}

type probeCall struct {
	done chan struct{}
	rtt  time.Duration
	err  error
}

func (s *Stream) Read(p []byte) (int, error) { return s.inner.Read(p) }
func (s *Stream) Write(p []byte) (int, error) {
	if !s.writeBudget.reserve(len(p)) {
		return 0, fmt.Errorf("%w: stream write queue limit exceeded", ErrResourceExhausted)
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	n, err := s.inner.Write(p)
	if unsent := len(p) - n; unsent > 0 {
		s.writeBudget.release(unsent)
	}
	return n, err
}
func (s *Stream) Close() error                       { return s.inner.Close() }
func (s *Stream) CloseWrite() error                  { return s.inner.CloseWrite() }
func (s *Stream) Reset() error                       { return s.inner.Reset() }
func (s *Stream) SetDeadline(t time.Time) error      { return s.inner.SetDeadline(t) }
func (s *Stream) SetReadDeadline(t time.Time) error  { return s.inner.SetReadDeadline(t) }
func (s *Stream) SetWriteDeadline(t time.Time) error { return s.inner.SetWriteDeadline(t) }

// OpenStream opens an outbound stream.
func (s *Session) OpenStream() (*Stream, error) {
	return s.OpenStreamContext(context.Background())
}

// OpenStreamContext opens an outbound stream and honors context cancellation while opening it.
func (s *Session) OpenStreamContext(ctx context.Context) (*Stream, error) {
	if s == nil || s.inner == nil {
		return nil, io.ErrClosedPipe
	}
	if ctx == nil {
		ctx = context.Background()
	}
	stream, err := s.inner.OpenStream(ctx)
	if err != nil {
		return nil, err
	}
	return s.wrapStream(stream), nil
}

// AcceptStream waits for an inbound stream.
func (s *Session) AcceptStream() (*Stream, error) {
	if s == nil || s.inner == nil {
		return nil, io.ErrClosedPipe
	}
	stream, err := s.inner.AcceptStream()
	if err != nil {
		return nil, err
	}
	return s.wrapStream(stream), nil
}

func (s *Session) wrapStream(stream *libyamux.Stream) *Stream {
	budget := &streamWriteBudget{
		max:      s.maxStreamWriteQueueBytes,
		streamID: stream.StreamID(),
		tracker:  s.writeTracker,
	}
	return &Stream{inner: stream, writeBudget: budget}
}

type streamWriteBudget struct {
	mu       sync.Mutex
	pending  int
	max      int
	streamID uint32
	tracker  *sessionWriteTracker
}

func (b *streamWriteBudget) reserve(size int) bool {
	if size == 0 {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if size > b.max-b.pending {
		return false
	}
	if b.pending == 0 {
		b.tracker.register(b.streamID, b)
	}
	b.pending += size
	return true
}

func (b *streamWriteBudget) release(size int) {
	if size == 0 {
		return
	}
	b.mu.Lock()
	b.pending -= size
	if b.pending == 0 {
		b.tracker.unregister(b.streamID, b)
	}
	b.mu.Unlock()
}

type sessionWriteTracker struct {
	mu      sync.RWMutex
	streams map[uint32]*streamWriteBudget
}

func newSessionWriteTracker() *sessionWriteTracker {
	return &sessionWriteTracker{streams: make(map[uint32]*streamWriteBudget)}
}

func (t *sessionWriteTracker) register(streamID uint32, budget *streamWriteBudget) {
	t.mu.Lock()
	t.streams[streamID] = budget
	t.mu.Unlock()
}

func (t *sessionWriteTracker) unregister(streamID uint32, budget *streamWriteBudget) {
	t.mu.Lock()
	if t.streams[streamID] == budget {
		delete(t.streams, streamID)
	}
	t.mu.Unlock()
}

func (t *sessionWriteTracker) release(streamID uint32, size int) {
	t.mu.RLock()
	budget := t.streams[streamID]
	t.mu.RUnlock()
	if budget != nil {
		budget.release(size)
	}
}

// Probe sends a yamux ping and waits for its ACK or context cancellation.
func (s *Session) Probe(ctx context.Context) (time.Duration, error) {
	if s == nil || s.inner == nil {
		return 0, io.ErrClosedPipe
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	probe := s.sharedProbe()
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-probe.done:
		if errors.Is(probe.err, libyamux.ErrTimeout) {
			return 0, fmt.Errorf("%w: %v", ErrLivenessTimeout, probe.err)
		}
		return probe.rtt, probe.err
	}
}

func (s *Session) sharedProbe() *probeCall {
	s.probeMu.Lock()
	defer s.probeMu.Unlock()
	if s.probe != nil {
		return s.probe
	}
	probe := &probeCall{done: make(chan struct{})}
	s.probe = probe
	go func() {
		probe.rtt, probe.err = s.inner.Ping()
		s.probeMu.Lock()
		close(probe.done)
		if s.probe == probe {
			s.probe = nil
		}
		s.probeMu.Unlock()
	}()
	return probe
}

// LivenessFailures reports the first automatic probe failure. The channel closes with the session.
func (s *Session) LivenessFailures() <-chan error {
	if s == nil || s.inner == nil || s.livenessFailures == nil {
		closed := make(chan error)
		close(closed)
		return closed
	}
	return s.livenessFailures
}

// Close closes the session and all of its streams.
func (s *Session) Close() error {
	if s == nil || s.inner == nil {
		return nil
	}
	err := s.inner.Close()
	s.finishLiveness(nil)
	return err
}

// CloseChan is closed when the session terminates.
func (s *Session) CloseChan() <-chan struct{} {
	if s == nil || s.inner == nil {
		closed := make(chan struct{})
		close(closed)
		return closed
	}
	return s.inner.CloseChan()
}

// NewClient creates a client-side session.
func NewClient(conn net.Conn, limits YamuxLimits, liveness LivenessOptions) (*Session, error) {
	return newSession(conn, limits, liveness, true)
}

// NewServer creates a server-side session.
func NewServer(conn net.Conn, limits YamuxLimits, liveness LivenessOptions) (*Session, error) {
	return newSession(conn, limits, liveness, false)
}

func newSession(conn net.Conn, limits YamuxLimits, liveness LivenessOptions, client bool) (*Session, error) {
	if conn == nil {
		return nil, errors.New("yamux connection must be non-nil")
	}
	limits, err := normalizeLimits(limits)
	if err != nil {
		return nil, err
	}
	if liveness.Interval < 0 || liveness.Timeout < 0 {
		return nil, errors.New("yamux liveness durations must be >= 0")
	}
	if (liveness.Interval == 0) != (liveness.Timeout == 0) {
		return nil, errors.New("yamux liveness interval and timeout must both be set")
	}

	cfg := libyamux.DefaultConfig()
	cfg.LogOutput = io.Discard
	cfg.AcceptBacklog = int(limits.MaxInboundStreams)
	cfg.MaxIncomingStreams = limits.MaxInboundStreams
	cfg.InitialStreamWindowSize = uint32(limits.MaxStreamReceiveBytes)
	cfg.MaxStreamWindowSize = uint32(limits.MaxStreamReceiveBytes)
	cfg.MaxMessageSize = uint32(limits.PreferredOutboundFrameBytes)
	cfg.EnableKeepAlive = false
	cfg.MeasureRTTInterval = disabledRTTMeasureInterval
	if liveness.Interval > 0 {
		cfg.ConnectionWriteTimeout = liveness.Timeout
	}

	manager := newSessionMemoryManager(limits)
	writeTracker := newSessionWriteTracker()
	factory := manager.newStream
	conn = &frameLimitConn{
		Conn:          conn,
		maxFrameBytes: uint32(limits.MaxFrameBytes),
		writeTracker:  writeTracker,
	}
	var inner *libyamux.Session
	if client {
		inner, err = libyamux.Client(conn, cfg, factory)
	} else {
		inner, err = libyamux.Server(conn, cfg, factory)
	}
	if err != nil {
		return nil, err
	}
	session := &Session{
		inner:                    inner,
		maxStreamWriteQueueBytes: limits.MaxStreamWriteQueueBytes,
		writeTracker:             writeTracker,
	}
	if liveness.Interval > 0 {
		session.livenessFailures = make(chan error, 1)
		session.scheduleLiveness(liveness)
	}
	return session, nil
}

func (s *Session) scheduleLiveness(options LivenessOptions) {
	s.livenessMu.Lock()
	defer s.livenessMu.Unlock()
	if s.livenessDone {
		return
	}
	s.livenessTimer = time.AfterFunc(options.Interval, func() {
		s.runLivenessProbe(options)
	})
}

func (s *Session) runLivenessProbe(options LivenessOptions) {
	select {
	case <-s.inner.CloseChan():
		s.finishLiveness(nil)
		return
	default:
	}
	_, err := s.inner.Ping()
	if err != nil {
		if errors.Is(err, libyamux.ErrTimeout) {
			err = fmt.Errorf("%w: %v", ErrLivenessTimeout, err)
		}
		s.finishLiveness(fmt.Errorf("%w: %v", ErrLivenessTimeout, err))
		_ = s.inner.Close()
		return
	}
	s.scheduleLiveness(options)
}

func (s *Session) finishLiveness(err error) {
	s.livenessMu.Lock()
	defer s.livenessMu.Unlock()
	if s.livenessDone || s.livenessFailures == nil {
		return
	}
	s.livenessDone = true
	if s.livenessTimer != nil {
		s.livenessTimer.Stop()
		s.livenessTimer = nil
	}
	if err != nil {
		s.livenessFailures <- err
	}
	close(s.livenessFailures)
}

func normalizeLimits(limits YamuxLimits) (YamuxLimits, error) {
	defaults := DefaultLimits()
	if limits.MaxActiveStreams == 0 {
		limits.MaxActiveStreams = defaults.MaxActiveStreams
	}
	if limits.MaxInboundStreams == 0 {
		limits.MaxInboundStreams = defaults.MaxInboundStreams
	}
	if limits.MaxFrameBytes == 0 {
		limits.MaxFrameBytes = defaults.MaxFrameBytes
	}
	if limits.PreferredOutboundFrameBytes == 0 {
		limits.PreferredOutboundFrameBytes = defaults.PreferredOutboundFrameBytes
	}
	if limits.MaxStreamWriteQueueBytes == 0 {
		limits.MaxStreamWriteQueueBytes = defaults.MaxStreamWriteQueueBytes
	}
	if limits.MaxStreamReceiveBytes == 0 {
		limits.MaxStreamReceiveBytes = defaults.MaxStreamReceiveBytes
	}
	if limits.MaxSessionReceiveBytes == 0 {
		limits.MaxSessionReceiveBytes = defaults.MaxSessionReceiveBytes
	}
	if limits.MaxActiveStreams == 0 || limits.MaxInboundStreams == 0 {
		return YamuxLimits{}, errors.New("yamux stream limits must be > 0")
	}
	if limits.MaxInboundStreams > limits.MaxActiveStreams {
		return YamuxLimits{}, errors.New("yamux max inbound streams must not exceed max active streams")
	}
	if limits.MaxFrameBytes < 1024 || limits.PreferredOutboundFrameBytes < 1024 {
		return YamuxLimits{}, errors.New("yamux frame limits must be >= 1024")
	}
	if limits.PreferredOutboundFrameBytes > limits.MaxFrameBytes {
		return YamuxLimits{}, errors.New("yamux preferred outbound frame bytes must not exceed max frame bytes")
	}
	if limits.MaxFrameBytes > limits.MaxStreamReceiveBytes {
		return YamuxLimits{}, errors.New("yamux max frame bytes must not exceed max stream receive bytes")
	}
	if limits.MaxStreamReceiveBytes < DefaultMaxStreamReceiveBytes {
		return YamuxLimits{}, fmt.Errorf("yamux max stream receive bytes must be >= %d", DefaultMaxStreamReceiveBytes)
	}
	if limits.MaxStreamReceiveBytes > limits.MaxSessionReceiveBytes {
		return YamuxLimits{}, errors.New("yamux max stream receive bytes must not exceed max session receive bytes")
	}
	return limits, nil
}

type frameLimitConn struct {
	net.Conn
	mu                 sync.Mutex
	writeMu            sync.Mutex
	maxFrameBytes      uint32
	writeTracker       *sessionWriteTracker
	header             [12]byte
	headerOffset       int
	bodyRemaining      uint32
	writeHeader        [12]byte
	writeHeaderOffset  int
	writeBodyRemaining uint32
	writeStreamID      uint32
}

func (c *frameLimitConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	n, err := c.Conn.Write(p)
	c.trackWrittenData(p[:n])
	return n, err
}

func (c *frameLimitConn) trackWrittenData(p []byte) {
	for len(p) > 0 {
		if c.writeHeaderOffset < len(c.writeHeader) {
			copied := copy(c.writeHeader[c.writeHeaderOffset:], p)
			c.writeHeaderOffset += copied
			p = p[copied:]
			if c.writeHeaderOffset < len(c.writeHeader) {
				return
			}
			if c.writeHeader[1] != 0 {
				c.writeHeaderOffset = 0
				continue
			}
			c.writeStreamID = binary.BigEndian.Uint32(c.writeHeader[4:8])
			c.writeBodyRemaining = binary.BigEndian.Uint32(c.writeHeader[8:12])
			if c.writeBodyRemaining == 0 {
				c.writeHeaderOffset = 0
				continue
			}
		}

		written := len(p)
		if uint32(written) > c.writeBodyRemaining {
			written = int(c.writeBodyRemaining)
		}
		if c.writeTracker != nil {
			c.writeTracker.release(c.writeStreamID, written)
		}
		c.writeBodyRemaining -= uint32(written)
		p = p[written:]
		if c.writeBodyRemaining == 0 {
			c.writeHeaderOffset = 0
		}
	}
}

func (c *frameLimitConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	if c.headerOffset == len(c.header) && c.bodyRemaining == 0 {
		c.headerOffset = 0
	}
	if c.headerOffset < len(c.header) {
		if c.headerOffset == 0 {
			if _, err := io.ReadFull(c.Conn, c.header[:]); err != nil {
				return 0, err
			}
			if c.header[1] == 0 {
				c.bodyRemaining = binary.BigEndian.Uint32(c.header[8:12])
				if c.bodyRemaining > c.maxFrameBytes {
					return 0, fmt.Errorf("%w: yamux frame length %d exceeds limit %d", ErrResourceExhausted, c.bodyRemaining, c.maxFrameBytes)
				}
			}
		}
		n := copy(p, c.header[c.headerOffset:])
		c.headerOffset += n
		return n, nil
	}
	if uint32(len(p)) > c.bodyRemaining {
		p = p[:c.bodyRemaining]
	}
	n, err := c.Conn.Read(p)
	c.bodyRemaining -= uint32(n)
	if c.bodyRemaining == 0 {
		c.headerOffset = 0
	}
	return n, err
}

type sessionMemoryManager struct {
	mu           sync.Mutex
	maxStreams   uint32
	active       uint32
	maxStream    int
	maxSession   int
	sessionBytes int
}

func newSessionMemoryManager(limits YamuxLimits) *sessionMemoryManager {
	return &sessionMemoryManager{
		maxStreams: limits.MaxActiveStreams,
		maxStream:  limits.MaxStreamReceiveBytes,
		maxSession: limits.MaxSessionReceiveBytes,
	}
}

func (m *sessionMemoryManager) newStream() (libyamux.MemoryManager, error) {
	return &streamMemoryManager{session: m}, nil
}

type streamMemoryManager struct {
	session *sessionMemoryManager
	bytes   int
	done    bool
	active  bool
}

func (m *streamMemoryManager) ReserveMemory(size int, _ uint8) error {
	if size < 0 {
		return errors.New("yamux cannot reserve negative memory")
	}
	m.session.mu.Lock()
	defer m.session.mu.Unlock()
	if m.done {
		return errors.New("yamux stream memory scope is closed")
	}
	activating := !m.active
	if activating {
		if m.session.active >= m.session.maxStreams {
			return fmt.Errorf("%w: active stream limit exceeded", ErrResourceExhausted)
		}
	}
	if m.bytes+size > m.session.maxStream {
		return fmt.Errorf("%w: stream receive memory limit exceeded", ErrResourceExhausted)
	}
	if m.session.sessionBytes+size > m.session.maxSession {
		return fmt.Errorf("%w: session receive memory limit exceeded", ErrResourceExhausted)
	}
	if activating {
		m.session.active++
		m.active = true
	}
	m.bytes += size
	m.session.sessionBytes += size
	return nil
}

func (m *streamMemoryManager) ReleaseMemory(size int) {
	if size <= 0 {
		return
	}
	m.session.mu.Lock()
	defer m.session.mu.Unlock()
	if size > m.bytes {
		size = m.bytes
	}
	m.bytes -= size
	m.session.sessionBytes -= size
}

func (m *streamMemoryManager) Done() {
	m.session.mu.Lock()
	defer m.session.mu.Unlock()
	if m.done {
		return
	}
	m.done = true
	m.session.sessionBytes -= m.bytes
	m.bytes = 0
	if m.active && m.session.active > 0 {
		m.session.active--
	}
}
