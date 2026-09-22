package websocket

import (
	"bufio"
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	ws "github.com/gorilla/websocket"
)

// Messages is a copyable handle to one canonical connection owner. Close
// requests immediate shutdown; WaitCleanup observes actual socket close and
// all original read/write/factory calls returning. Retire then returns the
// reservation and shared Environment borrow exactly once.
type Messages struct{ *owner }

type owner struct {
	mu                                sync.Mutex
	options                           Options
	reservation, environment          resourcev4.Reference
	conn                              *ws.Conn
	transport                         *ownedConn
	handshake                         *handshakeConn
	lifetime                          context.Context
	cancel                            context.CancelCauseFunc
	prepareCtx, readCtx, writeCtx     context.Context
	readGeneration, writeGeneration   uint64
	preparing, reading, writing       bool
	closed, worker, complete, retired bool
	closeErr                          error
	wake, stop, done                  chan struct{}
	controlWindow                     time.Time
	controls                          uint32
	checking                          bool
	prepareBytes                      uint64
	consumer, consumerTLS13           bool
	acceptedEndpoint                  protocolv4.AcceptedWebSocketEndpoint
	checkAcceptedRoute                func(protocolv4.AcceptedWebSocketEndpoint, *protocolv4.SignedMap, uint64, protocolv4.HelloPolicy) error
}

// ConnectionGuarantees uses the original completed dial/upgrade, never URL
// text, a requested option or another connection's TLS state. Route policy is
// checked by the same trusted source/accepted adapter before admission.
func (m *Messages) ConnectionGuarantees() (protocolv4.V4ConnectionGuarantees, error) {
	if m == nil || m.owner == nil {
		return protocolv4.V4ConnectionGuarantees{}, resourcev4.ErrOwner
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.retired || m.preparing || m.conn == nil {
		return protocolv4.V4ConnectionGuarantees{}, resourcev4.ErrClosed
	}
	class := "accepted_websocket"
	if m.consumer {
		class = "native_websocket_loopback"
		if m.consumerTLS13 {
			class = "native_websocket_tls13"
		}
	}
	g, ok := protocolv4.ConnectionAssurance(class)
	if !ok {
		return g, resourcev4.ErrConfiguration
	}
	return g, nil
}

type callContext struct {
	context.Context
	lifetime context.Context
	deadline time.Time
}

func (c *callContext) Done() <-chan struct{}       { return c.lifetime.Done() }
func (c *callContext) Err() error                  { return c.lifetime.Err() }
func (c *callContext) Deadline() (time.Time, bool) { return c.deadline, true }
func (c *callContext) Value(key any) any {
	if value := c.lifetime.Value(key); value != nil {
		return value
	}
	return c.Context.Value(key)
}

func newOwner(ctx context.Context, o Options, reservation, environment resourcev4.Reference) (*owner, error) {
	charge, err := Charge(o)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if reservation == environment {
		return nil, resourcev4.ErrOwner
	}
	if err := reservation.CheckSameEnvironment(environment); err != nil {
		return nil, err
	}
	shared, err := environment.Borrow()
	if err != nil {
		return nil, err
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		shared.Release()
		return nil, err
	}
	lifetime, cancel := context.WithCancelCause(context.Background())
	m := &owner{options: o, reservation: owned, environment: shared, lifetime: lifetime, cancel: cancel,
		prepareCtx: ctx, preparing: true, worker: true, wake: make(chan struct{}, 1), stop: make(chan struct{}), done: make(chan struct{})}
	go m.lifecycle()
	return m, nil
}

func (m *owner) signalLocked() {
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

func (m *owner) sealLocked() {
	if !m.closed {
		m.closed = true
		m.reservation.Seal()
		close(m.stop)
	}
}

func (m *owner) lifecycle() {
	defer func() { m.mu.Lock(); m.worker = false; m.cleanupLocked(); m.mu.Unlock() }()
	for {
		m.mu.Lock()
		prepare, read, write := m.prepareCtx, m.readCtx, m.writeCtx
		rg, wg := m.readGeneration, m.writeGeneration
		var pd, rd, wd <-chan struct{}
		if prepare != nil {
			pd = prepare.Done()
		}
		if read != nil {
			rd = read.Done()
		}
		if write != nil {
			wd = write.Done()
		}
		m.mu.Unlock()
		var observed uint8
		select {
		case <-m.stop:
		case <-pd:
			observed = 1
		case <-rd:
			observed = 2
		case <-wd:
			observed = 3
		case <-m.wake:
			continue
		}
		m.mu.Lock()
		if observed == 1 && !m.preparing || observed == 2 && (!m.reading || m.readGeneration != rg) || observed == 3 && (!m.writing || m.writeGeneration != wg) {
			m.mu.Unlock()
			continue
		}
		m.sealLocked()
		transport, cancel := m.transport, m.cancel
		m.mu.Unlock()
		cancel(net.ErrClosed)
		if transport != nil {
			err := transport.Close()
			m.mu.Lock()
			m.closeErr = err
			m.mu.Unlock()
		}
		return
	}
}

func (m *owner) cleanupLocked() {
	if !m.closed || m.worker || m.preparing || m.reading || m.writing || m.checking || m.complete {
		return
	}
	m.conn, m.transport = nil, nil
	m.handshake = nil
	m.checkAcceptedRoute = nil
	m.acceptedEndpoint = protocolv4.AcceptedWebSocketEndpoint{}
	m.prepareCtx, m.readCtx, m.writeCtx, m.lifetime, m.cancel = nil, nil, nil, nil, nil
	m.complete = true
	close(m.done)
}

func (m *owner) finishPrepare(success bool) {
	m.mu.Lock()
	m.preparing, m.prepareCtx = false, nil
	if !success {
		m.sealLocked()
	}
	m.signalLocked()
	m.cleanupLocked()
	m.mu.Unlock()
	if !success {
		// The factory owns its failed prepare until the original transport and
		// worker have returned. No cleanup tail escapes without a charged owner.
		<-m.done
		_ = (&Messages{m}).Retire()
	}
}

func (m *owner) attach(conn net.Conn) (net.Conn, error) {
	owned := &ownedConn{Conn: conn}
	if m.prepareBytes != 0 {
		owned.prepareRemaining.Store(int64(m.prepareBytes))
		owned.preparing.Store(true)
	}
	m.mu.Lock()
	if m.closed || m.transport != nil {
		m.mu.Unlock()
		_ = owned.Close()
		return nil, net.ErrClosed
	}
	m.transport = owned
	m.mu.Unlock()
	return owned, nil
}

func (m *owner) httpTransport(conn net.Conn) (net.Conn, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil, net.ErrClosed
	}
	m.handshake = &handshakeConn{Conn: conn, active: true, remaining: int64(m.options.HandshakeBytes)}
	return m.handshake, nil
}

func (m *owner) install(conn *ws.Conn, ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if m.closed {
		return net.ErrClosed
	}
	if err := m.environment.Check(); err != nil {
		return err
	}
	if m.handshake != nil {
		m.handshake.active = false
	}
	if m.transport != nil {
		m.transport.preparing.Store(false)
	}
	conn.SetReadLimit(int64(m.options.MaxMessageBytes))
	conn.EnableWriteCompression(false)
	conn.SetPongHandler(func(string) error { return m.control() })
	conn.SetPingHandler(func(data string) error {
		if err := m.control(); err != nil {
			return err
		}
		m.mu.Lock()
		ctx := m.readCtx
		m.mu.Unlock()
		if ctx == nil {
			return net.ErrClosed
		}
		return conn.WriteControl(ws.PongMessage, []byte(data), operationDeadline(ctx, m.options.MessageTimeout))
	})
	conn.SetCloseHandler(func(int, string) error { return nil })
	m.conn = conn
	return nil
}

// Control handlers run in Gorilla's sole reader. A fixed one-second window
// bounds native ping/pong processing independently of Flowersec liveness.
func (m *owner) control() error {
	now := time.Now()
	if m.controlWindow.IsZero() || now.Sub(m.controlWindow) >= time.Second {
		m.controlWindow, m.controls = now, 0
	}
	if m.controls >= m.options.MaxControlsPerSecond {
		return ErrControlRate
	}
	m.controls++
	return nil
}

func (m *owner) begin(ctx context.Context, writing bool) (*ws.Conn, error) {
	if ctx == nil {
		return nil, resourcev4.ErrConfiguration
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.preparing || m.conn == nil {
		return nil, net.ErrClosed
	}
	if m.checking {
		return nil, ErrConcurrent
	}
	if err := ctx.Err(); err != nil {
		m.sealLocked()
		return nil, err
	}
	if err := m.reservation.Check(); err != nil {
		m.sealLocked()
		return nil, err
	}
	if err := m.environment.Check(); err != nil {
		m.sealLocked()
		return nil, err
	}
	if writing {
		if m.writing {
			return nil, ErrConcurrent
		}
		m.writing, m.writeCtx = true, ctx
		m.writeGeneration++
	} else {
		if m.reading {
			return nil, ErrConcurrent
		}
		m.reading, m.readCtx = true, ctx
		m.readGeneration++
	}
	m.signalLocked()
	return m.conn, nil
}

func (m *owner) finish(ctx context.Context, writing bool, err error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	err = preferContext(ctx, err)
	if writing {
		m.writing, m.writeCtx = false, nil
	} else {
		m.reading, m.readCtx = false, nil
	}
	if err != nil {
		m.sealLocked()
	}
	m.signalLocked()
	m.cleanupLocked()
	return err
}

func (m *Messages) Close() error {
	if m == nil || m.owner == nil {
		return nil
	}
	m.mu.Lock()
	m.sealLocked()
	m.mu.Unlock()
	return nil
}

func (m *Messages) WaitCleanup(ctx context.Context) error {
	if ctx == nil {
		return resourcev4.ErrConfiguration
	}
	if m == nil || m.owner == nil {
		return nil
	}
	select {
	case <-m.done:
		return m.closeErr
	default:
	}
	select {
	case <-m.done:
		return m.closeErr
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (m *Messages) Retire() error {
	if m == nil || m.owner == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.complete {
		return resourcev4.ErrOwner
	}
	if !m.retired {
		m.retired = true
		m.reservation.Release()
		m.environment.Release()
	}
	return nil
}

// The wrapper owns the one physical close, including Gorilla's upgrade-error
// paths and TLS handshake cancellation. TLS and HTTP parsing use wrappers of
// this same physical owner, so cancellation cannot leave an uncharged socket.
type ownedConn struct {
	net.Conn
	once             sync.Once
	closeErr         error
	preparing        atomic.Bool
	prepareRemaining atomic.Int64
}

var ErrPrepareBytes = errors.New("websocketv4: preparation byte budget exhausted")

func (c *ownedConn) prepareAllowance(n int) (int, bool) {
	if !c.preparing.Load() {
		return n, false
	}
	for {
		remaining := c.prepareRemaining.Load()
		allowed := min(int64(n), remaining)
		if c.prepareRemaining.CompareAndSwap(remaining, remaining-allowed) {
			return int(allowed), true
		}
	}
}

func (c *ownedConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	allowed, limited := c.prepareAllowance(len(p))
	if allowed == 0 {
		return 0, ErrPrepareBytes
	}
	n, err := c.Conn.Read(p[:allowed])
	if limited {
		c.prepareRemaining.Add(int64(allowed - n))
	}
	return n, err
}

func (c *ownedConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	allowed, limited := c.prepareAllowance(len(p))
	if allowed == 0 {
		return 0, ErrPrepareBytes
	}
	n, err := c.Conn.Write(p[:allowed])
	if limited {
		c.prepareRemaining.Add(int64(allowed - n))
	}
	if err == nil && n < len(p) && allowed < len(p) {
		err = ErrPrepareBytes
	}
	return n, err
}

func (c *ownedConn) Close() error {
	c.once.Do(func() { c.closeErr = c.Conn.Close() })
	return c.closeErr
}

// HTTP response bytes are bounded after TLS decrypts. Upgrade completion
// switches to the fixed WebSocket I/O buffer and per-message read limit.
type handshakeConn struct {
	net.Conn
	active    bool
	remaining int64
}

func (c *handshakeConn) Read(p []byte) (int, error) {
	if !c.active {
		return c.Conn.Read(p)
	}
	if c.remaining <= 0 {
		return 0, ErrHeaderLimit
	}
	if int64(len(p)) > c.remaining {
		p = p[:c.remaining]
	}
	n, err := c.Conn.Read(p)
	c.remaining -= int64(n)
	return n, err
}

type upgradeWriter struct {
	http.ResponseWriter
	owner *owner
}

func (w *upgradeWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, resourcev4.ErrConfiguration
	}
	conn, buffers, err := h.Hijack()
	if err != nil {
		return nil, nil, err
	}
	owned, err := w.owner.attach(conn)
	if err != nil {
		return nil, nil, err
	}
	return owned, buffers, nil
}
