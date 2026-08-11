package websocket

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier"
	fsyamux "github.com/floegence/flowersec/flowersec-go/v2/internal/mux/yamux"
	gorillaws "github.com/gorilla/websocket"
)

var (
	ErrUnexpectedInitialMessage = errors.New("unexpected WebSocket message before carrier activation")
	ErrInvalidInitialMessage    = errors.New("invalid initial WebSocket message")
	ErrPendingServerState       = errors.New("invalid pending WebSocket server state")
)

type pendingState uint8

const (
	pendingAwaitingInitial pendingState = iota
	pendingWaiting
	pendingResponding
	pendingActivating
	pendingActive
	pendingRejected
	pendingClosed
)

type initialMessageResult struct {
	raw []byte
	err error
}

// PendingServer owns one server-side WebSocket from a bounded initial binary
// exchange through the hop Yamux session. It does not interpret Flowersec
// admission bytes; the topology layer decides whether the response activates
// the carrier.
type PendingServer struct {
	raw    *gorillaws.Conn
	limits fsyamux.YamuxLimits
	writer *serializedWebSocketWriter

	ctx    context.Context
	cancel context.CancelCauseFunc

	stateMu           sync.Mutex
	state             pendingState
	responseSent      bool
	responseStarted   bool
	activationStarted bool
	session           *Session

	initialMessage      chan initialMessageResult
	initialMessageOnce  sync.Once
	receiveUsed         atomic.Bool
	pumpDone            chan struct{}
	initialMessageLimit int

	pipeReader *io.PipeReader
	pipeWriter *io.PipeWriter
	byteConn   *pumpedByteConn

	transportCloseOnce sync.Once
	pipeCloseOnce      sync.Once
	pipeCloseErr       error
	closeOnce          sync.Once
	closeErr           error
}

// NewPendingServer validates one TLS 1.3 tunnel WebSocket and starts its single
// reader pump. initialMessageLimit bounds the pre-Yamux binary message.
func NewPendingServer(conn *gorillaws.Conn, resources ResourcePolicy, initialMessageLimit int) (*PendingServer, error) {
	if initialMessageLimit < 1 {
		return nil, ErrInvalidInitialMessage
	}
	if err := ValidateReady(conn, SubprotocolTunnel); err != nil {
		return nil, err
	}
	normalized, err := yamuxLimitsFromResourcePolicy(resources)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancelCause(context.Background())
	pipeReader, pipeWriter := io.Pipe()
	server := &PendingServer{
		raw: conn, limits: normalized,
		writer: &serializedWebSocketWriter{conn: conn, permit: make(chan struct{}, 1)},
		ctx:    ctx, cancel: cancel, state: pendingAwaitingInitial,
		initialMessage: make(chan initialMessageResult, 1), pumpDone: make(chan struct{}),
		pipeReader: pipeReader, pipeWriter: pipeWriter,
		initialMessageLimit: initialMessageLimit,
	}
	server.writer.permit <- struct{}{}
	server.byteConn = &pumpedByteConn{owner: server}
	maxMessageBytes := int64(normalized.MaxFrameBytes + yamuxHeaderSizeBytes)
	minimum := int64(initialMessageLimit)
	if maxMessageBytes < minimum {
		maxMessageBytes = minimum
	}
	conn.SetReadLimit(maxMessageBytes)
	server.installControlHandlers()
	go server.readPump()
	return server, nil
}

// ReceiveInitialMessage returns the single bounded pre-Yamux binary message.
func (server *PendingServer) ReceiveInitialMessage(ctx context.Context) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if !server.receiveUsed.CompareAndSwap(false, true) {
		return nil, ErrPendingServerState
	}
	select {
	case result := <-server.initialMessage:
		return result.raw, result.err
	case <-ctx.Done():
		server.fail(ctx.Err())
		return nil, ctx.Err()
	}
}

// SendInitialResponse writes exactly one binary response. activate linearizes
// the waiting-to-activating transition before peer Yamux bytes are accepted.
func (server *PendingServer) SendInitialResponse(ctx context.Context, raw []byte, activate bool) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		server.fail(err)
		return err
	}
	if len(raw) == 0 {
		return ErrInvalidInitialMessage
	}
	server.stateMu.Lock()
	if server.state != pendingWaiting || server.responseStarted {
		server.stateMu.Unlock()
		return ErrPendingServerState
	}
	server.responseStarted = true
	server.state = pendingResponding
	server.stateMu.Unlock()
	commitResponse := func() error {
		server.stateMu.Lock()
		defer server.stateMu.Unlock()
		if server.state != pendingResponding {
			if cause := context.Cause(server.ctx); cause != nil {
				return cause
			}
			return ErrPendingServerState
		}
		server.responseSent = true
		if activate {
			server.state = pendingActivating
		} else {
			server.state = pendingRejected
		}
		return nil
	}
	if err := server.writer.writeMessage(ctx, gorillaws.BinaryMessage, raw, commitResponse); err != nil {
		server.fail(err)
		return err
	}
	return nil
}

// WaitWhilePending reports peer close or pre-SUCCESS protocol bytes. Canceling
// ctx only stops the waiter; the reader pump remains owned by this server.
func (server *PendingServer) WaitWhilePending(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-server.pumpDone:
		if cause := context.Cause(server.ctx); cause != nil {
			return cause
		}
		return io.ErrClosedPipe
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Activate constructs the role-selected hop Yamux session after SUCCESS only.
func (server *PendingServer) Activate(ctx context.Context, role Role) (*Session, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		server.fail(err)
		return nil, err
	}
	if role != ClientRole && role != ServerRole {
		return nil, ErrPendingServerState
	}
	server.stateMu.Lock()
	if server.state != pendingActivating || !server.responseSent || server.activationStarted {
		server.stateMu.Unlock()
		return nil, ErrPendingServerState
	}
	server.activationStarted = true
	server.stateMu.Unlock()

	session, err := newSessionWithByteConn(server.raw, server.byteConn, role, SubprotocolTunnel, server.limits, func() error {
		return server.closePipes(io.ErrClosedPipe)
	})
	if err != nil {
		server.fail(err)
		return nil, err
	}
	session.closeControl = func(ctx context.Context, applicationError carrier.ApplicationError) error {
		return server.writer.writeControl(
			gorillaws.CloseMessage,
			gorillaws.FormatCloseMessage(closeStatusCode, applicationError.Reason),
			closeControlDeadline(ctx),
		)
	}
	server.stateMu.Lock()
	if server.state == pendingClosed {
		cause := context.Cause(server.ctx)
		server.stateMu.Unlock()
		_ = session.Close()
		if cause == nil {
			cause = io.ErrClosedPipe
		}
		return nil, cause
	}
	server.session = session
	server.state = pendingActive
	server.stateMu.Unlock()
	return session, nil
}

// CloseWithError closes the pending exchange or activated carrier session
// without constructing Yamux on rejected and timed-out paths.
func (server *PendingServer) CloseWithError(applicationError carrier.ApplicationError) error {
	return server.CloseWithErrorContext(context.Background(), applicationError)
}

func (server *PendingServer) CloseWithErrorContext(ctx context.Context, applicationError carrier.ApplicationError) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := validateApplicationError(applicationError); err != nil {
		return err
	}
	server.closeOnce.Do(func() {
		server.stateMu.Lock()
		server.state = pendingClosed
		session := server.session
		server.stateMu.Unlock()
		server.cancel(io.ErrClosedPipe)
		if session != nil {
			server.closeErr = errors.Join(session.CloseWithErrorContext(ctx, applicationError), server.closeTransport(io.ErrClosedPipe))
		} else {
			controlErr := server.writer.writeControl(
				gorillaws.CloseMessage,
				gorillaws.FormatCloseMessage(closeStatusCode, applicationError.Reason),
				closeControlDeadline(ctx),
			)
			server.closeErr = errors.Join(controlErr, server.closeTransport(io.ErrClosedPipe))
		}
		_ = server.closeTransport(io.ErrClosedPipe)
	})
	return errors.Join(server.closeErr, context.Cause(ctx))
}

func (server *PendingServer) readPump() {
	defer close(server.pumpDone)
	messageType, reader, err := server.raw.NextReader()
	if err != nil {
		server.publishInitialMessage(nil, err)
		server.fail(err)
		return
	}
	if messageType != gorillaws.BinaryMessage {
		err = errors.Join(ErrInvalidInitialMessage, ErrNonBinaryMessage)
		server.publishInitialMessage(nil, err)
		server.fail(err)
		return
	}
	raw, err := readBoundedMessage(reader, server.initialMessageLimit)
	if err != nil {
		err = errors.Join(ErrInvalidInitialMessage, err)
		server.publishInitialMessage(nil, err)
		server.fail(err)
		return
	}
	server.stateMu.Lock()
	if server.state != pendingAwaitingInitial {
		server.stateMu.Unlock()
		server.fail(ErrPendingServerState)
		return
	}
	server.state = pendingWaiting
	server.stateMu.Unlock()
	server.publishInitialMessage(raw, nil)

	buffer := make([]byte, 32<<10)
	for {
		messageType, reader, err = server.raw.NextReader()
		if err != nil {
			server.fail(err)
			return
		}
		server.stateMu.Lock()
		state := server.state
		if state == pendingWaiting || state == pendingResponding || state == pendingAwaitingInitial {
			server.state = pendingClosed
			server.stateMu.Unlock()
			server.finishFailure(ErrUnexpectedInitialMessage)
			return
		}
		if state == pendingRejected || state == pendingClosed {
			server.stateMu.Unlock()
			return
		}
		server.stateMu.Unlock()
		if messageType != gorillaws.BinaryMessage {
			server.fail(ErrNonBinaryMessage)
			return
		}
		if _, err := io.CopyBuffer(server.pipeWriter, reader, buffer); err != nil {
			server.fail(err)
			return
		}
	}
}

func readBoundedMessage(reader io.Reader, maximum int) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(reader, int64(maximum)+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maximum {
		return nil, ErrInvalidInitialMessage
	}
	return raw, nil
}

func (server *PendingServer) publishInitialMessage(raw []byte, err error) {
	server.initialMessageOnce.Do(func() { server.initialMessage <- initialMessageResult{raw: raw, err: err} })
}

func (server *PendingServer) fail(cause error) {
	if cause == nil {
		cause = io.ErrClosedPipe
	}
	server.stateMu.Lock()
	if server.state == pendingClosed {
		server.stateMu.Unlock()
		return
	}
	server.state = pendingClosed
	server.stateMu.Unlock()
	server.finishFailure(cause)
}

func (server *PendingServer) finishFailure(cause error) {
	server.cancel(cause)
	server.publishInitialMessage(nil, cause)
	_ = server.closeTransport(cause)
}

func (server *PendingServer) closeTransport(cause error) error {
	var closeErr error
	server.transportCloseOnce.Do(func() {
		server.cancel(cause)
		closeErr = errors.Join(
			server.closePipes(cause),
			server.raw.Close(),
		)
	})
	return closeErr
}

func (server *PendingServer) closePipes(cause error) error {
	server.pipeCloseOnce.Do(func() {
		server.pipeCloseErr = errors.Join(
			server.pipeWriter.CloseWithError(cause),
			server.pipeReader.CloseWithError(cause),
		)
	})
	return server.pipeCloseErr
}

func (server *PendingServer) installControlHandlers() {
	server.raw.SetPingHandler(func(payload string) error {
		if !server.controlAllowed() {
			return ErrUnexpectedInitialMessage
		}
		return server.writer.writeControl(gorillaws.PongMessage, []byte(payload), time.Now().Add(2*time.Second))
	})
	server.raw.SetPongHandler(func(string) error {
		if !server.controlAllowed() {
			return ErrUnexpectedInitialMessage
		}
		return nil
	})
}

func (server *PendingServer) controlAllowed() bool {
	server.stateMu.Lock()
	defer server.stateMu.Unlock()
	return server.state != pendingRejected && server.state != pendingClosed
}

type serializedWebSocketWriter struct {
	conn   *gorillaws.Conn
	permit chan struct{}
}

func (writer *serializedWebSocketWriter) writeMessage(
	ctx context.Context,
	messageType int,
	payload []byte,
	beforeCommit func() error,
) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-writer.permit:
	}
	defer func() { writer.permit <- struct{}{} }()
	if deadline, ok := ctx.Deadline(); ok {
		if err := writer.conn.SetWriteDeadline(deadline); err != nil {
			return err
		}
		defer writer.conn.SetWriteDeadline(time.Time{})
	}
	stop := context.AfterFunc(ctx, func() { _ = writer.conn.Close() })
	defer func() { _ = stop() }()
	messageWriter, err := writer.conn.NextWriter(messageType)
	if err != nil {
		return err
	}
	if _, err := messageWriter.Write(payload); err != nil {
		return errors.Join(err, messageWriter.Close())
	}
	var commitErr error
	if beforeCommit != nil {
		commitErr = beforeCommit()
	}
	closeErr := messageWriter.Close()
	return errors.Join(commitErr, closeErr)
}

func (writer *serializedWebSocketWriter) writeControl(messageType int, payload []byte, deadline time.Time) error {
	select {
	case <-writer.permit:
		defer func() { writer.permit <- struct{}{} }()
		return writer.conn.WriteControl(messageType, payload, deadline)
	case <-time.After(time.Until(deadline)):
		return context.DeadlineExceeded
	}
}

type pumpedByteConn struct{ owner *PendingServer }

func (conn *pumpedByteConn) Read(payload []byte) (int, error) {
	return conn.owner.pipeReader.Read(payload)
}

func (conn *pumpedByteConn) Write(payload []byte) (int, error) {
	if len(payload) == 0 {
		return 0, nil
	}
	err := conn.owner.writer.writeMessage(context.Background(), gorillaws.BinaryMessage, payload, nil)
	if err != nil {
		return 0, err
	}
	return len(payload), nil
}

func (conn *pumpedByteConn) Close() error {
	conn.owner.fail(io.ErrClosedPipe)
	return nil
}

func (conn *pumpedByteConn) LocalAddr() net.Addr  { return conn.owner.raw.LocalAddr() }
func (conn *pumpedByteConn) RemoteAddr() net.Addr { return conn.owner.raw.RemoteAddr() }
func (conn *pumpedByteConn) SetDeadline(deadline time.Time) error {
	return errors.Join(conn.owner.raw.SetReadDeadline(deadline), conn.owner.raw.SetWriteDeadline(deadline))
}
func (conn *pumpedByteConn) SetReadDeadline(deadline time.Time) error {
	return conn.owner.raw.SetReadDeadline(deadline)
}
func (conn *pumpedByteConn) SetWriteDeadline(deadline time.Time) error {
	return conn.owner.raw.SetWriteDeadline(deadline)
}

var _ net.Conn = (*pumpedByteConn)(nil)
