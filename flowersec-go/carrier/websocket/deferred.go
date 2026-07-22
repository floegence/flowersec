package websocket

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/floegence/flowersec/flowersec-go/artifactv2"
	"github.com/floegence/flowersec/flowersec-go/carrier"
	fsyamux "github.com/floegence/flowersec/flowersec-go/mux/yamux"
	gorillaws "github.com/gorilla/websocket"
)

var (
	ErrUnexpectedWaitingMessage = errors.New("unexpected WebSocket message while tunnel admission is waiting")
	ErrDeferredAdmissionState   = errors.New("invalid deferred WebSocket tunnel admission state")
)

type deferredState uint8

const (
	deferredAwaitingAdmission deferredState = iota
	deferredWaiting
	deferredResponding
	deferredActivating
	deferredActive
	deferredRejected
	deferredClosed
)

type deferredAdmissionResult struct {
	decoded *artifactv2.DecodedRequest
	err     error
}

// DeferredTunnelServer owns one server-side WebSocket from FSB2 through the
// hop Yamux session. Its reader pump is the only goroutine that calls
// NextReader, so pre-SUCCESS messages cannot be reinterpreted after activation.
type DeferredTunnelServer struct {
	raw      *gorillaws.Conn
	limits   fsyamux.YamuxLimits
	liveness fsyamux.LivenessOptions
	writer   *serializedWebSocketWriter

	ctx    context.Context
	cancel context.CancelCauseFunc

	stateMu           sync.Mutex
	state             deferredState
	responseSent      bool
	responseStarted   bool
	activationStarted bool
	session           *Session

	admission     chan deferredAdmissionResult
	admissionOnce sync.Once
	receiveUsed   atomic.Bool
	pumpDone      chan struct{}

	pipeReader *io.PipeReader
	pipeWriter *io.PipeWriter
	byteConn   *pumpedByteConn

	transportCloseOnce sync.Once
	pipeCloseOnce      sync.Once
	pipeCloseErr       error
	closeOnce          sync.Once
	closeErr           error
	activationCount    atomic.Int32
}

// NewDeferredTunnelServer validates one TLS 1.3 tunnel WebSocket and starts
// the single reader pump before any admission bytes are consumed.
func NewDeferredTunnelServer(conn *gorillaws.Conn, resources ResourcePolicy, liveness LivenessPolicy) (*DeferredTunnelServer, error) {
	if err := ValidateReady(conn, SubprotocolTunnel); err != nil {
		return nil, err
	}
	normalized, err := yamuxLimitsFromResourcePolicy(resources)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancelCause(context.Background())
	pipeReader, pipeWriter := io.Pipe()
	server := &DeferredTunnelServer{
		raw: conn, limits: normalized, liveness: fsyamux.LivenessOptions(liveness),
		writer: &serializedWebSocketWriter{conn: conn, permit: make(chan struct{}, 1)},
		ctx:    ctx, cancel: cancel, state: deferredAwaitingAdmission,
		admission: make(chan deferredAdmissionResult, 1), pumpDone: make(chan struct{}),
		pipeReader: pipeReader, pipeWriter: pipeWriter,
	}
	server.writer.permit <- struct{}{}
	server.byteConn = &pumpedByteConn{owner: server}
	maxMessageBytes := int64(normalized.MaxFrameBytes + yamuxHeaderSizeBytes)
	minimum := int64(artifactv2.FSB2HeaderSize + artifactv2.MaxCanonicalFSB2Payload)
	if maxMessageBytes < minimum {
		maxMessageBytes = minimum
	}
	conn.SetReadLimit(maxMessageBytes)
	server.installControlHandlers()
	go server.readPump()
	return server, nil
}

// ReceiveAdmission returns the single bounded binary FSB2 message.
func (server *DeferredTunnelServer) ReceiveAdmission(ctx context.Context) (*artifactv2.DecodedRequest, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if !server.receiveUsed.CompareAndSwap(false, true) {
		return nil, ErrDeferredAdmissionState
	}
	select {
	case result := <-server.admission:
		return result.decoded, result.err
	case <-ctx.Done():
		server.fail(ctx.Err())
		return nil, ctx.Err()
	}
}

// SendAdmission writes exactly one bounded binary FSA2. SUCCESS linearizes the
// WAITING to ACTIVATING transition before any peer Yamux bytes are accepted.
func (server *DeferredTunnelServer) SendAdmission(ctx context.Context, response artifactv2.AdmissionResponse, reasons artifactv2.ReasonRegistry) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		server.fail(err)
		return err
	}
	raw, err := artifactv2.MarshalResponse(response, reasons)
	if err != nil {
		return err
	}
	server.stateMu.Lock()
	if server.state != deferredWaiting || server.responseStarted {
		server.stateMu.Unlock()
		return ErrDeferredAdmissionState
	}
	server.responseStarted = true
	server.state = deferredResponding
	server.stateMu.Unlock()
	if err := server.writer.writeMessage(ctx, gorillaws.BinaryMessage, raw); err != nil {
		server.fail(err)
		return err
	}
	server.stateMu.Lock()
	if server.state != deferredResponding {
		cause := context.Cause(server.ctx)
		server.stateMu.Unlock()
		if cause == nil {
			cause = ErrDeferredAdmissionState
		}
		return cause
	}
	server.responseSent = true
	if response.Status == artifactv2.AdmissionSuccess {
		server.state = deferredActivating
	} else {
		server.state = deferredRejected
	}
	server.stateMu.Unlock()
	return nil
}

// WaitWhilePending reports peer close or pre-SUCCESS protocol bytes. Canceling
// ctx only stops the waiter; the reader pump remains owned by this server.
func (server *DeferredTunnelServer) WaitWhilePending(ctx context.Context) error {
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

// Activate constructs the server-role hop Yamux session after SUCCESS only.
func (server *DeferredTunnelServer) Activate(ctx context.Context) (*Session, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		server.fail(err)
		return nil, err
	}
	server.stateMu.Lock()
	if server.state != deferredActivating || !server.responseSent || server.activationStarted {
		server.stateMu.Unlock()
		return nil, ErrDeferredAdmissionState
	}
	server.activationStarted = true
	server.activationCount.Add(1)
	server.stateMu.Unlock()

	session, err := newSessionWithByteConn(server.raw, server.byteConn, ServerRole, SubprotocolTunnel, server.limits, server.liveness, func() error {
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
	if server.state == deferredClosed {
		cause := context.Cause(server.ctx)
		server.stateMu.Unlock()
		_ = session.Close()
		if cause == nil {
			cause = io.ErrClosedPipe
		}
		return nil, cause
	}
	server.session = session
	server.state = deferredActive
	server.stateMu.Unlock()
	return session, nil
}

// CloseWithError closes admission or the activated carrier session without
// constructing Yamux on rejected and timed-out paths.
func (server *DeferredTunnelServer) CloseWithError(applicationError carrier.ApplicationError) error {
	return server.CloseWithErrorContext(context.Background(), applicationError)
}

func (server *DeferredTunnelServer) CloseWithErrorContext(ctx context.Context, applicationError carrier.ApplicationError) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := validateApplicationError(applicationError); err != nil {
		return err
	}
	server.closeOnce.Do(func() {
		server.stateMu.Lock()
		server.state = deferredClosed
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

func (server *DeferredTunnelServer) readPump() {
	defer close(server.pumpDone)
	messageType, reader, err := server.raw.NextReader()
	if err != nil {
		server.publishAdmission(nil, err)
		server.fail(err)
		return
	}
	if messageType != gorillaws.BinaryMessage {
		err = invalidAdmissionMessage(ErrNonBinaryMessage)
		server.publishAdmission(nil, err)
		server.fail(err)
		return
	}
	raw, err := readBoundedMessage(reader, artifactv2.FSB2HeaderSize+artifactv2.MaxCanonicalFSB2Payload)
	if err != nil {
		err = invalidAdmissionMessage(err)
		server.publishAdmission(nil, err)
		server.fail(err)
		return
	}
	decoded, err := artifactv2.ParseRequest(raw)
	if err != nil || decoded.Request.PathKind != artifactv2.PathTunnel {
		if err == nil {
			err = fmt.Errorf("FSB2 path %q does not match tunnel subprotocol", decoded.Request.PathKind)
		}
		err = invalidAdmissionMessage(err)
		server.publishAdmission(nil, err)
		server.fail(err)
		return
	}
	server.stateMu.Lock()
	if server.state != deferredAwaitingAdmission {
		server.stateMu.Unlock()
		server.fail(ErrDeferredAdmissionState)
		return
	}
	server.state = deferredWaiting
	server.stateMu.Unlock()
	server.publishAdmission(decoded, nil)

	buffer := make([]byte, 32<<10)
	for {
		messageType, reader, err = server.raw.NextReader()
		if err != nil {
			server.fail(err)
			return
		}
		server.stateMu.Lock()
		state := server.state
		if state == deferredWaiting || state == deferredResponding || state == deferredAwaitingAdmission {
			server.state = deferredClosed
			server.stateMu.Unlock()
			server.finishFailure(ErrUnexpectedWaitingMessage)
			return
		}
		if state == deferredRejected || state == deferredClosed {
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
		return nil, ErrInvalidAdmissionMessage
	}
	return raw, nil
}

func (server *DeferredTunnelServer) publishAdmission(decoded *artifactv2.DecodedRequest, err error) {
	server.admissionOnce.Do(func() { server.admission <- deferredAdmissionResult{decoded: decoded, err: err} })
}

func (server *DeferredTunnelServer) fail(cause error) {
	if cause == nil {
		cause = io.ErrClosedPipe
	}
	server.stateMu.Lock()
	if server.state == deferredClosed {
		server.stateMu.Unlock()
		return
	}
	server.state = deferredClosed
	server.stateMu.Unlock()
	server.finishFailure(cause)
}

func (server *DeferredTunnelServer) finishFailure(cause error) {
	server.cancel(cause)
	server.publishAdmission(nil, cause)
	_ = server.closeTransport(cause)
}

func (server *DeferredTunnelServer) closeTransport(cause error) error {
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

func (server *DeferredTunnelServer) closePipes(cause error) error {
	server.pipeCloseOnce.Do(func() {
		server.pipeCloseErr = errors.Join(
			server.pipeWriter.CloseWithError(cause),
			server.pipeReader.CloseWithError(cause),
		)
	})
	return server.pipeCloseErr
}

func (server *DeferredTunnelServer) installControlHandlers() {
	server.raw.SetPingHandler(func(payload string) error {
		if !server.controlAllowed() {
			return ErrUnexpectedWaitingMessage
		}
		return server.writer.writeControl(gorillaws.PongMessage, []byte(payload), time.Now().Add(2*time.Second))
	})
	server.raw.SetPongHandler(func(string) error {
		if !server.controlAllowed() {
			return ErrUnexpectedWaitingMessage
		}
		return nil
	})
}

func (server *DeferredTunnelServer) controlAllowed() bool {
	server.stateMu.Lock()
	defer server.stateMu.Unlock()
	return server.state == deferredActivating || server.state == deferredActive
}

type serializedWebSocketWriter struct {
	conn   *gorillaws.Conn
	permit chan struct{}
}

func (writer *serializedWebSocketWriter) writeMessage(ctx context.Context, messageType int, payload []byte) error {
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
	_, writeErr := messageWriter.Write(payload)
	return errors.Join(writeErr, messageWriter.Close())
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

type pumpedByteConn struct{ owner *DeferredTunnelServer }

func (conn *pumpedByteConn) Read(payload []byte) (int, error) {
	return conn.owner.pipeReader.Read(payload)
}

func (conn *pumpedByteConn) Write(payload []byte) (int, error) {
	if len(payload) == 0 {
		return 0, nil
	}
	err := conn.owner.writer.writeMessage(context.Background(), gorillaws.BinaryMessage, payload)
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
