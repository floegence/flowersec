// Package websocket adapts a WebSocket connection and hop-local Yamux to
// Flowersec's transport-neutral carrier contract. Network-facing and tunnel
// connections require TLS 1.3; plaintext direct connections are restricted to
// TCP loopback at both ends.
package websocket

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/floegence/flowersec/flowersec-go/v3/internal/carrier"
	carrierlife "github.com/floegence/flowersec/flowersec-go/v3/internal/carrier/internal/lifecycle"
	fsyamux "github.com/floegence/flowersec/flowersec-go/v3/internal/mux/yamux"
	gorillaws "github.com/gorilla/websocket"
)

const (
	SubprotocolDirect = "flowersec.direct.v2"
	SubprotocolTunnel = "flowersec.tunnel.v2"

	closeStatusCode      = 4000
	maxCloseReasonBytes  = 123
	yamuxHeaderSizeBytes = 12
	closeControlTimeout  = 500 * time.Millisecond
)

// ResourcePolicy is the Flowersec-owned resource contract for a WebSocket
// carrier. InboundBidirectionalStreams is the physical carrier capacity and
// includes the lifetime control and persistent RPC streams.
type ResourcePolicy struct {
	InboundBidirectionalStreams uint16
	MaxConcurrentStreams        uint32
	MaxFrameBytes               int
	PreferredWriteBytes         int
	MaxStreamWriteQueueBytes    int
	MaxStreamReceiveBytes       int
	MaxSessionReceiveBytes      int
}

// DefaultResourcePolicy returns the hardened WebSocket carrier defaults.
func DefaultResourcePolicy() ResourcePolicy {
	return resourcePolicyFromYamux(fsyamux.DefaultLimits())
}

// BindSessionResourcePolicy reserves one physical stream for control, one for
// RPC, and exactly maxLogical physical streams for application data.
func BindSessionResourcePolicy(policy ResourcePolicy, maxLogical uint16) (ResourcePolicy, error) {
	physical, err := carrier.RequiredIncomingStreams(maxLogical)
	if err != nil {
		return ResourcePolicy{}, err
	}
	limits, err := yamuxLimitsFromResourcePolicy(policy)
	if err != nil {
		return ResourcePolicy{}, err
	}
	limits.MaxInboundStreams = uint32(physical)
	if limits.MaxActiveStreams < limits.MaxInboundStreams {
		limits.MaxActiveStreams = limits.MaxInboundStreams
	}
	limits, err = fsyamux.ValidateLimits(limits)
	if err != nil {
		return ResourcePolicy{}, err
	}
	return resourcePolicyFromYamux(limits), nil
}

func yamuxLimitsFromResourcePolicy(policy ResourcePolicy) (fsyamux.YamuxLimits, error) {
	return fsyamux.ValidateLimits(fsyamux.YamuxLimits{
		MaxActiveStreams:            policy.MaxConcurrentStreams,
		MaxInboundStreams:           uint32(policy.InboundBidirectionalStreams),
		MaxFrameBytes:               policy.MaxFrameBytes,
		PreferredOutboundFrameBytes: policy.PreferredWriteBytes,
		MaxStreamWriteQueueBytes:    policy.MaxStreamWriteQueueBytes,
		MaxStreamReceiveBytes:       policy.MaxStreamReceiveBytes,
		MaxSessionReceiveBytes:      policy.MaxSessionReceiveBytes,
	})
}

func resourcePolicyFromYamux(limits fsyamux.YamuxLimits) ResourcePolicy {
	return ResourcePolicy{
		InboundBidirectionalStreams: uint16(limits.MaxInboundStreams),
		MaxConcurrentStreams:        limits.MaxActiveStreams,
		MaxFrameBytes:               limits.MaxFrameBytes,
		PreferredWriteBytes:         limits.PreferredOutboundFrameBytes,
		MaxStreamWriteQueueBytes:    limits.MaxStreamWriteQueueBytes,
		MaxStreamReceiveBytes:       limits.MaxStreamReceiveBytes,
		MaxSessionReceiveBytes:      limits.MaxSessionReceiveBytes,
	}
}

var (
	ErrInvalidRole             = errors.New("invalid WebSocket carrier role")
	ErrInvalidSubprotocol      = errors.New("invalid WebSocket v2 subprotocol")
	ErrTLS13Required           = errors.New("WebSocket carrier requires TLS 1.3")
	ErrNonBinaryMessage        = errors.New("WebSocket carrier received a non-binary message")
	ErrInvalidApplicationError = errors.New("invalid WebSocket application error")
)

type Role uint8

const (
	ClientRole Role = 1
	ServerRole Role = 2
)

// NewAfterAdmission switches an authenticated v2 WebSocket from its bounded
// admission message to hop-local Yamux. Admission bytes must be exchanged by
// the caller before invoking this function.
func NewAfterAdmission(conn *gorillaws.Conn, role Role, subprotocol string, resources ResourcePolicy) (*Session, error) {
	if role != ClientRole && role != ServerRole {
		return nil, ErrInvalidRole
	}
	if err := ValidateReady(conn, subprotocol); err != nil {
		return nil, err
	}
	normalized, err := yamuxLimitsFromResourcePolicy(resources)
	if err != nil {
		return nil, err
	}
	byteConn := newBinaryByteConn(conn, int64(normalized.MaxFrameBytes+yamuxHeaderSizeBytes))
	return newSessionWithByteConn(conn, byteConn, role, subprotocol, normalized, nil)
}

func newSessionWithByteConn(conn *gorillaws.Conn, byteConn net.Conn, role Role, subprotocol string, limits fsyamux.YamuxLimits, beforeMuxClose func() error) (*Session, error) {
	if err := byteConn.SetDeadline(time.Time{}); err != nil {
		return nil, fmt.Errorf("clear WebSocket admission deadline: %w", err)
	}
	var mux *fsyamux.Session
	if role == ClientRole {
		var err error
		mux, err = fsyamux.NewClient(byteConn, limits)
		if err != nil {
			return nil, err
		}
	} else {
		var err error
		mux, err = fsyamux.NewServer(byteConn, limits)
		if err != nil {
			return nil, err
		}
	}
	ctx, cancel := context.WithCancelCause(context.Background())
	session := &Session{
		raw:            conn,
		mux:            mux,
		path:           pathForSubprotocol(subprotocol),
		ctx:            ctx,
		cancel:         cancel,
		acceptCh:       make(chan *fsyamux.Stream, limits.MaxInboundStreams),
		capacity:       uint16(limits.MaxInboundStreams),
		beforeMuxClose: beforeMuxClose,
	}
	go session.acceptLoop()
	return session, nil
}

// ValidateReady checks the credential-free WebSocket carrier-ready boundary:
// one exact registered v2 subprotocol and either TLS 1.3 or the restricted
// plaintext loopback direct profile are already negotiated.
func ValidateReady(conn *gorillaws.Conn, subprotocol string) error {
	if conn == nil {
		return net.ErrClosed
	}
	if !validSubprotocol(subprotocol) || conn.Subprotocol() != subprotocol {
		return ErrInvalidSubprotocol
	}
	return validateTransportSecurity(conn, subprotocol)
}

type Session struct {
	raw    *gorillaws.Conn
	mux    *fsyamux.Session
	path   carrier.Path
	ctx    context.Context
	cancel context.CancelCauseFunc

	acceptCh  chan *fsyamux.Stream
	acceptMu  sync.RWMutex
	acceptErr error
	capacity  uint16

	closeOnce      sync.Once
	closeErr       error
	beforeMuxClose func() error
	closeControl   func(context.Context, carrier.ApplicationError) error
}

func (*Session) Kind() carrier.Kind                   { return carrier.KindWebSocket }
func (session *Session) Path() carrier.Path           { return session.path }
func (session *Session) MaxIncomingStreams() uint16   { return session.capacity }
func (session *Session) Termination() <-chan struct{} { return session.ctx.Done() }

func pathForSubprotocol(subprotocol string) carrier.Path {
	if subprotocol == SubprotocolTunnel {
		return carrier.PathTunnel
	}
	return carrier.PathDirect
}

func (session *Session) OpenStream(ctx context.Context) (carrier.Stream, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	stream, err := session.mux.OpenStreamContext(ctx)
	if err != nil {
		return nil, err
	}
	return wrapStream(session.ctx, stream), nil
}

func (session *Session) AcceptStream(ctx context.Context) (carrier.Stream, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case stream, ok := <-session.acceptCh:
		if ok {
			return wrapStream(session.ctx, stream), nil
		}
		session.acceptMu.RLock()
		err := session.acceptErr
		session.acceptMu.RUnlock()
		if err == nil {
			err = io.ErrClosedPipe
		}
		return nil, err
	}
}

func (session *Session) acceptLoop() {
	defer close(session.acceptCh)
	for {
		stream, err := session.mux.AcceptStream()
		if err != nil {
			session.acceptMu.Lock()
			session.acceptErr = err
			session.acceptMu.Unlock()
			return
		}
		select {
		case session.acceptCh <- stream:
		case <-session.ctx.Done():
			_ = stream.Reset()
			return
		}
	}
}

func (session *Session) CloseWithError(applicationError carrier.ApplicationError) error {
	return session.CloseWithErrorContext(context.Background(), applicationError)
}

func (session *Session) Abort(applicationError carrier.ApplicationError) error {
	if session == nil {
		return nil
	}
	session.closeOnce.Do(func() {
		session.cancel(io.ErrClosedPipe)
		session.closeErr = errors.Join(session.mux.Close(), session.raw.Close())
	})
	return session.closeErr
}

func (session *Session) CloseWithErrorContext(ctx context.Context, applicationError carrier.ApplicationError) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := validateApplicationError(applicationError); err != nil {
		return err
	}
	session.closeOnce.Do(func() {
		session.cancel(io.ErrClosedPipe)
		var controlErr error
		if session.closeControl != nil {
			controlErr = session.closeControl(ctx, applicationError)
		} else {
			controlErr = session.raw.WriteControl(
				gorillaws.CloseMessage,
				gorillaws.FormatCloseMessage(closeStatusCode, applicationError.Reason),
				closeControlDeadline(ctx),
			)
		}
		var beforeCloseErr error
		if session.beforeMuxClose != nil {
			beforeCloseErr = session.beforeMuxClose()
		}
		session.closeErr = errors.Join(
			normalizeWebSocketShutdownError(controlErr, true, applicationError),
			beforeCloseErr,
			normalizeWebSocketShutdownError(session.mux.Close(), false, carrier.ApplicationError{}),
		)
	})
	return errors.Join(session.closeErr, context.Cause(ctx))
}

// Flush waits until peer processing crosses the current mux write boundary.
func (session *Session) Flush(ctx context.Context) error {
	return session.mux.Flush(ctx)
}

func normalizeWebSocketShutdownError(err error, allowTimeout bool, applicationError carrier.ApplicationError) error {
	if err == nil || errors.Is(err, net.ErrClosed) || errors.Is(err, gorillaws.ErrCloseSent) ||
		errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.ECONNRESET) {
		return nil
	}
	var closeError *gorillaws.CloseError
	if applicationError.Code == 1 && applicationError.Reason == "session closed" &&
		errors.As(err, &closeError) && closeError.Code == closeStatusCode && closeError.Text == applicationError.Reason {
		return nil
	}
	var networkError net.Error
	if allowTimeout && errors.As(err, &networkError) && networkError.Timeout() {
		return nil
	}
	return err
}

func closeControlDeadline(ctx context.Context) time.Time {
	now := time.Now()
	deadline := now.Add(closeControlTimeout)
	if ctx.Err() != nil {
		return now
	}
	if callerDeadline, ok := ctx.Deadline(); ok && callerDeadline.Before(deadline) {
		return callerDeadline
	}
	return deadline
}

func (session *Session) Close() error {
	return session.CloseWithError(carrier.ApplicationError{})
}

type Stream struct {
	inner     *fsyamux.Stream
	lifecycle *carrierlife.Stream
}

func wrapStream(sessionContext context.Context, inner *fsyamux.Stream) *Stream {
	return &Stream{inner: inner, lifecycle: carrierlife.NewStream(sessionContext)}
}

func (stream *Stream) Read(payload []byte) (int, error) {
	n, err := stream.inner.Read(payload)
	stream.lifecycle.ReadResult(err)
	return n, err
}

func (stream *Stream) Write(payload []byte) (int, error) {
	n, err := stream.inner.Write(payload)
	stream.lifecycle.WriteResult(err)
	return n, err
}

func (stream *Stream) Context() context.Context { return stream.lifecycle.Context() }
func (stream *Stream) CloseWrite() error {
	err := stream.inner.CloseWrite()
	stream.lifecycle.CloseWriteResult(err)
	return err
}

func (stream *Stream) StopSending() error {
	return carrier.ErrStopSendingUnavailable
}

func (stream *Stream) Reset() error {
	err := stream.inner.Reset()
	stream.lifecycle.Terminate(carrier.ErrStreamReset)
	return err
}

func (stream *Stream) Close() error {
	err := stream.inner.Close()
	stream.lifecycle.Terminate(io.ErrClosedPipe)
	return err
}

type binaryByteConn struct {
	conn *gorillaws.Conn

	readMu  sync.Mutex
	reader  io.Reader
	writeMu sync.Mutex
}

func newBinaryByteConn(conn *gorillaws.Conn, maxMessageBytes int64) *binaryByteConn {
	conn.SetReadLimit(maxMessageBytes)
	return &binaryByteConn{conn: conn}
}

func (conn *binaryByteConn) Read(payload []byte) (int, error) {
	if len(payload) == 0 {
		return 0, nil
	}
	conn.readMu.Lock()
	defer conn.readMu.Unlock()
	for {
		if conn.reader == nil {
			messageType, reader, err := conn.conn.NextReader()
			if err != nil {
				return 0, err
			}
			if messageType != gorillaws.BinaryMessage {
				return 0, ErrNonBinaryMessage
			}
			conn.reader = reader
		}
		n, err := conn.reader.Read(payload)
		if errors.Is(err, io.EOF) {
			conn.reader = nil
			if n > 0 {
				return n, nil
			}
			continue
		}
		return n, err
	}
}

func (conn *binaryByteConn) Write(payload []byte) (int, error) {
	if len(payload) == 0 {
		return 0, nil
	}
	conn.writeMu.Lock()
	defer conn.writeMu.Unlock()
	writer, err := conn.conn.NextWriter(gorillaws.BinaryMessage)
	if err != nil {
		return 0, err
	}
	n, writeErr := writer.Write(payload)
	closeErr := writer.Close()
	return n, errors.Join(writeErr, closeErr)
}

func (conn *binaryByteConn) Close() error         { return conn.conn.Close() }
func (conn *binaryByteConn) LocalAddr() net.Addr  { return conn.conn.LocalAddr() }
func (conn *binaryByteConn) RemoteAddr() net.Addr { return conn.conn.RemoteAddr() }
func (conn *binaryByteConn) SetDeadline(deadline time.Time) error {
	return errors.Join(conn.conn.SetReadDeadline(deadline), conn.conn.SetWriteDeadline(deadline))
}
func (conn *binaryByteConn) SetReadDeadline(deadline time.Time) error {
	return conn.conn.SetReadDeadline(deadline)
}
func (conn *binaryByteConn) SetWriteDeadline(deadline time.Time) error {
	return conn.conn.SetWriteDeadline(deadline)
}

func validateTransportSecurity(conn *gorillaws.Conn, subprotocol string) error {
	underlying := conn.UnderlyingConn()
	if tlsConn, ok := underlying.(*tls.Conn); ok {
		if tlsConn.ConnectionState().Version == tls.VersionTLS13 {
			return nil
		}
		return ErrTLS13Required
	}
	return validatePlaintextLoopback(underlying, subprotocol)
}

func validatePlaintextLoopback(conn net.Conn, subprotocol string) error {
	if conn == nil || subprotocol != SubprotocolDirect || !loopbackTCPAddress(conn.LocalAddr()) || !loopbackTCPAddress(conn.RemoteAddr()) {
		return ErrTLS13Required
	}
	return nil
}

func loopbackTCPAddress(address net.Addr) bool {
	tcpAddress, ok := address.(*net.TCPAddr)
	return ok && tcpAddress != nil && tcpAddress.IP != nil && tcpAddress.IP.IsLoopback()
}

func validateApplicationError(applicationError carrier.ApplicationError) error {
	if len(applicationError.Reason) > maxCloseReasonBytes || !utf8.ValidString(applicationError.Reason) {
		return fmt.Errorf("%w: reason exceeds the WebSocket close frame", ErrInvalidApplicationError)
	}
	return nil
}

func validSubprotocol(value string) bool {
	return value == SubprotocolDirect || value == SubprotocolTunnel
}

var _ carrier.Session = (*Session)(nil)
var _ carrier.Stream = (*Stream)(nil)
var _ net.Conn = (*binaryByteConn)(nil)
