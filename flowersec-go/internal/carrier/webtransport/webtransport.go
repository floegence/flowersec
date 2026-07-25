// Package webtransport adapts HTTP/3 WebTransport native bidirectional
// streams to Flowersec's transport-neutral carrier contract.
package webtransport

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier"
	carrierlife "github.com/floegence/flowersec/flowersec-go/v2/internal/carrier/internal/lifecycle"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier/rawquic"
	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	http3qlog "github.com/quic-go/quic-go/http3/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
	wt "github.com/quic-go/webtransport-go"
)

const (
	PathDirect = "/flowersec/webtransport/v2/direct"
	PathTunnel = "/flowersec/webtransport/v2/tunnel"

	MaxH3IncomingUniStreams int64 = 16
	streamResetCode               = wt.StreamErrorCode(0xf502)
	maxSessionErrorCode           = uint64(1<<32 - 1)
)

var (
	ErrInvalidURL              = errors.New("invalid WebTransport v2 URL")
	ErrInvalidTLS              = errors.New("invalid WebTransport TLS configuration")
	ErrOriginPolicyRequired    = errors.New("WebTransport Origin policy is required")
	ErrInvalidApplicationError = errors.New("invalid WebTransport application error")
	ErrEarlyData               = errors.New("WebTransport application early data is forbidden")
	ErrInvalidSession          = errors.New("invalid WebTransport session")
)

type Limits = rawquic.Limits

func DefaultLimits() Limits { return rawquic.DefaultLimits() }

func BindSessionLimits(limits Limits, maxLogical uint16) (Limits, error) {
	return rawquic.BindSessionLimits(limits, maxLogical)
}

// newQUICConfig enables native HTTP/3 datagrams and partial stream reset while
// keeping application early data disabled.
func newQUICConfig(limits Limits) (*quic.Config, error) {
	if err := limits.Validate(); err != nil {
		return nil, err
	}
	return &quic.Config{
		InitialPacketSize:                rawquic.MinimumInitialPacketSize,
		HandshakeIdleTimeout:             limits.HandshakeIdleTimeout,
		MaxIdleTimeout:                   limits.MaxIdleTimeout,
		InitialStreamReceiveWindow:       limits.InitialStreamReceiveWindow,
		MaxStreamReceiveWindow:           limits.MaxStreamReceiveWindow,
		InitialConnectionReceiveWindow:   limits.InitialConnectionReceiveWindow,
		MaxConnectionReceiveWindow:       limits.MaxConnectionReceiveWindow,
		MaxIncomingStreams:               limits.MaxInboundStreams,
		MaxIncomingUniStreams:            MaxH3IncomingUniStreams,
		KeepAlivePeriod:                  limits.KeepAlivePeriod,
		Allow0RTT:                        false,
		EnableDatagrams:                  true,
		EnableStreamResetPartialDelivery: true,
		Tracer:                           releaseEvidenceTracer,
	}, nil
}

func releaseEvidenceTracer(ctx context.Context, isClient bool, connID quic.ConnectionID) qlogwriter.Trace {
	if os.Getenv("FLOWERSEC_TRANSPORT_RELEASE_EVIDENCE") != "1" {
		return nil
	}
	return http3qlog.DefaultConnectionTracer(ctx, isClient, connID)
}

// newServerQUICConfig reserves the long-lived HTTP/3 CONNECT request stream in
// addition to the carrier's control, RPC, and logical data streams.
func newServerQUICConfig(limits Limits) (*quic.Config, error) {
	config, err := newQUICConfig(limits)
	if err != nil {
		return nil, err
	}
	config.MaxIncomingStreams++
	return config, nil
}

type Dialer struct {
	inner       *wt.Dialer
	capacity    uint16
	ctx         context.Context
	cancel      context.CancelCauseFunc
	dialWG      sync.WaitGroup
	mu          sync.Mutex
	connections map[*quic.Conn]*dialConnection
	started     bool
	closed      bool
	closeOnce   sync.Once
	closeErr    error
}

type dialConnection struct {
	connection *quic.Conn
	done       chan error
}

const webTransportConnectionDrainTimeout = 5 * time.Second

func NewDialer(tlsConfig *tls.Config, limits Limits) (*Dialer, error) {
	preparedTLS, err := prepareTLS(tlsConfig, false)
	if err != nil {
		return nil, err
	}
	config, err := newQUICConfig(limits)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancelCause(context.Background())
	dialer := &Dialer{
		capacity: uint16(limits.MaxInboundStreams), ctx: ctx, cancel: cancel,
		connections: make(map[*quic.Conn]*dialConnection),
	}
	dialer.inner = &wt.Dialer{
		TLSClientConfig: preparedTLS,
		QUICConfig:      config,
		DialAddr:        dialer.dialQUIC,
	}
	return dialer, nil
}

// Dial establishes one confirmed WebTransport session. Origin is the only
// caller-supplied HTTP header; Flowersec credentials stay on the admission
// stream and are never copied into a CONNECT header.
func (dialer *Dialer) Dial(ctx context.Context, rawURL, origin string) (*Session, error) {
	if dialer == nil || dialer.inner == nil {
		return nil, ErrInvalidSession
	}
	if ctx == nil {
		ctx = context.Background()
	}
	dialer.mu.Lock()
	if dialer.closed {
		dialer.mu.Unlock()
		return nil, ErrInvalidSession
	}
	dialer.dialWG.Add(1)
	dialer.mu.Unlock()
	defer dialer.dialWG.Done()
	dialCtx, cancel := context.WithCancelCause(ctx)
	stop := context.AfterFunc(dialer.ctx, func() { cancel(ErrInvalidSession) })
	defer func() {
		stop()
		cancel(context.Canceled)
	}()
	parsed, err := parseURL(rawURL)
	if err != nil {
		return nil, err
	}
	path, err := pathForConnectPath(parsed.Path)
	if err != nil {
		return nil, err
	}
	header := make(http.Header)
	if origin != "" {
		if err := validateOrigin(origin); err != nil {
			return nil, err
		}
		header.Set("Origin", origin)
	}
	dialer.mu.Lock()
	if dialer.closed {
		dialer.mu.Unlock()
		return nil, ErrInvalidSession
	}
	dialer.started = true
	dialer.mu.Unlock()
	response, inner, err := dialer.inner.Dial(dialCtx, rawURL, header)
	if err != nil {
		return nil, err
	}
	if response == nil || response.StatusCode != http.StatusOK {
		_ = inner.CloseWithError(0, "unexpected HTTP status")
		return nil, ErrInvalidSession
	}
	return wrapSession(inner, dialer.capacity, path)
}

func (dialer *Dialer) Close() error {
	if dialer == nil || dialer.inner == nil {
		return nil
	}
	dialer.closeOnce.Do(func() {
		dialer.mu.Lock()
		dialer.closed = true
		dialer.cancel(ErrInvalidSession)
		dialer.mu.Unlock()
		dialer.dialWG.Wait()

		dialer.mu.Lock()
		started := dialer.started
		connections := make([]*dialConnection, 0, len(dialer.connections))
		for _, connection := range dialer.connections {
			connections = append(connections, connection)
		}
		dialer.mu.Unlock()
		if started {
			dialer.closeErr = dialer.inner.Close()
		}
		for _, tracked := range connections {
			dialer.closeErr = errors.Join(dialer.closeErr, tracked.connection.CloseWithError(0, ""))
		}
		deadline := time.NewTimer(webTransportConnectionDrainTimeout)
		defer deadline.Stop()
		for _, tracked := range connections {
			select {
			case err := <-tracked.done:
				dialer.closeErr = errors.Join(dialer.closeErr, err)
			case <-deadline.C:
				dialer.closeErr = errors.Join(dialer.closeErr, errors.New("WebTransport QUIC connection did not drain"))
				return
			}
		}
	})
	return dialer.closeErr
}

func (dialer *Dialer) dialQUIC(ctx context.Context, address string, tlsConfig *tls.Config, config *quic.Config) (*quic.Conn, error) {
	connection, err := quic.DialAddr(ctx, address, tlsConfig, config)
	if err != nil {
		return nil, err
	}
	tracked := &dialConnection{connection: connection, done: make(chan error, 1)}
	dialer.mu.Lock()
	closed := dialer.closed
	dialer.connections[connection] = tracked
	dialer.mu.Unlock()
	go dialer.observeQUICConnection(tracked)
	if closed {
		_ = connection.CloseWithError(0, "")
		return nil, ErrInvalidSession
	}
	return connection, nil
}

func (dialer *Dialer) observeQUICConnection(tracked *dialConnection) {
	<-tracked.connection.Context().Done()
	ctx, cancel := context.WithTimeout(context.Background(), webTransportConnectionDrainTimeout)
	err := waitForQLOGTraceClose(ctx, tracked.connection.QlogTrace())
	cancel()
	tracked.done <- err
	close(tracked.done)
	dialer.mu.Lock()
	delete(dialer.connections, tracked.connection)
	dialer.mu.Unlock()
}

func waitForQLOGTraceClose(ctx context.Context, trace qlogwriter.Trace) error {
	if trace == nil {
		return nil
	}
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		producer := trace.AddProducer()
		if producer == nil {
			return nil
		}
		if err := producer.Close(); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("WebTransport qlog trace did not close: %w", context.Cause(ctx))
		case <-ticker.C:
		}
	}
}

type Server struct {
	inner    *wt.Server
	capacity uint16

	lifecycleMu sync.Mutex
	serveCalled bool
	closed      bool
	closeOnce   sync.Once
	closeErr    error
}

func NewServer(tlsConfig *tls.Config, limits Limits, checkOrigin func(*http.Request) bool) (*Server, error) {
	if checkOrigin == nil {
		return nil, ErrOriginPolicyRequired
	}
	preparedTLS, err := prepareTLS(tlsConfig, true)
	if err != nil {
		return nil, err
	}
	config, err := newServerQUICConfig(limits)
	if err != nil {
		return nil, err
	}
	h3 := &http3.Server{TLSConfig: preparedTLS, QUICConfig: config}
	inner := &wt.Server{H3: h3, CheckOrigin: checkOrigin}
	wt.ConfigureHTTP3Server(h3)
	return &Server{inner: inner, capacity: uint16(limits.MaxInboundStreams)}, nil
}

// SetHandler installs the CONNECT handler before Serve starts.
func (server *Server) SetHandler(handler http.Handler) { server.inner.H3.Handler = handler }

func (server *Server) Upgrade(writer http.ResponseWriter, request *http.Request) (*Session, error) {
	if server == nil || server.inner == nil || request == nil ||
		(request.URL.Path != PathDirect && request.URL.Path != PathTunnel) ||
		request.URL.RawPath != "" || request.URL.RawQuery != "" {
		return nil, ErrInvalidURL
	}
	path, err := pathForConnectPath(request.URL.Path)
	if err != nil {
		return nil, err
	}
	inner, err := server.inner.Upgrade(writer, request)
	if err != nil {
		return nil, err
	}
	return wrapSession(inner, server.capacity, path)
}

type serveStartPacketConn struct {
	net.PacketConn
	ready chan struct{}
	once  sync.Once
}

func (packetConn *serveStartPacketConn) markReady() {
	packetConn.once.Do(func() { close(packetConn.ready) })
}

func (packetConn *serveStartPacketConn) ReadFrom(payload []byte) (int, net.Addr, error) {
	packetConn.markReady()
	return packetConn.PacketConn.ReadFrom(payload)
}

func (packetConn *serveStartPacketConn) WriteTo(payload []byte, address net.Addr) (int, error) {
	packetConn.markReady()
	return packetConn.PacketConn.WriteTo(payload, address)
}

func (packetConn *serveStartPacketConn) LocalAddr() net.Addr {
	packetConn.markReady()
	return packetConn.PacketConn.LocalAddr()
}

type oobServeStartPacketConn struct {
	*serveStartPacketConn
	oob        quic.OOBCapablePacketConn
	connection net.Conn
}

func (packetConn *oobServeStartPacketConn) Read(payload []byte) (int, error) {
	packetConn.markReady()
	return packetConn.connection.Read(payload)
}

func (packetConn *oobServeStartPacketConn) Write(payload []byte) (int, error) {
	packetConn.markReady()
	return packetConn.connection.Write(payload)
}

func (packetConn *oobServeStartPacketConn) RemoteAddr() net.Addr {
	packetConn.markReady()
	return packetConn.connection.RemoteAddr()
}

func (packetConn *oobServeStartPacketConn) SyscallConn() (syscall.RawConn, error) {
	packetConn.markReady()
	return packetConn.oob.SyscallConn()
}

func (packetConn *oobServeStartPacketConn) SetReadBuffer(bytes int) error {
	packetConn.markReady()
	return packetConn.oob.SetReadBuffer(bytes)
}

func (packetConn *oobServeStartPacketConn) SetWriteBuffer(bytes int) error {
	packetConn.markReady()
	if tunable, ok := packetConn.PacketConn.(interface{ SetWriteBuffer(int) error }); ok {
		return tunable.SetWriteBuffer(bytes)
	}
	return errors.New("packet connection does not support send-buffer tuning")
}

func (packetConn *oobServeStartPacketConn) ReadMsgUDP(payload, oob []byte) (int, int, int, *net.UDPAddr, error) {
	packetConn.markReady()
	return packetConn.oob.ReadMsgUDP(payload, oob)
}

func (packetConn *oobServeStartPacketConn) WriteMsgUDP(payload, oob []byte, address *net.UDPAddr) (int, int, error) {
	packetConn.markReady()
	return packetConn.oob.WriteMsgUDP(payload, oob, address)
}

func trackServeStart(packetConn net.PacketConn) (net.PacketConn, <-chan struct{}) {
	tracked := &serveStartPacketConn{PacketConn: packetConn, ready: make(chan struct{})}
	oob, hasOOB := packetConn.(quic.OOBCapablePacketConn)
	connection, hasConnection := packetConn.(net.Conn)
	if hasOOB && hasConnection {
		return &oobServeStartPacketConn{serveStartPacketConn: tracked, oob: oob, connection: connection}, tracked.ready
	}
	return tracked, tracked.ready
}

func (server *Server) Serve(packetConn net.PacketConn) error {
	if server == nil || server.inner == nil || packetConn == nil {
		return ErrInvalidSession
	}
	server.lifecycleMu.Lock()
	if server.closed || server.serveCalled {
		server.lifecycleMu.Unlock()
		return ErrInvalidSession
	}
	server.serveCalled = true
	tracked, ready := trackServeStart(packetConn)
	result := make(chan error, 1)
	go func() { result <- server.inner.Serve(tracked) }()
	select {
	case <-ready:
		// webtransport-go touches the PacketConn only after registering Serve in
		// its internal refCount. Releasing Close after this point prevents Add
		// from racing with Wait while preserving the optimized UDP interface.
		server.lifecycleMu.Unlock()
		return <-result
	case err := <-result:
		server.lifecycleMu.Unlock()
		return err
	}
}

func (server *Server) Close() error {
	if server == nil || server.inner == nil {
		return nil
	}
	server.closeOnce.Do(func() {
		server.lifecycleMu.Lock()
		server.closed = true
		server.closeErr = server.inner.Close()
		server.lifecycleMu.Unlock()
	})
	return server.closeErr
}

type Session struct {
	inner     *wt.Session
	path      carrier.Path
	capacity  uint16
	closeOnce sync.Once
	closeErr  error
}

func wrapSession(inner *wt.Session, capacity uint16, path carrier.Path) (*Session, error) {
	if inner == nil {
		return nil, ErrInvalidSession
	}
	if err := path.Validate(); err != nil {
		return nil, ErrInvalidSession
	}
	state := inner.SessionState().ConnectionState
	if state.Used0RTT {
		return nil, ErrEarlyData
	}
	if state.TLS.Version != tls.VersionTLS13 || !state.SupportsDatagrams.Local || !state.SupportsDatagrams.Remote ||
		!state.SupportsStreamResetPartialDelivery.Local {
		return nil, ErrInvalidSession
	}
	session := &Session{inner: inner, path: path, capacity: capacity}
	go session.rejectUnidirectionalApplicationStreams()
	return session, nil
}

func (*Session) Kind() carrier.Kind                 { return carrier.KindWebTransport }
func (session *Session) Path() carrier.Path         { return session.path }
func (session *Session) MaxIncomingStreams() uint16 { return session.capacity }

func (*Session) UnreliableAvailable() bool { return true }

func (session *Session) SendUnreliable(payload []byte) error {
	if len(payload) == 0 || len(payload) > carrier.MaxUnreliableWireBytes {
		return carrier.ErrUnreliableTooLarge
	}
	if err := session.inner.SendDatagram(payload); err != nil {
		var tooLarge *quic.DatagramTooLargeError
		if errors.As(err, &tooLarge) {
			return fmt.Errorf("%w: native limit %d", carrier.ErrUnreliableTooLarge, tooLarge.MaxDatagramPayloadSize)
		}
		return err
	}
	return nil
}

func (session *Session) ReceiveUnreliable(ctx context.Context) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	payload, err := session.inner.ReceiveDatagram(ctx)
	if err != nil {
		return nil, err
	}
	return payload, nil
}

func pathForConnectPath(path string) (carrier.Path, error) {
	switch path {
	case PathDirect:
		return carrier.PathDirect, nil
	case PathTunnel:
		return carrier.PathTunnel, nil
	default:
		return "", ErrInvalidURL
	}
}

func (session *Session) OpenStream(ctx context.Context) (carrier.Stream, error) {
	stream, err := session.inner.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	return &Stream{inner: stream, lifecycle: carrierlife.NewStream(session.inner.Context())}, nil
}

func (session *Session) AcceptStream(ctx context.Context) (carrier.Stream, error) {
	stream, err := session.inner.AcceptStream(ctx)
	if err != nil {
		return nil, err
	}
	return &Stream{inner: stream, lifecycle: carrierlife.NewStream(session.inner.Context())}, nil
}

func (session *Session) CloseWithError(applicationError carrier.ApplicationError) error {
	return session.CloseWithErrorContext(context.Background(), applicationError)
}

func (session *Session) CloseWithErrorContext(ctx context.Context, applicationError carrier.ApplicationError) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := validateApplicationError(applicationError); err != nil {
		return err
	}
	session.closeOnce.Do(func() {
		session.closeErr = normalizeSessionCloseError(session.inner.CloseWithError(wt.SessionErrorCode(applicationError.Code), applicationError.Reason))
	})
	return errors.Join(session.closeErr, context.Cause(ctx))
}

func normalizeSessionCloseError(err error) error {
	if err == nil {
		return nil
	}
	// webtransport-go cancels the CONNECT stream's write side immediately
	// before closing it and quic-go reports that exact successful teardown.
	const canceledStreamPrefix = "close called for canceled stream "
	streamID := strings.TrimPrefix(err.Error(), canceledStreamPrefix)
	if streamID != err.Error() {
		if _, parseErr := strconv.ParseUint(streamID, 10, 64); parseErr == nil {
			return nil
		}
	}
	return err
}

func (session *Session) Close() error {
	return session.CloseWithError(carrier.ApplicationError{})
}

func (session *Session) rejectUnidirectionalApplicationStreams() {
	for {
		stream, err := session.inner.AcceptUniStream(session.inner.Context())
		if err != nil {
			return
		}
		stream.CancelRead(streamResetCode)
	}
}

type Stream struct {
	inner          *wt.Stream
	lifecycle      *carrierlife.Stream
	closeWriteOnce sync.Once
	closeWriteErr  error
	resetOnce      sync.Once
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
	stream.closeWriteOnce.Do(func() { stream.closeWriteErr = stream.inner.Close() })
	stream.lifecycle.CloseWriteResult(stream.closeWriteErr)
	return stream.closeWriteErr
}

func (stream *Stream) Reset() error {
	stream.resetOnce.Do(func() {
		stream.inner.CancelRead(streamResetCode)
		stream.inner.CancelWrite(streamResetCode)
		stream.lifecycle.Terminate(carrier.ErrStreamReset)
	})
	return nil
}

func (stream *Stream) Close() error { return stream.Reset() }

func ValidateURL(rawURL string) error {
	_, err := parseURL(rawURL)
	return err
}

func parseURL(rawURL string) (*url.URL, error) {
	if rawURL == "" || strings.Contains(rawURL, "\\") || strings.Contains(rawURL, "%") {
		return nil, ErrInvalidURL
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.RawFragment != "" ||
		(parsed.Path != PathDirect && parsed.Path != PathTunnel) || parsed.RawPath != "" || parsed.Opaque != "" {
		return nil, ErrInvalidURL
	}
	if err := validateHostPort(parsed); err != nil {
		return nil, err
	}
	return parsed, nil
}

func validateOrigin(origin string) error {
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil ||
		parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return ErrInvalidURL
	}
	return validateHostPort(parsed)
}

func validateHostPort(parsed *url.URL) error {
	hostname := parsed.Hostname()
	if hostname == "" || strings.HasSuffix(hostname, ".") {
		return ErrInvalidURL
	}
	for _, char := range hostname {
		if char > 0x7f {
			return ErrInvalidURL
		}
	}
	if port := parsed.Port(); port != "" {
		value, err := strconv.ParseUint(port, 10, 16)
		if err != nil || value == 0 {
			return ErrInvalidURL
		}
	}
	return nil
}

func prepareTLS(config *tls.Config, server bool) (*tls.Config, error) {
	if config == nil || config.MinVersion < tls.VersionTLS13 ||
		(config.MaxVersion != 0 && config.MaxVersion < tls.VersionTLS13) {
		return nil, ErrInvalidTLS
	}
	if server {
		if !hasServerCertificate(config) {
			return nil, ErrInvalidTLS
		}
	} else if config.InsecureSkipVerify || config.RootCAs == nil || len(config.RootCAs.Subjects()) == 0 {
		return nil, ErrInvalidTLS
	}
	clone := config.Clone()
	if len(clone.NextProtos) == 0 {
		clone.NextProtos = []string{http3.NextProtoH3}
	}
	if len(clone.NextProtos) != 1 || clone.NextProtos[0] != http3.NextProtoH3 {
		return nil, ErrInvalidTLS
	}
	clone.MinVersion = tls.VersionTLS13
	return clone, nil
}

func hasServerCertificate(config *tls.Config) bool {
	if config.GetCertificate != nil || config.GetConfigForClient != nil {
		return true
	}
	for _, certificate := range config.Certificates {
		if len(certificate.Certificate) != 0 && certificate.PrivateKey != nil {
			return true
		}
	}
	return false
}

func validateApplicationError(applicationError carrier.ApplicationError) error {
	if applicationError.Code > maxSessionErrorCode ||
		len(applicationError.Reason) > carrier.MaxApplicationErrorReasonBytes ||
		!utf8.ValidString(applicationError.Reason) {
		return fmt.Errorf("%w: code or reason is out of range", ErrInvalidApplicationError)
	}
	return nil
}

var _ carrier.Session = (*Session)(nil)
var _ carrier.UnreliableTransport = (*Session)(nil)
var _ carrier.Stream = (*Stream)(nil)
