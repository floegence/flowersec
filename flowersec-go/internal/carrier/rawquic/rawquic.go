// Package rawquic adapts native QUIC bidirectional streams to Flowersec's
// transport-neutral carrier contract.
package rawquic

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier"
	carrierlife "github.com/floegence/flowersec/flowersec-go/v2/internal/carrier/internal/lifecycle"
	quic "github.com/quic-go/quic-go"
)

const (
	ALPNDirect = "flowersec-direct/2"
	ALPNTunnel = "flowersec-tunnel/2"

	streamResetCode            quic.StreamErrorCode      = 0xf502
	closeCode                  quic.ApplicationErrorCode = 0xf500
	maxQUICApplicationCode                               = 1<<62 - 1
	connectionIDLength                                   = 8
	maxStreamReceiveWindow                               = 6 << 20
	maxConnectionReceiveWindow                           = 16 << 20
)

var (
	ErrInvalidLimits           = errors.New("invalid raw QUIC limits")
	ErrInvalidALPN             = errors.New("invalid raw QUIC ALPN")
	ErrInvalidTLS              = errors.New("invalid raw QUIC TLS configuration")
	ErrInvalidApplicationError = errors.New("invalid raw QUIC application error")
	ErrEarlyData               = errors.New("raw QUIC application early data is forbidden")
)

// Limits bounds QUIC stream counts, buffering, and handshake liveness. Every
// field is required; callers can start from DefaultLimits and tune explicitly.
type Limits struct {
	MaxInboundStreams              int64
	InitialStreamReceiveWindow     uint64
	MaxStreamReceiveWindow         uint64
	InitialConnectionReceiveWindow uint64
	MaxConnectionReceiveWindow     uint64
	HandshakeIdleTimeout           time.Duration
	MaxIdleTimeout                 time.Duration
	KeepAlivePeriod                time.Duration
}

func DefaultLimits() Limits {
	return Limits{
		MaxInboundStreams:              carrier.MaxLogicalIncomingStreams + carrier.ReservedSessionStreams,
		InitialStreamReceiveWindow:     512 << 10,
		MaxStreamReceiveWindow:         6 << 20,
		InitialConnectionReceiveWindow: 1 << 20,
		MaxConnectionReceiveWindow:     16 << 20,
		HandshakeIdleTimeout:           10 * time.Second,
		MaxIdleTimeout:                 60 * time.Second,
		KeepAlivePeriod:                20 * time.Second,
	}
}

// BindSessionLimits reserves one native stream for control, one for RPC, and
// exactly maxLogical native streams for application data.
func BindSessionLimits(limits Limits, maxLogical uint16) (Limits, error) {
	physical, err := carrier.RequiredIncomingStreams(maxLogical)
	if err != nil {
		return Limits{}, err
	}
	limits.MaxInboundStreams = int64(physical)
	if err := limits.Validate(); err != nil {
		return Limits{}, err
	}
	return limits, nil
}

// Validate rejects limits that exceed Flowersec's bounded resource policy.
func (limits Limits) Validate() error {
	if limits.MaxInboundStreams < 1 || limits.MaxInboundStreams > 130 ||
		limits.InitialStreamReceiveWindow == 0 ||
		limits.InitialStreamReceiveWindow > maxStreamReceiveWindow ||
		limits.MaxStreamReceiveWindow > maxStreamReceiveWindow ||
		limits.InitialStreamReceiveWindow > limits.MaxStreamReceiveWindow ||
		limits.InitialConnectionReceiveWindow == 0 ||
		limits.InitialConnectionReceiveWindow > maxConnectionReceiveWindow ||
		limits.MaxConnectionReceiveWindow > maxConnectionReceiveWindow ||
		limits.InitialConnectionReceiveWindow > limits.MaxConnectionReceiveWindow ||
		limits.HandshakeIdleTimeout <= 0 || limits.MaxIdleTimeout <= 0 ||
		limits.KeepAlivePeriod < 0 || limits.KeepAlivePeriod >= limits.MaxIdleTimeout {
		return ErrInvalidLimits
	}
	return nil
}

// newConfig builds the non-early QUIC policy shared by clients and servers.
// Unidirectional application streams stay disabled; unreliable messages use
// native RFC 9221 DATAGRAM frames when the Flowersec handshake selects them.
func newConfig(limits Limits) (*quic.Config, error) {
	if err := limits.Validate(); err != nil {
		return nil, err
	}
	return &quic.Config{
		HandshakeIdleTimeout:             limits.HandshakeIdleTimeout,
		MaxIdleTimeout:                   limits.MaxIdleTimeout,
		InitialStreamReceiveWindow:       limits.InitialStreamReceiveWindow,
		MaxStreamReceiveWindow:           limits.MaxStreamReceiveWindow,
		InitialConnectionReceiveWindow:   limits.InitialConnectionReceiveWindow,
		MaxConnectionReceiveWindow:       limits.MaxConnectionReceiveWindow,
		MaxIncomingStreams:               limits.MaxInboundStreams,
		MaxIncomingUniStreams:            -1,
		KeepAlivePeriod:                  limits.KeepAlivePeriod,
		Allow0RTT:                        false,
		EnableDatagrams:                  true,
		EnableStreamResetPartialDelivery: true,
	}, nil
}

func Dial(ctx context.Context, address string, tlsConfig *tls.Config, limits Limits) (*Session, error) {
	preparedTLS, err := prepareTLS(tlsConfig, false)
	if err != nil {
		return nil, err
	}
	config, err := newConfig(limits)
	if err != nil {
		return nil, err
	}
	remote, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, err
	}
	if preparedTLS.ServerName == "" {
		host, _, splitErr := net.SplitHostPort(address)
		if splitErr != nil {
			return nil, splitErr
		}
		preparedTLS.ServerName = host
	}
	network := "udp6"
	local := &net.UDPAddr{IP: net.IPv6unspecified}
	if remote.IP.To4() != nil {
		network = "udp4"
		local.IP = net.IPv4zero
	}
	packetConn, err := net.ListenUDP(network, local)
	if err != nil {
		return nil, err
	}
	return dialPacketConn(ctx, remote, preparedTLS, config, uint16(limits.MaxInboundStreams), packetConn)
}

func dialPacketConn(
	ctx context.Context,
	remote net.Addr,
	tlsConfig *tls.Config,
	config *quic.Config,
	capacity uint16,
	packetConn net.PacketConn,
) (*Session, error) {
	transport := &quic.Transport{Conn: packetConn, ConnectionIDLength: connectionIDLength}
	conn, err := transport.Dial(ctx, remote, tlsConfig, config)
	if err != nil {
		_ = transport.Close()
		_ = packetConn.Close()
		return nil, err
	}
	session, err := newSession(conn, transport, packetConn, capacity)
	if err != nil {
		_ = conn.CloseWithError(closeCode, "invalid negotiated transport")
		_ = transport.Close()
		_ = packetConn.Close()
		return nil, err
	}
	return session, nil
}

type Listener struct {
	listener   *quic.Listener
	transport  *quic.Transport
	packetConn net.PacketConn
	capacity   uint16
	closeOnce  sync.Once
	closeErr   error
}

func Listen(address string, tlsConfig *tls.Config, limits Limits) (*Listener, error) {
	preparedTLS, err := prepareTLS(tlsConfig, true)
	if err != nil {
		return nil, err
	}
	config, err := newConfig(limits)
	if err != nil {
		return nil, err
	}
	local, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, err
	}
	packetConn, err := net.ListenUDP("udp", local)
	if err != nil {
		return nil, err
	}
	transport := &quic.Transport{Conn: packetConn, ConnectionIDLength: connectionIDLength}
	listener, err := transport.Listen(preparedTLS, config)
	if err != nil {
		_ = transport.Close()
		_ = packetConn.Close()
		return nil, err
	}
	return &Listener{listener: listener, transport: transport, packetConn: packetConn, capacity: uint16(limits.MaxInboundStreams)}, nil
}

func (listener *Listener) Accept(ctx context.Context) (*Session, error) {
	conn, err := listener.listener.Accept(ctx)
	if err != nil {
		return nil, err
	}
	session, err := newSession(conn, nil, nil, listener.capacity)
	if err != nil {
		_ = conn.CloseWithError(closeCode, "invalid negotiated transport")
		return nil, err
	}
	return session, nil
}

func (listener *Listener) Addr() net.Addr { return listener.listener.Addr() }
func (listener *Listener) Close() error {
	listener.closeOnce.Do(func() {
		listenerErr := listener.listener.Close()
		transportErr := listener.transport.Close()
		packetErr := listener.packetConn.Close()
		listener.closeErr = errors.Join(listenerErr, transportErr, packetErr)
	})
	return listener.closeErr
}

type Session struct {
	conn       *quic.Conn
	transport  *quic.Transport
	packetConn net.PacketConn
	path       carrier.Path
	capacity   uint16
	closeOnce  sync.Once
	closeErr   error

	migrationMu sync.Mutex
	migration   *migrationPath
	// quic-go registers the live connection with every transport that sends a
	// path probe. Closing one of those transports would terminate the connection,
	// so their sockets remain session-owned until connection teardown.
	migrationTransports []*migrationPath
}

type migrationPath struct {
	path      *quic.Path
	transport *quic.Transport
	conn      net.PacketConn
}

func newSession(conn *quic.Conn, transport *quic.Transport, packetConn net.PacketConn, capacity uint16) (*Session, error) {
	state := conn.ConnectionState()
	if state.Used0RTT {
		return nil, ErrEarlyData
	}
	if !validALPN(state.TLS.NegotiatedProtocol) {
		return nil, ErrInvalidALPN
	}
	if !state.SupportsDatagrams.Local || !state.SupportsDatagrams.Remote {
		return nil, carrier.ErrUnreliableUnavailable
	}
	path := carrier.PathDirect
	if state.TLS.NegotiatedProtocol == ALPNTunnel {
		path = carrier.PathTunnel
	}
	return &Session{conn: conn, transport: transport, packetConn: packetConn, path: path, capacity: capacity}, nil
}

func (*Session) Kind() carrier.Kind                 { return carrier.KindQUIC }
func (session *Session) Path() carrier.Path         { return session.path }
func (session *Session) MaxIncomingStreams() uint16 { return session.capacity }

func (*Session) UnreliableAvailable() bool { return true }

func (session *Session) SendUnreliable(payload []byte) error {
	if len(payload) == 0 || len(payload) > carrier.MaxUnreliableWireBytes {
		return carrier.ErrUnreliableTooLarge
	}
	if err := session.conn.SendDatagram(payload); err != nil {
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
	payload, err := session.conn.ReceiveDatagram(ctx)
	if err != nil {
		return nil, err
	}
	return payload, nil
}

func (session *Session) OpenStream(ctx context.Context) (carrier.Stream, error) {
	stream, err := session.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	return &Stream{stream: stream, lifecycle: carrierlife.NewStream(session.conn.Context())}, nil
}

func (session *Session) AcceptStream(ctx context.Context) (carrier.Stream, error) {
	stream, err := session.conn.AcceptStream(ctx)
	if err != nil {
		return nil, err
	}
	return &Stream{stream: stream, lifecycle: carrierlife.NewStream(session.conn.Context())}, nil
}

func (session *Session) CloseWithError(applicationError carrier.ApplicationError) error {
	return session.CloseWithErrorContext(context.Background(), applicationError)
}

func (session *Session) CloseWithErrorContext(ctx context.Context, applicationError carrier.ApplicationError) error {
	if ctx == nil {
		ctx = context.Background()
	}
	validated, err := ValidateApplicationError(applicationError)
	if err != nil {
		return err
	}
	session.closeOnce.Do(func() {
		connectionErr := session.conn.CloseWithError(quic.ApplicationErrorCode(validated.Code), validated.Reason)
		session.migrationMu.Lock()
		migrationErr := closeMigrationTransports(session.migrationTransports)
		session.migration = nil
		session.migrationTransports = nil
		session.migrationMu.Unlock()
		var transportErr, packetErr error
		if session.transport != nil {
			transportErr = session.transport.Close()
		}
		if session.packetConn != nil {
			packetErr = session.packetConn.Close()
		}
		session.closeErr = errors.Join(connectionErr, migrationErr, transportErr, packetErr)
	})
	return errors.Join(session.closeErr, context.Cause(ctx))
}

func (session *Session) Close() error {
	return session.CloseWithError(carrier.ApplicationError{Code: uint64(closeCode)})
}

// Migrate validates a new client-side network path and atomically switches the
// live QUIC connection to it. Ownership of packetConn transfers to the session
// on entry. Once probing starts, its transport remains owned until session close
// because quic-go binds the live connection to every probed transport.
func (session *Session) Migrate(ctx context.Context, packetConn net.PacketConn) error {
	if session == nil || session.conn == nil || packetConn == nil {
		if packetConn != nil {
			_ = packetConn.Close()
		}
		return net.ErrClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}
	session.migrationMu.Lock()
	defer session.migrationMu.Unlock()
	if err := session.conn.Context().Err(); err != nil {
		_ = packetConn.Close()
		return err
	}
	transport := &quic.Transport{Conn: packetConn, ConnectionIDLength: connectionIDLength}
	path, err := session.conn.AddPath(transport)
	if err != nil {
		_ = transport.Close()
		_ = packetConn.Close()
		return err
	}
	candidate := &migrationPath{path: path, transport: transport, conn: packetConn}
	session.migrationTransports = append(session.migrationTransports, candidate)
	if err := path.Probe(ctx); err != nil {
		_ = path.Close()
		return err
	}
	if err := path.Switch(); err != nil {
		_ = path.Close()
		return err
	}
	previous := session.migration
	session.migration = candidate
	if previous != nil {
		_ = previous.path.Close()
	}
	return nil
}

func closeMigrationTransports(migrations []*migrationPath) error {
	var result error
	for _, migration := range migrations {
		if migration == nil {
			continue
		}
		result = errors.Join(result, migration.transport.Close(), migration.conn.Close())
	}
	return result
}

func ValidateApplicationError(applicationError carrier.ApplicationError) (carrier.ApplicationError, error) {
	if applicationError.Code > maxQUICApplicationCode ||
		len(applicationError.Reason) > carrier.MaxApplicationErrorReasonBytes ||
		!utf8.ValidString(applicationError.Reason) {
		return carrier.ApplicationError{}, ErrInvalidApplicationError
	}
	return applicationError, nil
}

type Stream struct {
	stream         *quic.Stream
	lifecycle      *carrierlife.Stream
	closeWriteOnce sync.Once
	closeWriteErr  error
	resetOnce      sync.Once
}

func (stream *Stream) Read(payload []byte) (int, error) {
	n, err := stream.stream.Read(payload)
	stream.lifecycle.ReadResult(err)
	return n, err
}

func (stream *Stream) Write(payload []byte) (int, error) {
	n, err := stream.stream.Write(payload)
	stream.lifecycle.WriteResult(err)
	return n, err
}

func (stream *Stream) Context() context.Context { return stream.lifecycle.Context() }

func (stream *Stream) CloseWrite() error {
	stream.closeWriteOnce.Do(func() { stream.closeWriteErr = stream.stream.Close() })
	stream.lifecycle.CloseWriteResult(stream.closeWriteErr)
	return stream.closeWriteErr
}

func (stream *Stream) Reset() error {
	stream.resetOnce.Do(func() {
		stream.stream.CancelRead(streamResetCode)
		stream.stream.CancelWrite(streamResetCode)
		stream.lifecycle.Terminate(carrier.ErrStreamReset)
	})
	return nil
}

func (stream *Stream) Close() error { return stream.Reset() }

func prepareTLS(config *tls.Config, server bool) (*tls.Config, error) {
	if config == nil || config.MinVersion < tls.VersionTLS13 ||
		(config.MaxVersion != 0 && config.MaxVersion < tls.VersionTLS13) {
		return nil, fmt.Errorf("%w: TLS 1.3 is required", ErrInvalidTLS)
	}
	if server {
		if !hasServerCertificate(config) {
			return nil, fmt.Errorf("%w: server certificate material is required", ErrInvalidTLS)
		}
	} else if config.InsecureSkipVerify || config.RootCAs == nil || len(config.RootCAs.Subjects()) == 0 {
		return nil, fmt.Errorf("%w: explicit client verification roots are required", ErrInvalidTLS)
	}
	if len(config.NextProtos) != 1 || !validALPN(config.NextProtos[0]) {
		return nil, fmt.Errorf("%w: exactly one registered path profile is required", ErrInvalidALPN)
	}
	clone := config.Clone()
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

func validALPN(value string) bool { return value == ALPNDirect || value == ALPNTunnel }

var _ carrier.Session = (*Session)(nil)
var _ carrier.UnreliableTransport = (*Session)(nil)
var _ carrier.PathMigrator = (*Session)(nil)
var _ carrier.Stream = (*Stream)(nil)
