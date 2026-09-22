package websocket

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/carrierv4/numeric"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	ws "github.com/gorilla/websocket"
)

var (
	ErrNonBinary    = errors.New("websocketv4: nonbinary message")
	ErrExtensions   = errors.New("websocketv4: extensions are forbidden")
	ErrSubprotocol  = errors.New("websocketv4: unexpected subprotocol")
	ErrHeaderLimit  = errors.New("websocketv4: HTTP upgrade exceeds limit")
	ErrTLSHandshake = errors.New("websocketv4: TLS policy or handshake failed")
	ErrControlRate  = errors.New("websocketv4: control message rate exceeded")
	ErrConcurrent   = errors.New("websocketv4: concurrent message operation")
	ErrHTTPVersion  = errors.New("websocketv4: HTTP/1.1 upgrade required")
	ErrEndpoint     = numeric.ErrEndpoint
	ErrDialPlatform = numeric.ErrPlatform
)

// DialConfig is trusted local configuration. CheckPolicy must validate the
// signed endpoint/path, Origin, application authentication and transport policy
// before any connection. In particular, ws is allowed only for the authorized
// private loopback profile. TLSConfig supplies the applicable CA/pin policy.
// RemoteAddress is one previously prepared numeric endpoint. CheckPolicy must
// bind it to the original URL and authorization; DNS resolution, address
// selection and their task/cleanup accounting belong to the preparing caller.
// This factory never resolves a hostname, races addresses or retries another
// endpoint. URL remains the HTTP authority and the default TLS verification
// name. A numeric URL must match RemoteAddress, including the effective port.
// Dial supports Darwin and Linux. Numeric IPv6 zone IDs must be prepared by
// the caller; this provider does not resolve interface names either.
// This factory does not inject Flowersec credentials, cookies or proxy settings.
// Header, URL and CheckPolicy are borrowed only for this synchronous prepare
// call and must not be mutated concurrently. TLSConfig is cloned after charge
// admission; its shared trust stores, callbacks and session cache remain
// caller-qualified immutable TLS policy state for the connection lifetime.
type DialConfig struct {
	URL, Subprotocol string
	RemoteAddress    netip.AddrPort
	Header           http.Header
	TLSConfig        *tls.Config
	CheckPolicy      func(*url.URL, netip.AddrPort, http.Header) error
	// PrepareBytes caps aggregate physical socket reads and writes through
	// TLS and HTTP preparation. Zero uses the finite 256 KiB provider ceiling.
	PrepareBytes uint64
}

// UpgradeConfig requires an explicit trusted policy for TLS, path, Origin,
// absent-Origin handling and application authentication. HTTP server parsing,
// header caps and TLS termination preceding Upgrade are host responsibilities.
// A browser's extension offer is permitted; the response negotiates none.
type UpgradeConfig struct {
	Subprotocol    string
	ResponseHeader http.Header
	CheckPolicy    func(*http.Request) error
	// CheckAcceptedRoute is required for a later direct Session entrance.
	// It is a bounded local trusted deployment check of the original signed
	// candidate's complete TLS/pin/consumer and application policy, using the
	// immutable observations below. Its shared storage must be preadmitted in
	// the same Environment and remain immutable until provider cleanup.
	// It must not perform I/O, invoke application code or retain its arguments.
	CheckAcceptedRoute func(protocolv4.AcceptedWebSocketEndpoint, *protocolv4.SignedMap, uint64, protocolv4.HelloPolicy) error
}

func validSubprotocol(s string) bool {
	return s == SubprotocolDirect || s == SubprotocolTunnel || s == SubprotocolLocal
}

func checkEndpoint(u *url.URL, address netip.AddrPort) error {
	if !address.IsValid() || address.Port() == 0 || u.Hostname() == "" {
		return ErrEndpoint
	}
	port := uint64(80)
	if u.Scheme == "wss" {
		port = 443
	}
	if explicit := u.Port(); explicit != "" {
		var err error
		port, err = strconv.ParseUint(explicit, 10, 16)
		if err != nil {
			return ErrEndpoint
		}
	}
	if port != uint64(address.Port()) {
		return ErrEndpoint
	}
	if numeric, err := netip.ParseAddr(u.Hostname()); err == nil && numeric.Unmap() != address.Addr().Unmap() {
		return ErrEndpoint
	}
	return nil
}

// The original prepare call performs the one numeric connect synchronously.
// No standard dialer cancellation callback can outlive that original owner.
func (m *owner) dialEndpoint(ctx context.Context, address netip.AddrPort) (net.Conn, error) {
	conn, err := connectNumeric(ctx, address, operationDeadline(ctx, m.options.HandshakeTimeout))
	if err != nil {
		return nil, err
	}
	return m.attach(conn)
}

// headerSize validates before Gorilla copies caller headers. Reject all
// case variants of reserved upgrade headers, including noncanonical map keys.
func headerSize(h http.Header, limit uint32, outbound bool) (uint64, error) {
	var total uint64
	for key, values := range h {
		if outbound && (strings.EqualFold(key, "Sec-WebSocket-Extensions") || strings.EqualFold(key, "Sec-WebSocket-Protocol") || strings.EqualFold(key, "Sec-WebSocket-Key") || strings.EqualFold(key, "Sec-WebSocket-Version") || strings.EqualFold(key, "Connection") || strings.EqualFold(key, "Upgrade")) {
			return 0, resourcev4.ErrConfiguration
		}
		if len(key) == 0 || strings.ContainsAny(key, "\r\n") {
			return 0, resourcev4.ErrConfiguration
		}
		for _, value := range values {
			if strings.ContainsAny(value, "\r\n") {
				return 0, resourcev4.ErrConfiguration
			}
			total += uint64(len(key)) + uint64(len(value)) + 4
			if total > uint64(limit) {
				return 0, ErrHeaderLimit
			}
		}
		// Even empty header slices consume map entries when copied.
		if len(values) == 0 {
			total += uint64(len(key)) + 4
			if total > uint64(limit) {
				return 0, ErrHeaderLimit
			}
		}
	}
	return total, nil
}

// Dial performs only credential-free carrier preparation. The supplied context
// belongs to this call, not the returned connection lifetime. Errors from
// policy, dialing, TLS and HTTP upgrade retain their original identity.
func Dial(ctx context.Context, cfg DialConfig, options Options, reservation, environment resourcev4.Reference) (*Messages, error) {
	if ctx == nil || cfg.CheckPolicy == nil || !validSubprotocol(cfg.Subprotocol) {
		return nil, resourcev4.ErrConfiguration
	}
	if !cfg.RemoteAddress.IsValid() || cfg.RemoteAddress.Port() == 0 {
		return nil, ErrEndpoint
	}
	if err := checkDialPlatform(cfg.RemoteAddress); err != nil {
		return nil, err
	}
	if _, err := Charge(options); err != nil {
		return nil, err
	}
	if cfg.PrepareBytes > 262144 {
		return nil, resourcev4.ErrConfiguration
	}
	n, err := headerSize(cfg.Header, options.HandshakeBytes, true)
	if err != nil {
		return nil, err
	}
	if uint64(len(cfg.URL))+n+512 > uint64(options.HandshakeBytes) {
		return nil, ErrHeaderLimit
	}
	m, err := newOwner(ctx, options, reservation, environment)
	if err != nil {
		return nil, err
	}
	m.prepareBytes = cfg.PrepareBytes
	if m.prepareBytes == 0 {
		m.prepareBytes = 262144
	}
	success := false
	defer func() { m.finishPrepare(success) }()
	u, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, err
	}
	if u.User != nil || u.Fragment != "" || (u.Scheme != "ws" && u.Scheme != "wss") {
		return nil, resourcev4.ErrConfiguration
	}
	if err := checkEndpoint(u, cfg.RemoteAddress); err != nil {
		return nil, err
	}
	if err := cfg.CheckPolicy(u, cfg.RemoteAddress, cfg.Header); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	dialer := ws.Dialer{ReadBufferSize: int(options.ReadBufferBytes), WriteBufferSize: int(options.WriteBufferBytes),
		Subprotocols: []string{cfg.Subprotocol}}
	dialer.NetDialContext = func(call context.Context, _, _ string) (net.Conn, error) {
		conn, err := m.dialEndpoint(call, cfg.RemoteAddress)
		if err != nil {
			return nil, err
		}
		return m.httpTransport(conn)
	}
	if u.Scheme == "wss" {
		if cfg.TLSConfig == nil || cfg.TLSConfig.MinVersion > tls.VersionTLS13 || cfg.TLSConfig.MaxVersion != 0 && cfg.TLSConfig.MaxVersion < tls.VersionTLS13 {
			return nil, resourcev4.ErrConfiguration
		}
		if cfg.TLSConfig.InsecureSkipVerify && cfg.TLSConfig.VerifyConnection == nil && cfg.TLSConfig.VerifyPeerCertificate == nil {
			return nil, errors.Join(ErrTLSHandshake, resourcev4.ErrConfiguration)
		}
		tlsConfig := cfg.TLSConfig.Clone()
		tlsConfig.MinVersion, tlsConfig.MaxVersion = tls.VersionTLS13, tls.VersionTLS13
		tlsConfig.NextProtos = []string{"http/1.1"}
		if tlsConfig.ServerName == "" {
			tlsConfig.ServerName = u.Hostname()
		}
		dialer.NetDialTLSContext = func(call context.Context, _, _ string) (net.Conn, error) {
			raw, err := m.dialEndpoint(call, cfg.RemoteAddress)
			if err != nil {
				return nil, err
			}
			// Attach the physical socket before TLS starts. Cancellation and
			// TLS failure retain its original Close owner and prepare pin.
			conn := tls.Client(raw, tlsConfig)
			// Handshake uses Background internally. The owned socket deadline
			// and lifecycle worker enforce timeout/cancellation without TLS
			// scheduling an unjoined context.AfterFunc observer.
			if err := conn.Handshake(); err != nil {
				return nil, errors.Join(ErrTLSHandshake, err)
			}
			state := conn.ConnectionState()
			if state.Version != tls.VersionTLS13 || (state.NegotiatedProtocol != "" && state.NegotiatedProtocol != "http/1.1") {
				return nil, errors.Join(ErrTLSHandshake, resourcev4.ErrConfiguration)
			}
			m.mu.Lock()
			m.consumerTLS13 = true
			m.mu.Unlock()
			return m.httpTransport(conn)
		}
	}
	// Gorilla's HandshakeTimeout remains zero: its WithTimeout would otherwise
	// create a runtime timer callback outside the owned lifecycle. The explicit
	// deadline bounds numeric connect, TLS and HTTP through this same socket.
	conn, response, err := dialer.DialContext(&callContext{Context: ctx, lifetime: m.lifetime, deadline: operationDeadline(ctx, options.HandshakeTimeout)}, cfg.URL, cfg.Header)
	if err != nil {
		return nil, preferContext(ctx, err)
	}
	if response.ProtoMajor != 1 || response.ProtoMinor != 1 {
		return nil, ErrHTTPVersion
	}
	// Gorilla accepts unsolicited valid permessage-deflate responses. Inspect
	// every response field before any WebSocket read or credential publication.
	for _, value := range response.Header.Values("Sec-WebSocket-Extensions") {
		if strings.TrimSpace(value) != "" {
			return nil, ErrExtensions
		}
	}
	if conn.Subprotocol() != cfg.Subprotocol || len(response.Header.Values("Sec-WebSocket-Protocol")) != 1 {
		return nil, ErrSubprotocol
	}
	if err := m.install(conn, ctx); err != nil {
		return nil, err
	}
	m.mu.Lock()
	m.consumer = true
	m.mu.Unlock()
	success = true
	return &Messages{m}, nil
}

// Upgrade takes ownership only of the connection actually hijacked by its own
// Gorilla upgrader. It does not accept caller-built WebSocket connections.
func Upgrade(ctx context.Context, w http.ResponseWriter, request *http.Request, cfg UpgradeConfig, options Options, reservation, environment resourcev4.Reference) (*Messages, error) {
	if ctx == nil || w == nil || request == nil || cfg.CheckPolicy == nil || !validSubprotocol(cfg.Subprotocol) {
		return nil, resourcev4.ErrConfiguration
	}
	if _, err := Charge(options); err != nil {
		return nil, err
	}
	n, err := headerSize(request.Header, options.HandshakeBytes, false)
	if err != nil {
		return nil, err
	}
	if n+uint64(len(request.RequestURI))+uint64(len(request.Host))+512 > uint64(options.HandshakeBytes) {
		return nil, ErrHeaderLimit
	}
	if _, err := headerSize(cfg.ResponseHeader, options.HandshakeBytes-512, true); err != nil {
		return nil, err
	}
	m, err := newOwner(ctx, options, reservation, environment)
	if err != nil {
		return nil, err
	}
	success := false
	defer func() { m.finishPrepare(success) }()
	if err := cfg.CheckPolicy(request); err != nil {
		return nil, err
	}
	if cfg.CheckAcceptedRoute != nil {
		endpoint, err := ObserveAcceptedEndpoint(request, cfg.Subprotocol)
		if err != nil {
			return nil, err
		}
		m.acceptedEndpoint, m.checkAcceptedRoute = endpoint, cfg.CheckAcceptedRoute
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if request.ProtoMajor != 1 || request.ProtoMinor != 1 {
		return nil, ErrHTTPVersion
	}
	found := false
	for _, offered := range ws.Subprotocols(request) {
		found = found || offered == cfg.Subprotocol
	}
	if !found {
		return nil, ErrSubprotocol
	}
	upgrader := ws.Upgrader{ReadBufferSize: int(options.ReadBufferBytes), WriteBufferSize: int(options.WriteBufferBytes),
		Subprotocols: []string{cfg.Subprotocol}, HandshakeTimeout: options.HandshakeTimeout, CheckOrigin: func(*http.Request) bool { return true }}
	conn, err := upgrader.Upgrade(&upgradeWriter{ResponseWriter: w, owner: m}, request, cfg.ResponseHeader)
	if err != nil {
		return nil, preferContext(ctx, err)
	}
	if conn.Subprotocol() != cfg.Subprotocol {
		return nil, ErrSubprotocol
	}
	if err := m.install(conn, ctx); err != nil {
		return nil, err
	}
	success = true
	return &Messages{m}, nil
}

func preferContext(ctx context.Context, err error) error {
	if cause := ctx.Err(); cause != nil {
		return cause
	}
	return err
}

func operationDeadline(ctx context.Context, timeout time.Duration) time.Time {
	deadline := time.Now().Add(timeout)
	if caller, ok := ctx.Deadline(); ok && caller.Before(deadline) {
		return caller
	}
	return deadline
}

// ReadMessage streams exactly one binary message into the caller's existing
// reservation. Legal WS continuation frames remain one message. No following
// message is consumed, and partial bytes with an error must never be published.
func (m *Messages) ReadMessage(ctx context.Context, dst []byte) (n int, err error) {
	if m == nil || m.owner == nil {
		return 0, net.ErrClosed
	}
	conn, err := m.begin(ctx, false)
	if err != nil {
		return 0, err
	}
	defer func() { err = m.finish(ctx, false, err) }()
	limit := len(dst)
	if limit > int(m.options.MaxMessageBytes) {
		limit = int(m.options.MaxMessageBytes)
	}
	if limit == 0 {
		return 0, io.ErrShortBuffer
	}
	conn.SetReadLimit(int64(limit))
	if err := conn.SetReadDeadline(operationDeadline(ctx, m.options.MessageTimeout)); err != nil {
		return 0, err
	}
	kind, reader, err := conn.NextReader()
	if err != nil {
		return 0, readError(err)
	}
	if kind != ws.BinaryMessage {
		return 0, ErrNonBinary
	}
	for n < limit {
		count, readErr := reader.Read(dst[n:limit])
		n += count
		if readErr == io.EOF {
			return n, nil
		}
		if readErr != nil {
			return n, readError(readErr)
		}
	}
	var probe [1]byte
	count, err := reader.Read(probe[:])
	if count != 0 {
		return n, protocolv4.ErrPayloadTooLarge
	}
	if err == io.EOF {
		return n, nil
	}
	return n, readError(err)
}

func readError(err error) error {
	if errors.Is(err, ws.ErrReadLimit) {
		return protocolv4.ErrPayloadTooLarge
	}
	return err
}

// WriteMessage publishes the original complete message without another
// application buffer. InitialExchange/SessionMessageInput own envelope phase
// validation and writer serialization. A zero-length write sends no message.
func (m *Messages) WriteMessage(ctx context.Context, wire []byte) (err error) {
	if m == nil || m.owner == nil {
		return net.ErrClosed
	}
	conn, err := m.begin(ctx, true)
	if err != nil {
		return err
	}
	defer func() { err = m.finish(ctx, true, err) }()
	if len(wire) == 0 {
		return nil
	}
	if uint64(len(wire)) > uint64(m.options.MaxMessageBytes) {
		return protocolv4.ErrPayloadTooLarge
	}
	if err := conn.SetWriteDeadline(operationDeadline(ctx, m.options.MessageTimeout)); err != nil {
		return err
	}
	return conn.WriteMessage(ws.BinaryMessage, wire)
}
