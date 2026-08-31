// Package candidatev3 composes concrete runtime adapters into credential-free
// candidate attempts and one-shot admission commits.
package candidatev3

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"sync"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v4/internal/admissionv3"
	websocketadmission "github.com/floegence/flowersec/flowersec-go/v4/internal/admissionv3/websocket"
	"github.com/floegence/flowersec/flowersec-go/v4/internal/artifactv3"
	"github.com/floegence/flowersec/flowersec-go/v4/internal/carrier"
	"github.com/floegence/flowersec/flowersec-go/v4/internal/carrier/quicbase"
	rawquic "github.com/floegence/flowersec/flowersec-go/v4/internal/carrier/rawquicv3"
	carrierws "github.com/floegence/flowersec/flowersec-go/v4/internal/carrier/websocketv3"
	carrierwt "github.com/floegence/flowersec/flowersec-go/v4/internal/carrier/webtransportv3"
	"github.com/floegence/flowersec/flowersec-go/v4/internal/transportsecurity"
	gorillaws "github.com/gorilla/websocket"
	quic "github.com/quic-go/quic-go"
)

var (
	ErrInvalidCarrierCandidate  = errors.New("invalid Flowersec v3 carrier candidate")
	ErrInvalidCarrierDialConfig = errors.New("invalid Flowersec v3 carrier dial configuration")
)

type WebSocketDialConfig struct {
	Dialer                      *gorillaws.Dialer
	Resources                   carrierws.ResourcePolicy
	Origin                      string
	PlaintextLoopbackDirectOnly bool
}

type RawQUICDialConfig struct {
	TLSConfig *tls.Config
	Limits    quicbase.Limits
	Dial      func(context.Context, string, *tls.Config, quicbase.Limits) (*rawquic.Session, error)
}

type WebTransportDialConfig struct {
	TLSConfig *tls.Config
	Limits    quicbase.Limits
	Origin    string
}

// GoNativeConfig contains the runtime inputs shared by the production Go
// WebSocket, raw QUIC, and WebTransport adapters.
type GoNativeConfig struct {
	TrustRoots                 *x509.CertPool
	Origin                     string
	RootlessLoopbackDirectOnly bool
}

// NewGoNativeFactory composes the production adapters available in one Go
// runtime. WebTransport is present only when its required origin is present.
func NewGoNativeFactory(config GoNativeConfig) (*Factory, error) {
	if config.RootlessLoopbackDirectOnly {
		return nil, ErrInvalidCarrierDialConfig
	}
	webSocketClient := *gorillaws.DefaultDialer
	webSocketClient.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
	if config.TrustRoots != nil {
		webSocketClient.TLSClientConfig.RootCAs = config.TrustRoots.Clone()
	}
	webSocketDial, err := NewWebSocketCarrierDial(WebSocketDialConfig{
		Dialer:    &webSocketClient,
		Resources: carrierws.DefaultResourcePolicy(),
		Origin:    config.Origin,
	})
	if err != nil {
		return nil, err
	}
	dialers := map[artifactv3.Carrier]Dial{
		artifactv3.CarrierWebSocket: webSocketDial,
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
	if config.TrustRoots != nil {
		tlsConfig.RootCAs = config.TrustRoots.Clone()
	}
	rawQUICDial, err := NewRawQUICCarrierDial(RawQUICDialConfig{
		TLSConfig: tlsConfig.Clone(), Limits: quicbase.DefaultLimits(), Dial: rawquic.Dial,
	})
	if err != nil {
		return nil, err
	}
	dialers[artifactv3.CarrierRawQUIC] = rawQUICDial
	webTransportDial, err := NewWebTransportCarrierDial(WebTransportDialConfig{
		TLSConfig: tlsConfig.Clone(),
		Limits:    quicbase.DefaultLimits(),
		Origin:    config.Origin,
	})
	if err != nil {
		return nil, err
	}
	dialers[artifactv3.CarrierWebTransport] = webTransportDial
	return NewFactory(dialers)
}

// RootlessLoopbackDirectOnly reports whether every candidate belongs to the
// restricted plaintext loopback direct profile. A mixed or secure candidate
// set always requires explicit trust roots.
func RootlessLoopbackDirectOnly(artifact artifactv3.Artifact) bool {
	return false
}

// NewWebTransportCarrierDial completes HTTP/3 CONNECT and opens one native
// bidirectional admission stream without sending Flowersec credentials.
func NewWebTransportCarrierDial(config WebTransportDialConfig) (Dial, error) {
	if !validQUICClientTLS(config.TLSConfig) ||
		(config.TLSConfig.MaxVersion != 0 && config.TLSConfig.MaxVersion < tls.VersionTLS13) {
		return nil, ErrInvalidCarrierDialConfig
	}
	if err := config.Limits.Validate(); err != nil {
		return nil, err
	}
	baseTLS := config.TLSConfig.Clone()
	if baseTLS.MinVersion < tls.VersionTLS13 {
		baseTLS.MinVersion = tls.VersionTLS13
	}
	return func(ctx context.Context, candidate artifactv3.Candidate, contract artifactv3.SessionContract, attemptNow time.Time) (ReadyCarrier, error) {
		dialURL, err := validateWebTransportCandidate(candidate)
		if err != nil {
			return nil, err
		}
		limits, err := quicbase.BindSessionLimits(config.Limits, contract.MaxInboundStreams)
		if err != nil {
			return nil, err
		}
		bindQUICTimeouts(&limits, contract)
		if ctx == nil {
			ctx = context.Background()
		}
		attemptTLS, err := transportsecurity.BuildClientTLSSnapshot(baseTLS, dialURL, candidate.TLS)
		if err != nil {
			return nil, err
		}
		dialer, err := carrierwt.NewDialer(attemptTLS, limits)
		if err != nil {
			return nil, err
		}
		stopLocalClose := context.AfterFunc(ctx, func() { _ = dialer.CloseLocal() })
		session, err := dialer.Dial(ctx, dialURL, config.Origin)
		if !stopLocalClose() {
			_ = dialer.CloseLocal()
			_ = dialer.Close()
			return nil, context.Cause(ctx)
		}
		if err != nil {
			_ = dialer.CloseLocal()
			_ = dialer.Close()
			if isQUICTLSFailure(err) {
				return nil, transportsecurity.ClassifyLocatedTLSFailure(candidate.TLS, err)
			}
			return nil, err
		}
		stream, err := carrierwt.AcceptAdmissionStream(ctx, session)
		if err != nil {
			_ = session.Close()
			_ = dialer.CloseLocal()
			_ = dialer.Close()
			return nil, err
		}
		owned := &ownedCarrierSession{Session: session, owner: dialer}
		return &streamAdmissionHandle{
			session: owned,
			stream:  stream,
		}, nil
	}, nil
}

// NewRawQUICCarrierDial reaches 1-RTT with one exact path ALPN and opens the
// native bidirectional admission stream without sending FSB3.
func NewRawQUICCarrierDial(config RawQUICDialConfig) (Dial, error) {
	if config.Dial == nil || !validQUICClientTLS(config.TLSConfig) ||
		(config.TLSConfig.MaxVersion != 0 && config.TLSConfig.MaxVersion < tls.VersionTLS13) {
		return nil, ErrInvalidCarrierDialConfig
	}
	if err := config.Limits.Validate(); err != nil {
		return nil, err
	}
	baseTLS := config.TLSConfig.Clone()
	if baseTLS.MinVersion < tls.VersionTLS13 {
		baseTLS.MinVersion = tls.VersionTLS13
	}
	return func(ctx context.Context, candidate artifactv3.Candidate, contract artifactv3.SessionContract, attemptNow time.Time) (ReadyCarrier, error) {
		address, alpn, err := validateRawQUICCandidate(candidate)
		if err != nil {
			return nil, err
		}
		_, canonical, err := canonicalDialCandidate(candidate, artifactv3.CarrierRawQUIC)
		if err != nil {
			return nil, err
		}
		tlsConfig, err := transportsecurity.BuildClientTLSSnapshot(baseTLS, canonical.NormalizedURL, candidate.TLS)
		if err != nil {
			return nil, err
		}
		tlsConfig.NextProtos = []string{alpn}
		limits, err := quicbase.BindSessionLimits(config.Limits, contract.MaxInboundStreams)
		if err != nil {
			return nil, err
		}
		bindQUICTimeouts(&limits, contract)
		session, err := config.Dial(ctx, address, tlsConfig, limits)
		if err != nil {
			if isQUICTLSFailure(err) {
				return nil, transportsecurity.ClassifyLocatedTLSFailure(candidate.TLS, err)
			}
			return nil, err
		}
		stream, err := rawquic.OpenAdmissionStream(ctx, session)
		if err != nil {
			_ = session.Close()
			return nil, err
		}
		return &streamAdmissionHandle{
			session: session,
			stream:  stream,
		}, nil
	}, nil
}

func validQUICClientTLS(config *tls.Config) bool {
	return config != nil && !config.InsecureSkipVerify
}

func bindQUICTimeouts(limits *quicbase.Limits, contract artifactv3.SessionContract) {
	if limits == nil {
		return
	}
	if contract.EstablishTimeoutSeconds != 0 {
		limits.HandshakeIdleTimeout = time.Duration(contract.EstablishTimeoutSeconds) * time.Second
	}
	if contract.IdleTimeoutSeconds != 0 {
		idle := time.Duration(contract.IdleTimeoutSeconds) * time.Second
		limits.MaxIdleTimeout = idle
		if limits.KeepAlivePeriod >= idle {
			limits.KeepAlivePeriod = 0
		}
	}
}

// NewWebSocketCarrierDial builds a carrier-ready dial that performs only TLS
// and WebSocket upgrade. FSB3 remains behind ReadyCarrier.Commit,
// and Yamux is created only after FSA3 success.
func NewWebSocketCarrierDial(config WebSocketDialConfig) (Dial, error) {
	if config.Dialer == nil {
		return nil, ErrInvalidCarrierDialConfig
	}
	resources, err := carrierws.BindSessionResourcePolicy(config.Resources, carrier.MaxLogicalIncomingStreams)
	if err != nil {
		return nil, err
	}
	dialer := *config.Dialer
	if dialer.NetDial != nil && dialer.NetDialContext == nil {
		return nil, ErrInvalidCarrierDialConfig
	}
	// Gorilla bypasses TLSClientConfig when the callback performs TLS itself.
	// v3 must own the complete TLS policy, so custom TLS callbacks are forbidden.
	if dialer.NetDialTLSContext != nil {
		return nil, ErrInvalidCarrierDialConfig
	}
	if dialer.TLSClientConfig == nil {
		dialer.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS13}
	} else {
		if dialer.TLSClientConfig.InsecureSkipVerify ||
			(dialer.TLSClientConfig.MaxVersion != 0 && dialer.TLSClientConfig.MaxVersion < tls.VersionTLS13) {
			return nil, ErrInvalidCarrierDialConfig
		}
		dialer.TLSClientConfig = dialer.TLSClientConfig.Clone()
		if dialer.TLSClientConfig.MinVersion < tls.VersionTLS13 {
			dialer.TLSClientConfig.MinVersion = tls.VersionTLS13
		}
	}

	return func(ctx context.Context, candidate artifactv3.Candidate, contract artifactv3.SessionContract, attemptNow time.Time) (ReadyCarrier, error) {
		subprotocol, dialURL, err := validateWebSocketCandidate(candidate)
		if err != nil {
			return nil, err
		}
		attemptDialer := dialer
		attemptTLS, err := transportsecurity.BuildClientTLSSnapshot(dialer.TLSClientConfig, dialURL, candidate.TLS)
		if err != nil {
			return nil, err
		}
		attemptDialer.TLSClientConfig = attemptTLS
		attemptDialer.Subprotocols = []string{subprotocol}
		if ctx == nil {
			ctx = context.Background()
		}
		baseDialContext := attemptDialer.NetDialContext
		if baseDialContext == nil {
			baseDialContext = (&net.Dialer{}).DialContext
		}
		var stopDialCancellation func() bool
		attemptDialer.NetDialContext = func(dialCtx context.Context, network, address string) (net.Conn, error) {
			conn, dialErr := baseDialContext(dialCtx, network, address)
			if dialErr != nil {
				return nil, dialErr
			}
			stopDialCancellation = context.AfterFunc(ctx, func() { _ = conn.Close() })
			return conn, nil
		}
		headers := http.Header{}
		if config.Origin != "" {
			headers.Set("Origin", config.Origin)
		}
		var tlsHandshakeMu sync.Mutex
		var tlsHandshakeErr error
		ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
			TLSHandshakeDone: func(_ tls.ConnectionState, err error) {
				if err != nil {
					tlsHandshakeMu.Lock()
					tlsHandshakeErr = transportsecurity.ClassifyLocatedTLSFailure(candidate.TLS, err)
					tlsHandshakeMu.Unlock()
				}
			},
		})
		conn, _, err := attemptDialer.DialContext(ctx, dialURL, headers)
		if stopDialCancellation != nil {
			stopDialCancellation()
		}
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, ctxErr
			}
			tlsHandshakeMu.Lock()
			locatedTLSError := tlsHandshakeErr
			tlsHandshakeMu.Unlock()
			if locatedTLSError != nil {
				return nil, locatedTLSError
			}
			return nil, err
		}
		if err := carrierws.ValidateReady(conn, subprotocol); err != nil {
			_ = conn.Close()
			return nil, err
		}
		attemptResources, err := carrierws.BindSessionResourcePolicy(resources, contract.MaxInboundStreams)
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		handle := &webSocketAdmissionHandle{
			conn: conn, subprotocol: subprotocol, resources: attemptResources, role: carrierws.ClientRole,
		}
		return handle, nil
	}, nil
}

func isQUICTLSFailure(err error) bool {
	var transportError *quic.TransportError
	return errors.As(err, &transportError) && transportError.ErrorCode >= 0x100 && transportError.ErrorCode < 0x200
}

func kindFromCandidate(candidate artifactv3.Candidate) (artifactv3.PathKind, bool) {
	switch candidate.WireProfile {
	case "flowersec-direct/3":
		return artifactv3.PathDirect, true
	case "flowersec-tunnel/3":
		return artifactv3.PathTunnel, true
	default:
		return "", false
	}
}

type ownedCarrierSession struct {
	carrier.Session
	owner interface {
		CloseLocal() error
		Close() error
	}
	localOnce sync.Once
	localErr  error
	closeOnce sync.Once
	closeErr  error
}

func (session *ownedCarrierSession) Path() carrier.Path { return session.Session.Path() }

// Optional carrier capabilities are not promoted through an embedded
// interface. Preserve negotiated unreliable-message support when a dialer
// owns the native session lifecycle.
func (session *ownedCarrierSession) UnreliableAvailable() bool {
	transport, ok := session.Session.(carrier.UnreliableTransport)
	return ok && transport.UnreliableAvailable()
}

func (session *ownedCarrierSession) SendUnreliable(payload []byte) error {
	transport, ok := session.Session.(carrier.UnreliableTransport)
	if !ok {
		return carrier.ErrUnreliableUnavailable
	}
	return transport.SendUnreliable(payload)
}

func (session *ownedCarrierSession) ReceiveUnreliable(ctx context.Context) ([]byte, error) {
	transport, ok := session.Session.(carrier.UnreliableTransport)
	if !ok {
		return nil, carrier.ErrUnreliableUnavailable
	}
	return transport.ReceiveUnreliable(ctx)
}

func (session *ownedCarrierSession) CloseWithError(applicationError carrier.ApplicationError) error {
	return session.CloseWithErrorContext(context.Background(), applicationError)
}

func (session *ownedCarrierSession) Abort(applicationError carrier.ApplicationError) error {
	session.closeOnce.Do(func() {
		session.closeErr = errors.Join(session.Session.Abort(applicationError), session.owner.CloseLocal(), session.owner.Close())
	})
	return session.closeErr
}

func (session *ownedCarrierSession) CloseWithErrorContext(ctx context.Context, applicationError carrier.ApplicationError) error {
	if ctx == nil {
		ctx = context.Background()
	}
	session.closeOnce.Do(func() {
		session.closeErr = errors.Join(session.closeLocalWithErrorContext(ctx, applicationError), session.owner.Close())
	})
	return errors.Join(session.closeErr, context.Cause(ctx))
}

func (session *ownedCarrierSession) Close() error {
	return session.CloseWithError(carrier.ApplicationError{})
}

func (session *ownedCarrierSession) closeLocalWithErrorContext(ctx context.Context, applicationError carrier.ApplicationError) error {
	session.localOnce.Do(func() {
		session.localErr = errors.Join(session.Session.CloseWithErrorContext(ctx, applicationError), session.owner.CloseLocal())
	})
	return errors.Join(session.localErr, context.Cause(ctx))
}

type webSocketAdmissionHandle struct {
	conn        *gorillaws.Conn
	subprotocol string
	resources   carrierws.ResourcePolicy
	role        carrierws.Role
	mu          sync.Mutex
	session     *carrierws.Session

	closeOnce sync.Once
	closeErr  error
}

func (handle *webSocketAdmissionHandle) Admission() admissionv3.ClientExchange {
	if handle == nil || handle.conn == nil {
		return nil
	}
	return &webSocketAdmissionExchange{
		handle:   handle,
		exchange: websocketadmission.NewClientExchange(handle.conn),
	}
}

type webSocketAdmissionExchange struct {
	handle   *webSocketAdmissionHandle
	exchange admissionv3.ClientExchange
}

func (exchange *webSocketAdmissionExchange) Commit(ctx context.Context, rawFSB3 []byte) error {
	if exchange == nil || exchange.handle == nil || exchange.exchange == nil {
		return net.ErrClosed
	}
	decoded, err := artifactv3.ParseRequest(rawFSB3)
	if err != nil {
		return err
	}
	if err := exchange.exchange.Commit(ctx, rawFSB3); err != nil {
		return err
	}
	role := carrierws.ClientRole
	if decoded.Request.PathKind == artifactv3.PathTunnel && decoded.Request.Role == 2 {
		role = carrierws.ServerRole
	}
	exchange.handle.mu.Lock()
	exchange.handle.role = role
	exchange.handle.mu.Unlock()
	return nil
}

func (handle *webSocketAdmissionHandle) Establish() (carrier.Session, error) {
	if handle == nil || handle.conn == nil {
		return nil, ErrInvalidCarrierCandidate
	}
	handle.mu.Lock()
	role := handle.role
	handle.mu.Unlock()
	if role == 0 {
		role = carrierws.ClientRole
	}
	session, err := carrierws.NewAfterAdmission(handle.conn, role, handle.subprotocol, handle.resources)
	if err != nil {
		_ = handle.conn.Close()
		return nil, err
	}
	handle.mu.Lock()
	handle.session = session
	handle.mu.Unlock()
	return session, nil
}

func (handle *webSocketAdmissionHandle) Close(context.Context) error {
	if handle == nil {
		return nil
	}
	handle.closeOnce.Do(func() {
		handle.mu.Lock()
		session := handle.session
		handle.mu.Unlock()
		if session != nil {
			handle.closeErr = session.Close()
			return
		}
		if handle.conn != nil {
			handle.closeErr = normalizeWebSocketAdmissionClose(handle.conn.Close())
		}
	})
	return handle.closeErr
}

func normalizeWebSocketAdmissionClose(err error) error {
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func validateWebSocketCandidate(candidate artifactv3.Candidate) (subprotocol, dialURL string, err error) {
	kind, canonical, err := canonicalDialCandidate(candidate, artifactv3.CarrierWebSocket)
	if err != nil {
		return "", "", err
	}
	if kind == artifactv3.PathDirect {
		return carrierws.SubprotocolDirect, canonical.NormalizedURL, nil
	}
	return carrierws.SubprotocolTunnel, canonical.NormalizedURL, nil
}

type streamAdmissionHandle struct {
	session carrier.Session
	stream  carrier.Stream

	closeOnce sync.Once
	closeErr  error
}

func (handle *streamAdmissionHandle) Admission() admissionv3.ClientExchange {
	if handle == nil || handle.session == nil || handle.stream == nil {
		return nil
	}
	path := artifactv3.PathDirect
	if handle.session.Path() == carrier.PathTunnel {
		path = artifactv3.PathTunnel
	}
	return admissionv3.NewStreamClientExchange(handle.stream, path)
}

func (handle *streamAdmissionHandle) Establish() (carrier.Session, error) {
	if handle == nil || handle.session == nil {
		return nil, ErrInvalidCarrierCandidate
	}
	return handle.session, nil
}

func (handle *streamAdmissionHandle) Close(ctx context.Context) error {
	if handle == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	handle.closeOnce.Do(func() {
		var streamErr, sessionErr error
		if handle.stream != nil {
			streamErr = handle.stream.Reset()
		}
		if handle.session != nil {
			sessionErr = handle.session.CloseWithErrorContext(ctx, carrier.ApplicationError{})
		}
		handle.closeErr = errors.Join(streamErr, sessionErr)
	})
	return handle.closeErr
}

func validateRawQUICCandidate(candidate artifactv3.Candidate) (address, alpn string, err error) {
	kind, canonical, err := canonicalDialCandidate(candidate, artifactv3.CarrierRawQUIC)
	if err != nil {
		return "", "", err
	}
	parsed, parseErr := url.Parse(canonical.NormalizedURL)
	if parseErr != nil {
		return "", "", errors.Join(ErrInvalidCarrierCandidate, parseErr)
	}
	port := parsed.Port()
	if port == "" {
		port = "443"
	}
	switch kind {
	case artifactv3.PathDirect:
		alpn = rawquic.ALPNDirect
	case artifactv3.PathTunnel:
		alpn = rawquic.ALPNTunnel
	}
	return net.JoinHostPort(parsed.Hostname(), port), alpn, nil
}

func validateWebTransportCandidate(candidate artifactv3.Candidate) (string, error) {
	_, canonical, err := canonicalDialCandidate(candidate, artifactv3.CarrierWebTransport)
	if err != nil {
		return "", err
	}
	if err := carrierwt.ValidateURL(canonical.NormalizedURL); err != nil {
		return "", errors.Join(ErrInvalidCarrierCandidate, err)
	}
	return canonical.NormalizedURL, nil
}

func canonicalDialCandidate(candidate artifactv3.Candidate, wantCarrier artifactv3.Carrier) (artifactv3.PathKind, artifactv3.CanonicalCandidate, error) {
	if candidate.Carrier != wantCarrier {
		return "", artifactv3.CanonicalCandidate{}, ErrInvalidCarrierCandidate
	}
	var kind artifactv3.PathKind
	switch candidate.WireProfile {
	case rawquic.ALPNDirect:
		kind = artifactv3.PathDirect
	case rawquic.ALPNTunnel:
		kind = artifactv3.PathTunnel
	default:
		return "", artifactv3.CanonicalCandidate{}, ErrInvalidCarrierCandidate
	}
	canonical, _, _, canonicalErr := artifactv3.CanonicalizeCandidates(kind, []artifactv3.Candidate{candidate})
	if canonicalErr != nil || len(canonical) != 1 {
		return "", artifactv3.CanonicalCandidate{}, errors.Join(ErrInvalidCarrierCandidate, canonicalErr)
	}
	return kind, canonical[0], nil
}

var _ ReadyCarrier = (*webSocketAdmissionHandle)(nil)
var _ ReadyCarrier = (*streamAdmissionHandle)(nil)
var _ carrier.Session = (*ownedCarrierSession)(nil)
