// Package candidatev2 composes concrete runtime adapters into credential-free
// candidate attempts and one-shot admission commits.
package candidatev2

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/admissionv2"
	websocketadmission "github.com/floegence/flowersec/flowersec-go/v2/internal/admissionv2/websocket"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/artifactv2"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier/quicbase"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier/rawquic"
	carrierws "github.com/floegence/flowersec/flowersec-go/v2/internal/carrier/websocket"
	carrierwt "github.com/floegence/flowersec/flowersec-go/v2/internal/carrier/webtransport"
	gorillaws "github.com/gorilla/websocket"
)

var (
	ErrInvalidCarrierCandidate  = errors.New("invalid Flowersec v2 carrier candidate")
	ErrInvalidCarrierDialConfig = errors.New("invalid Flowersec v2 carrier dial configuration")
)

type WebSocketDialConfig struct {
	Dialer    *gorillaws.Dialer
	Resources carrierws.ResourcePolicy
	Origin    string
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
	TrustRoots *x509.CertPool
	Origin     string
}

// NewGoNativeFactory composes the production adapters available in one Go
// runtime. WebTransport is present only when its required origin is present.
func NewGoNativeFactory(config GoNativeConfig) (*Factory, error) {
	if config.TrustRoots == nil || len(config.TrustRoots.Subjects()) == 0 {
		return nil, ErrInvalidCarrierDialConfig
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: config.TrustRoots.Clone()}
	webSocketClient := *gorillaws.DefaultDialer
	webSocketClient.TLSClientConfig = tlsConfig.Clone()
	webSocketDial, err := NewWebSocketCarrierDial(WebSocketDialConfig{
		Dialer:    &webSocketClient,
		Resources: carrierws.DefaultResourcePolicy(),
		Origin:    config.Origin,
	})
	if err != nil {
		return nil, err
	}
	rawQUICDial, err := NewRawQUICCarrierDial(RawQUICDialConfig{
		TLSConfig: tlsConfig.Clone(),
		Limits:    quicbase.DefaultLimits(),
		Dial:      rawquic.Dial,
	})
	if err != nil {
		return nil, err
	}
	dialers := map[artifactv2.Carrier]Dial{
		artifactv2.CarrierWebSocket: webSocketDial,
		artifactv2.CarrierRawQUIC:   rawQUICDial,
	}
	if config.Origin != "" {
		webTransportDial, err := NewWebTransportCarrierDial(WebTransportDialConfig{
			TLSConfig: tlsConfig.Clone(),
			Limits:    quicbase.DefaultLimits(),
			Origin:    config.Origin,
		})
		if err != nil {
			return nil, err
		}
		dialers[artifactv2.CarrierWebTransport] = webTransportDial
	}
	return NewFactory(dialers)
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
	return func(ctx context.Context, candidate artifactv2.Candidate, contract artifactv2.SessionContract) (ReadyCarrier, error) {
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
		dialer, err := carrierwt.NewDialer(baseTLS, limits)
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
// native bidirectional admission stream without sending FSB2.
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
	return func(ctx context.Context, candidate artifactv2.Candidate, contract artifactv2.SessionContract) (ReadyCarrier, error) {
		address, alpn, err := validateRawQUICCandidate(candidate)
		if err != nil {
			return nil, err
		}
		tlsConfig := baseTLS.Clone()
		tlsConfig.NextProtos = []string{alpn}
		limits, err := quicbase.BindSessionLimits(config.Limits, contract.MaxInboundStreams)
		if err != nil {
			return nil, err
		}
		bindQUICTimeouts(&limits, contract)
		session, err := config.Dial(ctx, address, tlsConfig, limits)
		if err != nil {
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
	return config != nil && !config.InsecureSkipVerify && config.RootCAs != nil && len(config.RootCAs.Subjects()) != 0
}

func bindQUICTimeouts(limits *quicbase.Limits, contract artifactv2.SessionContract) {
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
// and WebSocket upgrade. FSB2 remains behind ReadyCarrier.Commit,
// and Yamux is created only after FSA2 success.
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

	return func(ctx context.Context, candidate artifactv2.Candidate, contract artifactv2.SessionContract) (ReadyCarrier, error) {
		subprotocol, dialURL, err := validateWebSocketCandidate(candidate)
		if err != nil {
			return nil, err
		}
		attemptDialer := dialer
		if strings.HasPrefix(dialURL, "ws://") {
			kind, ok := kindFromCandidate(candidate)
			if !ok || !loopbackWebSocketURL(dialURL) || kind != artifactv2.PathDirect {
				return nil, ErrInvalidCarrierCandidate
			}
			attemptDialer.TLSClientConfig = nil
		}
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
		conn, _, err := attemptDialer.DialContext(ctx, dialURL, headers)
		if stopDialCancellation != nil {
			stopDialCancellation()
		}
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, ctxErr
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
			conn: conn, subprotocol: subprotocol, resources: attemptResources,
		}
		return handle, nil
	}, nil
}

func kindFromCandidate(candidate artifactv2.Candidate) (artifactv2.PathKind, bool) {
	switch candidate.WireProfile {
	case "flowersec-direct/2":
		return artifactv2.PathDirect, true
	case "flowersec-tunnel/2":
		return artifactv2.PathTunnel, true
	default:
		return "", false
	}
}

func loopbackWebSocketURL(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "ws" || parsed.Path != "/flowersec/v2/direct" || parsed.User != nil {
		return false
	}
	host := parsed.Hostname()
	address, err := netip.ParseAddr(host)
	return err == nil && address.IsLoopback()
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
	mu          sync.Mutex
	session     *carrierws.Session

	closeOnce sync.Once
	closeErr  error
}

func (handle *webSocketAdmissionHandle) Admission() admissionv2.ClientExchange {
	if handle == nil || handle.conn == nil {
		return nil
	}
	return websocketadmission.NewClientExchange(handle.conn)
}

func (handle *webSocketAdmissionHandle) Establish() (carrier.Session, error) {
	if handle == nil || handle.conn == nil {
		return nil, ErrInvalidCarrierCandidate
	}
	session, err := carrierws.NewAfterAdmission(handle.conn, carrierws.ClientRole, handle.subprotocol, handle.resources)
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

func validateWebSocketCandidate(candidate artifactv2.Candidate) (subprotocol, dialURL string, err error) {
	kind, canonical, err := canonicalDialCandidate(candidate, artifactv2.CarrierWebSocket)
	if err != nil {
		return "", "", err
	}
	if kind == artifactv2.PathDirect {
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

func (handle *streamAdmissionHandle) Admission() admissionv2.ClientExchange {
	if handle == nil || handle.session == nil || handle.stream == nil {
		return nil
	}
	path := artifactv2.PathDirect
	if handle.session.Path() == carrier.PathTunnel {
		path = artifactv2.PathTunnel
	}
	return admissionv2.NewStreamClientExchange(handle.stream, path)
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

func validateRawQUICCandidate(candidate artifactv2.Candidate) (address, alpn string, err error) {
	kind, canonical, err := canonicalDialCandidate(candidate, artifactv2.CarrierRawQUIC)
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
	case artifactv2.PathDirect:
		alpn = rawquic.ALPNDirect
	case artifactv2.PathTunnel:
		alpn = rawquic.ALPNTunnel
	}
	return net.JoinHostPort(parsed.Hostname(), port), alpn, nil
}

func validateWebTransportCandidate(candidate artifactv2.Candidate) (string, error) {
	_, canonical, err := canonicalDialCandidate(candidate, artifactv2.CarrierWebTransport)
	if err != nil {
		return "", err
	}
	if err := carrierwt.ValidateURL(canonical.NormalizedURL); err != nil {
		return "", errors.Join(ErrInvalidCarrierCandidate, err)
	}
	return canonical.NormalizedURL, nil
}

func canonicalDialCandidate(candidate artifactv2.Candidate, wantCarrier artifactv2.Carrier) (artifactv2.PathKind, artifactv2.CanonicalCandidate, error) {
	if candidate.Carrier != wantCarrier {
		return "", artifactv2.CanonicalCandidate{}, ErrInvalidCarrierCandidate
	}
	var kind artifactv2.PathKind
	switch candidate.WireProfile {
	case rawquic.ALPNDirect:
		kind = artifactv2.PathDirect
	case rawquic.ALPNTunnel:
		kind = artifactv2.PathTunnel
	default:
		return "", artifactv2.CanonicalCandidate{}, ErrInvalidCarrierCandidate
	}
	canonical, _, _, canonicalErr := artifactv2.CanonicalizeCandidates(kind, []artifactv2.Candidate{candidate})
	if canonicalErr != nil || len(canonical) != 1 {
		return "", artifactv2.CanonicalCandidate{}, errors.Join(ErrInvalidCarrierCandidate, canonicalErr)
	}
	return kind, canonical[0], nil
}

var _ ReadyCarrier = (*webSocketAdmissionHandle)(nil)
var _ ReadyCarrier = (*streamAdmissionHandle)(nil)
var _ carrier.Session = (*ownedCarrierSession)(nil)
