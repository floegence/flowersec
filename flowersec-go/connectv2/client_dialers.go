package connectv2

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/admissionv2"
	"github.com/floegence/flowersec/flowersec-go/v2/artifactv2"
	"github.com/floegence/flowersec/flowersec-go/v2/carrier"
	"github.com/floegence/flowersec/flowersec-go/v2/carrier/rawquic"
	carrierws "github.com/floegence/flowersec/flowersec-go/v2/carrier/websocket"
	carrierwt "github.com/floegence/flowersec/flowersec-go/v2/carrier/webtransport"
	gorillaws "github.com/gorilla/websocket"
)

var (
	ErrInvalidCarrierCandidate  = errors.New("invalid Flowersec v2 carrier candidate")
	ErrInvalidCarrierDialConfig = errors.New("invalid Flowersec v2 carrier dial configuration")
)

type WebSocketDialConfig struct {
	Dialer    *gorillaws.Dialer
	Resources carrierws.ResourcePolicy
	Liveness  carrierws.LivenessPolicy
}

type RawQUICDialConfig struct {
	TLSConfig *tls.Config
	Limits    rawquic.Limits
}

type WebTransportDialConfig struct {
	TLSConfig *tls.Config
	Limits    carrierwt.Limits
	Origin    string
}

// NewWebTransportCarrierDial completes HTTP/3 CONNECT and opens one native
// bidirectional admission stream without sending Flowersec credentials.
func NewWebTransportCarrierDial(config WebTransportDialConfig) (CarrierDial, error) {
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
	return func(ctx context.Context, candidate artifactv2.Candidate, contract artifactv2.SessionContract) (AdmissionHandle, error) {
		dialURL, err := validateWebTransportCandidate(candidate)
		if err != nil {
			return nil, err
		}
		limits, err := carrierwt.BindSessionLimits(config.Limits, contract.MaxInboundStreams)
		if err != nil {
			return nil, err
		}
		bindQUICIdleTimeout(&limits, contract)
		dialer, err := carrierwt.NewDialer(baseTLS, limits)
		if err != nil {
			return nil, err
		}
		session, err := dialer.Dial(ctx, dialURL, config.Origin)
		if err != nil {
			_ = dialer.Close()
			return nil, err
		}
		owned := &ownedCarrierSession{Session: session, owner: dialer}
		stream, err := owned.OpenStream(ctx)
		if err != nil {
			_ = owned.Close()
			return nil, err
		}
		return &streamAdmissionHandle{session: owned, stream: stream}, nil
	}, nil
}

// NewRawQUICCarrierDial reaches 1-RTT with one exact path ALPN and opens the
// native bidirectional admission stream without sending FSB2.
func NewRawQUICCarrierDial(config RawQUICDialConfig) (CarrierDial, error) {
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
	return func(ctx context.Context, candidate artifactv2.Candidate, contract artifactv2.SessionContract) (AdmissionHandle, error) {
		address, alpn, err := validateRawQUICCandidate(candidate)
		if err != nil {
			return nil, err
		}
		tlsConfig := baseTLS.Clone()
		tlsConfig.NextProtos = []string{alpn}
		limits, err := rawquic.BindSessionLimits(config.Limits, contract.MaxInboundStreams)
		if err != nil {
			return nil, err
		}
		bindQUICIdleTimeout(&limits, contract)
		session, err := rawquic.Dial(ctx, address, tlsConfig, limits)
		if err != nil {
			return nil, err
		}
		stream, err := session.OpenStream(ctx)
		if err != nil {
			_ = session.Close()
			return nil, err
		}
		return &streamAdmissionHandle{session: session, stream: stream}, nil
	}, nil
}

func validQUICClientTLS(config *tls.Config) bool {
	return config != nil && !config.InsecureSkipVerify && config.RootCAs != nil && len(config.RootCAs.Subjects()) != 0
}

func bindQUICIdleTimeout(limits *rawquic.Limits, contract artifactv2.SessionContract) {
	if limits == nil || contract.IdleTimeoutSeconds == 0 {
		return
	}
	idle := time.Duration(contract.IdleTimeoutSeconds) * time.Second
	limits.MaxIdleTimeout = idle
	if limits.KeepAlivePeriod >= idle {
		limits.KeepAlivePeriod = 0
	}
}

// NewWebSocketCarrierDial builds a carrier-ready dial that performs only TLS
// and WebSocket upgrade. FSB2 remains behind AdmissionHandle.CommitAdmission,
// and Yamux is created only after FSA2 success.
func NewWebSocketCarrierDial(config WebSocketDialConfig) (CarrierDial, error) {
	resources, err := carrierws.BindSessionResourcePolicy(config.Resources, carrier.MaxLogicalIncomingStreams)
	if err != nil {
		return nil, err
	}
	dialer := *gorillaws.DefaultDialer
	if config.Dialer != nil {
		dialer = *config.Dialer
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

	return func(ctx context.Context, candidate artifactv2.Candidate, contract artifactv2.SessionContract) (AdmissionHandle, error) {
		subprotocol, dialURL, err := validateWebSocketCandidate(candidate)
		if err != nil {
			return nil, err
		}
		attemptDialer := dialer
		attemptDialer.Subprotocols = []string{subprotocol}
		conn, _, err := attemptDialer.DialContext(ctx, dialURL, nil)
		if err != nil {
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
		return &webSocketAdmissionHandle{
			conn: conn, subprotocol: subprotocol, resources: attemptResources, liveness: config.Liveness,
		}, nil
	}, nil
}

type ownedCarrierSession struct {
	carrier.Session
	owner interface{ Close() error }
	once  sync.Once
	err   error
}

func (session *ownedCarrierSession) Path() carrier.Path { return session.Session.Path() }

func (session *ownedCarrierSession) CloseWithError(applicationError carrier.ApplicationError) error {
	return session.CloseWithErrorContext(context.Background(), applicationError)
}

func (session *ownedCarrierSession) CloseWithErrorContext(ctx context.Context, applicationError carrier.ApplicationError) error {
	if ctx == nil {
		ctx = context.Background()
	}
	session.once.Do(func() {
		session.err = errors.Join(session.Session.CloseWithErrorContext(ctx, applicationError), session.owner.Close())
	})
	return errors.Join(session.err, context.Cause(ctx))
}

func (session *ownedCarrierSession) Close() error {
	return session.CloseWithError(carrier.ApplicationError{})
}

type webSocketAdmissionHandle struct {
	conn        *gorillaws.Conn
	subprotocol string
	resources   carrierws.ResourcePolicy
	liveness    carrierws.LivenessPolicy
	used        atomic.Bool

	mu      sync.Mutex
	session *carrierws.Session

	closeOnce sync.Once
	closeErr  error
}

func (handle *webSocketAdmissionHandle) CommitAdmission(ctx context.Context, fsb2 []byte, reasons artifactv2.ReasonRegistry) (carrier.Session, error) {
	if handle == nil || handle.conn == nil || !handle.used.CompareAndSwap(false, true) {
		return nil, ErrCommitAlreadyUsed
	}
	if _, err := carrierws.CommitAdmission(ctx, handle.conn, fsb2, reasons); err != nil {
		return nil, err
	}
	session, err := carrierws.NewAfterAdmission(handle.conn, carrierws.ClientRole, handle.subprotocol, handle.resources, handle.liveness)
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
			handle.closeErr = handle.conn.Close()
		}
	})
	return handle.closeErr
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
	used    atomic.Bool

	closeOnce sync.Once
	closeErr  error
}

func (handle *streamAdmissionHandle) CommitAdmission(ctx context.Context, fsb2 []byte, reasons artifactv2.ReasonRegistry) (carrier.Session, error) {
	if handle == nil || handle.session == nil || handle.stream == nil || !handle.used.CompareAndSwap(false, true) {
		return nil, ErrCommitAlreadyUsed
	}
	decoded, err := artifactv2.ParseRequest(fsb2)
	if err != nil || !carrierPathMatchesArtifact(handle.session.Path(), decoded.Request.PathKind) {
		_ = handle.Close(ctx)
		return nil, errors.Join(ErrInvalidCarrierCandidate, err)
	}
	if _, err := admissionv2.Commit(ctx, handle.stream, fsb2, reasons); err != nil {
		_ = handle.Close(ctx)
		return nil, err
	}
	return handle.session, nil
}

func carrierPathMatchesArtifact(path carrier.Path, kind artifactv2.PathKind) bool {
	return path == carrier.PathDirect && kind == artifactv2.PathDirect ||
		path == carrier.PathTunnel && kind == artifactv2.PathTunnel
}

func (handle *streamAdmissionHandle) Close(context.Context) error {
	if handle == nil {
		return nil
	}
	handle.closeOnce.Do(func() {
		var streamErr, sessionErr error
		if handle.stream != nil {
			streamErr = handle.stream.Reset()
		}
		if handle.session != nil {
			sessionErr = handle.session.Close()
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

var _ AdmissionHandle = (*webSocketAdmissionHandle)(nil)
var _ AdmissionHandle = (*streamAdmissionHandle)(nil)
var _ carrier.Session = (*ownedCarrierSession)(nil)
