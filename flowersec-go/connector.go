package flowersec

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/url"
	"regexp"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/artifactv2"
	"github.com/floegence/flowersec/flowersec-go/v2/carrier/rawquic"
	carrierws "github.com/floegence/flowersec/flowersec-go/v2/carrier/websocket"
	carrierwt "github.com/floegence/flowersec/flowersec-go/v2/carrier/webtransport"
	"github.com/floegence/flowersec/flowersec-go/v2/connectv2"
	"github.com/floegence/flowersec/flowersec-go/v2/fserrors"
	"github.com/floegence/flowersec/flowersec-go/v2/session"
	gorillaws "github.com/gorilla/websocket"
)

var (
	ErrInvalidConnectorOptions = errors.New("invalid Flowersec connector options")
	ErrConnectionFailed        = errors.New("Flowersec connection failed")
	admissionReasonPattern     = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
)

// AdmissionReason is an application-audited admission rejection reason.
type AdmissionReason string

// AdmissionReasonRegistry is the closed set of rejection reasons accepted
// from the peer during admission.
type AdmissionReasonRegistry map[AdmissionReason]struct{}

// ConnectorOptions configures carrier-neutral client trust and lifecycle
// policy. Carrier selection and carrier-specific tuning remain internal.
type ConnectorOptions struct {
	TrustRoots       *x509.CertPool
	Origin           string
	AdmissionReasons AdmissionReasonRegistry
	ConnectTimeout   time.Duration
}

// Connector establishes a Flowersec v2 session without exposing the selected
// carrier, candidate, or carrier-specific configuration.
type Connector struct {
	inner   connectorBackend
	timeout time.Duration
}

// Session is the carrier-neutral Flowersec v2 session contract.
type Session interface {
	Path() Path
	EndpointInstanceID() (string, bool)
	RPC() RPCPeer
	OpenStream(context.Context, string, Metadata) (ByteStream, error)
	AcceptStream(context.Context) (IncomingStream, error)
	Rekey(context.Context) error
	ProbeLiveness(context.Context) (time.Duration, error)
	Termination() <-chan struct{}
	WaitClosed(context.Context) error
	Close() error
}

type (
	Path           = session.PathKind
	Metadata       = session.Metadata
	ByteStream     = session.ByteStream
	IncomingStream = session.IncomingStream
	RPCPeer        = session.RPCPeer
)

const (
	PathDirect = session.PathDirect
	PathTunnel = session.PathTunnel
)

// ConnectError is the redacted, stable public failure projection. It never
// retains the internal cause or per-candidate diagnostics.
type ConnectError struct {
	Path  string
	Stage string
	Code  string
}

func (err *ConnectError) Error() string {
	if err == nil {
		return "<nil>"
	}
	return "Flowersec connection failed (path=" + err.Path + " stage=" + err.Stage + " code=" + err.Code + ")"
}

func (*ConnectError) Unwrap() error { return ErrConnectionFailed }

type connectorBackend interface {
	Connect(context.Context) (connectv2.Result, error)
}

// NewConnector creates a production connector with equal WSS, raw QUIC, and
// WebTransport support.
func NewConnector(lease ArtifactLease, options ConnectorOptions) (*Connector, error) {
	if lease.artifact.value == nil || lease.commitSpend == nil || options.TrustRoots == nil ||
		len(options.TrustRoots.Subjects()) == 0 || options.ConnectTimeout < 0 || !validOrigin(options.Origin) {
		return nil, ErrInvalidConnectorOptions
	}
	reasons := make(artifactv2.ReasonRegistry, len(options.AdmissionReasons))
	for reason := range options.AdmissionReasons {
		if !admissionReasonPattern.MatchString(string(reason)) {
			return nil, ErrInvalidConnectorOptions
		}
		reasons[string(reason)] = struct{}{}
	}

	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: options.TrustRoots.Clone()}
	webSocketClient := *gorillaws.DefaultDialer
	webSocketClient.TLSClientConfig = tlsConfig.Clone()
	webSocketDial, err := connectv2.NewWebSocketCarrierDial(connectv2.WebSocketDialConfig{
		Dialer:    &webSocketClient,
		Resources: carrierws.DefaultResourcePolicy(),
	})
	if err != nil {
		return nil, ErrInvalidConnectorOptions
	}
	rawQUICDial, err := connectv2.NewRawQUICCarrierDial(connectv2.RawQUICDialConfig{
		TLSConfig: tlsConfig.Clone(), Limits: rawquic.DefaultLimits(),
	})
	if err != nil {
		return nil, ErrInvalidConnectorOptions
	}
	webTransportDial, err := connectv2.NewWebTransportCarrierDial(connectv2.WebTransportDialConfig{
		TLSConfig: tlsConfig.Clone(), Limits: carrierwt.DefaultLimits(), Origin: options.Origin,
	})
	if err != nil {
		return nil, ErrInvalidConnectorOptions
	}
	factory, err := connectv2.NewAdmissionFactory(map[artifactv2.Carrier]connectv2.CarrierDial{
		artifactv2.CarrierWebSocket:    webSocketDial,
		artifactv2.CarrierRawQUIC:      rawQUICDial,
		artifactv2.CarrierWebTransport: webTransportDial,
	}, reasons)
	if err != nil {
		return nil, ErrInvalidConnectorOptions
	}
	inner := connectv2.NewConnector(connectv2.ArtifactLease{
		Artifact: *lease.artifact.value, CommitSpend: lease.commitSpend,
	}, session.GoCapabilities(), connectv2.Adaptive, factory)
	return &Connector{inner: inner, timeout: options.ConnectTimeout}, nil
}

func validOrigin(value string) bool {
	origin, err := url.Parse(value)
	return err == nil && origin.Scheme == "https" && origin.Host != "" && origin.User == nil &&
		(origin.Path == "" || origin.Path == "/") && origin.RawQuery == "" && origin.Fragment == ""
}

// Connect establishes and returns only the carrier-neutral session contract.
func (connector *Connector) Connect(ctx context.Context) (Session, error) {
	if connector == nil || connector.inner == nil {
		return nil, ErrInvalidConnectorOptions
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if connector.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, connector.timeout)
		defer cancel()
	}
	result, err := connector.inner.Connect(ctx)
	if err != nil {
		return nil, redactConnectError(err)
	}
	if result.Session == nil {
		return nil, redactConnectError(ErrConnectionFailed)
	}
	return result.Session, nil
}

func redactConnectError(err error) error {
	var internal *fserrors.Error
	if errors.As(err, &internal) {
		return &ConnectError{Path: string(internal.Path), Stage: string(internal.Stage), Code: string(internal.Code)}
	}
	code := string(fserrors.CodeDialFailed)
	if errors.Is(err, context.DeadlineExceeded) {
		code = string(fserrors.CodeTimeout)
	} else if errors.Is(err, context.Canceled) {
		code = string(fserrors.CodeCanceled)
	}
	return &ConnectError{Path: string(fserrors.PathAuto), Stage: string(fserrors.StageConnect), Code: code}
}
