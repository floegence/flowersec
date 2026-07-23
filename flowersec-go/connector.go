package flowersec

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/url"
	"strconv"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/artifactv2"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier/rawquic"
	carrierws "github.com/floegence/flowersec/flowersec-go/v2/internal/carrier/websocket"
	carrierwt "github.com/floegence/flowersec/flowersec-go/v2/internal/carrier/webtransport"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/connectv2"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/fserrors"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/protocolv2"
	internalrpc "github.com/floegence/flowersec/flowersec-go/v2/internal/rpc"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/session"
	gorillaws "github.com/gorilla/websocket"
)

var (
	ErrInvalidConnectorOptions = errors.New("invalid Flowersec connector options")
	ErrConnectionFailed        = errors.New("Flowersec connection failed")
)

// ConnectErrorCode is the closed, carrier-neutral connection outcome set.
type ConnectErrorCode string

const (
	ConnectInvalid  ConnectErrorCode = "invalid"
	ConnectCanceled ConnectErrorCode = "canceled"
	ConnectTimeout  ConnectErrorCode = "timeout"
	ConnectFailed   ConnectErrorCode = "failed"
)

// ConnectorOptions configures carrier-neutral client trust and lifecycle
// policy. Carrier selection and carrier-specific tuning remain internal.
type ConnectorOptions struct {
	TrustRoots     *x509.CertPool
	Origin         string
	ConnectTimeout time.Duration
}

// Connector establishes a Flowersec v2 session without exposing the selected
// carrier, candidate, or carrier-specific configuration.
type Connector struct {
	inner   connectorBackend
	timeout time.Duration
}

// String deliberately reveals no carrier or candidate state.
func (*Connector) String() string { return "Flowersec.Connector" }

// GoString deliberately reveals no carrier or candidate state.
func (*Connector) GoString() string { return "flowersec.Connector" }

// Session is the carrier-neutral Flowersec v2 session contract.
type Session interface {
	RPC() RPCPeer
	UnreliableMessages() (UnreliableMessageChannel, error)
	OpenStream(context.Context, string, Metadata) (ByteStream, error)
	AcceptStream(context.Context) (IncomingStream, error)
	Rekey(context.Context) error
	ProbeLiveness(context.Context) (time.Duration, error)
	Termination() <-chan struct{}
	WaitClosed(context.Context) error
	Close() error
}

type UnreliableSendStatus string

const (
	UnreliableAccepted       UnreliableSendStatus = "accepted"
	UnreliableDroppedExpired UnreliableSendStatus = "dropped_expired"
	UnreliableDroppedBudget  UnreliableSendStatus = "dropped_budget"
	UnreliableDroppedCarrier UnreliableSendStatus = "dropped_carrier"
)

type UnreliableSendOptions struct {
	ExpiresAt time.Time
}

// UnreliableMessageChannel sends opaque end-to-end encrypted messages without
// retransmission. An accepted send is queued locally and may still be lost.
type UnreliableMessageChannel interface {
	MaxMessageBytes() int
	Send(context.Context, []byte, UnreliableSendOptions) (UnreliableSendStatus, error)
	Receive(context.Context) ([]byte, error)
}

// Metadata is the bounded JSON object attached to an application stream.
type Metadata map[string]any

// ByteStream is a carrier-neutral encrypted application stream.
type ByteStream interface {
	io.Reader
	io.Writer
	io.Closer
	Kind() string
	TerminalError() *SessionError
	CloseWrite() error
	Reset() error
}

// IncomingStream is one accepted application stream and its bounded metadata.
type IncomingStream struct {
	Kind     string
	Metadata Metadata
	Stream   ByteStream
}

// RPCPeer provides bidirectional RPC over the session's reserved stream.
type RPCPeer interface {
	Call(context.Context, uint32, any, any) error
	Notify(context.Context, uint32, any) error
}

// ConnectError is the redacted, stable public connection failure.
type ConnectError struct {
	code ConnectErrorCode
}

func (err *ConnectError) Error() string {
	if err == nil {
		return "<nil>"
	}
	return "Flowersec connection failed (code=" + string(err.code) + ")"
}

func (*ConnectError) Unwrap() error { return ErrConnectionFailed }

// Is preserves cancellation and deadline matching without exposing the
// internal connection failure that produced this public projection.
func (err *ConnectError) Is(target error) bool {
	if target == ErrConnectionFailed {
		return true
	}
	if err == nil {
		return false
	}
	switch err.Code() {
	case ConnectCanceled:
		return target == context.Canceled
	case ConnectTimeout:
		return target == context.DeadlineExceeded
	default:
		return false
	}
}

// Code returns the closed, carrier-neutral connection outcome.
func (err *ConnectError) Code() ConnectErrorCode {
	if err == nil || err.code == "" {
		return ConnectFailed
	}
	return err.code
}

// SessionErrorCode is the closed failure set shared by sessions, RPC, and streams.
type SessionErrorCode string

const (
	SessionCanceled              SessionErrorCode = "canceled"
	SessionTimeout               SessionErrorCode = "timeout"
	SessionClosed                SessionErrorCode = "closed"
	SessionGoingAway             SessionErrorCode = "going_away"
	SessionResourceExhausted     SessionErrorCode = "resource_exhausted"
	SessionStreamRejected        SessionErrorCode = "stream_rejected"
	SessionStreamReset           SessionErrorCode = "stream_reset"
	SessionRekeyFailed           SessionErrorCode = "rekey_failed"
	SessionLivenessFailed        SessionErrorCode = "liveness_failed"
	SessionUnreliableUnavailable SessionErrorCode = "unreliable_unavailable"
	SessionUnreliableTooLarge    SessionErrorCode = "unreliable_too_large"
	SessionUnreliableDropped     SessionErrorCode = "unreliable_dropped"
	SessionOperationFailed       SessionErrorCode = "operation_failed"
)

// SessionError contains no carrier, wire, key, credential, or peer detail.
type SessionError struct {
	code SessionErrorCode
}

func (err *SessionError) Error() string {
	if err == nil {
		return "<nil>"
	}
	return "Flowersec session failed (code=" + string(err.code) + ")"
}

// Unwrap preserves stable cancellation and deadline matching. Other session
// failures deliberately retain no public cause.
func (err *SessionError) Unwrap() error {
	if err == nil {
		return nil
	}
	switch err.Code() {
	case SessionCanceled:
		return context.Canceled
	case SessionTimeout:
		return context.DeadlineExceeded
	default:
		return nil
	}
}

// Code returns the closed carrier-neutral session outcome.
func (err *SessionError) Code() SessionErrorCode {
	if err == nil || err.code == "" {
		return SessionOperationFailed
	}
	return err.code
}

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
	}, artifactv2.ReasonRegistry{})
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
	return &opaqueSession{inner: result.Session}, nil
}

type opaqueSession struct {
	inner session.SessionV2
}

func (*opaqueSession) String() string   { return "Flowersec.Session" }
func (*opaqueSession) GoString() string { return "flowersec.Session" }

func (current *opaqueSession) RPC() RPCPeer { return &opaqueRPCPeer{inner: current.inner.RPC()} }

func (current *opaqueSession) UnreliableMessages() (UnreliableMessageChannel, error) {
	channel, err := current.inner.UnreliableMessages()
	if err != nil {
		return nil, redactSessionError(err)
	}
	return &opaqueUnreliableMessageChannel{inner: channel}, nil
}

func (current *opaqueSession) OpenStream(ctx context.Context, kind string, metadata Metadata) (ByteStream, error) {
	stream, err := current.inner.OpenStream(ctx, kind, session.Metadata(metadata))
	if err != nil {
		return nil, redactSessionError(err)
	}
	return &opaqueByteStream{inner: stream}, nil
}

func (current *opaqueSession) AcceptStream(ctx context.Context) (IncomingStream, error) {
	incoming, err := current.inner.AcceptStream(ctx)
	if err != nil {
		return IncomingStream{}, redactSessionError(err)
	}
	return IncomingStream{
		Kind: incoming.Kind, Metadata: Metadata(incoming.Metadata), Stream: &opaqueByteStream{inner: incoming.Stream},
	}, nil
}

func (current *opaqueSession) Rekey(ctx context.Context) error {
	return redactNilSessionError(current.inner.Rekey(ctx))
}

func (current *opaqueSession) ProbeLiveness(ctx context.Context) (time.Duration, error) {
	duration, err := current.inner.ProbeLiveness(ctx)
	return duration, redactNilSessionError(err)
}

func (current *opaqueSession) Termination() <-chan struct{} { return current.inner.Termination() }

func (current *opaqueSession) WaitClosed(ctx context.Context) error {
	return redactNilSessionError(current.inner.WaitClosed(ctx))
}

func (current *opaqueSession) Close() error { return redactNilSessionError(current.inner.Close()) }

type opaqueRPCPeer struct {
	inner session.RPCPeer
}

type opaqueUnreliableMessageChannel struct {
	inner session.UnreliableMessageChannel
}

func (*opaqueUnreliableMessageChannel) String() string { return "Flowersec.UnreliableMessageChannel" }
func (*opaqueUnreliableMessageChannel) GoString() string {
	return "flowersec.UnreliableMessageChannel"
}
func (channel *opaqueUnreliableMessageChannel) MaxMessageBytes() int {
	return channel.inner.MaxMessageBytes()
}
func (channel *opaqueUnreliableMessageChannel) Send(ctx context.Context, payload []byte, options UnreliableSendOptions) (UnreliableSendStatus, error) {
	status, err := channel.inner.Send(ctx, payload, session.UnreliableSendOptions{ExpiresAt: options.ExpiresAt})
	return UnreliableSendStatus(status), redactNilSessionError(err)
}
func (channel *opaqueUnreliableMessageChannel) Receive(ctx context.Context) ([]byte, error) {
	payload, err := channel.inner.Receive(ctx)
	return payload, redactNilSessionError(err)
}

// RPCError is a sanitized application error returned by a remote RPC handler.
// Code and Message are application-level values; transport and session causes
// are projected through SessionError instead.
type RPCError struct {
	Code    uint32
	Message string
}

func (err *RPCError) Error() string {
	if err == nil {
		return "<nil>"
	}
	return "Flowersec RPC failed (code=" + strconv.FormatUint(uint64(err.Code), 10) + ")"
}

func (*opaqueRPCPeer) String() string   { return "Flowersec.RPCPeer" }
func (*opaqueRPCPeer) GoString() string { return "flowersec.RPCPeer" }

func (peer *opaqueRPCPeer) Call(ctx context.Context, typeID uint32, request, response any) error {
	if peer == nil || peer.inner == nil {
		return &SessionError{code: SessionClosed}
	}
	return redactRPCError(peer.inner.Call(ctx, typeID, request, response))
}

func (peer *opaqueRPCPeer) Notify(ctx context.Context, typeID uint32, request any) error {
	if peer == nil || peer.inner == nil {
		return &SessionError{code: SessionClosed}
	}
	return redactRPCError(peer.inner.Notify(ctx, typeID, request))
}

type opaqueByteStream struct {
	inner session.ByteStream
}

func (*opaqueByteStream) String() string   { return "Flowersec.ByteStream" }
func (*opaqueByteStream) GoString() string { return "flowersec.ByteStream" }

func (stream *opaqueByteStream) Read(buffer []byte) (int, error) {
	count, err := stream.inner.Read(buffer)
	return count, redactNilSessionError(err)
}

func (stream *opaqueByteStream) Write(buffer []byte) (int, error) {
	count, err := stream.inner.Write(buffer)
	return count, redactNilSessionError(err)
}

func (stream *opaqueByteStream) Close() error { return redactNilSessionError(stream.inner.Close()) }

func (stream *opaqueByteStream) Kind() string { return stream.inner.Kind() }

func (stream *opaqueByteStream) TerminalError() *SessionError {
	err := stream.inner.TerminalError()
	if err == nil {
		return nil
	}
	return redactSessionError(err)
}

func (stream *opaqueByteStream) CloseWrite() error {
	return redactNilSessionError(stream.inner.CloseWrite())
}

func (stream *opaqueByteStream) Reset() error { return redactNilSessionError(stream.inner.Reset()) }

func redactNilSessionError(err error) error {
	if err == nil {
		return nil
	}
	return redactSessionError(err)
}

func redactRPCError(err error) error {
	if err == nil {
		return nil
	}
	var application *internalrpc.CallError
	if errors.As(err, &application) && application != nil {
		return &RPCError{Code: application.Code, Message: application.Message}
	}
	return redactSessionError(err)
}

func redactSessionError(err error) *SessionError {
	code := SessionOperationFailed
	switch {
	case errors.Is(err, context.Canceled):
		code = SessionCanceled
	case errors.Is(err, context.DeadlineExceeded):
		code = SessionTimeout
	case errors.Is(err, session.ErrSessionClosed):
		code = SessionClosed
	case errors.Is(err, session.ErrGoingAway):
		code = SessionGoingAway
	case errors.Is(err, session.ErrResourceExhausted):
		code = SessionResourceExhausted
	case errors.Is(err, session.ErrOpenRejected):
		code = SessionStreamRejected
	case errors.Is(err, protocolv2.ErrStreamReset):
		code = SessionStreamReset
	case errors.Is(err, session.ErrRekey), errors.Is(err, session.ErrRekeyInProgress):
		code = SessionRekeyFailed
	case errors.Is(err, session.ErrLivenessProbe):
		code = SessionLivenessFailed
	case errors.Is(err, session.ErrUnreliableUnavailable):
		code = SessionUnreliableUnavailable
	case errors.Is(err, session.ErrUnreliableMessageTooLarge):
		code = SessionUnreliableTooLarge
	case errors.Is(err, session.ErrUnreliableDropped):
		code = SessionUnreliableDropped
	}
	return &SessionError{code: code}
}

func redactConnectError(err error) error {
	code := ConnectFailed
	var internal *fserrors.Error
	if errors.As(err, &internal) {
		switch internal.Code {
		case fserrors.CodeCanceled:
			code = ConnectCanceled
		case fserrors.CodeTimeout:
			code = ConnectTimeout
		case fserrors.CodeInvalidInput, fserrors.CodeInvalidOption:
			code = ConnectInvalid
		}
		return &ConnectError{code: code}
	}
	if errors.Is(err, context.DeadlineExceeded) {
		code = ConnectTimeout
	} else if errors.Is(err, context.Canceled) {
		code = ConnectCanceled
	}
	return &ConnectError{code: code}
}
