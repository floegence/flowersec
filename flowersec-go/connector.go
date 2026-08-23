package flowersec

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"strconv"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v3/internal/admissionv3"
	"github.com/floegence/flowersec/flowersec-go/v3/internal/artifactv3"
	"github.com/floegence/flowersec/flowersec-go/v3/internal/candidatev3"
	"github.com/floegence/flowersec/flowersec-go/v3/internal/connectv3"
	"github.com/floegence/flowersec/flowersec-go/v3/internal/defaults"
	"github.com/floegence/flowersec/flowersec-go/v3/internal/fserrors"
	"github.com/floegence/flowersec/flowersec-go/v3/internal/protocolv2"
	"github.com/floegence/flowersec/flowersec-go/v3/internal/protocolv3"
	internalrpc "github.com/floegence/flowersec/flowersec-go/v3/internal/rpc"
	"github.com/floegence/flowersec/flowersec-go/v3/internal/session"
	sessionv3 "github.com/floegence/flowersec/flowersec-go/v3/internal/sessionv3"
)

var (
	ErrInvalidConnectorOptions = errors.New("invalid Flowersec connector options")
	ErrConnectionFailed        = errors.New("Flowersec connection failed")
)

// ConnectErrorCode is the closed, carrier-neutral connection outcome set.
type ConnectErrorCode string

const (
	ConnectArtifactInvalid              ConnectErrorCode = "artifact_invalid"
	ConnectExpired                      ConnectErrorCode = "expired_artifact"
	ConnectTransportSecurityUnsupported ConnectErrorCode = "transport_security_unsupported"
	ConnectTransportSecurityFailed      ConnectErrorCode = "transport_security_failed"
	ConnectConnectionFailed             ConnectErrorCode = "connection_failed"
)

func (code ConnectErrorCode) String() string { return string(code) }

// ConnectorOptions configures carrier-neutral client trust and lifecycle
// policy. Carrier selection and carrier-specific tuning remain internal.
type ConnectorOptions struct {
	TrustRoots     *x509.CertPool
	Origin         string
	ConnectTimeout time.Duration
	RPCHandlers    *RPCHandlers
}

type connector struct {
	inner   connectorBackend
	timeout time.Duration
}

// Session is the carrier-neutral Flowersec v3 session contract.
type Session interface {
	RPC() RPCPeer
	UnreliableMessages() (UnreliableMessageChannel, error)
	OpenStream(context.Context, string, StreamMetadata) (ByteStream, error)
	AcceptStream(context.Context) (IncomingStream, error)
	Rekey(context.Context) error
	ProbeLiveness(context.Context) (time.Duration, error)
	WaitTermination(context.Context) (SessionTermination, error)
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

// SessionTermination is the stable, redacted terminal state of a session.
type SessionTermination struct {
	Error SessionError
}

// UnreliableMessageChannel sends opaque end-to-end encrypted messages without
// retransmission. An accepted send is queued locally and may still be lost.
type UnreliableMessageChannel interface {
	MaxMessageBytes() int
	Send(context.Context, []byte, UnreliableSendOptions) (UnreliableSendStatus, error)
	Receive(context.Context) ([]byte, error)
}

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
	Metadata StreamMetadata
	Stream   ByteStream
}

// RPCPeer provides bidirectional RPC over the session's reserved stream.
type RPCPeer interface {
	Call(context.Context, uint32, any, any) error
	Notify(context.Context, uint32, any) error
	OnNotify(uint32, func(context.Context, json.RawMessage)) func()
}

// ConnectError is the redacted, stable public connection failure.
type ConnectError struct {
	code        ConnectErrorCode
	disposition RetryDisposition
	detail      connectErrorDetail
}

type connectErrorDetail uint8

const (
	connectErrorDetailNone connectErrorDetail = iota
	connectErrorDetailInvalidOptions
	connectErrorDetailCanceled
	connectErrorDetailTimeout
)

func (err *ConnectError) Error() string {
	if err == nil {
		return "<nil>"
	}
	return "Flowersec connection failed (code=" + string(err.Code()) + ")"
}

func (err *ConnectError) Unwrap() error {
	if err != nil && err.detail == connectErrorDetailInvalidOptions {
		return ErrInvalidConnectorOptions
	}
	return ErrConnectionFailed
}

// Is preserves cancellation and deadline matching without exposing the
// internal connection failure that produced this public projection.
func (err *ConnectError) Is(target error) bool {
	if target == ErrConnectionFailed {
		return true
	}
	if err == nil {
		return false
	}
	switch err.detail {
	case connectErrorDetailCanceled:
		return target == context.Canceled
	case connectErrorDetailTimeout:
		return target == context.DeadlineExceeded
	default:
		return false
	}
}

// Code returns the closed, carrier-neutral connection outcome.
func (err *ConnectError) Code() ConnectErrorCode {
	if err == nil {
		return ConnectConnectionFailed
	}
	switch err.code {
	case ConnectArtifactInvalid, ConnectExpired, ConnectTransportSecurityUnsupported,
		ConnectTransportSecurityFailed, ConnectConnectionFailed:
		return err.code
	default:
		return ConnectConnectionFailed
	}
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
	Connect(context.Context) (connectv3.Result, error)
}

type transportEndpointKey struct {
	carrier       artifactv3.Carrier
	path          artifactv3.PathKind
	normalizedURL string
}

type controllerConnectOutcome struct {
	err               error
	spendStarted      bool
	retryDisposition  RetryDisposition
	hasDisposition    bool
	securityFailure   bool
	opaqueTrigger     bool
	triggerCandidates map[transportEndpointKey]artifactv3.Candidate
	failedEndpoints   map[transportEndpointKey]struct{}
}

// Connect establishes one carrier-neutral session from a single-use artifact
// lease. Carrier selection and connection-attempt state remain internal.
func Connect(ctx context.Context, lease ArtifactLease, options ConnectorOptions) (Session, error) {
	claimed, ok := lease.claimArtifact()
	if !ok {
		return nil, &ConnectError{code: ConnectArtifactInvalid}
	}
	return connectClaimed(ctx, claimed, options, nil)
}

func connectClaimed(
	ctx context.Context,
	claimed claimedArtifactLease,
	options ConnectorOptions,
	filter func(artifactv3.Candidate) bool,
) (Session, error) {
	connector, err := newConnectorWithFilter(claimed.lease, options, filter)
	if err != nil {
		_ = claimed.retire(nonNilContext(ctx))
		return nil, err
	}
	established, internalErr := connector.connectInternal(ctx)
	if internalErr != nil && !claimed.spendStarted() {
		_ = claimed.retire(nonNilContext(ctx))
	}
	return established, redactConnectError(internalErr)
}

func newConnector(lease ArtifactLease, options ConnectorOptions) (*connector, error) {
	return newConnectorWithFilter(lease, options, nil)
}

func newConnectorWithFilter(lease ArtifactLease, options ConnectorOptions, filter func(artifactv3.Candidate) bool) (*connector, error) {
	if lease.artifact.value == nil || lease.state == nil || lease.state.commitSpend == nil {
		return nil, &ConnectError{code: ConnectArtifactInvalid}
	}
	if !validConnectorOptions(options) {
		return nil, &ConnectError{
			code: ConnectArtifactInvalid, disposition: terminalDisposition(),
			detail: connectErrorDetailInvalidOptions,
		}
	}
	factory, err := candidatev3.NewGoNativeFactory(candidatev3.GoNativeConfig{
		TrustRoots: options.TrustRoots,
		Origin:     options.Origin,
	})
	if err != nil {
		return nil, &ConnectError{
			code: ConnectArtifactInvalid, disposition: terminalDisposition(),
			detail: connectErrorDetailInvalidOptions,
		}
	}
	connectorOptions := make([]connectv3.ConnectorOption, 0, 2)
	if options.RPCHandlers != nil {
		connectorOptions = append(connectorOptions, connectv3.WithRPCRouter(newRPCRouter(options.RPCHandlers.freeze())))
	}
	if filter != nil {
		connectorOptions = append(connectorOptions, connectv3.WithCandidateFilter(filter))
	}
	inner := connectv3.NewConnector(connectv3.ArtifactLease{
		Artifact: *lease.artifact.value, CommitSpend: lease.commitSpend,
	}, factory, connectorOptions...)
	return &connector{inner: inner, timeout: options.ConnectTimeout}, nil
}

func validConnectorOptions(options ConnectorOptions) bool {
	return validConnectorPolicy(options)
}

func validConnectorPolicy(options ConnectorOptions) bool {
	return (options.TrustRoots == nil || len(options.TrustRoots.Subjects()) != 0) &&
		options.ConnectTimeout >= 0 && validOrigin(options.Origin) &&
		(options.RPCHandlers == nil || options.RPCHandlers.valid())
}

func validOrigin(value string) bool {
	if value == "" {
		return true
	}
	origin, err := url.Parse(value)
	return err == nil && (origin.Scheme == "https" || origin.Scheme == "http") && origin.Host != "" && origin.User == nil &&
		origin.Hostname() != "" && origin.Path == "" && origin.RawPath == "" && origin.Opaque == "" &&
		origin.RawQuery == "" && !origin.ForceQuery && origin.Fragment == "" && origin.RawFragment == ""
}

func (connector *connector) connect(ctx context.Context) (Session, error) {
	established, err := connector.connectInternal(ctx)
	return established, redactConnectError(err)
}

func (connector *connector) connectInternal(ctx context.Context) (Session, error) {
	if connector == nil || connector.inner == nil {
		return nil, &fserrors.Error{Stage: fserrors.StageValidate, Code: fserrors.CodeInvalidOption, Err: ErrInvalidConnectorOptions}
	}
	if ctx == nil {
		ctx = context.Background()
	}
	timeout := connector.timeout
	if timeout == 0 {
		timeout = defaults.ConnectTimeout
	}
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	result, err := connector.inner.Connect(ctx)
	if err != nil {
		return nil, err
	}
	if result.Session == nil {
		return nil, ErrConnectionFailed
	}
	return &opaqueSessionV3{inner: result.Session}, nil
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

func (current *opaqueSession) OpenStream(ctx context.Context, kind string, metadata StreamMetadata) (ByteStream, error) {
	stream, err := current.inner.OpenStream(ctx, kind, session.Metadata(metadata.sessionValues()))
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
		Kind: incoming.Kind, Metadata: StreamMetadata{values: map[string]any(incoming.Metadata)}, Stream: &opaqueByteStream{inner: incoming.Stream},
	}, nil
}

func (current *opaqueSession) Rekey(ctx context.Context) error {
	return redactNilSessionError(current.inner.Rekey(ctx))
}

func (current *opaqueSession) ProbeLiveness(ctx context.Context) (time.Duration, error) {
	duration, err := current.inner.ProbeLiveness(ctx)
	return duration, redactNilSessionError(err)
}

func (current *opaqueSession) WaitTermination(ctx context.Context) (SessionTermination, error) {
	err := current.inner.WaitClosed(ctx)
	if err == nil {
		return SessionTermination{Error: SessionError{code: SessionClosed}}, nil
	}
	projected := redactSessionError(err)
	select {
	case <-current.inner.Termination():
		return SessionTermination{Error: *projected}, nil
	default:
	}
	if projected.Code() == SessionCanceled || projected.Code() == SessionTimeout {
		return SessionTermination{}, projected
	}
	return SessionTermination{Error: *projected}, nil
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

// OnNotify registers a handler for peer notifications. The returned function
// removes only this subscription and is safe to call repeatedly.
func (peer *opaqueRPCPeer) OnNotify(typeID uint32, handler func(context.Context, json.RawMessage)) func() {
	if peer == nil || peer.inner == nil || handler == nil {
		return func() {}
	}
	return peer.inner.OnNotify(typeID, func(ctx context.Context, payload []byte) {
		defer func() { _ = recover() }()
		handler(ctx, append(json.RawMessage(nil), payload...))
	})
}

type opaqueByteStream struct {
	inner session.ByteStream
}

func (*opaqueByteStream) String() string   { return "Flowersec.ByteStream" }
func (*opaqueByteStream) GoString() string { return "flowersec.ByteStream" }

func (stream *opaqueByteStream) Read(buffer []byte) (int, error) {
	count, err := stream.inner.Read(buffer)
	if errors.Is(err, io.EOF) {
		return count, io.EOF
	}
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

type opaqueSessionV3 struct {
	inner sessionv3.Session
}

func (*opaqueSessionV3) String() string   { return "Flowersec.Session" }
func (*opaqueSessionV3) GoString() string { return "flowersec.Session" }

func (current *opaqueSessionV3) RPC() RPCPeer { return &opaqueRPCPeerV3{inner: current.inner.RPC()} }

func (current *opaqueSessionV3) UnreliableMessages() (UnreliableMessageChannel, error) {
	channel, err := current.inner.UnreliableMessages()
	if err != nil {
		return nil, redactSessionError(err)
	}
	return &opaqueUnreliableMessageChannelV3{inner: channel}, nil
}

func (current *opaqueSessionV3) OpenStream(ctx context.Context, kind string, metadata StreamMetadata) (ByteStream, error) {
	stream, err := current.inner.OpenStream(ctx, kind, sessionv3.Metadata(metadata.sessionValues()))
	if err != nil {
		return nil, redactSessionError(err)
	}
	return &opaqueByteStreamV3{inner: stream}, nil
}

func (current *opaqueSessionV3) AcceptStream(ctx context.Context) (IncomingStream, error) {
	incoming, err := current.inner.AcceptStream(ctx)
	if err != nil {
		return IncomingStream{}, redactSessionError(err)
	}
	return IncomingStream{
		Kind: incoming.Kind, Metadata: StreamMetadata{values: map[string]any(incoming.Metadata)},
		Stream: &opaqueByteStreamV3{inner: incoming.Stream},
	}, nil
}

func (current *opaqueSessionV3) Rekey(ctx context.Context) error {
	return redactNilSessionError(current.inner.Rekey(ctx))
}

func (current *opaqueSessionV3) ProbeLiveness(ctx context.Context) (time.Duration, error) {
	duration, err := current.inner.ProbeLiveness(ctx)
	return duration, redactNilSessionError(err)
}

func (current *opaqueSessionV3) WaitTermination(ctx context.Context) (SessionTermination, error) {
	err := current.inner.WaitClosed(ctx)
	if err == nil {
		return SessionTermination{Error: SessionError{code: SessionClosed}}, nil
	}
	projected := redactSessionError(err)
	select {
	case <-current.inner.Termination():
		return SessionTermination{Error: *projected}, nil
	default:
	}
	if projected.Code() == SessionCanceled || projected.Code() == SessionTimeout {
		return SessionTermination{}, projected
	}
	return SessionTermination{Error: *projected}, nil
}

func (current *opaqueSessionV3) Close() error { return redactNilSessionError(current.inner.Close()) }

type opaqueRPCPeerV3 struct{ inner sessionv3.RPCPeer }

func (*opaqueRPCPeerV3) String() string   { return "Flowersec.RPCPeer" }
func (*opaqueRPCPeerV3) GoString() string { return "flowersec.RPCPeer" }

func (peer *opaqueRPCPeerV3) Call(ctx context.Context, typeID uint32, request, response any) error {
	if peer == nil || peer.inner == nil {
		return &SessionError{code: SessionClosed}
	}
	return redactRPCError(peer.inner.Call(ctx, typeID, request, response))
}

func (peer *opaqueRPCPeerV3) Notify(ctx context.Context, typeID uint32, request any) error {
	if peer == nil || peer.inner == nil {
		return &SessionError{code: SessionClosed}
	}
	return redactRPCError(peer.inner.Notify(ctx, typeID, request))
}

func (peer *opaqueRPCPeerV3) OnNotify(typeID uint32, handler func(context.Context, json.RawMessage)) func() {
	if peer == nil || peer.inner == nil || handler == nil {
		return func() {}
	}
	return peer.inner.OnNotify(typeID, func(ctx context.Context, payload []byte) {
		defer func() { _ = recover() }()
		handler(ctx, append(json.RawMessage(nil), payload...))
	})
}

type opaqueUnreliableMessageChannelV3 struct {
	inner sessionv3.UnreliableMessageChannel
}

func (*opaqueUnreliableMessageChannelV3) String() string { return "Flowersec.UnreliableMessageChannel" }
func (*opaqueUnreliableMessageChannelV3) GoString() string {
	return "flowersec.UnreliableMessageChannel"
}
func (channel *opaqueUnreliableMessageChannelV3) MaxMessageBytes() int {
	return channel.inner.MaxMessageBytes()
}
func (channel *opaqueUnreliableMessageChannelV3) Send(ctx context.Context, payload []byte, options UnreliableSendOptions) (UnreliableSendStatus, error) {
	status, err := channel.inner.Send(ctx, payload, sessionv3.UnreliableSendOptions{ExpiresAt: options.ExpiresAt})
	return UnreliableSendStatus(status), redactNilSessionError(err)
}
func (channel *opaqueUnreliableMessageChannelV3) Receive(ctx context.Context) ([]byte, error) {
	payload, err := channel.inner.Receive(ctx)
	return payload, redactNilSessionError(err)
}

type opaqueByteStreamV3 struct{ inner sessionv3.ByteStream }

func (*opaqueByteStreamV3) String() string   { return "Flowersec.ByteStream" }
func (*opaqueByteStreamV3) GoString() string { return "flowersec.ByteStream" }
func (stream *opaqueByteStreamV3) Read(buffer []byte) (int, error) {
	count, err := stream.inner.Read(buffer)
	if errors.Is(err, io.EOF) {
		return count, io.EOF
	}
	return count, redactNilSessionError(err)
}
func (stream *opaqueByteStreamV3) Write(buffer []byte) (int, error) {
	count, err := stream.inner.Write(buffer)
	return count, redactNilSessionError(err)
}
func (stream *opaqueByteStreamV3) Close() error { return redactNilSessionError(stream.inner.Close()) }
func (stream *opaqueByteStreamV3) Kind() string { return stream.inner.Kind() }
func (stream *opaqueByteStreamV3) TerminalError() *SessionError {
	if err := stream.inner.TerminalError(); err != nil {
		return redactSessionError(err)
	}
	return nil
}
func (stream *opaqueByteStreamV3) CloseWrite() error {
	return redactNilSessionError(stream.inner.CloseWrite())
}
func (stream *opaqueByteStreamV3) Reset() error { return redactNilSessionError(stream.inner.Reset()) }

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
	case errors.Is(err, session.ErrSessionClosed), errors.Is(err, sessionv3.ErrSessionClosed):
		code = SessionClosed
	case errors.Is(err, session.ErrGoingAway), errors.Is(err, sessionv3.ErrGoingAway):
		code = SessionGoingAway
	case errors.Is(err, session.ErrResourceExhausted), errors.Is(err, sessionv3.ErrResourceExhausted):
		code = SessionResourceExhausted
	case errors.Is(err, protocolv3.ErrCounterExhausted):
		code = SessionResourceExhausted
	case errors.Is(err, session.ErrOpenRejected), errors.Is(err, sessionv3.ErrOpenRejected):
		code = SessionStreamRejected
	case errors.Is(err, protocolv2.ErrStreamReset), errors.Is(err, protocolv3.ErrStreamReset):
		code = SessionStreamReset
	case errors.Is(err, session.ErrRekey), errors.Is(err, session.ErrRekeyInProgress),
		errors.Is(err, sessionv3.ErrRekey), errors.Is(err, sessionv3.ErrRekeyInProgress):
		code = SessionRekeyFailed
	case errors.Is(err, session.ErrLivenessProbe), errors.Is(err, sessionv3.ErrLivenessProbe):
		code = SessionLivenessFailed
	case errors.Is(err, session.ErrUnreliableUnavailable), errors.Is(err, sessionv3.ErrUnreliableUnavailable):
		code = SessionUnreliableUnavailable
	case errors.Is(err, session.ErrUnreliableMessageTooLarge), errors.Is(err, sessionv3.ErrUnreliableMessageTooLarge):
		code = SessionUnreliableTooLarge
	case errors.Is(err, session.ErrUnreliableDropped), errors.Is(err, sessionv3.ErrUnreliableDropped):
		code = SessionUnreliableDropped
	}
	return &SessionError{code: code}
}

func redactConnectError(err error) error {
	if err == nil {
		return nil
	}
	code := ConnectConnectionFailed
	var internal *fserrors.Error
	if errors.As(err, &internal) {
		if errors.Is(internal, connectv3.ErrArtifactExpired) {
			return &ConnectError{code: ConnectExpired}
		}
		switch internal.Code {
		case fserrors.CodeCanceled:
			return &ConnectError{
				code: ConnectConnectionFailed, disposition: terminalDisposition(),
				detail: connectErrorDetailCanceled,
			}
		case fserrors.CodeTimeout:
			return &ConnectError{
				code: ConnectConnectionFailed, disposition: retryableDisposition(),
				detail: connectErrorDetailTimeout,
			}
		case fserrors.CodeInvalidInput:
			code = ConnectArtifactInvalid
		case fserrors.CodeInvalidOption:
			return &ConnectError{
				code: ConnectArtifactInvalid, disposition: terminalDisposition(),
				detail: connectErrorDetailInvalidOptions,
			}
		case fserrors.CodeUnsupportedCapability, fserrors.CodeTLSUnsupported:
			code = ConnectTransportSecurityUnsupported
		case fserrors.CodeTLSPolicyExpired, fserrors.CodeTLSFailed:
			code = ConnectTransportSecurityFailed
		}
		return &ConnectError{code: code}
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return &ConnectError{
			code: ConnectConnectionFailed, disposition: retryableDisposition(),
			detail: connectErrorDetailTimeout,
		}
	} else if errors.Is(err, context.Canceled) {
		return &ConnectError{
			code: ConnectConnectionFailed, disposition: terminalDisposition(),
			detail: connectErrorDetailCanceled,
		}
	}
	return &ConnectError{code: code}
}

func connectForController(
	ctx context.Context,
	claimed claimedArtifactLease,
	options ConnectorOptions,
	allowed map[transportEndpointKey]struct{},
) (Session, controllerConnectOutcome) {
	var filter func(artifactv3.Candidate) bool
	if allowed != nil {
		path := claimed.lease.artifact.value.Path.Kind
		filter = func(candidate artifactv3.Candidate) bool {
			_, ok := allowed[endpointKey(path, candidate)]
			return ok
		}
	}
	connector, err := newConnectorWithFilter(claimed.lease, options, filter)
	if err != nil {
		_ = claimed.retire(nonNilContext(ctx))
		return nil, controllerConnectOutcome{err: err}
	}
	established, internalErr := connector.connectInternal(ctx)
	outcome := analyzeControllerConnectOutcome(claimed, internalErr)
	if internalErr != nil && !outcome.spendStarted {
		_ = claimed.retire(nonNilContext(ctx))
	}
	return established, outcome
}

func analyzeControllerConnectOutcome(claimed claimedArtifactLease, internalErr error) controllerConnectOutcome {
	outcome := controllerConnectOutcome{spendStarted: claimed.spendStarted()}
	if internalErr == nil {
		return outcome
	}
	outcome.err = redactConnectError(internalErr)
	switch {
	case errors.Is(internalErr, admissionv3.ErrAdmissionRejected):
		outcome.retryDisposition = terminalDisposition()
		outcome.hasDisposition = true
	case errors.Is(internalErr, admissionv3.ErrAdmissionRetryable):
		outcome.retryDisposition = retryableDisposition()
		outcome.hasDisposition = true
	}
	artifact := claimed.lease.artifact.value
	if artifact == nil {
		return outcome
	}
	byID := make(map[string]artifactv3.Candidate, len(artifact.Path.Candidates))
	outcome.failedEndpoints = make(map[transportEndpointKey]struct{}, len(artifact.Path.Candidates))
	for _, candidate := range artifact.Path.Candidates {
		byID[candidate.ID] = candidate
		outcome.failedEndpoints[endpointKey(artifact.Path.Kind, candidate)] = struct{}{}
	}
	var internal *fserrors.Error
	if !errors.As(internalErr, &internal) {
		return outcome
	}
	outcome.securityFailure = internal.Code == fserrors.CodeTLSFailed || internal.Code == fserrors.CodeTLSPolicyExpired
	for _, diagnostic := range internal.Diagnostics {
		candidate, ok := byID[diagnostic.CandidateID]
		if !ok || candidate.TLS.Mode != artifactv3.TLSModePin {
			continue
		}
		securityTrigger := diagnostic.Code == fserrors.CodeTLSPolicyExpired ||
			(diagnostic.Code == fserrors.CodeTLSFailed &&
				(diagnostic.Detail == "" || diagnostic.Detail == "pin_mismatch" || diagnostic.Detail == "unknown"))
		opaqueTrigger := diagnostic.Code == fserrors.CodeDialFailed && diagnostic.Detail == "browser_pin_opaque"
		if !securityTrigger && !opaqueTrigger {
			continue
		}
		if outcome.triggerCandidates == nil {
			outcome.triggerCandidates = make(map[transportEndpointKey]artifactv3.Candidate)
		}
		outcome.triggerCandidates[endpointKey(artifact.Path.Kind, candidate)] = candidate
		outcome.securityFailure = outcome.securityFailure || securityTrigger
		outcome.opaqueTrigger = outcome.opaqueTrigger || opaqueTrigger
	}
	return outcome
}

func endpointKey(path artifactv3.PathKind, candidate artifactv3.Candidate) transportEndpointKey {
	return transportEndpointKey{carrier: candidate.Carrier, path: path, normalizedURL: candidate.NormalizedURL}
}

func nonNilContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}
