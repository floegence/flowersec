package flowersec

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/connectv2"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/fserrors"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/protocolv2"
	internalrpc "github.com/floegence/flowersec/flowersec-go/v2/internal/rpc"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/session"
)

func mustParseInternalFixtureArtifact(t *testing.T) Artifact {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "testdata", "transport_v2", "artifact_vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixtures struct {
		Positive []struct {
			ArtifactJSON string `json:"artifact_json"`
		} `json:"positive"`
	}
	if err := json.Unmarshal(raw, &fixtures); err != nil {
		t.Fatal(err)
	}
	artifact, err := ParseArtifact([]byte(fixtures.Positive[0].ArtifactJSON))
	if err != nil {
		t.Fatal(err)
	}
	return artifact
}

func TestArtifactLeaseAuthorizesExactlyOneConcurrentSpend(t *testing.T) {
	artifact := mustParseInternalFixtureArtifact(t)
	started := make(chan struct{})
	release := make(chan struct{})
	lease, err := NewArtifactLease(artifact, func(context.Context) error {
		close(started)
		<-release
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	first := make(chan error, 1)
	go func() { first <- lease.commitSpend(context.Background()) }()
	<-started
	if err := lease.commitSpend(context.Background()); !errors.Is(err, errArtifactLeaseConsumed) {
		t.Fatalf("concurrent commitSpend() error = %v, want consumed", err)
	}
	close(release)
	if err := <-first; err != nil {
		t.Fatalf("first commitSpend() error = %v", err)
	}
	if err := lease.commitSpend(context.Background()); !errors.Is(err, errArtifactLeaseConsumed) {
		t.Fatalf("reused commitSpend() error = %v, want consumed", err)
	}
}

func TestArtifactLeaseAllowsRetryAfterSpendFailure(t *testing.T) {
	artifact := mustParseInternalFixtureArtifact(t)
	attempts := 0
	lease, err := NewArtifactLease(artifact, func(context.Context) error {
		attempts++
		if attempts == 1 {
			return errors.New("durability failed")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := lease.commitSpend(context.Background()); err == nil {
		t.Fatal("first commitSpend() error = nil")
	}
	if err := lease.commitSpend(context.Background()); err != nil {
		t.Fatalf("retry commitSpend() error = %v", err)
	}
}

func TestConnectorFreezesHandlersOnlyAfterLocalValidation(t *testing.T) {
	artifact := mustParseInternalFixtureArtifact(t)
	lease, err := NewArtifactLease(artifact, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	handlers, err := NewSessionHandlers(SessionHandlerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	trustRoots := x509.NewCertPool()
	trustRoots.AddCert(&x509.Certificate{RawSubject: []byte("test root")})

	if _, err := newConnector(lease, ConnectorOptions{
		TrustRoots: trustRoots,
		Origin:     "invalid",
		Handlers:   handlers,
	}); !errors.Is(err, ErrInvalidConnectorOptions) {
		t.Fatalf("newConnector() error = %v, want invalid options", err)
	}
	if err := handlers.HandleRPC(1, func(context.Context, json.RawMessage) (any, *RPCError) {
		return nil, nil
	}); err != nil {
		t.Fatalf("HandleRPC() after invalid options = %v", err)
	}

	if _, err := newConnector(lease, ConnectorOptions{
		TrustRoots: trustRoots,
		Origin:     "https://client.example",
		Handlers:   handlers,
	}); err != nil {
		t.Fatalf("newConnector() error = %v", err)
	}
	if err := handlers.HandleStream("late", func(context.Context, IncomingStream) {}); !errors.Is(err, ErrSessionHandlersFrozen) {
		t.Fatalf("HandleStream() after valid connector = %v, want frozen", err)
	}
}

func TestConnectorMapsInternalResultToCarrierNeutralSession(t *testing.T) {
	want := inertSession{path: session.PathTunnel}
	connector := &connector{inner: staticConnectorBackend{result: connectv2.Result{Session: want}}}

	got, err := connector.connect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	opaque, ok := got.(*opaqueSession)
	if !ok || opaque.inner != want {
		t.Fatalf("Connect session = %#v, want carrier-neutral tunnel session", got)
	}
	if formatted, want := fmt.Sprintf("%#v", got), "flowersec.Session"; formatted != want {
		t.Fatalf("formatted Session = %q, want %q", formatted, want)
	}
}

func TestConnectorZeroTimeoutUsesSharedDefault(t *testing.T) {
	backend := &deadlineConnectorBackend{}
	connector := &connector{inner: backend}
	_, _ = connector.connect(context.Background())
	if backend.remaining < 9*time.Second || backend.remaining > 10*time.Second {
		t.Fatalf("zero-value connector timeout = %v, want shared 10 second default", backend.remaining)
	}
}

func TestUnreliableUnavailableProjectsStablePublicCode(t *testing.T) {
	current := &opaqueSession{inner: inertSession{path: session.PathDirect}}
	channel, err := current.UnreliableMessages()
	if channel != nil {
		t.Fatalf("channel = %#v, want nil", channel)
	}
	var projected *SessionError
	if !errors.As(err, &projected) || projected.Code() != SessionUnreliableUnavailable {
		t.Fatalf("UnreliableMessages error = %#v, want %q", err, SessionUnreliableUnavailable)
	}
}

func TestConnectorRedactsInternalCandidateFailure(t *testing.T) {
	connector := &connector{inner: staticConnectorBackend{err: errors.New("candidate secret-id at wss://secret.example failed")}}

	_, err := connector.connect(context.Background())
	if !errors.Is(err, ErrConnectionFailed) || strings.Contains(err.Error(), "secret") {
		t.Fatalf("Connect error = %q, want redacted stable failure", err)
	}
	var public *ConnectError
	if !errors.As(err, &public) || public.Code() != ConnectFailed {
		t.Fatalf("Connect error projection = %#v", public)
	}
	if got, want := public.Error(), "Flowersec connection failed (code=failed)"; got != want {
		t.Fatalf("Connect error = %q, want %q", got, want)
	}
}

func TestConnectorProjectsArtifactExpiryWithoutInternalDetails(t *testing.T) {
	internal := fserrors.Wrap(
		fserrors.PathDirect,
		fserrors.StageValidate,
		fserrors.CodeTimeout,
		errors.Join(connectv2.ErrArtifactExpired, errors.New("secret artifact detail")),
	)
	connector := &connector{inner: staticConnectorBackend{err: internal}}

	_, err := connector.connect(context.Background())
	var public *ConnectError
	if !errors.As(err, &public) || public.Code() != ConnectExpired {
		t.Fatalf("Connect error = %#v, want code %q", err, ConnectExpired)
	}
	if strings.Contains(err.Error(), "secret") {
		t.Fatalf("Connect error leaked internal details: %q", err)
	}
}

func TestPublicErrorsPreserveStableCancellationAndDeadlineCauses(t *testing.T) {
	for _, test := range []struct {
		name        string
		internal    error
		connectCode ConnectErrorCode
		sessionCode SessionErrorCode
	}{
		{name: "canceled", internal: context.Canceled, connectCode: ConnectCanceled, sessionCode: SessionCanceled},
		{name: "deadline", internal: context.DeadlineExceeded, connectCode: ConnectTimeout, sessionCode: SessionTimeout},
	} {
		t.Run(test.name, func(t *testing.T) {
			connectErr := redactConnectError(test.internal)
			if !errors.Is(connectErr, ErrConnectionFailed) || !errors.Is(connectErr, test.internal) {
				t.Fatalf("connect error causes = %v, want ErrConnectionFailed and %v", connectErr, test.internal)
			}
			var projectedConnect *ConnectError
			if !errors.As(connectErr, &projectedConnect) || projectedConnect.Code() != test.connectCode {
				t.Fatalf("connect error = %#v, want code %q", projectedConnect, test.connectCode)
			}

			sessionErr := redactSessionError(test.internal)
			if !errors.Is(sessionErr, test.internal) || sessionErr.Code() != test.sessionCode {
				t.Fatalf("session error = %#v, want code %q and cause %v", sessionErr, test.sessionCode, test.internal)
			}
		})
	}
}

func TestProtocolStreamResetProjectsStablePublicCode(t *testing.T) {
	stream := &opaqueByteStream{inner: staticByteStream{err: protocolv2.ErrStreamReset}}
	err := stream.TerminalError()
	if err.Code() != SessionStreamReset {
		t.Fatalf("stream reset code = %q, want %q", err.Code(), SessionStreamReset)
	}
	if _, readErr := stream.Read(nil); readErr == nil {
		t.Fatal("stream read error = nil, want reset projection")
	} else if projected, ok := readErr.(*SessionError); !ok || projected.Code() != SessionStreamReset {
		t.Fatalf("stream read error = %#v, want %q", readErr, SessionStreamReset)
	}
}

func TestPublicByteStreamPreservesEOF(t *testing.T) {
	stream := &opaqueByteStream{inner: staticByteStream{err: io.EOF}}
	if count, err := stream.Read(make([]byte, 1)); count != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("Read = %d, %v, want 0, io.EOF", count, err)
	}
}

func TestRPCProjectionPreservesApplicationErrorAndRedactsTransportFailure(t *testing.T) {
	peer := &opaqueRPCPeer{inner: staticRPCPeer{err: &internalrpc.CallError{
		TypeID: 7, Code: 404, Message: "handler not found",
	}}}
	err := peer.Call(context.Background(), 7, struct{}{}, &struct{}{})
	var application *RPCError
	if !errors.As(err, &application) || application.Code != 404 || application.Message != "handler not found" {
		t.Fatalf("RPC application error = %#v, want code/message projection", err)
	}

	peer = &opaqueRPCPeer{inner: staticRPCPeer{err: errors.New("candidate secret at wss://secret.example")}}
	err = peer.Call(context.Background(), 7, struct{}{}, &struct{}{})
	var sessionErr *SessionError
	if !errors.As(err, &sessionErr) || sessionErr.Code() != SessionOperationFailed || strings.Contains(err.Error(), "secret") {
		t.Fatalf("RPC transport error = %#v, want redacted operation failure", err)
	}
}

type staticConnectorBackend struct {
	result connectv2.Result
	err    error
}

type deadlineConnectorBackend struct{ remaining time.Duration }

func (backend *deadlineConnectorBackend) Connect(ctx context.Context) (connectv2.Result, error) {
	deadline, ok := ctx.Deadline()
	if ok {
		backend.remaining = time.Until(deadline)
	}
	return connectv2.Result{}, errors.New("stop after recording deadline")
}

type staticRPCPeer struct{ err error }

func (peer staticRPCPeer) Call(context.Context, uint32, any, any) error { return peer.err }
func (peer staticRPCPeer) Notify(context.Context, uint32, any) error    { return peer.err }

type staticByteStream struct{ err error }

func (staticByteStream) ID() uint64                       { return 7 }
func (staticByteStream) Kind() string                     { return "rpc" }
func (stream staticByteStream) TerminalError() error      { return stream.err }
func (stream staticByteStream) Read([]byte) (int, error)  { return 0, stream.err }
func (stream staticByteStream) Write([]byte) (int, error) { return 0, stream.err }
func (stream staticByteStream) Close() error              { return stream.err }
func (stream staticByteStream) CloseWrite() error         { return stream.err }
func (stream staticByteStream) Reset() error              { return stream.err }

func (backend staticConnectorBackend) Connect(context.Context) (connectv2.Result, error) {
	return backend.result, backend.err
}

type inertSession struct{ path session.PathKind }

func (value inertSession) Path() session.PathKind       { return value.path }
func (inertSession) EndpointInstanceID() (string, bool) { return "", false }
func (inertSession) RPC() session.RPCPeer               { return nil }
func (inertSession) UnreliableMessages() (session.UnreliableMessageChannel, error) {
	return nil, session.ErrUnreliableUnavailable
}
func (inertSession) OpenStream(context.Context, string, session.Metadata) (session.ByteStream, error) {
	return nil, nil
}
func (inertSession) AcceptStream(context.Context) (session.IncomingStream, error) {
	return session.IncomingStream{}, nil
}
func (inertSession) Rekey(context.Context) error                          { return nil }
func (inertSession) ProbeLiveness(context.Context) (time.Duration, error) { return 0, nil }
func (inertSession) Termination() <-chan struct{}                         { return make(chan struct{}) }
func (inertSession) WaitClosed(context.Context) error                     { return nil }
func (inertSession) Close() error                                         { return nil }
