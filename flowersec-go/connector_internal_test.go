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

	"github.com/floegence/flowersec/flowersec-go/v3/internal/connectv3"
	"github.com/floegence/flowersec/flowersec-go/v3/internal/fserrors"
	"github.com/floegence/flowersec/flowersec-go/v3/internal/protocolv3"
	internalrpc "github.com/floegence/flowersec/flowersec-go/v3/internal/rpc"
	session "github.com/floegence/flowersec/flowersec-go/v3/internal/sessionv3"
)

func mustParseInternalFixtureArtifact(t *testing.T) Artifact {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "testdata", "transport_v3", "artifact_vectors.json"))
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
	if !lease.claimForConnectionController() {
		t.Fatal("lease claim failed")
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

func TestArtifactLeaseBurnsAfterSpendFailure(t *testing.T) {
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
	if !lease.claimForConnectionController() {
		t.Fatal("lease claim failed")
	}
	if err := lease.commitSpend(context.Background()); err == nil {
		t.Fatal("first commitSpend() error = nil")
	}
	if err := lease.commitSpend(context.Background()); !errors.Is(err, errArtifactLeaseConsumed) {
		t.Fatalf("reused commitSpend() error = %v, want consumed", err)
	}
	if attempts != 1 {
		t.Fatalf("commit callback attempts = %d, want 1", attempts)
	}
}

func TestArtifactLeaseBurnsAfterSpendCancellation(t *testing.T) {
	artifact := mustParseInternalFixtureArtifact(t)
	attempts := 0
	lease, err := NewArtifactLease(artifact, func(ctx context.Context) error {
		attempts++
		return ctx.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	if !lease.claimForConnectionController() {
		t.Fatal("lease claim failed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := lease.commitSpend(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled commitSpend() error = %v, want canceled", err)
	}
	if err := lease.commitSpend(context.Background()); !errors.Is(err, errArtifactLeaseConsumed) {
		t.Fatalf("reused commitSpend() error = %v, want consumed", err)
	}
	if attempts != 1 {
		t.Fatalf("commit callback attempts = %d, want 1", attempts)
	}
}

func TestArtifactLeaseBurnsWhenSpendCallbackOutlivesCancellation(t *testing.T) {
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
	if !lease.claimForConnectionController() {
		t.Fatal("lease claim failed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- lease.commitSpend(ctx) }()
	<-started
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled commitSpend() error = %v, want canceled", err)
	}
	lease.state.mu.Lock()
	status := lease.state.status
	lease.state.mu.Unlock()
	if status != artifactLeaseConsumed {
		t.Fatalf("lease status after callback outlives cancellation = %d, want consumed", status)
	}
	close(release)
}

func TestArtifactLeaseBurnsAfterSpendCallbackPanic(t *testing.T) {
	artifact := mustParseInternalFixtureArtifact(t)
	lease, err := NewArtifactLease(artifact, func(context.Context) error { panic("unknown spend result") })
	if err != nil {
		t.Fatal(err)
	}
	if !lease.claimForConnectionController() {
		t.Fatal("lease claim failed")
	}
	if err := lease.commitSpend(context.Background()); err == nil {
		t.Fatal("panic callback returned nil error")
	}
	if err := lease.commitSpend(context.Background()); !errors.Is(err, errArtifactLeaseConsumed) {
		t.Fatalf("reused commitSpend() error = %v, want consumed", err)
	}
}

func TestConnectorFreezesRPCHandlersOnlyAfterLocalValidation(t *testing.T) {
	artifact := mustParseInternalFixtureArtifact(t)
	lease, err := NewArtifactLease(artifact, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	handlers := NewRPCHandlers()
	trustRoots := x509.NewCertPool()
	trustRoots.AddCert(&x509.Certificate{RawSubject: []byte("test root")})

	if _, err := newConnector(lease, ConnectorOptions{
		TrustRoots:  trustRoots,
		Origin:      "invalid",
		RPCHandlers: handlers,
	}); !errors.Is(err, ErrInvalidConnectorOptions) {
		t.Fatalf("newConnector() error = %v, want invalid options", err)
	}
	if err := handlers.HandleRPC(1, func(context.Context, json.RawMessage) (any, *RPCError) {
		return nil, nil
	}); err != nil {
		t.Fatalf("HandleRPC() after invalid options = %v", err)
	}

	if _, err := newConnector(lease, ConnectorOptions{
		TrustRoots:  trustRoots,
		Origin:      "https://client.example",
		RPCHandlers: handlers,
	}); err != nil {
		t.Fatalf("newConnector() error = %v", err)
	}
	if err := handlers.HandleNotification(2, func(context.Context, json.RawMessage) error { return nil }); !errors.Is(err, ErrHandlerRegistryFrozen) {
		t.Fatalf("HandleNotification() after valid connector = %v, want frozen", err)
	}
}

func TestRPCHandlersFreezeSharedNamespaceWithoutReplacingOriginal(t *testing.T) {
	handlers := NewRPCHandlers()
	original := func(context.Context, json.RawMessage) (any, *RPCError) { return "original", nil }
	if err := handlers.HandleRPC(0, original); !errors.Is(err, ErrInvalidHandlerRegistration) {
		t.Fatalf("zero HandleRPC() error = %v", err)
	}
	if err := handlers.HandleRPC(1, nil); !errors.Is(err, ErrInvalidHandlerRegistration) {
		t.Fatalf("nil HandleRPC() error = %v", err)
	}
	if err := handlers.HandleRPC(1, original); err != nil {
		t.Fatal(err)
	}
	if err := handlers.HandleNotification(^uint32(0), func(context.Context, json.RawMessage) error { return nil }); err != nil {
		t.Fatalf("maximum type ID registration error = %v", err)
	}
	if err := handlers.HandleRPC(1, func(context.Context, json.RawMessage) (any, *RPCError) { return "replacement", nil }); !errors.Is(err, ErrHandlerAlreadyExists) {
		t.Fatalf("duplicate HandleRPC() error = %v", err)
	}
	if err := handlers.HandleNotification(1, func(context.Context, json.RawMessage) error { return nil }); !errors.Is(err, ErrHandlerAlreadyExists) {
		t.Fatalf("cross-role duplicate error = %v", err)
	}

	firstSnapshot := handlers.freeze()
	if secondSnapshot := handlers.freeze(); secondSnapshot != firstSnapshot {
		t.Fatal("repeated freeze returned a different snapshot")
	}
	response, rpcErr := firstSnapshot.requests[1](context.Background(), json.RawMessage(`null`))
	if response != "original" || rpcErr != nil {
		t.Fatalf("frozen original handler = %#v, %#v", response, rpcErr)
	}
	if firstRouter, secondRouter := newRPCRouter(firstSnapshot), newRPCRouter(firstSnapshot); firstRouter == secondRouter {
		t.Fatal("two sessions received the same RPC router")
	}
	if err := handlers.HandleNotification(2, func(context.Context, json.RawMessage) error { return nil }); !errors.Is(err, ErrHandlerRegistryFrozen) {
		t.Fatalf("registration after freeze error = %v", err)
	}
}

func TestConnectorAllowsEmptyOriginForNonWebTransportProfiles(t *testing.T) {
	artifact := mustParseInternalFixtureArtifact(t)
	lease, err := NewArtifactLease(artifact, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	trustRoots := x509.NewCertPool()
	trustRoots.AddCert(&x509.Certificate{RawSubject: []byte("test root")})
	if _, err := newConnector(lease, ConnectorOptions{TrustRoots: trustRoots}); err != nil {
		t.Fatalf("newConnector() empty Origin error = %v", err)
	}
	if _, err := newConnector(lease, ConnectorOptions{TrustRoots: trustRoots, Origin: "http://client.example"}); err != nil {
		t.Fatalf("newConnector() HTTP Origin error = %v", err)
	}
}

func TestConnectorUsesPlatformTrustRootsWhenNoPoolIsConfigured(t *testing.T) {
	secure := mustParseInternalFixtureArtifact(t)
	secureLease, err := NewArtifactLease(secure, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newConnector(secureLease, ConnectorOptions{}); err != nil {
		t.Fatalf("platform-root newConnector() error = %v", err)
	}
}

func TestConnectorOriginIsAnExactHTTPOrigin(t *testing.T) {
	for _, origin := range []string{"", "http://client.example", "https://client.example"} {
		if !validOrigin(origin) {
			t.Fatalf("validOrigin(%q) = false, want true", origin)
		}
	}
	for _, origin := range []string{
		"ftp://client.example",
		"https://user@client.example",
		"https://client.example/",
		"https://client.example/path",
		"https://client.example?query",
		"https://client.example#fragment",
	} {
		if validOrigin(origin) {
			t.Fatalf("validOrigin(%q) = true, want false", origin)
		}
	}
}

func TestConnectorMapsInternalResultToCarrierNeutralSession(t *testing.T) {
	want := inertSession{path: session.PathTunnel}
	connector := &connector{inner: staticConnectorBackend{result: connectv3.Result{Session: want}}}

	got, err := connector.connect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	opaque, ok := got.(*opaqueSessionV3)
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
	current := &opaqueSessionV3{inner: inertSession{path: session.PathDirect}}
	channel, err := current.UnreliableMessages()
	if channel != nil {
		t.Fatalf("channel = %#v, want nil", channel)
	}
	var projected *SessionError
	if !errors.As(err, &projected) || projected.Code() != SessionUnreliableUnavailable {
		t.Fatalf("UnreliableMessages error = %#v, want %q", err, SessionUnreliableUnavailable)
	}
}

func TestWaitTerminationSeparatesTerminalCauseFromWaitCancellation(t *testing.T) {
	closed := &opaqueSessionV3{inner: inertSession{waitErr: session.ErrSessionClosed}}
	termination, err := closed.WaitTermination(context.Background())
	if err != nil {
		t.Fatalf("WaitTermination closed error = %v, want nil", err)
	}
	if termination.Error.Code() != SessionClosed {
		t.Fatalf("WaitTermination closed = %#v, want SessionClosed", termination)
	}
	canceled := &opaqueSessionV3{inner: inertSession{waitErr: context.Canceled}}
	termination, err = canceled.WaitTermination(context.Background())
	if termination != (SessionTermination{}) {
		t.Fatalf("WaitTermination canceled termination = %#v, want none", termination)
	}
	if projected, ok := err.(*SessionError); !ok || projected.Code() != SessionCanceled {
		t.Fatalf("WaitTermination canceled error = %#v, want SessionCanceled", err)
	}
}

func TestConnectorRedactsInternalCandidateFailure(t *testing.T) {
	connector := &connector{inner: staticConnectorBackend{err: errors.New("candidate secret-id at wss://secret.example failed")}}

	_, err := connector.connect(context.Background())
	if !errors.Is(err, ErrConnectionFailed) || strings.Contains(err.Error(), "secret") {
		t.Fatalf("Connect error = %q, want redacted stable failure", err)
	}
	var public *ConnectError
	if !errors.As(err, &public) || public.Code() != ConnectConnectionFailed {
		t.Fatalf("Connect error projection = %#v", public)
	}
	if got, want := public.Error(), "Flowersec connection failed (code=connection_failed)"; got != want {
		t.Fatalf("Connect error = %q, want %q", got, want)
	}
}

func TestConnectorProjectsArtifactExpiryWithoutInternalDetails(t *testing.T) {
	internal := fserrors.Wrap(
		fserrors.PathDirect,
		fserrors.StageValidate,
		fserrors.CodeTimeout,
		errors.Join(connectv3.ErrArtifactExpired, errors.New("secret artifact detail")),
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

func TestControllerTreatsExpiredPinDiagnosticAsReplacementTrigger(t *testing.T) {
	artifact := mustParseInternalFixtureArtifact(t)
	candidate := artifact.value.Path.Candidates[1]
	lease, err := NewArtifactLease(artifact, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	claimed, ok := lease.claimArtifact()
	if !ok {
		t.Fatal("artifact lease claim failed")
	}
	internalErr := &fserrors.Error{
		Path:  fserrors.PathDirect,
		Stage: fserrors.StageConnect,
		Code:  fserrors.CodeTLSPolicyExpired,
		Diagnostics: []fserrors.CandidateDiagnostic{{
			CandidateID: candidate.ID,
			Carrier:     string(candidate.Carrier),
			Stage:       fserrors.StageValidate,
			Code:        fserrors.CodeTLSPolicyExpired,
			Detail:      "policy_expired",
		}},
	}
	outcome := analyzeControllerConnectOutcome(claimed, internalErr)
	if outcome.err == nil || connectErrorCode(outcome.err) != ConnectTransportSecurityFailed {
		t.Fatalf("controller outcome error = %v, want transport_security_failed", outcome.err)
	}
	if !outcome.securityFailure || len(outcome.triggerCandidates) != 1 {
		t.Fatalf("controller outcome = %+v, want security refresh trigger", outcome)
	}
	if _, ok := outcome.triggerCandidates[endpointKey(artifact.value.Path.Kind, candidate)]; !ok {
		t.Fatalf("trigger candidates = %+v, want candidate %q", outcome.triggerCandidates, candidate.ID)
	}
}

func TestPublicErrorsPreserveStableCancellationAndDeadlineCauses(t *testing.T) {
	for _, test := range []struct {
		name        string
		internal    error
		disposition RetryDispositionKind
		sessionCode SessionErrorCode
	}{
		{name: "canceled", internal: context.Canceled, disposition: RetryDispositionTerminal, sessionCode: SessionCanceled},
		{name: "deadline", internal: context.DeadlineExceeded, disposition: RetryDispositionRetryable, sessionCode: SessionTimeout},
	} {
		t.Run(test.name, func(t *testing.T) {
			connectErr := redactConnectError(test.internal)
			if !errors.Is(connectErr, ErrConnectionFailed) || !errors.Is(connectErr, test.internal) {
				t.Fatalf("connect error causes = %v, want ErrConnectionFailed and %v", connectErr, test.internal)
			}
			var projectedConnect *ConnectError
			if !errors.As(connectErr, &projectedConnect) || projectedConnect.Code() != ConnectConnectionFailed {
				t.Fatalf("connect error = %#v, want code %q", projectedConnect, ConnectConnectionFailed)
			}
			if got := projectedConnect.RetryDisposition().Kind; got != test.disposition {
				t.Fatalf("connect disposition = %q, want %q", got, test.disposition)
			}

			sessionErr := redactSessionError(test.internal)
			if !errors.Is(sessionErr, test.internal) || sessionErr.Code() != test.sessionCode {
				t.Fatalf("session error = %#v, want code %q and cause %v", sessionErr, test.sessionCode, test.internal)
			}
		})
	}
}

func TestProtocolStreamResetProjectsStablePublicCode(t *testing.T) {
	stream := &opaqueByteStreamV3{inner: staticByteStream{err: protocolv3.ErrStreamReset}}
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
	stream := &opaqueByteStreamV3{inner: staticByteStream{err: io.EOF}}
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

func TestRPCProjectionMapsMalformedApplicationEnvelopeToOperationFailure(t *testing.T) {
	const secret = "malformed-rpc-secret-marker"
	peer := &opaqueRPCPeer{inner: staticRPCPeer{err: errors.New("rpc invalid application error: " + secret)}}
	err := peer.Call(context.Background(), 7, struct{}{}, &struct{}{})
	var sessionErr *SessionError
	if !errors.As(err, &sessionErr) || sessionErr.Code() != SessionOperationFailed {
		t.Fatalf("RPC malformed response = %#v, want %q", err, SessionOperationFailed)
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("RPC malformed response exposed internal detail: %v", err)
	}
}

type staticConnectorBackend struct {
	result connectv3.Result
	err    error
}

type deadlineConnectorBackend struct{ remaining time.Duration }

func (backend *deadlineConnectorBackend) Connect(ctx context.Context) (connectv3.Result, error) {
	deadline, ok := ctx.Deadline()
	if ok {
		backend.remaining = time.Until(deadline)
	}
	return connectv3.Result{}, errors.New("stop after recording deadline")
}

type staticRPCPeer struct{ err error }

func (peer staticRPCPeer) Call(context.Context, uint32, any, any) error          { return peer.err }
func (peer staticRPCPeer) Notify(context.Context, uint32, any) error             { return peer.err }
func (peer staticRPCPeer) OnNotify(uint32, func(context.Context, []byte)) func() { return func() {} }

type staticByteStream struct{ err error }

func (staticByteStream) ID() uint64                       { return 7 }
func (staticByteStream) Kind() string                     { return "rpc" }
func (stream staticByteStream) TerminalError() error      { return stream.err }
func (stream staticByteStream) Read([]byte) (int, error)  { return 0, stream.err }
func (stream staticByteStream) Write([]byte) (int, error) { return 0, stream.err }
func (stream staticByteStream) Close() error              { return stream.err }
func (stream staticByteStream) CloseWrite() error         { return stream.err }
func (stream staticByteStream) Reset() error              { return stream.err }

func (backend staticConnectorBackend) Connect(context.Context) (connectv3.Result, error) {
	return backend.result, backend.err
}

type inertSession struct {
	path    session.PathKind
	waitErr error
}

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
func (inertSession) WaitTermination(context.Context) (SessionTermination, error) {
	return SessionTermination{}, nil
}
func (value inertSession) WaitClosed(context.Context) error { return value.waitErr }
func (inertSession) Close() error                           { return nil }
