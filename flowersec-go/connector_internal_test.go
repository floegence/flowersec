package flowersec

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/connectv2"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/protocolv2"
	internalrpc "github.com/floegence/flowersec/flowersec-go/v2/internal/rpc"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/session"
)

func TestConnectorMapsInternalResultToCarrierNeutralSession(t *testing.T) {
	want := inertSession{path: session.PathTunnel}
	connector := &Connector{inner: staticConnectorBackend{result: connectv2.Result{Session: want}}}

	got, err := connector.Connect(context.Background())
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
	connector := &Connector{inner: staticConnectorBackend{err: errors.New("candidate secret-id at wss://secret.example failed")}}

	_, err := connector.Connect(context.Background())
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
