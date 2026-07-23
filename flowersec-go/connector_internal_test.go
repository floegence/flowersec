package flowersec

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/connectv2"
	"github.com/floegence/flowersec/flowersec-go/v2/session"
)

func TestConnectorMapsInternalResultToCarrierNeutralSession(t *testing.T) {
	want := inertSession{path: session.PathTunnel}
	connector := &Connector{inner: staticConnectorBackend{result: connectv2.Result{Session: want}}}

	got, err := connector.Connect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got != want || got.Path() != session.PathTunnel {
		t.Fatalf("Connect session = %#v, want carrier-neutral tunnel session", got)
	}
}

func TestConnectorRedactsInternalCandidateFailure(t *testing.T) {
	connector := &Connector{inner: staticConnectorBackend{err: errors.New("candidate secret-id at wss://secret.example failed")}}

	_, err := connector.Connect(context.Background())
	if !errors.Is(err, ErrConnectionFailed) || strings.Contains(err.Error(), "secret") {
		t.Fatalf("Connect error = %q, want redacted stable failure", err)
	}
	var public *ConnectError
	if !errors.As(err, &public) || public.Path != "auto" || public.Stage != "connect" || public.Code != "dial_failed" {
		t.Fatalf("Connect error projection = %#v", public)
	}
}

type staticConnectorBackend struct {
	result connectv2.Result
	err    error
}

func (backend staticConnectorBackend) Connect(context.Context) (connectv2.Result, error) {
	return backend.result, backend.err
}

type inertSession struct{ path session.PathKind }

func (value inertSession) Path() session.PathKind       { return value.path }
func (inertSession) EndpointInstanceID() (string, bool) { return "", false }
func (inertSession) RPC() session.RPCPeer               { return nil }
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
