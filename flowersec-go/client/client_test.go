package client

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/crypto/e2ee"
	fsyamux "github.com/floegence/flowersec/flowersec-go/mux/yamux"
	"github.com/floegence/flowersec/flowersec-go/observability"
	"github.com/floegence/flowersec/flowersec-go/rpc"
	"github.com/floegence/flowersec/flowersec-go/streamhello"
)

func newYamuxPair(t *testing.T) (client *fsyamux.Session, server *fsyamux.Session, closeFn func()) {
	t.Helper()
	a, b := net.Pipe()
	srv, err := fsyamux.NewServer(a, fsyamux.YamuxLimits{}, fsyamux.LivenessOptions{})
	if err != nil {
		_ = a.Close()
		_ = b.Close()
		t.Fatalf("yamux server: %v", err)
	}
	cli, err := fsyamux.NewClient(b, fsyamux.YamuxLimits{}, fsyamux.LivenessOptions{})
	if err != nil {
		_ = srv.Close()
		_ = a.Close()
		_ = b.Close()
		t.Fatalf("yamux client: %v", err)
	}
	return cli, srv, func() {
		_ = cli.Close()
		_ = srv.Close()
		_ = a.Close()
		_ = b.Close()
	}
}

func TestClientCloseNil(t *testing.T) {
	var c *session
	if err := c.Close(); err != nil {
		t.Fatalf("Close() on nil client should be nil, got %v", err)
	}
}

func TestWatchLivenessEmitsStableDiagnostic(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	mux, err := fsyamux.NewClient(a, fsyamux.YamuxLimits{}, fsyamux.LivenessOptions{
		Interval: 10 * time.Millisecond,
		Timeout:  20 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	recorder := &transportDiagnosticObserver{events: make(chan observability.DiagnosticEvent, 1)}
	observer := observability.NormalizeClientObserver(recorder, observability.ClientObserverContext{Path: PathTunnel})
	client := &session{path: PathTunnel, mux: mux, observer: observer}
	go client.watchLiveness()
	select {
	case event := <-recorder.events:
		if event.Stage != observability.DiagnosticStageYamux || event.Code != "liveness_timeout" || event.Result != observability.DiagnosticResultFail {
			t.Fatalf("unexpected diagnostic: %+v", event)
		}
	case <-time.After(time.Second):
		t.Fatal("missing liveness_timeout diagnostic")
	}
}

func TestSessionGetters(t *testing.T) {
	c := &session{
		path:               PathTunnel,
		endpointInstanceID: "endpoint-1",
		secure:             &e2ee.SecureChannel{},
		mux:                &fsyamux.Session{},
		rpc:                &rpc.Client{},
	}
	if got := c.Path(); got != PathTunnel {
		t.Fatalf("Path() = %q, want %q", got, PathTunnel)
	}
	if got := c.EndpointInstanceID(); got != "endpoint-1" {
		t.Fatalf("EndpointInstanceID() = %q", got)
	}
	if c.Secure() == nil || c.Mux() == nil || c.RPC() == nil {
		t.Fatal("expected non-nil underlying handles")
	}

	var nilClient *session
	if nilClient.Path() != "" || nilClient.EndpointInstanceID() != "" || nilClient.Secure() != nil || nilClient.Mux() != nil || nilClient.RPC() != nil {
		t.Fatal("nil session getters should return zero values")
	}
}

func TestClientOpenStreamValidation(t *testing.T) {
	c := &session{}
	ctx := context.Background()
	if _, err := c.OpenStream(ctx, ""); err == nil {
		t.Fatal("OpenStream(\"\") should fail")
	}
	if _, err := c.OpenStream(ctx, "echo"); err == nil {
		t.Fatal("OpenStream(\"echo\") should fail when not connected")
	}
}

func TestClientOpenStreamWritesHello(t *testing.T) {
	cli, srv, closeFn := newYamuxPair(t)
	defer closeFn()

	c := &session{path: PathDirect, mux: cli}
	st, err := c.OpenStream(context.Background(), "echo")
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	defer st.Close()

	in, err := srv.AcceptStream()
	if err != nil {
		t.Fatalf("server AcceptStream: %v", err)
	}
	defer in.Close()

	h, err := streamhello.ReadStreamHello(in, 8*1024)
	if err != nil {
		t.Fatalf("ReadStreamHello: %v", err)
	}
	if h.Kind != "echo" {
		t.Fatalf("kind mismatch: got %q", h.Kind)
	}
}

func TestClientOpenStream_ContextCanceled_ReturnsCanceled(t *testing.T) {
	cli, _, closeFn := newYamuxPair(t)
	defer closeFn()

	c := &session{path: PathDirect, mux: cli}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := c.OpenStream(ctx, "echo")
	if err == nil {
		t.Fatal("expected error")
	}
	var fe *Error
	if !errors.As(err, &fe) {
		t.Fatalf("expected *client.Error, got %T", err)
	}
	if fe.Path != PathDirect || fe.Stage != StageYamux || fe.Code != CodeCanceled {
		t.Fatalf("unexpected error: %+v", fe)
	}
}

func TestSessionPingNilAndNotConnected(t *testing.T) {
	var nilClient *session
	if err := nilClient.Ping(); err == nil {
		t.Fatal("expected error")
	}
	c := &session{path: PathTunnel}
	if err := c.Ping(); err == nil {
		t.Fatal("expected error")
	}
}

func TestClassifyConnectObserverReason(t *testing.T) {
	if got := classifyConnectObserverReason(context.DeadlineExceeded); got != observability.ConnectReasonTimeout {
		t.Fatalf("timeout reason = %q", got)
	}
	if got := classifyConnectObserverReason(context.Canceled); got != observability.ConnectReasonCanceled {
		t.Fatalf("canceled reason = %q", got)
	}
	if got := classifyConnectObserverReason(errors.New("boom")); got != observability.ConnectReasonWebsocketError {
		t.Fatalf("default reason = %q", got)
	}
}
