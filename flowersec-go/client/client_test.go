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
	if _, err := c.OpenStream(ctx, " \t "); err == nil {
		t.Fatal("OpenStream with a blank kind should fail")
	} else {
		var flowersecErr *Error
		if !errors.As(err, &flowersecErr) || flowersecErr.Stage != StageRPC || flowersecErr.Code != CodeMissingStreamKind {
			t.Fatalf("empty stream kind error = %v", err)
		}
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

func TestClientOpenStream_ContextDeadlineCancelsBlockedOpen(t *testing.T) {
	local, remote := net.Pipe()
	mux, err := fsyamux.NewClient(local, fsyamux.YamuxLimits{MaxActiveStreams: 2, MaxInboundStreams: 1}, fsyamux.LivenessOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()
	defer remote.Close()
	first, err := mux.OpenStream()
	if err != nil {
		t.Fatalf("first OpenStream() failed: %v", err)
	}
	defer first.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		_, err := (&session{path: PathDirect, mux: mux}).OpenStream(ctx, "echo")
		errCh <- err
	}()

	select {
	case err := <-errCh:
		var fe *Error
		if !errors.As(err, &fe) {
			t.Fatalf("expected *client.Error, got %T", err)
		}
		if fe.Path != PathDirect || fe.Stage != StageYamux || fe.Code != CodeTimeout {
			t.Fatalf("unexpected error: %+v", fe)
		}
	case <-time.After(time.Second):
		_ = mux.Close()
		t.Fatal("OpenStream did not stop after context deadline")
	}
}

func TestClientOpenStreamPreservesSecureOutboundExhaustion(t *testing.T) {
	transport := newPendingBinaryTransport()
	secure := e2ee.NewSecureChannel(transport, e2ee.RecordKeyState{}, 1<<20, 0)
	if err := secure.SetMaxOutboundBufferedBytes(8); err != nil {
		t.Fatal(err)
	}
	mux, err := fsyamux.NewClient(secure, fsyamux.YamuxLimits{}, fsyamux.LivenessOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()
	defer secure.Close()

	client := &session{path: PathDirect, mux: mux, secure: secure}
	_, firstErr := client.OpenStream(context.Background(), "rpc")
	if firstErr != nil {
		assertResourceExhausted(t, firstErr)
		return
	}
	select {
	case <-mux.CloseChan():
	case <-time.After(time.Second):
		t.Fatal("secure outbound exhaustion did not close the Yamux session")
	}
	_, err = client.OpenStream(context.Background(), "rpc")
	assertResourceExhausted(t, err)
}

func assertResourceExhausted(t *testing.T, err error) {
	t.Helper()
	var flowersecErr *Error
	if !errors.As(err, &flowersecErr) {
		t.Fatalf("expected *client.Error, got %T: %v", err, err)
	}
	if flowersecErr.Stage != StageYamux && flowersecErr.Stage != StageRPC {
		t.Fatalf("resource error stage = %q", flowersecErr.Stage)
	}
	if flowersecErr.Code != CodeResourceExhausted {
		t.Fatalf("resource error code = %q", flowersecErr.Code)
	}
	if !errors.Is(err, e2ee.ErrOutboundBufferExceeded) {
		t.Fatalf("resource error lost secure-channel cause: %v", err)
	}
}

type pendingBinaryTransport struct {
	closed chan struct{}
}

func newPendingBinaryTransport() *pendingBinaryTransport {
	return &pendingBinaryTransport{closed: make(chan struct{})}
}

func (t *pendingBinaryTransport) ReadBinary(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-t.closed:
		return nil, net.ErrClosed
	}
}

func (*pendingBinaryTransport) WriteBinary(context.Context, []byte) error { return nil }

func (t *pendingBinaryTransport) Close() error {
	select {
	case <-t.closed:
	default:
		close(t.closed)
	}
	return nil
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

func TestClassifyContextOrCodeMapsLivenessTimeout(t *testing.T) {
	if got := classifyContextOrCode(fsyamux.ErrLivenessTimeout, CodePingFailed); got != CodeTimeout {
		t.Fatalf("liveness timeout code = %q", got)
	}
}
