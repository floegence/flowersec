package tunnelv2_test

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/carrier"
	"github.com/floegence/flowersec/flowersec-go/v2/tunnelv2"
)

func TestBrokerBridgesControlAndBidirectionalStreamsAcrossMixedCarriers(t *testing.T) {
	kinds := []struct {
		name   string
		client carrier.Kind
		server carrier.Kind
	}{
		{name: "WW", client: carrier.KindWebSocket, server: carrier.KindWebSocket},
		{name: "QQ", client: carrier.KindQUIC, server: carrier.KindQUIC},
		{name: "WQ", client: carrier.KindWebSocket, server: carrier.KindQUIC},
		{name: "QW", client: carrier.KindQUIC, server: carrier.KindWebSocket},
	}
	for _, topology := range kinds {
		t.Run(topology.name, func(t *testing.T) {
			clientEndpoint, clientTunnel := memorySessionPair(topology.client)
			serverEndpoint, serverTunnel := memorySessionPair(topology.server)
			ctx, cancel := context.WithCancel(context.Background())
			bridgeDone := make(chan error, 1)
			go func() {
				bridgeDone <- tunnelv2.Bridge(ctx, clientTunnel, serverTunnel, tunnelv2.Limits{
					MaxConcurrentStreams: 8,
					CopyBufferBytes:      1024,
				})
			}()

			controlClient := openStream(t, clientEndpoint)
			controlServer := acceptStream(t, serverEndpoint)
			assertOpenStreamRoundTrip(t, controlClient, controlServer, "FSC2", "FSH2")

			clientOpened := openStream(t, clientEndpoint)
			serverAccepted := acceptStream(t, serverEndpoint)
			assertHalfCloseRoundTrip(t, clientOpened, serverAccepted, "client-data", "server-response")

			serverOpened := openStream(t, serverEndpoint)
			clientAccepted := acceptStream(t, clientEndpoint)
			assertHalfCloseRoundTrip(t, serverOpened, clientAccepted, "server-data", "client-response")

			cancel()
			select {
			case err := <-bridgeDone:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("Bridge error = %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("Bridge did not stop after cancellation")
			}
		})
	}
}

func TestBrokerResetIsIsolatedFromSiblingStream(t *testing.T) {
	clientEndpoint, clientTunnel := memorySessionPair(carrier.KindWebSocket)
	serverEndpoint, serverTunnel := memorySessionPair(carrier.KindQUIC)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = tunnelv2.Bridge(ctx, clientTunnel, serverTunnel, tunnelv2.DefaultLimits()) }()

	controlClient := openStream(t, clientEndpoint)
	controlServer := acceptStream(t, serverEndpoint)
	assertOpenStreamRoundTrip(t, controlClient, controlServer, "FSC2", "FSH2")

	resetClient := openStream(t, clientEndpoint)
	resetServer := acceptStream(t, serverEndpoint)
	survivorClient := openStream(t, clientEndpoint)
	survivorServer := acceptStream(t, serverEndpoint)
	if err := resetClient.Reset(); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 1)
	if _, err := resetServer.Read(buffer); !errors.Is(err, carrier.ErrStreamReset) {
		t.Fatalf("mirrored reset error = %v", err)
	}
	assertHalfCloseRoundTrip(t, survivorClient, survivorServer, "survivor", "still-alive")
}

func TestBrokerTargetOpenFailureIsIsolatedFromSiblingStream(t *testing.T) {
	clientEndpoint, clientTunnel := memorySessionPair(carrier.KindWebSocket)
	serverEndpoint, serverTunnel := memorySessionPair(carrier.KindQUIC)
	failingTarget := &failOpenSession{Session: serverTunnel, failOnCall: 2}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = tunnelv2.Bridge(ctx, clientTunnel, failingTarget, tunnelv2.DefaultLimits()) }()

	controlClient := openStream(t, clientEndpoint)
	controlServer := acceptStream(t, serverEndpoint)
	assertOpenStreamRoundTrip(t, controlClient, controlServer, "FSC2", "FSH2")

	failed := openStream(t, clientEndpoint)
	if _, err := failed.Write([]byte("fail-this-stream")); err == nil {
		buffer := make([]byte, 1)
		if _, err := failed.Read(buffer); !errors.Is(err, carrier.ErrStreamReset) {
			t.Fatalf("failed stream error = %v, want reset", err)
		}
	} else if !errors.Is(err, carrier.ErrStreamReset) {
		t.Fatalf("failed stream write error = %v, want reset", err)
	}

	survivorClient := openStream(t, clientEndpoint)
	survivorServer := acceptStream(t, serverEndpoint)
	assertHalfCloseRoundTrip(t, survivorClient, survivorServer, "survivor", "still-alive")
}

func TestBrokerStopsWhenEitherControlDirectionCloses(t *testing.T) {
	clientEndpoint, clientTunnel := memorySessionPair(carrier.KindWebSocket)
	_, serverTunnel := memorySessionPair(carrier.KindQUIC)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bridgeDone := make(chan error, 1)
	go func() { bridgeDone <- tunnelv2.Bridge(ctx, clientTunnel, serverTunnel, tunnelv2.DefaultLimits()) }()
	control := openStream(t, clientEndpoint)
	if err := control.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-bridgeDone:
		if !errors.Is(err, tunnelv2.ErrControlClosed) {
			t.Fatalf("Bridge control EOF error = %v", err)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Bridge waited for the other control direction after EOF")
	}
}

func TestBrokerCleanupDeadlineOwnsCarrierCloseAndLeavesNoCloseTask(t *testing.T) {
	clientEndpoint, clientTunnel := memorySessionPair(carrier.KindWebSocket)
	serverEndpoint, serverTunnel := memorySessionPair(carrier.KindQUIC)
	release := make(chan struct{})
	client := newDeadlineCloseSession(clientTunnel, release)
	server := newDeadlineCloseSession(serverTunnel, release)
	ctx, cancel := context.WithCancel(context.Background())
	bridgeDone := make(chan error, 1)
	go func() {
		bridgeDone <- tunnelv2.Bridge(ctx, client, server, tunnelv2.Limits{
			MaxConcurrentStreams: 8,
			CopyBufferBytes:      1024,
			CleanupTimeout:       20 * time.Millisecond,
		})
	}()
	_ = openStream(t, clientEndpoint)
	_ = acceptStream(t, serverEndpoint)
	cancel()
	waitForCloseEntry(t, client.entered)

	select {
	case err := <-bridgeDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Bridge error = %v, want canceled", err)
		}
	case <-time.After(250 * time.Millisecond):
		close(release)
		<-bridgeDone
		t.Fatal("Bridge cleanup ignored its configured deadline")
	}
	if active := client.active.Load() + server.active.Load(); active != 0 {
		close(release)
		t.Fatalf("Bridge left %d carrier close operation(s) active", active)
	}
	close(release)
}

func openStream(t *testing.T, session carrier.Session) carrier.Stream {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	stream, err := session.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return stream
}

func acceptStream(t *testing.T, session carrier.Session) carrier.Stream {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	stream, err := session.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return stream
}

func assertHalfCloseRoundTrip(t *testing.T, left, right carrier.Stream, request, response string) {
	t.Helper()
	if _, err := left.Write([]byte(request)); err != nil {
		t.Fatal(err)
	}
	if err := left.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	requestBytes, err := io.ReadAll(right)
	if err != nil {
		t.Fatal(err)
	}
	if string(requestBytes) != request {
		t.Fatalf("request = %q", requestBytes)
	}
	if _, err := right.Write([]byte(response)); err != nil {
		t.Fatal(err)
	}
	if err := right.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	responseBytes, err := io.ReadAll(left)
	if err != nil {
		t.Fatal(err)
	}
	if string(responseBytes) != response {
		t.Fatalf("response = %q", responseBytes)
	}
}

func assertOpenStreamRoundTrip(t *testing.T, left, right carrier.Stream, request, response string) {
	t.Helper()
	if _, err := left.Write([]byte(request)); err != nil {
		t.Fatal(err)
	}
	requestBytes := make([]byte, len(request))
	if _, err := io.ReadFull(right, requestBytes); err != nil {
		t.Fatal(err)
	}
	if string(requestBytes) != request {
		t.Fatalf("request = %q", requestBytes)
	}
	if _, err := right.Write([]byte(response)); err != nil {
		t.Fatal(err)
	}
	responseBytes := make([]byte, len(response))
	if _, err := io.ReadFull(left, responseBytes); err != nil {
		t.Fatal(err)
	}
	if string(responseBytes) != response {
		t.Fatalf("response = %q", responseBytes)
	}
}

type memorySession struct {
	kind      carrier.Kind
	path      carrier.Path
	peer      *memorySession
	ctx       context.Context
	cancel    context.CancelCauseFunc
	incoming  chan carrier.Stream
	closeOnce sync.Once
}

type failOpenSession struct {
	carrier.Session
	mu         sync.Mutex
	openCalls  int
	failOnCall int
}

type deadlineCloseSession struct {
	carrier.Session
	entered chan struct{}
	release <-chan struct{}
	active  atomic.Int32
	once    sync.Once
}

func newDeadlineCloseSession(session carrier.Session, release <-chan struct{}) *deadlineCloseSession {
	return &deadlineCloseSession{Session: session, entered: make(chan struct{}), release: release}
}

func (session *deadlineCloseSession) CloseWithError(applicationError carrier.ApplicationError) error {
	session.active.Add(1)
	defer session.active.Add(-1)
	session.once.Do(func() { close(session.entered) })
	<-session.release
	return session.Session.CloseWithError(applicationError)
}

func (session *deadlineCloseSession) CloseWithErrorContext(ctx context.Context, applicationError carrier.ApplicationError) error {
	session.active.Add(1)
	defer session.active.Add(-1)
	session.once.Do(func() { close(session.entered) })
	select {
	case <-session.release:
		return session.Session.CloseWithErrorContext(ctx, applicationError)
	case <-ctx.Done():
		return errors.Join(ctx.Err(), session.Session.CloseWithErrorContext(context.Background(), applicationError))
	}
}

func waitForCloseEntry(t *testing.T, entered <-chan struct{}) {
	t.Helper()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("carrier close did not start")
	}
}

func (session *failOpenSession) OpenStream(ctx context.Context) (carrier.Stream, error) {
	session.mu.Lock()
	session.openCalls++
	call := session.openCalls
	session.mu.Unlock()
	if call == session.failOnCall {
		return nil, errors.New("injected target open failure")
	}
	return session.Session.OpenStream(ctx)
}

func memorySessionPair(kind carrier.Kind) (*memorySession, *memorySession) {
	return memorySessionPairWithPath(kind, carrier.PathTunnel)
}

func memorySessionPairWithPath(kind carrier.Kind, path carrier.Path) (*memorySession, *memorySession) {
	leftCtx, leftCancel := context.WithCancelCause(context.Background())
	rightCtx, rightCancel := context.WithCancelCause(context.Background())
	left := &memorySession{kind: kind, path: path, ctx: leftCtx, cancel: leftCancel, incoming: make(chan carrier.Stream, 32)}
	right := &memorySession{kind: kind, path: path, ctx: rightCtx, cancel: rightCancel, incoming: make(chan carrier.Stream, 32)}
	left.peer = right
	right.peer = left
	return left, right
}

func (session *memorySession) Kind() carrier.Kind         { return session.kind }
func (session *memorySession) Path() carrier.Path         { return session.path }
func (session *memorySession) MaxIncomingStreams() uint16 { return 130 }
func (session *memorySession) OpenStream(ctx context.Context) (carrier.Stream, error) {
	left, right := memoryStreamPair()
	select {
	case session.peer.incoming <- right:
		return left, nil
	case <-ctx.Done():
		_ = left.Reset()
		_ = right.Reset()
		return nil, ctx.Err()
	case <-session.ctx.Done():
		_ = left.Reset()
		_ = right.Reset()
		return nil, context.Cause(session.ctx)
	}
}
func (session *memorySession) AcceptStream(ctx context.Context) (carrier.Stream, error) {
	select {
	case stream := <-session.incoming:
		return stream, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-session.ctx.Done():
		return nil, context.Cause(session.ctx)
	}
}
func (session *memorySession) CloseWithError(carrier.ApplicationError) error { return session.Close() }
func (session *memorySession) CloseWithErrorContext(context.Context, carrier.ApplicationError) error {
	return session.Close()
}
func (session *memorySession) Close() error {
	session.closeOnce.Do(func() { session.cancel(io.ErrClosedPipe) })
	return nil
}

type memoryStream struct {
	reader *io.PipeReader
	writer *io.PipeWriter
	ctx    context.Context
	cancel context.CancelCauseFunc
	once   sync.Once
}

func memoryStreamPair() (*memoryStream, *memoryStream) {
	abReader, abWriter := io.Pipe()
	baReader, baWriter := io.Pipe()
	leftCtx, leftCancel := context.WithCancelCause(context.Background())
	rightCtx, rightCancel := context.WithCancelCause(context.Background())
	return &memoryStream{reader: baReader, writer: abWriter, ctx: leftCtx, cancel: leftCancel},
		&memoryStream{reader: abReader, writer: baWriter, ctx: rightCtx, cancel: rightCancel}
}

func (stream *memoryStream) Read(payload []byte) (int, error)  { return stream.reader.Read(payload) }
func (stream *memoryStream) Write(payload []byte) (int, error) { return stream.writer.Write(payload) }
func (stream *memoryStream) Context() context.Context          { return stream.ctx }
func (stream *memoryStream) CloseWrite() error                 { return stream.writer.Close() }
func (stream *memoryStream) Reset() error                      { return stream.closeWithError(carrier.ErrStreamReset) }
func (stream *memoryStream) Close() error                      { return stream.Reset() }
func (stream *memoryStream) closeWithError(err error) error {
	stream.once.Do(func() {
		stream.cancel(err)
		_ = stream.reader.CloseWithError(err)
		_ = stream.writer.CloseWithError(err)
	})
	return nil
}

var _ carrier.Session = (*memorySession)(nil)
var _ carrier.Stream = (*memoryStream)(nil)
