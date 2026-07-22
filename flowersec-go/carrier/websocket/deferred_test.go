package websocket

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/artifactv2"
	"github.com/floegence/flowersec/flowersec-go/carrier"
	gorillaws "github.com/gorilla/websocket"
)

func TestDeferredTunnelServerRejectsExtraMessageBeforeSuccess(t *testing.T) {
	client, server := newUpgradedPair(t, SubprotocolTunnel)
	deferred, err := NewDeferredTunnelServer(server, DefaultResourcePolicy(), LivenessPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.WriteMessage(gorillaws.BinaryMessage, validWebSocketFSB2(t, artifactv2.PathTunnel)); err != nil {
		t.Fatal(err)
	}
	if _, err := deferred.ReceiveAdmission(context.Background()); err != nil {
		t.Fatalf("ReceiveAdmission: %v", err)
	}
	waitDone := make(chan error, 1)
	go func() { waitDone <- deferred.WaitWhilePending(context.Background()) }()
	_ = client.WriteMessage(gorillaws.BinaryMessage, []byte("early-yamux"))
	select {
	case err := <-waitDone:
		if !errors.Is(err, ErrUnexpectedWaitingMessage) {
			t.Fatalf("WaitWhilePending error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("extra message did not terminate waiting admission")
	}
	if _, err := deferred.Activate(context.Background()); !errors.Is(err, ErrDeferredAdmissionState) {
		t.Fatalf("Activate after violation error = %v", err)
	}
}

func TestDeferredTunnelServerRespondingStillRejectsEarlyMessage(t *testing.T) {
	client, server := newUpgradedPair(t, SubprotocolTunnel)
	deferred, err := NewDeferredTunnelServer(server, DefaultResourcePolicy(), LivenessPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.WriteMessage(gorillaws.BinaryMessage, validWebSocketFSB2(t, artifactv2.PathTunnel)); err != nil {
		t.Fatal(err)
	}
	if _, err := deferred.ReceiveAdmission(context.Background()); err != nil {
		t.Fatal(err)
	}
	<-deferred.writer.permit
	sendDone := make(chan error, 1)
	go func() {
		sendDone <- deferred.SendAdmission(context.Background(), artifactv2.AdmissionResponse{Status: artifactv2.AdmissionSuccess}, nil)
	}()
	waitForDeferredState(t, deferred, deferredResponding)
	waitDone := make(chan error, 1)
	go func() { waitDone <- deferred.WaitWhilePending(context.Background()) }()
	_ = client.WriteMessage(gorillaws.BinaryMessage, []byte("before-fsa2-complete"))
	select {
	case err := <-waitDone:
		if !errors.Is(err, ErrUnexpectedWaitingMessage) {
			t.Fatalf("WaitWhilePending error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("RESPONDING accepted early Yamux bytes")
	}
	deferred.writer.permit <- struct{}{}
	if err := <-sendDone; err == nil {
		t.Fatal("SUCCESS write completed after RESPONDING protocol violation")
	}
	if deferred.activationCount.Load() != 0 {
		t.Fatal("RESPONDING violation constructed Yamux")
	}
}

func TestDeferredTunnelServerRejectsControlFrameBeforeSuccess(t *testing.T) {
	client, server := newUpgradedPair(t, SubprotocolTunnel)
	deferred, err := NewDeferredTunnelServer(server, DefaultResourcePolicy(), LivenessPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.WriteMessage(gorillaws.BinaryMessage, validWebSocketFSB2(t, artifactv2.PathTunnel)); err != nil {
		t.Fatal(err)
	}
	if _, err := deferred.ReceiveAdmission(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitDone := make(chan error, 1)
	go func() { waitDone <- deferred.WaitWhilePending(context.Background()) }()
	_ = client.WriteControl(gorillaws.PingMessage, []byte("early-ping"), time.Now().Add(time.Second))
	select {
	case err := <-waitDone:
		if !errors.Is(err, ErrUnexpectedWaitingMessage) {
			t.Fatalf("WaitWhilePending error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("control frame did not terminate waiting admission")
	}
}

func TestDeferredTunnelServerRejectsNonBinaryAdmission(t *testing.T) {
	client, server := newUpgradedPair(t, SubprotocolTunnel)
	deferred, err := NewDeferredTunnelServer(server, DefaultResourcePolicy(), LivenessPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.WriteMessage(gorillaws.TextMessage, []byte("FSB2")); err != nil {
		t.Fatal(err)
	}
	if _, err := deferred.ReceiveAdmission(context.Background()); !errors.Is(err, ErrInvalidAdmissionMessage) {
		t.Fatalf("ReceiveAdmission error = %v", err)
	}
	assertWebSocketPeerClosed(t, client)
}

func TestDeferredTunnelServerRejectDoesNotStartYamux(t *testing.T) {
	client, server := newUpgradedPair(t, SubprotocolTunnel)
	deferred, err := NewDeferredTunnelServer(server, DefaultResourcePolicy(), LivenessPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.WriteMessage(gorillaws.BinaryMessage, validWebSocketFSB2(t, artifactv2.PathTunnel)); err != nil {
		t.Fatal(err)
	}
	if _, err := deferred.ReceiveAdmission(context.Background()); err != nil {
		t.Fatal(err)
	}
	reasons := artifactv2.ReasonRegistry{"capacity": {}}
	responseDone := make(chan artifactv2.AdmissionResponse, 1)
	clientErr := make(chan error, 1)
	go func() {
		messageType, raw, readErr := client.ReadMessage()
		if readErr != nil {
			clientErr <- readErr
			return
		}
		if messageType != gorillaws.BinaryMessage {
			clientErr <- ErrNonBinaryMessage
			return
		}
		response, parseErr := artifactv2.ParseResponse(raw, reasons)
		if parseErr != nil {
			clientErr <- parseErr
			return
		}
		responseDone <- response
	}()
	if err := deferred.SendAdmission(context.Background(), artifactv2.AdmissionResponse{
		Status: artifactv2.AdmissionRetryable, Reason: "capacity",
	}, reasons); err != nil {
		t.Fatalf("SendAdmission: %v", err)
	}
	select {
	case response := <-responseDone:
		if response.Status != artifactv2.AdmissionRetryable || response.Reason != "capacity" {
			t.Fatalf("response = %+v", response)
		}
	case err := <-clientErr:
		t.Fatal(err)
	case <-time.After(time.Second):
		t.Fatal("client did not receive rejection")
	}
	if deferred.activationCount.Load() != 0 {
		t.Fatal("rejection constructed Yamux")
	}
	if _, err := deferred.Activate(context.Background()); !errors.Is(err, ErrDeferredAdmissionState) {
		t.Fatalf("Activate after reject error = %v", err)
	}
	_ = deferred.CloseWithError(carrier.ApplicationError{Reason: "rejected"})
}

func TestDeferredTunnelServerActivatesYamuxOnlyAfterSuccess(t *testing.T) {
	clientConn, serverConn := newUpgradedPair(t, SubprotocolTunnel)
	resources := DefaultResourcePolicy()
	deferred, err := NewDeferredTunnelServer(serverConn, resources, LivenessPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	rawFSB2 := validWebSocketFSB2(t, artifactv2.PathTunnel)
	clientAdmission := make(chan error, 1)
	go func() {
		_, commitErr := CommitAdmission(context.Background(), clientConn, rawFSB2, nil)
		clientAdmission <- commitErr
	}()
	if _, err := deferred.ReceiveAdmission(context.Background()); err != nil {
		t.Fatal(err)
	}
	if deferred.activationCount.Load() != 0 {
		t.Fatal("Yamux activated before SUCCESS")
	}
	if err := deferred.SendAdmission(context.Background(), artifactv2.AdmissionResponse{Status: artifactv2.AdmissionSuccess}, nil); err != nil {
		t.Fatal(err)
	}
	if err := <-clientAdmission; err != nil {
		t.Fatal(err)
	}

	serverSession, err := deferred.Activate(context.Background())
	if err != nil {
		t.Fatalf("server Activate: %v", err)
	}
	clientSession, err := NewAfterAdmission(clientConn, ClientRole, SubprotocolTunnel, resources, LivenessPolicy{})
	if err != nil {
		t.Fatalf("client NewAfterAdmission: %v", err)
	}
	t.Cleanup(func() { _ = clientSession.Close() })
	t.Cleanup(func() { _ = serverSession.Close() })
	if deferred.activationCount.Load() != 1 {
		t.Fatalf("activation count = %d", deferred.activationCount.Load())
	}
	assertCarrierRoundTrip(t, clientSession, serverSession)
}

func TestDeferredCloseUsesCallerCleanupDeadline(t *testing.T) {
	clientConn, serverConn := newUpgradedPair(t, SubprotocolTunnel)
	t.Cleanup(func() { _ = clientConn.Close() })
	deferred, err := NewDeferredTunnelServer(serverConn, DefaultResourcePolicy(), LivenessPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	<-deferred.writer.permit
	defer func() { deferred.writer.permit <- struct{}{} }()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	started := time.Now()
	err = deferred.CloseWithErrorContext(ctx, carrier.ApplicationError{Reason: "deadline"})
	if elapsed := time.Since(started); elapsed > 250*time.Millisecond {
		t.Fatalf("deferred close took %v, want caller cleanup deadline", elapsed)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deferred close error = %v, want deadline exceeded", err)
	}
}

func TestDeferredTunnelServerActiveCloseWritesReasonBeforeClosingPipes(t *testing.T) {
	clientConn, serverConn := newUpgradedPair(t, SubprotocolTunnel)
	resources := DefaultResourcePolicy()
	deferred, err := NewDeferredTunnelServer(serverConn, resources, LivenessPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	clientAdmission := make(chan error, 1)
	go func() {
		_, commitErr := CommitAdmission(context.Background(), clientConn, validWebSocketFSB2(t, artifactv2.PathTunnel), nil)
		clientAdmission <- commitErr
	}()
	if _, err := deferred.ReceiveAdmission(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := deferred.SendAdmission(context.Background(), artifactv2.AdmissionResponse{Status: artifactv2.AdmissionSuccess}, nil); err != nil {
		t.Fatal(err)
	}
	if err := <-clientAdmission; err != nil {
		t.Fatal(err)
	}
	serverSession, err := deferred.Activate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	clientSession, err := NewAfterAdmission(clientConn, ClientRole, SubprotocolTunnel, resources, LivenessPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	events := make(chan string, 3)
	originalControl := serverSession.closeControl
	serverSession.closeControl = func(ctx context.Context, applicationError carrier.ApplicationError) error {
		if applicationError.Reason != "replacement" {
			t.Errorf("close reason = %q", applicationError.Reason)
		}
		events <- "control"
		return originalControl(ctx, applicationError)
	}
	originalBeforeClose := serverSession.beforeMuxClose
	serverSession.beforeMuxClose = func() error {
		events <- "pipes"
		return originalBeforeClose()
	}
	_ = deferred.CloseWithError(carrier.ApplicationError{Reason: "replacement"})
	_ = deferred.CloseWithError(carrier.ApplicationError{Reason: "ignored"})
	if first, second := <-events, <-events; first != "control" || second != "pipes" {
		t.Fatalf("close order = %q then %q", first, second)
	}
	select {
	case event := <-events:
		t.Fatalf("non-idempotent close event = %q", event)
	case <-time.After(20 * time.Millisecond):
	}
	_ = clientSession.Close()
	_ = serverSession.Close()
}

func TestDeferredTunnelServerValidatesTLSAndExactSubprotocol(t *testing.T) {
	_, directServer := newUpgradedPair(t, SubprotocolDirect)
	if _, err := NewDeferredTunnelServer(directServer, DefaultResourcePolicy(), LivenessPolicy{}); !errors.Is(err, ErrInvalidSubprotocol) {
		t.Fatalf("direct subprotocol error = %v", err)
	}
	_, plainServer := newPlainUpgradedPair(t)
	if _, err := NewDeferredTunnelServer(plainServer, DefaultResourcePolicy(), LivenessPolicy{}); !errors.Is(err, ErrTLS13Required) {
		t.Fatalf("plain WebSocket error = %v", err)
	}
}

func TestDeferredTunnelServerReceiveCancellationClosesConnection(t *testing.T) {
	client, server := newUpgradedPair(t, SubprotocolTunnel)
	deferred, err := NewDeferredTunnelServer(server, DefaultResourcePolicy(), LivenessPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, err := deferred.ReceiveAdmission(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ReceiveAdmission error = %v", err)
	}
	assertWebSocketPeerClosed(t, client)
}

func TestDeferredTunnelServerSendCancellationClosesConnection(t *testing.T) {
	client, server := newUpgradedPair(t, SubprotocolTunnel)
	deferred, err := NewDeferredTunnelServer(server, DefaultResourcePolicy(), LivenessPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.WriteMessage(gorillaws.BinaryMessage, validWebSocketFSB2(t, artifactv2.PathTunnel)); err != nil {
		t.Fatal(err)
	}
	if _, err := deferred.ReceiveAdmission(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := deferred.SendAdmission(ctx, artifactv2.AdmissionResponse{Status: artifactv2.AdmissionSuccess}, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("SendAdmission error = %v", err)
	}
	assertWebSocketPeerClosed(t, client)
}

func assertCarrierRoundTrip(t *testing.T, client, server carrier.Session) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	accepted := make(chan carrier.Stream, 1)
	go func() {
		stream, _ := server.AcceptStream(ctx)
		accepted <- stream
	}()
	clientStream, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := clientStream.Write([]byte("deferred-yamux")); err != nil {
		t.Fatal(err)
	}
	if err := clientStream.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	serverStream := <-accepted
	payload, err := io.ReadAll(serverStream)
	if err != nil {
		t.Fatal(err)
	}
	if string(payload) != "deferred-yamux" {
		t.Fatalf("payload = %q", payload)
	}
	_ = clientStream.Reset()
	_ = serverStream.Reset()
}

func newPlainUpgradedPair(t *testing.T) (*gorillaws.Conn, *gorillaws.Conn) {
	t.Helper()
	serverConn := make(chan *gorillaws.Conn, 1)
	upgrader := gorillaws.Upgrader{Subprotocols: []string{SubprotocolTunnel}}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		conn, err := upgrader.Upgrade(writer, request, nil)
		if err == nil {
			serverConn <- conn
		}
	}))
	t.Cleanup(server.Close)
	dialer := gorillaws.Dialer{Subprotocols: []string{SubprotocolTunnel}}
	client, _, err := dialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	return client, <-serverConn
}

func waitForDeferredState(t *testing.T, server *DeferredTunnelServer, expected deferredState) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		server.stateMu.Lock()
		state := server.state
		server.stateMu.Unlock()
		if state == expected {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("deferred state did not reach %d", expected)
}
