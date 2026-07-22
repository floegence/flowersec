package websocket

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/carrier"
	gorillaws "github.com/gorilla/websocket"
)

func TestAfterAdmissionUsesHopYamuxBehindCarrierContract(t *testing.T) {
	client, server := newCarrierPair(t, SubprotocolDirect)
	if client.Kind() != carrier.KindWebSocket || server.Kind() != carrier.KindWebSocket {
		t.Fatalf("carrier kind = %q/%q", client.Kind(), server.Kind())
	}
	if client.Path() != carrier.PathDirect || server.Path() != carrier.PathDirect {
		t.Fatalf("carrier path = %q/%q, want direct", client.Path(), server.Path())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	accepted := make(chan carrier.Stream, 1)
	go func() {
		stream, _ := server.AcceptStream(ctx)
		accepted <- stream
	}()
	clientStream, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	if _, err := clientStream.Write([]byte("websocket-yamux")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := clientStream.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	if err := clientStream.Context().Err(); err != nil {
		t.Fatalf("CloseWrite canceled the readable stream context: %v", err)
	}
	serverStream := <-accepted
	payload, err := io.ReadAll(serverStream)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(payload) != "websocket-yamux" {
		t.Fatalf("payload = %q", payload)
	}
	if _, err := serverStream.Write([]byte("response")); err != nil {
		t.Fatalf("response Write: %v", err)
	}
	if err := serverStream.CloseWrite(); err != nil {
		t.Fatalf("response CloseWrite: %v", err)
	}
	response, err := io.ReadAll(clientStream)
	if err != nil {
		t.Fatalf("response ReadAll: %v", err)
	}
	if string(response) != "response" {
		t.Fatalf("response = %q", response)
	}
	if err := clientStream.Context().Err(); err == nil {
		t.Fatal("stream context remained active after both directions finished")
	}
}

func TestSessionPathMatchesExactSubprotocol(t *testing.T) {
	client, server := newCarrierPair(t, SubprotocolTunnel)
	if client.Path() != carrier.PathTunnel || server.Path() != carrier.PathTunnel {
		t.Fatalf("carrier path = %q/%q, want tunnel", client.Path(), server.Path())
	}
}

func TestBindSessionResourcePolicyUsesExactPhysicalCapacity(t *testing.T) {
	policy, err := BindSessionResourcePolicy(DefaultResourcePolicy(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if policy.InboundBidirectionalStreams != 3 || policy.MaxConcurrentStreams < 3 {
		t.Fatalf("bound policy = %+v", policy)
	}
}

func TestCloseWithErrorContextAcceptsNilContext(t *testing.T) {
	client, _ := newCarrierPair(t, SubprotocolDirect)
	_ = client.CloseWithErrorContext(nil, carrier.ApplicationError{Reason: "test close"})
}

func TestCanceledAcceptDoesNotCloseSessionOrDropNextStream(t *testing.T) {
	client, server := newCarrierPair(t, SubprotocolTunnel)
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := server.AcceptStream(canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("AcceptStream canceled error = %v", err)
	}

	ctx, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	opened, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatalf("OpenStream after canceled accept: %v", err)
	}
	defer opened.Close()
	accepted, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("AcceptStream after canceled accept: %v", err)
	}
	defer accepted.Close()
}

func TestYamuxResetIsIsolatedFromSiblingStream(t *testing.T) {
	client, server := newCarrierPair(t, SubprotocolDirect)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	first, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatalf("open first stream: %v", err)
	}
	second, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatalf("open second stream: %v", err)
	}
	if _, err := first.Write([]byte("reset-me")); err != nil {
		t.Fatalf("write first: %v", err)
	}
	if _, err := second.Write([]byte("survivor")); err != nil {
		t.Fatalf("write second: %v", err)
	}
	serverFirst, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("accept first: %v", err)
	}
	serverSecond, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("accept second: %v", err)
	}
	if err := first.Reset(); err != nil {
		t.Fatalf("reset first: %v", err)
	}
	buffer := make([]byte, 32)
	for {
		_, err := serverFirst.Read(buffer)
		if err != nil {
			if errors.Is(err, io.EOF) {
				t.Fatalf("reset stream ended with clean EOF: %v", err)
			}
			break
		}
	}
	if err := second.CloseWrite(); err != nil {
		t.Fatalf("close second: %v", err)
	}
	payload, err := io.ReadAll(serverSecond)
	if err != nil {
		t.Fatalf("read second: %v", err)
	}
	if string(payload) != "survivor" {
		t.Fatalf("surviving payload = %q", payload)
	}
}

func TestExactSubprotocolAndTLS13AreRequired(t *testing.T) {
	_, server := newUpgradedPair(t, SubprotocolDirect)
	resources := DefaultResourcePolicy()
	if _, err := NewAfterAdmission(server, ServerRole, SubprotocolTunnel, resources, LivenessPolicy{}); !errors.Is(err, ErrInvalidSubprotocol) {
		t.Fatalf("NewAfterAdmission subprotocol error = %v", err)
	}
}

func TestBinaryByteConnCoalescesMessagesAndRejectsText(t *testing.T) {
	client, server := newUpgradedPair(t, SubprotocolDirect)
	t.Cleanup(func() { _ = client.Close() })
	t.Cleanup(func() { _ = server.Close() })

	wroteBinary := make(chan struct{})
	go func() {
		defer close(wroteBinary)
		_ = client.WriteMessage(gorillaws.BinaryMessage, []byte("abc"))
		_ = client.WriteMessage(gorillaws.BinaryMessage, []byte("def"))
	}()
	conn := newBinaryByteConn(server, 64)
	payload := make([]byte, 6)
	if _, err := io.ReadFull(conn, payload); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if string(payload) != "abcdef" {
		t.Fatalf("coalesced payload = %q", payload)
	}
	<-wroteBinary

	go func() { _ = client.WriteMessage(gorillaws.TextMessage, []byte("forbidden")) }()
	if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, ErrNonBinaryMessage) {
		t.Fatalf("text message error = %v", err)
	}
}

func newCarrierPair(t *testing.T, subprotocol string) (*Session, *Session) {
	t.Helper()
	clientConn, serverConn := newUpgradedPair(t, subprotocol)
	resources := DefaultResourcePolicy()
	serverCh := make(chan *Session, 1)
	errCh := make(chan error, 1)
	go func() {
		session, err := NewAfterAdmission(serverConn, ServerRole, subprotocol, resources, LivenessPolicy{})
		if err != nil {
			errCh <- err
			return
		}
		serverCh <- session
	}()
	client, err := NewAfterAdmission(clientConn, ClientRole, subprotocol, resources, LivenessPolicy{})
	if err != nil {
		t.Fatalf("client NewAfterAdmission: %v", err)
	}
	var server *Session
	select {
	case server = <-serverCh:
	case err := <-errCh:
		t.Fatalf("server NewAfterAdmission: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("server session timed out")
	}
	t.Cleanup(func() { _ = client.Close() })
	t.Cleanup(func() { _ = server.Close() })
	return client, server
}

func newUpgradedPair(t *testing.T, subprotocol string) (*gorillaws.Conn, *gorillaws.Conn) {
	t.Helper()
	serverConn := make(chan *gorillaws.Conn, 1)
	upgrader := gorillaws.Upgrader{Subprotocols: []string{subprotocol}}
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		conn, err := upgrader.Upgrade(writer, request, nil)
		if err != nil {
			return
		}
		serverConn <- conn
	}))
	t.Cleanup(server.Close)
	dialer := gorillaws.Dialer{
		Subprotocols:    []string{subprotocol},
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true}, // test server only
	}
	url := "wss" + strings.TrimPrefix(server.URL, "https")
	client, _, err := dialer.Dial(url, nil)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	select {
	case accepted := <-serverConn:
		return client, accepted
	case <-time.After(5 * time.Second):
		t.Fatal("upgrade timed out")
		return nil, nil
	}
}
