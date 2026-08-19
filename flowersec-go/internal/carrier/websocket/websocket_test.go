package websocket

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v3/internal/carrier"
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

func TestValidateReadyAllowsPlaintextOnlyForLoopbackDirect(t *testing.T) {
	client, server := newPlainUpgradedPair(t, SubprotocolDirect)
	defer client.Close()
	defer server.Close()
	if err := ValidateReady(client, SubprotocolDirect); err != nil {
		t.Fatalf("loopback direct client ValidateReady() error = %v", err)
	}
	if err := ValidateReady(server, SubprotocolDirect); err != nil {
		t.Fatalf("loopback direct server ValidateReady() error = %v", err)
	}

	tunnelClient, tunnelServer := newPlainUpgradedPair(t, SubprotocolTunnel)
	defer tunnelClient.Close()
	defer tunnelServer.Close()
	if err := ValidateReady(tunnelClient, SubprotocolTunnel); !errors.Is(err, ErrTLS13Required) {
		t.Fatalf("plaintext tunnel client error = %v, want ErrTLS13Required", err)
	}
	if err := ValidateReady(tunnelServer, SubprotocolTunnel); !errors.Is(err, ErrTLS13Required) {
		t.Fatalf("plaintext tunnel server error = %v, want ErrTLS13Required", err)
	}

	tls12Client, tls12Server := newTLS12UpgradedPair(t, SubprotocolDirect)
	defer tls12Client.Close()
	defer tls12Server.Close()
	if err := ValidateReady(tls12Client, SubprotocolDirect); !errors.Is(err, ErrTLS13Required) {
		t.Fatalf("TLS 1.2 loopback client error = %v, want ErrTLS13Required", err)
	}
	if err := ValidateReady(tls12Server, SubprotocolDirect); !errors.Is(err, ErrTLS13Required) {
		t.Fatalf("TLS 1.2 loopback server error = %v, want ErrTLS13Required", err)
	}

	for _, address := range []net.Addr{
		&net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 443},
		&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 443},
		nil,
	} {
		if loopbackTCPAddress(address) {
			t.Fatalf("non-loopback TCP boundary accepted address %#v", address)
		}
	}

	loopback := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 23998}
	nonLoopback := &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 443}
	for name, conn := range map[string]net.Conn{
		"local non-loopback":  addressConn{local: nonLoopback, remote: loopback},
		"remote non-loopback": addressConn{local: loopback, remote: nonLoopback},
		"missing local":       addressConn{remote: loopback},
		"missing remote":      addressConn{local: loopback},
		"non-TCP local":       addressConn{local: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 23998}, remote: loopback},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validatePlaintextLoopback(conn, SubprotocolDirect); !errors.Is(err, ErrTLS13Required) {
				t.Fatalf("validatePlaintextLoopback() error = %v, want ErrTLS13Required", err)
			}
		})
	}
	if err := validatePlaintextLoopback(addressConn{local: loopback, remote: loopback}, SubprotocolTunnel); !errors.Is(err, ErrTLS13Required) {
		t.Fatalf("tunnel validatePlaintextLoopback() error = %v, want ErrTLS13Required", err)
	}
}

type addressConn struct {
	local  net.Addr
	remote net.Addr
}

func (conn addressConn) Read([]byte) (int, error)         { return 0, net.ErrClosed }
func (conn addressConn) Write([]byte) (int, error)        { return 0, net.ErrClosed }
func (conn addressConn) Close() error                     { return nil }
func (conn addressConn) LocalAddr() net.Addr              { return conn.local }
func (conn addressConn) RemoteAddr() net.Addr             { return conn.remote }
func (conn addressConn) SetDeadline(time.Time) error      { return nil }
func (conn addressConn) SetReadDeadline(time.Time) error  { return nil }
func (conn addressConn) SetWriteDeadline(time.Time) error { return nil }

func TestBindSessionResourcePolicyUsesExactPhysicalCapacity(t *testing.T) {
	for _, logical := range []uint16{1, 128} {
		policy, err := BindSessionResourcePolicy(DefaultResourcePolicy(), logical)
		if err != nil {
			t.Fatal(err)
		}
		want := logical + 2
		if policy.InboundBidirectionalStreams != want || policy.MaxConcurrentStreams < uint32(want) {
			t.Fatalf("logical %d bound policy = %+v, want at least %d physical streams", logical, policy, want)
		}
	}
}

func TestCloseWithErrorContextAcceptsNilContext(t *testing.T) {
	client, _ := newCarrierPair(t, SubprotocolDirect)
	_ = client.CloseWithErrorContext(nil, carrier.ApplicationError{Reason: "test close"})
}

func TestNormalPeerCloseDuringLocalShutdownIsNotAnError(t *testing.T) {
	client, _ := newCarrierPair(t, SubprotocolDirect)
	client.closeControl = func(context.Context, carrier.ApplicationError) error {
		return &gorillaws.CloseError{Code: closeStatusCode, Text: "session closed"}
	}
	if err := client.CloseWithError(carrier.ApplicationError{Code: 1, Reason: "session closed"}); err != nil {
		t.Fatalf("normal peer close during local shutdown = %v, want nil", err)
	}
}

func TestShutdownPreservesNonMatchingPeerCloseErrors(t *testing.T) {
	tests := []struct {
		name       string
		local      carrier.ApplicationError
		peerCode   int
		peerReason string
	}{
		{name: "different local reason", local: carrier.ApplicationError{Code: 1, Reason: "other"}, peerCode: closeStatusCode, peerReason: "session closed"},
		{name: "different local code", local: carrier.ApplicationError{Code: 6, Reason: "session closed"}, peerCode: closeStatusCode, peerReason: "session closed"},
		{name: "different peer reason", local: carrier.ApplicationError{Code: 1, Reason: "session closed"}, peerCode: closeStatusCode, peerReason: "other"},
		{name: "different peer code", local: carrier.ApplicationError{Code: 1, Reason: "session closed"}, peerCode: closeStatusCode + 1, peerReason: "session closed"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			peerError := &gorillaws.CloseError{Code: test.peerCode, Text: test.peerReason}
			if got := normalizeWebSocketShutdownError(peerError, true, test.local); !errors.Is(got, peerError) {
				t.Fatalf("shutdown error = %v, want original %v", got, peerError)
			}
		})
	}
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

func TestYamuxStopSendingIsExplicitlyUnavailable(t *testing.T) {
	client, _ := newCarrierPair(t, SubprotocolDirect)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if err := stream.StopSending(); !errors.Is(err, carrier.ErrStopSendingUnavailable) {
		t.Fatalf("StopSending error = %v, want ErrStopSendingUnavailable", err)
	}
}

func TestExactSubprotocolIsRequired(t *testing.T) {
	client, server := newUpgradedPair(t, SubprotocolDirect)
	t.Cleanup(func() { _ = client.Close() })
	t.Cleanup(func() { _ = server.Close() })
	resources := DefaultResourcePolicy()
	if _, err := NewAfterAdmission(server, ServerRole, SubprotocolTunnel, resources); !errors.Is(err, ErrInvalidSubprotocol) {
		t.Fatalf("NewAfterAdmission subprotocol error = %v", err)
	}
	if err := ValidateReady(server, ""); !errors.Is(err, ErrInvalidSubprotocol) {
		t.Fatalf("ValidateReady missing subprotocol error = %v", err)
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
		session, err := NewAfterAdmission(serverConn, ServerRole, subprotocol, resources)
		if err != nil {
			errCh <- err
			return
		}
		serverCh <- session
	}()
	client, err := NewAfterAdmission(clientConn, ClientRole, subprotocol, resources)
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

func newPlainUpgradedPair(t *testing.T, subprotocol string) (*gorillaws.Conn, *gorillaws.Conn) {
	t.Helper()
	serverConn := make(chan *gorillaws.Conn, 1)
	upgrader := gorillaws.Upgrader{Subprotocols: []string{subprotocol}}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		conn, err := upgrader.Upgrade(writer, request, nil)
		if err == nil {
			serverConn <- conn
		}
	}))
	t.Cleanup(server.Close)
	dialer := gorillaws.Dialer{Subprotocols: []string{subprotocol}}
	client, _, err := dialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatalf("plaintext Dial: %v", err)
	}
	select {
	case accepted := <-serverConn:
		return client, accepted
	case <-time.After(5 * time.Second):
		t.Fatal("plaintext upgrade timed out")
		return nil, nil
	}
}

func newTLS12UpgradedPair(t *testing.T, subprotocol string) (*gorillaws.Conn, *gorillaws.Conn) {
	t.Helper()
	serverConn := make(chan *gorillaws.Conn, 1)
	upgrader := gorillaws.Upgrader{Subprotocols: []string{subprotocol}}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		conn, err := upgrader.Upgrade(writer, request, nil)
		if err == nil {
			serverConn <- conn
		}
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12}
	server.StartTLS()
	t.Cleanup(server.Close)
	dialer := gorillaws.Dialer{
		Subprotocols: []string{subprotocol},
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS12,
			MaxVersion:         tls.VersionTLS12,
			InsecureSkipVerify: true, // test server only
		},
	}
	client, _, err := dialer.Dial("wss"+strings.TrimPrefix(server.URL, "https"), nil)
	if err != nil {
		t.Fatalf("TLS 1.2 Dial: %v", err)
	}
	select {
	case accepted := <-serverConn:
		return client, accepted
	case <-time.After(5 * time.Second):
		t.Fatal("TLS 1.2 upgrade timed out")
		return nil, nil
	}
}
