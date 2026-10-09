package flowersec

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func invitationSecurityServer(t *testing.T, options InvitationExchangeHandlerOptions) *httptest.Server {
	t.Helper()
	handler, err := NewInvitationExchangeHandler(options)
	if err != nil {
		t.Fatal(err)
	}
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: private}}}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

func invitationRawClient(t *testing.T, server *httptest.Server, code InvitationCode) *websocket.Conn {
	t.Helper()
	dialer := websocket.Dialer{TLSClientConfig: server.Client().Transport.(*http.Transport).TLSClientConfig, Subprotocols: []string{invitationSubprotocol}}
	connection, _, err := dialer.Dial("wss"+strings.TrimPrefix(server.URL, "https"), http.Header{"X-Flowersec-Invitation": []string{code.LookupID()}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	_ = connection.SetReadDeadline(time.Now().Add(time.Second))
	return connection
}

func TestInvitationSecurityReplayTamperAndCredentialProof(t *testing.T) {
	code, _ := NewInvitationCode()
	var delivered atomic.Int32
	server := invitationSecurityServer(t, InvitationExchangeHandlerOptions{Purpose: "test.enrollment", Timeout: time.Second, Lookup: func(context.Context, string) (InvitationCode, error) { return code, nil }, Describe: func(context.Context, string) ([]byte, error) { delivered.Add(1); return []byte("descriptor"), nil }})
	// Record a valid handshake and confirmation for replay against fresh server randomness.
	client := invitationRawClient(t, server, code)
	state, _ := invitationHandshake(code, "test.enrollment", code.LookupID(), true)
	first, _, _, _ := state.WriteMessage(nil, []byte("client"))
	_ = client.WriteMessage(websocket.BinaryMessage, first)
	second, err := invitationRead(client)
	if err != nil {
		t.Fatal(err)
	}
	_, send, receive, err := state.ReadMessage(nil, second)
	if err != nil {
		t.Fatal(err)
	}
	third, _ := send.Encrypt(nil, nil, []byte("confirm"))
	_ = client.WriteMessage(websocket.BinaryMessage, third)
	fourth, err := invitationRead(client)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = receive.Decrypt(nil, nil, fourth); err != nil {
		t.Fatal(err)
	}
	_ = client.Close()
	for _, attack := range []string{"replay", "tamper", "wrong-key"} {
		t.Run(attack, func(t *testing.T) {
			peer := invitationRawClient(t, server, code)
			message := append([]byte(nil), first...)
			if attack == "tamper" {
				message[len(message)-1] ^= 1
			}
			if attack == "wrong-key" {
				wrong, _ := NewInvitationCode()
				hs, _ := invitationHandshake(wrong, "test.enrollment", code.LookupID(), true)
				message, _, _, _ = hs.WriteMessage(nil, []byte("client"))
			}
			_ = peer.WriteMessage(websocket.BinaryMessage, message)
			response, err := invitationRead(peer)
			if attack == "replay" {
				if err != nil || len(response) == 0 {
					t.Fatal("recorded first frame should require a fresh confirmation")
				}
				_ = peer.WriteMessage(websocket.BinaryMessage, third)
				_, err = invitationRead(peer)
			}
			if err == nil {
				t.Fatal("attack accepted")
			}
		})
	}
	if delivered.Load() != 1 {
		t.Fatal("replayed or unproved client reached descriptor callback")
	}
}

func TestInvitationSecurityBoundsTimeoutAndLiveCancellation(t *testing.T) {
	code, _ := NewInvitationCode()
	entered := make(chan struct{}, 1)
	server := invitationSecurityServer(t, InvitationExchangeHandlerOptions{Purpose: "test.enrollment", Timeout: time.Second, MaxConcurrent: 1, Lookup: func(context.Context, string) (InvitationCode, error) { return code, nil }, Describe: func(ctx context.Context, _ string) ([]byte, error) {
		entered <- struct{}{}
		<-ctx.Done()
		return nil, ctx.Err()
	}})
	options := InvitationExchangeOptions{URL: "wss" + strings.TrimPrefix(server.URL, "https"), Purpose: "test.enrollment", Code: code}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := ExchangeInvitation(ctx, options); done <- err }()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("exchange did not authenticate")
	}
	_, err := ExchangeInvitation(context.Background(), options)
	if err == nil {
		t.Fatal("concurrency limit ignored")
	}
	cancel()
	if err = <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("live cancellation lost: %v", err)
	}
	timeoutServer := invitationSecurityServer(t, InvitationExchangeHandlerOptions{Purpose: "test.enrollment", Timeout: time.Second, Lookup: func(ctx context.Context, _ string) (InvitationCode, error) {
		<-ctx.Done()
		return InvitationCode{}, ctx.Err()
	}, Describe: func(context.Context, string) ([]byte, error) { t.Fatal("timeout reached descriptor"); return nil, nil }})
	options.URL = "wss" + strings.TrimPrefix(timeoutServer.URL, "https")
	options.Timeout = 30 * time.Millisecond
	if _, err = ExchangeInvitation(context.Background(), options); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout lost: %v", err)
	}
	oversized := invitationSecurityServer(t, InvitationExchangeHandlerOptions{Purpose: "test.enrollment", Lookup: func(context.Context, string) (InvitationCode, error) { return code, nil }, Describe: func(context.Context, string) ([]byte, error) { return make([]byte, invitationMaxPayload+1), nil }})
	options.URL = "wss" + strings.TrimPrefix(oversized.URL, "https")
	options.Timeout = time.Second
	if _, err = ExchangeInvitation(context.Background(), options); err == nil {
		t.Fatal("oversized descriptor delivered")
	}
}

func TestInvitationSecurityTLSProfile(t *testing.T) {
	now := time.Now()
	leaf := &x509.Certificate{IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	state := tls.ConnectionState{Version: tls.VersionTLS13, PeerCertificates: []*x509.Certificate{leaf}}
	if err := verifyInvitationCertificate(state, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if err := verifyInvitationCertificate(state, "other.example"); err == nil {
		t.Fatal("wrong hostname accepted")
	}
	leaf.IsCA = true
	if err := verifyInvitationCertificate(state, "127.0.0.1"); err == nil {
		t.Fatal("CA leaf accepted")
	}
	leaf.IsCA = false
	leaf.NotAfter = now.Add(-time.Second)
	if err := verifyInvitationCertificate(state, "127.0.0.1"); err == nil {
		t.Fatal("expired leaf accepted")
	}
	leaf.NotAfter = now.Add(time.Hour)
	leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	if err := verifyInvitationCertificate(state, "127.0.0.1"); err == nil {
		t.Fatal("client-only certificate accepted")
	}
}
