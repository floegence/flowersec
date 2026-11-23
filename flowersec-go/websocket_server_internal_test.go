package flowersec

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestWebSocketHTTPServerAppliesBoundedDefaultHeaderTimeout(t *testing.T) {
	handler := &webSocketBoundary{handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), enabled: true}
	server, err := NewWebSocketHTTPServer(WebSocketHTTPServerOptions{
		Handler: handler,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{{
			Certificate: [][]byte{{1}},
		}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if server.httpServer.ReadHeaderTimeout != defaultWebSocketReadHeaderTimeout {
		t.Fatalf("default read-header timeout = %s, want %s", server.httpServer.ReadHeaderTimeout, defaultWebSocketReadHeaderTimeout)
	}
	if server.httpServer.ReadHeaderTimeout <= 0 || server.httpServer.ReadHeaderTimeout > 10*time.Second {
		t.Fatalf("default read-header timeout is not safely bounded: %s", server.httpServer.ReadHeaderTimeout)
	}
}

func TestWebSocketHTTPServerShutdownDeadlineForceClosesUncooperativeHijackedConnection(t *testing.T) {
	hijacked := make(chan struct{})
	releaseHandler := make(chan struct{})
	boundary := &webSocketBoundary{enabled: true, handler: http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		connection, _, err := writer.(http.Hijacker).Hijack()
		if err != nil {
			t.Errorf("Hijack: %v", err)
			return
		}
		close(hijacked)
		<-releaseHandler
		_ = connection.Close()
	})}
	serverTLS, roots := internalWebSocketServerTLS(t)
	server, err := NewWebSocketHTTPServer(WebSocketHTTPServerOptions{Handler: boundary, TLSConfig: serverTLS})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(listener) }()
	connection, err := tls.Dial("tcp", listener.Addr().String(), &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "localhost",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if _, err := fmt.Fprintf(connection, "GET %s HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n", WebSocketDirectPath); err != nil {
		t.Fatal(err)
	}
	select {
	case <-hijacked:
	case <-time.After(time.Second):
		t.Fatal("test handler did not hijack the WebSocket connection")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := server.Shutdown(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Shutdown error = %v, want exhausted context", err)
	}
	_ = connection.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := connection.Read(make([]byte, 1)); err == nil {
		t.Fatal("uncooperative hijacked connection remained open after forced Shutdown")
	} else if networkErr, ok := err.(net.Error); ok && networkErr.Timeout() {
		t.Fatal("forced Shutdown did not close the uncooperative hijacked connection")
	}
	close(releaseHandler)
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-serveDone:
	case <-time.After(time.Second):
		t.Fatal("Serve did not return after forced Shutdown")
	}
}

func internalWebSocketServerTLS(t *testing.T) (*tls.Config, *x509.CertPool) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: privateKey}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	return &tls.Config{Certificates: []tls.Certificate{certificate}}, roots
}
