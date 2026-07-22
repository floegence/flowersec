package rawquic

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"testing"
	"time"
)

func TestEightCarrierStreamsUseEightDistinctNativeBidiStreamIDs(t *testing.T) {
	serverTLS, clientTLS := nativeTestTLS(t)
	serverTLS.NextProtos = []string{ALPNDirect}
	clientTLS.NextProtos = []string{ALPNDirect}
	listener, err := Listen("127.0.0.1:0", serverTLS, DefaultLimits())
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer listener.Close()
	serverCh := make(chan *Session, 1)
	go func() {
		session, _ := listener.Accept(context.Background())
		serverCh <- session
	}()
	client, err := Dial(context.Background(), listener.Addr().String(), clientTLS, DefaultLimits())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close()
	server := <-serverCh
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	clientIDs := make(map[int64]struct{}, 8)
	serverIDs := make(map[int64]struct{}, 8)
	for index := range 8 {
		opened, err := client.OpenStream(ctx)
		if err != nil {
			t.Fatalf("OpenStream %d: %v", index, err)
		}
		stream := opened.(*Stream)
		clientIDs[int64(stream.stream.StreamID())] = struct{}{}
		if _, err := stream.Write([]byte{byte(index)}); err != nil {
			t.Fatalf("Write %d: %v", index, err)
		}
		accepted, err := server.AcceptStream(ctx)
		if err != nil {
			t.Fatalf("AcceptStream %d: %v", index, err)
		}
		peer := accepted.(*Stream)
		serverIDs[int64(peer.stream.StreamID())] = struct{}{}
		if stream.stream.StreamID() != peer.stream.StreamID() {
			t.Fatalf("stream ID mismatch: client=%d server=%d", stream.stream.StreamID(), peer.stream.StreamID())
		}
		_ = stream.Reset()
		_ = peer.Reset()
	}
	if len(clientIDs) != 8 || len(serverIDs) != 8 {
		t.Fatalf("native stream IDs = client %v server %v", clientIDs, serverIDs)
	}
}

func TestClientMigrationValidatesAndSwitchesToNewPacketConn(t *testing.T) {
	serverTLS, clientTLS := nativeTestTLS(t)
	serverTLS.NextProtos = []string{ALPNDirect}
	clientTLS.NextProtos = []string{ALPNDirect}
	listener, err := Listen("127.0.0.1:0", serverTLS, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverCh := make(chan *Session, 1)
	go func() {
		session, _ := listener.Accept(context.Background())
		serverCh <- session
	}()
	client, err := Dial(context.Background(), listener.Addr().String(), clientTLS, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server := <-serverCh
	defer server.Close()

	newPacketConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Migrate(ctx, newPacketConn); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	opened, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	if _, err := opened.Write([]byte("after-migration")); err != nil {
		t.Fatal(err)
	}
	if err := opened.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	accepted, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer accepted.Close()
	buffer := make([]byte, len("after-migration"))
	if _, err := io.ReadFull(accepted, buffer); err != nil {
		t.Fatal(err)
	}
	if string(buffer) != "after-migration" {
		t.Fatalf("payload = %q", buffer)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("Close after migration: %v", err)
	}
}

func nativeTestTLS(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(parsed)
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: privateKey}},
	}, &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, ServerName: "localhost"}
}
