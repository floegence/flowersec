package webtransport

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier"
	"github.com/quic-go/quic-go/http3"
)

func TestTransportManagedPassivePeerRebindingPreservesWebTransportSession(t *testing.T) {
	if _, ok := reflect.TypeOf((*Session)(nil)).MethodByName("Migrate"); ok {
		t.Fatal("WebTransport must not expose application-managed active migration")
	}
	var carrierSession carrier.Session = (*Session)(nil)
	if _, ok := carrierSession.(carrier.PathMigrator); ok {
		t.Fatal("WebTransport must not implement the active PathMigrator capability")
	}

	serverTLS, clientTLS := migrationTLSConfigs(t)
	server, err := NewServer(serverTLS, DefaultLimits(), func(request *http.Request) bool {
		return request.Header.Get("Origin") == "https://client.example"
	})
	if err != nil {
		t.Fatal(err)
	}
	serverSessions := make(chan *Session, 1)
	serverErrors := make(chan error, 1)
	server.SetHandler(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		session, upgradeErr := server.Upgrade(writer, request)
		if upgradeErr != nil {
			serverErrors <- upgradeErr
			return
		}
		serverSessions <- session
	}))
	serverPacketConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(serverPacketConn) }()
	t.Cleanup(func() {
		_ = server.Close()
		_ = serverPacketConn.Close()
		select {
		case <-serveDone:
		case <-time.After(5 * time.Second):
			t.Error("WebTransport server did not stop")
		}
	})

	proxy := newWebTransportNATProxy(t, serverPacketConn.LocalAddr().(*net.UDPAddr))
	t.Cleanup(proxy.Close)
	dialer, err := NewDialer(clientTLS, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dialer.Close() })
	target := (&url.URL{
		Scheme: "https",
		Host:   net.JoinHostPort("localhost", fmt.Sprint(proxy.LocalAddr().(*net.UDPAddr).Port)),
		Path:   PathDirect,
	}).String()
	client, err := dialer.Dial(context.Background(), target, "https://client.example")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	var peer *Session
	select {
	case peer = <-serverSessions:
	case err := <-serverErrors:
		t.Fatal(err)
	case <-time.After(5 * time.Second):
		t.Fatal("WebTransport server session timed out")
	}
	t.Cleanup(func() { _ = peer.Close() })

	clientIdentity := client.inner
	peerIdentity := peer.inner
	oldPeerAddress := proxy.ActivePathAddress()
	waitForWebTransportPeerAddress(t, peer, oldPeerAddress)
	newPeerAddress := proxy.Rebind(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for attempt := 0; peer.inner.RemoteAddr().String() != newPeerAddress; attempt++ {
		payload := []byte(fmt.Sprintf("rebind-datagram-%d", attempt))
		if err := client.SendUnreliable(payload); err != nil {
			t.Fatalf("SendUnreliable after rebind: %v", err)
		}
		got, err := peer.ReceiveUnreliable(ctx)
		if err != nil {
			t.Fatalf("ReceiveUnreliable after rebind: %v", err)
		}
		if string(got) != string(payload) {
			t.Fatalf("DATAGRAM payload = %q, want %q", got, payload)
		}
		select {
		case <-ctx.Done():
			t.Fatalf("peer address stayed %q, want rebound %q", peer.inner.RemoteAddr(), newPeerAddress)
		case <-time.After(10 * time.Millisecond):
		}
	}
	assertWebTransportStreamRoundTrip(t, ctx, client, peer, "native-bidi-after-passive-rebind")
	if client.inner != clientIdentity || peer.inner != peerIdentity {
		t.Fatal("passive rebinding replaced the WebTransport session")
	}
}

func assertWebTransportStreamRoundTrip(t *testing.T, ctx context.Context, sender, receiver *Session, payload string) {
	t.Helper()
	opened, err := sender.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	if _, err := opened.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	if err := opened.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	accepted, err := receiver.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer accepted.Close()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(accepted, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != payload {
		t.Fatalf("stream payload = %q, want %q", got, payload)
	}
	response := []byte("rebind-response")
	if _, err := accepted.Write(response); err != nil {
		t.Fatal(err)
	}
	if err := accepted.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got = make([]byte, len(response))
	if _, err := io.ReadFull(opened, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(response) {
		t.Fatalf("stream response = %q, want %q", got, response)
	}
}

func waitForWebTransportPeerAddress(t *testing.T, session *Session, want string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if session.inner.RemoteAddr().String() == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("peer address = %q, want %q", session.inner.RemoteAddr(), want)
}

type webTransportNATProxy struct {
	front  *net.UDPConn
	server *net.UDPAddr

	mu      sync.Mutex
	client  *net.UDPAddr
	active  *net.UDPConn
	paths   []*net.UDPConn
	closed  bool
	waiters sync.WaitGroup
}

func newWebTransportNATProxy(t *testing.T, server *net.UDPAddr) *webTransportNATProxy {
	t.Helper()
	front, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	proxy := &webTransportNATProxy{front: front, server: server}
	proxy.addPath(t)
	proxy.waiters.Add(1)
	go proxy.forwardClientPackets()
	return proxy
}

func (proxy *webTransportNATProxy) LocalAddr() net.Addr { return proxy.front.LocalAddr() }

func (proxy *webTransportNATProxy) ActivePathAddress() string {
	proxy.mu.Lock()
	defer proxy.mu.Unlock()
	return proxy.active.LocalAddr().String()
}

func (proxy *webTransportNATProxy) Rebind(t *testing.T) string {
	t.Helper()
	return proxy.addPath(t).LocalAddr().String()
}

func (proxy *webTransportNATProxy) addPath(t *testing.T) *net.UDPConn {
	t.Helper()
	path, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	proxy.mu.Lock()
	proxy.paths = append(proxy.paths, path)
	proxy.active = path
	proxy.mu.Unlock()
	proxy.waiters.Add(1)
	go proxy.forwardServerPackets(path)
	return path
}

func (proxy *webTransportNATProxy) forwardClientPackets() {
	defer proxy.waiters.Done()
	buffer := make([]byte, 64<<10)
	for {
		n, client, err := proxy.front.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		proxy.mu.Lock()
		proxy.client = client
		active := proxy.active
		proxy.mu.Unlock()
		if _, err := active.WriteToUDP(buffer[:n], proxy.server); err != nil {
			return
		}
	}
}

func (proxy *webTransportNATProxy) forwardServerPackets(path *net.UDPConn) {
	defer proxy.waiters.Done()
	buffer := make([]byte, 64<<10)
	for {
		n, _, err := path.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		proxy.mu.Lock()
		client := proxy.client
		proxy.mu.Unlock()
		if client != nil {
			if _, err := proxy.front.WriteToUDP(buffer[:n], client); err != nil {
				return
			}
		}
	}
}

func (proxy *webTransportNATProxy) Close() {
	proxy.mu.Lock()
	if proxy.closed {
		proxy.mu.Unlock()
		return
	}
	proxy.closed = true
	paths := append([]*net.UDPConn(nil), proxy.paths...)
	proxy.mu.Unlock()
	_ = proxy.front.Close()
	for _, path := range paths {
		_ = path.Close()
	}
	proxy.waiters.Wait()
}

func migrationTLSConfigs(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: privateKey}
	pool := x509.NewCertPool()
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool.AddCert(parsed)
	return &tls.Config{
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{certificate},
			NextProtos:   []string{http3.NextProtoH3},
		}, &tls.Config{
			MinVersion: tls.VersionTLS13,
			RootCAs:    pool,
			ServerName: "localhost",
			NextProtos: []string{http3.NextProtoH3},
		}
}
