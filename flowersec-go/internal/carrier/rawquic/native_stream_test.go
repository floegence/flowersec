package rawquic

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
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

func TestClientMigrationValidatesAndSwitchesExclusivelyToNewPacketConn(t *testing.T) {
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
	oldUDP, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	oldPacketConn := &observedPacketConn{PacketConn: oldUDP}
	client, err := dialPacketConnForTest(context.Background(), listener.Addr().String(), clientTLS, DefaultLimits(), oldPacketConn)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server := <-serverCh
	defer server.Close()

	oldLocalAddress := client.conn.LocalAddr().String()
	newUDP, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	newPacketConn := &observedPacketConn{PacketConn: newUDP}
	newLocalAddress := newPacketConn.LocalAddr().String()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Migrate(ctx, newPacketConn); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	probeWrites := newPacketConn.Writes()
	assertNativeStreamRoundTrip(t, ctx, client, server, "activate-migration")
	waitForWritesGreaterThan(t, newPacketConn, probeWrites)
	if got := client.conn.LocalAddr().String(); got != newLocalAddress || got == oldLocalAddress {
		t.Fatalf("active local address = %q, want new %q instead of old %q", got, newLocalAddress, oldLocalAddress)
	}

	oldWrites := waitForStableWrites(t, oldPacketConn)
	newWrites := newPacketConn.Writes()
	assertNativeStreamRoundTrip(t, ctx, client, server, "after-migration")
	time.Sleep(100 * time.Millisecond)
	if got := oldPacketConn.Writes(); got != oldWrites {
		t.Fatalf("old path sent %d packets after switch, want no change from %d", got, oldWrites)
	}
	if got := newPacketConn.Writes(); got <= newWrites {
		t.Fatalf("new path sent %d packets after stream, want more than %d", got, newWrites)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("Close after migration: %v", err)
	}
}

func TestClientMigrationProbeFailureRollsBackToWorkingPath(t *testing.T) {
	client, server := newMigrationTestPair(t, nil)
	oldLocalAddress := client.conn.LocalAddr().String()
	candidateUDP, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	candidate := &observedPacketConn{PacketConn: candidateUDP, dropWrites: true}
	probeContext, cancelProbe := context.WithTimeout(context.Background(), 150*time.Millisecond)
	err = client.Migrate(probeContext, candidate)
	cancelProbe()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Migrate error = %v, want context deadline exceeded", err)
	}
	if candidate.Closed() {
		t.Fatal("failed candidate transport was closed early and could terminate the live QUIC connection")
	}
	if got := client.conn.LocalAddr().String(); got != oldLocalAddress {
		t.Fatalf("active local address = %q after rollback, want %q", got, oldLocalAddress)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	assertNativeStreamRoundTrip(t, ctx, client, server, "after-failed-migration")
	if err := client.Close(); err != nil {
		t.Fatalf("Close after rollback: %v", err)
	}
	if !candidate.Closed() {
		t.Fatal("session close did not release the retained failed migration transport")
	}
}

func TestServerPassivelyRebindsPeerWithoutReplacingSession(t *testing.T) {
	serverTLS, clientTLS := nativeTestTLS(t)
	serverTLS.NextProtos = []string{ALPNDirect}
	clientTLS.NextProtos = []string{ALPNDirect}
	listener, err := Listen("127.0.0.1:0", serverTLS, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	proxy := newNATRebindingProxy(t, listener.Addr().(*net.UDPAddr))
	defer proxy.Close()
	serverCh := make(chan *Session, 1)
	go func() {
		session, _ := listener.Accept(context.Background())
		serverCh <- session
	}()
	client, err := Dial(context.Background(), proxy.LocalAddr().String(), clientTLS, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server := <-serverCh
	defer server.Close()

	oldPeerAddress := proxy.ActivePathAddress()
	waitForAddress(t, func() string { return server.conn.RemoteAddr().String() }, oldPeerAddress)
	newPeerAddress := proxy.Rebind(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for server.conn.RemoteAddr().String() != newPeerAddress {
		assertNativeStreamRoundTrip(t, ctx, client, server, "passive-rebind")
		select {
		case <-ctx.Done():
			t.Fatalf("server peer address stayed %q, want rebound %q", server.conn.RemoteAddr(), newPeerAddress)
		case <-time.After(10 * time.Millisecond):
		}
	}
	assertNativeStreamRoundTrip(t, ctx, server, client, "same-session-after-rebind")
}

func newMigrationTestPair(t *testing.T, clientPacketConn net.PacketConn) (*Session, *Session) {
	t.Helper()
	serverTLS, clientTLS := nativeTestTLS(t)
	serverTLS.NextProtos = []string{ALPNDirect}
	clientTLS.NextProtos = []string{ALPNDirect}
	listener, err := Listen("127.0.0.1:0", serverTLS, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	serverCh := make(chan *Session, 1)
	go func() {
		session, _ := listener.Accept(context.Background())
		serverCh <- session
	}()
	var client *Session
	if clientPacketConn == nil {
		client, err = Dial(context.Background(), listener.Addr().String(), clientTLS, DefaultLimits())
	} else {
		client, err = dialPacketConnForTest(context.Background(), listener.Addr().String(), clientTLS, DefaultLimits(), clientPacketConn)
	}
	if err != nil {
		t.Fatal(err)
	}
	server := <-serverCh
	t.Cleanup(func() { _ = client.Close() })
	t.Cleanup(func() { _ = server.Close() })
	return client, server
}

func dialPacketConnForTest(
	ctx context.Context,
	address string,
	tlsConfig *tls.Config,
	limits Limits,
	packetConn net.PacketConn,
) (*Session, error) {
	preparedTLS, err := prepareTLS(tlsConfig, false)
	if err != nil {
		return nil, err
	}
	config, err := newConfig(limits)
	if err != nil {
		return nil, err
	}
	remote, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, err
	}
	if preparedTLS.ServerName == "" {
		host, _, splitErr := net.SplitHostPort(address)
		if splitErr != nil {
			return nil, splitErr
		}
		preparedTLS.ServerName = host
	}
	return dialPacketConn(ctx, remote, preparedTLS, config, uint16(limits.MaxInboundStreams), packetConn)
}

func assertNativeStreamRoundTrip(t *testing.T, ctx context.Context, sender, receiver *Session, payload string) {
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
	buffer := make([]byte, len(payload))
	if _, err := io.ReadFull(accepted, buffer); err != nil {
		t.Fatal(err)
	}
	if string(buffer) != payload {
		t.Fatalf("payload = %q, want %q", buffer, payload)
	}
}

func waitForStableWrites(t *testing.T, conn *observedPacketConn) uint64 {
	t.Helper()
	previous := conn.Writes()
	stable := 0
	for range 50 {
		time.Sleep(10 * time.Millisecond)
		current := conn.Writes()
		if current == previous {
			stable++
			if stable == 5 {
				return current
			}
		} else {
			previous = current
			stable = 0
		}
	}
	t.Fatalf("packet writes did not quiesce; last count %d", previous)
	return 0
}

func waitForWritesGreaterThan(t *testing.T, conn *observedPacketConn, previous uint64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if conn.Writes() > previous {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("packet writes = %d, want more than %d", conn.Writes(), previous)
}

func waitForAddress(t *testing.T, current func() string, want string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if current() == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("address = %q, want %q", current(), want)
}

type observedPacketConn struct {
	net.PacketConn
	writes     atomic.Uint64
	closed     atomic.Bool
	dropWrites bool
}

func (conn *observedPacketConn) WriteTo(payload []byte, address net.Addr) (int, error) {
	conn.writes.Add(1)
	if conn.dropWrites {
		return len(payload), nil
	}
	return conn.PacketConn.WriteTo(payload, address)
}

func (conn *observedPacketConn) Close() error {
	conn.closed.Store(true)
	return conn.PacketConn.Close()
}

func (conn *observedPacketConn) Writes() uint64 { return conn.writes.Load() }
func (conn *observedPacketConn) Closed() bool   { return conn.closed.Load() }

type natRebindingProxy struct {
	front  *net.UDPConn
	server *net.UDPAddr

	mu      sync.Mutex
	client  *net.UDPAddr
	active  *net.UDPConn
	paths   []*net.UDPConn
	closed  bool
	waiters sync.WaitGroup
}

func newNATRebindingProxy(t *testing.T, server *net.UDPAddr) *natRebindingProxy {
	t.Helper()
	front, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	proxy := &natRebindingProxy{front: front, server: server}
	proxy.addPath(t)
	proxy.waiters.Add(1)
	go proxy.forwardClientPackets()
	return proxy
}

func (proxy *natRebindingProxy) LocalAddr() net.Addr { return proxy.front.LocalAddr() }

func (proxy *natRebindingProxy) ActivePathAddress() string {
	proxy.mu.Lock()
	defer proxy.mu.Unlock()
	return proxy.active.LocalAddr().String()
}

func (proxy *natRebindingProxy) Rebind(t *testing.T) string {
	t.Helper()
	path := proxy.addPath(t)
	return path.LocalAddr().String()
}

func (proxy *natRebindingProxy) addPath(t *testing.T) *net.UDPConn {
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

func (proxy *natRebindingProxy) forwardClientPackets() {
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

func (proxy *natRebindingProxy) forwardServerPackets(path *net.UDPConn) {
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

func (proxy *natRebindingProxy) Close() {
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
