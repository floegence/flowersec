package connectv4

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/carrierv4/tlspolicy"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

func serverTLSCertificate(t *testing.T, days int, dns string) ([]byte, *ecdsa.PrivateKey, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Unix(0, 0), NotAfter: time.UnixMilli(int64(days) * 86400000),
		DNSNames: []string{dns}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	return der, key, roots
}

func newServerTLSListener(t *testing.T, f *websocketServeFixture, der []byte, key crypto.Signer) *WebSocketTLSListener {
	t.Helper()
	raw, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	c := WebSocketTLSListenerConfig{CertificateDER: [][]byte{der}, Signer: key, Clock: f.clock, Root: f.root, Owner: f.owner, RuntimeBytes: 16384,
		PerConnection: resourcev4.Vector{resourcev4.ProviderBytes: 131072, resourcev4.Tasks: 2, resourcev4.Timers: 2}, HandshakeTimeout: time.Second}
	c.Owner.Backing[0] = 50
	cost, err := WebSocketTLSListenerCharge(c)
	if err != nil {
		_ = raw.Close()
		t.Fatal(err)
	}
	l, err := NewWebSocketTLSListener(raw, c, f.reserve(t, cost), f.shared)
	if err != nil {
		_ = raw.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = l.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := l.WaitCleanup(ctx); err != nil {
			t.Error("TLS listener actual cleanup", err)
			return
		}
		if err := l.Retire(); err != nil {
			t.Error(err)
		}
	})
	return l
}

func serverTLSClient(roots *x509.CertPool) *tls.Config {
	return &tls.Config{RootCAs: roots, ServerName: "accepted.example", Time: func() time.Time { return time.UnixMilli(1000) }, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, NextProtos: []string{"http/1.1"}}
}

func TestWebSocketTLSListenerActualConnectionAndDrain(t *testing.T) {
	f := websocketServeTestOwner(t)
	der, key, roots := serverTLSCertificate(t, 14, "accepted.example")
	l := newServerTLSListener(t, f, der, key)
	before := f.root.Snapshot()
	accepted := make(chan *tls.Conn, 1)
	errs := make(chan error, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			errs <- err
			return
		}
		s := c.(*tls.Conn)
		if err := s.Handshake(); err != nil {
			_ = s.Close()
			errs <- err
			return
		}
		accepted <- s
	}()
	client, err := tls.Dial("tcp", l.Addr().String(), serverTLSClient(roots))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	var server *tls.Conn
	select {
	case server = <-accepted:
	case err = <-errs:
		t.Fatal(err)
	case <-time.After(3 * time.Second):
		t.Fatal("handshake timeout")
	}
	defer server.Close()
	request := httptest.NewRequest(http.MethodGet, "https://accepted.example/flowersec/v4/direct", nil)
	state := server.ConnectionState()
	request.TLS = &state
	if _, err := l.accepted(request); err == nil {
		t.Fatal("unbound request state became TLS evidence")
	}
	request = request.WithContext(l.ConnContext(context.Background(), server))
	if _, err := l.accepted(request); err != nil {
		t.Fatal(err)
	}
	if _, err := l.accepted(request.WithContext(l.ConnContext(context.Background(), client))); err == nil {
		t.Fatal("foreign connection adopted")
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if err := l.Retire(); !errors.Is(err, resourcev4.ErrCapacity) {
		t.Fatal("listener stop retired live connection", err)
	}
	if _, err := l.accepted(request); err != nil {
		t.Fatal("Drain disabled original connection", err)
	}
	written := make(chan error, 1)
	go func() { _, err := server.Write([]byte("draining")); written <- err }()
	var data [8]byte
	if _, err := io.ReadFull(client, data[:]); err != nil || string(data[:]) != "draining" {
		t.Fatal(string(data[:]), err)
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
	_ = server.Close()
	if err := l.WaitCleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.root.Snapshot() != before {
		t.Fatal("original socket retained resources")
	}
}

type blockedTLSSigner struct {
	crypto.Signer
	entered, release chan struct{}
	once             sync.Once
	abnormal         string
}

func (s *blockedTLSSigner) Sign(r io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	s.once.Do(func() { close(s.entered) })
	<-s.release
	if s.abnormal == "panic" {
		panic("test key provider failure")
	}
	if s.abnormal == "goexit" {
		runtime.Goexit()
	}
	return s.Signer.Sign(r, message, opts)
}

func TestWebSocketTLSListenerAbnormalSignerKeepsOriginalCleanup(t *testing.T) {
	for _, mode := range []string{"panic", "goexit"} {
		t.Run(mode, func(t *testing.T) {
			f := websocketServeTestOwner(t)
			der, key, roots := serverTLSCertificate(t, 14, "accepted.example")
			signer := &blockedTLSSigner{Signer: key, entered: make(chan struct{}), release: make(chan struct{}), abnormal: mode}
			close(signer.release)
			l := newServerTLSListener(t, f, der, signer)
			before := f.root.Snapshot()
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer func() { _ = recover() }()
				conn, err := l.Accept()
				if err != nil {
					t.Error(err)
					return
				}
				defer conn.Close()
				_ = conn.(*tls.Conn).Handshake()
			}()
			client, err := tls.Dial("tcp", l.Addr().String(), serverTLSClient(roots))
			if client != nil {
				_ = client.Close()
			}
			if err == nil {
				t.Fatal("abnormal signer succeeded")
			}
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("original TLS task did not exit")
			}
			if f.root.Snapshot() != before {
				t.Fatal("abnormal signing tail leaked original owner")
			}
		})
	}
}

func TestWebSocketTLSListenerReservesBeforePhysicalAccept(t *testing.T) {
	f := websocketServeTestOwner(t)
	der, key, _ := serverTLSCertificate(t, 14, "accepted.example")
	l := newServerTLSListener(t, f, der, key)
	before := f.root.Snapshot()
	occupied := f.reserve(t, resourcev4.Vector{resourcev4.Connections: before.Limit[resourcev4.Connections] - before.Charged[resourcev4.Connections]})
	full := f.root.Snapshot()
	if _, err := l.Accept(); !errors.Is(err, resourcev4.ErrCapacity) {
		t.Fatal("unreserved accept entered", err)
	}
	if f.root.Snapshot() != full {
		t.Fatal("failed capacity changed original accounts")
	}
	occupied.Release()
	finished := make(chan error, 1)
	go func() {
		conn, err := l.Accept()
		if conn != nil {
			_ = conn.Close()
		}
		finished <- err
	}()
	client, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
	if f.root.Snapshot() != before {
		t.Fatal("original accepted connection was not returned")
	}
}

func TestWebSocketTLSListenerClosedSocketRetainsOriginalSigner(t *testing.T) {
	f := websocketServeTestOwner(t)
	der, key, roots := serverTLSCertificate(t, 14, "accepted.example")
	signer := &blockedTLSSigner{Signer: key, entered: make(chan struct{}), release: make(chan struct{})}
	l := newServerTLSListener(t, f, der, signer)
	var release sync.Once
	defer release.Do(func() { close(signer.release) })
	before := f.root.Snapshot()
	servers := make(chan *tls.Conn, 1)
	finished := make(chan error, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			finished <- err
			return
		}
		s := c.(*tls.Conn)
		servers <- s
		err = s.Handshake()
		_ = s.Close()
		finished <- err
	}()
	clientDone := make(chan error, 1)
	go func() {
		c, err := tls.Dial("tcp", l.Addr().String(), serverTLSClient(roots))
		if c != nil {
			_ = c.Close()
		}
		clientDone <- err
	}()
	var server *tls.Conn
	select {
	case server = <-servers:
	case <-time.After(3 * time.Second):
		t.Fatal("accept timeout")
	}
	select {
	case <-signer.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("sign timeout")
	}
	_ = server.NetConn().Close()
	_ = l.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := l.WaitCleanup(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("blocked signer reported cleaned", err)
	}
	if err := l.Retire(); !errors.Is(err, resourcev4.ErrCapacity) {
		t.Fatal(err)
	}
	if f.root.Snapshot().Reservations != before.Reservations+1 {
		t.Fatal("blocked signer refunded connection")
	}
	release.Do(func() { close(signer.release) })
	if err := <-finished; err == nil {
		t.Fatal("closed original handshake succeeded")
	}
	if err := <-clientDone; err == nil {
		t.Fatal("canceled handshake succeeded")
	}
	if err := l.WaitCleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.root.Snapshot() != before {
		t.Fatal("exited signer did not retire original charge")
	}
}

func TestWebSocketTLSListenerRejectsTLS12AndForeignHTTPHost(t *testing.T) {
	f := websocketServeTestOwner(t)
	der, key, roots := serverTLSCertificate(t, 14, "accepted.example")
	l := newServerTLSListener(t, f, der, key)
	checks := make(chan error, 2)
	server := &http.Server{ConnContext: l.ConnContext, ConnState: l.ConnState, ReadHeaderTimeout: time.Second, ErrorLog: log.New(io.Discard, "", 0), Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := l.accepted(r)
		checks <- err
		w.Header().Set("Connection", "close")
		w.WriteHeader(204)
	})}
	go func() { _ = server.Serve(l) }()
	defer server.Close()
	config := serverTLSClient(roots)
	config.MinVersion, config.MaxVersion = tls.VersionTLS12, tls.VersionTLS12
	if c, err := tls.Dial("tcp", l.Addr().String(), config); err == nil {
		_ = c.Close()
		t.Fatal("TLS 1.2 accepted")
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: serverTLSClient(roots)}}
	response, err := client.Get("https://" + l.Addr().String() + "/flowersec/v4/direct")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if err := <-checks; err != nil {
		t.Fatal(err)
	}
	foreign := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := l.accepted(r)
		checks <- err
		w.WriteHeader(204)
	}))
	foreign.Config.ConnContext = l.ConnContext
	foreign.StartTLS()
	defer foreign.Close()
	response, err = foreign.Client().Get(foreign.URL)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if err := <-checks; !errors.Is(err, tlspolicy.ErrCertificate) {
		t.Fatal("foreign host supplied original evidence", err)
	}
}

func TestWebSocketTLSListenerOriginalHandshakeDeadlineCannotBeExtended(t *testing.T) {
	f := websocketServeTestOwner(t)
	der, key, _ := serverTLSCertificate(t, 14, "accepted.example")
	l := newServerTLSListener(t, f, der, key)
	finished := make(chan error, 1)
	go func() {
		conn, err := l.Accept()
		if err != nil {
			finished <- err
			return
		}
		defer conn.Close()
		// A borrowed HTTP host may clear or set its own larger timeout before
		// handshake; neither can renew the original finite preparation cap.
		if err := conn.SetDeadline(time.Time{}); err != nil {
			finished <- err
			return
		}
		if err := conn.SetReadDeadline(time.Now().Add(time.Hour)); err != nil {
			finished <- err
			return
		}
		finished <- conn.(*tls.Conn).Handshake()
	}()
	client, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	select {
	case err := <-finished:
		var timeout net.Error
		if !errors.As(err, &timeout) || !timeout.Timeout() {
			t.Fatal("original timeout not enforced", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("host extended original TLS handshake")
	}
}
