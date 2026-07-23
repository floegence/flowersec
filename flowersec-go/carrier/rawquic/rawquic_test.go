package rawquic_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/carrier"
	"github.com/floegence/flowersec/flowersec-go/v2/carrier/rawquic"
)

func TestLimitsRejectUnboundedOrInconsistentValues(t *testing.T) {
	tests := []rawquic.Limits{
		{MaxInboundStreams: 0},
		{MaxInboundStreams: 131},
		{MaxInboundStreams: 1, InitialStreamReceiveWindow: 2, MaxStreamReceiveWindow: 1},
		{MaxInboundStreams: 1, InitialConnectionReceiveWindow: 2, MaxConnectionReceiveWindow: 1},
	}
	for _, mutate := range []func(*rawquic.Limits){
		func(limits *rawquic.Limits) { limits.InitialStreamReceiveWindow = (6 << 20) + 1 },
		func(limits *rawquic.Limits) { limits.MaxStreamReceiveWindow = (6 << 20) + 1 },
		func(limits *rawquic.Limits) { limits.InitialConnectionReceiveWindow = (16 << 20) + 1 },
		func(limits *rawquic.Limits) { limits.MaxConnectionReceiveWindow = (16 << 20) + 1 },
	} {
		limits := rawquic.DefaultLimits()
		mutate(&limits)
		tests = append(tests, limits)
	}
	for _, limits := range tests {
		if err := limits.Validate(); !errors.Is(err, rawquic.ErrInvalidLimits) {
			t.Fatalf("Validate(%+v) error = %v, want ErrInvalidLimits", limits, err)
		}
	}

	limits := rawquic.DefaultLimits()
	limits.InitialStreamReceiveWindow = 6 << 20
	limits.MaxStreamReceiveWindow = 6 << 20
	limits.InitialConnectionReceiveWindow = 16 << 20
	limits.MaxConnectionReceiveWindow = 16 << 20
	if err := limits.Validate(); err != nil {
		t.Fatalf("Validate(max bounded receive windows): %v", err)
	}
}

func TestBindSessionLimitsUsesExactPhysicalCapacity(t *testing.T) {
	limits, err := rawquic.BindSessionLimits(rawquic.DefaultLimits(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if limits.MaxInboundStreams != 3 {
		t.Fatalf("physical inbound streams = %d, want 3", limits.MaxInboundStreams)
	}
	if _, err := rawquic.BindSessionLimits(rawquic.DefaultLimits(), 129); !errors.Is(err, carrier.ErrInvalidStreamCapacity) {
		t.Fatalf("invalid logical capacity error = %v", err)
	}
}

func TestCloseWithErrorContextAcceptsNilContext(t *testing.T) {
	client, _ := newRawQUICPair(t, rawquic.ALPNDirect)
	_ = client.CloseWithErrorContext(nil, carrier.ApplicationError{Reason: "test close"})
}

func TestDialDerivesServerNameFromDNSAddress(t *testing.T) {
	serverTLS, clientTLS := testDNSOnlyTLSConfigs(t, "localhost")
	serverTLS.NextProtos = []string{rawquic.ALPNDirect}
	listener, err := rawquic.Listen("127.0.0.1:0", serverTLS, rawquic.DefaultLimits())
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer listener.Close()

	accepted := make(chan *rawquic.Session, 1)
	acceptErr := make(chan error, 1)
	go func() {
		session, err := listener.Accept(context.Background())
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- session
	}()

	clientTLS.NextProtos = []string{rawquic.ALPNDirect}
	address := net.JoinHostPort("localhost", fmt.Sprint(listener.Addr().(*net.UDPAddr).Port))
	client, err := rawquic.Dial(context.Background(), address, clientTLS, rawquic.DefaultLimits())
	if err != nil {
		t.Fatalf("Dial DNS address: %v", err)
	}
	defer client.Close()

	select {
	case server := <-accepted:
		defer server.Close()
	case err := <-acceptErr:
		t.Fatalf("Accept: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("Accept timed out")
	}
}

func TestDialAndListenRequireExactRegisteredALPN(t *testing.T) {
	serverTLS, clientTLS := testTLSConfigs(t)
	for _, profile := range []string{rawquic.ALPNDirect, rawquic.ALPNTunnel} {
		t.Run(profile, func(t *testing.T) {
			server := serverTLS.Clone()
			server.NextProtos = []string{profile}
			listener, err := rawquic.Listen("127.0.0.1:0", server, rawquic.DefaultLimits())
			if err != nil {
				t.Fatalf("Listen: %v", err)
			}
			defer listener.Close()

			accepted := make(chan carrier.Session, 1)
			acceptErr := make(chan error, 1)
			go func() {
				session, err := listener.Accept(context.Background())
				if err != nil {
					acceptErr <- err
					return
				}
				accepted <- session
			}()

			client := clientTLS.Clone()
			client.NextProtos = []string{profile}
			clientSession, err := rawquic.Dial(context.Background(), listener.Addr().String(), client, rawquic.DefaultLimits())
			if err != nil {
				t.Fatalf("Dial: %v", err)
			}
			defer clientSession.Close()

			var serverSession carrier.Session
			select {
			case serverSession = <-accepted:
			case err := <-acceptErr:
				t.Fatalf("Accept: %v", err)
			case <-time.After(5 * time.Second):
				t.Fatal("Accept timed out")
			}
			defer serverSession.Close()

			if clientSession.Kind() != carrier.KindQUIC || serverSession.Kind() != carrier.KindQUIC {
				t.Fatalf("carrier kind = %q/%q", clientSession.Kind(), serverSession.Kind())
			}
			wantPath := carrier.PathDirect
			if profile == rawquic.ALPNTunnel {
				wantPath = carrier.PathTunnel
			}
			if clientSession.Path() != wantPath || serverSession.Path() != wantPath {
				t.Fatalf("carrier path = %q/%q, want %q", clientSession.Path(), serverSession.Path(), wantPath)
			}
			assertNativeStreamRoundTrip(t, clientSession, serverSession)
		})
	}

	bad := serverTLS.Clone()
	bad.NextProtos = []string{"flowersec/2"}
	if _, err := rawquic.Listen("127.0.0.1:0", bad, rawquic.DefaultLimits()); !errors.Is(err, rawquic.ErrInvalidALPN) {
		t.Fatalf("Listen invalid ALPN error = %v", err)
	}
	bad = clientTLS.Clone()
	bad.NextProtos = []string{rawquic.ALPNDirect, rawquic.ALPNTunnel}
	if _, err := rawquic.Dial(context.Background(), "127.0.0.1:1", bad, rawquic.DefaultLimits()); !errors.Is(err, rawquic.ErrInvalidALPN) {
		t.Fatalf("Dial invalid ALPN error = %v", err)
	}
}

func TestDialAndListenRejectTLSAuthenticationBypass(t *testing.T) {
	serverTLS, clientTLS := testTLSConfigs(t)
	serverTLS.NextProtos = []string{rawquic.ALPNDirect}
	clientTLS.NextProtos = []string{rawquic.ALPNDirect}

	missingCertificate := &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{rawquic.ALPNDirect}}
	if _, err := rawquic.Listen("127.0.0.1:0", missingCertificate, rawquic.DefaultLimits()); !errors.Is(err, rawquic.ErrInvalidTLS) {
		t.Fatalf("Listen missing certificate error = %v, want ErrInvalidTLS", err)
	}
	missingPrivateKey := serverTLS.Clone()
	missingPrivateKey.Certificates = append([]tls.Certificate(nil), serverTLS.Certificates...)
	missingPrivateKey.Certificates[0].PrivateKey = nil
	if _, err := rawquic.Listen("127.0.0.1:0", missingPrivateKey, rawquic.DefaultLimits()); !errors.Is(err, rawquic.ErrInvalidTLS) {
		t.Fatalf("Listen missing private key error = %v, want ErrInvalidTLS", err)
	}

	missingRoots := clientTLS.Clone()
	missingRoots.RootCAs = nil
	if _, err := rawquic.Dial(context.Background(), "127.0.0.1:1", missingRoots, rawquic.DefaultLimits()); !errors.Is(err, rawquic.ErrInvalidTLS) {
		t.Fatalf("Dial missing roots error = %v, want ErrInvalidTLS", err)
	}
	emptyRoots := clientTLS.Clone()
	emptyRoots.RootCAs = x509.NewCertPool()
	if _, err := rawquic.Dial(context.Background(), "127.0.0.1:1", emptyRoots, rawquic.DefaultLimits()); !errors.Is(err, rawquic.ErrInvalidTLS) {
		t.Fatalf("Dial empty roots error = %v, want ErrInvalidTLS", err)
	}

	insecure := clientTLS.Clone()
	insecure.InsecureSkipVerify = true
	if _, err := rawquic.Dial(context.Background(), "127.0.0.1:1", insecure, rawquic.DefaultLimits()); !errors.Is(err, rawquic.ErrInvalidTLS) {
		t.Fatalf("Dial insecure verification error = %v, want ErrInvalidTLS", err)
	}
}

func TestDialRejectsWrongHostnameAndTrustRoot(t *testing.T) {
	serverTLS, clientTLS := testTLSConfigs(t)
	serverTLS.NextProtos = []string{rawquic.ALPNDirect}
	listener, err := rawquic.Listen("127.0.0.1:0", serverTLS, rawquic.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	for name, mutate := range map[string]func(*tls.Config){
		"wrong_hostname": func(config *tls.Config) { config.ServerName = "not-localhost.example" },
		"wrong_trust_root": func(config *tls.Config) {
			_, unrelatedClient := testTLSConfigs(t)
			config.RootCAs = unrelatedClient.RootCAs
		},
	} {
		t.Run(name, func(t *testing.T) {
			config := clientTLS.Clone()
			config.NextProtos = []string{rawquic.ALPNDirect}
			mutate(config)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if session, err := rawquic.Dial(ctx, listener.Addr().String(), config, rawquic.DefaultLimits()); err == nil {
				_ = session.Close()
				t.Fatalf("Dial with %s unexpectedly succeeded", name)
			}
		})
	}
}

func TestApplicationCloseReasonIsBoundedBeforeTransportUse(t *testing.T) {
	serverTLS, _ := testTLSConfigs(t)
	serverTLS.NextProtos = []string{rawquic.ALPNDirect}
	listener, err := rawquic.Listen("127.0.0.1:0", serverTLS, rawquic.DefaultLimits())
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer listener.Close()
	if _, err := rawquic.ValidateApplicationError(carrier.ApplicationError{Reason: strings.Repeat("x", carrier.MaxApplicationErrorReasonBytes+1)}); !errors.Is(err, rawquic.ErrInvalidApplicationError) {
		t.Fatalf("ValidateApplicationError error = %v", err)
	}
}

func TestNativeResetIsIsolatedFromSiblingStream(t *testing.T) {
	client, server := newRawQUICPair(t, rawquic.ALPNDirect)
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
	defer second.Close()
	if _, err := first.Write([]byte("reset-me")); err != nil {
		t.Fatalf("write first stream: %v", err)
	}
	if _, err := second.Write([]byte("survivor")); err != nil {
		t.Fatalf("write second stream: %v", err)
	}
	serverFirst, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("accept first stream: %v", err)
	}
	serverSecond, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("accept second stream: %v", err)
	}
	defer serverSecond.Close()

	if err := first.Reset(); err != nil {
		t.Fatalf("reset first stream: %v", err)
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
		t.Fatalf("close surviving stream: %v", err)
	}
	payload, err := io.ReadAll(serverSecond)
	if err != nil {
		t.Fatalf("read surviving stream: %v", err)
	}
	if string(payload) != "survivor" {
		t.Fatalf("surviving payload = %q", payload)
	}
	if _, err := serverSecond.Write([]byte("still-alive")); err != nil {
		t.Fatalf("write surviving response: %v", err)
	}
	if err := serverSecond.CloseWrite(); err != nil {
		t.Fatalf("close surviving response: %v", err)
	}
	response, err := io.ReadAll(second)
	if err != nil {
		t.Fatalf("read surviving response: %v", err)
	}
	if string(response) != "still-alive" {
		t.Fatalf("surviving response = %q", response)
	}
}

func TestNativeStreamFlowControlStallDoesNotBlockSibling(t *testing.T) {
	limits := rawquic.DefaultLimits()
	limits.InitialStreamReceiveWindow = 16 << 10
	limits.MaxStreamReceiveWindow = 16 << 10
	limits.InitialConnectionReceiveWindow = 256 << 10
	limits.MaxConnectionReceiveWindow = 256 << 10
	client, server := newRawQUICPairWithLimits(t, rawquic.ALPNDirect, limits)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	blocked, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocked.Reset()
	writeDone := make(chan error, 1)
	go func() {
		_, err := blocked.Write(make([]byte, 8<<20))
		writeDone <- err
	}()
	serverBlocked, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer serverBlocked.Reset()

	sibling, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer sibling.Close()
	if _, err := sibling.Write([]byte("interactive")); err != nil {
		t.Fatal(err)
	}
	if err := sibling.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	serverSibling, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer serverSibling.Close()
	payload, err := io.ReadAll(serverSibling)
	if err != nil {
		t.Fatal(err)
	}
	if string(payload) != "interactive" {
		t.Fatalf("sibling payload = %q", payload)
	}
	if _, err := serverSibling.Write([]byte("ok")); err != nil {
		t.Fatal(err)
	}
	if err := serverSibling.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	response, err := io.ReadAll(sibling)
	if err != nil || string(response) != "ok" {
		t.Fatalf("sibling response = %q, error = %v", response, err)
	}

	select {
	case err := <-writeDone:
		t.Fatalf("unread stream did not remain flow-control blocked: %v", err)
	default:
	}
	_ = blocked.Reset()
	select {
	case <-writeDone:
	case <-ctx.Done():
		t.Fatal("reset did not unblock flow-controlled writer")
	}
}

func TestSourceContainsNoYamuxOrDatagramAPISurface(t *testing.T) {
	_, testFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	rawBytes, err := os.ReadFile(filepath.Join(filepath.Dir(testFile), "rawquic.go"))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	raw := string(rawBytes)
	if strings.Contains(strings.ToLower(raw), "yamux") {
		t.Fatal("raw QUIC adapter must not reference Yamux")
	}
	for _, forbidden := range []string{"SendDatagram", "ReceiveDatagram"} {
		if strings.Contains(raw, forbidden) {
			t.Fatalf("raw QUIC adapter exposes %s", forbidden)
		}
	}
	if strings.Contains(raw, "func NewConfig(") {
		t.Fatal("raw QUIC public API must not expose a quic-go Config builder")
	}
}

func assertNativeStreamRoundTrip(t *testing.T, client, server carrier.Session) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	accepted := make(chan carrier.Stream, 1)
	acceptErr := make(chan error, 1)
	go func() {
		stream, err := server.AcceptStream(ctx)
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- stream
	}()
	clientStream, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	defer clientStream.Close()
	if _, err := clientStream.Write([]byte("native-bidi")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := clientStream.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	if err := clientStream.Context().Err(); err != nil {
		t.Fatalf("CloseWrite canceled the readable stream context: %v", err)
	}

	var serverStream carrier.Stream
	select {
	case serverStream = <-accepted:
	case err := <-acceptErr:
		t.Fatalf("AcceptStream: %v", err)
	case <-ctx.Done():
		t.Fatal("AcceptStream timed out")
	}
	defer serverStream.Close()
	payload, err := io.ReadAll(serverStream)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(payload) != "native-bidi" {
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

func testTLSConfigs(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
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
		t.Fatalf("CreateCertificate: %v", err)
	}
	certificate := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: privateKey}
	pool := x509.NewCertPool()
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	pool.AddCert(parsed)
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}}, &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, ServerName: "localhost"}
}

func testDNSOnlyTLSConfigs(t *testing.T, serverName string) (*tls.Config, *tls.Config) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: serverName},
		DNSNames:     []string{serverName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	certificate := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: privateKey}
	pool := x509.NewCertPool()
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	pool.AddCert(parsed)
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}},
		&tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool}
}

func newRawQUICPair(t *testing.T, profile string) (carrier.Session, carrier.Session) {
	return newRawQUICPairWithLimits(t, profile, rawquic.DefaultLimits())
}

func newRawQUICPairWithLimits(t *testing.T, profile string, limits rawquic.Limits) (carrier.Session, carrier.Session) {
	t.Helper()
	serverTLS, clientTLS := testTLSConfigs(t)
	serverTLS.NextProtos = []string{profile}
	listener, err := rawquic.Listen("127.0.0.1:0", serverTLS, limits)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	serverCh := make(chan carrier.Session, 1)
	errCh := make(chan error, 1)
	go func() {
		session, err := listener.Accept(context.Background())
		if err != nil {
			errCh <- err
			return
		}
		serverCh <- session
	}()
	clientTLS.NextProtos = []string{profile}
	client, err := rawquic.Dial(context.Background(), listener.Addr().String(), clientTLS, limits)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	var server carrier.Session
	select {
	case server = <-serverCh:
	case err := <-errCh:
		t.Fatalf("Accept: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("Accept timed out")
	}
	t.Cleanup(func() { _ = client.Close() })
	t.Cleanup(func() { _ = server.Close() })
	return client, server
}
