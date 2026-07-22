package webtransport_test

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
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/carrier"
	"github.com/floegence/flowersec/flowersec-go/carrier/webtransport"
	"github.com/quic-go/quic-go/http3"
)

func TestBindSessionLimitsUsesExactPhysicalCapacity(t *testing.T) {
	limits, err := webtransport.BindSessionLimits(webtransport.DefaultLimits(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if limits.MaxInboundStreams != 3 {
		t.Fatalf("physical inbound streams = %d, want 3", limits.MaxInboundStreams)
	}
}

func TestCloseWithErrorContextAcceptsNilContext(t *testing.T) {
	client, _ := newSessionPair(t, webtransport.PathDirect)
	_ = client.CloseWithErrorContext(nil, carrier.ApplicationError{Reason: "test close"})
}

func TestURLRegistryRejectsCrossPathAndAmbientURLFeatures(t *testing.T) {
	valid := []string{
		"https://example.test" + webtransport.PathDirect,
		"https://example.test:8443" + webtransport.PathTunnel,
	}
	for _, rawURL := range valid {
		if err := webtransport.ValidateURL(rawURL); err != nil {
			t.Fatalf("ValidateURL(%q): %v", rawURL, err)
		}
	}
	invalid := []string{
		"http://example.test" + webtransport.PathDirect,
		"https://example.test/flowersec/v2/direct",
		"https://example.test" + webtransport.PathDirect + "?token=secret",
		"https://user@example.test" + webtransport.PathTunnel,
		"https://example.test" + webtransport.PathTunnel + "#fragment",
	}
	for _, rawURL := range invalid {
		if err := webtransport.ValidateURL(rawURL); !errors.Is(err, webtransport.ErrInvalidURL) {
			t.Fatalf("ValidateURL(%q) error = %v", rawURL, err)
		}
	}
}

func TestServerRequiresExplicitOriginPolicy(t *testing.T) {
	serverTLS, _ := testTLSConfigs(t)
	if _, err := webtransport.NewServer(serverTLS, webtransport.DefaultLimits(), nil); !errors.Is(err, webtransport.ErrOriginPolicyRequired) {
		t.Fatalf("NewServer nil Origin policy error = %v", err)
	}
}

func TestDialerAndServerRejectTLSAuthenticationBypass(t *testing.T) {
	_, clientTLS := testTLSConfigs(t)

	missingCertificate := &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{http3.NextProtoH3}}
	if _, err := webtransport.NewServer(missingCertificate, webtransport.DefaultLimits(), func(*http.Request) bool { return true }); !errors.Is(err, webtransport.ErrInvalidTLS) {
		t.Fatalf("NewServer missing certificate error = %v, want ErrInvalidTLS", err)
	}
	serverTLS, _ := testTLSConfigs(t)
	serverTLS.Certificates = append([]tls.Certificate(nil), serverTLS.Certificates...)
	serverTLS.Certificates[0].PrivateKey = nil
	if _, err := webtransport.NewServer(serverTLS, webtransport.DefaultLimits(), func(*http.Request) bool { return true }); !errors.Is(err, webtransport.ErrInvalidTLS) {
		t.Fatalf("NewServer missing private key error = %v, want ErrInvalidTLS", err)
	}

	missingRoots := clientTLS.Clone()
	missingRoots.RootCAs = nil
	if _, err := webtransport.NewDialer(missingRoots, webtransport.DefaultLimits()); !errors.Is(err, webtransport.ErrInvalidTLS) {
		t.Fatalf("NewDialer missing roots error = %v, want ErrInvalidTLS", err)
	}
	emptyRoots := clientTLS.Clone()
	emptyRoots.RootCAs = x509.NewCertPool()
	if _, err := webtransport.NewDialer(emptyRoots, webtransport.DefaultLimits()); !errors.Is(err, webtransport.ErrInvalidTLS) {
		t.Fatalf("NewDialer empty roots error = %v, want ErrInvalidTLS", err)
	}

	insecure := clientTLS.Clone()
	insecure.InsecureSkipVerify = true
	if _, err := webtransport.NewDialer(insecure, webtransport.DefaultLimits()); !errors.Is(err, webtransport.ErrInvalidTLS) {
		t.Fatalf("NewDialer insecure verification error = %v, want ErrInvalidTLS", err)
	}
}

func TestDialRejectsWrongHostnameAndTrustRoot(t *testing.T) {
	serverTLS, clientTLS := testTLSConfigs(t)
	server, err := webtransport.NewServer(serverTLS, webtransport.DefaultLimits(), func(*http.Request) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	server.SetHandler(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		session, upgradeErr := server.Upgrade(writer, request)
		if upgradeErr == nil {
			_ = session.Close()
		}
	}))
	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(udpConn) }()
	defer func() {
		_ = server.Close()
		_ = udpConn.Close()
		select {
		case <-serveDone:
		case <-time.After(5 * time.Second):
			t.Error("WebTransport server did not stop")
		}
	}()
	port := udpConn.LocalAddr().(*net.UDPAddr).Port
	target := (&url.URL{Scheme: "https", Host: net.JoinHostPort("localhost", fmt.Sprint(port)), Path: webtransport.PathDirect}).String()

	for name, mutate := range map[string]func(*tls.Config){
		"wrong_hostname": func(config *tls.Config) { config.ServerName = "not-localhost.example" },
		"wrong_trust_root": func(config *tls.Config) {
			_, unrelatedClient := testTLSConfigs(t)
			config.RootCAs = unrelatedClient.RootCAs
		},
	} {
		t.Run(name, func(t *testing.T) {
			config := clientTLS.Clone()
			mutate(config)
			dialer, err := webtransport.NewDialer(config, webtransport.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			defer dialer.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if session, err := dialer.Dial(ctx, target, "https://client.example"); err == nil {
				_ = session.Close()
				t.Fatalf("Dial with %s unexpectedly succeeded", name)
			}
		})
	}
}

func TestNativeBidirectionalStreamRoundTrip(t *testing.T) {
	client, server := newSessionPair(t, webtransport.PathDirect)
	if client.Kind() != carrier.KindWebTransport || server.Kind() != carrier.KindWebTransport {
		t.Fatalf("carrier kind = %q/%q", client.Kind(), server.Kind())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	accepted := make(chan carrier.Stream, 1)
	errCh := make(chan error, 1)
	go func() {
		stream, err := server.AcceptStream(ctx)
		if err != nil {
			errCh <- err
			return
		}
		accepted <- stream
	}()
	clientStream, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	defer clientStream.Close()
	if _, err := clientStream.Write([]byte("webtransport-native")); err != nil {
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
	case err := <-errCh:
		t.Fatalf("AcceptStream: %v", err)
	case <-ctx.Done():
		t.Fatal("AcceptStream timed out")
	}
	defer serverStream.Close()
	payload, err := io.ReadAll(serverStream)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(payload) != "webtransport-native" {
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

func TestSessionPathMatchesExactConnectPath(t *testing.T) {
	for _, testCase := range []struct {
		path string
		want carrier.Path
	}{
		{path: webtransport.PathDirect, want: carrier.PathDirect},
		{path: webtransport.PathTunnel, want: carrier.PathTunnel},
	} {
		t.Run(testCase.path, func(t *testing.T) {
			client, server := newSessionPair(t, testCase.path)
			if client.Path() != testCase.want || server.Path() != testCase.want {
				t.Fatalf("carrier path = %q/%q, want %q", client.Path(), server.Path(), testCase.want)
			}
		})
	}
}

func TestAdapterSourceDoesNotExposeDatagramsOrReferenceYamux(t *testing.T) {
	_, testFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(testFile), "webtransport.go"))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	source := string(raw)
	if strings.Contains(strings.ToLower(source), "yamux") {
		t.Fatal("WebTransport adapter must not reference Yamux")
	}
	for _, forbidden := range []string{"func (session *Session) SendDatagram", "func (session *Session) ReceiveDatagram"} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("WebTransport adapter exposes forbidden API %q", forbidden)
		}
	}
	for _, forbidden := range []string{"func NewQUICConfig(", "func NewServerQUICConfig("} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("WebTransport public API must not expose quic-go Config builder %q", forbidden)
		}
	}
	if strings.Contains(source, "strings.Contains(rawURL, PathTunnel)") {
		t.Fatal("WebTransport path binding must use the parsed exact CONNECT path")
	}
	if !regexp.MustCompile(`DialAddr:\s+quic\.DialAddr`).MatchString(source) {
		t.Fatal("WebTransport adapter no longer overrides the dependency's early dial default")
	}
}

func newSessionPair(t *testing.T, path string) (carrier.Session, carrier.Session) {
	t.Helper()
	serverTLS, clientTLS := testTLSConfigs(t)
	server, err := webtransport.NewServer(serverTLS, webtransport.DefaultLimits(), func(request *http.Request) bool {
		return request.Header.Get("Origin") == "https://client.example"
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	serverSession := make(chan carrier.Session, 1)
	serverErr := make(chan error, 1)
	server.SetHandler(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		session, err := server.Upgrade(writer, request)
		if err != nil {
			serverErr <- err
			return
		}
		serverSession <- session
	}))
	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.Serve(udpConn) }()
	t.Cleanup(func() {
		_ = server.Close()
		_ = udpConn.Close()
		select {
		case <-serveErr:
		case <-time.After(5 * time.Second):
			t.Error("WebTransport server did not stop")
		}
	})

	dialer, err := webtransport.NewDialer(clientTLS, webtransport.DefaultLimits())
	if err != nil {
		t.Fatalf("NewDialer: %v", err)
	}
	t.Cleanup(func() { _ = dialer.Close() })
	address := udpConn.LocalAddr().(*net.UDPAddr)
	target := (&url.URL{Scheme: "https", Host: net.JoinHostPort("localhost", strings.Split(address.String(), ":")[1]), Path: path}).String()
	client, err := dialer.Dial(context.Background(), target, "https://client.example")
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	var accepted carrier.Session
	select {
	case accepted = <-serverSession:
	case err := <-serverErr:
		t.Fatalf("Upgrade: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("server session timed out")
	}
	t.Cleanup(func() { _ = client.Close() })
	t.Cleanup(func() { _ = accepted.Close() })
	return client, accepted
}

func testTLSConfigs(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
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
	server := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}, NextProtos: []string{http3.NextProtoH3}}
	client := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, ServerName: "localhost", NextProtos: []string{http3.NextProtoH3}}
	return server, client
}
