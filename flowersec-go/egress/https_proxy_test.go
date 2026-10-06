package egress_test

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/egress"
)

func proxyFixture(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *tls.Config) {
	t.Helper()
	server := httptest.NewUnstartedServer(handler)
	server.EnableHTTP2 = false
	server.StartTLS()
	t.Cleanup(server.Close)
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	return server, &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}
}

func TestHTTPSProxyPreservesTargetTLSAndResolvesAtProxy(t *testing.T) {
	var requests atomic.Int32
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "runtime-cloud.invalid" || r.Header.Get("X-Test") != "end-to-end" {
			t.Errorf("target request was changed: host=%q", r.Host)
		}
		_, _ = io.WriteString(w, "cloud response")
	}))
	defer target.Close()
	proxy, trust := proxyFixture(t, func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != http.MethodConnect || r.Host != "runtime-cloud.invalid:443" {
			t.Errorf("unexpected CONNECT: %s %s", r.Method, r.Host)
			http.Error(w, "denied", http.StatusForbidden)
			return
		}
		upstream, err := net.Dial("tcp", target.Listener.Addr().String())
		if err != nil {
			t.Error(err)
			return
		}
		defer upstream.Close()
		client, buffered, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer client.Close()
		_, _ = buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
		_ = buffered.Flush()
		done := make(chan struct{})
		go func() { _, _ = io.Copy(upstream, buffered); _ = upstream.Close(); close(done) }()
		_, _ = io.Copy(client, upstream)
		_ = client.Close()
		<-done
	})
	dialer, err := egress.NewHTTPSProxy(egress.HTTPSProxyOptions{URL: proxy.URL, TLSConfig: trust})
	if err != nil {
		t.Fatal(err)
	}
	transport := dialer.HTTPTransport()
	defer transport.CloseIdleConnections()
	// The fixture certificate covers example.com; the request authority stays intact.
	targetRoots := x509.NewCertPool()
	targetRoots.AddCert(target.Certificate())
	transport.TLSClientConfig = &tls.Config{RootCAs: targetRoots, ServerName: "example.com", MinVersion: tls.VersionTLS13}
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	request, _ := http.NewRequest(http.MethodGet, "https://runtime-cloud.invalid/", nil)
	request.Header.Set("X-Test", "end-to-end")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil || string(body) != "cloud response" || requests.Load() != 1 {
		t.Fatalf("response=%q err=%v requests=%d", body, err, requests.Load())
	}
	transport.CloseIdleConnections()
	transport.TLSClientConfig = &tls.Config{RootCAs: targetRoots, ServerName: "wrong.invalid", MinVersion: tls.VersionTLS13}
	if response, err := client.Do(request); err == nil {
		response.Body.Close()
		t.Fatal("target TLS verification bypassed")
	}
}

func TestHTTPSProxyRejectsInvalidPolicy(t *testing.T) {
	var zero egress.HTTPSProxy
	if zero.Valid() {
		t.Fatal("zero-value proxy accepted")
	}
	if _, err := zero.DialContext(t.Context(), "tcp", "cloud.invalid:443"); !errors.Is(err, egress.ErrInvalidProxy) {
		t.Fatalf("zero-value dial error=%v", err)
	}
	for _, raw := range []string{"http://proxy.test", "https://user:secret@proxy.test", "https://proxy.test/path", "https://proxy.test?secret=x", "https://proxy.test#fragment", "https://proxy.test:0", "https://proxy.test:99999"} {
		t.Run(raw, func(t *testing.T) {
			if _, err := egress.NewHTTPSProxy(egress.HTTPSProxyOptions{URL: raw}); !errors.Is(err, egress.ErrInvalidProxy) {
				t.Fatalf("err=%v", err)
			}
		})
	}
	for _, config := range []*tls.Config{{InsecureSkipVerify: true}, {ServerName: "other.test"}, {MinVersion: tls.VersionTLS10}, {MaxVersion: tls.VersionTLS12}} {
		if _, err := egress.NewHTTPSProxy(egress.HTTPSProxyOptions{URL: "https://proxy.test", TLSConfig: config}); !errors.Is(err, egress.ErrInvalidProxy) {
			t.Fatalf("invalid TLS accepted: %v", err)
		}
	}
}

func TestHTTPSProxyAuthenticatesClientAndServerIndependently(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, public, private)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	clientRoots := x509.NewCertPool()
	clientRoots.AddCert(certificate)
	var authenticated atomic.Int32
	proxy := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.TLS.VerifiedChains) == 0 {
			t.Error("client certificate was not verified")
		}
		authenticated.Add(1)
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
	}))
	proxy.TLS = &tls.Config{ClientCAs: clientRoots, ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: tls.VersionTLS13}
	proxy.StartTLS()
	defer proxy.Close()
	serverRoots := x509.NewCertPool()
	serverRoots.AddCert(proxy.Certificate())
	clientCertificate := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: private}
	for _, test := range []struct {
		name        string
		trust       *tls.Config
		wantSuccess bool
	}{
		{"mutual authentication", &tls.Config{RootCAs: serverRoots, Certificates: []tls.Certificate{clientCertificate}}, true},
		{"missing client identity", &tls.Config{RootCAs: serverRoots}, false},
		{"untrusted proxy", &tls.Config{RootCAs: x509.NewCertPool(), Certificates: []tls.Certificate{clientCertificate}}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			route, err := egress.NewHTTPSProxy(egress.HTTPSProxyOptions{URL: proxy.URL, TLSConfig: test.trust})
			if err != nil {
				t.Fatal(err)
			}
			conn, err := route.DialContext(t.Context(), "tcp", "cloud.invalid:443")
			if conn != nil {
				conn.Close()
			}
			if (err == nil) != test.wantSuccess {
				t.Fatalf("dial error=%v, success wanted=%v", err, test.wantSuccess)
			}
		})
	}
	if authenticated.Load() != 1 {
		t.Fatalf("authenticated requests=%d", authenticated.Load())
	}
}

func TestHTTPSProxyDoesNotFallBackAndRedactsErrors(t *testing.T) {
	var direct atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { direct.Add(1) }))
	defer target.Close()
	for _, status := range []int{http.StatusProxyAuthRequired, http.StatusForbidden, http.StatusBadGateway} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			proxy, trust := proxyFixture(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(status)
				_, _ = io.WriteString(w, "secret proxy diagnostics")
			})
			dialer, err := egress.NewHTTPSProxy(egress.HTTPSProxyOptions{URL: proxy.URL, TLSConfig: trust})
			if err != nil {
				t.Fatal(err)
			}
			_, err = dialer.DialContext(t.Context(), "tcp", target.Listener.Addr().String())
			if !errors.Is(err, egress.ErrProxyConnection) || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), target.Listener.Addr().String()) {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
	if direct.Load() != 0 {
		t.Fatal("proxy failure fell back to direct")
	}
}

func TestHTTPSProxyCancellationClosesHandshake(t *testing.T) {
	closed := make(chan struct{})
	accepted := make(chan struct{})
	proxy, trust := proxyFixture(t, func(w http.ResponseWriter, _ *http.Request) {
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		close(accepted)
		_, _ = io.Copy(io.Discard, conn)
		close(closed)
	})
	dialer, err := egress.NewHTTPSProxy(egress.HTTPSProxyOptions{URL: proxy.URL, TLSConfig: trust})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	result := make(chan error, 1)
	go func() { _, err := dialer.DialContext(ctx, "tcp", "cloud.invalid:443"); result <- err }()
	select {
	case <-accepted:
	case <-time.After(3 * time.Second):
		t.Fatal("CONNECT not received")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err=%v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("canceled dial stalled")
	}
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("canceled connection leaked")
	}
}

func TestHTTPSProxyPreservesBytesBufferedAfterConnect(t *testing.T) {
	proxy, trust := proxyFixture(t, func(w http.ResponseWriter, _ *http.Request) {
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\nhello\n")
		_, _ = io.Copy(io.Discard, conn)
	})
	dialer, err := egress.NewHTTPSProxy(egress.HTTPSProxyOptions{URL: proxy.URL, TLSConfig: trust})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := dialer.DialContext(t.Context(), "tcp", "cloud.invalid:443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	got, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil || got != "hello\n" {
		t.Fatalf("got=%q err=%v", got, err)
	}
}
