package flowersec

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestProxyNetworkPolicyRequiresIndependentNumericAuthority(t *testing.T) {
	for _, host := range []string{"127.1", "2130706433", "0177.0.0.1", "0x7f.0.0.1", "999999999999999999999999", "0xffffffffffffffffffffffff", "example.test.", "fe80::1%en0", "[::1]", "a..test"} {
		if _, err := compileProxyNetworkPolicy(host, "443", []string{"0.0.0.0/0", "::/0"}); err == nil {
			t.Fatalf("ambiguous authority accepted: %q", host)
		}
	}
	if _, err := compileProxyNetworkPolicy("example.test", "443", nil); err == nil {
		t.Fatal("DNS name alone granted a numeric network destination")
	}
	policy, err := compileProxyNetworkPolicy("::ffff:127.0.0.1", "80", []string{"127.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	if !policy.allows(netip.MustParseAddr("127.0.0.1")) || policy.allows(netip.MustParseAddr("127.0.0.2")) {
		t.Fatal("numeric authority was not pinned to its normalized address")
	}
	if _, err := compileProxyNetworkPolicy("example.test", "443", []string{"192.0.2.1/24"}); err == nil {
		t.Fatal("noncanonical network prefix accepted")
	}
}

func TestProxyOriginalResponseHeadersPrecedeNativeNormalization(t *testing.T) {
	for _, test := range []struct {
		name, headers string
		valid         bool
	}{
		{"hidden_length", "Content-Length: 2\r\nConnection: close, content-length\r\n", true},
		{"mixed_framing", "Content-Length: 2\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n", false},
		{"duplicate_singleton", "Content-Length: 2\r\nContent-Type: text/plain\r\nContent-Type: application/json\r\nConnection: close\r\n", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				connection, writer, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Error(err)
					return
				}
				defer connection.Close()
				_, _ = io.WriteString(writer, "HTTP/1.1 103 Early Hints\r\nLink: </style.css>\r\n\r\nHTTP/1.1 200 OK\r\n"+test.headers+"\r\nok")
				_ = writer.Flush()
			}))
			defer upstream.Close()
			server, err := NewProxyServer(ProxyServerOptions{Upstream: upstream.URL, UpstreamOrigin: upstream.URL})
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			response, err := server.httpClient.Get(upstream.URL)
			if !test.valid {
				if err == nil {
					_ = response.Body.Close()
					t.Fatal("invalid original headers accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if response.Header.Get("Connection") != "close, content-length" || response.ContentLength != 2 {
				t.Fatalf("original facts lost: %+v", response.Header)
			}
			for _, header := range proxyResponseHeaders(response.Header, server.config) {
				if header.Name == "content-length" {
					t.Fatal("Connection-nominated length leaked")
				}
			}
			body, err := io.ReadAll(response.Body)
			if err != nil || string(body) != "ok" {
				t.Fatalf("native body damaged: %q %v", body, err)
			}
		})
	}
}

// Real DNS answers exercise the whole-answer gate before the native TCP dial.
func proxyTestResolver(t *testing.T, addresses ...netip.Addr) *net.Resolver {
	t.Helper()
	socket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		var input [2048]byte
		for {
			n, peer, err := socket.ReadFrom(input[:])
			if err != nil {
				return
			}
			var parser dnsmessage.Parser
			header, err := parser.Start(input[:n])
			if err != nil {
				continue
			}
			question, err := parser.Question()
			if err != nil {
				continue
			}
			builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: header.ID, Response: true, Authoritative: true, RecursionAvailable: true})
			_ = builder.StartQuestions()
			_ = builder.Question(question)
			_ = builder.StartAnswers()
			for _, address := range addresses {
				resource := dnsmessage.ResourceHeader{Name: question.Name, Class: dnsmessage.ClassINET, TTL: 60}
				if question.Type == dnsmessage.TypeA && address.Is4() {
					_ = builder.AResource(resource, dnsmessage.AResource{A: address.As4()})
				} else if question.Type == dnsmessage.TypeAAAA && address.Is6() {
					_ = builder.AAAAResource(resource, dnsmessage.AAAAResource{AAAA: address.As16()})
				}
			}
			response, err := builder.Finish()
			if err == nil {
				_, _ = socket.WriteTo(response, peer)
			}
		}
	}()
	t.Cleanup(func() { _ = socket.Close(); <-done })
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "udp", socket.LocalAddr().String())
	}}
}

func TestProxyNetworkPolicyRejectsMixedDNSBeforeDial(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	policy, err := compileProxyNetworkPolicy("proxy.test", port, []string{"127.0.0.1/32"})
	if err != nil {
		t.Fatal(err)
	}
	policy.resolver = proxyTestResolver(t, netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("192.0.2.1"))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if connection, err := policy.dialContext(ctx, "tcp", net.JoinHostPort("proxy.test", port)); err == nil {
		_ = connection.Close()
		t.Fatal("mixed DNS answer reached a TCP socket")
	}
	_ = listener.(*net.TCPListener).SetDeadline(time.Now().Add(20 * time.Millisecond))
	if connection, err := listener.Accept(); err == nil {
		_ = connection.Close()
		t.Fatal("a forbidden answer was filtered after dialing")
	}
}

func TestProxyHTTPClientConnDoesNotReplayReusedRequest(t *testing.T) {
	var requests atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		if requests.Add(1) == 2 {
			connection, _, err := writer.(http.Hijacker).Hijack()
			if err == nil {
				_ = connection.Close()
			}
			return
		}
		_, _ = io.WriteString(writer, "ok")
	}))
	defer upstream.Close()
	server, err := NewProxyServer(ProxyServerOptions{Upstream: upstream.URL, UpstreamOrigin: upstream.URL, MaxConcurrentHTTPStreams: 1, MaxConcurrentEventStreams: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	response, err := server.httpClient.Get(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	request, _ := http.NewRequest(http.MethodGet, upstream.URL, nil)
	request.Header.Set("Idempotency-Key", "must-not-authorize-a-replay")
	response, err = server.httpClient.Do(request)
	if err == nil {
		_ = response.Body.Close()
		t.Fatal("an uncertain reused-connection failure was replayed")
	}
	if requests.Load() != 2 {
		t.Fatalf("upstream requests = %d", requests.Load())
	}
}

func TestProxyHTTPPoolOwnsBodiesAndIgnoresAmbientProxy(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("ALL_PROXY", "http://127.0.0.1:1")
	var connections atomic.Int32
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(writer, "ok")
	}))
	upstream.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	upstream.Start()
	defer upstream.Close()
	server, err := NewProxyServer(ProxyServerOptions{Upstream: upstream.URL, UpstreamOrigin: upstream.URL, MaxConcurrentHTTPStreams: 1, MaxConcurrentEventStreams: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	response, err := server.httpClient.Get(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	if extra, err := server.httpClient.Get(upstream.URL); err == nil {
		_ = extra.Body.Close()
		t.Fatal("headers refunded a live response body's pool slot")
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	response, err = server.httpClient.Get(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	if connections.Load() != 1 {
		t.Fatalf("keep-alive connections = %d", connections.Load())
	}
}

func TestProxyNumericDialPreservesLogicalTLSIdentity(t *testing.T) {
	observedSNI := make(chan string, 1)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		observedSNI <- request.TLS.ServerName
		_, _ = io.WriteString(writer, request.Host)
	}))
	defer upstream.Close()
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(upstream.URL, "https://"))
	logicalURL := "https://example.com:" + port // httptest's certificate includes example.com.
	server, err := NewProxyServer(ProxyServerOptions{Upstream: logicalURL, UpstreamOrigin: logicalURL, AllowedUpstreamHosts: []string{"example.com"}, AllowedUpstreamAddresses: []string{"127.0.0.1"}})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	server.config.network.resolver = proxyTestResolver(t, netip.MustParseAddr("127.0.0.1"))
	roots := x509.NewCertPool()
	roots.AddCert(upstream.Certificate())
	server.httpClient.Transport.(*proxyHTTPTransport).native.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	response, err := server.httpClient.Get(logicalURL)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	sni := <-observedSNI
	if err != nil || sni != "example.com" || string(body) != "example.com:"+port {
		t.Fatalf("logical TLS/HTTP identity lost: SNI=%q Host=%q err=%v", sni, body, err)
	}
}
