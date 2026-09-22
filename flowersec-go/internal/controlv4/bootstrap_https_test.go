package controlv4

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

func testHTTPSBootstrap(t *testing.T, handler http.Handler, customize func(*HTTPSBootstrapConfig)) (*HTTPSBootstrapProvider, *resourcev4.Root) {
	t.Helper()
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("numeric adapter supports Darwin and Linux")
	}
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	certs := x509.NewCertPool()
	certs.AddCert(server.Certificate())
	cfg := HTTPSBootstrapConfig{BaseURL: server.URL + "/revocation", RemoteAddress: netip.MustParseAddrPort(server.Listener.Addr().String()), TLS: &tls.Config{RootCAs: certs}, HeaderBytes: 1024, Timeout: time.Second, RuntimeBytes: 65536, ProviderRuntimeBytes: 1 << 20}
	if customize != nil {
		customize(&cfg)
	}
	charge, err := HTTPSBootstrapCharge(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var limit resourcev4.Vector
	for i := range limit {
		limit[i] = 1 << 30
	}
	root, err := resourcev4.NewRoot(resourcev4.Config{ProfileRevision: [32]byte{1}, Limit: limit, AccountSlots: 4, ReservationSlots: 8, ReferenceSlots: 32})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(root.Close)
	reserve := func(id byte, cost resourcev4.Vector) resourcev4.Reference {
		ref, err := root.Reserve(resourcev4.OwnerKey{ProfileRevision: [32]byte{1}, Environment: [16]byte{1}, Instance: [16]byte{id}, Backing: [16]byte{id}, Kind: 1}, cost)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(ref.Release)
		return ref
	}
	dependencies := reserve(1, resourcev4.Vector{resourcev4.SDKBytes: 4096})
	borrow, err := dependencies.Borrow()
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewHTTPSBootstrapProvider(cfg, reserve(2, charge), borrow)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		p.Close()
		if err := p.Retire(); err != nil {
			t.Error(err)
		}
	})
	return p, root
}

func bootstrapRequest() protocolv4.NamespaceBootstrapRequest {
	return protocolv4.NamespaceBootstrapRequest{Tenant: "tenant-1", Authority: "revocation-1", Nonce: [32]byte{1}}
}

func TestHTTPSBootstrapUsesOriginalHTTPSControlQueries(t *testing.T) {
	var requests atomic.Int32
	p, _ := testHTTPSBootstrap(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Proto != "HTTP/1.1" || r.TLS == nil || r.TLS.Version != tls.VersionTLS13 || r.Method != "GET" || r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" || r.Header.Get("Accept-Encoding") != "" {
			t.Error("unexpected transport or ambient authorization")
		}
		if r.Header.Get("Cache-Control") != "no-store" {
			t.Error("bootstrap cache not disabled")
		}
		q := r.URL.Query()
		switch r.URL.Path {
		case "/revocation/bootstrap":
			if q.Get("tenant_id") != "tenant-1" || q.Get("revocation_authority_id") != "revocation-1" || q.Get("nonce") != "01"+strings.Repeat("00", 31) {
				t.Error("query lost original association")
			}
		case "/revocation/state":
			if q.Get("digest") != "02"+strings.Repeat("00", 31) || q.Get("encoded_bytes") != "4" {
				t.Error("content request not original")
			}
		default:
			t.Error("wrong endpoint")
		}
		w.Header().Set("Content-Type", "application/cbor")
		w.Header().Set("Content-Length", "4")
		_, _ = w.Write([]byte{1, 2, 3, 4})
	}), nil)
	output := make([]byte, 128)
	if n, err := p.Query(context.Background(), bootstrapRequest(), output); err != nil || n != 4 || !bytes.Equal(output[:n], []byte{1, 2, 3, 4}) {
		t.Fatal(n, err)
	}
	if n, err := p.Fetch(context.Background(), protocolv4.NamespaceContent{Digest: [32]byte{2}, EncodedBytes: 4}, output[:4:4]); err != nil || n != 4 {
		t.Fatal(n, err)
	}
	if requests.Load() != 2 {
		t.Fatal("unexpected retry or extra control read")
	}
}

func TestHTTPSBootstrapOrdinaryRefreshUsesIndependentSignedReads(t *testing.T) {
	var requests atomic.Int32
	p, _ := testHTTPSBootstrap(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path != "/revocation/trust" && r.URL.Path != "/revocation/head" {
			t.Error("refresh reused bootstrap or content endpoint")
		}
		query := r.URL.Query()
		if len(query) != 2 || query.Get("tenant_id") != "tenant-1" || query.Get("revocation_authority_id") != "revocation-1" {
			t.Error("refresh lookup changed the installed namespace")
		}
		w.Header().Set("Content-Type", "application/cbor")
		w.Header().Set("Content-Length", "4")
		_, _ = w.Write([]byte{1, 2, 3, 4})
	}), nil)
	query := protocolv4.NamespaceRefreshRequest{Tenant: "tenant-1", Authority: "revocation-1"}
	for _, read := range []func(context.Context, protocolv4.NamespaceRefreshRequest, []byte) (int, error){p.Trust, p.Head} {
		out := make([]byte, 128)
		if n, err := read(context.Background(), query, out); n != 4 || err != nil || !bytes.Equal(out[:4], []byte{1, 2, 3, 4}) {
			t.Fatal("ordinary control read failed", n, err)
		}
	}
	if requests.Load() != 2 {
		t.Fatal("invented extra physical attempts")
	}
}

func TestHTTPSBootstrapRejectsUnboundedOrRedirectedResponse(t *testing.T) {
	cases := map[string]string{
		"redirect":     "HTTP/1.1 302 Found\r\nLocation: https://example.invalid/\r\nContent-Length: 0\r\n\r\n",
		"chunked":      "HTTP/1.1 200 OK\r\nContent-Type: application/cbor\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
		"compressed":   "HTTP/1.1 200 OK\r\nContent-Type: application/cbor\r\nContent-Encoding: gzip\r\nContent-Length: 1\r\n\r\nx",
		"too_large":    "HTTP/1.1 200 OK\r\nContent-Type: application/cbor\r\nContent-Length: 99999\r\n\r\n",
		"no_length":    "HTTP/1.1 200 OK\r\nContent-Type: application/cbor\r\n\r\nx",
		"truncated":    "HTTP/1.1 200 OK\r\nContent-Type: application/cbor\r\nContent-Length: 4\r\n\r\nx",
		"header_limit": "HTTP/1.1 200 OK\r\nLong-Header: " + strings.Repeat("x", 2048) + "\r\nContent-Length: 1\r\n\r\nx",
	}
	for name, wire := range cases {
		t.Run(name, func(t *testing.T) {
			var count atomic.Int32
			p, _ := testHTTPSBootstrap(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				count.Add(1)
				conn, output, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Error(err)
					return
				}
				defer conn.Close()
				_, _ = output.WriteString(wire)
				_ = output.Flush()
			}), nil)
			output := make([]byte, 128)
			if n, err := p.Query(context.Background(), bootstrapRequest(), output); err == nil || n != 0 {
				t.Fatal("invalid response accepted", n, err)
			}
			if count.Load() != 1 {
				t.Fatal("unexpected retry/redirect")
			}
		})
	}
}

func TestHTTPSBootstrapCloseRetainsActualTLSCallback(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	p, root := testHTTPSBootstrap(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { t.Error("request after cancellation") }), func(c *HTTPSBootstrapConfig) {
		c.TLS.VerifyConnection = func(tls.ConnectionState) error { close(entered); <-release; return nil }
	})
	done := make(chan error, 1)
	go func() { _, err := p.Query(context.Background(), bootstrapRequest(), make([]byte, 128)); done <- err }()
	<-entered
	before := root.Snapshot()
	if _, err := p.Query(context.Background(), bootstrapRequest(), make([]byte, 128)); !errors.Is(err, ErrBusy) {
		t.Fatal("second physical read admitted", err)
	}
	p.Close()
	if err := p.Retire(); !errors.Is(err, ErrBusy) || root.Snapshot() != before {
		t.Fatal("blocked callback no longer charged", err)
	}
	select {
	case <-done:
		t.Fatal("returned before TLS callback exit")
	default:
	}
	close(release)
	if err := <-done; !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
	if err := p.Retire(); err != nil {
		t.Fatal(err)
	}
}

func TestHTTPSBootstrapCancellationClosesOriginalBodyRead(t *testing.T) {
	entered := make(chan struct{})
	p, _ := testHTTPSBootstrap(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/cbor")
		w.Header().Set("Content-Length", "4")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		close(entered)
		<-r.Context().Done()
	}), nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := p.Query(ctx, bootstrapRequest(), make([]byte, 128)); done <- err }()
	<-entered
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("original body read did not exit")
	}
}

func TestHTTPSBootstrapFetchRequiresExactOriginalLength(t *testing.T) {
	p, _ := testHTTPSBootstrap(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/cbor")
		w.Header().Set("Content-Length", "1")
		_, _ = fmt.Fprint(w, "x")
	}), nil)
	if n, err := p.Fetch(context.Background(), protocolv4.NamespaceContent{EncodedBytes: 4}, make([]byte, 4)); err == nil || n != 0 {
		t.Fatal("truncated original content accepted", n, err)
	}
}
