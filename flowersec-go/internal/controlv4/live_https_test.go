package controlv4

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

func liveHTTPSRequest() sessionv4.LiveAuthorizationRequest {
	return sessionv4.LiveAuthorizationRequest{Tenant: "tenant", Audience: "listener", CryptoProfile: "fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1", Issuer: [16]byte{1}, Lease: [16]byte{2}, Attempt: [16]byte{3}, Artifact: [32]byte{4}, ClientIdentity: [32]byte{5}, ServerIdentity: [32]byte{6}, Winner: protocolv4.PoolMember{Index: 15, CandidateID: [16]byte{7}, RouteDigest: [32]byte{8}}, ActivationNotAfterMS: 1000000, AttemptNo: 1}
}

func testLiveHTTPS(t *testing.T, handler http.Handler, customize func(*LiveHTTPSConfig)) (*LiveHTTPSTransport, *resourcev4.Root) {
	t.Helper()
	certificates := operationsTestCertificates(t)
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificates.server}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: certificates.roots}
	server.StartTLS()
	t.Cleanup(server.Close)
	c := LiveHTTPSConfig{HTTPS: HTTPSBootstrapConfig{BaseURL: server.URL + "/control", RemoteAddress: netip.MustParseAddrPort(server.Listener.Addr().String()), TLS: &tls.Config{RootCAs: certificates.roots, Certificates: []tls.Certificate{certificates.reader}}, HeaderBytes: 1024, Timeout: time.Second, RuntimeBytes: 65536, ProviderRuntimeBytes: 1 << 20}, RuntimeBytes: 4096}
	if customize != nil {
		customize(&c)
	}
	charge, err := LiveHTTPSTransportCharge(c)
	if err != nil {
		t.Fatal(err)
	}
	providerCharge, err := HTTPSBootstrapCharge(c.HTTPS)
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
	p, err := NewLiveHTTPSTransport(c, reserve(1, charge), reserve(2, providerCharge), reserve(3, resourcev4.Vector{resourcev4.SDKBytes: 65536}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		p.Close()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := p.WaitCleanup(ctx); err != nil {
			t.Error(err)
		}
	})
	return p, root
}

func TestLiveHTTPSAuthenticatedOriginalProjection(t *testing.T) {
	q := liveHTTPSRequest()
	codec, err := NewLiveAuthorizationCodec()
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	p, _ := testLiveHTTPS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != "POST" || r.URL.Path != "/control/live/authorize" || r.URL.RawQuery != "" || r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || r.Header.Get("Content-Type") != "application/cbor" || r.Header.Get("Cookie") != "" || r.Header.Get("Accept-Encoding") != "" || r.Header.Get("Cache-Control") != "no-store" || r.ContentLength > liveRequestBytes {
			t.Error("original authenticated request changed")
		}
		wire, err := io.ReadAll(io.LimitReader(r.Body, liveRequestBytes+1))
		if err != nil {
			t.Error(err)
		}
		got, err := codec.Decode(wire)
		if err != nil || got != q {
			t.Errorf("wrong request projection: %v", err)
		}
		// Transport preserves opaque proof bytes. Session separately enforces
		// signatures/current namespace; transport success is not authorization.
		w.Header().Set("Content-Type", "application/cbor")
		w.Header().Set("Content-Length", "1")
		_, _ = w.Write([]byte{0xa0})
	}), nil)
	dst := make([]byte, 4096)
	n, err := p.RequestAuthorization(context.Background(), q, dst)
	if err != nil || n != 1 || dst[0] != 0xa0 || calls.Load() != 1 {
		t.Fatal(n, err, calls.Load())
	}
	q.AttemptNo = 2
	if _, err := p.RequestAuthorization(context.Background(), q, dst); err == nil || calls.Load() != 1 {
		t.Fatal("retry request accepted", err)
	}
}

func TestLiveHTTPSRejectsUnboundedAndRedirectedResponses(t *testing.T) {
	for _, mode := range []string{"redirect", "oversize", "compressed", "chunked", "receipt-status"} {
		t.Run(mode, func(t *testing.T) {
			var calls atomic.Int32
			p, _ := testLiveHTTPS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				_, _ = io.Copy(io.Discard, r.Body)
				w.Header().Set("Content-Type", "application/cbor")
				w.Header().Set("Content-Length", "1")
				switch mode {
				case "redirect":
					w.Header().Set("Location", "/elsewhere")
					w.WriteHeader(http.StatusTemporaryRedirect)
				case "oversize":
					w.Header().Set("Content-Length", strconv.Itoa(4097))
				case "compressed":
					w.Header().Set("Content-Encoding", "gzip")
				case "chunked":
					w.Header().Del("Content-Length")
					w.(http.Flusher).Flush()
				case "receipt-status":
					w.WriteHeader(http.StatusConflict)
				}
				_, _ = w.Write([]byte{0xa0})
			}), nil)
			dst := bytes.Repeat([]byte{0xfe}, 4096)
			if n, err := p.RequestAuthorization(context.Background(), liveHTTPSRequest(), dst); err == nil || n != 0 || calls.Load() != 1 || !bytes.Equal(dst, make([]byte, 4096)) {
				t.Fatal(n, err, calls.Load())
			}
		})
	}
}

func TestLiveHTTPSCloseRetainsActualTLSCallback(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	var calls atomic.Int32
	p, root := testLiveHTTPS(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }), func(c *LiveHTTPSConfig) {
		c.HTTPS.TLS.VerifyConnection = func(tls.ConnectionState) error { close(entered); <-release; return nil }
	})
	dst := make([]byte, 4096)
	done := make(chan error, 1)
	go func() { _, err := p.RequestAuthorization(context.Background(), liveHTTPSRequest(), dst); done <- err }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("TLS callback not entered")
	}
	before := root.Snapshot()
	p.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := p.WaitCleanup(ctx); !errors.Is(err, context.DeadlineExceeded) || root.Snapshot() != before {
		t.Fatal("callback resource tail released", err)
	}
	once.Do(func() { close(release) })
	if err := <-done; err == nil || calls.Load() != 0 {
		t.Fatal("late callback published request", err, calls.Load())
	}
	if err := p.WaitCleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestLiveAuthorizationCodecRejectsNoncanonicalAndChangedRequest(t *testing.T) {
	c, err := NewLiveAuthorizationCodec()
	if err != nil {
		t.Fatal(err)
	}
	var dst [liveRequestBytes]byte
	n, err := EncodeLiveAuthorizationRequest(dst[:], liveHTTPSRequest())
	if err != nil {
		t.Fatal(err)
	}
	valid := bytes.Clone(dst[:n])
	for _, wire := range [][]byte{append(bytes.Clone(valid), 0), append([]byte{0x98, 13}, valid[1:]...), {0x80}, bytes.Repeat([]byte{0}, liveRequestBytes+1)} {
		if _, err := c.Decode(wire); err == nil {
			t.Fatal("invalid request accepted")
		}
	}
	valid[len(valid)-1] = 2
	if _, err := c.Decode(valid); err == nil {
		t.Fatal("second attempt accepted")
	}
	for _, name := range []string{"Tenant", "Audience", "Profile", "Index"} {
		q := liveHTTPSRequest()
		switch name {
		case "Tenant":
			q.Tenant = "Tenant"
		case "Audience":
			q.Audience = "bad\n"
		case "Profile":
			q.CryptoProfile = "future"
		case "Index":
			q.Winner.Index = 16
		}
		if _, err := EncodeLiveAuthorizationRequest(dst[:], q); err == nil {
			t.Fatal(name)
		}
	}
	if _, err := LiveHTTPSTransportCharge(LiveHTTPSConfig{RuntimeBytes: 1}); err == nil {
		t.Fatal("missing explicit client authentication accepted")
	}
}
