package protocolv4_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/controlv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

type httpIssueAuthority struct {
	client           [32]byte
	calls, commits   atomic.Int32
	entered, release chan struct{}
}

func (a *httpIssueAuthority) BeginDirectIssue(ctx context.Context, q protocolv4.DirectIssueRequest, _ protocolv4.DirectIssueFacts) (protocolv4.DirectIssuePermit, error) {
	digest, ok := controlv4.AuthenticatedDirectIssueClient(ctx)
	if !ok || digest != a.client || !bytes.Equal(q.Authentication, digest[:]) || q.RequestID == ([32]byte{}) {
		return nil, errors.New("unauthenticated test authority request")
	}
	a.calls.Add(1)
	if a.entered != nil {
		close(a.entered)
		<-a.release
	}
	return a, nil
}
func (*httpIssueAuthority) Check(ctx context.Context) error { return ctx.Err() }
func (a *httpIssueAuthority) Commit(ctx context.Context, digest [32]byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if digest == ([32]byte{}) {
		return errors.New("missing digest")
	}
	a.commits.Add(1)
	return nil
}
func (*httpIssueAuthority) Close() {}

func issuerHTTPCertificates(t *testing.T) (server, client, stranger tls.Certificate, roots *x509.CertPool) {
	t.Helper()
	key := func() *ecdsa.PrivateKey {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	caKey := key()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.UnixMilli(0), NotAfter: time.UnixMilli(6000), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots = x509.NewCertPool()
	roots.AddCert(ca)
	issue := func(serial int64, usage x509.ExtKeyUsage) tls.Certificate {
		k := key()
		c := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: time.UnixMilli(0), NotAfter: time.UnixMilli(5000), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
		if usage == x509.ExtKeyUsageServerAuth {
			c.IPAddresses = []net.IP{net.IPv4(127, 0, 0, 1)}
		}
		der, err := x509.CreateCertificate(rand.Reader, c, ca, &k.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
	}
	return issue(2, x509.ExtKeyUsageServerAuth), issue(3, x509.ExtKeyUsageClientAuth), issue(4, x509.ExtKeyUsageClientAuth), roots
}

func issueHTTPService(t *testing.T, a *httpIssueAuthority) (*controlv4.DirectIssueHTTPSService, *protocolv4.DirectIssueHTTPTestHarness, string, *http.Client, *http.Client) {
	t.Helper()
	serverCert, clientCert, strangerCert, roots := issuerHTTPCertificates(t)
	a.client = sha256.Sum256(clientCert.Certificate[0])
	h := protocolv4.NewDirectIssueHTTPTestHarness(t, a)
	c := controlv4.DirectIssueHTTPSConfig{Clock: h.Clock, ClientCertificateDER: clientCert.Certificate[0], RequestsPerMinute: 60, Burst: 10, WorkMS: 2000, RuntimeBytes: 16384}
	cost, err := controlv4.DirectIssueHTTPSServiceCharge(c)
	if err != nil {
		t.Fatal(err)
	}
	dep := h.Reserve(resourcev4.Vector{resourcev4.SDKBytes: 65536})
	t.Cleanup(dep.Release)
	s, err := controlv4.NewDirectIssueHTTPSService(h.Issuer, c, h.Reserve(cost), dep)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(s)
	server.TLS, err = controlv4.OperationsTLSConfig(serverCert, roots)
	if err != nil {
		t.Fatal(err)
	}
	server.TLS.Time = func() time.Time { return time.UnixMilli(1100) }
	server.StartTLS()
	t.Cleanup(server.Close)
	t.Cleanup(func() {
		s.Close()
		if err := s.WaitCleanup(context.Background()); err != nil {
			t.Error(err)
		}
	})
	client := func(cert tls.Certificate) *http.Client {
		transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13, Time: server.TLS.Time}, DisableKeepAlives: true}
		t.Cleanup(transport.CloseIdleConnections)
		return &http.Client{Transport: transport, Timeout: 3 * time.Second}
	}
	return s, h, server.URL, client(clientCert), client(strangerCert)
}

func issueHTTPBody() []byte { return append([]byte{0x81, 0x58, 0x20}, bytes.Repeat([]byte{1}, 32)...) }

func TestDirectIssueHTTPNativeIdentityAndOriginalCommit(t *testing.T) {
	a := &httpIssueAuthority{}
	_, h, base, client, stranger := issueHTTPService(t, a)
	for _, tc := range []struct {
		name, path string
		client     *http.Client
		body       []byte
		cookie     bool
		status     int
	}{
		{"stranger", "/issue/direct", stranger, issueHTTPBody(), false, http.StatusForbidden},
		{"wrong-path", "/issue/other", client, issueHTTPBody(), false, http.StatusBadRequest},
		{"cookie", "/issue/direct", client, issueHTTPBody(), true, http.StatusBadRequest},
		{"noncanonical", "/issue/direct", client, append([]byte{0x82}, issueHTTPBody()[1:]...), false, http.StatusBadRequest},
		{"oversize", "/issue/direct", client, append(issueHTTPBody(), 0), false, http.StatusBadRequest},
		{"success", "/issue/direct", client, issueHTTPBody(), false, http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, err := http.NewRequest(http.MethodPost, base+tc.path, bytes.NewReader(tc.body))
			if err != nil {
				t.Fatal(err)
			}
			r.Header.Set("Content-Type", "application/cbor")
			if tc.cookie {
				r.Header.Set("Cookie", "ambient=1")
			}
			response, err := tc.client.Do(r)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			body, err := io.ReadAll(io.LimitReader(response.Body, 65537))
			if err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != tc.status || response.Header.Get("Cache-Control") != "no-store" {
				t.Fatal(response.StatusCode)
			}
			if tc.status == http.StatusOK {
				if response.Header.Get("Content-Type") != "application/cbor" || response.ContentLength != int64(len(body)) || len(body) > 65536 {
					t.Fatal("wrong bounded response")
				}
				if err := h.Verify(body); err != nil {
					t.Fatal("not original signed Artifact", err)
				}
			} else if len(body) != 0 {
				t.Fatal("refusal leaked response material")
			}
		})
	}
	if a.calls.Load() != 1 || a.commits.Load() != 1 {
		t.Fatal("unauthenticated input reached issuer", a.calls.Load(), a.commits.Load())
	}
	if _, ok := controlv4.AuthenticatedDirectIssueClient(context.Background()); ok {
		t.Fatal("caller constructed authenticated context")
	}
}

func TestDirectIssueHTTPCloseJoinsActualAuthorityTail(t *testing.T) {
	a := &httpIssueAuthority{entered: make(chan struct{}), release: make(chan struct{})}
	var once sync.Once
	defer once.Do(func() { close(a.release) })
	s, _, base, client, _ := issueHTTPService(t, a)
	done := make(chan struct{})
	go func() {
		defer close(done)
		response, _ := client.Post(base+"/issue/direct", "application/cbor", bytes.NewReader(issueHTTPBody()))
		if response != nil {
			response.Body.Close()
		}
	}()
	select {
	case <-a.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("authority not entered")
	}
	s.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := s.WaitCleanup(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("authority tail released", err)
	}
	once.Do(func() { close(a.release) })
	if err := s.WaitCleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	<-done
	if a.calls.Load() != 1 || a.commits.Load() != 0 {
		t.Fatal("canceled authority revived publication")
	}
}

func TestDirectIssueHTTPSourceReturnsIndependentlyVerifiedLease(t *testing.T) {
	a := &httpIssueAuthority{}
	_, h, base, client, _ := issueHTTPService(t, a)
	i := h.SourceInputs()
	c := controlv4.DirectIssueSourceConfig{
		HTTPS: controlv4.HTTPSBootstrapConfig{BaseURL: base, RemoteAddress: netip.MustParseAddrPort(strings.TrimPrefix(base, "https://")), TLS: client.Transport.(*http.Transport).TLSClientConfig, HeaderBytes: 1024, Timeout: time.Second, RuntimeBytes: 65536, ProviderRuntimeBytes: 1 << 20},
		Root:  i.Root, Clock: h.Clock, Owner: i.Owner, Trust: i.Trust, ClientCertificate: i.Client, ServerCertificate: i.Server, ActivationSigningKeyID: i.ActivationKey, ApplicationProfile: i.ApplicationProfile, RPCMaxGeneralOutstanding: i.K, MapBytes: 65536, MapNodes: 16384, RuntimeBytes: 65536, LeaseRuntimeBytes: 8192,
	}
	charge, err := controlv4.DirectIssueSourceCharge(c)
	if err != nil {
		t.Fatal(err)
	}
	https, err := controlv4.HTTPSBootstrapCharge(c.HTTPS)
	if err != nil {
		t.Fatal(err)
	}
	dependencies := h.Reserve(resourcev4.Vector{resourcev4.SDKBytes: 65536})
	t.Cleanup(dependencies.Release)
	source, err := controlv4.NewDirectIssueSource(c, h.Reserve(charge), h.Reserve(https), dependencies)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		source.Close()
		if err := source.WaitCleanup(context.Background()); err != nil {
			t.Error(err)
		}
	})
	q := sessionv4.MaterialLeaseRequest{IdentityDigest: i.ClientIdentity, Tenant: i.Tenant, Audience: i.Audience, Profile: i.Profile, Role: protocolv4.ClientToServer, Requirements: sessionv4.MaterialRequirements{ApplicationProfile: i.ApplicationProfile, RPCMaxGeneralOutstanding: i.K}}
	wrong := q
	wrong.IdentityDigest[0] ^= 1
	if lease, err := source.AcquireLease(context.Background(), wrong); err == nil || lease != nil || a.calls.Load() != 0 {
		t.Fatal("wrong identity reached issuer", err)
	}
	lease, err := source.AcquireLease(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	if lease == nil || a.calls.Load() != 1 || a.commits.Load() != 1 {
		t.Fatal("original issuance did not complete")
	}
	source.Close()
	if err := source.WaitCleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := lease.WaitCleanup(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("source close destroyed transferred lease", err)
	}
	lease.Close()
	if err := lease.WaitCleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if lease, err := source.AcquireLease(context.Background(), q); err == nil || lease != nil || a.calls.Load() != 1 {
		t.Fatal("closed source issued again", err)
	}
}
