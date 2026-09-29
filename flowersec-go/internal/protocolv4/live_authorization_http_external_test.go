package protocolv4_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/controlv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

type liveHTTPSHost struct {
	h                 *protocolv4.LiveAuthorizationHTTPTestHarness
	identity          ledgerv4.SQLiteIdentity
	client            [32]byte
	callbacks, closed atomic.Int32
	policyErr         error
	denied            bool
	entered, release  chan struct{}
}

func (h *liveHTTPSHost) Check(i ledgerv4.SQLiteIdentity, _ uint64, _ bool) error {
	if i != h.identity {
		return ledgerv4.ErrFenced
	}
	return nil
}
func (h *liveHTTPSHost) CheckLiveAuthorizationShare(i ledgerv4.SQLiteIdentity, rate, burst uint16) error {
	if i != h.identity || rate != 60 || burst != 20 {
		return ledgerv4.ErrDenied
	}
	return nil
}
func (h *liveHTTPSHost) AcquireLiveAuthorization(ctx context.Context, principal [32]byte, q sessionv4.LiveAuthorizationRequest) (controlv4.LiveAuthorizationAccess, error) {
	f := h.h.Fields
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if principal != h.client || q.Tenant != f.Tenant || q.ClientIdentity != f.ClientIdentity || q.Audience != f.Audience || q.Artifact != f.Artifact {
		return nil, ledgerv4.ErrDenied
	}
	return &liveHTTPSAccess{host: h}, nil
}

type liveHTTPSAccess struct {
	host   *liveHTTPSHost
	closed bool
}

func (a *liveHTTPSAccess) Material() (controlv4.LiveAuthorizationMaterial, error) {
	h := a.host.h
	return controlv4.LiveAuthorizationMaterial{Plan: h.Plan, Artifact: h.Artifact, Trust: h.Trust, Deadline: h.Deadline}, nil
}
func (a *liveHTTPSAccess) Check(ctx context.Context) error {
	if a.closed {
		return ledgerv4.ErrOwner
	}
	return ctx.Err()
}
func (a *liveHTTPSAccess) CheckLiveSpend(i ledgerv4.SQLiteIdentity, f protocolv4.LiveActivationFields) error {
	if i != a.host.identity || f != a.host.h.Fields {
		return ledgerv4.ErrDenied
	}
	return nil
}
func (a *liveHTTPSAccess) Authorize(ctx context.Context) (bool, error) {
	h := a.host
	h.callbacks.Add(1)
	if h.entered != nil {
		close(h.entered)
		<-h.release
	}
	return !h.denied, h.policyErr
}
func (a *liveHTTPSAccess) Close() { a.closed = true; a.host.closed.Add(1) }

type liveHTTPFixture struct {
	t         *testing.T
	h         *protocolv4.LiveAuthorizationHTTPTestHarness
	host      *liveHTTPSHost
	backing   *ledgerv4.SQLiteBacking
	store     *ledgerv4.SQLiteStore
	limits    ledgerv4.SQLiteLimits
	transport *controlv4.LiveHTTPSTransport
}

func newLiveHTTPFixture(t *testing.T) *liveHTTPFixture {
	t.Helper()
	h := protocolv4.NewLiveAuthorizationHTTPTestHarness(t)
	f := &liveHTTPFixture{t: t, h: h, limits: ledgerv4.SQLiteLimits{MaxPages: 256, MaxRecords: 16, MaxRecordBytes: 65536, RuntimeBytes: 65536, ProviderRuntimeBytes: 1 << 20, DiskOverheadBytes: 65536}}
	f.host = &liveHTTPSHost{h: h, identity: ledgerv4.SQLiteIdentity{Authority: h.Fields.Authority, StoreID: [32]byte{67}, Generation: 1}}
	cost, err := ledgerv4.SQLiteBackingCharge(f.limits)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "live-authorization.db")
	f.backing, err = ledgerv4.NewSQLiteBacking(path, f.limits, h.Reserve(cost), h.Environment)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		closeDirectSQLite(t, f.store)
		f.backing.Close()
		for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
			if err := os.Remove(path + suffix); err != nil && !os.IsNotExist(err) {
				t.Error(err)
			}
		}
		if err := f.backing.ReleaseRemoved(); err != nil {
			t.Error(err)
		}
	})
	cost, err = ledgerv4.SQLiteStoreCharge(f.limits)
	if err != nil {
		t.Fatal(err)
	}
	f.store, err = ledgerv4.CreateSQLite(context.Background(), f.backing, f.host.identity, f.host, h.Reserve(cost), h.Environment)
	if err != nil {
		t.Fatal(err)
	}
	return f
}
func (f *liveHTTPFixture) request() sessionv4.LiveAuthorizationRequest {
	x := f.h.Fields
	return sessionv4.LiveAuthorizationRequest{Tenant: x.Tenant, Audience: x.Audience, CryptoProfile: x.Profile, Issuer: x.Issuer, Lease: x.Lease, Attempt: x.Attempt, Artifact: x.Artifact, ClientIdentity: x.ClientIdentity, ServerIdentity: x.ServerIdentity, Winner: x.Winner, ActivationNotAfterMS: x.ActivationEnd, AttemptNo: 1}
}
func (f *liveHTTPFixture) serve() (*controlv4.LiveAuthorizationHTTPSService, string, *http.Client, *http.Client) {
	t := f.t
	t.Helper()
	serverCert, clientCert, strangerCert, roots := issuerHTTPCertificates(t)
	f.host.client = sha256.Sum256(clientCert.Certificate[0])
	c := controlv4.LiveAuthorizationHTTPSConfig{Store: f.store, Clock: f.h.Clock, Host: f.host, ClientCertificateDER: clientCert.Certificate[0], MaxRecordBytes: f.limits.MaxRecordBytes, RequestsPerMinute: 60, Burst: 20, WorkMS: 2000, RuntimeBytes: 65536}
	service, spend, invoke, reader, read, err := controlv4.LiveAuthorizationHTTPSServiceCharges(c)
	if err != nil {
		t.Fatal(err)
	}
	p, err := controlv4.NewLiveAuthorizationHTTPSService(c, f.h.Reserve(service), f.h.Reserve(spend), f.h.Reserve(invoke), f.h.Reserve(reader), f.h.Reserve(read), f.h.Environment)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(p)
	server.TLS, err = controlv4.OperationsTLSConfig(serverCert, roots)
	if err != nil {
		t.Fatal(err)
	}
	server.TLS.Time = func() time.Time { return time.UnixMilli(1100) }
	server.StartTLS()
	t.Cleanup(server.Close)
	clientConfig := controlv4.LiveHTTPSConfig{HTTPS: controlv4.HTTPSBootstrapConfig{BaseURL: server.URL, RemoteAddress: netip.MustParseAddrPort(server.Listener.Addr().String()), TLS: &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{clientCert}, Time: server.TLS.Time}, HeaderBytes: 1024, Timeout: 2 * time.Second, RuntimeBytes: 65536, ProviderRuntimeBytes: 1 << 20}, RuntimeBytes: 4096}
	clientCost, err := controlv4.LiveHTTPSTransportCharge(clientConfig)
	if err != nil {
		t.Fatal(err)
	}
	providerCost, err := controlv4.HTTPSBootstrapCharge(clientConfig.HTTPS)
	if err != nil {
		t.Fatal(err)
	}
	f.transport, err = controlv4.NewLiveHTTPSTransport(clientConfig, f.h.Reserve(clientCost), f.h.Reserve(providerCost), f.h.Environment)
	if err != nil {
		t.Fatal(err)
	}
	transport := f.transport
	t.Cleanup(func() {
		transport.Close()
		if err := transport.WaitCleanup(context.Background()); err != nil {
			t.Error(err)
		}
	})
	t.Cleanup(func() {
		p.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := p.WaitCleanup(ctx); err != nil {
			t.Error(err)
		}
	})
	client := func(cert tls.Certificate) *http.Client {
		tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13, Time: server.TLS.Time}, DisableKeepAlives: true}
		t.Cleanup(tr.CloseIdleConnections)
		return &http.Client{Transport: tr, Timeout: 3 * time.Second}
	}
	return p, server.URL, client(clientCert), client(strangerCert)
}
func liveHTTPRequest(t *testing.T, client *http.Client, base string, q sessionv4.LiveAuthorizationRequest) (int, []byte) {
	t.Helper()
	var wire [1024]byte
	n, err := controlv4.EncodeLiveAuthorizationRequest(wire[:], q)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Post(base+"/live/authorize", "application/cbor", bytes.NewReader(wire[:n]))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 65537))
	if err != nil {
		t.Fatal(err)
	}
	if response.Header.Get("Cache-Control") != "no-store" || response.ContentLength != int64(len(body)) {
		t.Fatal("unbounded response")
	}
	if response.StatusCode != 200 && len(body) != 0 {
		t.Fatal("failure leaked material")
	}
	if response.StatusCode == 200 && response.Header.Get("Content-Type") != "application/cbor" {
		t.Fatal("wrong response type")
	}
	return response.StatusCode, body
}
func TestLiveAuthorizationHTTPOriginalSQLiteAndReadOnlyDuplicates(t *testing.T) {
	f := newLiveHTTPFixture(t)
	p, base, client, stranger := f.serve()
	q := f.request()
	if status, _ := liveHTTPRequest(t, stranger, base, q); status != http.StatusForbidden {
		t.Fatal(status)
	}
	wrong := q
	wrong.Winner.CandidateID[0] ^= 1
	if status, _ := liveHTTPRequest(t, client, base, wrong); status != http.StatusConflict {
		t.Fatal(status)
	}
	original := make([]byte, 4096)
	n, err := f.transport.RequestAuthorization(context.Background(), q, original)
	if err != nil {
		t.Fatal("native transport to original SQLite service", err)
	}
	original = original[:n]
	if err := f.h.Verify(original); err != nil {
		t.Fatal("not the original signed plan", err)
	}
	status, duplicate := liveHTTPRequest(t, client, base, q)
	if status != http.StatusOK || !bytes.Equal(original, duplicate) || f.host.callbacks.Load() != 1 {
		t.Fatal("duplicate reran policy or changed material", status, f.host.callbacks.Load())
	}
	wrong = q
	wrong.Attempt[0] ^= 1
	if status, _ := liveHTTPRequest(t, client, base, wrong); status != http.StatusConflict {
		t.Fatal(status)
	}
	p.Close()
	if err := p.WaitCleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	closeDirectSQLite(t, f.store)
	cost, err := ledgerv4.SQLiteStoreCharge(f.limits)
	if err != nil {
		t.Fatal(err)
	}
	f.store, err = ledgerv4.OpenSQLite(context.Background(), f.backing, f.host.identity, f.host, f.h.Reserve(cost), f.h.Environment)
	if err != nil {
		t.Fatal(err)
	}
	_, base, client, _ = f.serve()
	status, duplicate = liveHTTPRequest(t, client, base, q)
	if status != http.StatusOK || !bytes.Equal(original, duplicate) || f.host.callbacks.Load() != 1 {
		t.Fatal("restart changed original result", status)
	}
	f.h.RevokeIssuer(t)
	if status, _ := liveHTTPRequest(t, client, base, q); status == http.StatusOK {
		t.Fatal("current revocation ignored")
	}
	if f.host.callbacks.Load() != 1 {
		t.Fatal("revocation reran policy")
	}
}
func TestLiveAuthorizationHTTPDeniedAndUnknownNeverRedispatch(t *testing.T) {
	for _, outcome := range []string{"denied", "unknown"} {
		t.Run(outcome, func(t *testing.T) {
			f := newLiveHTTPFixture(t)
			f.host.denied = outcome == "denied"
			if outcome == "unknown" {
				f.host.policyErr = errors.New("private policy failure")
			}
			_, base, client, _ := f.serve()
			status, _ := liveHTTPRequest(t, client, base, f.request())
			if outcome == "denied" && status != 403 || outcome == "unknown" && status != 503 {
				t.Fatal(status)
			}
			status, _ = liveHTTPRequest(t, client, base, f.request())
			if status != 409 || f.host.callbacks.Load() != 1 {
				t.Fatal("terminal result redispatched", status, f.host.callbacks.Load())
			}
		})
	}
}
func TestLiveAuthorizationHTTPCancellationRetainsActualPolicyTail(t *testing.T) {
	f := newLiveHTTPFixture(t)
	f.host.entered, f.host.release = make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(f.host.release) })
	p, base, client, _ := f.serve()
	q := f.request()
	done := make(chan struct{})
	go func() {
		defer close(done)
		var wire [1024]byte
		n, _ := controlv4.EncodeLiveAuthorizationRequest(wire[:], q)
		response, _ := client.Post(base+"/live/authorize", "application/cbor", bytes.NewReader(wire[:n]))
		if response != nil {
			response.Body.Close()
		}
	}()
	select {
	case <-f.host.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("policy did not start")
	}
	if status, _ := liveHTTPRequest(t, client, base, q); status != 429 {
		t.Fatal("concurrent waiter entered", status)
	}
	p.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := p.WaitCleanup(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("tail released before callback exit", err)
	}
	once.Do(func() { close(f.host.release) })
	if err := p.WaitCleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	<-done
	_, base, client, _ = f.serve()
	if status, _ := liveHTTPRequest(t, client, base, q); status != 409 || f.host.callbacks.Load() != 1 {
		t.Fatal("cancelled spend redispatched", status)
	}
}
