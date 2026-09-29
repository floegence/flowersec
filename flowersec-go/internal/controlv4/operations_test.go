package controlv4

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/diagnosticv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

type operationsCertificates struct {
	roots                    *x509.CertPool
	server, reader, stranger tls.Certificate
}

func operationsTestCertificates(t *testing.T) operationsCertificates {
	t.Helper()
	key := func() *ecdsa.PrivateKey {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	caKey := key()
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "operations test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	issue := func(serial int64, usage x509.ExtKeyUsage) tls.Certificate {
		k := key()
		template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "private-management-identity"},
			NotBefore: now.Add(-time.Minute), NotAfter: now.Add(30 * time.Minute), KeyUsage: x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{usage}}
		if usage == x509.ExtKeyUsageServerAuth {
			template.IPAddresses = []net.IP{net.IPv4(127, 0, 0, 1)}
		}
		der, err := x509.CreateCertificate(rand.Reader, template, ca, &k.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		leaf, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k, Leaf: leaf}
	}
	return operationsCertificates{roots, issue(2, x509.ExtKeyUsageServerAuth), issue(3, x509.ExtKeyUsageClientAuth), issue(4, x509.ExtKeyUsageClientAuth)}
}

type operationsFixture struct {
	p            *OperationsService
	root         *resourcev4.Root
	environment  *sessionv4.Environment
	config       OperationsConfig
	dependencies resourcev4.Reference
	tick         *atomic.Uint64
	next         byte
	t            *testing.T
}

func (f *operationsFixture) reserve(environment byte, cost resourcev4.Vector) resourcev4.Reference {
	f.t.Helper()
	f.next++
	ref, err := f.root.Reserve(resourcev4.OwnerKey{ProfileRevision: [32]byte{1}, Environment: [16]byte{environment},
		Instance: [16]byte{f.next}, Backing: [16]byte{f.next}, Kind: 1}, cost)
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(ref.Release)
	return ref
}

func operationsTestFixture(t *testing.T, certificates operationsCertificates, change func(*OperationsConfig)) *operationsFixture {
	t.Helper()
	var limit resourcev4.Vector
	for i := range limit {
		limit[i] = 1 << 30
	}
	root, err := resourcev4.NewRoot(resourcev4.Config{ProfileRevision: [32]byte{1}, Limit: limit,
		AccountSlots: 4, ReservationSlots: 32, ReferenceSlots: 96})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		root.Close()
		if snapshot := root.Snapshot(); !snapshot.CleanupComplete || snapshot.References != 0 {
			t.Error("resource tail", snapshot)
		}
	})
	tick := &atomic.Uint64{}
	clock, err := timev4.NewClock(timev4.Profile{Rate: timev4.Rate{Denominator: 1000}, MaxWidthMS: 10, MaxAgeMS: 3600000, MaxRoundTripMS: 1000},
		func() (timev4.Tick, error) {
			return timev4.Tick{Milliseconds: tick.Load(), Incarnation: [16]byte{1}}, nil
		})
	if err != nil {
		t.Fatal(err)
	}
	mark, err := clock.Monotonic()
	if err != nil {
		t.Fatal(err)
	}
	now := uint64(time.Now().UnixMilli())
	if err := clock.InstallTrusted(mark, timev4.Interval{LowerMS: now, UpperMS: now + 1}); err != nil {
		t.Fatal(err)
	}
	f := &operationsFixture{t: t, root: root, tick: tick}
	f.dependencies = f.reserve(1, resourcev4.Vector{resourcev4.SDKBytes: 65536})
	ec := sessionv4.EnvironmentConfig{Positions: 2, RuntimeBytes: 65536}
	ecost, err := sessionv4.EnvironmentCharge(ec)
	if err != nil {
		t.Fatal(err)
	}
	f.environment, err = sessionv4.NewEnvironment(ec, f.reserve(1, ecost), f.dependencies)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		f.environment.Close()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := f.environment.WaitCleanup(ctx); err != nil {
			t.Error(err)
			return
		}
		if err := f.environment.Retire(); err != nil {
			t.Error(err)
		}
	})
	f.config = OperationsConfig{Root: root, Environment: f.environment, Clock: clock,
		Readers:        []OperationsReader{{CertificateDER: certificates.reader.Certificate[0]}},
		RuntimeProfile: "go-managed", ProviderFamily: "wss", FeatureProfile: "transport", RequestsPerMinute: 60,
		CallMS: 1000, RuntimeBytes: 65536}
	if change != nil {
		change(&f.config)
	}
	cost, err := OperationsServiceCharge(f.config)
	if err != nil {
		t.Fatal(err)
	}
	f.p, err = NewOperationsService(f.config, f.reserve(1, cost), f.dependencies)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		f.p.Close()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := f.p.WaitCleanup(ctx); err != nil {
			t.Error(err)
		}
	})
	return f
}

func operationsTestRequest(certificate tls.Certificate) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "https://localhost/operations", nil)
	r.RemoteAddr = "127.0.0.1:12345"
	r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true,
		PeerCertificates: []*x509.Certificate{certificate.Leaf}, VerifiedChains: [][]*x509.Certificate{{certificate.Leaf}}}
	return r
}

type operationsTestWriter struct {
	*httptest.ResponseRecorder
	deadline func(time.Time)
	write    func()
}

func (w *operationsTestWriter) SetWriteDeadline(d time.Time) error {
	if w.deadline != nil {
		w.deadline(d)
	}
	return nil
}
func (w *operationsTestWriter) Write(b []byte) (int, error) {
	if w.write != nil {
		w.write()
	}
	return w.ResponseRecorder.Write(b)
}
func operationsWriter() *operationsTestWriter {
	return &operationsTestWriter{ResponseRecorder: httptest.NewRecorder()}
}

func TestOperationsNativeTLSAndKeepaliveRevocation(t *testing.T) {
	certificates := operationsTestCertificates(t)
	f := operationsTestFixture(t, certificates, nil)
	config, err := OperationsTLSConfig(certificates.server, certificates.roots)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(f.p)
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.TLS = config
	server.StartTLS()
	defer server.Close()
	client := func(certificate *tls.Certificate, version uint16) *http.Client {
		cfg := &tls.Config{RootCAs: certificates.roots, MinVersion: version, MaxVersion: version}
		if certificate != nil {
			cfg.Certificates = []tls.Certificate{*certificate}
		}
		transport := &http.Transport{TLSClientConfig: cfg, DisableCompression: true}
		t.Cleanup(transport.CloseIdleConnections)
		return &http.Client{Transport: transport, Timeout: 2 * time.Second}
	}
	for _, c := range []*http.Client{client(nil, tls.VersionTLS13), client(&certificates.reader, tls.VersionTLS12)} {
		response, err := c.Get(server.URL + "/operations")
		if response != nil {
			response.Body.Close()
		}
		if err == nil {
			t.Fatal("invalid native TLS authentication succeeded")
		}
	}
	response, err := client(&certificates.stranger, tls.VersionTLS13).Get(server.URL + "/operations")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatal("unregistered same-CA reader admitted", response.StatusCode)
	}
	c := client(&certificates.reader, tls.VersionTLS13)
	response, err = c.Get(server.URL + "/operations")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, OperationsResponseBytes+1))
	response.Body.Close()
	if err != nil || response.StatusCode != http.StatusOK || len(body) > OperationsResponseBytes || response.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("invalid bounded snapshot", response.StatusCode, err)
	}
	var snapshot operationsSnapshot
	if err := json.Unmarshal(body, &snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot.Environment.Positions != 2 || snapshot.Resources.ProfileRevision != [32]byte{1} || snapshot.Metrics[diagnosticv4.MetricConnectionAttempt].Metric != "connection_attempt" || snapshot.MetricDimensions.Duration[diagnosticv4.DurationUnder10MS] != "lt_10ms" || snapshot.ResourceDimensions[resourcev4.SDKBytes] != "sdk_bytes" {
		t.Fatal("aggregate dimensions lost")
	}
	for _, secret := range []string{"private-management-identity", "certificate", "tenant", "endpoint", "correlation_id", "localhost", "127.0.0.1"} {
		if bytes.Contains(body, []byte(secret)) {
			t.Fatal("sensitive output field", secret)
		}
	}
	if err := f.p.RevokeReader(0); err != nil {
		t.Fatal(err)
	}
	reused := false
	request, _ := http.NewRequest(http.MethodGet, server.URL+"/operations", nil)
	request = request.WithContext(httptrace.WithClientTrace(request.Context(), &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) { reused = info.Reused }}))
	response, err = c.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if !reused || response.StatusCode != http.StatusForbidden {
		t.Fatal("keepalive retained revoked authority", reused, response.StatusCode)
	}
}

func TestOperationsQueriesAndDenialsShareRateCap(t *testing.T) {
	certificates := operationsTestCertificates(t)
	f := operationsTestFixture(t, certificates, func(c *OperationsConfig) { c.RequestsPerMinute = 2 })
	for i, mutate := range []func(*http.Request){
		func(r *http.Request) { r.URL.RawQuery = "fields=secret" },
		func(r *http.Request) { r.RemoteAddr = "192.0.2.1:1000" },
		func(*http.Request) {},
	} {
		r := operationsTestRequest(certificates.reader)
		mutate(r)
		w := operationsWriter()
		f.p.ServeHTTP(w, r)
		if w.Code != []int{400, 403, 429}[i] {
			t.Fatal("request bypassed rate/auth cap", i, w.Code)
		}
	}
	f.tick.Store(60000)
	w := operationsWriter()
	f.p.ServeHTTP(w, operationsTestRequest(certificates.reader))
	if w.Code != 200 {
		t.Fatal("original finite rate window failed", w.Code)
	}
	if f.p.denied.Load() != 1 || f.p.capacity.Load() != 1 {
		t.Fatal("aggregate denial counts lost")
	}
}

func TestOperationsRejectsRequestShapesAndUntrustedConnections(t *testing.T) {
	certificates := operationsTestCertificates(t)
	f := operationsTestFixture(t, certificates, nil)
	cases := map[string]struct {
		change func(*http.Request)
		status int
	}{
		"method":             {func(r *http.Request) { r.Method = http.MethodPost }, 400},
		"route":              {func(r *http.Request) { r.URL.Path = "/audit" }, 400},
		"encoded-route":      {func(r *http.Request) { r.URL.RawPath = "/%6fperations" }, 400},
		"empty-query":        {func(r *http.Request) { r.URL.ForceQuery = true }, 400},
		"body":               {func(r *http.Request) { r.Body = io.NopCloser(strings.NewReader("x")) }, 400},
		"length":             {func(r *http.Request) { r.ContentLength = 1 }, 400},
		"chunked":            {func(r *http.Request) { r.TransferEncoding = []string{"chunked"} }, 400},
		"no-tls":             {func(r *http.Request) { r.TLS = nil }, 403},
		"old-tls":            {func(r *http.Request) { r.TLS.Version = tls.VersionTLS12 }, 403},
		"unverified":         {func(r *http.Request) { r.TLS.VerifiedChains = nil }, 403},
		"different-verified": {func(r *http.Request) { r.TLS.VerifiedChains[0][0] = certificates.stranger.Leaf }, 403},
		"mapped-loopback":    {func(r *http.Request) { r.RemoteAddr = "[::ffff:127.0.0.1]:1000" }, 403},
	}
	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			r := operationsTestRequest(certificates.reader)
			test.change(r)
			w := operationsWriter()
			f.p.ServeHTTP(w, r)
			if w.Code != test.status || strings.Contains(w.Body.String(), "resources") {
				t.Fatal("invalid request queried snapshot", w.Code)
			}
		})
	}
	w := httptest.NewRecorder()
	f.p.ServeHTTP(w, operationsTestRequest(certificates.reader))
	if w.Code != 503 {
		t.Fatal("unbounded writer accepted")
	}
	f.tick.Store(31 * 60 * 1000)
	w = httptest.NewRecorder()
	f.p.ServeHTTP(w, operationsTestRequest(certificates.reader))
	if w.Code != 403 {
		t.Fatal("expired registered certificate reused", w.Code)
	}
}

func TestOperationsRevocationDuringExternalDeadlinePreventsQuery(t *testing.T) {
	certificates := operationsTestCertificates(t)
	f := operationsTestFixture(t, certificates, nil)
	w := operationsWriter()
	w.deadline = func(d time.Time) {
		if !d.IsZero() {
			if err := f.p.RevokeReader(0); err != nil {
				t.Error(err)
			}
		}
	}
	f.p.ServeHTTP(w, operationsTestRequest(certificates.reader))
	if w.Code != 403 || strings.Contains(w.Body.String(), "resources") {
		t.Fatal("revoked response published", w.Code)
	}
}

func TestOperationsCloseRetainsOriginalBlockedResponse(t *testing.T) {
	certificates := operationsTestCertificates(t)
	f := operationsTestFixture(t, certificates, nil)
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	w := operationsWriter()
	w.write = func() { close(entered); <-release }
	go func() { defer close(done); f.p.ServeHTTP(w, operationsTestRequest(certificates.reader)) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("response not reached")
	}
	before := f.root.Snapshot()
	other := operationsWriter()
	f.p.ServeHTTP(other, operationsTestRequest(certificates.reader))
	if other.Code != 429 {
		close(release)
		t.Fatal("second snapshot position admitted")
	}
	f.p.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	err := f.p.WaitCleanup(ctx)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) || f.root.Snapshot() != before {
		close(release)
		t.Fatal("logical close refunded running writer", err)
	}
	close(release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("response did not return")
	}
	if err := f.p.WaitCleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if after := f.root.Snapshot(); after.Charged[resourcev4.SDKBytes] >= before.Charged[resourcev4.SDKBytes] {
		t.Fatal("actual writer exit did not release charge")
	}
	if f.p.config.Root != nil || f.p.readers[0] != (operationsReader{}) {
		t.Fatal("closed service retained owner or identity graph")
	}
}

func TestOperationsRootEnvironmentAndRegistrationValidation(t *testing.T) {
	certificates := operationsTestCertificates(t)
	f := operationsTestFixture(t, certificates, nil)
	for name, change := range map[string]func(*OperationsConfig){
		"root":             func(c *OperationsConfig) { c.Root = &resourcev4.Root{} },
		"duplicate-reader": func(c *OperationsConfig) { c.Readers = append([]OperationsReader{}, c.Readers[0], c.Readers[0]) },
		"bad-certificate":  func(c *OperationsConfig) { c.Readers = []OperationsReader{{CertificateDER: []byte{0}}} },
		"uncanonical-network": func(c *OperationsConfig) {
			c.ManagementNetworks = []netip.Prefix{netip.MustParsePrefix("192.0.2.1/24")}
		},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := f.config
			change(&cfg)
			cost, err := OperationsServiceCharge(cfg)
			if err != nil {
				t.Fatal(err)
			}
			p, err := NewOperationsService(cfg, f.reserve(1, cost), f.dependencies)
			if p != nil {
				p.Close()
			}
			if err == nil {
				t.Fatal("invalid registration accepted")
			}
		})
	}
	cost, err := OperationsServiceCharge(f.config)
	if err != nil {
		t.Fatal(err)
	}
	foreign := f.reserve(2, resourcev4.Vector{resourcev4.SDKBytes: 65536})
	if p, err := NewOperationsService(f.config, f.reserve(2, cost), foreign); err == nil {
		p.Close()
		t.Fatal("wrong Environment admitted")
	}
	f.environment.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := f.environment.WaitCleanup(ctx); err != nil {
		t.Fatal(err)
	}
	if err := f.environment.Retire(); err != nil {
		t.Fatal(err)
	}
	w := operationsWriter()
	f.p.ServeHTTP(w, operationsTestRequest(certificates.reader))
	if w.Code != 200 {
		t.Fatal("closed Environment unavailable to management", w.Code)
	}
	var snapshot operationsSnapshot
	if err := json.Unmarshal(w.Body.Bytes(), &snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot.Environment.Positions != 2 || snapshot.Environment.Active != 0 || !snapshot.Environment.Closed || !snapshot.Environment.CleanupComplete {
		t.Fatal("retirement erased configured caps or fabricated activity")
	}
}

func TestOperationsMaximumAggregateEncodingFitsOutputCap(t *testing.T) {
	// Saturated counters and full-width integers cost more JSON bytes than any
	// running deployment. Keep the complete current registry in this boundary.
	var counts diagnosticv4.Counts
	counts.Total = ^uint64(0)
	for i := range counts.State {
		counts.State[i] = ^uint64(0)
	}
	for i := range counts.Phase {
		counts.Phase[i] = ^uint64(0)
	}
	for i := range counts.Code {
		counts.Code[i] = ^uint64(0)
	}
	for i := range counts.Duration {
		counts.Duration[i] = ^uint64(0)
	}
	for i := range counts.Attempt {
		counts.Attempt[i] = ^uint64(0)
	}
	s := operationsSnapshot{Revision: "flowersec-operations-1", ObservedUTCMS: ^uint64(0), RuntimeProfile: strings.Repeat("x", 64), ProviderFamily: strings.Repeat("x", 64), FeatureProfile: strings.Repeat("x", 64),
		MetricDimensions: diagnosticv4.CounterDimensions(), ResourceDimensions: resourcev4.DimensionNames(), Denied: ^uint64(0), CapacityRejected: ^uint64(0)}
	for i := range s.Metrics {
		s.Metrics[i] = operationsMetric{Metric: diagnosticv4.Metric(i).String(), Counts: counts}
	}
	for i := range s.Resources.Peak {
		s.Resources.Peak[i], s.Resources.Charged[i], s.Resources.Limit[i] = ^uint64(0), ^uint64(0), ^uint64(0)
	}
	for i := range s.Resources.ProfileRevision {
		s.Resources.ProfileRevision[i] = 255
	}
	s.Resources.Reservations, s.Resources.References, s.Resources.ResultOwners = ^uint32(0), ^uint32(0), ^uint32(0)
	// The optional owners are substantially smaller than the remaining encoded
	// headroom; exercise every registered slot as well as the full metric bank.
	s.Executor = &sessionv4.ExecutorOperationsSnapshot{}
	s.Stores = make([]operationsStoreSnapshot, 8)
	for i := range s.Stores {
		s.Stores[i] = operationsStoreSnapshot{Slot: uint8(i), State: "unavailable", ReadDuration: "100_999ms", Audit: &ledgerv4.AuditStatus{Sequence: ^uint64(0), ObservedUTCMS: ^uint64(0)}}
	}
	body, err := json.Marshal(s)
	if err != nil || len(body) > OperationsResponseBytes-8192 {
		t.Fatal("bounded snapshot lacks optional-field headroom", len(body), err)
	}
}
