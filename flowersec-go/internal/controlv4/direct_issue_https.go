package controlv4

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

type directIssueClientContextKey struct{}
type directIssueClientContext struct{ digest [32]byte }

// AuthenticatedDirectIssueClient returns the actual client identity installed
// by this HTTPS service after native mutual TLS and trusted-time checks. The
// authority's authentication hook compares it with the request envelope and
// applies its own tenant, identity, issuance and namespace-read permissions.
// An arbitrary context or caller-constructed envelope cannot install this key.
func AuthenticatedDirectIssueClient(ctx context.Context) ([32]byte, bool) {
	if ctx == nil {
		return [32]byte{}, false
	}
	v, ok := ctx.Value(directIssueClientContextKey{}).(directIssueClientContext)
	return v.digest, ok
}

type DirectIssueHTTPSConfig struct {
	Clock                    *timev4.Clock
	ClientCertificateDER     []byte
	RequestsPerMinute, Burst uint16
	WorkMS, RuntimeBytes     uint64
}

type artifactByteIssuer interface {
	IssueArtifactBytes(context.Context, protocolv4.ArtifactIssueRequest, []byte) (int, error)
	ReferenceFor(*timev4.Clock, resourcev4.Reference) (resourcev4.Reference, error)
}

// DirectIssueHTTPSService mounts one issuer and one fixed client registration
// at POST /issue/direct. The native listener, TLS roots, header limits and
// connection/task capacity are separately owned host dependencies. Require
// mutual TLS 1.3 and disable session tickets on that listener. This service
// additionally pins the verified client certificate and checks its complete
// validity against trusted time. It does not start a listener or trust headers.
//
// The request is the canonical CBOR array [request_id: bytes32], exactly 35
// bytes. No identity, candidate or authority can be selected by that body. A
// successful response is the original signed Artifact as application/cbor,
// only after the issuer's durable obligation and exact digest commit succeed.
type DirectIssueHTTPSService struct {
	mu                                   sync.Mutex
	issuer                               artifactByteIssuer
	path                                 string
	c                                    DirectIssueHTTPSConfig
	client                               [32]byte
	notBefore, notAfter                  uint64
	origin                               timev4.Mark
	creditedMS, credit                   uint64
	reservation, shared, issuerReference resourcev4.Reference
	request                              [35]byte
	response                             []byte
	cancel                               context.CancelFunc
	done                                 chan struct{}
	busy, closed, cleaned                bool
}

func DirectIssueHTTPSServiceCharge(c DirectIssueHTTPSConfig) (resourcev4.Vector, error) {
	if c.Clock == nil || len(c.ClientCertificateDER) == 0 || len(c.ClientCertificateDER) > 16384 || c.RequestsPerMinute == 0 || c.RequestsPerMinute > 600 || c.Burst == 0 || c.Burst > c.RequestsPerMinute || c.WorkMS == 0 || c.WorkMS > 2000 || c.RuntimeBytes == 0 {
		return resourcev4.Vector{}, resourcev4.ErrConfiguration
	}
	return (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(DirectIssueHTTPSService{})) + controlCallContextBytes + uint64(unsafe.Sizeof(timev4.Window{})) + 65536 + 4*16384, resourcev4.Items: 1, resourcev4.WorkSlots: 1, resourcev4.Tasks: 1, resourcev4.Timers: 2}).Add(resourcev4.Vector{resourcev4.SDKBytes: c.RuntimeBytes})
}

func NewDirectIssueHTTPSService(issuer *protocolv4.DirectIssuer, c DirectIssueHTTPSConfig, reservation, dependencies resourcev4.Reference) (*DirectIssueHTTPSService, error) {
	return newArtifactIssueHTTPSService(issuer, "/issue/direct", c, reservation, dependencies)
}

// NewArtifactIssueHTTPSService exposes the general immutable issuer at the
// distinct /issue/artifact endpoint, with the same original bounded mTLS call.
func NewArtifactIssueHTTPSService(issuer *protocolv4.ArtifactIssuer, c DirectIssueHTTPSConfig, reservation, dependencies resourcev4.Reference) (*DirectIssueHTTPSService, error) {
	return newArtifactIssueHTTPSService(issuer, "/issue/artifact", c, reservation, dependencies)
}

func newArtifactIssueHTTPSService(issuer artifactByteIssuer, path string, c DirectIssueHTTPSConfig, reservation, dependencies resourcev4.Reference) (*DirectIssueHTTPSService, error) {
	cost, err := DirectIssueHTTPSServiceCharge(c)
	if err != nil {
		return nil, err
	}
	if err = reservation.CheckSameEnvironment(dependencies); err != nil {
		return nil, err
	}
	owned, err := reservation.Take(cost)
	if err != nil {
		return nil, err
	}
	adopted := false
	var shared, issuerRef resourcev4.Reference
	defer func() {
		if !adopted {
			owned.Release()
			shared.Release()
			issuerRef.Release()
		}
	}()
	shared, err = dependencies.Borrow()
	if err != nil {
		return nil, err
	}
	issuerRef, err = issuer.ReferenceFor(c.Clock, owned)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(c.ClientCertificateDER)
	if err != nil || cert.NotBefore.UnixMilli() < 0 || cert.NotAfter.UnixMilli() <= cert.NotBefore.UnixMilli() {
		return nil, resourcev4.ErrConfiguration
	}
	origin, err := c.Clock.Monotonic()
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(cert.Raw)
	c.ClientCertificateDER = nil
	p := &DirectIssueHTTPSService{issuer: issuer, path: path, c: c, client: digest, notBefore: uint64(cert.NotBefore.UnixMilli()), notAfter: uint64(cert.NotAfter.UnixMilli()), origin: origin, credit: uint64(c.Burst) * 60000, reservation: owned, shared: shared, issuerReference: issuerRef, response: make([]byte, 65536), done: make(chan struct{})}
	adopted = true
	return p, nil
}

func (p *DirectIssueHTTPSService) checkLocked() error {
	if p.closed {
		return resourcev4.ErrClosed
	}
	if err := p.reservation.Check(); err != nil {
		return err
	}
	if err := p.shared.Check(); err != nil {
		return err
	}
	return p.issuerReference.Check()
}

func (p *DirectIssueHTTPSService) currentLocked(now timev4.Sample) error {
	if err := p.checkLocked(); err != nil {
		return err
	}
	if !now.BelongsTo(p.c.Clock) || !now.Mark.SameEra(p.origin) || now.LowerMS < p.notBefore || now.UpperMS >= p.notAfter {
		return timev4.ErrExpired
	}
	return nil
}

func (p *DirectIssueHTTPSService) begin() (*controlCallContext, int) {
	if p == nil || !p.mu.TryLock() {
		return nil, http.StatusTooManyRequests
	}
	defer p.mu.Unlock()
	if p.busy {
		return nil, http.StatusTooManyRequests
	}
	if p.checkLocked() != nil {
		return nil, http.StatusServiceUnavailable
	}
	call := newControlCallContext(time.Duration(p.c.WorkMS) * time.Millisecond)
	p.busy, p.cancel = true, call.stopCall
	return call, http.StatusOK
}

func (p *DirectIssueHTTPSService) authenticate(r *http.Request) int {
	now, err := p.c.Clock.Sample()
	if err != nil {
		return http.StatusServiceUnavailable
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.currentLocked(now) != nil || now.Milliseconds < p.origin.Milliseconds {
		return http.StatusServiceUnavailable
	}
	elapsed, _, err := p.c.Clock.Profile().Rate.Elapsed(now.Milliseconds - p.origin.Milliseconds)
	if err != nil || elapsed < p.creditedMS {
		return http.StatusServiceUnavailable
	}
	delta := elapsed - p.creditedMS
	capacity := uint64(p.c.Burst) * 60000
	if delta >= 60000 {
		p.credit = capacity
	} else {
		p.credit = min(capacity, p.credit+uint64(p.c.RequestsPerMinute)*delta)
	}
	p.creditedMS = elapsed
	if p.credit < 60000 {
		return http.StatusTooManyRequests
	}
	p.credit -= 60000
	s := r.TLS
	if s == nil || !s.HandshakeComplete || s.Version != tls.VersionTLS13 || s.DidResume || len(s.PeerCertificates) == 0 || len(s.PeerCertificates) > 8 || len(s.VerifiedChains) == 0 || len(s.VerifiedChains[0]) == 0 {
		return http.StatusForbidden
	}
	cert, verified := s.PeerCertificates[0], s.VerifiedChains[0][0]
	if cert == nil || verified == nil || len(cert.Raw) == 0 || len(cert.Raw) > 16384 || !bytes.Equal(cert.Raw, verified.Raw) || sha256.Sum256(cert.Raw) != p.client {
		return http.StatusForbidden
	}
	return http.StatusOK
}

func directIssueHTTPFailure(w http.ResponseWriter, status int) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Length", "0")
	w.WriteHeader(status)
}

func (p *DirectIssueHTTPSService) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	call, status := p.begin()
	if status != http.StatusOK {
		directIssueHTTPFailure(w, status)
		return
	}
	defer p.finish()
	defer call.finish()
	if r == nil {
		directIssueHTTPFailure(w, http.StatusBadRequest)
		return
	}
	if status = p.authenticate(r); status != http.StatusOK {
		directIssueHTTPFailure(w, status)
		return
	}
	if r.Method != http.MethodPost || r.URL.Path != p.path || r.URL.RawPath != "" || r.URL.RawQuery != "" || r.URL.ForceQuery || r.ContentLength != 35 || len(r.TransferEncoding) != 0 || r.Header.Get("Content-Type") != "application/cbor" || r.Header.Get("Content-Encoding") != "" || r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" {
		directIssueHTTPFailure(w, http.StatusBadRequest)
		return
	}
	parent := context.WithValue(r.Context(), directIssueClientContextKey{}, directIssueClientContext{p.client})
	if call.startHTTP(parent, w) != nil {
		directIssueHTTPFailure(w, http.StatusServiceUnavailable)
		return
	}
	window, err := timev4.NewWindow(p.c.Clock, p.c.WorkMS)
	if err != nil {
		directIssueHTTPFailure(w, http.StatusServiceUnavailable)
		return
	}
	defer window.Cancel()
	if _, err = io.ReadFull(r.Body, p.request[:]); err != nil || p.request[0] != 0x81 || p.request[1] != 0x58 || p.request[2] != 0x20 {
		directIssueHTTPFailure(w, http.StatusBadRequest)
		return
	}
	check := func() error {
		if err := window.Check(); err != nil {
			return err
		}
		now, err := p.c.Clock.Sample()
		if err != nil {
			return err
		}
		p.mu.Lock()
		defer p.mu.Unlock()
		if err := call.cause(); err != nil {
			return err
		}
		return p.currentLocked(now)
	}
	if check() != nil {
		directIssueHTTPFailure(w, http.StatusServiceUnavailable)
		return
	}
	request := protocolv4.DirectIssueRequest{RequestID: [32]byte(p.request[3:]), Authentication: p.client[:]}
	n, err := p.issuer.IssueArtifactBytes(call, request, p.response)
	if err != nil || n <= 0 || n > len(p.response) || check() != nil {
		directIssueHTTPFailure(w, http.StatusServiceUnavailable)
		return
	}
	// The final gate commits this exact response to the original writer. Later
	// Close cancels I/O but cannot retract bytes already handed to the host.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/cbor")
	w.Header().Set("Content-Length", strconv.Itoa(n))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(p.response[:n:n])
}

func (p *DirectIssueHTTPSService) finish() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cancel()
	p.cancel, p.busy = nil, false
	clear(p.request[:])
	clear(p.response)
	p.cleanupLocked()
}

func (p *DirectIssueHTTPSService) Close() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	if p.cancel != nil {
		p.cancel()
	}
	p.cleanupLocked()
}

func (p *DirectIssueHTTPSService) cleanupLocked() {
	if !p.closed || p.busy || p.cleaned {
		return
	}
	clear(p.response)
	p.response = nil
	p.issuer, p.c = nil, DirectIssueHTTPSConfig{}
	p.reservation.Release()
	p.shared.Release()
	p.issuerReference.Release()
	p.reservation, p.shared, p.issuerReference = resourcev4.Reference{}, resourcev4.Reference{}, resourcev4.Reference{}
	p.cleaned = true
	close(p.done)
}

func (p *DirectIssueHTTPSService) WaitCleanup(ctx context.Context) error {
	if p == nil || ctx == nil {
		return resourcev4.ErrConfiguration
	}
	select {
	case <-p.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
