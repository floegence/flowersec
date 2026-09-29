package controlv4

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"sync"
	"time"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// Both an already prepared recipient and a once-only deferred registration
// retain their original incarnation and resources through physical delivery.
type TunnelServerAllowEndpoint interface {
	ControlReferenceFor(*timev4.Clock, resourcev4.Reference) (resourcev4.Reference, error)
	Receive(context.Context, sessionv4.TunnelServerAllowRequest, []byte) error
}

type TunnelServerAllowHTTPSServiceConfig struct {
	Recipient                TunnelServerAllowEndpoint
	Clock                    *timev4.Clock
	ClientCertificateDER     []byte
	RequestsPerMinute, Burst uint16
	WorkMS, RuntimeBytes     uint64
}

// TunnelServerAllowHTTPSService belongs to one original recipient registration.
// Mount it at /tunnel/server-allow on an independently bounded TLS 1.3 listener
// requiring client certificates and disabling resumption. Authentication and
// rate admission precede body parsing; exactly one actual request may run.
type TunnelServerAllowHTTPSService struct {
	mu                             sync.Mutex
	c                              TunnelServerAllowHTTPSServiceConfig
	reservation, shared, recipient resourcev4.Reference
	client                         [32]byte
	notBefore, notAfter            uint64
	origin                         timev4.Mark
	creditedMS, credit             uint64
	codec                          *TunnelServerAllowCodec
	request, grant                 []byte
	cancel                         context.CancelFunc
	done                           chan struct{}
	busy, closed, cleaned          bool
}

func TunnelServerAllowHTTPSServiceCharge(c TunnelServerAllowHTTPSServiceConfig) (resourcev4.Vector, error) {
	if c.Recipient == nil || c.Clock == nil || len(c.ClientCertificateDER) == 0 || len(c.ClientCertificateDER) > 16384 || c.RequestsPerMinute == 0 || c.RequestsPerMinute > 600 || c.Burst == 0 || c.Burst > 16 || c.WorkMS == 0 || c.WorkMS > 90000 || c.RuntimeBytes == 0 {
		return resourcev4.Vector{}, resourcev4.ErrConfiguration
	}
	codec, err := TunnelServerAllowCodecBackingBytes()
	if err != nil {
		return resourcev4.Vector{}, err
	}
	limit, err := tunnelAllowWireLimit()
	if err != nil {
		return resourcev4.Vector{}, err
	}
	return (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(TunnelServerAllowHTTPSService{})) + codec + 2*uint64(limit) + controlCallContextBytes + uint64(unsafe.Sizeof(timev4.Window{})) + 4*16384,
		resourcev4.Items: 1, resourcev4.WorkSlots: 1, resourcev4.Tasks: 1, resourcev4.Timers: 2}).Add(resourcev4.Vector{resourcev4.SDKBytes: c.RuntimeBytes})
}

func NewTunnelServerAllowHTTPSService(c TunnelServerAllowHTTPSServiceConfig, reservation, dependencies resourcev4.Reference) (_ *TunnelServerAllowHTTPSService, err error) {
	cost, err := TunnelServerAllowHTTPSServiceCharge(c)
	if err != nil {
		return nil, err
	}
	if err = reservation.CheckSameEnvironment(dependencies); err != nil {
		return nil, err
	}
	certificate, err := x509.ParseCertificate(c.ClientCertificateDER)
	if err != nil || certificate.NotBefore.UnixMilli() < 0 || certificate.NotAfter.UnixMilli() <= certificate.NotBefore.UnixMilli() {
		return nil, resourcev4.ErrConfiguration
	}
	owned, err := reservation.Take(cost)
	if err != nil {
		return nil, err
	}
	p := &TunnelServerAllowHTTPSService{c: c, reservation: owned, client: sha256.Sum256(certificate.Raw), notBefore: uint64(certificate.NotBefore.UnixMilli()), notAfter: uint64(certificate.NotAfter.UnixMilli()), done: make(chan struct{})}
	p.c.ClientCertificateDER = nil
	adopted := false
	defer func() {
		if !adopted {
			p.Close()
		}
	}()
	p.shared, err = dependencies.Borrow()
	if err != nil {
		return nil, err
	}
	p.origin, err = c.Clock.Monotonic()
	if err != nil {
		return nil, err
	}
	p.codec, err = NewTunnelServerAllowCodec()
	if err != nil {
		return nil, err
	}
	limit, _ := tunnelAllowWireLimit()
	grant, _ := protocolv4.SchemaByteLimit("Grant")
	p.request, p.grant = make([]byte, limit), make([]byte, grant)
	p.credit = uint64(c.Burst) * 60000
	p.recipient, err = c.Recipient.ControlReferenceFor(c.Clock, owned)
	if err != nil {
		return nil, err
	}
	adopted = true
	return p, nil
}

func (p *TunnelServerAllowHTTPSService) checkLocked(now timev4.Sample) error {
	if p.closed {
		return resourcev4.ErrClosed
	}
	for _, ref := range []resourcev4.Reference{p.reservation, p.shared, p.recipient} {
		if err := ref.Check(); err != nil {
			return err
		}
	}
	if !now.BelongsTo(p.c.Clock) || !now.Mark.SameEra(p.origin) || now.LowerMS < p.notBefore || now.UpperMS >= p.notAfter {
		return timev4.ErrExpired
	}
	return nil
}

func (p *TunnelServerAllowHTTPSService) authenticate(r *http.Request) int {
	now, err := p.c.Clock.Sample()
	if err != nil {
		return http.StatusServiceUnavailable
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.checkLocked(now) != nil || now.Milliseconds < p.origin.Milliseconds {
		return http.StatusServiceUnavailable
	}
	elapsed, _, err := p.c.Clock.Profile().Rate.Elapsed(now.Milliseconds - p.origin.Milliseconds)
	if err != nil || elapsed < p.creditedMS {
		return http.StatusServiceUnavailable
	}
	delta, capacity := elapsed-p.creditedMS, uint64(p.c.Burst)*60000
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

func (p *TunnelServerAllowHTTPSService) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if p == nil || !p.mu.TryLock() {
		directIssueHTTPFailure(w, http.StatusTooManyRequests)
		return
	}
	if p.closed || p.busy {
		p.mu.Unlock()
		directIssueHTTPFailure(w, http.StatusServiceUnavailable)
		return
	}
	call := newControlCallContext(time.Duration(p.c.WorkMS) * time.Millisecond)
	p.busy, p.cancel = true, call.stopCall
	p.mu.Unlock()
	defer func() {
		call.finish()
		call.stopCall()
		p.mu.Lock()
		defer p.mu.Unlock()
		clear(p.request)
		clear(p.grant)
		p.busy, p.cancel = false, nil
		p.cleanupLocked()
	}()
	if r == nil || r.URL == nil {
		directIssueHTTPFailure(w, http.StatusBadRequest)
		return
	}
	if status := p.authenticate(r); status != http.StatusOK {
		directIssueHTTPFailure(w, status)
		return
	}
	if r.Method != http.MethodPost || r.URL.Path != "/tunnel/server-allow" || r.URL.RawPath != "" || r.URL.RawQuery != "" || r.URL.ForceQuery || r.Body == nil || r.ContentLength <= 0 || r.ContentLength > int64(len(p.request)) || len(r.TransferEncoding) != 0 || r.Header.Get("Content-Type") != "application/cbor" || r.Header.Get("Content-Encoding") != "" || r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" {
		directIssueHTTPFailure(w, http.StatusBadRequest)
		return
	}
	if call.startHTTP(r.Context(), w) != nil {
		directIssueHTTPFailure(w, http.StatusServiceUnavailable)
		return
	}
	window, err := timev4.NewWindow(p.c.Clock, p.c.WorkMS)
	if err != nil {
		directIssueHTTPFailure(w, http.StatusServiceUnavailable)
		return
	}
	defer window.Cancel()
	if _, err = io.ReadFull(r.Body, p.request[:int(r.ContentLength)]); err != nil {
		directIssueHTTPFailure(w, http.StatusBadRequest)
		return
	}
	request, n, err := p.codec.Decode(p.request[:int(r.ContentLength)], p.grant)
	if err != nil {
		directIssueHTTPFailure(w, http.StatusBadRequest)
		return
	}
	guard := func() error {
		if err := call.Err(); err != nil {
			return err
		}
		if err := window.Check(); err != nil {
			return err
		}
		now, err := p.c.Clock.Sample()
		if err != nil {
			return err
		}
		p.mu.Lock()
		defer p.mu.Unlock()
		return p.checkLocked(now)
	}
	if err = guard(); err == nil {
		err = p.c.Recipient.Receive(call, request, p.grant[:n:n])
	}
	if err == nil {
		err = guard()
	}
	if err != nil {
		directIssueHTTPFailure(w, http.StatusConflict)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/cbor")
	w.Header().Set("Content-Length", "1")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte{0xf5})
}

func (p *TunnelServerAllowHTTPSService) Close() {
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

func (p *TunnelServerAllowHTTPSService) cleanupLocked() {
	if !p.closed || p.busy || p.cleaned {
		return
	}
	clear(p.request)
	clear(p.grant)
	p.request, p.grant, p.codec = nil, nil, nil
	p.c = TunnelServerAllowHTTPSServiceConfig{}
	p.recipient.Release()
	p.shared.Release()
	p.reservation.Release()
	p.recipient, p.shared, p.reservation = resourcev4.Reference{}, resourcev4.Reference{}, resourcev4.Reference{}
	p.cleaned = true
	close(p.done)
}

func (p *TunnelServerAllowHTTPSService) WaitCleanup(ctx context.Context) error {
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
