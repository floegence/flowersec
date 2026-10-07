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

	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// PoolHTTPSServiceConfig binds one independently authenticated control client
// and its source access to the original PoolService. Access is host input, never
// extracted from CBOR, HTTP headers or a caller-selected source identity.
type PoolHTTPSServiceConfig struct {
	Service    *PoolService
	OwnerProof *PoolOwnerProofIssuer
	// OriginalCommitted runs only for this invocation's actual success reply,
	// after whole-outbox COMMIT/publication. Replays and restored rows never invoke
	// it. The host must preadmit its finite route position and copy borrowed input
	// before returning; the callback itself joins all actual construction work.
	OriginalCommitted        func(context.Context, protocolv4.TopUpRequestFacts, []byte) error
	Access                   ledgerv4.TopUpAccess
	Clock                    *timev4.Clock
	Tenant                   string
	Source                   [16]byte
	ClientCertificateDER     []byte
	RequestsPerMinute, Burst uint16
	WorkMS, RuntimeBytes     uint64
}

// PoolHTTPSService is a single finite native HTTP invocation position for
// POST /pool/top-up, /pool/ack and optional /pool/owner-proof. The host owns the bounded listener and must
// require verified client certificates on TLS 1.3 with resumption disabled.
// Success bytes come only from the original complete-outbox publication chain.
type PoolHTTPSService struct {
	mu                                       sync.Mutex
	config                                   PoolHTTPSServiceConfig
	reservation, shared, service, ownerProof resourcev4.Reference
	client                                   [32]byte
	notBefore, notAfter                      uint64
	origin                                   timev4.Mark
	credit, creditedMS                       uint64
	request, response                        []byte
	observerRequest                          *protocolv4.TopUpCodec
	observerReply                            *protocolv4.Decoder
	cancel                                   context.CancelFunc
	done                                     chan struct{}
	busy, closed, cleaned                    bool
}

func PoolHTTPSServiceCharge(c PoolHTTPSServiceConfig) (resourcev4.Vector, error) {
	if c.Service == nil || c.Access == nil || c.Clock == nil || c.Tenant == "" || len(c.Tenant) > 128 || c.Source == ([16]byte{}) || len(c.ClientCertificateDER) == 0 || len(c.ClientCertificateDER) > 16384 || c.RequestsPerMinute == 0 || c.RequestsPerMinute > 600 || c.Burst == 0 || c.Burst > 16 || c.WorkMS == 0 || c.WorkMS > 90000 || c.RuntimeBytes == 0 {
		return resourcev4.Vector{}, resourcev4.ErrConfiguration
	}
	extra := uint64(0)
	if c.OriginalCommitted != nil {
		request, err := protocolv4.TopUpCodecBackingBytes()
		if err != nil {
			return resourcev4.Vector{}, err
		}
		reply, err := protocolv4.DecoderBackingBytes(524288, 256)
		if err != nil {
			return resourcev4.Vector{}, err
		}
		extra = request + reply
	}
	return (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(PoolHTTPSService{})) + controlCallContextBytes + uint64(unsafe.Sizeof(timev4.Window{})) + 2*524288 + 4*16384 + 32768 + extra, resourcev4.Items: 1, resourcev4.WorkSlots: 1, resourcev4.Tasks: 2, resourcev4.Timers: 2}).Add(resourcev4.Vector{resourcev4.SDKBytes: c.RuntimeBytes})
}

func (p *PoolService) controlReferenceFor(tenant string, source [16]byte, environment resourcev4.Reference) (resourcev4.Reference, error) {
	if p == nil {
		return resourcev4.Reference{}, resourcev4.ErrConfiguration
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.config.Tenant != tenant || p.config.Source != source {
		return resourcev4.Reference{}, resourcev4.ErrOwner
	}
	if err := p.reservation.CheckSameEnvironment(environment); err != nil {
		return resourcev4.Reference{}, err
	}
	if err := p.shared.Check(); err != nil {
		return resourcev4.Reference{}, err
	}
	return p.reservation.Borrow()
}

func NewPoolHTTPSService(c PoolHTTPSServiceConfig, reservation, dependencies resourcev4.Reference) (_ *PoolHTTPSService, err error) {
	charge, err := PoolHTTPSServiceCharge(c)
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
	owned, err := reservation.Take(charge)
	if err != nil {
		return nil, err
	}
	p := &PoolHTTPSService{config: c, reservation: owned, client: sha256.Sum256(certificate.Raw), notBefore: uint64(certificate.NotBefore.UnixMilli()), notAfter: uint64(certificate.NotAfter.UnixMilli()), done: make(chan struct{})}
	p.config.ClientCertificateDER = nil
	success := false
	defer func() {
		if !success {
			p.Close()
		}
	}()
	p.shared, err = dependencies.Borrow()
	if err != nil {
		return nil, err
	}
	p.service, err = c.Service.controlReferenceFor(c.Tenant, c.Source, dependencies)
	if err != nil {
		return nil, err
	}
	if c.OwnerProof != nil {
		p.ownerProof, err = c.OwnerProof.controlReferenceFor(c.Tenant, c.Source, c.Clock, c.Service, dependencies)
		if err != nil {
			return nil, err
		}
	}
	if c.OriginalCommitted != nil {
		p.observerRequest, err = protocolv4.NewTopUpCodec()
		if err != nil {
			return nil, err
		}
		p.observerReply, err = protocolv4.NewDecoder(524288, 256)
		if err != nil {
			return nil, err
		}
	}
	p.origin, err = c.Clock.Monotonic()
	if err != nil {
		return nil, err
	}
	p.credit = uint64(c.Burst) * 60000
	p.request, p.response = make([]byte, 524288), make([]byte, 524288)
	success = true
	return p, nil
}

func (p *PoolHTTPSService) checkLocked(now timev4.Sample) error {
	if p.closed {
		return resourcev4.ErrClosed
	}
	for _, ref := range []resourcev4.Reference{p.reservation, p.shared, p.service} {
		if err := ref.Check(); err != nil {
			return err
		}
	}
	if p.config.OwnerProof != nil {
		if err := p.ownerProof.Check(); err != nil {
			return err
		}
	}
	if !now.BelongsTo(p.config.Clock) || !now.Mark.SameEra(p.origin) || now.LowerMS < p.notBefore || now.UpperMS >= p.notAfter {
		return timev4.ErrExpired
	}
	return nil
}

func (p *PoolHTTPSService) authenticate(r *http.Request) int {
	now, err := p.config.Clock.Sample()
	if err != nil {
		return http.StatusServiceUnavailable
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.checkLocked(now) != nil || now.Milliseconds < p.origin.Milliseconds {
		return http.StatusServiceUnavailable
	}
	elapsed, _, err := p.config.Clock.Profile().Rate.Elapsed(now.Milliseconds - p.origin.Milliseconds)
	if err != nil || elapsed < p.creditedMS {
		return http.StatusServiceUnavailable
	}
	delta, capacity := elapsed-p.creditedMS, uint64(p.config.Burst)*60000
	if delta >= 60000 {
		p.credit = capacity
	} else {
		p.credit = min(capacity, p.credit+uint64(p.config.RequestsPerMinute)*delta)
	}
	p.creditedMS = elapsed
	if p.credit < 60000 {
		return http.StatusTooManyRequests
	}
	p.credit -= 60000
	state := r.TLS
	if state == nil || !state.HandshakeComplete || state.Version != tls.VersionTLS13 || state.DidResume || len(state.PeerCertificates) == 0 || len(state.PeerCertificates) > 8 || len(state.VerifiedChains) == 0 || len(state.VerifiedChains[0]) == 0 {
		return http.StatusForbidden
	}
	certificate, verified := state.PeerCertificates[0], state.VerifiedChains[0][0]
	if certificate == nil || verified == nil || len(certificate.Raw) == 0 || len(certificate.Raw) > 16384 || !bytes.Equal(certificate.Raw, verified.Raw) || sha256.Sum256(certificate.Raw) != p.client {
		return http.StatusForbidden
	}
	return http.StatusOK
}

func (p *PoolHTTPSService) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if p == nil || !p.mu.TryLock() {
		directIssueHTTPFailure(w, http.StatusTooManyRequests)
		return
	}
	if p.closed || p.busy {
		p.mu.Unlock()
		directIssueHTTPFailure(w, http.StatusServiceUnavailable)
		return
	}
	call := newControlCallContext(time.Duration(p.config.WorkMS) * time.Millisecond)
	p.busy, p.cancel = true, call.stopCall
	config := p.config
	p.mu.Unlock()
	defer func() {
		call.finish()
		call.stopCall()
		p.mu.Lock()
		defer p.mu.Unlock()
		clear(p.request)
		clear(p.response)
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
	if config.Access.CheckTopUpAccess(config.Tenant, config.Source) != nil {
		directIssueHTTPFailure(w, http.StatusForbidden)
		return
	}
	method := ControlPoolTopUp
	ownerProof := false
	contentType, requestLimit := "application/cbor", int64(len(p.request))
	switch r.URL.Path {
	case "/pool/top-up":
	case "/pool/ack":
		method = ControlPoolAck
	case "/pool/owner-proof":
		if config.OwnerProof == nil {
			directIssueHTTPFailure(w, http.StatusNotFound)
			return
		}
		ownerProof = true
		contentType, requestLimit = "application/json", 4096
	default:
		directIssueHTTPFailure(w, http.StatusNotFound)
		return
	}
	if r.Method != http.MethodPost || r.URL.RawPath != "" || r.URL.RawQuery != "" || r.URL.ForceQuery || r.Body == nil || r.ContentLength <= 0 || r.ContentLength > requestLimit || len(r.TransferEncoding) != 0 || r.Header.Get("Content-Type") != contentType || r.Header.Get("Content-Encoding") != "" || r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" {
		directIssueHTTPFailure(w, http.StatusBadRequest)
		return
	}
	if err := call.startHTTP(r.Context(), w); err != nil {
		directIssueHTTPFailure(w, http.StatusServiceUnavailable)
		return
	}
	window, err := timev4.NewWindow(config.Clock, config.WorkMS)
	if err != nil {
		directIssueHTTPFailure(w, http.StatusServiceUnavailable)
		return
	}
	defer window.Cancel()
	n := int(r.ContentLength)
	if _, err = io.ReadFull(r.Body, p.request[:n:n]); err != nil {
		directIssueHTTPFailure(w, http.StatusBadRequest)
		return
	}
	check := func() error {
		if err := call.Err(); err != nil {
			return err
		}
		if err := window.Check(); err != nil {
			return err
		}
		now, err := config.Clock.Sample()
		if err != nil {
			return err
		}
		p.mu.Lock()
		defer p.mu.Unlock()
		return p.checkLocked(now)
	}
	if err = check(); err != nil {
		directIssueHTTPFailure(w, http.StatusServiceUnavailable)
		return
	}
	var result int
	failure := false
	if ownerProof {
		facts, parseErr := parsePoolOwnerProofJSON(p.request[:n:n])
		if parseErr != nil || facts.Tenant != config.Tenant || facts.Source != config.Source {
			directIssueHTTPFailure(w, http.StatusBadRequest)
			return
		}
		result, err = config.OwnerProof.Issue(call, config.Access, facts, p.response[:512:512])
	} else {
		result, failure, err = config.Service.Exchange(call, method, config.Access, p.request[:n:n], p.response)
	}
	if err != nil || result <= 0 || result > len(p.response) {
		directIssueHTTPFailure(w, http.StatusServiceUnavailable)
		return
	}
	if err = check(); err != nil {
		directIssueHTTPFailure(w, http.StatusServiceUnavailable)
		return
	}
	if !ownerProof && method == ControlPoolTopUp && !failure && config.OriginalCommitted != nil {
		doc, e := p.observerReply.DecodeShape(p.response[:result:result], "", protocolv4.DecodeContext{})
		if e != nil {
			directIssueHTTPFailure(w, http.StatusServiceUnavailable)
			return
		}
		x := doc.Root()
		code, ok := x.Index(0).Text()
		response, present := x.Index(1).ByteString()
		if x.Len() != 4 || !ok || !present {
			doc.Release()
			directIssueHTTPFailure(w, http.StatusServiceUnavailable)
			return
		}
		if code == "success" {
			facts, e := p.observerRequest.InspectRequest(p.request[:n:n])
			if e == nil {
				e = config.OriginalCommitted(call, facts, response)
			}
			if e != nil {
				doc.Release()
				directIssueHTTPFailure(w, http.StatusServiceUnavailable)
				return
			}
		} else if code != "replay" {
			doc.Release()
			directIssueHTTPFailure(w, http.StatusServiceUnavailable)
			return
		}
		doc.Release()
		if err = check(); err != nil {
			directIssueHTTPFailure(w, http.StatusServiceUnavailable)
			return
		}
	}
	status := http.StatusOK
	if failure {
		status = http.StatusConflict
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/cbor")
	w.Header().Set("Content-Length", strconv.Itoa(result))
	w.WriteHeader(status)
	_, _ = w.Write(p.response[:result:result])
}

func (p *PoolHTTPSService) Close() {
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
func (p *PoolHTTPSService) cleanupLocked() {
	if !p.closed || p.busy || p.cleaned {
		return
	}
	clear(p.request)
	clear(p.response)
	p.request, p.response = nil, nil
	p.config = PoolHTTPSServiceConfig{}
	p.observerRequest, p.observerReply = nil, nil
	p.ownerProof.Release()
	p.service.Release()
	p.shared.Release()
	p.reservation.Release()
	p.ownerProof, p.service, p.shared, p.reservation = resourcev4.Reference{}, resourcev4.Reference{}, resourcev4.Reference{}, resourcev4.Reference{}
	p.cleaned = true
	close(p.done)
}
func (p *PoolHTTPSService) WaitCleanup(ctx context.Context) error {
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
