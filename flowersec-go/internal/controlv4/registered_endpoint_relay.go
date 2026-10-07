package controlv4

import (
	"bytes"
	"context"
	"crypto/sha256"
	"net/http"
	"net/url"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// RegisteredEndpointRelayConfig is installed before original acquisition. Its
// own leaf is the same endpoint mTLS leaf installed at the authority. The
// candidate and immutable deadline belong to the verified original registry;
// a response cannot select a relay, enlarge a window or replace that registry.
type RegisteredEndpointRelayConfig struct {
	HTTPS        HTTPSBootstrapConfig
	Clock        *timev4.Clock
	Deadline     *timev4.Deadline
	Parent       [32]byte
	Candidate    protocolv4.PoolMember
	Role         protocolv4.Direction
	Listener     bool
	RuntimeBytes uint64
}

type RegisteredEndpointRelay struct {
	mu                                                    sync.Mutex
	config                                                RegisteredEndpointRelayConfig
	provider                                              *HTTPSBootstrapProvider
	reservation, dependencies                             resourcev4.Reference
	body, request                                         []byte
	requestBytes                                          int
	attempt                                               [16]byte
	cutoff                                                uint64
	readyUsed, ready, prepareUsed, prepared, activateUsed bool
	cancel                                                context.CancelFunc
	busy, closed, failed, cleaned                         bool
	done                                                  chan struct{}
}

func RegisteredEndpointRelayCharges(c RegisteredEndpointRelayConfig) (resourcev4.Vector, resourcev4.Vector, error) {
	endpoint, err := url.Parse(c.HTTPS.BaseURL)
	if err != nil || endpoint.Scheme != "https" || endpoint.Path != "/" || endpoint.RawPath != "" || endpoint.RawQuery != "" || endpoint.ForceQuery || endpoint.Fragment != "" || endpoint.User != nil || c.Clock == nil || c.Deadline == nil || !c.Deadline.BelongsTo(c.Clock) || c.Parent == ([32]byte{}) || c.Candidate.CandidateID == ([16]byte{}) || c.Candidate.RouteDigest == ([32]byte{}) || c.Candidate.Index >= 16 || c.Role > protocolv4.ServerToClient || c.RuntimeBytes == 0 || c.HTTPS.TLS == nil || len(c.HTTPS.TLS.Certificates) != 1 || len(c.HTTPS.TLS.Certificates[0].Certificate) == 0 || c.HTTPS.TLS.GetClientCertificate != nil {
		return resourcev4.Vector{}, resourcev4.Vector{}, resourcev4.ErrConfiguration
	}
	provider, err := HTTPSBootstrapCharge(c.HTTPS)
	if err != nil {
		return resourcev4.Vector{}, resourcev4.Vector{}, err
	}
	cost, err := (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(RegisteredEndpointRelay{})) + remoteOriginalLiveRelayBodyBytes + liveRequestBytes + controlCallContextBytes + uint64(unsafe.Sizeof(timev4.Deadline{})) + 1, resourcev4.Items: 1, resourcev4.Tasks: 1, resourcev4.WorkSlots: 1, resourcev4.Timers: 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: c.RuntimeBytes})
	return cost, provider, err
}

func NewRegisteredEndpointRelay(c RegisteredEndpointRelayConfig, reservation, providerReservation, dependencies resourcev4.Reference) (*RegisteredEndpointRelay, error) {
	cost, _, err := RegisteredEndpointRelayCharges(c)
	if err != nil {
		return nil, err
	}
	if err = reservation.CheckSameEnvironment(providerReservation); err != nil {
		return nil, err
	}
	if err = reservation.CheckSameEnvironment(dependencies); err != nil {
		return nil, err
	}
	owned, err := reservation.Take(cost)
	if err != nil {
		return nil, err
	}
	shared, err := dependencies.Borrow()
	if err != nil {
		owned.Release()
		return nil, err
	}
	borrowed, err := dependencies.Borrow()
	if err != nil {
		shared.Release()
		owned.Release()
		return nil, err
	}
	provider, err := NewHTTPSBootstrapProvider(c.HTTPS, providerReservation, borrowed)
	if err != nil {
		borrowed.Release()
		shared.Release()
		owned.Release()
		return nil, err
	}
	c.HTTPS = HTTPSBootstrapConfig{}
	return &RegisteredEndpointRelay{config: c, provider: provider, reservation: owned, dependencies: shared, body: make([]byte, remoteOriginalLiveRelayBodyBytes), request: make([]byte, liveRequestBytes), done: make(chan struct{})}, nil
}

func (p *RegisteredEndpointRelay) MatchesBinding(parent [32]byte, candidate uint64, role protocolv4.Direction) bool {
	if p == nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return !p.closed && p.config.Parent == parent && p.config.Candidate.Index == candidate && p.config.Role == role
}
func (p *RegisteredEndpointRelay) BeforeServerRegistration() error {
	if p == nil {
		return resourcev4.ErrConfiguration
	}
	if err := p.check(); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.failed || p.config.Role != protocolv4.ServerToClient || p.config.Listener && !p.ready {
		return resourcev4.ErrOwner
	}
	return nil
}
func (p *RegisteredEndpointRelay) CheckEnvironment(ref resourcev4.Reference) error {
	if p == nil {
		return resourcev4.ErrConfiguration
	}
	return p.reservation.CheckSameEnvironment(ref)
}
func (p *RegisteredEndpointRelay) MatchesEndpointLeaf(certificateDER []byte) bool {
	if p == nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return !p.closed && p.provider != nil && len(p.provider.tls.Certificates) == 1 && len(p.provider.tls.Certificates[0].Certificate) > 0 && sha256.Sum256(p.provider.tls.Certificates[0].Certificate[0]) == sha256.Sum256(certificateDER)
}
func (p *RegisteredEndpointRelay) check() error {
	if err := p.reservation.Check(); err != nil {
		return err
	}
	if err := p.dependencies.Check(); err != nil {
		return err
	}
	if err := p.config.Deadline.Check(); err != nil {
		return err
	}
	p.mu.Lock()
	closed, cutoff := p.closed, p.cutoff
	p.mu.Unlock()
	if closed {
		return resourcev4.ErrClosed
	}
	if cutoff != 0 {
		now, err := p.config.Clock.Sample()
		if err != nil {
			return err
		}
		if !now.ValidBefore(cutoff) {
			return timev4.ErrExpired
		}
	}
	return nil
}

// AnnounceReady is called only after the endpoint's actual native listener has
// bound. It consumes the one READY submission, including cancellation or an
// unknown response, and cannot turn a driver message into physical readiness.
func (p *RegisteredEndpointRelay) AnnounceReady(ctx context.Context, guard func() error) error {
	return p.exchange(ctx, 0, guard, func(w *poolWireWriter) error {
		w.array(5)
		w.text("tunnel-relay-ready-1")
		w.blob(p.config.Parent[:])
		w.blob(p.config.Candidate.CandidateID[:])
		w.blob(p.config.Candidate.RouteDigest[:])
		w.uint(uint64(p.config.Role))
		return w.err
	})
}

// Prepare follows the SDK's native Prepare on A's original physical owner.
// The original canonical request is retained through Activate; a later stage
// cannot substitute a second attempt or request with a renewed deadline.
func (p *RegisteredEndpointRelay) Prepare(ctx context.Context, q sessionv4.LiveAuthorizationRequest, guard func() error) error {
	return p.exchange(ctx, 1, guard, func(w *poolWireWriter) error {
		if q.Artifact != p.config.Parent || q.Winner != p.config.Candidate || q.Attempt == ([16]byte{}) || q.ActivationNotAfterMS == 0 || q.ActivationNotAfterMS > p.config.Deadline.Cap() {
			return resourcev4.ErrOwner
		}
		size, err := EncodeLiveAuthorizationRequest(p.request, q)
		if err != nil {
			return err
		}
		p.mu.Lock()
		p.requestBytes, p.attempt, p.cutoff = size, q.Attempt, q.ActivationNotAfterMS
		p.mu.Unlock()
		w.put(p.request[:size])
		return w.err
	})
}

// Activate consumes only this A response's proof and client Grant before the
// same original SDK claim returns. No server Grant or bearer publication token
// is available to the endpoint, and every stage authenticates its fixed leaf.
func (p *RegisteredEndpointRelay) Activate(ctx context.Context, q sessionv4.LiveAuthorizationRequest, proof, grant []byte, guard func() error) error {
	return p.exchange(ctx, 2, guard, func(w *poolWireWriter) error {
		var request [liveRequestBytes]byte
		defer clear(request[:])
		n, err := EncodeLiveAuthorizationRequest(request[:], q)
		if err != nil {
			return err
		}
		if q.Attempt != p.attempt || n != p.requestBytes || !bytes.Equal(request[:n], p.request[:p.requestBytes]) || len(proof) == 0 || len(proof) > 65536 || len(grant) == 0 || len(grant) > 65536 {
			return resourcev4.ErrOwner
		}
		w.array(4)
		w.text("tunnel-relay-activate-client-1")
		w.blob(p.request[:p.requestBytes])
		w.blob(proof)
		w.blob(grant)
		return w.err
	})
}

func (p *RegisteredEndpointRelay) exchange(ctx context.Context, stage uint8, guard func() error, encode func(*poolWireWriter) error) (err error) {
	if p == nil || ctx == nil || guard == nil || encode == nil {
		return resourcev4.ErrConfiguration
	}
	if !p.mu.TryLock() {
		return ErrBusy
	}
	if p.closed || p.failed || p.busy {
		p.mu.Unlock()
		return ErrBusy
	}
	switch stage {
	case 0:
		if !p.config.Listener || p.readyUsed {
			p.mu.Unlock()
			return resourcev4.ErrOwner
		}
		p.readyUsed = true
	case 1:
		if p.config.Role != protocolv4.ClientToServer || p.prepareUsed || p.config.Listener && !p.ready {
			p.mu.Unlock()
			return resourcev4.ErrOwner
		}
		p.prepareUsed = true
	case 2:
		if p.config.Role != protocolv4.ClientToServer || !p.prepared || p.activateUsed {
			p.mu.Unlock()
			return resourcev4.ErrOwner
		}
		p.activateUsed = true
	default:
		p.mu.Unlock()
		return resourcev4.ErrConfiguration
	}
	call := newHTTPSCallContext(p.provider)
	p.busy, p.cancel = true, call.stopCall
	p.mu.Unlock()
	returned := false
	defer func() {
		if recovered := recover(); recovered != nil || !returned {
			err = ErrControlTaskExit
			call.cancel(err)
		}
		call.finish()
		clear(p.body)
		p.mu.Lock()
		defer p.mu.Unlock()
		if err == nil {
			err = call.cause()
		}
		if err == nil {
			err = p.reservation.Check()
		}
		if err == nil {
			err = p.dependencies.Check()
		}
		if p.closed && err == nil {
			err = context.Canceled
		}
		if err != nil {
			p.failed = true
			clear(p.request)
			p.requestBytes = 0
		} else if stage == 0 {
			p.ready = true
		} else if stage == 1 {
			p.prepared = true
		} else {
			clear(p.request)
			p.requestBytes = 0
		}
		call.stopCall()
		p.busy, p.cancel = false, nil
		p.cleanupLocked()
	}()
	check := func() error {
		if err := call.cause(); err != nil {
			return err
		}
		if err := p.check(); err != nil {
			return err
		}
		return guard()
	}
	call.beforeWrite = check
	if err = call.start(ctx); err == nil {
		err = check()
	}
	writer := poolWireWriter{dst: p.body}
	if err == nil {
		err = encode(&writer)
	}
	if err == nil {
		err = check()
	}
	path := "/tunnel/relay-ready"
	if stage == 1 {
		path = "/tunnel/relay-prepare"
	} else if stage == 2 {
		path = "/tunnel/relay-activate-client"
	}
	var response [1]byte
	if err == nil {
		var n int
		n, _, err = p.provider.exchangeContent(call, http.MethodPost, path, nil, p.body[:writer.n], response[:], true, false, "application/cbor")
		if err == nil && (n != 1 || response[0] != 0xf5) {
			err = ErrResponse
		}
	}
	if err == nil {
		err = check()
	}
	returned = true
	return err
}
func (p *RegisteredEndpointRelay) Close() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	if p.cancel != nil {
		p.cancel()
	}
	if p.provider != nil {
		p.provider.Close()
	}
	p.cleanupLocked()
}
func (p *RegisteredEndpointRelay) cleanupLocked() {
	if !p.closed || p.busy || p.cleaned {
		return
	}
	if p.provider != nil && p.provider.Retire() != nil {
		return
	}
	clear(p.body)
	clear(p.request)
	p.body, p.request = nil, nil
	p.provider = nil
	p.config = RegisteredEndpointRelayConfig{}
	p.reservation.Release()
	p.dependencies.Release()
	p.cleaned = true
	close(p.done)
}
func (p *RegisteredEndpointRelay) WaitCleanup(ctx context.Context) error {
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
