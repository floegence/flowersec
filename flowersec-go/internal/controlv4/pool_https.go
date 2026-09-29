package controlv4

import (
	"context"
	"net/http"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

type PoolHTTPSConfig struct {
	HTTPS        HTTPSBootstrapConfig
	Decoder      PoolControlResultDecoder
	RuntimeBytes uint64
}

// PoolHTTPSTransport is an independently bootstrapped cold-start transport.
// Its fixed application binding is POST <BaseURL>/pool/top-up (41006) and
// POST <BaseURL>/pool/ack (41007), with canonical request/Ack bytes. HTTP 200
// carries a success envelope and HTTP 409 an application-error envelope, both
// application/cbor with an explicit positive Content-Length <= 524288.
// The configured application decoder validates their full result contract;
// HTTP/TLS success alone never supplies operation-terminal evidence.
//
// The host supplies explicit TLS trust and client authentication, separately
// from the pool it replenishes. There is no control-Session dependency, cookie
// jar, proxy, redirect, resolver, retry, compression or connection pool.
type PoolHTTPSTransport struct {
	mu                    sync.Mutex
	provider              *HTTPSBootstrapProvider
	decoder               PoolControlResultDecoder
	reservation, shared   resourcev4.Reference
	response              []byte
	cancel                context.CancelFunc
	done                  chan struct{}
	busy, closed, cleaned bool
}

// PoolHTTPSTransportCharge covers the response envelope and decoder's admitted
// runtime backing. HTTPSBootstrapCharge covers the separate physical provider.
func PoolHTTPSTransportCharge(c PoolHTTPSConfig) (resourcev4.Vector, error) {
	if c.Decoder == nil || c.RuntimeBytes == 0 {
		return resourcev4.Vector{}, resourcev4.ErrConfiguration
	}
	if _, err := HTTPSBootstrapCharge(c.HTTPS); err != nil {
		return resourcev4.Vector{}, err
	}
	return (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(PoolHTTPSTransport{})) + 524288, resourcev4.Items: 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: c.RuntimeBytes})
}

func NewPoolHTTPSTransport(c PoolHTTPSConfig, reservation, providerReservation, dependencies resourcev4.Reference) (*PoolHTTPSTransport, error) {
	cost, err := PoolHTTPSTransportCharge(c)
	if err != nil {
		return nil, err
	}
	if err = reservation.CheckSameEnvironment(providerReservation); err != nil {
		return nil, err
	}
	if err = reservation.CheckSameEnvironment(dependencies); err != nil {
		return nil, err
	}
	shared, err := dependencies.Borrow()
	if err != nil {
		return nil, err
	}
	owned, err := reservation.Take(cost)
	if err != nil {
		shared.Release()
		return nil, err
	}
	providerBorrow, err := dependencies.Borrow()
	if err != nil {
		owned.Release()
		shared.Release()
		return nil, err
	}
	provider, err := NewHTTPSBootstrapProvider(c.HTTPS, providerReservation, providerBorrow)
	providerBorrow.Release()
	if err != nil {
		owned.Release()
		shared.Release()
		return nil, err
	}
	return &PoolHTTPSTransport{provider: provider, decoder: c.Decoder, reservation: owned, shared: shared, response: make([]byte, 524288), done: make(chan struct{})}, nil
}

func (p *PoolHTTPSTransport) TopUp(ctx context.Context, wire, dst []byte) (sessionv4.TopUpExchangeResult, error) {
	return p.call(ctx, ControlPoolTopUp, wire, dst)
}
func (p *PoolHTTPSTransport) Ack(ctx context.Context, wire []byte) (sessionv4.TopUpExchangeResult, error) {
	return p.call(ctx, ControlPoolAck, wire, nil)
}
func (p *PoolHTTPSTransport) call(ctx context.Context, method uint32, wire, dst []byte) (result sessionv4.TopUpExchangeResult, err error) {
	if p == nil || ctx == nil || len(wire) == 0 || len(wire) > 524288 || method == ControlPoolTopUp && len(dst) < 524288 {
		return result, resourcev4.ErrConfiguration
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return result, ErrResponse
	}
	if p.busy {
		p.mu.Unlock()
		return result, ErrBusy
	}
	if err = p.reservation.Check(); err == nil {
		err = p.shared.Check()
	}
	if err != nil {
		p.mu.Unlock()
		return result, err
	}
	// One original deadline includes network and decoding. Cancellation never
	// permits a second call to reuse response storage before this call exits.
	call := newHTTPSCallContext(p.provider)
	p.busy, p.cancel = true, call.stopCall
	provider, decoder := p.provider, p.decoder
	p.mu.Unlock()
	returned := false
	defer func() {
		if recovered := recover(); recovered != nil || !returned {
			err = ErrControlTaskExit
			call.cancel(err)
		}
		call.finish()
		// A result can own application-defined evidence release hooks. Keep
		// this original call busy until both hooks leave, without holding mu.
		released := false
		defer func() {
			if recovered := recover(); recovered != nil || !released {
				err = ErrControlTaskExit
			}
			p.mu.Lock()
			clear(p.response)
			call.stopCall()
			p.busy, p.cancel = false, nil
			p.cleanupLocked()
			p.mu.Unlock()
		}()
		p.mu.Lock()
		if err == nil {
			err = call.cause()
		}
		if err == nil {
			err = p.reservation.Check()
		}
		if err == nil {
			err = p.shared.Check()
		}
		if p.closed && err == nil {
			err = context.Canceled
		}
		p.mu.Unlock()
		if err != nil {
			clear(dst)
			discarded := result
			result = sessionv4.TopUpExchangeResult{}
			discarded.Release()
		}
		released = true
	}()
	if err = call.start(ctx); err == nil {
		result, err = p.exchangeAndDecode(call, provider, decoder, method, wire, dst)
	}
	err = poolControlError(err)
	returned = true
	return result, err
}

func (p *PoolHTTPSTransport) exchangeAndDecode(call *controlCallContext, provider *HTTPSBootstrapProvider, decoder PoolControlResultDecoder, method uint32, wire, dst []byte) (result sessionv4.TopUpExchangeResult, err error) {
	path := "/pool/top-up"
	if method == ControlPoolAck {
		path = "/pool/ack"
	}
	n, applicationError, err := provider.exchange(call, http.MethodPost, path, nil, wire, p.response, false, true)
	if err != nil {
		return result, err
	}
	if err = call.Err(); err != nil {
		return result, err
	}
	result, err = decoder.DecodePoolControlResult(call, method, applicationError, p.response[:n:n], dst)
	if err == nil {
		err = checkPoolControlResult(method, applicationError, result, len(dst))
	}
	return result, err
}

func (p *PoolHTTPSTransport) Close() {
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
func (p *PoolHTTPSTransport) cleanupLocked() {
	if !p.closed || p.busy || p.cleaned {
		return
	}
	// The original call joins its one observer after the decoder and evidence
	// cleanup exit. A live callback keeps busy set after physical I/O closes.
	if p.provider != nil {
		if err := p.provider.Retire(); err != nil {
			return
		}
	}
	clear(p.response)
	p.response, p.provider, p.decoder = nil, nil, nil
	p.reservation.Release()
	p.shared.Release()
	p.reservation, p.shared = resourcev4.Reference{}, resourcev4.Reference{}
	p.cleaned = true
	close(p.done)
}
func (p *PoolHTTPSTransport) WaitCleanup(ctx context.Context) error {
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

var _ sessionv4.TopUpControlTransport = (*PoolHTTPSTransport)(nil)
