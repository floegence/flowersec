package controlv4

import (
	"context"
	"net/http"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

type TunnelServerAllowHTTPSConfig struct {
	HTTPS        HTTPSBootstrapConfig
	RuntimeBytes uint64
}

// TunnelServerAllowHTTPSTransport publishes one original instruction over a
// separately authenticated TLS 1.3 connection. It has no retry, redirect,
// outbox or recovery queue. The caller owns the once-only publication guard.
// HTTP 200 with canonical CBOR true acknowledges receipt only; it says nothing
// about hop claim, pairing, end-to-end admission or READY.
type TunnelServerAllowHTTPSTransport struct {
	mu                    sync.Mutex
	provider              *HTTPSBootstrapProvider
	reservation, shared   resourcev4.Reference
	request               []byte
	response              [1]byte
	cancel                context.CancelFunc
	done                  chan struct{}
	busy, closed, cleaned bool
}

func TunnelServerAllowHTTPSTransportCharge(c TunnelServerAllowHTTPSConfig) (resourcev4.Vector, error) {
	if c.RuntimeBytes == 0 || c.HTTPS.TLS == nil || len(c.HTTPS.TLS.Certificates) == 0 && c.HTTPS.TLS.GetClientCertificate == nil {
		return resourcev4.Vector{}, resourcev4.ErrConfiguration
	}
	if _, err := HTTPSBootstrapCharge(c.HTTPS); err != nil {
		return resourcev4.Vector{}, err
	}
	limit, err := tunnelAllowWireLimit()
	if err != nil {
		return resourcev4.Vector{}, err
	}
	return (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(TunnelServerAllowHTTPSTransport{})) + uint64(limit), resourcev4.Items: 1, resourcev4.WorkSlots: 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: c.RuntimeBytes})
}

func NewTunnelServerAllowHTTPSTransport(c TunnelServerAllowHTTPSConfig, reservation, providerReservation, dependencies resourcev4.Reference) (*TunnelServerAllowHTTPSTransport, error) {
	cost, err := TunnelServerAllowHTTPSTransportCharge(c)
	if err != nil {
		return nil, err
	}
	for _, ref := range []resourcev4.Reference{providerReservation, dependencies} {
		if err = reservation.CheckSameEnvironment(ref); err != nil {
			return nil, err
		}
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
	borrow, err := dependencies.Borrow()
	if err != nil {
		owned.Release()
		shared.Release()
		return nil, err
	}
	provider, err := NewHTTPSBootstrapProvider(c.HTTPS, providerReservation, borrow)
	borrow.Release()
	if err != nil {
		owned.Release()
		shared.Release()
		return nil, err
	}
	limit, _ := tunnelAllowWireLimit()
	return &TunnelServerAllowHTTPSTransport{provider: provider, reservation: owned, shared: shared, request: make([]byte, limit), done: make(chan struct{})}, nil
}

func (p *TunnelServerAllowHTTPSTransport) PublishServerAllow(ctx context.Context, request sessionv4.TunnelServerAllowRequest, grant []byte, guard func() error) (err error) {
	if p == nil || ctx == nil || guard == nil {
		return resourcev4.ErrConfiguration
	}
	if !p.mu.TryLock() {
		return ErrBusy
	}
	if p.closed || p.busy {
		p.mu.Unlock()
		return ErrBusy
	}
	if err = p.reservation.Check(); err == nil {
		err = p.shared.Check()
	}
	if err != nil {
		p.mu.Unlock()
		return err
	}
	size, err := EncodeTunnelServerAllow(p.request, request, grant)
	if err != nil {
		p.mu.Unlock()
		return err
	}
	call := newHTTPSCallContext(p.provider)
	call.beforeWrite = guard
	p.busy, p.cancel = true, call.stopCall
	provider := p.provider
	p.mu.Unlock()
	returned := false
	defer func() {
		if recover() != nil || !returned {
			err = ErrControlTaskExit
			call.cancel(err)
		}
		call.finish()
		p.mu.Lock()
		defer p.mu.Unlock()
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
		clear(p.request)
		clear(p.response[:])
		call.beforeWrite = nil
		call.stopCall()
		p.busy, p.cancel = false, nil
		p.cleanupLocked()
	}()
	if err = call.start(ctx); err == nil {
		var n int
		n, _, err = provider.exchange(call, http.MethodPost, "/tunnel/server-allow", nil, p.request[:size:size], p.response[:], true, false)
		if err == nil && (n != 1 || p.response[0] != 0xf5) {
			err = ErrResponse
		}
	}
	returned = true
	return err
}

func (p *TunnelServerAllowHTTPSTransport) Close() {
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

func (p *TunnelServerAllowHTTPSTransport) cleanupLocked() {
	if !p.closed || p.busy || p.cleaned {
		return
	}
	if p.provider != nil && p.provider.Retire() != nil {
		return
	}
	clear(p.request)
	p.request, p.provider = nil, nil
	p.reservation.Release()
	p.shared.Release()
	p.reservation, p.shared = resourcev4.Reference{}, resourcev4.Reference{}
	p.cleaned = true
	close(p.done)
}

func (p *TunnelServerAllowHTTPSTransport) WaitCleanup(ctx context.Context) error {
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

var _ sessionv4.TunnelServerAllowProvider = (*TunnelServerAllowHTTPSTransport)(nil)
