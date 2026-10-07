package controlv4

import (
	"context"
	"net/http"
	"net/url"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

const remoteOriginalLiveRelayBodyBytes = 2*65536 + liveRequestBytes + 256

// RemoteOriginalLiveRelayConfig fixes one original issuer mTLS transport before
// TxA. The relay's public mapping is installed independently; this provider has
// no relay ledger, parent material lookup or publication recovery capability.
type RemoteOriginalLiveRelayConfig struct {
	HTTPS        HTTPSBootstrapConfig
	RuntimeBytes uint64
}

// RemoteOriginalLiveRelay retains its prepaid original request and physical
// transport until the TxB callback returns. A dispatch is consumed once, even
// on failure, and never rescheduled or reconstructed from a stored result.
type RemoteOriginalLiveRelay struct {
	mu                          sync.Mutex
	provider                    *HTTPSBootstrapProvider
	reservation, dependencies   resourcev4.Reference
	body, request               []byte
	cancel                      context.CancelFunc
	busy, used, closed, cleaned bool
	done                        chan struct{}
}

func RemoteOriginalLiveRelayCharges(c RemoteOriginalLiveRelayConfig) (resourcev4.Vector, resourcev4.Vector, error) {
	u, err := url.Parse(c.HTTPS.BaseURL)
	if err != nil || u.Scheme != "https" || u.Path != "/" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.User != nil || c.RuntimeBytes == 0 || c.HTTPS.TLS == nil || len(c.HTTPS.TLS.Certificates) != 1 || c.HTTPS.TLS.GetClientCertificate != nil {
		return resourcev4.Vector{}, resourcev4.Vector{}, resourcev4.ErrConfiguration
	}
	provider, err := HTTPSBootstrapCharge(c.HTTPS)
	if err != nil {
		return resourcev4.Vector{}, resourcev4.Vector{}, err
	}
	cost, err := (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(RemoteOriginalLiveRelay{})) + remoteOriginalLiveRelayBodyBytes + liveRequestBytes + controlCallContextBytes + 1, resourcev4.Items: 1, resourcev4.Tasks: 1, resourcev4.WorkSlots: 1, resourcev4.Timers: 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: c.RuntimeBytes})
	return cost, provider, err
}

func NewRemoteOriginalLiveRelay(c RemoteOriginalLiveRelayConfig, reservation, providerReservation, dependencies resourcev4.Reference) (*RemoteOriginalLiveRelay, error) {
	cost, _, err := RemoteOriginalLiveRelayCharges(c)
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
	return &RemoteOriginalLiveRelay{provider: provider, reservation: owned, dependencies: shared, body: make([]byte, remoteOriginalLiveRelayBodyBytes), request: make([]byte, liveRequestBytes), done: make(chan struct{})}, nil
}

func (p *RemoteOriginalLiveRelay) DispatchOriginalLive(ctx context.Context, q sessionv4.LiveAuthorizationRequest, material [3][]byte, guard func() error) (err error) {
	if p == nil || ctx == nil || guard == nil {
		return resourcev4.ErrConfiguration
	}
	if !p.mu.TryLock() {
		return ErrBusy
	}
	if p.closed || p.busy || p.used {
		p.mu.Unlock()
		return ErrBusy
	}
	if err = p.reservation.Check(); err == nil {
		err = p.dependencies.Check()
	}
	if err != nil {
		p.mu.Unlock()
		return err
	}
	// Claim before inspecting original material: malformed or canceled originals
	// do not leave an authority with permission to dispatch a second invocation.
	call := newHTTPSCallContext(p.provider)
	p.busy, p.used, p.cancel = true, true, call.stopCall
	p.mu.Unlock()
	returned := false
	defer func() {
		if recovered := recover(); recovered != nil || !returned {
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
			err = p.dependencies.Check()
		}
		if p.closed && err == nil {
			err = context.Canceled
		}
		clear(p.body)
		clear(p.request)
		call.stopCall()
		p.busy, p.cancel = false, nil
		p.cleanupLocked()
	}()
	check := func() error {
		if err := call.cause(); err != nil {
			return err
		}
		if err := p.reservation.Check(); err != nil {
			return err
		}
		if err := p.dependencies.Check(); err != nil {
			return err
		}
		return guard()
	}
	call.beforeWrite = check
	if err = call.start(ctx); err == nil {
		err = check()
	}
	var size int
	if err == nil {
		size, err = EncodeLiveAuthorizationRequest(p.request, q)
	}
	if err == nil && (len(material[0]) == 0 || len(material[0]) > 65536 || len(material[2]) == 0 || len(material[2]) > 65536) {
		err = ErrResponse
	}
	writer := poolWireWriter{dst: p.body}
	if err == nil {
		writer.array(4)
		writer.text("tunnel-relay-server-grant-1")
		writer.blob(p.request[:size])
		writer.blob(material[0])
		writer.blob(material[2])
		err = writer.err
	}
	var response [1]byte
	if err == nil {
		err = check()
	}
	if err == nil {
		var count int
		count, _, err = p.provider.exchangeContent(call, http.MethodPost, "/tunnel/relay-server-grant", nil, p.body[:writer.n], response[:], true, false, "application/cbor")
		if err == nil && (count != 1 || response[0] != 0xf5) {
			err = ErrResponse
		}
	}
	if err == nil {
		err = check()
	}
	returned = true
	return err
}

func (p *RemoteOriginalLiveRelay) Close() {
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
func (p *RemoteOriginalLiveRelay) cleanupLocked() {
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
	p.reservation.Release()
	p.dependencies.Release()
	p.cleaned = true
	close(p.done)
}
func (p *RemoteOriginalLiveRelay) WaitCleanup(ctx context.Context) error {
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
