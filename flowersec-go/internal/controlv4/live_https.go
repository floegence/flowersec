package controlv4

import (
	"context"
	"net/http"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

const liveRequestBytes = 1024

// EncodeLiveAuthorizationRequest writes the reference application's
// live-authorization-1 envelope. This fixed CBOR array is an application
// binding, not an L0 credential or proof of authority. The server independently
// authenticates the client and resolves the original Artifact by its digest.
// The request contains no PSK, signed Artifact, or identity private key.
func EncodeLiveAuthorizationRequest(dst []byte, q sessionv4.LiveAuthorizationRequest) (int, error) {
	if err := checkLiveRequest(q); err != nil {
		return 0, err
	}
	w := poolWireWriter{dst: dst[:min(len(dst), liveRequestBytes)]}
	w.array(13)
	w.text("live-authorization-1")
	for _, s := range []string{q.Tenant, q.Audience, q.CryptoProfile} {
		w.text(s)
	}
	for _, b := range [][]byte{q.Issuer[:], q.Lease[:], q.Attempt[:], q.Artifact[:], q.ClientIdentity[:], q.ServerIdentity[:]} {
		w.blob(b)
	}
	w.array(3)
	w.uint(q.Winner.Index)
	w.blob(q.Winner.CandidateID[:])
	w.blob(q.Winner.RouteDigest[:])
	w.uint(q.ActivationNotAfterMS)
	w.uint(uint64(q.AttemptNo))
	if w.err != nil {
		clear(dst[:w.n])
		return 0, w.err
	}
	return w.n, nil
}

func checkLiveRequest(q sessionv4.LiveAuthorizationRequest) error {
	for _, s := range []string{q.Tenant, q.Audience} {
		if len(s) == 0 || len(s) > 128 {
			return resourcev4.ErrConfiguration
		}
		for i, c := range s {
			alpha := c >= 'a' && c <= 'z' || c >= '0' && c <= '9'
			if !alpha && (i == 0 || c != '.' && c != '_' && c != ':' && c != '/' && c != '@' && c != '-') {
				return resourcev4.ErrConfiguration
			}
		}
	}
	if q.CryptoProfile != "fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1" && q.CryptoProfile != "fs4-kkpsk0-p256-aes256gcm-ed25519-sha256-1" {
		return resourcev4.ErrConfiguration
	}
	if q.Winner.Index > 15 || q.ActivationNotAfterMS == 0 || q.AttemptNo != 1 {
		return resourcev4.ErrConfiguration
	}
	return nil
}

type LiveHTTPSConfig struct {
	HTTPS        HTTPSBootstrapConfig
	RuntimeBytes uint64
	Tunnel       bool
}

// LiveHTTPSTransport performs a single POST <BaseURL>/live/authorize over an
// independently configured TLS 1.3 connection with explicit client identity.
// The server must require and authorize that identity before its original
// durable invocation. Success is HTTP 200/application/cbor and the complete
// original signed ActivationAuthorization. A receipt or HTTP error is never
// converted into new authorization. Session verifies the returned proof against
// the current namespace, original request, winner and activation owner.
//
// No physical retry, redirect, cookie jar, proxy or connection pool exists.
// Close fences publication; cleanup retains the original buffers and resource
// owners until network I/O and any TLS callback have actually exited.
type LiveHTTPSTransport struct {
	mu                    sync.Mutex
	provider              *HTTPSBootstrapProvider
	decoder               *protocolv4.Decoder
	response              []byte
	reservation, shared   resourcev4.Reference
	request               [liveRequestBytes]byte
	cancel                context.CancelFunc
	done                  chan struct{}
	busy, closed, cleaned bool
}

func LiveHTTPSTransportCharge(c LiveHTTPSConfig) (resourcev4.Vector, error) {
	if c.RuntimeBytes == 0 || c.HTTPS.TLS == nil || len(c.HTTPS.TLS.Certificates) == 0 && c.HTTPS.TLS.GetClientCertificate == nil {
		return resourcev4.Vector{}, resourcev4.ErrConfiguration
	}
	if _, err := HTTPSBootstrapCharge(c.HTTPS); err != nil {
		return resourcev4.Vector{}, err
	}
	var extra uint64
	if c.Tunnel {
		limit := liveTunnelMaterialLimit()
		codec, err := protocolv4.DecoderBackingBytes(limit, 4)
		if err != nil {
			return resourcev4.Vector{}, err
		}
		extra = codec + uint64(limit)
	}
	return (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(LiveHTTPSTransport{})) + extra, resourcev4.Items: 1, resourcev4.WorkSlots: 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: c.RuntimeBytes})
}

func NewLiveHTTPSTransport(c LiveHTTPSConfig, reservation, providerReservation, dependencies resourcev4.Reference) (*LiveHTTPSTransport, error) {
	cost, err := LiveHTTPSTransportCharge(c)
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
	p := &LiveHTTPSTransport{provider: provider, reservation: owned, shared: shared, done: make(chan struct{})}
	if c.Tunnel {
		p.decoder, err = protocolv4.NewDecoder(liveTunnelMaterialLimit(), 4)
		if err != nil {
			p.Close()
			return nil, err
		}
		p.response = make([]byte, liveTunnelMaterialLimit())
	}
	return p, nil
}

func (p *LiveHTTPSTransport) RequestAuthorization(ctx context.Context, q sessionv4.LiveAuthorizationRequest, dst []byte) (int, error) {
	sizes, err := p.requestAuthorization(ctx, q, [2][]byte{dst, nil}, false)
	return sizes[0], err
}

func (p *LiveHTTPSTransport) RequestTunnelAuthorization(ctx context.Context, q sessionv4.LiveAuthorizationRequest, dst [2][]byte) ([2]int, error) {
	return p.requestAuthorization(ctx, q, dst, true)
}

func (p *LiveHTTPSTransport) requestAuthorization(ctx context.Context, q sessionv4.LiveAuthorizationRequest, outputs [2][]byte, tunnel bool) (sizes [2]int, err error) {
	dst := outputs[0]
	limit, _ := protocolv4.SchemaByteLimit("ActivationAuthorization")
	if p == nil || ctx == nil || len(dst) < limit {
		return sizes, resourcev4.ErrConfiguration
	}
	if !p.mu.TryLock() {
		return sizes, ErrBusy
	}
	if p.closed || p.busy {
		p.mu.Unlock()
		return sizes, ErrBusy
	}
	if tunnel {
		grant, _ := protocolv4.SchemaByteLimit("Grant")
		if p.decoder == nil || len(outputs[1]) < grant {
			p.mu.Unlock()
			return sizes, resourcev4.ErrConfiguration
		}
	}
	err = p.reservation.Check()
	if err == nil {
		err = p.shared.Check()
	}
	if err != nil {
		p.mu.Unlock()
		return sizes, err
	}
	size, err := EncodeLiveAuthorizationRequest(p.request[:], q)
	if err != nil {
		p.mu.Unlock()
		return sizes, err
	}
	call := newHTTPSCallContext(p.provider)
	p.busy, p.cancel = true, call.stopCall
	provider := p.provider
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
			err = p.shared.Check()
		}
		if p.closed && err == nil {
			err = context.Canceled
		}
		if err != nil {
			sizes = [2]int{}
			clear(dst[:limit])
			clear(outputs[1])
		}
		clear(p.request[:])
		clear(p.response)
		call.stopCall()
		p.busy, p.cancel = false, nil
		p.cleanupLocked()
	}()
	if err = call.start(ctx); err == nil {
		body := dst[:limit:limit]
		if tunnel {
			body = p.response
		}
		var n int
		n, _, err = provider.exchange(call, http.MethodPost, "/live/authorize", nil, p.request[:size:size], body, false, false)
		if err == nil {
			if tunnel {
				sizes, err = decodeLiveTunnelMaterial(p.decoder, body[:n:n], outputs)
			} else {
				sizes[0] = n
			}
		}
	}
	returned = true
	return sizes, err
}

func (p *LiveHTTPSTransport) Close() {
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

func (p *LiveHTTPSTransport) cleanupLocked() {
	if !p.closed || p.busy || p.cleaned {
		return
	}
	if p.provider != nil && p.provider.Retire() != nil {
		return
	}
	clear(p.request[:])
	clear(p.response)
	p.response, p.decoder = nil, nil
	p.provider = nil
	p.reservation.Release()
	p.shared.Release()
	p.reservation, p.shared = resourcev4.Reference{}, resourcev4.Reference{}
	p.cleaned = true
	close(p.done)
}

func (p *LiveHTTPSTransport) WaitCleanup(ctx context.Context) error {
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

var _ sessionv4.LiveAuthorizationProvider = (*LiveHTTPSTransport)(nil)
