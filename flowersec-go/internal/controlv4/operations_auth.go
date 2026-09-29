package controlv4

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/netip"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// OperationsTLSConfig is for a separately admitted native management listener.
// It requires an independent client CA and TLS 1.3. Resumption is disabled so a
// new connection cannot reuse an old client-certificate authentication result.
// Server credentials, client roots and their native backing remain immutable
// caller-owned dependencies through actual listener cleanup.
func OperationsTLSConfig(server tls.Certificate, clientRoots *x509.CertPool) (*tls.Config, error) {
	if len(server.Certificate) == 0 || server.PrivateKey == nil || clientRoots == nil {
		return nil, resourcev4.ErrConfiguration
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{server}, ClientCAs: clientRoots,
		ClientAuth: tls.RequireAndVerifyClientCert, SessionTicketsDisabled: true,
		NextProtos: []string{"http/1.1"}}, nil
}

func (p *OperationsService) begin() (*controlCallContext, int) {
	if !p.mu.TryLock() {
		operationsIncrement(&p.capacity)
		return nil, http.StatusTooManyRequests
	}
	defer p.mu.Unlock()
	if p.closed || p.reservation.Check() != nil || p.dependencies.Check() != nil || p.environment.CheckRetained() != nil {
		return nil, http.StatusServiceUnavailable
	}
	if p.busy {
		operationsIncrement(&p.capacity)
		return nil, http.StatusTooManyRequests
	}
	call := newControlCallContext(time.Duration(p.config.CallMS) * time.Millisecond)
	p.busy, p.cancel = true, call.stopCall
	return call, http.StatusOK
}

// The original request or incident worker pins config through this sample.
// A callback may close the service; the following gate rechecks that closure.
func (p *OperationsService) sample() (timev4.Sample, error) {
	p.mu.Lock()
	if p.closed || p.cleaned || !p.busy && !p.incidentRunning {
		p.mu.Unlock()
		return timev4.Sample{}, timev4.ErrUnavailable
	}
	clock := p.config.Clock
	p.mu.Unlock()
	return clock.Sample()
}

func (p *OperationsService) authenticate(r *http.Request) (int, int) {
	now, err := p.sample()
	if err != nil {
		return 0, http.StatusServiceUnavailable
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.reservation.Check() != nil || p.dependencies.Check() != nil || p.environment.CheckRetained() != nil {
		return 0, http.StatusServiceUnavailable
	}
	if p.hasOrigin {
		if !now.Mark.SameEra(p.origin) || now.Milliseconds < p.origin.Milliseconds {
			return 0, http.StatusServiceUnavailable
		}
		lower, _, err := p.config.Clock.Profile().Rate.Elapsed(now.Milliseconds - p.origin.Milliseconds)
		if err != nil {
			return 0, http.StatusServiceUnavailable
		}
		if lower >= 60000 {
			p.origin, p.requests = now.Mark, 0
		}
	} else {
		p.origin, p.hasOrigin = now.Mark, true
	}
	if p.requests >= p.config.RequestsPerMinute {
		operationsIncrement(&p.capacity)
		return 0, http.StatusTooManyRequests
	}
	p.requests++ // Denials share a finite pre-query flood bound.
	deny := func() (int, int) {
		operationsIncrement(&p.denied)
		return 0, http.StatusForbidden
	}
	remote, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return deny()
	}
	allowed := false
	for _, network := range p.networks[:p.networkCount] {
		allowed = allowed || network.Contains(remote.Addr())
	}
	state := r.TLS
	if !allowed || state == nil || !state.HandshakeComplete || state.Version != tls.VersionTLS13 || len(state.PeerCertificates) == 0 || len(state.PeerCertificates) > 8 || len(state.VerifiedChains) == 0 || len(state.VerifiedChains[0]) == 0 {
		return deny()
	}
	leaf, verified := state.PeerCertificates[0], state.VerifiedChains[0][0]
	if leaf == nil || verified == nil || len(leaf.Raw) == 0 || len(leaf.Raw) > 16384 || !bytes.Equal(leaf.Raw, verified.Raw) {
		return deny()
	}
	digest := sha256.Sum256(leaf.Raw)
	for i, reader := range p.readers[:p.readerCount] {
		if reader.digest != digest || reader.revoked || now.LowerMS < reader.notBefore || now.UpperMS >= reader.notAfter {
			continue
		}
		return i, http.StatusOK
	}
	return deny()
}

// Recheck the exact original registration before native output handoff. A
// revoked registration cannot be replaced with another matching current user.
func (p *OperationsService) current(reader int) bool {
	now, err := p.sample()
	if err != nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.currentLocked(reader, now)
}

func (p *OperationsService) currentLocked(reader int, now timev4.Sample) bool {
	if p.closed || reader < 0 || reader >= p.readerCount || p.readers[reader].revoked || p.reservation.Check() != nil || p.dependencies.Check() != nil {
		return false
	}
	if !now.BelongsTo(p.config.Clock) {
		return false
	}
	r := p.readers[reader]
	return now.LowerMS >= r.notBefore && now.UpperMS < r.notAfter
}
