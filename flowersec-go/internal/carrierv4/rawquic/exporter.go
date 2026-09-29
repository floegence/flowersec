package rawquic

import (
	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/internal/exporter"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

// ExportBinding is bounded local work on this original owned connection. The
// owner lock retains TLS backing until the derivation returns, even on Close.
func (p *OwnedConnection) ExportBinding(artifact [32]byte) ([32]byte, error) {
	if p == nil || p.ownedConnection == nil {
		return [32]byte{}, resourcev4.ErrOwner
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.checkLocked(); err != nil {
		return [32]byte{}, err
	}
	state := p.session.conn.ConnectionState()
	if state.Used0RTT || state.TLS.NegotiatedProtocol != ALPNDirect {
		return [32]byte{}, exporter.ErrUnavailable
	}
	return exporter.Raw(state.TLS, artifact)
}
