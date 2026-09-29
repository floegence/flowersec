package webtransport

import (
	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/internal/exporter"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/quic-go/quic-go/http3"
)

// ExportBinding retains the original TLS and CONNECT owners together. A
// missing installed association never falls back to a raw TLS exporter.
func (p *OwnedConnection) ExportBinding(artifact [32]byte) ([32]byte, error) {
	if p == nil || p.ownedConnection == nil {
		return [32]byte{}, resourcev4.ErrOwner
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.checkLocked(); err != nil {
		return [32]byte{}, err
	}
	select {
	case <-p.session.ready:
	default:
		return [32]byte{}, exporter.ErrUnavailable
	}
	state := p.conn.ConnectionState()
	if state.Used0RTT || state.TLS.NegotiatedProtocol != http3.NextProtoH3 || p.session.request == nil || uint64(p.session.request.StreamID()) != p.session.id {
		return [32]byte{}, exporter.ErrUnavailable
	}
	return exporter.WebTransport(state.TLS, p.session.id, artifact)
}
