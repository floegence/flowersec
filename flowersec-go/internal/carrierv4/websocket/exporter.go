package websocket

import (
	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/internal/exporter"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

// WebSocketConnection exposes the concrete original owner to private Session
// assembly, including when a factory retains its lifetime around this owner.
func (m *Messages) WebSocketConnection() *Messages { return m }

func (m *Messages) ExportBinding(artifact [32]byte) ([32]byte, error) {
	if m == nil || m.owner == nil {
		return [32]byte{}, resourcev4.ErrOwner
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.retired || m.preparing || m.conn == nil {
		return [32]byte{}, resourcev4.ErrClosed
	}
	if err := m.reservation.Check(); err != nil {
		return [32]byte{}, err
	}
	if err := m.environment.Check(); err != nil {
		return [32]byte{}, err
	}
	if m.tlsConnection == nil {
		return [32]byte{}, exporter.ErrUnavailable
	}
	state := m.tlsConnection.ConnectionState()
	if state.NegotiatedProtocol != "" && state.NegotiatedProtocol != "http/1.1" {
		return [32]byte{}, exporter.ErrUnavailable
	}
	return exporter.Raw(state, artifact)
}
