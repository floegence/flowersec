package assemblyv4

import (
	"errors"
	"net"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/rawquic"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/webtransport"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

// InterruptTransport cuts the listener's original UDP socket. It admits no
// replacement listener and emits no application close to connected peers.
func (s *QUICServer) InterruptTransport() error {
	if s == nil {
		return resourcev4.ErrConfiguration
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.listener == nil {
		return resourcev4.ErrClosed
	}
	return s.listener.InterruptTransport()
}

// InterruptConnections closes the original admitted native sockets while
// preserving this listener. It sends no authenticated Flowersec CLOSE or fake
// failure. Each original Session observes the resulting actual transport I/O
// failure and retains responsibility for its normal cancellation and cleanup.
// The finite listener reservation covers the one-at-a-time operation; no
// second connection inventory or background shutdown task is created.
func (s *QUICServer) InterruptConnections() error {
	if s == nil {
		return resourcev4.ErrConfiguration
	}
	var result error
	for index := 0; ; index++ {
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return errors.Join(result, resourcev4.ErrClosed)
		}
		if index >= len(s.slots) {
			s.mu.Unlock()
			return result
		}
		var connection *rawquic.OwnedConnection
		ingress := s.slots[index]
		s.mu.Unlock()
		if ingress != nil {
			ingress.mu.Lock()
			if ingress.provider != nil {
				connection = ingress.provider.connection
			}
			ingress.mu.Unlock()
		}
		if connection != nil {
			result = errors.Join(result, connection.Close())
		}
	}
}
func (s *WebTransportServer) InterruptConnections() error {
	if s == nil {
		return resourcev4.ErrConfiguration
	}
	var result error
	for index := 0; ; index++ {
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return errors.Join(result, resourcev4.ErrClosed)
		}
		if index >= len(s.slots) {
			s.mu.Unlock()
			return result
		}
		var connection *webtransport.OwnedConnection
		ingress := s.slots[index]
		s.mu.Unlock()
		if ingress != nil {
			ingress.mu.Lock()
			if ingress.provider != nil {
				connection = ingress.provider.connection
			}
			ingress.mu.Unlock()
		}
		if connection != nil {
			result = errors.Join(result, connection.Close())
		}
	}
}
func (s *WebSocketServer) InterruptConnections() error {
	if s == nil {
		return resourcev4.ErrConfiguration
	}
	var result error
	for index := 0; ; index++ {
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return errors.Join(result, resourcev4.ErrClosed)
		}
		if index >= len(s.slots) {
			s.mu.Unlock()
			return result
		}
		var connection net.Conn
		if original := s.slots[index].connection; original != nil {
			connection = original
		}
		s.mu.Unlock()
		if connection != nil {
			err := connection.Close()
			if !errors.Is(err, net.ErrClosed) {
				result = errors.Join(result, err)
			}
		}
	}
}
