package flowersec

import (
	"context"
	"net/netip"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/assemblyv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
)

type QUICServerConfig = assemblyv4.QUICServerConfig

// QUICServer owns a finite native UDP/TLS listener and its accepted ingress
// positions. It exposes neither a raw native connection nor an unauthenticated
// Session. The TransportEnvironment and immutable signing dependencies remain shared.
type QUICServer struct{ inner *assemblyv4.QUICServer }

// QUICIngress owns one accepted TLS connection until ServeHandle.AcceptQUIC
// transfers it to the existing TransportEnvironment admission path. Close an ingress
// which will not be accepted; WaitCleanup observes its actual native retirement.
type QUICIngress struct{ inner *assemblyv4.QUICIngress }

func QUICServerCharge(c QUICServerConfig) (ResourceVector, error) {
	return assemblyv4.QUICServerCharge(c)
}

func NewQUICServer(c QUICServerConfig, reservation, environment ResourceReference) (*QUICServer, error) {
	server, err := assemblyv4.NewQUICServer(c, reservation, environment)
	if err != nil {
		return nil, err
	}
	return &QUICServer{inner: server}, nil
}

// Accept admits and verifies one native connection without reading ClientHello.
// The original entrance policy and deadline must be passed unchanged to
// ServeHandle.AcceptQUIC. Calls are bounded by the configured ingress positions.
func (s *QUICServer) Accept(ctx context.Context, entrance AcceptedEntranceConfig) (*QUICIngress, error) {
	if s == nil || s.inner == nil {
		return nil, cryptov4.ErrConfiguration
	}
	ingress, err := s.inner.Accept(ctx, entrance)
	if err != nil {
		return nil, err
	}
	return &QUICIngress{inner: ingress}, nil
}

func (s *QUICServer) Address() netip.AddrPort {
	if s == nil || s.inner == nil {
		return netip.AddrPort{}
	}
	return s.inner.Address()
}

func (s *QUICServer) Close() error {
	if s == nil || s.inner == nil {
		return nil
	}
	return s.inner.Close()
}

func (s *QUICServer) InterruptConnections() error {
	if s == nil || s.inner == nil {
		return cryptov4.ErrConfiguration
	}
	return s.inner.InterruptConnections()
}

// InterruptTransport cuts the original UDP socket without sending an
// application close. Follow it with Close and WaitCleanup to retire the server.
func (s *QUICServer) InterruptTransport() error {
	if s == nil || s.inner == nil {
		return cryptov4.ErrConfiguration
	}
	return s.inner.InterruptTransport()
}

func (s *QUICServer) WaitCleanup(ctx context.Context) error {
	if s == nil || s.inner == nil {
		return cryptov4.ErrConfiguration
	}
	return s.inner.WaitCleanup(ctx)
}

func (i *QUICIngress) Close() error {
	if i == nil || i.inner == nil {
		return nil
	}
	return i.inner.Close()
}

func (i *QUICIngress) WaitCleanup(ctx context.Context) error {
	if i == nil || i.inner == nil {
		return cryptov4.ErrConfiguration
	}
	return i.inner.WaitCleanup(ctx)
}
