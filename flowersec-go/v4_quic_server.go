package flowersec

import (
	"context"
	"net/netip"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/assemblyv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
)

type V4QUICServerConfig = assemblyv4.QUICServerConfig

// V4QUICServer owns a finite native UDP/TLS listener and its accepted ingress
// positions. It exposes neither a raw native connection nor an unauthenticated
// Session. The Environment and immutable signing dependencies remain shared.
type V4QUICServer struct{ inner *assemblyv4.QUICServer }

// V4QUICIngress owns one accepted TLS connection until ServeHandle.AcceptQUIC
// transfers it to the existing Environment admission path. Close an ingress
// which will not be accepted; WaitCleanup observes its actual native retirement.
type V4QUICIngress struct{ inner *assemblyv4.QUICIngress }

func V4QUICServerCharge(c V4QUICServerConfig) (V4ResourceVector, error) {
	return assemblyv4.QUICServerCharge(c)
}

func NewV4QUICServer(c V4QUICServerConfig, reservation, environment V4ResourceReference) (*V4QUICServer, error) {
	server, err := assemblyv4.NewQUICServer(c, reservation, environment)
	if err != nil {
		return nil, err
	}
	return &V4QUICServer{inner: server}, nil
}

// Accept admits and verifies one native connection without reading ClientHello.
// The original entrance policy and deadline must be passed unchanged to
// ServeHandle.AcceptQUIC. Calls are bounded by the configured ingress positions.
func (s *V4QUICServer) Accept(ctx context.Context, entrance V4AcceptedEntranceConfig) (*V4QUICIngress, error) {
	if s == nil || s.inner == nil {
		return nil, cryptov4.ErrConfiguration
	}
	ingress, err := s.inner.Accept(ctx, entrance)
	if err != nil {
		return nil, err
	}
	return &V4QUICIngress{inner: ingress}, nil
}

func (s *V4QUICServer) Address() netip.AddrPort {
	if s == nil || s.inner == nil {
		return netip.AddrPort{}
	}
	return s.inner.Address()
}

func (s *V4QUICServer) Close() error {
	if s == nil || s.inner == nil {
		return nil
	}
	return s.inner.Close()
}

func (s *V4QUICServer) WaitCleanup(ctx context.Context) error {
	if s == nil || s.inner == nil {
		return cryptov4.ErrConfiguration
	}
	return s.inner.WaitCleanup(ctx)
}

func (i *V4QUICIngress) Close() error {
	if i == nil || i.inner == nil {
		return nil
	}
	return i.inner.Close()
}

func (i *V4QUICIngress) WaitCleanup(ctx context.Context) error {
	if i == nil || i.inner == nil {
		return cryptov4.ErrConfiguration
	}
	return i.inner.WaitCleanup(ctx)
}
