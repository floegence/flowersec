package flowersec

import (
	"context"
	"net/netip"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/assemblyv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
)

type V4WebTransportServerConfig = assemblyv4.WebTransportServerConfig

// V4WebTransportServer owns a finite native UDP/TLS listener and its accepted ingress
// positions. It exposes neither a raw native connection nor an unauthenticated
// Session. The Environment and immutable signing dependencies remain shared.
type V4WebTransportServer struct {
	inner *assemblyv4.WebTransportServer
}

// V4WebTransportIngress owns one accepted TLS connection until ServeHandle.AcceptWebTransport
// transfers it to the existing Environment admission path. Close an ingress
// which will not be accepted; WaitCleanup observes its actual native retirement.
type V4WebTransportIngress struct {
	inner *assemblyv4.WebTransportIngress
}

func V4WebTransportServerCharge(c V4WebTransportServerConfig) (V4ResourceVector, error) {
	return assemblyv4.WebTransportServerCharge(c)
}

func NewV4WebTransportServer(c V4WebTransportServerConfig, reservation, environment V4ResourceReference) (*V4WebTransportServer, error) {
	server, err := assemblyv4.NewWebTransportServer(c, reservation, environment)
	if err != nil {
		return nil, err
	}
	return &V4WebTransportServer{inner: server}, nil
}

// Accept admits and verifies one native connection without reading ClientHello.
// The original entrance policy and deadline must be passed unchanged to
// ServeHandle.AcceptWebTransport. Calls are bounded by the configured ingress positions.
func (s *V4WebTransportServer) Accept(ctx context.Context, entrance V4AcceptedEntranceConfig) (*V4WebTransportIngress, error) {
	if s == nil || s.inner == nil {
		return nil, cryptov4.ErrConfiguration
	}
	ingress, err := s.inner.Accept(ctx, entrance)
	if err != nil {
		return nil, err
	}
	return &V4WebTransportIngress{inner: ingress}, nil
}

func (s *V4WebTransportServer) Address() netip.AddrPort {
	if s == nil || s.inner == nil {
		return netip.AddrPort{}
	}
	return s.inner.Address()
}

func (s *V4WebTransportServer) Close() error {
	if s == nil || s.inner == nil {
		return nil
	}
	return s.inner.Close()
}

func (s *V4WebTransportServer) WaitCleanup(ctx context.Context) error {
	if s == nil || s.inner == nil {
		return cryptov4.ErrConfiguration
	}
	return s.inner.WaitCleanup(ctx)
}

func (i *V4WebTransportIngress) Close() error {
	if i == nil || i.inner == nil {
		return nil
	}
	return i.inner.Close()
}

func (i *V4WebTransportIngress) WaitCleanup(ctx context.Context) error {
	if i == nil || i.inner == nil {
		return cryptov4.ErrConfiguration
	}
	return i.inner.WaitCleanup(ctx)
}
