package flowersec

import (
	"context"
	"net/netip"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/assemblyv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
)

type WebTransportServerConfig = assemblyv4.WebTransportServerConfig

// WebTransportServer owns a finite native UDP/TLS listener and its accepted ingress
// positions. It exposes neither a raw native connection nor an unauthenticated
// Session. The TransportEnvironment and immutable signing dependencies remain shared.
type WebTransportServer struct {
	inner *assemblyv4.WebTransportServer
}

// WebTransportIngress owns one accepted TLS connection until ServeHandle.AcceptWebTransport
// transfers it to the existing TransportEnvironment admission path. Close an ingress
// which will not be accepted; WaitCleanup observes its actual native retirement.
type WebTransportIngress struct {
	inner *assemblyv4.WebTransportIngress
}

func WebTransportServerCharge(c WebTransportServerConfig) (ResourceVector, error) {
	return assemblyv4.WebTransportServerCharge(c)
}

func NewWebTransportServer(c WebTransportServerConfig, reservation, environment ResourceReference) (*WebTransportServer, error) {
	server, err := assemblyv4.NewWebTransportServer(c, reservation, environment)
	if err != nil {
		return nil, err
	}
	return &WebTransportServer{inner: server}, nil
}

// Accept admits and verifies one native connection without reading ClientHello.
// The original entrance policy and deadline must be passed unchanged to
// ServeHandle.AcceptWebTransport. Calls are bounded by the configured ingress positions.
func (s *WebTransportServer) Accept(ctx context.Context, entrance AcceptedEntranceConfig) (*WebTransportIngress, error) {
	if s == nil || s.inner == nil {
		return nil, cryptov4.ErrConfiguration
	}
	ingress, err := s.inner.Accept(ctx, entrance)
	if err != nil {
		return nil, err
	}
	return &WebTransportIngress{inner: ingress}, nil
}

func (s *WebTransportServer) Address() netip.AddrPort {
	if s == nil || s.inner == nil {
		return netip.AddrPort{}
	}
	return s.inner.Address()
}

func (s *WebTransportServer) Close() error {
	if s == nil || s.inner == nil {
		return nil
	}
	return s.inner.Close()
}

func (s *WebTransportServer) InterruptConnections() error {
	if s == nil || s.inner == nil {
		return cryptov4.ErrConfiguration
	}
	return s.inner.InterruptConnections()
}

func (s *WebTransportServer) WaitCleanup(ctx context.Context) error {
	if s == nil || s.inner == nil {
		return cryptov4.ErrConfiguration
	}
	return s.inner.WaitCleanup(ctx)
}

func (i *WebTransportIngress) Close() error {
	if i == nil || i.inner == nil {
		return nil
	}
	return i.inner.Close()
}

func (i *WebTransportIngress) WaitCleanup(ctx context.Context) error {
	if i == nil || i.inner == nil {
		return cryptov4.ErrConfiguration
	}
	return i.inner.WaitCleanup(ctx)
}
