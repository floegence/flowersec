package flowersec

import (
	"context"
	"net/http"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/assemblyv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
)

const (
	CurrentWebSocketDirectPath = "/flowersec/v4/direct"
	CurrentWebSocketTunnelPath = "/flowersec/v4/tunnel"
)

type WebSocketIngress = assemblyv4.WebSocketIngress
type WebSocketIngressConfig = assemblyv4.WebSocketIngressConfig

func WebSocketIngressCharge(config WebSocketIngressConfig) (ResourceVector, error) {
	return assemblyv4.WebSocketIngressCharge(config)
}

func NewWebSocketIngress(writer http.ResponseWriter, request *http.Request, config WebSocketIngressConfig, reservation ResourceReference) (*WebSocketIngress, error) {
	return assemblyv4.NewWebSocketIngress(writer, request, config, reservation)
}

// PrepareTunnel uses the listener's original signed route, TLS policy and
// pre-authentication scope. Its nonnil result transfers cleanup even with an
// error. HOP_AUTH and durable claim still belong to NewTunnelHop.
func (s *QUICServer) PrepareTunnel(ctx context.Context, config PreparedCarrierConfig) (*PreparedCarrier, error) {
	if s == nil || s.inner == nil {
		return nil, cryptov4.ErrConfiguration
	}
	return s.inner.PrepareTunnel(ctx, config)
}

func (s *WebTransportServer) PrepareTunnel(ctx context.Context, config PreparedCarrierConfig) (*PreparedCarrier, error) {
	if s == nil || s.inner == nil {
		return nil, cryptov4.ErrConfiguration
	}
	return s.inner.PrepareTunnel(ctx, config)
}
