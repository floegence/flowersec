package flowersec

import "github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"

type TunnelCarrierPreparation = sessionv4.TunnelCarrierPreparation
type TunnelRouteConfig = sessionv4.TunnelRouteConfig
type TunnelRoute = sessionv4.TunnelRoute
type TunnelRouteRun = sessionv4.TunnelRouteRun

// TunnelRouteCharge admits the route invocation and immutable public material.
// NewTunnelRoute separately reserves both carriers, all six hop positions and
// the original forwarding pair before invoking either physical preparation.
func TunnelRouteCharge(config TunnelRouteConfig) (ResourceVector, error) {
	return sessionv4.TunnelRouteCharge(config)
}
func NewTunnelRoute(config TunnelRouteConfig, reservation, dependencies ResourceReference) (*TunnelRoute, error) {
	return sessionv4.NewTunnelRoute(config, reservation, dependencies)
}
