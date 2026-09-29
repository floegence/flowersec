package controlplane

import (
	"github.com/floegence/flowersec/flowersec-go/v6/internal/controlv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

type V4TunnelServerAllowHTTPSServiceConfig = controlv4.TunnelServerAllowHTTPSServiceConfig
type V4TunnelServerAllowHTTPSService = controlv4.TunnelServerAllowHTTPSService

func V4TunnelServerAllowHTTPSServiceCharge(c V4TunnelServerAllowHTTPSServiceConfig) (resourcev4.Vector, error) {
	return controlv4.TunnelServerAllowHTTPSServiceCharge(c)
}

func NewV4TunnelServerAllowHTTPSService(c V4TunnelServerAllowHTTPSServiceConfig, reservation, dependencies resourcev4.Reference) (*V4TunnelServerAllowHTTPSService, error) {
	return controlv4.NewTunnelServerAllowHTTPSService(c, reservation, dependencies)
}
