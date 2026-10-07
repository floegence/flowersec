package controlplane

import (
	"github.com/floegence/flowersec/flowersec-go/v6/internal/controlv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

type TunnelServerAllowHTTPSServiceConfig = controlv4.TunnelServerAllowHTTPSServiceConfig
type TunnelServerAllowHTTPSService = controlv4.TunnelServerAllowHTTPSService

func TunnelServerAllowHTTPSServiceCharge(c TunnelServerAllowHTTPSServiceConfig) (resourcev4.Vector, error) {
	return controlv4.TunnelServerAllowHTTPSServiceCharge(c)
}

func NewTunnelServerAllowHTTPSService(c TunnelServerAllowHTTPSServiceConfig, reservation, dependencies resourcev4.Reference) (*TunnelServerAllowHTTPSService, error) {
	return controlv4.NewTunnelServerAllowHTTPSService(c, reservation, dependencies)
}
