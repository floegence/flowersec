package controlplane

import (
	"github.com/floegence/flowersec/flowersec-go/v6/internal/controlv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

type PoolTunnelAuthorityConfig = controlv4.PoolTunnelAuthorityConfig
type PoolTunnelAuthority = controlv4.PoolTunnelAuthority

func PoolTunnelAuthorityCharge(config PoolTunnelAuthorityConfig) (resourcev4.Vector, error) {
	return controlv4.PoolTunnelAuthorityCharge(config)
}
func NewPoolTunnelAuthority(config PoolTunnelAuthorityConfig, reservation, dependencies resourcev4.Reference) (*PoolTunnelAuthority, error) {
	return controlv4.NewPoolTunnelAuthority(config, reservation, dependencies)
}
