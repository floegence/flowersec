package controlplane

import (
	"context"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/controlv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

type PoolTunnelDeploymentConfig = controlv4.PoolTunnelDeploymentConfig
type PoolTunnelDeployment = controlv4.PoolTunnelDeployment

func PoolTunnelDeploymentCharge(c PoolTunnelDeploymentConfig) (resourcev4.Vector, error) {
	return controlv4.PoolTunnelDeploymentCharge(c)
}
func NewPoolTunnelDeployment(ctx context.Context, c PoolTunnelDeploymentConfig, reservation, dependencies resourcev4.Reference) (*PoolTunnelDeployment, error) {
	return controlv4.NewPoolTunnelDeployment(ctx, c, reservation, dependencies)
}

type PoolTunnelSigningRoute = controlv4.PoolTunnelSigningRoute
type PoolTunnelDeploymentPolicyConfig = controlv4.PoolTunnelDeploymentPolicyConfig

func PoolTunnelDeploymentPolicyCharge(c PoolTunnelDeploymentPolicyConfig) (resourcev4.Vector, error) {
	return controlv4.PoolTunnelDeploymentPolicyCharge(c)
}
func NewPoolTunnelDeploymentFromPolicy(ctx context.Context, c PoolTunnelDeploymentPolicyConfig, reservation, dependencies resourcev4.Reference) (*PoolTunnelDeployment, error) {
	return controlv4.NewPoolTunnelDeploymentFromPolicy(ctx, c, reservation, dependencies)
}
