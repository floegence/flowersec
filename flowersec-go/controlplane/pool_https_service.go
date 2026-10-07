package controlplane

import (
	"github.com/floegence/flowersec/flowersec-go/v6/internal/controlv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

type PoolHTTPSServiceConfig = controlv4.PoolHTTPSServiceConfig
type PoolHTTPSService = controlv4.PoolHTTPSService

func PoolHTTPSServiceCharge(c PoolHTTPSServiceConfig) (resourcev4.Vector, error) {
	return controlv4.PoolHTTPSServiceCharge(c)
}
func NewPoolHTTPSService(c PoolHTTPSServiceConfig, reservation, dependencies resourcev4.Reference) (*PoolHTTPSService, error) {
	return controlv4.NewPoolHTTPSService(c, reservation, dependencies)
}
