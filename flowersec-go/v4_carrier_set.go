package flowersec

import "github.com/floegence/flowersec/flowersec-go/v6/internal/assemblyv4"

type V4CarrierEndpoint = assemblyv4.CarrierEndpoint
type V4CarrierSetConfig = assemblyv4.CarrierSetConfig
type V4CarrierSet = assemblyv4.CarrierSet

func V4CarrierSetCharge(c V4CarrierSetConfig) (V4ResourceVector, error) {
	return assemblyv4.CarrierSetCharge(c)
}

func NewV4CarrierSet(c V4CarrierSetConfig, reservation, environment V4ResourceReference, accounts ...V4ResourceAccount) (*V4CarrierSet, error) {
	return assemblyv4.NewCarrierSet(c, reservation, environment, accounts...)
}
