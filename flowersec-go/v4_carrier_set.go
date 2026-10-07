package flowersec

import "github.com/floegence/flowersec/flowersec-go/v6/internal/assemblyv4"

type CarrierEndpoint = assemblyv4.CarrierEndpoint
type CarrierSetConfig = assemblyv4.CarrierSetConfig
type CarrierSet = assemblyv4.CarrierSet

func CarrierSetCharge(c CarrierSetConfig) (ResourceVector, error) {
	return assemblyv4.CarrierSetCharge(c)
}

func NewCarrierSet(c CarrierSetConfig, reservation, environment ResourceReference, accounts ...ResourceAccount) (*CarrierSet, error) {
	return assemblyv4.NewCarrierSet(c, reservation, environment, accounts...)
}
