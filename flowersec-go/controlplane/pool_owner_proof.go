package controlplane

import (
	"github.com/floegence/flowersec/flowersec-go/v6/internal/controlv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

type PoolOwnerProofIssuerConfig = controlv4.PoolOwnerProofIssuerConfig
type PoolOwnerProofIssuer = controlv4.PoolOwnerProofIssuer

func PoolOwnerProofIssuerCharge(c PoolOwnerProofIssuerConfig) (resourcev4.Vector, error) {
	return controlv4.PoolOwnerProofIssuerCharge(c)
}
func NewPoolOwnerProofIssuer(c PoolOwnerProofIssuerConfig, reservation, dependencies resourcev4.Reference) (*PoolOwnerProofIssuer, error) {
	return controlv4.NewPoolOwnerProofIssuer(c, reservation, dependencies)
}
