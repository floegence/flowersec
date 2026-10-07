package controlplane

import (
	"github.com/floegence/flowersec/flowersec-go/v6/internal/controlv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

// These deployment owners must be constructed from independently provisioned
// identity, source fences and original trust. A SQLite journal never supplies
// or reconstructs its own source authority.
type PoolBatchVerificationConfig = controlv4.PoolBatchVerificationConfig
type PoolSourceIssuanceLimits = controlv4.PoolSourceIssuanceLimits
type PoolSourceAuthorityConfig = controlv4.PoolSourceAuthorityConfig
type PoolSourceAuthority = controlv4.PoolSourceAuthority

func PoolSourceAuthorityCharge(config PoolSourceAuthorityConfig) (resourcev4.Vector, error) {
	return controlv4.PoolSourceAuthorityCharge(config)
}
func NewPoolSourceAuthority(config PoolSourceAuthorityConfig, reservation, dependencies resourcev4.Reference) (*PoolSourceAuthority, error) {
	return controlv4.NewPoolSourceAuthority(config, reservation, dependencies)
}
