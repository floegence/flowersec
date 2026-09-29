package flowersec

import (
	"github.com/floegence/flowersec/flowersec-go/v6/internal/assemblyv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrier/quicbase"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/webtransport"
)

type V4WebTransportLimits = quicbase.Limits
type V4WebTransportProviderOptions = webtransport.OwnedOptions
type V4WebTransportFactoryConfig = assemblyv4.WebTransportFactoryConfig
type V4WebTransportCarrierFactory = assemblyv4.WebTransportCarrierFactory

func DefaultV4WebTransportLimits() V4WebTransportLimits { return quicbase.DefaultLimits() }

func V4WebTransportCarrierFactoryCharge(c V4WebTransportFactoryConfig) (V4ResourceVector, error) {
	return assemblyv4.WebTransportCarrierFactoryCharge(c)
}

// NewV4WebTransportCarrierFactory fixes one direct signed route and numeric address.
// It prepares TLS and the native maintenance stream without transmitting
// Flowersec credentials. Environment.Connect owns admission and activation.
func NewV4WebTransportCarrierFactory(c V4WebTransportFactoryConfig, reservation, environment V4ResourceReference) (*V4WebTransportCarrierFactory, error) {
	return assemblyv4.NewWebTransportCarrierFactory(c, reservation, environment)
}
