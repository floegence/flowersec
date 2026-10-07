package flowersec

import (
	"github.com/floegence/flowersec/flowersec-go/v6/internal/assemblyv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrier/quicbase"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/webtransport"
)

type WebTransportLimits = quicbase.Limits
type WebTransportProviderOptions = webtransport.OwnedOptions
type WebTransportFactoryConfig = assemblyv4.WebTransportFactoryConfig
type WebTransportCarrierFactory = assemblyv4.WebTransportCarrierFactory

func DefaultWebTransportLimits() WebTransportLimits { return quicbase.DefaultLimits() }

func WebTransportCarrierFactoryCharge(c WebTransportFactoryConfig) (ResourceVector, error) {
	return assemblyv4.WebTransportCarrierFactoryCharge(c)
}

// NewWebTransportCarrierFactory fixes one direct signed route and numeric address.
// It prepares TLS and the native maintenance stream without transmitting
// Flowersec credentials. TransportEnvironment.Connect owns admission and activation.
func NewWebTransportCarrierFactory(c WebTransportFactoryConfig, reservation, environment ResourceReference) (*WebTransportCarrierFactory, error) {
	return assemblyv4.NewWebTransportCarrierFactory(c, reservation, environment)
}
