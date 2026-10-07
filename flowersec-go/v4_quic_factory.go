package flowersec

import (
	"github.com/floegence/flowersec/flowersec-go/v6/internal/assemblyv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrier/quicbase"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/rawquic"
)

type QUICLimits = quicbase.Limits
type QUICProviderOptions = rawquic.OwnedOptions
type QUICFactoryConfig = assemblyv4.QUICFactoryConfig
type QUICCarrierFactory = assemblyv4.QUICCarrierFactory

func DefaultQUICLimits() QUICLimits { return quicbase.DefaultLimits() }

func QUICCarrierFactoryCharge(c QUICFactoryConfig) (ResourceVector, error) {
	return assemblyv4.QUICCarrierFactoryCharge(c)
}

// NewQUICCarrierFactory fixes one signed route and its physical role and numeric address.
// It prepares TLS and the native maintenance stream without transmitting
// Flowersec credentials. TransportEnvironment.Connect owns admission and activation.
func NewQUICCarrierFactory(c QUICFactoryConfig, reservation, environment ResourceReference) (*QUICCarrierFactory, error) {
	return assemblyv4.NewQUICCarrierFactory(c, reservation, environment)
}
