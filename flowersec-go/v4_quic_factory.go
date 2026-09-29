package flowersec

import (
	"github.com/floegence/flowersec/flowersec-go/v6/internal/assemblyv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrier/quicbase"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/rawquic"
)

type V4QUICLimits = quicbase.Limits
type V4QUICProviderOptions = rawquic.OwnedOptions
type V4QUICFactoryConfig = assemblyv4.QUICFactoryConfig
type V4QUICCarrierFactory = assemblyv4.QUICCarrierFactory

func DefaultV4QUICLimits() V4QUICLimits { return quicbase.DefaultLimits() }

func V4QUICCarrierFactoryCharge(c V4QUICFactoryConfig) (V4ResourceVector, error) {
	return assemblyv4.QUICCarrierFactoryCharge(c)
}

// NewV4QUICCarrierFactory fixes one signed route and its physical role and numeric address.
// It prepares TLS and the native maintenance stream without transmitting
// Flowersec credentials. Environment.Connect owns admission and activation.
func NewV4QUICCarrierFactory(c V4QUICFactoryConfig, reservation, environment V4ResourceReference) (*V4QUICCarrierFactory, error) {
	return assemblyv4.NewQUICCarrierFactory(c, reservation, environment)
}
