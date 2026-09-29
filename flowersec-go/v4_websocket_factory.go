package flowersec

import (
	"github.com/floegence/flowersec/flowersec-go/v6/internal/assemblyv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/websocket"
)

type V4WebSocketProviderOptions = websocket.Options
type V4WebSocketFactoryConfig = assemblyv4.WebSocketFactoryConfig
type V4WebSocketCarrierFactory = assemblyv4.WebSocketCarrierFactory
type V4WebSocketEndpoint = assemblyv4.WebSocketEndpoint
type V4WebSocketSetConfig = assemblyv4.WebSocketSetConfig
type V4WebSocketCarrierSet = assemblyv4.WebSocketCarrierSet

func V4WebSocketCarrierSetCharge(c V4WebSocketSetConfig) (V4ResourceVector, error) {
	return assemblyv4.WebSocketCarrierSetCharge(c)
}

func NewV4WebSocketCarrierSet(c V4WebSocketSetConfig, reservation, environment V4ResourceReference, accounts ...V4ResourceAccount) (*V4WebSocketCarrierSet, error) {
	return assemblyv4.NewWebSocketCarrierSet(c, reservation, environment, accounts...)
}

func V4WebSocketCarrierFactoryCharge(c V4WebSocketFactoryConfig) (V4ResourceVector, error) {
	return assemblyv4.WebSocketCarrierFactoryCharge(c)
}

func NewV4WebSocketCarrierFactory(c V4WebSocketFactoryConfig, reservation, environment V4ResourceReference) (*V4WebSocketCarrierFactory, error) {
	return assemblyv4.NewWebSocketCarrierFactory(c, reservation, environment)
}
