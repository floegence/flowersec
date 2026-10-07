package flowersec

import (
	"github.com/floegence/flowersec/flowersec-go/v6/internal/assemblyv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/websocket"
)

type WebSocketProviderOptions = websocket.Options
type WebSocketFactoryConfig = assemblyv4.WebSocketFactoryConfig
type WebSocketCarrierFactory = assemblyv4.WebSocketCarrierFactory
type WebSocketEndpoint = assemblyv4.WebSocketEndpoint
type WebSocketSetConfig = assemblyv4.WebSocketSetConfig
type WebSocketCarrierSet = assemblyv4.WebSocketCarrierSet

func WebSocketCarrierSetCharge(c WebSocketSetConfig) (ResourceVector, error) {
	return assemblyv4.WebSocketCarrierSetCharge(c)
}

func NewWebSocketCarrierSet(c WebSocketSetConfig, reservation, environment ResourceReference, accounts ...ResourceAccount) (*WebSocketCarrierSet, error) {
	return assemblyv4.NewWebSocketCarrierSet(c, reservation, environment, accounts...)
}

func WebSocketCarrierFactoryCharge(c WebSocketFactoryConfig) (ResourceVector, error) {
	return assemblyv4.WebSocketCarrierFactoryCharge(c)
}

func NewWebSocketCarrierFactory(c WebSocketFactoryConfig, reservation, environment ResourceReference) (*WebSocketCarrierFactory, error) {
	return assemblyv4.NewWebSocketCarrierFactory(c, reservation, environment)
}
