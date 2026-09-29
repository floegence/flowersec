package flowersec

import "github.com/floegence/flowersec/flowersec-go/v6/internal/assemblyv4"

type V4WebSocketServerConfig = assemblyv4.WebSocketServerConfig
type V4WebSocketServer = assemblyv4.WebSocketServer

func V4WebSocketServerCharge(c V4WebSocketServerConfig) (V4ResourceVector, error) {
	return assemblyv4.WebSocketServerCharge(c)
}

// NewV4WebSocketServer fixes native TLS, certificate, complete Route and finite
// HTTP connection/header admission. Set V4WebSocketAcceptOptions.Server to this
// owner for ServeHandle.AcceptWebSocket. The server owns its accepted sockets;
// the shared Environment, key provider and trust roots remain independently owned.
func NewV4WebSocketServer(c V4WebSocketServerConfig, reservation, dependencies V4ResourceReference) (*V4WebSocketServer, error) {
	return assemblyv4.NewWebSocketServer(c, reservation, dependencies)
}
