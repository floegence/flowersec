package flowersec

import "github.com/floegence/flowersec/flowersec-go/v6/internal/assemblyv4"

type WebSocketServerConfig = assemblyv4.WebSocketServerConfig
type WebSocketServer = assemblyv4.WebSocketServer

func WebSocketServerCharge(c WebSocketServerConfig) (ResourceVector, error) {
	return assemblyv4.WebSocketServerCharge(c)
}

// NewWebSocketServer fixes native TLS, certificate, complete Route and finite
// HTTP connection/header admission. Set WebSocketAcceptOptions.Server to this
// owner for ServeHandle.AcceptWebSocket. The server owns its accepted sockets;
// the shared TransportEnvironment, key provider and trust roots remain independently owned.
func NewWebSocketServer(c WebSocketServerConfig, reservation, dependencies ResourceReference) (*WebSocketServer, error) {
	return assemblyv4.NewWebSocketServer(c, reservation, dependencies)
}
