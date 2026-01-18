package defaults

import "time"

const (
	// ConnectTimeout is the default timeout for establishing a WebSocket connection.
	ConnectTimeout = 10 * time.Second
	// HandshakeTimeout is the default timeout for completing the E2EE handshake.
	HandshakeTimeout = 10 * time.Second
)
