package yamux

import (
	"net"

	"github.com/hashicorp/yamux"
)

// NewClient creates a yamux client session with defaults if cfg is nil.
func NewClient(conn net.Conn, cfg *yamux.Config) (*yamux.Session, error) {
	if cfg == nil {
		cfg = yamux.DefaultConfig()
	}
	return yamux.Client(conn, cfg)
}

// NewServer creates a yamux server session with defaults if cfg is nil.
func NewServer(conn net.Conn, cfg *yamux.Config) (*yamux.Session, error) {
	if cfg == nil {
		cfg = yamux.DefaultConfig()
	}
	return yamux.Server(conn, cfg)
}
