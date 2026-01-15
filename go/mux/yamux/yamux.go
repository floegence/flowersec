package yamux

import (
	"net"

	"github.com/hashicorp/yamux"
)

func NewClient(conn net.Conn, cfg *yamux.Config) (*yamux.Session, error) {
	if cfg == nil {
		cfg = yamux.DefaultConfig()
	}
	return yamux.Client(conn, cfg)
}

func NewServer(conn net.Conn, cfg *yamux.Config) (*yamux.Session, error) {
	if cfg == nil {
		cfg = yamux.DefaultConfig()
	}
	return yamux.Server(conn, cfg)
}
