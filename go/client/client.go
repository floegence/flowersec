package client

import (
	"errors"
	"io"
	"sync"

	"github.com/floegence/flowersec/crypto/e2ee"
	"github.com/floegence/flowersec/rpc"
	rpchello "github.com/floegence/flowersec/rpc/hello"
	hyamux "github.com/hashicorp/yamux"
)

// Path describes which top-level connect path is used.
type Path string

const (
	PathTunnel Path = "tunnel"
	PathDirect Path = "direct"
)

// Client is a high-level session that bundles SecureChannel + yamux + RPC.
//
// It is intended as the default entrypoint for users. Advanced integrations can
// build their own stack by importing lower-level packages.
type Client struct {
	Path               Path
	EndpointInstanceID string // Only for PathTunnel; empty for PathDirect.

	Secure *e2ee.SecureChannel
	Mux    *hyamux.Session
	RPC    *rpc.Client

	rpcStream io.ReadWriteCloser

	closeOnce sync.Once
	closeErr  error
}

// Close tears down all resources in a best-effort manner.
func (c *Client) Close() error {
	if c == nil {
		return nil
	}
	c.closeOnce.Do(func() {
		var firstErr error
		if c.RPC != nil {
			c.RPC.Close()
		}
		if c.rpcStream != nil {
			if err := c.rpcStream.Close(); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		if c.Mux != nil {
			if err := c.Mux.Close(); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		if c.Secure != nil {
			if err := c.Secure.Close(); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		c.closeErr = firstErr
	})
	return c.closeErr
}

// OpenStream opens a new yamux stream and writes the StreamHello(kind) preface.
//
// Every yamux stream in this project is expected to start with a StreamHello frame.
func (c *Client) OpenStream(kind string) (io.ReadWriteCloser, error) {
	if c == nil || c.Mux == nil {
		return nil, errors.New("client is not connected")
	}
	if kind == "" {
		return nil, errors.New("missing stream kind")
	}
	s, err := c.Mux.OpenStream()
	if err != nil {
		return nil, err
	}
	if err := rpchello.WriteStreamHello(s, kind); err != nil {
		_ = s.Close()
		return nil, err
	}
	return s, nil
}
