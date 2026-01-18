package client

import (
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
	path               Path
	endpointInstanceID string // Only for PathTunnel; empty for PathDirect.

	secure *e2ee.SecureChannel
	mux    *hyamux.Session
	rpc    *rpc.Client

	rpcStream io.ReadWriteCloser

	closeOnce sync.Once
	closeErr  error
}

func (c *Client) Path() Path {
	if c == nil {
		return ""
	}
	return c.path
}

func (c *Client) EndpointInstanceID() string {
	if c == nil {
		return ""
	}
	return c.endpointInstanceID
}

func (c *Client) Secure() *e2ee.SecureChannel {
	if c == nil {
		return nil
	}
	return c.secure
}

func (c *Client) Mux() *hyamux.Session {
	if c == nil {
		return nil
	}
	return c.mux
}

func (c *Client) RPC() *rpc.Client {
	if c == nil {
		return nil
	}
	return c.rpc
}

// Close tears down all resources in a best-effort manner.
func (c *Client) Close() error {
	if c == nil {
		return nil
	}
	c.closeOnce.Do(func() {
		var firstErr error
		if c.rpc != nil {
			c.rpc.Close()
		}
		if c.rpcStream != nil {
			if err := c.rpcStream.Close(); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		if c.mux != nil {
			if err := c.mux.Close(); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		if c.secure != nil {
			if err := c.secure.Close(); err != nil && firstErr == nil {
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
	if c == nil || c.mux == nil {
		var path Path
		if c != nil {
			path = c.path
		}
		return nil, wrapErr(path, StageYamux, CodeNotConnected, ErrNotConnected)
	}
	if kind == "" {
		return nil, wrapErr(c.path, StageValidate, CodeMissingStreamKind, ErrMissingStreamKind)
	}
	s, err := c.mux.OpenStream()
	if err != nil {
		return nil, wrapErr(c.path, StageYamux, CodeOpenStreamFailed, err)
	}
	if err := rpchello.WriteStreamHello(s, kind); err != nil {
		_ = s.Close()
		return nil, wrapErr(c.path, StageRPC, CodeStreamHelloFailed, err)
	}
	return s, nil
}
