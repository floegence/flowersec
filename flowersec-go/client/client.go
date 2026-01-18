package client

import (
	"io"
	"sync"

	"github.com/floegence/flowersec/flowersec-go/crypto/e2ee"
	"github.com/floegence/flowersec/flowersec-go/fserrors"
	"github.com/floegence/flowersec/flowersec-go/rpc"
	"github.com/floegence/flowersec/flowersec-go/streamhello"
	hyamux "github.com/hashicorp/yamux"
)

// Client is a high-level session intended as the default user entrypoint.
//
// It intentionally does not expose the underlying SecureChannel or yamux.Session.
// Advanced integrations can opt into ClientInternal via a type assertion.
type Client interface {
	Path() Path
	EndpointInstanceID() string
	RPC() *rpc.Client
	OpenStream(kind string) (io.ReadWriteCloser, error)
	Close() error
}

// ClientInternal exposes the underlying stack for advanced integrations.
//
// The returned types may change in future versions.
type ClientInternal interface {
	Client
	Secure() *e2ee.SecureChannel
	Mux() *hyamux.Session
}

type session struct {
	path               Path
	endpointInstanceID string // Only for PathTunnel; empty for PathDirect.

	secure *e2ee.SecureChannel
	mux    *hyamux.Session
	rpc    *rpc.Client

	closeOnce sync.Once
	closeErr  error
}

func (c *session) Path() Path {
	if c == nil {
		return ""
	}
	return c.path
}

func (c *session) EndpointInstanceID() string {
	if c == nil {
		return ""
	}
	return c.endpointInstanceID
}

func (c *session) Secure() *e2ee.SecureChannel {
	if c == nil {
		return nil
	}
	return c.secure
}

func (c *session) Mux() *hyamux.Session {
	if c == nil {
		return nil
	}
	return c.mux
}

func (c *session) RPC() *rpc.Client {
	if c == nil {
		return nil
	}
	return c.rpc
}

// Close tears down all resources in a best-effort manner.
func (c *session) Close() error {
	if c == nil {
		return nil
	}
	c.closeOnce.Do(func() {
		var firstErr error
		if c.rpc != nil {
			if err := c.rpc.Close(); err != nil && firstErr == nil {
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
func (c *session) OpenStream(kind string) (io.ReadWriteCloser, error) {
	if c == nil || c.mux == nil {
		var path Path
		if c != nil {
			path = c.path
		}
		return nil, wrapErr(path, fserrors.StageYamux, fserrors.CodeNotConnected, ErrNotConnected)
	}
	if kind == "" {
		return nil, wrapErr(c.path, fserrors.StageValidate, fserrors.CodeMissingStreamKind, ErrMissingStreamKind)
	}
	s, err := c.mux.OpenStream()
	if err != nil {
		return nil, wrapErr(c.path, fserrors.StageYamux, fserrors.CodeOpenStreamFailed, err)
	}
	if err := streamhello.WriteStreamHello(s, kind); err != nil {
		_ = s.Close()
		return nil, wrapErr(c.path, fserrors.StageRPC, fserrors.CodeStreamHelloFailed, err)
	}
	return s, nil
}
