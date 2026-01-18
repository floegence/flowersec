package endpoint

import (
	"context"
	"io"
	"sync"

	"github.com/floegence/flowersec/crypto/e2ee"
	rpchello "github.com/floegence/flowersec/rpc/hello"
	hyamux "github.com/hashicorp/yamux"
)

type Path string

const (
	PathTunnel Path = "tunnel"
	PathDirect Path = "direct"
)

const DefaultMaxStreamHelloBytes = 8 * 1024

type Session struct {
	path               Path
	endpointInstanceID string

	secure *e2ee.SecureChannel
	mux    *hyamux.Session

	closeOnce sync.Once
	closeErr  error
}

func (s *Session) Path() Path {
	if s == nil {
		return ""
	}
	return s.path
}

func (s *Session) EndpointInstanceID() string {
	if s == nil {
		return ""
	}
	return s.endpointInstanceID
}

func (s *Session) Secure() *e2ee.SecureChannel {
	if s == nil {
		return nil
	}
	return s.secure
}

func (s *Session) Mux() *hyamux.Session {
	if s == nil {
		return nil
	}
	return s.mux
}

func (s *Session) Close() error {
	if s == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		var firstErr error
		if s.mux != nil {
			if err := s.mux.Close(); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		if s.secure != nil {
			if err := s.secure.Close(); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		s.closeErr = firstErr
	})
	return s.closeErr
}

// AcceptStreamHello accepts the next inbound stream and reads its StreamHello(kind) prefix.
func (s *Session) AcceptStreamHello(maxHelloBytes int) (string, io.ReadWriteCloser, error) {
	if s == nil || s.mux == nil {
		var path Path
		if s != nil {
			path = s.path
		}
		return "", nil, wrapErr(path, StageYamux, CodeNotConnected, ErrNotConnected)
	}
	if maxHelloBytes <= 0 {
		maxHelloBytes = DefaultMaxStreamHelloBytes
	}
	stream, err := s.mux.AcceptStream()
	if err != nil {
		return "", nil, wrapErr(s.path, StageYamux, CodeAcceptStreamFailed, err)
	}
	h, err := rpchello.ReadStreamHello(stream, maxHelloBytes)
	if err != nil {
		_ = stream.Close()
		return "", nil, wrapErr(s.path, StageRPC, CodeStreamHelloFailed, err)
	}
	return h.Kind, stream, nil
}

// ServeStreams runs an accept loop and dispatches each stream to handler(kind, stream).
//
// handler is invoked in its own goroutine for each accepted stream.
func (s *Session) ServeStreams(ctx context.Context, maxHelloBytes int, handler func(kind string, stream io.ReadWriteCloser)) error {
	if s == nil || s.mux == nil {
		var path Path
		if s != nil {
			path = s.path
		}
		return wrapErr(path, StageYamux, CodeNotConnected, ErrNotConnected)
	}
	if handler == nil {
		return wrapErr(s.path, StageValidate, CodeMissingHandler, ErrMissingHandler)
	}
	if maxHelloBytes <= 0 {
		maxHelloBytes = DefaultMaxStreamHelloBytes
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = s.Close()
		case <-done:
		}
	}()
	defer close(done)

	for {
		stream, err := s.mux.AcceptStream()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return wrapErr(s.path, StageYamux, CodeAcceptStreamFailed, err)
		}
		h, err := rpchello.ReadStreamHello(stream, maxHelloBytes)
		if err != nil {
			_ = stream.Close()
			continue
		}
		kind := h.Kind
		go handler(kind, stream)
	}
}
