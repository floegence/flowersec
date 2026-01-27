package endpoint

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/floegence/flowersec/flowersec-go/crypto/e2ee"
	"github.com/floegence/flowersec/flowersec-go/fserrors"
	"github.com/floegence/flowersec/flowersec-go/streamhello"
	hyamux "github.com/hashicorp/yamux"
)

const DefaultMaxStreamHelloBytes = 8 * 1024

// Session is a multiplexed endpoint session intended as the default user entrypoint.
//
// It intentionally does not expose the underlying SecureChannel or yamux.Session.
// Advanced integrations can opt into SessionInternal via a type assertion.
type Session interface {
	Path() Path
	EndpointInstanceID() string
	AcceptStreamHello(maxHelloBytes int) (string, io.ReadWriteCloser, error)
	ServeStreams(ctx context.Context, maxHelloBytes int, handler func(kind string, stream io.ReadWriteCloser), opts ...ServeStreamsOption) error
	OpenStream(kind string) (io.ReadWriteCloser, error)
	Ping() error
	Close() error
}

// SessionInternal exposes the underlying stack for advanced integrations.
//
// The returned types may change in future versions.
type SessionInternal interface {
	Session
	Secure() *e2ee.SecureChannel
	Mux() *hyamux.Session
}

type session struct {
	path               Path
	endpointInstanceID string

	secure *e2ee.SecureChannel
	mux    *hyamux.Session

	closeOnce sync.Once
	closeErr  error

	keepaliveStop chan struct{}
}

func (s *session) Path() Path {
	if s == nil {
		return ""
	}
	return s.path
}

func (s *session) EndpointInstanceID() string {
	if s == nil {
		return ""
	}
	return s.endpointInstanceID
}

func (s *session) Secure() *e2ee.SecureChannel {
	if s == nil {
		return nil
	}
	return s.secure
}

func (s *session) Mux() *hyamux.Session {
	if s == nil {
		return nil
	}
	return s.mux
}

func (s *session) Ping() error {
	if s == nil || s.secure == nil {
		var path Path
		if s != nil {
			path = s.path
		}
		return wrapErr(path, fserrors.StageSecure, fserrors.CodeNotConnected, ErrNotConnected)
	}
	if err := s.secure.Ping(); err != nil {
		return wrapErr(s.path, fserrors.StageSecure, fserrors.CodePingFailed, err)
	}
	return nil
}

func (s *session) Close() error {
	if s == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		var firstErr error
		if s.keepaliveStop != nil {
			close(s.keepaliveStop)
		}
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
func (s *session) AcceptStreamHello(maxHelloBytes int) (string, io.ReadWriteCloser, error) {
	if s == nil || s.mux == nil {
		var path Path
		if s != nil {
			path = s.path
		}
		return "", nil, wrapErr(path, fserrors.StageYamux, fserrors.CodeNotConnected, ErrNotConnected)
	}
	if maxHelloBytes <= 0 {
		maxHelloBytes = DefaultMaxStreamHelloBytes
	}
	stream, err := s.mux.AcceptStream()
	if err != nil {
		return "", nil, wrapErr(s.path, fserrors.StageYamux, fserrors.CodeAcceptStreamFailed, err)
	}
	h, err := streamhello.ReadStreamHello(stream, maxHelloBytes)
	if err != nil {
		_ = stream.Close()
		return "", nil, wrapErr(s.path, fserrors.StageRPC, fserrors.CodeStreamHelloFailed, err)
	}
	return h.Kind, stream, nil
}

// ServeStreams runs an accept loop and dispatches each stream to handler(kind, stream).
//
// handler is invoked in its own goroutine for each accepted stream.
//
// The stream is closed after handler returns.
func (s *session) ServeStreams(ctx context.Context, maxHelloBytes int, handler func(kind string, stream io.ReadWriteCloser), opts ...ServeStreamsOption) error {
	if s == nil || s.mux == nil {
		var path Path
		if s != nil {
			path = s.path
		}
		return wrapErr(path, fserrors.StageYamux, fserrors.CodeNotConnected, ErrNotConnected)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if handler == nil {
		return wrapErr(s.path, fserrors.StageValidate, fserrors.CodeMissingHandler, ErrMissingHandler)
	}
	if maxHelloBytes <= 0 {
		maxHelloBytes = DefaultMaxStreamHelloBytes
	}

	cfg, err := applyServeStreamsOptions(opts)
	if err != nil {
		return wrapErr(s.path, fserrors.StageValidate, fserrors.CodeInvalidOption, err)
	}

	if err := ctx.Err(); err != nil {
		return wrapCtxErr(s.path, err)
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
				return wrapCtxErr(s.path, ctx.Err())
			}
			return wrapErr(s.path, fserrors.StageYamux, fserrors.CodeAcceptStreamFailed, err)
		}
		h, err := streamhello.ReadStreamHello(stream, maxHelloBytes)
		if err != nil {
			_ = stream.Close()
			reportServeStreamsError(cfg.onError, wrapErr(s.path, fserrors.StageRPC, fserrors.CodeStreamHelloFailed, err))
			continue
		}
		kind := h.Kind
		go func(kind string, stream io.ReadWriteCloser) {
			defer stream.Close()
			defer func() {
				if r := recover(); r != nil {
					reportServeStreamsError(cfg.onError, fmt.Errorf("stream handler panic (kind=%q): %v", kind, r))
				}
			}()
			handler(kind, stream)
		}(kind, stream)
	}
}

func wrapCtxErr(path Path, err error) error {
	if err == nil {
		return nil
	}
	code := fserrors.CodeCanceled
	if errors.Is(err, context.DeadlineExceeded) {
		code = fserrors.CodeTimeout
	}
	if errors.Is(err, context.Canceled) {
		code = fserrors.CodeCanceled
	}
	return wrapErr(path, fserrors.StageClose, code, err)
}

// OpenStream opens a new yamux stream and writes the StreamHello(kind) preface.
//
// Every yamux stream in this project is expected to start with a StreamHello frame.
func (s *session) OpenStream(kind string) (io.ReadWriteCloser, error) {
	if s == nil || s.mux == nil {
		var path Path
		if s != nil {
			path = s.path
		}
		return nil, wrapErr(path, fserrors.StageYamux, fserrors.CodeNotConnected, ErrNotConnected)
	}
	if kind == "" {
		return nil, wrapErr(s.path, fserrors.StageValidate, fserrors.CodeMissingStreamKind, ErrMissingStreamKind)
	}
	st, err := s.mux.OpenStream()
	if err != nil {
		return nil, wrapErr(s.path, fserrors.StageYamux, fserrors.CodeOpenStreamFailed, err)
	}
	if err := streamhello.WriteStreamHello(st, kind); err != nil {
		_ = st.Close()
		return nil, wrapErr(s.path, fserrors.StageRPC, fserrors.CodeStreamHelloFailed, err)
	}
	return st, nil
}

func (s *session) startKeepalive(interval time.Duration) {
	if s == nil || s.secure == nil || interval <= 0 {
		return
	}
	if s.keepaliveStop != nil {
		return
	}
	stop := make(chan struct{})
	s.keepaliveStop = stop
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				if err := s.Ping(); err != nil {
					_ = s.Close()
					return
				}
			case <-stop:
				return
			}
		}
	}()
}
