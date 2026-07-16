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
	fsyamux "github.com/floegence/flowersec/flowersec-go/mux/yamux"
	fsstream "github.com/floegence/flowersec/flowersec-go/stream"
	"github.com/floegence/flowersec/flowersec-go/streamhello"
)

const DefaultMaxStreamHelloBytes = 8 * 1024

// Session is a multiplexed endpoint session intended as the default user entrypoint.
//
// It intentionally does not expose the underlying SecureChannel or yamux.Session.
// Advanced integrations can opt into SessionInternal via a type assertion.
type Session interface {
	Path() Path
	EndpointInstanceID() string
	AcceptStreamHello(maxHelloBytes int) (string, fsstream.Stream, error)
	ServeStreams(ctx context.Context, maxHelloBytes int, handler func(kind string, stream io.ReadWriteCloser), opts ...ServeStreamsOption) error
	OpenStream(ctx context.Context, kind string) (fsstream.Stream, error)
	Ping() error
	Rekey() error
	ProbeLiveness(ctx context.Context) (time.Duration, error)
	Close() error
}

// SessionInternal exposes the underlying stack for advanced integrations.
//
// The returned types may change in future versions.
type SessionInternal interface {
	Session
	Secure() *e2ee.SecureChannel
	Mux() *fsyamux.Session
}

type session struct {
	path               Path
	endpointInstanceID string

	secure *e2ee.SecureChannel
	mux    *fsyamux.Session

	closeOnce sync.Once
	closeErr  error
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

func (s *session) Mux() *fsyamux.Session {
	if s == nil {
		return nil
	}
	return s.mux
}

func (s *session) ProbeLiveness(ctx context.Context) (time.Duration, error) {
	if s == nil || s.mux == nil {
		var path Path
		if s != nil {
			path = s.path
		}
		return 0, wrapErr(path, fserrors.StageYamux, fserrors.CodeNotConnected, ErrNotConnected)
	}
	rtt, err := s.mux.Probe(ctx)
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			_ = s.Close()
		}
		return 0, wrapErr(s.path, fserrors.StageYamux, classifyContextOrCode(err, fserrors.CodePingFailed), err)
	}
	return rtt, nil
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

// Rekey emits an authenticated E2EE rekey record and advances the send key.
func (s *session) Rekey() error {
	if s == nil || s.secure == nil {
		var path Path
		if s != nil {
			path = s.path
		}
		return wrapErr(path, fserrors.StageSecure, fserrors.CodeNotConnected, ErrNotConnected)
	}
	if err := s.secure.Rekey(); err != nil {
		return wrapErr(s.path, fserrors.StageSecure, fserrors.CodeRekeyFailed, err)
	}
	return nil
}

func (s *session) Close() error {
	if s == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		var closeErr error
		if s.mux != nil {
			closeErr = errors.Join(closeErr, s.mux.Close())
		}
		if s.secure != nil {
			closeErr = errors.Join(closeErr, s.secure.Close())
		}
		if closeErr != nil {
			closeErr = wrapErr(s.path, fserrors.StageClose, fserrors.CodeNotConnected, closeErr)
		}
		s.closeErr = closeErr
	})
	return s.closeErr
}

// AcceptStreamHello accepts the next inbound stream and reads its StreamHello(kind) prefix.
func (s *session) AcceptStreamHello(maxHelloBytes int) (string, fsstream.Stream, error) {
	if s == nil || s.mux == nil {
		var path Path
		if s != nil {
			path = s.path
		}
		return "", nil, wrapErr(path, fserrors.StageYamux, fserrors.CodeNotConnected, ErrNotConnected)
	}
	if maxHelloBytes < 0 {
		return "", nil, wrapErr(s.path, fserrors.StageValidate, fserrors.CodeInvalidOption, ErrInvalidMaxStreamHelloBytes)
	}
	if maxHelloBytes == 0 {
		maxHelloBytes = DefaultMaxStreamHelloBytes
	}
	stream, err := s.mux.AcceptStream()
	if err != nil {
		if errors.Is(err, fsyamux.ErrResourceExhausted) {
			return "", nil, wrapErr(s.path, fserrors.StageYamux, fserrors.CodeResourceExhausted, err)
		}
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
	if maxHelloBytes < 0 {
		return wrapErr(s.path, fserrors.StageValidate, fserrors.CodeInvalidOption, ErrInvalidMaxStreamHelloBytes)
	}
	if maxHelloBytes == 0 {
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
			if errors.Is(err, fsyamux.ErrResourceExhausted) {
				return wrapErr(s.path, fserrors.StageYamux, fserrors.CodeResourceExhausted, err)
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
func (s *session) OpenStream(ctx context.Context, kind string) (fsstream.Stream, error) {
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

	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, wrapErr(s.path, fserrors.StageYamux, classifyContextCode(err), err)
	}

	st, err := s.mux.OpenStreamContext(ctx)
	if err != nil {
		if errors.Is(err, fsyamux.ErrResourceExhausted) {
			return nil, wrapErr(s.path, fserrors.StageYamux, fserrors.CodeResourceExhausted, err)
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, wrapErr(s.path, fserrors.StageYamux, classifyContextCode(err), err)
		}
		return nil, wrapErr(s.path, fserrors.StageYamux, fserrors.CodeOpenStreamFailed, err)
	}

	// Continue honoring ctx during the StreamHello write after the stream is open.
	if d, ok := ctx.Deadline(); ok {
		if ds, ok := any(st).(interface{ SetWriteDeadline(time.Time) error }); ok {
			_ = ds.SetWriteDeadline(d)
			defer func() { _ = ds.SetWriteDeadline(time.Time{}) }()
		}
	}
	stop := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			select {
			case <-stop:
				return
			default:
			}
			_ = st.Close()
		case <-stop:
		}
	}()
	writeErr := streamhello.WriteStreamHello(st, kind)
	close(stop)
	if writeErr != nil {
		_ = st.Close()
		if err := ctx.Err(); err != nil {
			return nil, wrapErr(s.path, fserrors.StageYamux, classifyContextCode(err), err)
		}
		return nil, wrapErr(s.path, fserrors.StageRPC, fserrors.CodeStreamHelloFailed, writeErr)
	}
	if err := ctx.Err(); err != nil {
		_ = st.Close()
		return nil, wrapErr(s.path, fserrors.StageYamux, classifyContextCode(err), err)
	}
	return st, nil
}

func classifyContextCode(err error) fserrors.Code {
	if errors.Is(err, context.DeadlineExceeded) {
		return fserrors.CodeTimeout
	}
	if errors.Is(err, context.Canceled) {
		return fserrors.CodeCanceled
	}
	return fserrors.CodeCanceled
}

func classifyContextOrCode(err error, fallback fserrors.Code) fserrors.Code {
	if errors.Is(err, context.DeadlineExceeded) {
		return fserrors.CodeTimeout
	}
	if errors.Is(err, context.Canceled) {
		return fserrors.CodeCanceled
	}
	return fallback
}
