package client

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/floegence/flowersec/flowersec-go/crypto/e2ee"
	"github.com/floegence/flowersec/flowersec-go/fserrors"
	fsyamux "github.com/floegence/flowersec/flowersec-go/mux/yamux"
	"github.com/floegence/flowersec/flowersec-go/observability"
	"github.com/floegence/flowersec/flowersec-go/rpc"
	"github.com/floegence/flowersec/flowersec-go/streamhello"
)

// Client is a high-level session intended as the default user entrypoint.
//
// It intentionally does not expose the underlying SecureChannel or yamux.Session.
// Advanced integrations can opt into ClientInternal via a type assertion.
type Client interface {
	Path() Path
	EndpointInstanceID() string
	RPC() *rpc.Client
	OpenStream(ctx context.Context, kind string) (io.ReadWriteCloser, error)
	Ping() error
	ProbeLiveness(ctx context.Context) (time.Duration, error)
	Close() error
}

// ClientInternal exposes the underlying stack for advanced integrations.
//
// The returned types may change in future versions.
type ClientInternal interface {
	Client
	Secure() *e2ee.SecureChannel
	Mux() *fsyamux.Session
}

type session struct {
	path               Path
	endpointInstanceID string // Only for PathTunnel; empty for PathDirect.

	secure   *e2ee.SecureChannel
	mux      *fsyamux.Session
	rpc      *rpc.Client
	observer observability.ClientObserver

	closeOnce sync.Once
	closeErr  error
}

func (c *session) watchLiveness() {
	if c == nil || c.mux == nil {
		return
	}
	err, ok := <-c.mux.LivenessFailures()
	if !ok || err == nil {
		return
	}
	if c.observer != nil {
		c.observer.OnDiagnosticEvent(observability.DiagnosticEvent{
			Path:       string(c.path),
			Stage:      observability.DiagnosticStageYamux,
			CodeDomain: observability.DiagnosticCodeDomainEvent,
			Code:       "liveness_timeout",
			Result:     observability.DiagnosticResultFail,
		})
	}
	_ = c.Close()
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

func (c *session) Mux() *fsyamux.Session {
	if c == nil {
		return nil
	}
	return c.mux
}

func (c *session) ProbeLiveness(ctx context.Context) (time.Duration, error) {
	if c == nil || c.mux == nil {
		var path Path
		if c != nil {
			path = c.path
		}
		return 0, wrapErr(path, fserrors.StageYamux, fserrors.CodeNotConnected, ErrNotConnected)
	}
	rtt, err := c.mux.Probe(ctx)
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			if c.observer != nil && (errors.Is(err, context.DeadlineExceeded) || errors.Is(err, fsyamux.ErrLivenessTimeout)) {
				c.observer.OnDiagnosticEvent(observability.DiagnosticEvent{
					Path:       string(c.path),
					Stage:      observability.DiagnosticStageYamux,
					CodeDomain: observability.DiagnosticCodeDomainEvent,
					Code:       "liveness_timeout",
					Result:     observability.DiagnosticResultFail,
				})
			}
			_ = c.Close()
		}
		return 0, wrapErr(c.path, fserrors.StageYamux, classifyContextOrCode(err, fserrors.CodePingFailed), err)
	}
	return rtt, nil
}

func (c *session) RPC() *rpc.Client {
	if c == nil {
		return nil
	}
	return c.rpc
}

func (c *session) Ping() error {
	if c == nil || c.secure == nil {
		var path Path
		if c != nil {
			path = c.path
		}
		return wrapErr(path, fserrors.StageSecure, fserrors.CodeNotConnected, ErrNotConnected)
	}
	if err := c.secure.Ping(); err != nil {
		return wrapErr(c.path, fserrors.StageSecure, fserrors.CodePingFailed, err)
	}
	return nil
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
func (c *session) OpenStream(ctx context.Context, kind string) (io.ReadWriteCloser, error) {
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

	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, wrapErr(c.path, fserrors.StageYamux, classifyContextCode(err), err)
	}

	s, err := c.mux.OpenStreamContext(ctx)
	if err != nil {
		if errors.Is(err, fsyamux.ErrResourceExhausted) {
			return nil, wrapErr(c.path, fserrors.StageYamux, fserrors.CodeResourceExhausted, err)
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, wrapErr(c.path, fserrors.StageYamux, classifyContextCode(err), err)
		}
		return nil, wrapErr(c.path, fserrors.StageYamux, fserrors.CodeOpenStreamFailed, err)
	}

	// Continue honoring ctx during the StreamHello write after the stream is open.
	if d, ok := ctx.Deadline(); ok {
		if ds, ok := any(s).(interface{ SetWriteDeadline(time.Time) error }); ok {
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
			_ = s.Close()
		case <-stop:
		}
	}()
	writeErr := streamhello.WriteStreamHello(s, kind)
	close(stop)
	if writeErr != nil {
		_ = s.Close()
		if err := ctx.Err(); err != nil {
			return nil, wrapErr(c.path, fserrors.StageYamux, classifyContextCode(err), err)
		}
		return nil, wrapErr(c.path, fserrors.StageRPC, fserrors.CodeStreamHelloFailed, writeErr)
	}
	if err := ctx.Err(); err != nil {
		_ = s.Close()
		return nil, wrapErr(c.path, fserrors.StageYamux, classifyContextCode(err), err)
	}
	return s, nil
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
