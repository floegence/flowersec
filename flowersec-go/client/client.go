package client

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/crypto/e2ee"
	"github.com/floegence/flowersec/flowersec-go/v2/fserrors"
	fsyamux "github.com/floegence/flowersec/flowersec-go/v2/mux/yamux"
	"github.com/floegence/flowersec/flowersec-go/v2/observability"
	"github.com/floegence/flowersec/flowersec-go/v2/rpc"
	fsstream "github.com/floegence/flowersec/flowersec-go/v2/stream"
	"github.com/floegence/flowersec/flowersec-go/v2/streamhello"
)

// Client is a high-level session intended as the default user entrypoint.
//
// It intentionally does not expose the underlying SecureChannel or yamux.Session.
// Advanced integrations can opt into ClientInternal via a type assertion.
type Client interface {
	Path() Path
	EndpointInstanceID() string
	RPC() *rpc.Client
	OpenStream(ctx context.Context, kind string) (fsstream.Stream, error)
	Ping() error
	Rekey() error
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

// Rekey emits an authenticated E2EE rekey record and advances the send key.
func (c *session) Rekey() error {
	if c == nil || c.secure == nil {
		var path Path
		if c != nil {
			path = c.path
		}
		return wrapErr(path, fserrors.StageSecure, fserrors.CodeNotConnected, ErrNotConnected)
	}
	if err := c.secure.Rekey(); err != nil {
		return wrapErr(c.path, fserrors.StageSecure, fserrors.CodeRekeyFailed, err)
	}
	return nil
}

// Close tears down all resources and returns every cleanup failure.
func (c *session) Close() error {
	if c == nil {
		return nil
	}
	c.closeOnce.Do(func() {
		var closeErr error
		if c.rpc != nil {
			closeErr = errors.Join(closeErr, c.rpc.Close())
		}
		if c.mux != nil {
			closeErr = errors.Join(closeErr, c.mux.Close())
		}
		if c.secure != nil {
			closeErr = errors.Join(closeErr, c.secure.Close())
		}
		if closeErr != nil {
			closeErr = wrapErr(c.path, fserrors.StageClose, fserrors.CodeNotConnected, closeErr)
		}
		c.closeErr = closeErr
	})
	return c.closeErr
}

// OpenStream opens a new yamux stream and writes the StreamHello(kind) preface.
//
// Every yamux stream in this project is expected to start with a StreamHello frame.
func (c *session) OpenStream(ctx context.Context, kind string) (fsstream.Stream, error) {
	kind = strings.TrimSpace(kind)
	if kind == "" {
		var path Path
		if c != nil {
			path = c.path
		}
		return nil, wrapErr(path, fserrors.StageRPC, fserrors.CodeMissingStreamKind, ErrMissingStreamKind)
	}
	if c == nil || c.mux == nil {
		var path Path
		if c != nil {
			path = c.path
		}
		return nil, wrapErr(path, fserrors.StageYamux, fserrors.CodeNotConnected, ErrNotConnected)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, wrapErr(c.path, fserrors.StageYamux, classifyContextCode(err), err)
	}

	s, err := c.mux.OpenStreamContext(ctx)
	if err != nil {
		if isResourceExhausted(err) {
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
		if isResourceExhausted(writeErr) {
			return nil, wrapErr(c.path, fserrors.StageRPC, fserrors.CodeResourceExhausted, writeErr)
		}
		return nil, wrapErr(c.path, fserrors.StageRPC, fserrors.CodeStreamHelloFailed, writeErr)
	}
	if err := ctx.Err(); err != nil {
		_ = s.Close()
		return nil, wrapErr(c.path, fserrors.StageYamux, classifyContextCode(err), err)
	}
	return s, nil
}

func isResourceExhausted(err error) bool {
	return errors.Is(err, fsyamux.ErrResourceExhausted) ||
		errors.Is(err, e2ee.ErrOutboundBufferExceeded)
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
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, fsyamux.ErrLivenessTimeout) {
		return fserrors.CodeTimeout
	}
	if errors.Is(err, context.Canceled) {
		return fserrors.CodeCanceled
	}
	return fallback
}
