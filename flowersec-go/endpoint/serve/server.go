package serve

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/floegence/flowersec/flowersec-go/endpoint"
	"github.com/floegence/flowersec/flowersec-go/fserrors"
	"github.com/floegence/flowersec/flowersec-go/observability"
	"github.com/floegence/flowersec/flowersec-go/rpc"
)

// StreamHandler handles a single accepted stream.
//
// The provided stream is closed after the handler returns.
type StreamHandler func(ctx context.Context, stream io.ReadWriteCloser)

// RPCOptions configures the built-in "rpc" stream handler.
type RPCOptions struct {
	// Kind is the StreamHello kind that identifies the RPC stream.
	// If empty, "rpc" is used.
	Kind string
	// Register is called for each RPC stream to register typeID handlers.
	// If nil, no built-in RPC stream handler is enabled.
	Register func(r *rpc.Router, srv *rpc.Server)
	// MaxFrameBytes caps incoming framed JSON bytes for the RPC session.
	// If <= 0, the rpc.Server default is used.
	MaxFrameBytes int
	// Observer attaches an optional metrics observer to each rpc.Server.
	Observer observability.RPCObserver
}

// Options configures a Server.
type Options struct {
	// MaxStreamHelloBytes caps the StreamHello frame size.
	// If <= 0, endpoint.DefaultMaxStreamHelloBytes is used.
	MaxStreamHelloBytes int
	RPC                 RPCOptions

	// OnError is called for non-fatal stream accept/dispatch errors (e.g. bad StreamHello)
	// and panics recovered from user handlers. It must not panic.
	OnError func(err error)
}

// Server dispatches endpoint streams by StreamHello(kind).
//
// It provides a default handler for the RPC stream kind (usually "rpc") and
// allows user-defined stream handlers for additional kinds (e.g. "echo").
type Server struct {
	maxHelloBytes int
	rpc           RPCOptions
	onError       func(err error)

	mu       sync.RWMutex
	handlers map[string]StreamHandler
}

// New constructs a Server with the provided options.
func New(opts Options) *Server {
	maxHello := opts.MaxStreamHelloBytes
	if maxHello <= 0 {
		maxHello = endpoint.DefaultMaxStreamHelloBytes
	}
	rpcOpts := opts.RPC
	if rpcOpts.Kind == "" {
		rpcOpts.Kind = "rpc"
	}
	return &Server{
		maxHelloBytes: maxHello,
		rpc:           rpcOpts,
		onError:       opts.OnError,
		handlers:      make(map[string]StreamHandler),
	}
}

// Handle registers a handler for the given stream kind.
//
// A nil handler removes the registration.
func (s *Server) Handle(kind string, h StreamHandler) {
	if s == nil || kind == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if h == nil {
		delete(s.handlers, kind)
		return
	}
	s.handlers[kind] = h
}

// ServeSession accepts and dispatches streams until ctx ends or the session fails.
func (s *Server) ServeSession(ctx context.Context, sess endpoint.Session) error {
	if s == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if sess == nil {
		return errors.New("missing session")
	}
	if err := ctx.Err(); err != nil {
		return wrapCtxErr(sess.Path(), err)
	}

	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = sess.Close()
		case <-done:
		}
	}()
	defer close(done)

	for {
		kind, stream, err := sess.AcceptStreamHello(s.maxHelloBytes)
		if err != nil {
			if ctx.Err() != nil {
				return wrapCtxErr(sess.Path(), ctx.Err())
			}
			var fe *endpoint.Error
			if errors.As(err, &fe) && fe.Code == endpoint.CodeStreamHelloFailed {
				s.reportError(err)
				continue
			}
			return err
		}
		go s.handleStream(ctx, sess.Path(), kind, stream)
	}
}

// HandleStream dispatches a single stream by kind.
func (s *Server) HandleStream(ctx context.Context, kind string, stream io.ReadWriteCloser) {
	if ctx == nil {
		ctx = context.Background()
	}
	s.handleStream(ctx, "", kind, stream)
}

func (s *Server) handleStream(ctx context.Context, path endpoint.Path, kind string, stream io.ReadWriteCloser) {
	if s == nil || stream == nil {
		return
	}
	defer stream.Close()
	defer func() {
		if recover() != nil {
			s.reportError(fmt.Errorf("stream handler panic (kind=%q)", kind))
		}
	}()
	if kind == "" {
		return
	}
	h := s.lookup(kind)
	if h != nil {
		h(ctx, stream)
		return
	}
	if kind == s.rpc.Kind && s.rpc.Register != nil {
		s.serveRPC(ctx, path, stream)
		return
	}
	if s.onError != nil {
		p := fserrors.PathAuto
		if path != "" {
			p = fserrors.Path(path)
		}
		s.reportError(fserrors.Wrap(p, fserrors.StageRPC, fserrors.CodeMissingHandler, fmt.Errorf("unhandled stream kind: %q", kind)))
	}
}

func (s *Server) lookup(kind string) StreamHandler {
	s.mu.RLock()
	h := s.handlers[kind]
	s.mu.RUnlock()
	return h
}

func (s *Server) serveRPC(ctx context.Context, path endpoint.Path, stream io.ReadWriteCloser) {
	router := rpc.NewRouter()
	srv := rpc.NewServer(stream, router)
	if s.rpc.MaxFrameBytes > 0 {
		srv.SetMaxFrameBytes(s.rpc.MaxFrameBytes)
	}
	if s.rpc.Observer != nil {
		srv.SetObserver(s.rpc.Observer)
	}
	defer func() {
		if recover() != nil {
			s.reportError(wrapRPCServeErr(path, errors.New("rpc register panic")))
		}
	}()
	s.rpc.Register(router, srv)
	if err := srv.Serve(ctx); err != nil {
		// Context cancellation is the normal shutdown signal for server loops.
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return
		}
		// EOF is a normal stream teardown when the peer closes cleanly.
		if errors.Is(err, io.EOF) {
			return
		}
		s.reportError(wrapRPCServeErr(path, err))
	}
}

func wrapCtxErr(path endpoint.Path, err error) error {
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
	p := fserrors.PathAuto
	if path != "" {
		p = fserrors.Path(path)
	}
	return fserrors.Wrap(p, fserrors.StageClose, code, err)
}

func wrapRPCServeErr(path endpoint.Path, err error) error {
	p := fserrors.PathAuto
	if path != "" {
		p = fserrors.Path(path)
	}
	return fserrors.Wrap(p, fserrors.StageRPC, fserrors.CodeRPCFailed, err)
}

func (s *Server) reportError(err error) {
	if s == nil || s.onError == nil || err == nil {
		return
	}
	defer func() {
		_ = recover()
	}()
	s.onError(err)
}
