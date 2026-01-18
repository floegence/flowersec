package serve

import (
	"context"
	"io"
	"sync"

	"github.com/floegence/flowersec/flowersec-go/endpoint"
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
}

// Server dispatches endpoint streams by StreamHello(kind).
//
// It provides a default handler for the RPC stream kind (usually "rpc") and
// allows user-defined stream handlers for additional kinds (e.g. "echo").
type Server struct {
	maxHelloBytes int
	rpc           RPCOptions

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
	return sess.ServeStreams(ctx, s.maxHelloBytes, func(kind string, stream io.ReadWriteCloser) {
		s.HandleStream(ctx, kind, stream)
	})
}

// HandleStream dispatches a single stream by kind.
func (s *Server) HandleStream(ctx context.Context, kind string, stream io.ReadWriteCloser) {
	if s == nil || stream == nil {
		return
	}
	defer stream.Close()
	if kind == "" {
		return
	}
	h := s.lookup(kind)
	if h != nil {
		h(ctx, stream)
		return
	}
	if kind == s.rpc.Kind && s.rpc.Register != nil {
		s.serveRPC(ctx, stream)
		return
	}
}

func (s *Server) lookup(kind string) StreamHandler {
	s.mu.RLock()
	h := s.handlers[kind]
	s.mu.RUnlock()
	return h
}

func (s *Server) serveRPC(ctx context.Context, stream io.ReadWriteCloser) {
	router := rpc.NewRouter()
	srv := rpc.NewServer(stream, router)
	if s.rpc.MaxFrameBytes > 0 {
		srv.SetMaxFrameBytes(s.rpc.MaxFrameBytes)
	}
	if s.rpc.Observer != nil {
		srv.SetObserver(s.rpc.Observer)
	}
	s.rpc.Register(router, srv)
	_ = srv.Serve(ctx)
}
