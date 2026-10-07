package flowersec

import (
	"context"
	"io"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
)

// StreamHandlers returns the proxy registrations for a frozen v4 Stream plan.
// Install them in StreamHandlerPlanConfig before READY. The authorize callback
// receives that plan's authenticated application binding and original metadata;
// it must authorize this specific proxy upstream. Each accepted stream retains
// its original v4 owner, executor permit and Session lifetime throughout I/O.
// The ProxyServer's total concurrency is shared by every plan using it.
func (server *ProxyServer) StreamHandlers(authorize func(context.Context, any, []byte) error) ([]RawStreamHandlerConfig, error) {
	if server == nil || authorize == nil {
		return nil, ErrInvalidProxyServer
	}
	server.stateMu.Lock()
	defer server.stateMu.Unlock()
	if server.closed || server.httpClient == nil || server.wsDialer == nil {
		return nil, ErrInvalidProxyServer
	}
	allowed := func(ctx context.Context, binding any, metadata []byte) error {
		server.stateMu.Lock()
		closed := server.closed
		server.stateMu.Unlock()
		if closed {
			return ErrInvalidProxyServer
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		return authorize(ctx, binding, metadata)
	}
	handle := func(websocket bool) func(context.Context, any, []byte, *StreamOwnership) error {
		return func(ctx context.Context, binding any, _ []byte, owner *StreamOwnership) error {
			if owner == nil {
				return ErrInvalidProxyServer
			}
			stream := &v4ProxyStream{owner: owner, ctx: ctx, binding: binding}
			return server.runLimited(ctx, stream, func(ctx context.Context) error {
				if websocket {
					if err := server.serveWebSocketStream(ctx, stream); err != nil {
						return err
					}
				} else {
					server.serveHTTPStream(ctx, stream)
				}
				return owner.Finish(ctx)
			})
		}
	}
	return []RawStreamHandlerConfig{
		{Kind: proxyHTTPStreamKind, Slots: uint32(server.config.maxHTTP), WorkClass: WorkResident, AuthorizeOpen: allowed, Handler: handle(false)},
		{Kind: proxyWSStreamKind, Slots: uint32(cap(server.permits)), WorkClass: WorkResident, AuthorizeOpen: allowed, Handler: handle(true)},
	}, nil
}

// This private I/O projection uses the original v4 owner directly. In
// particular, canceling the post-body observer does not reset a completed
// response before its FIN and drain can be published.
type v4ProxyStream struct {
	owner   *StreamOwnership
	ctx     context.Context
	binding any
}

func (s *v4ProxyStream) Read(dst []byte) (int, error) { return s.ReadContext(s.ctx, dst) }
func (s *v4ProxyStream) ReadContext(ctx context.Context, dst []byte) (int, error) {
	if len(dst) == 0 {
		return 0, nil
	}
	result, err := s.owner.ReadInto(ctx, dst)
	if err == nil && result.ReadTerminal == protocolv4.V4ReadTerminalEof {
		err = io.EOF
	}
	return int(result.Progress.Filled), err
}
func (s *v4ProxyStream) Write(src []byte) (int, error) { return s.owner.Write(s.ctx, src) }
func (s *v4ProxyStream) Reset() error                  { return s.owner.Close() }

// RegisterStreamHandlers adds the two current proxy declarations to the caller's
// application plan before it is frozen. Duplicate kinds are rejected before any
// change, including a conflicting typed declaration. NewStreamHandlerPlan admits
// the complete declarations and their original delegate graph together.
func (server *ProxyServer) RegisterStreamHandlers(plan *StreamHandlerPlanConfig, authorize func(context.Context, any, []byte) error) error {
	if plan == nil {
		return ErrInvalidProxyServer
	}
	declarations, err := server.StreamHandlers(authorize)
	if err != nil {
		return err
	}
	for _, existing := range plan.Handlers {
		for _, declaration := range declarations {
			if existing.Kind == declaration.Kind {
				return ErrInvalidProxyServer
			}
		}
	}
	plan.Handlers = append(plan.Handlers, declarations...)
	return nil
}

func (s *v4ProxyStream) credentialApplicationBinding() any { return s.binding }
