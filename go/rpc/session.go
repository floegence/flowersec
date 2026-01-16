package rpc

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"time"

	rpcv1 "github.com/flowersec/flowersec/gen/flowersec/rpc/v1"
	"github.com/flowersec/flowersec/observability"
)

// Handler processes an RPC request and returns payload or an RPC error.
type Handler func(ctx context.Context, payload json.RawMessage) (json.RawMessage, *rpcv1.RpcError)

// Router dispatches RPC requests by type ID.
type Router struct {
	mu       sync.RWMutex       // Guards handler registrations.
	handlers map[uint32]Handler // Handlers keyed by type ID.
}

// NewRouter constructs an empty router.
func NewRouter() *Router {
	return &Router{handlers: make(map[uint32]Handler)}
}

// Register binds a handler to a type ID.
func (r *Router) Register(typeID uint32, h Handler) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.handlers[typeID] = h
}

func (r *Router) handle(ctx context.Context, typeID uint32, payload json.RawMessage) (json.RawMessage, *rpcv1.RpcError) {
	r.mu.RLock()
	h := r.handlers[typeID]
	r.mu.RUnlock()
	if h == nil {
		return nil, &rpcv1.RpcError{Code: 404, Message: strPtr("handler not found")}
	}
	return h(ctx, payload)
}

// Server reads RPC envelopes and dispatches them through a Router.
type Server struct {
	r       io.ReadWriteCloser        // Underlying stream for framed JSON.
	router  *Router                   // Handler registry for incoming requests.
	maxLen  int                       // Max frame size for ReadJSONFrame.
	writeMu sync.Mutex                // Serializes writes on the stream.
	obs     observability.RPCObserver // Metrics observer.
}

// NewServer creates a server over a read/write stream.
func NewServer(rwc io.ReadWriteCloser, router *Router) *Server {
	return &Server{r: rwc, router: router, maxLen: 1 << 20, obs: observability.NoopRPCObserver}
}

// SetMaxFrameBytes caps incoming JSON frames.
func (s *Server) SetMaxFrameBytes(n int) { s.maxLen = n }

// SetObserver replaces the RPC observer; nil resets to no-op.
func (s *Server) SetObserver(obs observability.RPCObserver) {
	if obs == nil {
		obs = observability.NoopRPCObserver
	}
	s.obs = obs
}

// Notify sends a one-way notification to the peer.
func (s *Server) Notify(typeID uint32, payload json.RawMessage) error {
	env := rpcv1.RpcEnvelope{
		TypeId:     typeID,
		RequestId:  0,
		ResponseTo: 0,
		Payload:    payload,
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return WriteJSONFrame(s.r, env)
}

// Serve runs the request loop until the context ends or the stream fails.
func (s *Server) Serve(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		b, err := ReadJSONFrame(s.r, s.maxLen)
		if err != nil {
			s.obs.ServerFrameError(observability.RPCFrameRead)
			return err
		}
		var env rpcv1.RpcEnvelope
		if err := json.Unmarshal(b, &env); err != nil {
			continue
		}
		if env.ResponseTo != 0 {
			continue
		}
		if env.RequestId == 0 {
			// Notification: response_to=0 and request_id=0.
			_, rpcErr := s.router.handle(ctx, env.TypeId, env.Payload)
			s.obs.ServerRequest(rpcResultFromError(rpcErr))
			continue
		}
		respPayload, rpcErr := s.router.handle(ctx, env.TypeId, env.Payload)
		s.obs.ServerRequest(rpcResultFromError(rpcErr))
		resp := rpcv1.RpcEnvelope{
			TypeId:     env.TypeId,
			RequestId:  0,
			ResponseTo: env.RequestId,
			Payload:    respPayload,
			Error:      rpcErr,
		}
		s.writeMu.Lock()
		if err := WriteJSONFrame(s.r, resp); err != nil {
			s.obs.ServerFrameError(observability.RPCFrameWrite)
		}
		s.writeMu.Unlock()
	}
}

// Client issues RPC calls and receives notifications.
type Client struct {
	r      io.ReadWriteCloser // Underlying stream for framed JSON.
	maxLen int                // Max frame size for ReadJSONFrame.

	writeMu sync.Mutex // Serializes writes on the stream.

	mu      sync.Mutex                             // Guards pending/notify state.
	nextID  uint64                                 // Next request ID to allocate.
	pending map[uint64]chan rpcv1.RpcEnvelope      // Pending responses keyed by request ID.
	notify  map[uint32]map[*notifyHandler]struct{} // Notification handlers by type ID.
	closed  bool                                   // Closed flag for read/write paths.
	lastErr error                                  // Sticky error from read loop.
	obs     observability.RPCObserver              // Metrics observer.
}

// NewClient creates an RPC client and starts its read loop.
func NewClient(rwc io.ReadWriteCloser) *Client {
	c := &Client{
		r:       rwc,
		maxLen:  1 << 20,
		nextID:  1,
		pending: make(map[uint64]chan rpcv1.RpcEnvelope),
		notify:  make(map[uint32]map[*notifyHandler]struct{}),
		obs:     observability.NoopRPCObserver,
	}
	go c.readLoop()
	return c
}

// SetMaxFrameBytes caps incoming JSON frames.
func (c *Client) SetMaxFrameBytes(n int) { c.maxLen = n }

// SetObserver replaces the RPC observer; nil resets to no-op.
func (c *Client) SetObserver(obs observability.RPCObserver) {
	if obs == nil {
		obs = observability.NoopRPCObserver
	}
	c.obs = obs
}

type notifyHandler struct {
	fn func(payload json.RawMessage) // Handler callback.
}

// OnNotify registers a handler for incoming notifications by type ID.
func (c *Client) OnNotify(typeID uint32, h func(payload json.RawMessage)) (unsubscribe func()) {
	nh := &notifyHandler{fn: h}
	c.mu.Lock()
	m := c.notify[typeID]
	if m == nil {
		m = make(map[*notifyHandler]struct{})
		c.notify[typeID] = m
	}
	m[nh] = struct{}{}
	c.mu.Unlock()
	return func() {
		c.mu.Lock()
		if mm := c.notify[typeID]; mm != nil {
			delete(mm, nh)
			if len(mm) == 0 {
				delete(c.notify, typeID)
			}
		}
		c.mu.Unlock()
	}
}

// Notify sends a one-way notification to the peer.
func (c *Client) Notify(typeID uint32, payload json.RawMessage) error {
	env := rpcv1.RpcEnvelope{
		TypeId:     typeID,
		RequestId:  0,
		ResponseTo: 0,
		Payload:    payload,
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return WriteJSONFrame(c.r, env)
}

// Call sends an RPC request and waits for its response or context cancellation.
func (c *Client) Call(ctx context.Context, typeID uint32, payload json.RawMessage) (json.RawMessage, *rpcv1.RpcError, error) {
	start := time.Now()
	record := func(result observability.RPCResult) {
		c.obs.ClientCall(result, time.Since(start))
	}
	reqID, ch, err := c.reserve()
	if err != nil {
		record(observability.RPCResultTransportError)
		return nil, nil, err
	}
	defer c.release(reqID)

	env := rpcv1.RpcEnvelope{
		TypeId:     typeID,
		RequestId:  reqID,
		ResponseTo: 0,
		Payload:    payload,
	}
	c.writeMu.Lock()
	err = WriteJSONFrame(c.r, env)
	c.writeMu.Unlock()
	if err != nil {
		record(observability.RPCResultTransportError)
		return nil, nil, err
	}
	select {
	case <-ctx.Done():
		record(observability.RPCResultCanceled)
		return nil, nil, ctx.Err()
	case resp, ok := <-ch:
		if !ok {
			record(observability.RPCResultTransportError)
			return nil, nil, c.closedErr()
		}
		record(rpcResultFromError(resp.Error))
		return resp.Payload, resp.Error, nil
	}
}

func (c *Client) reserve() (uint64, chan rpcv1.RpcEnvelope, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		if c.lastErr != nil {
			return 0, nil, c.lastErr
		}
		return 0, nil, io.ErrClosedPipe
	}
	id := c.nextID
	c.nextID++
	ch := make(chan rpcv1.RpcEnvelope, 1)
	c.pending[id] = ch
	return id, ch, nil
}

func (c *Client) release(id uint64) {
	c.mu.Lock()
	if _, ok := c.pending[id]; ok {
		delete(c.pending, id)
	}
	c.mu.Unlock()
}

func (c *Client) readLoop() {
	for {
		b, err := ReadJSONFrame(c.r, c.maxLen)
		if err != nil {
			c.closeAll(err)
			return
		}
		var env rpcv1.RpcEnvelope
		if err := json.Unmarshal(b, &env); err != nil {
			continue
		}
		if env.ResponseTo == 0 {
			if env.RequestId == 0 {
				// Notification: fan out to registered handlers.
				c.obs.ClientNotify()
				c.mu.Lock()
				m := c.notify[env.TypeId]
				handlers := make([]*notifyHandler, 0, len(m))
				for h := range m {
					handlers = append(handlers, h)
				}
				c.mu.Unlock()
				for _, h := range handlers {
					h.fn(env.Payload)
				}
			}
			continue
		}
		c.mu.Lock()
		ch := c.pending[env.ResponseTo]
		c.mu.Unlock()
		if ch != nil {
			select {
			case ch <- env:
			default:
			}
		}
	}
}

func (c *Client) closeAll(err error) {
	c.mu.Lock()
	c.closed = true
	if c.lastErr == nil {
		c.lastErr = err
	}
	for id, ch := range c.pending {
		delete(c.pending, id)
		close(ch)
		_ = id
	}
	c.mu.Unlock()
	_ = err
}

func (c *Client) Close() error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	return c.r.Close()
}

func strPtr(s string) *string { return &s }

func rpcResultFromError(err *rpcv1.RpcError) observability.RPCResult {
	if err == nil {
		return observability.RPCResultOK
	}
	if err.Code == 404 {
		return observability.RPCResultHandlerNotFound
	}
	return observability.RPCResultRPCError
}

func (c *Client) closedErr() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.lastErr != nil {
		return c.lastErr
	}
	return io.ErrClosedPipe
}

var ErrTimeout = errors.New("rpc timeout")

// WithTimeout returns the parent context if d<=0; otherwise wraps it with a timeout.
func WithTimeout(parent context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	if d <= 0 {
		return parent, func() {}
	}
	return context.WithTimeout(parent, d)
}
