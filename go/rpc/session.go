package rpc

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"time"

	rpcv1 "github.com/flowersec/flowersec/gen/flowersec/rpc/v1"
)

type Handler func(ctx context.Context, payload json.RawMessage) (json.RawMessage, *rpcv1.RpcError)

type Router struct {
	mu       sync.RWMutex
	handlers map[uint32]Handler
}

func NewRouter() *Router {
	return &Router{handlers: make(map[uint32]Handler)}
}

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

type Server struct {
	r       io.ReadWriteCloser
	router  *Router
	maxLen  int
	writeMu sync.Mutex
}

func NewServer(rwc io.ReadWriteCloser, router *Router) *Server {
	return &Server{r: rwc, router: router, maxLen: 1 << 20}
}

func (s *Server) SetMaxFrameBytes(n int) { s.maxLen = n }

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

func (s *Server) Serve(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		b, err := ReadJSONFrame(s.r, s.maxLen)
		if err != nil {
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
			_, _ = s.router.handle(ctx, env.TypeId, env.Payload)
			continue
		}
		respPayload, rpcErr := s.router.handle(ctx, env.TypeId, env.Payload)
		resp := rpcv1.RpcEnvelope{
			TypeId:     env.TypeId,
			RequestId:  0,
			ResponseTo: env.RequestId,
			Payload:    respPayload,
			Error:      rpcErr,
		}
		s.writeMu.Lock()
		_ = WriteJSONFrame(s.r, resp)
		s.writeMu.Unlock()
	}
}

type Client struct {
	r      io.ReadWriteCloser
	maxLen int

	writeMu sync.Mutex

	mu      sync.Mutex
	nextID  uint64
	pending map[uint64]chan rpcv1.RpcEnvelope
	notify  map[uint32]map[*notifyHandler]struct{}
	closed  bool
}

func NewClient(rwc io.ReadWriteCloser) *Client {
	c := &Client{
		r:       rwc,
		maxLen:  1 << 20,
		nextID:  1,
		pending: make(map[uint64]chan rpcv1.RpcEnvelope),
		notify:  make(map[uint32]map[*notifyHandler]struct{}),
	}
	go c.readLoop()
	return c
}

func (c *Client) SetMaxFrameBytes(n int) { c.maxLen = n }

type notifyHandler struct {
	fn func(payload json.RawMessage)
}

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

func (c *Client) Call(ctx context.Context, typeID uint32, payload json.RawMessage) (json.RawMessage, *rpcv1.RpcError, error) {
	reqID, ch, err := c.reserve()
	if err != nil {
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
		return nil, nil, err
	}
	select {
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	case resp := <-ch:
		return resp.Payload, resp.Error, nil
	}
}

func (c *Client) reserve() (uint64, chan rpcv1.RpcEnvelope, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
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
	if ch, ok := c.pending[id]; ok {
		delete(c.pending, id)
		close(ch)
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

var ErrTimeout = errors.New("rpc timeout")

func WithTimeout(parent context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	if d <= 0 {
		return parent, func() {}
	}
	return context.WithTimeout(parent, d)
}
