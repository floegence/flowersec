package rpc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"sync"
	"time"

	"github.com/floegence/flowersec/flowersec-go/framing/jsonframe"
	rpcv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/rpc/v1"
	"github.com/floegence/flowersec/flowersec-go/internal/defaults"
	"github.com/floegence/flowersec/flowersec-go/observability"
)

const maxInvalidJSONFrames = 3

const maxPortableRequestID uint64 = 1<<53 - 1

const (
	defaultMaxConcurrentRequests  = defaults.RPCMaxConcurrentRequests
	defaultMaxQueuedRequests      = defaults.RPCMaxQueuedRequests
	defaultMaxQueuedNotifications = defaults.RPCMaxQueuedNotifications
)

// ServerOptions bounds server-side handler concurrency and queues.
type ServerOptions struct {
	MaxConcurrentRequests  int
	MaxQueuedRequests      int
	MaxQueuedNotifications int
}

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

func (r *Router) handle(ctx context.Context, typeID uint32, payload json.RawMessage) (out json.RawMessage, rpcErr *rpcv1.RpcError) {
	r.mu.RLock()
	h := r.handlers[typeID]
	r.mu.RUnlock()
	if h == nil {
		return nil, &rpcv1.RpcError{Code: 404, Message: strPtr("handler not found")}
	}
	defer func() {
		if recover() != nil {
			// Treat handler panics as internal errors so user code cannot crash the process.
			out = nil
			rpcErr = &rpcv1.RpcError{Code: 500, Message: strPtr("handler panic")}
		}
	}()
	return h(ctx, payload)
}

// Server reads RPC envelopes and dispatches them through a Router.
type Server struct {
	r       io.ReadWriteCloser        // Underlying stream for framed JSON.
	router  *Router                   // Handler registry for incoming requests.
	maxLen  int                       // Max frame size for jsonframe.ReadJSONFrame.
	writeMu sync.Mutex                // Serializes writes on the stream.
	obs     observability.RPCObserver // Metrics observer.
	options ServerOptions
}

// NewServer creates a server over a read/write stream.
func NewServer(rwc io.ReadWriteCloser, router *Router) *Server {
	server, _ := NewServerWithOptions(rwc, router, ServerOptions{})
	return server
}

// NewServerWithOptions creates a server with explicit bounded concurrency.
func NewServerWithOptions(rwc io.ReadWriteCloser, router *Router, options ServerOptions) (*Server, error) {
	if rwc == nil {
		return nil, errors.New("rpc stream must be non-nil")
	}
	if router == nil {
		return nil, errors.New("rpc router must be non-nil")
	}
	if options.MaxConcurrentRequests < 0 || options.MaxQueuedRequests < 0 || options.MaxQueuedNotifications < 0 {
		return nil, errors.New("rpc server limits must be >= 0")
	}
	if options.MaxConcurrentRequests == 0 {
		options.MaxConcurrentRequests = defaultMaxConcurrentRequests
	}
	if options.MaxQueuedRequests == 0 {
		options.MaxQueuedRequests = defaultMaxQueuedRequests
	}
	if options.MaxQueuedNotifications == 0 {
		options.MaxQueuedNotifications = defaultMaxQueuedNotifications
	}
	return &Server{
		r:       rwc,
		router:  router,
		maxLen:  jsonframe.DefaultMaxJSONFrameBytes,
		obs:     observability.NoopRPCObserver,
		options: options,
	}, nil
}

// SetMaxFrameBytes caps incoming JSON frames.
//
// Passing n==0 resets the cap to the library default (1 MiB). The RPC layer does not
// support disabling the size guard via this method to avoid memory DoS footguns.
func (s *Server) SetMaxFrameBytes(n int) error {
	if n < 0 {
		return errors.New("max frame bytes must be >= 0")
	}
	if n == 0 {
		s.maxLen = jsonframe.DefaultMaxJSONFrameBytes
		return nil
	}
	s.maxLen = n
	return nil
}

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
	err := jsonframe.WriteJSONFrame(s.r, env)
	if err != nil {
		s.obs.ServerFrameError(observability.RPCFrameWrite)
	}
	return err
}

// Serve runs the request loop until the context ends or the stream fails.
func (s *Server) Serve(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.options.MaxConcurrentRequests == 0 {
		s.options.MaxConcurrentRequests = defaultMaxConcurrentRequests
	}
	if s.options.MaxQueuedRequests == 0 {
		s.options.MaxQueuedRequests = defaultMaxQueuedRequests
	}
	if s.options.MaxQueuedNotifications == 0 {
		s.options.MaxQueuedNotifications = defaultMaxQueuedNotifications
	}
	stopContextClose := context.AfterFunc(ctx, func() { _ = s.r.Close() })
	defer stopContextClose()
	workerCtx, cancelWorkers := context.WithCancel(ctx)
	requestScheduler := newRequestScheduler(
		workerCtx,
		s.options.MaxConcurrentRequests,
		s.options.MaxQueuedRequests,
		s.handleRequest,
	)
	notifications := make(chan *rpcv1.RpcEnvelope, s.options.MaxQueuedNotifications)
	var notificationWorker sync.WaitGroup
	defer func() {
		cancelWorkers()
		requestScheduler.Close()
		notificationWorker.Wait()
	}()
	notificationWorker.Add(1)
	go func() {
		defer notificationWorker.Done()
		for {
			select {
			case <-workerCtx.Done():
				return
			case env := <-notifications:
				_, rpcErr := s.router.handle(workerCtx, env.TypeId, env.Payload)
				s.obs.ServerRequest(rpcResultFromError(rpcErr))
			}
		}
	}()
	invalidJSONFrames := 0
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		b, err := jsonframe.ReadJSONFrame(s.r, s.maxLen)
		if err != nil {
			s.obs.ServerFrameError(observability.RPCFrameRead)
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		env, err := decodeEnvelope(b)
		if err != nil {
			invalidJSONFrames++
			if invalidJSONFrames >= maxInvalidJSONFrames {
				s.obs.ServerFrameError(observability.RPCFrameRead)
				_ = s.r.Close()
				return errors.New("rpc invalid json frame")
			}
			continue
		}
		invalidJSONFrames = 0
		if env.ResponseTo != 0 {
			continue
		}
		if env.RequestId == 0 {
			// Notification: response_to=0 and request_id=0.
			notification := env
			select {
			case notifications <- &notification:
			default:
				s.obs.ServerRequest(observability.RPCResultResourceExhausted)
				_ = s.r.Close()
				return errors.New("rpc notification queue exhausted")
			}
			continue
		}
		if !requestScheduler.Submit(env) {
			s.obs.ServerRequest(observability.RPCResultResourceExhausted)
			s.writeResponse(rpcv1.RpcEnvelope{
				TypeId:     env.TypeId,
				ResponseTo: env.RequestId,
				Error:      &rpcv1.RpcError{Code: 429, Message: strPtr("server overloaded")},
			})
		}
	}
}

func (s *Server) handleRequest(ctx context.Context, env rpcv1.RpcEnvelope) {
	respPayload, rpcErr := s.router.handle(ctx, env.TypeId, env.Payload)
	s.obs.ServerRequest(rpcResultFromError(rpcErr))
	s.writeResponse(rpcv1.RpcEnvelope{
		TypeId:     env.TypeId,
		ResponseTo: env.RequestId,
		Payload:    respPayload,
		Error:      rpcErr,
	})
}

func (s *Server) writeResponse(resp rpcv1.RpcEnvelope) {
	s.writeMu.Lock()
	if err := jsonframe.WriteJSONFrame(s.r, resp); err != nil {
		s.obs.ServerFrameError(observability.RPCFrameWrite)
	}
	s.writeMu.Unlock()
}

// Client issues RPC calls and receives notifications.
type Client struct {
	r      io.ReadWriteCloser // Underlying stream for framed JSON.
	maxLen int                // Max frame size for jsonframe.ReadJSONFrame.

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
		maxLen:  jsonframe.DefaultMaxJSONFrameBytes,
		nextID:  1,
		pending: make(map[uint64]chan rpcv1.RpcEnvelope),
		notify:  make(map[uint32]map[*notifyHandler]struct{}),
		obs:     observability.NoopRPCObserver,
	}
	go c.readLoop()
	return c
}

// SetMaxFrameBytes caps incoming JSON frames.
//
// Passing n==0 resets the cap to the library default (1 MiB). The RPC layer does not
// support disabling the size guard via this method to avoid memory DoS footguns.
func (c *Client) SetMaxFrameBytes(n int) error {
	if n < 0 {
		return errors.New("max frame bytes must be >= 0")
	}
	if n == 0 {
		c.maxLen = jsonframe.DefaultMaxJSONFrameBytes
		return nil
	}
	c.maxLen = n
	return nil
}

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
	err := jsonframe.WriteJSONFrame(c.r, env)
	if err != nil {
		c.obs.ClientFrameError(observability.RPCFrameWrite)
	}
	return err
}

// Call sends an RPC request and waits for its response or context cancellation.
func (c *Client) Call(ctx context.Context, typeID uint32, payload json.RawMessage) (json.RawMessage, *rpcv1.RpcError, error) {
	if ctx == nil {
		ctx = context.Background()
	}
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
	err = jsonframe.WriteJSONFrame(c.r, env)
	c.writeMu.Unlock()
	if err != nil {
		c.obs.ClientFrameError(observability.RPCFrameWrite)
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
	if id == 0 || id > maxPortableRequestID {
		return 0, nil, errors.New("request id overflow")
	}
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
	invalidJSONFrames := 0
	for {
		b, err := jsonframe.ReadJSONFrame(c.r, c.maxLen)
		if err != nil {
			c.obs.ClientFrameError(observability.RPCFrameRead)
			c.closeAll(err)
			return
		}
		env, err := decodeEnvelope(b)
		if err != nil {
			invalidJSONFrames++
			if invalidJSONFrames >= maxInvalidJSONFrames {
				c.obs.ClientFrameError(observability.RPCFrameRead)
				_ = c.r.Close()
				c.closeAll(errors.New("rpc invalid json frame"))
				return
			}
			continue
		}
		invalidJSONFrames = 0
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
					func() {
						// User callbacks must not be able to crash the transport read loop.
						defer func() { _ = recover() }()
						h.fn(env.Payload)
					}()
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

func decodeEnvelope(data []byte) (rpcv1.RpcEnvelope, error) {
	var ids struct {
		RequestID  json.RawMessage `json:"request_id"`
		ResponseTo json.RawMessage `json:"response_to"`
	}
	if err := json.Unmarshal(data, &ids); err != nil {
		return rpcv1.RpcEnvelope{}, err
	}
	requestID, err := parsePortableRequestID("request_id", ids.RequestID)
	if err != nil {
		return rpcv1.RpcEnvelope{}, err
	}
	responseTo, err := parsePortableRequestID("response_to", ids.ResponseTo)
	if err != nil {
		return rpcv1.RpcEnvelope{}, err
	}
	var envelope rpcv1.RpcEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return rpcv1.RpcEnvelope{}, err
	}
	envelope.RequestId = requestID
	envelope.ResponseTo = responseTo
	return envelope, nil
}

func parsePortableRequestID(name string, raw json.RawMessage) (uint64, error) {
	value := bytes.TrimSpace(raw)
	if len(value) == 0 {
		return 0, fmt.Errorf("rpc envelope missing %s", name)
	}
	for _, b := range value {
		if b < '0' || b > '9' {
			return 0, fmt.Errorf("rpc envelope invalid %s", name)
		}
	}
	parsed, err := strconv.ParseUint(string(value), 10, 64)
	if err != nil || parsed > maxPortableRequestID {
		return 0, fmt.Errorf("rpc envelope invalid %s", name)
	}
	return parsed, nil
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
	if err.Code == 429 {
		return observability.RPCResultResourceExhausted
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
