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
	"unicode/utf8"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/defaults"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/framing/jsonframe"
	rpcv1 "github.com/floegence/flowersec/flowersec-go/v5/internal/rpcwire"
)

const maxInvalidJSONFrames = 3

const maxPortableRequestID uint64 = 1<<53 - 1

const maxRPCErrorMessageBytes = 1024

var errInvalidRPCApplicationError = errors.New("rpc invalid application error")

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
	mu                  sync.RWMutex       // Guards handler registrations.
	handlers            map[uint32]Handler // Handlers keyed by type ID.
	notify              map[uint32]map[*routerNotification]struct{}
	notificationsClosed bool
}

type routerNotification struct {
	fn func(context.Context, json.RawMessage)
}

// NewRouter constructs an empty router.
func NewRouter() *Router {
	return &Router{handlers: make(map[uint32]Handler), notify: make(map[uint32]map[*routerNotification]struct{})}
}

func (r *Router) OnNotify(typeID uint32, handler func(context.Context, json.RawMessage)) func() {
	if typeID == 0 || handler == nil {
		return func() {}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.notificationsClosed {
		return func() {}
	}
	entry := &routerNotification{fn: handler}
	if r.notify[typeID] == nil {
		r.notify[typeID] = make(map[*routerNotification]struct{})
	}
	r.notify[typeID][entry] = struct{}{}
	return func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		delete(r.notify[typeID], entry)
		if len(r.notify[typeID]) == 0 {
			delete(r.notify, typeID)
		}
	}
}

func (r *Router) CloseNotifications() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.notificationsClosed = true
	clear(r.notify)
}

func (r *Router) dispatchNotification(ctx context.Context, typeID uint32, payload json.RawMessage) {
	_, _ = r.handle(ctx, typeID, append(json.RawMessage(nil), payload...))
	r.mu.RLock()
	handlers := make([]*routerNotification, 0, len(r.notify[typeID]))
	for handler := range r.notify[typeID] {
		handlers = append(handlers, handler)
	}
	r.mu.RUnlock()
	for _, handler := range handlers {
		if ctx.Err() != nil {
			return
		}
		func() {
			defer func() { _ = recover() }()
			handler.fn(ctx, append(json.RawMessage(nil), payload...))
		}()
	}
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
	r       io.ReadWriteCloser // Underlying stream for framed JSON.
	router  *Router            // Handler registry for incoming requests.
	maxLen  int                // Max frame size for jsonframe.ReadJSONFrame.
	writeMu sync.Mutex         // Serializes writes on the stream.
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
	return jsonframe.WriteJSONFrame(s.r, env)
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
				s.router.dispatchNotification(workerCtx, env.TypeId, env.Payload)
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
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		env, err := decodeEnvelope(b)
		if err != nil {
			if errors.Is(err, errInvalidRPCApplicationError) {
				_ = s.r.Close()
				return errors.New("rpc invalid application error")
			}
			invalidJSONFrames++
			if invalidJSONFrames >= maxInvalidJSONFrames {
				_ = s.r.Close()
				return errors.New("rpc invalid json frame")
			}
			continue
		}
		invalidJSONFrames = 0
		if env.ResponseTo != 0 {
			_ = s.r.Close()
			return errors.New("rpc invalid response on server stream")
		}
		if env.RequestId == 0 {
			// Notification: response_to=0 and request_id=0.
			notification := env
			select {
			case notifications <- &notification:
			default:
				_ = s.r.Close()
				return errors.New("rpc notification queue exhausted")
			}
			continue
		}
		if !requestScheduler.Submit(env) {
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
	s.writeResponse(rpcv1.RpcEnvelope{
		TypeId:     env.TypeId,
		ResponseTo: env.RequestId,
		Payload:    respPayload,
		Error:      rpcErr,
	})
}

func (s *Server) writeResponse(resp rpcv1.RpcEnvelope) {
	resp.Error = sanitizeWireRPCError(resp.Error)
	s.writeMu.Lock()
	_ = jsonframe.WriteJSONFrame(s.r, resp)
	s.writeMu.Unlock()
}

// Client issues RPC calls and receives notifications.
type Client struct {
	r      io.ReadWriteCloser // Underlying stream for framed JSON.
	maxLen int                // Max frame size for jsonframe.ReadJSONFrame.

	writePermit chan struct{} // Serializes writes with cancellable admission.

	mu           sync.Mutex                             // Guards pending/notify state.
	nextID       uint64                                 // Next request ID to allocate.
	pending      map[uint64]chan rpcv1.RpcEnvelope      // Pending responses keyed by request ID.
	notify       map[uint32]map[*notifyHandler]struct{} // Notification handlers by type ID.
	closed       bool                                   // Closed flag for read/write paths.
	lastErr      error                                  // Sticky error from read loop.
	notifyQueue  chan rpcv1.RpcEnvelope
	notifyCtx    context.Context
	notifyCancel context.CancelFunc
}

// NewClient creates an RPC client and starts its read loop.
func NewClient(rwc io.ReadWriteCloser) *Client {
	notifyCtx, notifyCancel := context.WithCancel(context.Background())
	c := &Client{
		r:           rwc,
		maxLen:      jsonframe.DefaultMaxJSONFrameBytes,
		nextID:      1,
		pending:     make(map[uint64]chan rpcv1.RpcEnvelope),
		writePermit: make(chan struct{}, 1),
		notify:      make(map[uint32]map[*notifyHandler]struct{}),
		notifyQueue: make(chan rpcv1.RpcEnvelope, defaultMaxQueuedNotifications),
		notifyCtx:   notifyCtx, notifyCancel: notifyCancel,
	}
	go c.notificationLoop()
	go c.readLoop()
	return c
}

func (c *Client) notificationLoop() {
	for {
		select {
		case <-c.notifyCtx.Done():
			return
		case env := <-c.notifyQueue:
			c.mu.Lock()
			handlers := make([]*notifyHandler, 0, len(c.notify[env.TypeId]))
			for h := range c.notify[env.TypeId] {
				handlers = append(handlers, h)
			}
			c.mu.Unlock()
			for _, h := range handlers {
				go func(handler *notifyHandler, payload json.RawMessage) {
					// User callbacks must not be able to crash the transport.
					defer func() { _ = recover() }()
					handler.fn(payload)
				}(h, append(json.RawMessage(nil), env.Payload...))
			}
		}
	}
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
	return c.NotifyContext(context.Background(), typeID, payload)
}

func (c *Client) NotifyContext(ctx context.Context, typeID uint32, payload json.RawMessage) error {
	env := rpcv1.RpcEnvelope{
		TypeId:     typeID,
		RequestId:  0,
		ResponseTo: 0,
		Payload:    payload,
	}
	return c.writeEnvelope(ctx, env)
}

func (c *Client) writeEnvelope(ctx context.Context, env rpcv1.RpcEnvelope) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case c.writePermit <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	case <-c.notifyCtx.Done():
		return c.closedErr()
	}
	defer func() { <-c.writePermit }()
	if err := ctx.Err(); err != nil {
		return err
	}
	if c.notifyCtx.Err() != nil {
		return c.closedErr()
	}
	// A canceled write may have committed a partial frame. Retire the stream
	// before another caller can append bytes to that uncertain boundary.
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	err := jsonframe.WriteJSONFrame(c.r, env)
	stop()
	if contextErr := ctx.Err(); contextErr != nil {
		c.closeAll(contextErr)
		return contextErr
	}
	return err
}

// Call sends an RPC request and waits for its response or context cancellation.
func (c *Client) Call(ctx context.Context, typeID uint32, payload json.RawMessage) (json.RawMessage, *rpcv1.RpcError, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
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
	err = c.writeEnvelope(ctx, env)
	if err != nil {
		return nil, nil, err
	}
	select {
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	case resp, ok := <-ch:
		if !ok {
			return nil, nil, c.closedErr()
		}
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
			c.closeAll(err)
			return
		}
		env, err := decodeEnvelope(b)
		if err != nil {
			if errors.Is(err, errInvalidRPCApplicationError) {
				_ = c.r.Close()
				c.closeAll(errors.New("rpc invalid application error"))
				return
			}
			invalidJSONFrames++
			if invalidJSONFrames >= maxInvalidJSONFrames {
				_ = c.r.Close()
				c.closeAll(errors.New("rpc invalid json frame"))
				return
			}
			continue
		}
		invalidJSONFrames = 0
		if env.ResponseTo == 0 {
			if env.RequestId == 0 {
				// Queue notifications so a callback cannot stall response delivery
				// or deadlock by calling Client.Call synchronously.
				select {
				case c.notifyQueue <- env:
				default:
					_ = c.r.Close()
					c.closeAll(errors.New("rpc notification queue exhausted"))
					return
				}
				continue
			}
			_ = c.r.Close()
			c.closeAll(errors.New("rpc invalid request on client stream"))
			return
		}
		c.mu.Lock()
		ch := c.pending[env.ResponseTo]
		if ch != nil {
			select {
			case ch <- env:
			default:
			}
		}
		c.mu.Unlock()
	}
}

func decodeEnvelope(data []byte) (rpcv1.RpcEnvelope, error) {
	if !utf8.Valid(data) {
		return rpcv1.RpcEnvelope{}, fmt.Errorf("%w: invalid UTF-8", errInvalidRPCApplicationError)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return rpcv1.RpcEnvelope{}, err
	}
	if len(fields) < 4 || len(fields) > 5 {
		return rpcv1.RpcEnvelope{}, fmt.Errorf("%w: invalid envelope fields", errInvalidRPCApplicationError)
	}
	for name := range fields {
		switch name {
		case "type_id", "request_id", "response_to", "payload", "error":
		default:
			return rpcv1.RpcEnvelope{}, fmt.Errorf("%w: unknown envelope field", errInvalidRPCApplicationError)
		}
	}
	if _, ok := fields["payload"]; !ok {
		return rpcv1.RpcEnvelope{}, fmt.Errorf("%w: missing payload", errInvalidRPCApplicationError)
	}
	typeID, err := parseNonzeroUint32("type_id", fields["type_id"])
	if err != nil {
		return rpcv1.RpcEnvelope{}, err
	}
	requestID, err := parsePortableRequestID("request_id", fields["request_id"])
	if err != nil {
		return rpcv1.RpcEnvelope{}, err
	}
	responseTo, err := parsePortableRequestID("response_to", fields["response_to"])
	if err != nil {
		return rpcv1.RpcEnvelope{}, err
	}
	if requestID != 0 && responseTo != 0 {
		return rpcv1.RpcEnvelope{}, fmt.Errorf("%w: request and response IDs are mutually exclusive", errInvalidRPCApplicationError)
	}
	rawError := bytes.TrimSpace(fields["error"])
	hasError := len(rawError) > 0 && !bytes.Equal(rawError, []byte("null"))
	if hasError {
		if responseTo == 0 {
			return rpcv1.RpcEnvelope{}, fmt.Errorf("%w: error is only valid on a response", errInvalidRPCApplicationError)
		}
		var rpcError rpcv1.RpcError
		decoder := json.NewDecoder(bytes.NewReader(rawError))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&rpcError); err != nil || !validWireRPCError(&rpcError) {
			return rpcv1.RpcEnvelope{}, fmt.Errorf("%w: invalid error payload", errInvalidRPCApplicationError)
		}
	}
	var envelope rpcv1.RpcEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return rpcv1.RpcEnvelope{}, err
	}
	envelope.TypeId = typeID
	envelope.RequestId = requestID
	envelope.ResponseTo = responseTo
	return envelope, nil
}

func parseNonzeroUint32(name string, raw json.RawMessage) (uint32, error) {
	value := bytes.TrimSpace(raw)
	if len(value) == 0 {
		return 0, fmt.Errorf("%w: missing %s", errInvalidRPCApplicationError, name)
	}
	for _, b := range value {
		if b < '0' || b > '9' {
			return 0, fmt.Errorf("%w: invalid %s", errInvalidRPCApplicationError, name)
		}
	}
	parsed, err := strconv.ParseUint(string(value), 10, 32)
	if err != nil || parsed == 0 {
		return 0, fmt.Errorf("%w: invalid %s", errInvalidRPCApplicationError, name)
	}
	return uint32(parsed), nil
}

func validWireRPCError(rpcError *rpcv1.RpcError) bool {
	return rpcError != nil && rpcError.Code != 0 &&
		(rpcError.Message == nil || len(*rpcError.Message) <= maxRPCErrorMessageBytes && utf8.ValidString(*rpcError.Message))
}

func sanitizeWireRPCError(rpcError *rpcv1.RpcError) *rpcv1.RpcError {
	if rpcError == nil || validWireRPCError(rpcError) {
		return rpcError
	}
	message := "internal error"
	return &rpcv1.RpcError{Code: 500, Message: &message}
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
	c.notifyCancel()
	_ = err
}

func (c *Client) Close() error {
	c.closeAll(io.ErrClosedPipe)
	return c.r.Close()
}

func strPtr(s string) *string { return &s }

func (c *Client) closedErr() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.lastErr != nil {
		return c.lastErr
	}
	return io.ErrClosedPipe
}
