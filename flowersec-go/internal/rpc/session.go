package rpc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/floegence/flowersec/flowersec-go/v7/internal/defaults"
	"github.com/floegence/flowersec/flowersec-go/v7/internal/framing/jsonframe"
	rpcv1 "github.com/floegence/flowersec/flowersec-go/v7/internal/rpcwire"
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
	FrameLimits            FrameLimits
	MaxConcurrentRequests  int
	MaxQueuedRequests      int
	MaxQueuedNotifications int
}

// FrameLimits bounds the encoded JSON envelope, excluding its four-byte prefix.
// Each zero value selects the 1 MiB default for that direction.
type FrameLimits struct {
	ReadBytes, WriteBytes int
}

func (l FrameLimits) Valid() bool {
	return uint64(l.ReadBytes) <= math.MaxUint32 && uint64(l.WriteBytes) <= math.MaxUint32
}

func (l FrameLimits) normalized() (FrameLimits, error) {
	if !l.Valid() {
		return FrameLimits{}, errors.New("rpc frame limit outside uint32 range")
	}
	if l.ReadBytes == 0 {
		l.ReadBytes = jsonframe.DefaultMaxJSONFrameBytes
	}
	if l.WriteBytes == 0 {
		l.WriteBytes = jsonframe.DefaultMaxJSONFrameBytes
	}
	return l, nil
}

// Handler processes an RPC request and returns payload or an RPC error.
type Handler func(ctx context.Context, payload json.RawMessage) (json.RawMessage, *rpcv1.RpcError)

type receivedEnvelope struct {
	rpcv1.RpcEnvelope
	received time.Time
}

type InboundHandler func(ctx context.Context, typeID uint32, notification bool, received time.Time, payload json.RawMessage) (json.RawMessage, *rpcv1.RpcError)

// Router dispatches RPC requests by type ID.
type Router struct {
	mu                  sync.RWMutex               // Guards handler registrations.
	lookup              func(uint32, bool) Handler // Immutable deployment methods, shared by sessions.
	inbound             InboundHandler
	handlers            map[uint32]Handler // Handlers keyed by type ID.
	notify              map[uint32]map[*routerNotification]struct{}
	notificationsClosed bool
}

type routerNotification struct {
	fn func(context.Context, json.RawMessage)
}

// NewRouter constructs an empty router.
func NewRouter() *Router {
	return &Router{}
}

func NewRouterWithLookup(lookup func(uint32, bool) Handler) *Router {
	return &Router{lookup: lookup}
}

func NewInboundRouter(handler InboundHandler) *Router {
	return &Router{inbound: handler}
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
	if r.notify == nil {
		r.notify = make(map[uint32]map[*routerNotification]struct{})
	}
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

func (r *Router) dispatchNotification(ctx context.Context, env receivedEnvelope) {
	typeID, payload := env.TypeId, env.Payload
	_, _ = r.handle(ctx, env, append(json.RawMessage(nil), payload...))
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
	if r.handlers == nil {
		r.handlers = make(map[uint32]Handler)
	}
	r.handlers[typeID] = h
}

func (r *Router) handle(ctx context.Context, env receivedEnvelope, payload json.RawMessage) (out json.RawMessage, rpcErr *rpcv1.RpcError) {
	defer func() {
		if recover() != nil {
			out = nil
			rpcErr = &rpcv1.RpcError{Code: 500, Message: strPtr("internal error")}
		}
	}()
	if r.inbound != nil {
		return r.inbound(ctx, env.TypeId, env.RequestId == 0, env.received, payload)
	}
	typeID := env.TypeId
	r.mu.RLock()
	h := r.handlers[typeID]
	if h == nil && r.lookup != nil {
		h = r.lookup(typeID, env.RequestId == 0)
	}
	r.mu.RUnlock()
	if h == nil {
		return nil, &rpcv1.RpcError{Code: 404, Message: strPtr("handler not found")}
	}
	return h(ctx, payload)
}

// Server reads RPC envelopes and dispatches them through a Router.
type Server struct {
	r       io.ReadWriteCloser // Underlying stream for framed JSON.
	router  *Router            // Handler registry for incoming requests.
	maxLen  int                // Max frame size for jsonframe.ReadJSONFrame.
	writeMu sync.Mutex         // Serializes writes on the stream.
	limitMu sync.RWMutex       // Protects the legacy read-limit setter.
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
	limits, err := options.FrameLimits.normalized()
	if err != nil {
		return nil, err
	}
	options.FrameLimits = limits
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
		maxLen:  limits.ReadBytes,
		options: options,
	}, nil
}

// SetMaxFrameBytes caps incoming JSON frames.
//
// Passing n==0 resets the cap to the library default (1 MiB). The RPC layer does not
// support disabling the size guard via this method to avoid memory DoS footguns.
func (s *Server) SetMaxFrameBytes(n int) error {
	limits, err := (FrameLimits{ReadBytes: n}).normalized()
	if err != nil {
		return err
	}
	s.limitMu.Lock()
	s.maxLen = limits.ReadBytes
	s.limitMu.Unlock()
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
	body, err := jsonframe.Encode(env, s.options.FrameLimits.WriteBytes)
	if err != nil {
		return err
	}
	return s.writeEncoded(body)
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
	var workers sync.WaitGroup
	workers.Add(1)
	stopContextClose := context.AfterFunc(ctx, func() {
		defer workers.Done()
		_ = s.r.Close()
	})
	workerCtx, cancelWorkers := context.WithCancel(ctx)
	requestScheduler := newRequestScheduler(
		workerCtx,
		s.options.MaxConcurrentRequests,
		s.options.MaxQueuedRequests,
		s.handleRequest,
	)
	var notifications chan *receivedEnvelope
	defer func() {
		cancelWorkers()
		requestScheduler.Close()
		if stopContextClose() {
			workers.Done()
		}
		workers.Wait()
	}()
	invalidJSONFrames := 0
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		s.limitMu.RLock()
		maxLen := s.maxLen
		s.limitMu.RUnlock()
		b, err := jsonframe.ReadJSONFrame(s.r, maxLen)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		var received time.Time
		if s.router.inbound != nil {
			received = time.Now()
		}
		decoded, err := decodeEnvelope(b)
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
		env := receivedEnvelope{decoded, received}
		if env.ResponseTo != 0 {
			_ = s.r.Close()
			return errors.New("rpc invalid response on server stream")
		}
		if env.RequestId == 0 {
			// Notification: response_to=0 and request_id=0.
			if notifications == nil {
				notifications = make(chan *receivedEnvelope, s.options.MaxQueuedNotifications)
				workers.Go(func() { s.serveNotifications(workerCtx, notifications) })
			}
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

func (s *Server) serveNotifications(ctx context.Context, notifications <-chan *receivedEnvelope) {
	for {
		select {
		case <-ctx.Done():
			return
		case env := <-notifications:
			if ctx.Err() != nil {
				return
			}
			finished := make(chan struct{})
			go func() {
				defer close(finished)
				s.router.dispatchNotification(ctx, *env)
			}()
			select {
			case <-finished:
			case <-ctx.Done():
				return
			}
		}
	}
}

func (s *Server) handleRequest(ctx context.Context, env receivedEnvelope) {
	respPayload, rpcErr := s.router.handle(ctx, env, env.Payload)
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
	defer s.writeMu.Unlock()
	body, err := jsonframe.Encode(resp, s.options.FrameLimits.WriteBytes)
	if errors.Is(err, jsonframe.ErrFrameTooLarge) {
		// The handler has run, but no response bytes have been sent yet.
		resp.Payload = nil
		resp.Error = &rpcv1.RpcError{Code: 413, Message: strPtr("encoded RPC response exceeds write limit")}
		body, err = jsonframe.Encode(resp, s.options.FrameLimits.WriteBytes)
	}
	if err != nil {
		_ = s.r.Close()
		return
	}
	_ = s.writeEncoded(body)
}

func (s *Server) writeEncoded(body []byte) error {
	err := jsonframe.WriteEncoded(s.r, body)
	if err != nil {
		_ = s.r.Close()
	}
	return err
}

type pendingCall struct {
	typeID uint32
	reply  chan rpcv1.RpcEnvelope
}

// Client issues RPC calls and receives notifications.
type Client struct {
	r        io.ReadWriteCloser // Underlying stream for framed JSON.
	maxLen   int                // Max frame size for jsonframe.ReadJSONFrame.
	maxWrite int

	writePermit chan struct{} // Serializes writes with cancellable admission.
	workers     sync.WaitGroup

	mu           sync.Mutex                             // Guards pending/notify state.
	nextID       uint64                                 // Next request ID to allocate.
	pending      map[uint64]pendingCall                 // Pending responses keyed by request ID.
	notify       map[uint32]map[*notifyHandler]struct{} // Notification handlers by type ID.
	closed       bool                                   // Closed flag for read/write paths.
	lastErr      error                                  // Sticky error from read loop.
	notifyCtx    context.Context
	notifyCancel context.CancelFunc
}

// NewClient creates an RPC client and starts its read loop.
func NewClient(rwc io.ReadWriteCloser) *Client {
	c, _ := NewClientWithLimits(rwc, FrameLimits{})
	return c
}

func NewClientWithLimits(rwc io.ReadWriteCloser, limits FrameLimits) (*Client, error) {
	limits, err := limits.normalized()
	if err != nil {
		return nil, err
	}
	notifyCtx, notifyCancel := context.WithCancel(context.Background())
	c := &Client{
		r:           rwc,
		maxLen:      limits.ReadBytes,
		maxWrite:    limits.WriteBytes,
		nextID:      1,
		pending:     make(map[uint64]pendingCall),
		writePermit: make(chan struct{}, 1),
		notify:      make(map[uint32]map[*notifyHandler]struct{}),
		notifyCtx:   notifyCtx, notifyCancel: notifyCancel,
	}
	c.workers.Go(c.readLoop)
	return c, nil
}

// Wait joins the reader, notification dispatch and canceled writes after the
// owner has stopped admitting calls and shut down the stream.
func (c *Client) Wait() { c.workers.Wait() }

func (c *Client) notificationLoop(notifications <-chan rpcv1.RpcEnvelope) {
	for {
		select {
		case <-c.notifyCtx.Done():
			return
		case env := <-notifications:
			c.mu.Lock()
			handlers := make([]*notifyHandler, 0, len(c.notify[env.TypeId]))
			for h := range c.notify[env.TypeId] {
				handlers = append(handlers, h)
			}
			c.mu.Unlock()
			for _, h := range handlers {
				payload := append(json.RawMessage(nil), env.Payload...)
				c.workers.Go(func() {
					// User callbacks must not be able to crash the transport.
					defer func() { _ = recover() }()
					h.fn(payload)
				})
			}
		}
	}
}

// SetMaxFrameBytes caps incoming JSON frames.
//
// Passing n==0 resets the cap to the library default (1 MiB). The RPC layer does not
// support disabling the size guard via this method to avoid memory DoS footguns.
func (c *Client) SetMaxFrameBytes(n int) error {
	limits, err := (FrameLimits{ReadBytes: n}).normalized()
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.maxLen = limits.ReadBytes
	c.mu.Unlock()
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
	body, err := jsonframe.Encode(env, c.maxWrite)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// A canceled write may have committed a partial frame. Retire the stream
	// before another caller can append bytes to that uncertain boundary.
	c.workers.Add(1)
	stop := context.AfterFunc(ctx, func() {
		defer c.workers.Done()
		c.closeAll(ctx.Err())
		_ = c.r.Close()
	})
	err = jsonframe.WriteEncoded(c.r, body)
	if !stop() {
		c.closeAll(ctx.Err())
		return ctx.Err()
	}
	c.workers.Done()
	if err != nil {
		c.closeAll(err)
		_ = c.r.Close()
		return err
	}
	return ctx.Err()
}

// Call sends an RPC request and waits for its response or context cancellation.
func (c *Client) Call(ctx context.Context, typeID uint32, payload json.RawMessage) (json.RawMessage, *rpcv1.RpcError, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	reqID, ch, err := c.reserve(typeID)
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

func (c *Client) reserve(typeID uint32) (uint64, chan rpcv1.RpcEnvelope, error) {
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
	c.pending[id] = pendingCall{typeID: typeID, reply: ch}
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
	var notifications chan rpcv1.RpcEnvelope
	for {
		c.mu.Lock()
		maxLen := c.maxLen
		c.mu.Unlock()
		b, err := jsonframe.ReadJSONFrame(c.r, maxLen)
		if err != nil {
			c.closeAll(err)
			if errors.Is(err, jsonframe.ErrFrameTooLarge) {
				_ = c.r.Close()
			}
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
				if notifications == nil {
					notifications = make(chan rpcv1.RpcEnvelope, defaultMaxQueuedNotifications)
					c.workers.Go(func() { c.notificationLoop(notifications) })
				}
				select {
				case notifications <- env:
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
		if err := c.deliverResponse(env); err != nil {
			c.closeAll(err)
			_ = c.r.Close()
			return
		}
	}
}

func (c *Client) deliverResponse(env rpcv1.RpcEnvelope) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	call, ok := c.pending[env.ResponseTo]
	if !ok { // Canceled or already completed.
		return nil
	}
	if call.typeID != env.TypeId {
		return errors.New("rpc response method mismatch")
	}
	delete(c.pending, env.ResponseTo)
	call.reply <- env
	return nil
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
	envelope := rpcv1.RpcEnvelope{Payload: fields["payload"]}
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
	for id, call := range c.pending {
		delete(c.pending, id)
		close(call.reply)
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
