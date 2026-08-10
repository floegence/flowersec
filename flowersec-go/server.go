package flowersec

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"unicode/utf8"

	internaljsonframe "github.com/floegence/flowersec/flowersec-go/v2/internal/framing/jsonframe"
	internalrpc "github.com/floegence/flowersec/flowersec-go/v2/internal/rpc"
	rpcwire "github.com/floegence/flowersec/flowersec-go/v2/internal/rpcwire"
)

const (
	defaultConcurrentStreams = 64
	maxConcurrentStreams     = 128
	maxRPCErrorMessageBytes  = 1024
)

var (
	ErrInvalidSessionHandlers = errors.New("invalid Flowersec session handlers")
	ErrHandlerAlreadyExists   = errors.New("Flowersec session handler already exists")
	ErrSessionHandlersFrozen  = errors.New("Flowersec session handlers are frozen")
)

// StreamHandler processes one accepted application stream. A non-nil error
// resets that stream; the framework closes the stream after every return.
type StreamHandler func(context.Context, IncomingStream) error

// RPCHandler processes one bounded JSON RPC payload. Returning RPCError sends
// an application-level rejection without exposing transport or session state.
type RPCHandler func(context.Context, json.RawMessage) (any, *RPCError)

// RPCNotificationHandler processes one-way peer notifications. An error is
// isolated to that notification and does not terminate the session.
type RPCNotificationHandler func(context.Context, json.RawMessage) error

// SessionHandlerOptions bounds application stream dispatch and exposes only
// sanitized asynchronous failures.
type SessionHandlerOptions struct {
	MaxConcurrentStreams int
	OnError              func(error)
}

// SessionHandlers owns the inbound application stream and RPC registrations
// used by a carrier-neutral Flowersec session.
type SessionHandlers struct {
	maxConcurrent int
	onError       func(error)

	mu                   sync.RWMutex
	frozen               bool
	streamHandlers       map[string]StreamHandler
	rpcHandlers          map[uint32]RPCHandler
	notificationHandlers map[uint32]RPCNotificationHandler
}

// String deliberately reveals no handler registration state.
func (*SessionHandlers) String() string { return "Flowersec.SessionHandlers" }

// GoString deliberately reveals no handler registration state.
func (*SessionHandlers) GoString() string { return "flowersec.SessionHandlers" }

// MarshalJSON prevents generic serialization from exposing registrations.
func (*SessionHandlers) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

// NewSessionHandlers creates an empty, bounded handler registry.
func NewSessionHandlers(options SessionHandlerOptions) (*SessionHandlers, error) {
	concurrent := options.MaxConcurrentStreams
	if concurrent == 0 {
		concurrent = defaultConcurrentStreams
	}
	if concurrent < 1 || concurrent > maxConcurrentStreams {
		return nil, ErrInvalidSessionHandlers
	}
	return &SessionHandlers{
		maxConcurrent:        concurrent,
		onError:              options.OnError,
		streamHandlers:       make(map[string]StreamHandler),
		rpcHandlers:          make(map[uint32]RPCHandler),
		notificationHandlers: make(map[uint32]RPCNotificationHandler),
	}, nil
}

func (handlers *SessionHandlers) valid() bool {
	return handlers != nil && handlers.maxConcurrent >= 1 && handlers.maxConcurrent <= maxConcurrentStreams &&
		handlers.streamHandlers != nil && handlers.rpcHandlers != nil && handlers.notificationHandlers != nil
}

// HandleStream registers one application stream kind. Registrations are
// immutable by name so an accidental duplicate cannot replace live policy.
func (handlers *SessionHandlers) HandleStream(kind string, handler StreamHandler) error {
	if handlers == nil || !validStreamHandler(kind, handler) {
		return ErrInvalidSessionHandlers
	}
	handlers.mu.Lock()
	defer handlers.mu.Unlock()
	if handlers.frozen {
		return ErrSessionHandlersFrozen
	}
	if _, exists := handlers.streamHandlers[kind]; exists {
		return ErrHandlerAlreadyExists
	}
	handlers.streamHandlers[kind] = handler
	return nil
}

func (handlers *SessionHandlers) handleStreams(registrations map[string]StreamHandler) error {
	if handlers == nil || len(registrations) == 0 {
		return ErrInvalidSessionHandlers
	}
	handlers.mu.Lock()
	defer handlers.mu.Unlock()
	if handlers.frozen {
		return ErrSessionHandlersFrozen
	}
	for kind, handler := range registrations {
		if !validStreamHandler(kind, handler) {
			return ErrInvalidSessionHandlers
		}
		if _, exists := handlers.streamHandlers[kind]; exists {
			return ErrHandlerAlreadyExists
		}
	}
	for kind, handler := range registrations {
		handlers.streamHandlers[kind] = handler
	}
	return nil
}

func validStreamHandler(kind string, handler StreamHandler) bool {
	return handler != nil && utf8.ValidString(kind) && len(kind) >= 1 && len(kind) <= 255 && kind != "flowersec.rpc.v2"
}

// HandleRPC registers one nonzero RPC type ID. Connector snapshots these
// registrations before session establishment.
func (handlers *SessionHandlers) HandleRPC(typeID uint32, handler RPCHandler) error {
	if handlers == nil || typeID == 0 || handler == nil {
		return ErrInvalidSessionHandlers
	}
	handlers.mu.Lock()
	defer handlers.mu.Unlock()
	if handlers.frozen {
		return ErrSessionHandlersFrozen
	}
	if _, exists := handlers.rpcHandlers[typeID]; exists {
		return ErrHandlerAlreadyExists
	}
	if _, exists := handlers.notificationHandlers[typeID]; exists {
		return ErrHandlerAlreadyExists
	}
	handlers.rpcHandlers[typeID] = handler
	return nil
}

// HandleNotification registers one-way inbound notification handling. The
// type-ID namespace is shared with request handlers to keep routing explicit.
func (handlers *SessionHandlers) HandleNotification(typeID uint32, handler RPCNotificationHandler) error {
	if handlers == nil || typeID == 0 || handler == nil {
		return ErrInvalidSessionHandlers
	}
	handlers.mu.Lock()
	defer handlers.mu.Unlock()
	if handlers.frozen {
		return ErrSessionHandlersFrozen
	}
	if _, exists := handlers.rpcHandlers[typeID]; exists {
		return ErrHandlerAlreadyExists
	}
	if _, exists := handlers.notificationHandlers[typeID]; exists {
		return ErrHandlerAlreadyExists
	}
	handlers.notificationHandlers[typeID] = handler
	return nil
}

func (handlers *SessionHandlers) freeze() {
	if handlers == nil {
		return
	}
	handlers.mu.Lock()
	handlers.frozen = true
	handlers.mu.Unlock()
}

func (handlers *SessionHandlers) rpcRouter() *internalrpc.Router {
	router := internalrpc.NewRouter()
	if handlers == nil {
		return router
	}
	handlers.mu.RLock()
	registrations := make(map[uint32]RPCHandler, len(handlers.rpcHandlers))
	notifications := make(map[uint32]RPCNotificationHandler, len(handlers.notificationHandlers))
	for typeID, handler := range handlers.rpcHandlers {
		registrations[typeID] = handler
	}
	for typeID, handler := range handlers.notificationHandlers {
		notifications[typeID] = handler
	}
	handlers.mu.RUnlock()
	for typeID, handler := range registrations {
		handler := handler
		router.Register(typeID, func(ctx context.Context, request json.RawMessage) (json.RawMessage, *rpcwire.RpcError) {
			response, rpcErr := handler(ctx, append(json.RawMessage(nil), request...))
			if rpcErr != nil {
				return nil, validRPCWireError(rpcErr)
			}
			payload, err := json.Marshal(response)
			if err != nil || len(payload) > internaljsonframe.DefaultMaxJSONFrameBytes {
				return nil, internalRPCError()
			}
			return payload, nil
		})
	}
	for typeID, handler := range notifications {
		handler := handler
		router.Register(typeID, func(ctx context.Context, request json.RawMessage) (json.RawMessage, *rpcwire.RpcError) {
			if err := handler(ctx, append(json.RawMessage(nil), request...)); err != nil {
				return nil, internalRPCError()
			}
			return nil, nil
		})
	}
	return router
}

// routerForAcceptedSession snapshots the same immutable registrations used by
// Connect. It is intentionally package-private: Acceptor is the only owner of
// carrier admission and may inject the snapshot before a server Session is
// established.
func (handlers *SessionHandlers) routerForAcceptedSession() *internalrpc.Router {
	if handlers == nil {
		return internalrpc.NewRouter()
	}
	handlers.freeze()
	return handlers.rpcRouter()
}

var _ json.Marshaler = (*SessionHandlers)(nil)

func validRPCWireError(rpcErr *RPCError) *rpcwire.RpcError {
	if rpcErr == nil || rpcErr.Code == 0 || len(rpcErr.Message) > maxRPCErrorMessageBytes || !utf8.ValidString(rpcErr.Message) {
		return internalRPCError()
	}
	message := rpcErr.Message
	return &rpcwire.RpcError{Code: rpcErr.Code, Message: &message}
}

func internalRPCError() *rpcwire.RpcError {
	message := "handler failed"
	return &rpcwire.RpcError{Code: 500, Message: &message}
}

// Serve accepts and dispatches application streams until the context ends or
// the session closes. It owns the session lifecycle and waits for active
// handlers before returning.
func (handlers *SessionHandlers) Serve(ctx context.Context, current Session) error {
	if handlers == nil || current == nil || handlers.maxConcurrent < 1 {
		return ErrInvalidSessionHandlers
	}
	if ctx == nil {
		ctx = context.Background()
	}
	serveCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stopClose := context.AfterFunc(serveCtx, func() { _ = current.Close() })
	defer stopClose()
	semaphore := make(chan struct{}, handlers.maxConcurrent)
	var active sync.WaitGroup
	defer active.Wait()
	for {
		incoming, err := current.AcceptStream(serveCtx)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		if incoming.Stream == nil {
			handlers.reportError(&SessionError{code: SessionOperationFailed})
			continue
		}
		handler := handlers.streamHandler(incoming.Kind)
		if handler == nil {
			rejectIncoming(incoming)
			handlers.reportError(&SessionError{code: SessionStreamRejected})
			continue
		}
		select {
		case semaphore <- struct{}{}:
			active.Add(1)
			go func() {
				defer active.Done()
				defer func() { <-semaphore }()
				defer func() {
					if recover() != nil {
						_ = incoming.Stream.Reset()
						_ = incoming.Stream.Close()
						handlers.reportError(&SessionError{code: SessionOperationFailed})
					}
				}()
				if err := handler(serveCtx, incoming); err != nil {
					_ = incoming.Stream.Reset()
					_ = incoming.Stream.Close()
					return
				}
				if err := incoming.Stream.CloseWrite(); err != nil {
					handlers.reportError(err)
				}
			}()
		default:
			rejectIncoming(incoming)
			handlers.reportError(&SessionError{code: SessionResourceExhausted})
		}
	}
}

func (handlers *SessionHandlers) streamHandler(kind string) StreamHandler {
	handlers.mu.RLock()
	handler := handlers.streamHandlers[kind]
	handlers.mu.RUnlock()
	return handler
}

func rejectIncoming(incoming IncomingStream) {
	if incoming.Stream == nil {
		return
	}
	_ = incoming.Stream.Reset()
	_ = incoming.Stream.Close()
}

func (handlers *SessionHandlers) reportError(err error) {
	if handlers == nil || handlers.onError == nil || err == nil {
		return
	}
	defer func() { _ = recover() }()
	handlers.onError(err)
}
