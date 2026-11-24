package flowersec

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"unicode/utf8"

	internalrpc "github.com/floegence/flowersec/flowersec-go/v7/internal/rpc"
	rpcwire "github.com/floegence/flowersec/flowersec-go/v7/internal/rpcwire"
)

const (
	defaultConcurrentStreams = 64
	maxConcurrentStreams     = 128
	maxRPCErrorMessageBytes  = 1024
)

var (
	ErrInvalidHandlerRegistration = errors.New("invalid Flowersec handler registration")
	ErrHandlerAlreadyExists       = errors.New("Flowersec handler already exists")
	ErrHandlerRegistryFrozen      = errors.New("Flowersec handler registry is frozen")
)

// RPCHandler processes one bounded JSON RPC payload. Returning RPCError sends
// an application-level rejection without exposing transport or session state.
type RPCHandler func(context.Context, json.RawMessage) (any, *RPCError)

// RPCNotificationHandler processes one-way peer notifications. An error is
// isolated to that notification and does not terminate the session.
type RPCNotificationHandler func(context.Context, json.RawMessage) error

type rpcHandlerRegistry struct {
	mu       sync.RWMutex
	methods  map[uint32]registeredRPCHandler
	snapshot *rpcHandlerSnapshot
}

type registeredRPCHandler struct {
	handler      internalrpc.Handler
	notification bool
}

type rpcHandlerSnapshot struct {
	lookup func(uint32, bool) internalrpc.Handler
}

func newRPCHandlerRegistry() *rpcHandlerRegistry {
	return &rpcHandlerRegistry{methods: make(map[uint32]registeredRPCHandler)}
}

func (registry *rpcHandlerRegistry) valid() bool {
	return registry != nil && registry.methods != nil
}

func (registry *rpcHandlerRegistry) handleRPC(typeID uint32, handler RPCHandler) error {
	if !registry.valid() || typeID == 0 || handler == nil {
		return ErrInvalidHandlerRegistration
	}
	return registry.register(typeID, false, func(ctx context.Context, request json.RawMessage) (json.RawMessage, *rpcwire.RpcError) {
		response, rpcErr := handler(ctx, append(json.RawMessage(nil), request...))
		if rpcErr != nil {
			return nil, validRPCWireError(rpcErr)
		}
		payload, err := json.Marshal(response)
		if err != nil {
			return nil, internalRPCError()
		}
		return payload, nil
	})
}

func (registry *rpcHandlerRegistry) handleNotification(typeID uint32, handler RPCNotificationHandler) error {
	if !registry.valid() || typeID == 0 || handler == nil {
		return ErrInvalidHandlerRegistration
	}
	return registry.register(typeID, true, func(ctx context.Context, request json.RawMessage) (json.RawMessage, *rpcwire.RpcError) {
		if err := handler(ctx, append(json.RawMessage(nil), request...)); err != nil {
			return nil, internalRPCError()
		}
		return nil, nil
	})
}

func (registry *rpcHandlerRegistry) register(typeID uint32, notification bool, handler internalrpc.Handler) error {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if registry.snapshot != nil {
		return ErrHandlerRegistryFrozen
	}
	if _, exists := registry.methods[typeID]; exists {
		return ErrHandlerAlreadyExists
	}
	registry.methods[typeID] = registeredRPCHandler{handler: handler, notification: notification}
	return nil
}

func (registry *rpcHandlerRegistry) freeze() *rpcHandlerSnapshot {
	if !registry.valid() {
		return nil
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if registry.snapshot != nil {
		return registry.snapshot
	}
	methods := registry.methods
	registry.snapshot = &rpcHandlerSnapshot{lookup: func(id uint32, notification bool) internalrpc.Handler {
		entry := methods[id]
		if entry.notification && !notification {
			return nil
		}
		return entry.handler
	}}
	return registry.snapshot
}

// RPCHandlers is a reusable inbound RPC and notification definition for
// endpoint client sessions. It has no application-stream serving capability.
type RPCHandlers struct {
	registry *rpcHandlerRegistry
}

// NewRPCHandlers creates an empty client RPC handler definition.
func NewRPCHandlers() *RPCHandlers {
	return &RPCHandlers{registry: newRPCHandlerRegistry()}
}

// HandleRPC registers one nonzero inbound RPC type ID.
func (handlers *RPCHandlers) HandleRPC(typeID uint32, handler RPCHandler) error {
	if handlers == nil {
		return ErrInvalidHandlerRegistration
	}
	return handlers.registry.handleRPC(typeID, handler)
}

// HandleNotification registers one nonzero inbound notification type ID.
func (handlers *RPCHandlers) HandleNotification(typeID uint32, handler RPCNotificationHandler) error {
	if handlers == nil {
		return ErrInvalidHandlerRegistration
	}
	return handlers.registry.handleNotification(typeID, handler)
}

func (handlers *RPCHandlers) valid() bool {
	return handlers != nil && handlers.registry.valid()
}

func (handlers *RPCHandlers) freeze() *rpcHandlerSnapshot {
	if !handlers.valid() {
		return nil
	}
	return handlers.registry.freeze()
}

// String deliberately reveals no handler registration state.
func (*RPCHandlers) String() string { return "Flowersec.RPCHandlers" }

// GoString deliberately reveals no handler registration state.
func (*RPCHandlers) GoString() string { return "flowersec.RPCHandlers" }

// MarshalJSON prevents generic serialization from exposing registrations.
func (*RPCHandlers) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

// SessionHandlerOptions bounds accepted-session stream dispatch and exposes
// only sanitized asynchronous failures.
type SessionHandlerOptions struct {
	MaxConcurrentStreams int
	OnError              func(error)
}

type sessionHandlerSnapshot struct {
	rpc     *rpcHandlerSnapshot
	streams *streamHandlerSnapshot
}

// SessionHandlers defines RPC, notification, and application-stream handlers
// for accepted server sessions.
type SessionHandlers struct {
	rpc      *rpcHandlerRegistry
	streams  *StreamHandlers
	mu       sync.Mutex
	snapshot *sessionHandlerSnapshot
}

// String deliberately reveals no handler registration state.
func (*SessionHandlers) String() string { return "Flowersec.SessionHandlers" }

// GoString deliberately reveals no handler registration state.
func (*SessionHandlers) GoString() string { return "flowersec.SessionHandlers" }

// MarshalJSON prevents generic serialization from exposing registrations.
func (*SessionHandlers) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

// NewSessionHandlers creates an empty accepted-session handler definition.
func NewSessionHandlers(options SessionHandlerOptions) (*SessionHandlers, error) {
	streams, err := NewStreamHandlers(StreamHandlerOptions{
		MaxConcurrentStreams: options.MaxConcurrentStreams,
		OnError:              options.OnError,
	})
	if err != nil {
		return nil, ErrInvalidHandlerRegistration
	}
	return &SessionHandlers{
		rpc:     newRPCHandlerRegistry(),
		streams: streams,
	}, nil
}

func (handlers *SessionHandlers) valid() bool {
	return handlers != nil && handlers.rpc.valid() && handlers.streams.valid()
}

// HandleRPC registers one nonzero inbound RPC type ID.
func (handlers *SessionHandlers) HandleRPC(typeID uint32, handler RPCHandler) error {
	if handlers == nil {
		return ErrInvalidHandlerRegistration
	}
	return handlers.rpc.handleRPC(typeID, handler)
}

// HandleNotification registers one nonzero inbound notification type ID.
func (handlers *SessionHandlers) HandleNotification(typeID uint32, handler RPCNotificationHandler) error {
	if handlers == nil {
		return ErrInvalidHandlerRegistration
	}
	return handlers.rpc.handleNotification(typeID, handler)
}

// HandleStream registers one application stream kind for accepted sessions.
func (handlers *SessionHandlers) HandleStream(kind string, handler StreamHandler) error {
	if !handlers.valid() {
		return ErrInvalidHandlerRegistration
	}
	return handlers.streams.HandleStream(kind, handler)
}

func (handlers *SessionHandlers) registerStreams(registrations map[string]StreamHandler) error {
	if !handlers.valid() {
		return ErrInvalidHandlerRegistration
	}
	return handlers.streams.registerStreams(registrations)
}

func (handlers *SessionHandlers) freeze() *sessionHandlerSnapshot {
	if !handlers.valid() {
		return nil
	}
	handlers.mu.Lock()
	defer handlers.mu.Unlock()
	if handlers.snapshot != nil {
		return handlers.snapshot
	}
	handlers.snapshot = &sessionHandlerSnapshot{
		rpc: handlers.rpc.freeze(), streams: handlers.streams.freeze(),
	}
	return handlers.snapshot
}

func newRPCRouter(snapshot *rpcHandlerSnapshot) *internalrpc.Router {
	if snapshot == nil {
		return internalrpc.NewRouter()
	}
	return internalrpc.NewRouterWithLookup(snapshot.lookup)
}

func (handlers *SessionHandlers) rpcRouter() *internalrpc.Router {
	snapshot := handlers.freeze()
	if snapshot == nil {
		return internalrpc.NewRouter()
	}
	return newRPCRouter(snapshot.rpc)
}

func (handlers *SessionHandlers) routerForAcceptedSession() *internalrpc.Router {
	return handlers.rpcRouter()
}

var (
	_ json.Marshaler = (*RPCHandlers)(nil)
	_ json.Marshaler = (*SessionHandlers)(nil)
)

func validRPCWireError(rpcErr *RPCError) *rpcwire.RpcError {
	if rpcErr == nil || rpcErr.Code == 0 || len(rpcErr.Message) > maxRPCErrorMessageBytes || !utf8.ValidString(rpcErr.Message) {
		return internalRPCError()
	}
	if rpcErr.Message == "" && !rpcErr.MessagePresent {
		return &rpcwire.RpcError{Code: rpcErr.Code}
	}
	message := rpcErr.Message
	return &rpcwire.RpcError{Code: rpcErr.Code, Message: &message}
}

func internalRPCError() *rpcwire.RpcError {
	message := "internal error"
	return &rpcwire.RpcError{Code: 500, Message: &message}
}

// Serve accepts and dispatches application streams until the context ends or
// the session closes. It owns only this accepted Session's serving lifecycle.
func (handlers *SessionHandlers) Serve(ctx context.Context, current Session) error {
	snapshot := handlers.freeze()
	if snapshot == nil || snapshot.streams == nil || current == nil {
		return ErrInvalidHandlerRegistration
	}
	return serveStreamSnapshot(ctx, current, snapshot.streams)
}
