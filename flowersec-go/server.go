package flowersec

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"unicode/utf8"

	internaljsonframe "github.com/floegence/flowersec/flowersec-go/v5/internal/framing/jsonframe"
	internalrpc "github.com/floegence/flowersec/flowersec-go/v5/internal/rpc"
	rpcwire "github.com/floegence/flowersec/flowersec-go/v5/internal/rpcwire"
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
	mu            sync.RWMutex
	frozen        bool
	requests      map[uint32]RPCHandler
	notifications map[uint32]RPCNotificationHandler
	snapshot      *rpcHandlerSnapshot
}

type rpcHandlerSnapshot struct {
	requests      map[uint32]RPCHandler
	notifications map[uint32]RPCNotificationHandler
}

func newRPCHandlerRegistry() *rpcHandlerRegistry {
	return &rpcHandlerRegistry{
		requests:      make(map[uint32]RPCHandler),
		notifications: make(map[uint32]RPCNotificationHandler),
	}
}

func (registry *rpcHandlerRegistry) valid() bool {
	return registry != nil && registry.requests != nil && registry.notifications != nil
}

func (registry *rpcHandlerRegistry) handleRPC(typeID uint32, handler RPCHandler) error {
	if !registry.valid() || typeID == 0 || handler == nil {
		return ErrInvalidHandlerRegistration
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if registry.frozen {
		return ErrHandlerRegistryFrozen
	}
	if _, exists := registry.requests[typeID]; exists {
		return ErrHandlerAlreadyExists
	}
	if _, exists := registry.notifications[typeID]; exists {
		return ErrHandlerAlreadyExists
	}
	registry.requests[typeID] = handler
	return nil
}

func (registry *rpcHandlerRegistry) handleNotification(typeID uint32, handler RPCNotificationHandler) error {
	if !registry.valid() || typeID == 0 || handler == nil {
		return ErrInvalidHandlerRegistration
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if registry.frozen {
		return ErrHandlerRegistryFrozen
	}
	if _, exists := registry.requests[typeID]; exists {
		return ErrHandlerAlreadyExists
	}
	if _, exists := registry.notifications[typeID]; exists {
		return ErrHandlerAlreadyExists
	}
	registry.notifications[typeID] = handler
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
	requests := make(map[uint32]RPCHandler, len(registry.requests))
	notifications := make(map[uint32]RPCNotificationHandler, len(registry.notifications))
	for typeID, handler := range registry.requests {
		requests[typeID] = handler
	}
	for typeID, handler := range registry.notifications {
		notifications[typeID] = handler
	}
	registry.frozen = true
	registry.snapshot = &rpcHandlerSnapshot{requests: requests, notifications: notifications}
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
	router := internalrpc.NewRouter()
	if snapshot == nil {
		return router
	}
	for typeID, handler := range snapshot.requests {
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
	for typeID, handler := range snapshot.notifications {
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
	message := rpcErr.Message
	return &rpcwire.RpcError{Code: rpcErr.Code, Message: &message}
}

func internalRPCError() *rpcwire.RpcError {
	message := "handler failed"
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
