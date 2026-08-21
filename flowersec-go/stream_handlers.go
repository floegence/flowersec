package flowersec

import (
	"context"
	"encoding/json"
	"sync"

	internalprotocolv2 "github.com/floegence/flowersec/flowersec-go/v3/internal/protocolv2"
)

// StreamHandler processes one accepted application stream. A non-nil error
// resets and closes that stream; success closes its write direction.
type StreamHandler func(context.Context, IncomingStream) error

// StreamHandlerOptions bounds application-stream dispatch and exposes only
// sanitized asynchronous failures.
type StreamHandlerOptions struct {
	MaxConcurrentStreams int
	OnError              func(error)
}

type streamHandlerSnapshot struct {
	streams       map[string]StreamHandler
	maxConcurrent int
	onError       func(error)
}

// StreamHandlerRegistrar is the sealed application-stream registration
// boundary accepted by SDK-owned server applications such as ProxyServer.
// Only Flowersec handler registries implement it.
type StreamHandlerRegistrar interface {
	registerStreams(map[string]StreamHandler) error
}

// StreamHandlers is a carrier-neutral application-stream registry and
// dispatcher for any established Session.
type StreamHandlers struct {
	maxConcurrent int
	onError       func(error)

	mu       sync.RWMutex
	frozen   bool
	streams  map[string]StreamHandler
	snapshot *streamHandlerSnapshot
}

// NewStreamHandlers creates an empty application-stream handler definition.
func NewStreamHandlers(options StreamHandlerOptions) (*StreamHandlers, error) {
	concurrent := options.MaxConcurrentStreams
	if concurrent == 0 {
		concurrent = defaultConcurrentStreams
	}
	if concurrent < 1 || concurrent > maxConcurrentStreams {
		return nil, ErrInvalidHandlerRegistration
	}
	return &StreamHandlers{
		maxConcurrent: concurrent,
		onError:       options.OnError,
		streams:       make(map[string]StreamHandler),
	}, nil
}

func (handlers *StreamHandlers) valid() bool {
	return handlers != nil && handlers.maxConcurrent >= 1 &&
		handlers.maxConcurrent <= maxConcurrentStreams && handlers.streams != nil
}

// HandleStream registers one application stream kind.
func (handlers *StreamHandlers) HandleStream(kind string, handler StreamHandler) error {
	return handlers.registerStreams(map[string]StreamHandler{kind: handler})
}

func (handlers *StreamHandlers) registerStreams(registrations map[string]StreamHandler) error {
	if !handlers.valid() || len(registrations) == 0 {
		return ErrInvalidHandlerRegistration
	}
	handlers.mu.Lock()
	defer handlers.mu.Unlock()
	if handlers.frozen {
		return ErrHandlerRegistryFrozen
	}
	for kind, handler := range registrations {
		if !validStreamHandler(kind, handler) {
			return ErrInvalidHandlerRegistration
		}
		if _, exists := handlers.streams[kind]; exists {
			return ErrHandlerAlreadyExists
		}
	}
	for kind, handler := range registrations {
		handlers.streams[kind] = handler
	}
	return nil
}

func validStreamHandler(kind string, handler StreamHandler) bool {
	return handler != nil && internalprotocolv2.ValidApplicationStreamKind(kind) &&
		kind != "flowersec.rpc.v2" && kind != "flowersec.rpc.v3"
}

func (handlers *StreamHandlers) freeze() *streamHandlerSnapshot {
	if !handlers.valid() {
		return nil
	}
	handlers.mu.Lock()
	defer handlers.mu.Unlock()
	if handlers.snapshot != nil {
		return handlers.snapshot
	}
	streams := make(map[string]StreamHandler, len(handlers.streams))
	for kind, handler := range handlers.streams {
		streams[kind] = handler
	}
	handlers.frozen = true
	handlers.snapshot = &streamHandlerSnapshot{
		streams: streams, maxConcurrent: handlers.maxConcurrent, onError: handlers.onError,
	}
	return handlers.snapshot
}

// Serve accepts and dispatches application streams until the context ends or
// the session closes. It closes the session and waits for active handlers
// before returning.
func (handlers *StreamHandlers) Serve(ctx context.Context, current Session) error {
	snapshot := handlers.freeze()
	if snapshot == nil || current == nil {
		return ErrInvalidHandlerRegistration
	}
	return serveStreamSnapshot(ctx, current, snapshot)
}

func serveStreamSnapshot(ctx context.Context, current Session, snapshot *streamHandlerSnapshot) error {
	if ctx == nil {
		ctx = context.Background()
	}
	serveCtx, cancel := context.WithCancel(ctx)
	semaphore := make(chan struct{}, snapshot.maxConcurrent)
	var active sync.WaitGroup
	defer func() {
		cancel()
		_ = current.Close()
		active.Wait()
	}()
	for {
		incoming, err := current.AcceptStream(serveCtx)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		if incoming.Stream == nil {
			reportHandlerError(snapshot.onError, &SessionError{code: SessionOperationFailed})
			continue
		}
		handler := snapshot.streams[incoming.Kind]
		if handler == nil {
			rejectIncoming(incoming)
			reportHandlerError(snapshot.onError, &SessionError{code: SessionStreamRejected})
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
						reportHandlerError(snapshot.onError, &SessionError{code: SessionOperationFailed})
					}
				}()
				if err := handler(serveCtx, incoming); err != nil {
					_ = incoming.Stream.Reset()
					_ = incoming.Stream.Close()
					reportHandlerError(snapshot.onError, &SessionError{code: SessionOperationFailed})
					return
				}
				if err := incoming.Stream.CloseWrite(); err != nil {
					_ = incoming.Stream.Reset()
					_ = incoming.Stream.Close()
					reportHandlerError(snapshot.onError, &SessionError{code: SessionOperationFailed})
				}
			}()
		default:
			rejectIncoming(incoming)
			reportHandlerError(snapshot.onError, &SessionError{code: SessionResourceExhausted})
		}
	}
}

func rejectIncoming(incoming IncomingStream) {
	if incoming.Stream == nil {
		return
	}
	_ = incoming.Stream.Reset()
	_ = incoming.Stream.Close()
}

func reportHandlerError(onError func(error), err error) {
	if onError == nil || err == nil {
		return
	}
	defer func() { _ = recover() }()
	onError(err)
}

// String deliberately reveals no handler registration state.
func (*StreamHandlers) String() string { return "Flowersec.StreamHandlers" }

// GoString deliberately reveals no handler registration state.
func (*StreamHandlers) GoString() string { return "flowersec.StreamHandlers" }

// MarshalJSON prevents generic serialization from exposing registrations.
func (*StreamHandlers) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

var _ json.Marshaler = (*StreamHandlers)(nil)
