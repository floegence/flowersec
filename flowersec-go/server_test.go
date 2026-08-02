package flowersec

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	internalrpc "github.com/floegence/flowersec/flowersec-go/v2/internal/rpc"
)

func TestSessionHandlersDispatchAcceptedStreamMetadata(t *testing.T) {
	stream := &serverTestStream{Reader: bytes.NewReader([]byte("request"))}
	session := &serverTestSession{incoming: make(chan IncomingStream, 1), closed: make(chan struct{})}
	metadata, err := NewStreamMetadata(map[string]any{"request_id": "req-1"})
	if err != nil {
		t.Fatal(err)
	}
	session.incoming <- IncomingStream{
		Kind:     "files/read",
		Metadata: metadata,
		Stream:   stream,
	}

	handled := make(chan Metadata, 1)
	handlers, err := NewSessionHandlers(SessionHandlerOptions{MaxConcurrentStreams: 2})
	if err != nil {
		t.Fatalf("NewSessionHandlers() error = %v", err)
	}
	if err := handlers.HandleStream("files/read", func(_ context.Context, incoming IncomingStream) {
		handled <- incoming.Metadata
	}); err != nil {
		t.Fatalf("HandleStream() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- handlers.Serve(ctx, session) }()

	select {
	case metadata := <-handled:
		if metadata.Values()["request_id"] != "req-1" {
			t.Fatalf("request_id = %#v, want req-1", metadata.Values()["request_id"])
		}
	case <-time.After(time.Second):
		t.Fatal("stream handler was not called")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Serve() error = %v, want context cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Serve() did not stop")
	}
	if !stream.closed {
		t.Fatal("accepted stream was not closed after the handler returned")
	}
}

func TestSessionHandlersServeRegisteredRPC(t *testing.T) {
	handlers, err := NewSessionHandlers(SessionHandlerOptions{})
	if err != nil {
		t.Fatalf("NewSessionHandlers() error = %v", err)
	}
	if err := handlers.HandleRPC(41, func(_ context.Context, request json.RawMessage) (any, *RPCError) {
		var input struct {
			Value string `json:"value"`
		}
		if err := json.Unmarshal(request, &input); err != nil {
			return nil, &RPCError{Code: 400, Message: "invalid request"}
		}
		return struct {
			Value string `json:"value"`
		}{Value: input.Value + "-ok"}, nil
	}); err != nil {
		t.Fatalf("HandleRPC() error = %v", err)
	}
	if err := handlers.HandleRPC(42, func(context.Context, json.RawMessage) (any, *RPCError) {
		return strings.Repeat("x", (1<<20)+1), nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := handlers.HandleRPC(43, func(context.Context, json.RawMessage) (any, *RPCError) {
		return nil, &RPCError{Message: "missing application code"}
	}); err != nil {
		t.Fatal(err)
	}

	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()
	server := internalrpc.NewServer(serverConn, handlers.rpcRouter())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = server.Serve(ctx) }()
	client := internalrpc.NewClient(clientConn)
	defer client.Close()

	payload, rpcErr, err := client.Call(ctx, 41, json.RawMessage(`{"value":"input"}`))
	if err != nil {
		t.Fatalf("Call() error = %v", err)
	}
	if rpcErr != nil {
		t.Fatalf("Call() RPC error = %#v", rpcErr)
	}
	if string(payload) != `{"value":"input-ok"}` {
		t.Fatalf("Call() payload = %s", payload)
	}
	for _, typeID := range []uint32{42, 43} {
		payload, rpcErr, err := client.Call(ctx, typeID, json.RawMessage(`{}`))
		if err != nil {
			t.Fatalf("Call(%d) error = %v", typeID, err)
		}
		if string(payload) != "null" || rpcErr == nil || rpcErr.Code != 500 || rpcErr.Message == nil || *rpcErr.Message != "handler failed" {
			t.Fatalf("Call(%d) = payload %d bytes, error %#v", typeID, len(payload), rpcErr)
		}
	}
}

func TestSessionHandlersRejectInvalidAndDuplicateRegistrations(t *testing.T) {
	if _, err := NewSessionHandlers(SessionHandlerOptions{MaxConcurrentStreams: maxConcurrentStreams + 1}); !errors.Is(err, ErrInvalidSessionHandlers) {
		t.Fatalf("NewSessionHandlers() error = %v, want ErrInvalidSessionHandlers", err)
	}
	handlers, err := NewSessionHandlers(SessionHandlerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	streamHandler := func(context.Context, IncomingStream) {}
	if err := handlers.HandleStream("files/read", streamHandler); err != nil {
		t.Fatal(err)
	}
	if err := handlers.HandleStream("files/read", streamHandler); !errors.Is(err, ErrHandlerAlreadyExists) {
		t.Fatalf("duplicate HandleStream() error = %v", err)
	}
	rpcHandler := func(context.Context, json.RawMessage) (any, *RPCError) { return nil, nil }
	if err := handlers.HandleRPC(7, rpcHandler); err != nil {
		t.Fatal(err)
	}
	if err := handlers.HandleRPC(7, rpcHandler); !errors.Is(err, ErrHandlerAlreadyExists) {
		t.Fatalf("duplicate HandleRPC() error = %v", err)
	}
	if err := handlers.HandleRPC(0, rpcHandler); !errors.Is(err, ErrInvalidSessionHandlers) {
		t.Fatalf("zero HandleRPC() error = %v", err)
	}
}

func TestSessionHandlersFreezeRPCAndStreamRegistrationsTogether(t *testing.T) {
	handlers, err := NewSessionHandlers(SessionHandlerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	handlers.freeze()
	if err := handlers.HandleStream("late", func(context.Context, IncomingStream) {}); !errors.Is(err, ErrSessionHandlersFrozen) {
		t.Fatalf("late HandleStream() error = %v, want ErrSessionHandlersFrozen", err)
	}
	if err := handlers.HandleRPC(9, func(context.Context, json.RawMessage) (any, *RPCError) { return nil, nil }); !errors.Is(err, ErrSessionHandlersFrozen) {
		t.Fatalf("late HandleRPC() error = %v, want ErrSessionHandlersFrozen", err)
	}
}

func TestSessionHandlersResetStreamWhenConcurrencyIsExhausted(t *testing.T) {
	first := &serverTestStream{Reader: bytes.NewReader(nil)}
	second := &serverTestStream{Reader: bytes.NewReader(nil)}
	session := &serverTestSession{incoming: make(chan IncomingStream, 2), closed: make(chan struct{})}
	started := make(chan struct{})
	release := make(chan struct{})
	errorsCh := make(chan error, 1)
	handlers, err := NewSessionHandlers(SessionHandlerOptions{
		MaxConcurrentStreams: 1,
		OnError:              func(err error) { errorsCh <- err },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := handlers.HandleStream("held", func(context.Context, IncomingStream) {
		close(started)
		<-release
	}); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- handlers.Serve(ctx, session) }()
	session.incoming <- IncomingStream{Kind: "held", Metadata: EmptyStreamMetadata(), Stream: first}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("first stream handler did not start")
	}
	session.incoming <- IncomingStream{Kind: "held", Metadata: EmptyStreamMetadata(), Stream: second}
	select {
	case err := <-errorsCh:
		var sessionErr *SessionError
		if !errors.As(err, &sessionErr) || sessionErr.Code() != SessionResourceExhausted {
			t.Fatalf("OnError() = %v, want resource exhausted", err)
		}
	case <-time.After(time.Second):
		t.Fatal("overload was not reported")
	}
	if !second.reset || !second.closed {
		t.Fatalf("excess stream reset=%v closed=%v", second.reset, second.closed)
	}
	close(release)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Serve() did not stop")
	}
}

type serverTestSession struct {
	incoming chan IncomingStream
	closed   chan struct{}
}

func (*serverTestSession) RPC() RPCPeer { return nil }
func (*serverTestSession) UnreliableMessages() (UnreliableMessageChannel, error) {
	return nil, errors.New("unavailable")
}
func (*serverTestSession) OpenStream(context.Context, string, Metadata) (ByteStream, error) {
	return nil, errors.New("unavailable")
}
func (session *serverTestSession) AcceptStream(ctx context.Context) (IncomingStream, error) {
	select {
	case incoming := <-session.incoming:
		return incoming, nil
	case <-ctx.Done():
		return IncomingStream{}, ctx.Err()
	case <-session.closed:
		return IncomingStream{}, &SessionError{code: SessionClosed}
	}
}
func (*serverTestSession) Rekey(context.Context) error                          { return nil }
func (*serverTestSession) ProbeLiveness(context.Context) (time.Duration, error) { return 0, nil }
func (session *serverTestSession) Termination() <-chan struct{}                 { return session.closed }
func (session *serverTestSession) WaitTermination(ctx context.Context) (SessionTermination, error) {
	err := session.WaitClosed(ctx)
	if err != nil {
		return SessionTermination{}, err
	}
	return SessionTermination{Error: &SessionError{code: SessionClosed}}, nil
}
func (session *serverTestSession) WaitClosed(ctx context.Context) error {
	select {
	case <-session.closed:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (session *serverTestSession) Close() error {
	select {
	case <-session.closed:
	default:
		close(session.closed)
	}
	return nil
}

type serverTestStream struct {
	*bytes.Reader
	closed bool
	reset  bool
}

func (stream *serverTestStream) Write(payload []byte) (int, error) { return len(payload), nil }
func (stream *serverTestStream) Close() error                      { stream.closed = true; return nil }
func (*serverTestStream) Kind() string                             { return "files/read" }
func (*serverTestStream) TerminalError() *SessionError             { return nil }
func (*serverTestStream) CloseWrite() error                        { return nil }
func (stream *serverTestStream) Reset() error                      { stream.reset = true; return nil }

func ExampleSessionHandlers() {
	handlers, _ := NewSessionHandlers(SessionHandlerOptions{})
	_ = handlers.HandleRPC(100, func(context.Context, json.RawMessage) (any, *RPCError) {
		return struct {
			Ready bool `json:"ready"`
		}{Ready: true}, nil
	})
	_ = handlers.HandleStream("events", func(context.Context, IncomingStream) {})
	fmt.Println(handlers)
	// Output: Flowersec.SessionHandlers
}
