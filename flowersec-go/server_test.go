package flowersec

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	internalrpc "github.com/floegence/flowersec/flowersec-go/v5/internal/rpc"
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

	handled := make(chan StreamMetadata, 1)
	handlers, err := NewSessionHandlers(SessionHandlerOptions{MaxConcurrentStreams: 2})
	if err != nil {
		t.Fatalf("NewSessionHandlers() error = %v", err)
	}
	if err := handlers.HandleStream("files/read", func(_ context.Context, incoming IncomingStream) error {
		handled <- incoming.Metadata
		return nil
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
	closed, writeClosed, _ := stream.state()
	if !writeClosed || closed {
		t.Fatalf("accepted stream writeClosed=%v closed=%v, want true/false", writeClosed, closed)
	}
}

func TestStreamHandlersDispatchEstablishedConnectorSession(t *testing.T) {
	stream := &serverTestStream{Reader: bytes.NewReader([]byte("request"))}
	session := &serverTestSession{incoming: make(chan IncomingStream, 1), closed: make(chan struct{})}
	session.incoming <- IncomingStream{Kind: "files/read", Metadata: EmptyStreamMetadata(), Stream: stream}

	handled := make(chan struct{}, 1)
	handlers, err := NewStreamHandlers(StreamHandlerOptions{MaxConcurrentStreams: 2})
	if err != nil {
		t.Fatalf("NewStreamHandlers() error = %v", err)
	}
	if err := handlers.HandleStream("files/read", func(context.Context, IncomingStream) error {
		handled <- struct{}{}
		return nil
	}); err != nil {
		t.Fatalf("HandleStream() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- handlers.Serve(ctx, session) }()
	select {
	case <-handled:
	case <-time.After(time.Second):
		t.Fatal("stream handler was not called")
	}
	if err := handlers.HandleStream("late", func(context.Context, IncomingStream) error { return nil }); !errors.Is(err, ErrHandlerRegistryFrozen) {
		t.Fatalf("late HandleStream() error = %v, want ErrHandlerRegistryFrozen", err)
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
	_, writeClosed, reset := stream.state()
	if !writeClosed || reset {
		t.Fatalf("stream writeClosed=%v reset=%v, want true/false", writeClosed, reset)
	}
}

func TestStreamHandlersIsolateUnknownFailurePanicAndCloseWriteFailure(t *testing.T) {
	unknown := &serverTestStream{Reader: bytes.NewReader(nil)}
	failed := &serverTestStream{Reader: bytes.NewReader(nil)}
	panicked := &serverTestStream{Reader: bytes.NewReader(nil)}
	closeFailed := &serverTestStream{Reader: bytes.NewReader(nil), closeWriteErr: errors.New("close write failed")}
	succeeded := &serverTestStream{Reader: bytes.NewReader(nil)}
	session := &serverTestSession{incoming: make(chan IncomingStream, 5), closed: make(chan struct{})}
	errorsCh := make(chan error, 4)
	handlers, err := NewStreamHandlers(StreamHandlerOptions{
		MaxConcurrentStreams: 5,
		OnError:              func(err error) { errorsCh <- err },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := handlers.HandleStream("failed", func(context.Context, IncomingStream) error {
		return errors.New("handler failed")
	}); err != nil {
		t.Fatal(err)
	}
	if err := handlers.HandleStream("panicked", func(context.Context, IncomingStream) error {
		panic("handler panic")
	}); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"close-failed", "succeeded"} {
		if err := handlers.HandleStream(kind, func(context.Context, IncomingStream) error { return nil }); err != nil {
			t.Fatal(err)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- handlers.Serve(ctx, session) }()
	for _, incoming := range []IncomingStream{
		{Kind: "unknown", Metadata: EmptyStreamMetadata(), Stream: unknown},
		{Kind: "failed", Metadata: EmptyStreamMetadata(), Stream: failed},
		{Kind: "panicked", Metadata: EmptyStreamMetadata(), Stream: panicked},
		{Kind: "close-failed", Metadata: EmptyStreamMetadata(), Stream: closeFailed},
		{Kind: "succeeded", Metadata: EmptyStreamMetadata(), Stream: succeeded},
	} {
		session.incoming <- incoming
	}

	for received := 0; received < 4; received++ {
		select {
		case reported := <-errorsCh:
			var sessionErr *SessionError
			if !errors.As(reported, &sessionErr) {
				t.Fatalf("OnError() = %v, want sanitized SessionError", reported)
			}
		case <-time.After(time.Second):
			t.Fatal("stream failure was not reported")
		}
	}
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); {
		_, succeededWriteClosed, _ := succeeded.state()
		unknownClosed, _, unknownReset := unknown.state()
		failedClosed, _, failedReset := failed.state()
		panickedClosed, _, panickedReset := panicked.state()
		closeFailedClosed, _, closeFailedReset := closeFailed.state()
		if succeededWriteClosed && unknownClosed && unknownReset && failedClosed && failedReset &&
			panickedClosed && panickedReset && closeFailedClosed && closeFailedReset {
			break
		}
		time.Sleep(time.Millisecond)
	}
	_, succeededWriteClosed, succeededReset := succeeded.state()
	if !succeededWriteClosed || succeededReset {
		t.Fatalf("successful stream writeClosed=%v reset=%v, want true/false", succeededWriteClosed, succeededReset)
	}
	for name, stream := range map[string]*serverTestStream{
		"unknown": unknown, "failed": failed, "panicked": panicked, "close-failed": closeFailed,
	} {
		closed, _, reset := stream.state()
		if !closed || !reset {
			t.Fatalf("%s stream closed=%v reset=%v, want true/true", name, closed, reset)
		}
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
	validASCII := strings.Repeat("a", 1_024)
	validMultibyte := strings.Repeat("é", 512)
	wireErrorCases := []struct {
		name        string
		handlerErr  *RPCError
		wantCode    uint32
		wantMessage string
	}{
		{name: "zero code", handlerErr: &RPCError{Message: "missing application code"}, wantCode: 500, wantMessage: "handler failed"},
		{name: "empty message", handlerErr: &RPCError{Code: 7}, wantCode: 7, wantMessage: ""},
		{name: "ASCII at limit", handlerErr: &RPCError{Code: 7, Message: validASCII}, wantCode: 7, wantMessage: validASCII},
		{name: "ASCII over limit", handlerErr: &RPCError{Code: 7, Message: validASCII + "a"}, wantCode: 500, wantMessage: "handler failed"},
		{name: "multibyte at limit", handlerErr: &RPCError{Code: 7, Message: validMultibyte}, wantCode: 7, wantMessage: validMultibyte},
		{name: "multibyte over limit", handlerErr: &RPCError{Code: 7, Message: validMultibyte + "a"}, wantCode: 500, wantMessage: "handler failed"},
		{name: "invalid UTF-8", handlerErr: &RPCError{Code: 7, Message: string([]byte{0xff})}, wantCode: 500, wantMessage: "handler failed"},
	}
	for index, test := range wireErrorCases {
		typeID := uint32(43 + index)
		handlerErr := test.handlerErr
		if err := handlers.HandleRPC(typeID, func(context.Context, json.RawMessage) (any, *RPCError) {
			return nil, handlerErr
		}); err != nil {
			t.Fatalf("HandleRPC(%s) error = %v", test.name, err)
		}
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
	payload, rpcErr, err = client.Call(ctx, 42, json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("Call(42) error = %v", err)
	}
	if string(payload) != "null" || rpcErr == nil || rpcErr.Code != 500 || rpcErr.Message == nil || *rpcErr.Message != "handler failed" {
		t.Fatalf("Call(42) = payload %d bytes, error %#v", len(payload), rpcErr)
	}
	for index, test := range wireErrorCases {
		typeID := uint32(43 + index)
		payload, rpcErr, err := client.Call(ctx, typeID, json.RawMessage(`{}`))
		if err != nil {
			t.Fatalf("Call(%s) error = %v", test.name, err)
		}
		if string(payload) != "null" || rpcErr == nil || rpcErr.Code != test.wantCode || rpcErr.Message == nil || *rpcErr.Message != test.wantMessage {
			t.Fatalf("Call(%s) = payload %d bytes, error %#v", test.name, len(payload), rpcErr)
		}
	}
}

func TestPublicRPCPeerAndSessionHandlersExposeNotifications(t *testing.T) {
	var peer RPCPeer = &opaqueRPCPeerV3{}
	unsubscribe := peer.OnNotify(41, func(context.Context, json.RawMessage) {})
	if unsubscribe == nil {
		t.Fatal("OnNotify() returned nil unsubscribe function")
	}
	handlers, err := NewSessionHandlers(SessionHandlerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := handlers.HandleNotification(41, func(context.Context, json.RawMessage) error { return nil }); err != nil {
		t.Fatalf("HandleNotification() error = %v", err)
	}
}

func TestSessionHandlersNotificationRegistrationIsBoundedAndFrozen(t *testing.T) {
	handlers, err := NewSessionHandlers(SessionHandlerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	handler := func(context.Context, json.RawMessage) error { return errors.New("application notification failure") }
	if err := handlers.HandleNotification(42, handler); err != nil {
		t.Fatalf("HandleNotification() error = %v", err)
	}
	if err := handlers.HandleNotification(42, handler); !errors.Is(err, ErrHandlerAlreadyExists) {
		t.Fatalf("duplicate HandleNotification() error = %v", err)
	}
	if err := handlers.HandleRPC(42, func(context.Context, json.RawMessage) (any, *RPCError) { return nil, nil }); !errors.Is(err, ErrHandlerAlreadyExists) {
		t.Fatalf("notification/RPC collision error = %v", err)
	}
	handlers.freeze()
	if err := handlers.HandleNotification(43, handler); !errors.Is(err, ErrHandlerRegistryFrozen) {
		t.Fatalf("late HandleNotification() error = %v", err)
	}
}

func TestSessionHandlersRejectInvalidAndDuplicateRegistrations(t *testing.T) {
	if _, err := NewSessionHandlers(SessionHandlerOptions{MaxConcurrentStreams: maxConcurrentStreams + 1}); !errors.Is(err, ErrInvalidHandlerRegistration) {
		t.Fatalf("NewSessionHandlers() error = %v, want ErrInvalidHandlerRegistration", err)
	}
	handlers, err := NewSessionHandlers(SessionHandlerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	streamHandler := func(context.Context, IncomingStream) error { return nil }
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
	if err := handlers.HandleRPC(0, rpcHandler); !errors.Is(err, ErrInvalidHandlerRegistration) {
		t.Fatalf("zero HandleRPC() error = %v", err)
	}
}

func TestSessionHandlersEnforceSharedStreamKindContract(t *testing.T) {
	var vectors struct {
		StreamKinds []struct {
			ID     string `json:"id"`
			Unit   string `json:"unit"`
			Repeat int    `json:"repeat"`
			Suffix string `json:"suffix"`
			Valid  bool   `json:"valid"`
		} `json:"stream_kinds"`
		DuplicateKind string `json:"duplicate_kind"`
		RPCTypeIDs    []struct {
			ID    string `json:"id"`
			Value uint32 `json:"value"`
			Valid bool   `json:"valid"`
		} `json:"rpc_type_ids"`
		DuplicateTypeID uint32 `json:"duplicate_type_id"`
	}
	payload, err := os.ReadFile("../testdata/transport_v3/session_handler_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(payload, &vectors); err != nil {
		t.Fatal(err)
	}
	streamHandler := func(context.Context, IncomingStream) error { return nil }
	for _, vector := range vectors.StreamKinds {
		t.Run(vector.ID, func(t *testing.T) {
			handlers, err := NewSessionHandlers(SessionHandlerOptions{})
			if err != nil {
				t.Fatal(err)
			}
			kind := strings.Repeat(vector.Unit, vector.Repeat) + vector.Suffix
			err = handlers.HandleStream(kind, streamHandler)
			if vector.Valid && err != nil {
				t.Fatalf("HandleStream(%q) error = %v", vector.ID, err)
			}
			if !vector.Valid && !errors.Is(err, ErrInvalidHandlerRegistration) {
				t.Fatalf("HandleStream(%q) error = %v, want ErrInvalidHandlerRegistration", vector.ID, err)
			}
		})
	}
	invalidUTF8 := string([]byte{0xff})
	handlers, err := NewSessionHandlers(SessionHandlerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := handlers.HandleStream(invalidUTF8, streamHandler); !errors.Is(err, ErrInvalidHandlerRegistration) {
		t.Fatalf("invalid UTF-8 HandleStream() error = %v, want ErrInvalidHandlerRegistration", err)
	}
	handlers, err = NewSessionHandlers(SessionHandlerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := handlers.HandleStream(vectors.DuplicateKind, streamHandler); err != nil {
		t.Fatal(err)
	}
	if err := handlers.HandleStream(vectors.DuplicateKind, streamHandler); !errors.Is(err, ErrHandlerAlreadyExists) {
		t.Fatalf("duplicate HandleStream() error = %v, want ErrHandlerAlreadyExists", err)
	}
	for _, vector := range vectors.RPCTypeIDs {
		rpcHandlers := NewRPCHandlers()
		err := rpcHandlers.HandleRPC(vector.Value, func(context.Context, json.RawMessage) (any, *RPCError) { return nil, nil })
		if (err == nil) != vector.Valid {
			t.Fatalf("RPC type ID vector %s error = %v, valid = %t", vector.ID, err, vector.Valid)
		}
	}
	rpcHandlers := NewRPCHandlers()
	if err := rpcHandlers.HandleRPC(vectors.DuplicateTypeID, func(context.Context, json.RawMessage) (any, *RPCError) { return nil, nil }); err != nil {
		t.Fatal(err)
	}
	if err := rpcHandlers.HandleNotification(vectors.DuplicateTypeID, func(context.Context, json.RawMessage) error { return nil }); !errors.Is(err, ErrHandlerAlreadyExists) {
		t.Fatalf("fixture cross-role duplicate error = %v", err)
	}
}

func TestSessionHandlersFreezeRPCAndStreamRegistrationsTogether(t *testing.T) {
	handlers, err := NewSessionHandlers(SessionHandlerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	handlers.freeze()
	if err := handlers.HandleStream("late", func(context.Context, IncomingStream) error { return nil }); !errors.Is(err, ErrHandlerRegistryFrozen) {
		t.Fatalf("late HandleStream() error = %v, want ErrHandlerRegistryFrozen", err)
	}
	if err := handlers.HandleRPC(9, func(context.Context, json.RawMessage) (any, *RPCError) { return nil, nil }); !errors.Is(err, ErrHandlerRegistryFrozen) {
		t.Fatalf("late HandleRPC() error = %v, want ErrHandlerRegistryFrozen", err)
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
	if err := handlers.HandleStream("held", func(context.Context, IncomingStream) error {
		close(started)
		<-release
		return nil
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
	closed, _, reset := second.state()
	if !reset || !closed {
		t.Fatalf("excess stream reset=%v closed=%v", reset, closed)
	}
	close(release)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Serve() did not stop")
	}
}

func TestSessionHandlersResetOnlyFailedStreamAndContinueServing(t *testing.T) {
	failed := &serverTestStream{Reader: bytes.NewReader(nil)}
	succeeded := &serverTestStream{Reader: bytes.NewReader(nil)}
	session := &serverTestSession{incoming: make(chan IncomingStream, 2), closed: make(chan struct{})}
	secondHandled := make(chan struct{})
	var calls int
	var callsMu sync.Mutex
	handlers, err := NewSessionHandlers(SessionHandlerOptions{MaxConcurrentStreams: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := handlers.HandleStream("work", func(context.Context, IncomingStream) error {
		callsMu.Lock()
		calls++
		call := calls
		callsMu.Unlock()
		if call == 1 {
			return errors.New("application handler failed")
		}
		close(secondHandled)
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- handlers.Serve(ctx, session) }()
	session.incoming <- IncomingStream{Kind: "work", Metadata: EmptyStreamMetadata(), Stream: failed}
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); {
		closed, _, _ := failed.state()
		if closed {
			break
		}
		time.Sleep(time.Millisecond)
	}
	failedClosed, _, failedReset := failed.state()
	if !failedReset || !failedClosed {
		t.Fatalf("failed stream reset=%v closed=%v, want both true", failedReset, failedClosed)
	}

	session.incoming <- IncomingStream{Kind: "work", Metadata: EmptyStreamMetadata(), Stream: succeeded}
	select {
	case <-secondHandled:
	case <-time.After(time.Second):
		t.Fatal("accept loop did not continue after handler failure")
	}
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); {
		_, writeClosed, _ := succeeded.state()
		if writeClosed {
			break
		}
		time.Sleep(time.Millisecond)
	}
	succeededClosed, succeededWriteClosed, succeededReset := succeeded.state()
	if succeededReset || succeededClosed || !succeededWriteClosed {
		t.Fatalf("successful stream reset=%v closed=%v writeClosed=%v, want false/false/true", succeededReset, succeededClosed, succeededWriteClosed)
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
}

func TestSessionHandlersCancellationClosesSessionBeforeWaitingForBlockedHandlers(t *testing.T) {
	previous := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(previous)

	stream := newBlockingServerStream()
	session := &serverTestSession{incoming: make(chan IncomingStream, 1), closed: make(chan struct{}), closeStream: stream}
	handlers, err := NewSessionHandlers(SessionHandlerOptions{MaxConcurrentStreams: 1})
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	if err := handlers.HandleStream("blocking", func(_ context.Context, incoming IncomingStream) error {
		close(started)
		_, readErr := incoming.Stream.Read(make([]byte, 1))
		return readErr
	}); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- handlers.Serve(ctx, session) }()
	session.incoming <- IncomingStream{Kind: "blocking", Metadata: EmptyStreamMetadata(), Stream: stream}
	<-started
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Serve() error = %v, want context cancellation", err)
		}
	case <-time.After(250 * time.Millisecond):
		_ = session.Close()
		<-done
		t.Fatal("Serve() waited for a blocked handler before closing its Session")
	}
}

func TestSessionHandlersServeWaitsForSessionCloseCompletion(t *testing.T) {
	closeStarted := make(chan struct{})
	closeRelease := make(chan struct{})
	session := &serverTestSession{
		incoming:     make(chan IncomingStream),
		closed:       make(chan struct{}),
		closeStarted: closeStarted,
		closeRelease: closeRelease,
	}
	handlers, err := NewSessionHandlers(SessionHandlerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- handlers.Serve(ctx, session) }()
	cancel()
	select {
	case <-closeStarted:
	case <-time.After(time.Second):
		t.Fatal("Session.Close was not started")
	}
	select {
	case err := <-done:
		close(closeRelease)
		t.Fatalf("Serve() returned before Session.Close completed: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	close(closeRelease)
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Serve() error = %v, want context cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Serve() did not return after Session.Close completed")
	}
}

type serverTestSession struct {
	incoming     chan IncomingStream
	closed       chan struct{}
	closeStream  ByteStream
	closeStarted chan struct{}
	closeRelease chan struct{}
	closeOnce    sync.Once
}

func (*serverTestSession) RPC() RPCPeer { return nil }
func (*serverTestSession) UnreliableMessages() (UnreliableMessageChannel, error) {
	return nil, errors.New("unavailable")
}
func (*serverTestSession) OpenStream(context.Context, string, StreamMetadata) (ByteStream, error) {
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
	return SessionTermination{Error: SessionError{code: SessionClosed}}, nil
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
	session.closeOnce.Do(func() {
		close(session.closed)
		if session.closeStream != nil {
			_ = session.closeStream.Reset()
		}
		if session.closeStarted != nil {
			close(session.closeStarted)
		}
		if session.closeRelease != nil {
			<-session.closeRelease
		}
	})
	return nil
}

type blockingServerStream struct {
	closed chan struct{}
	once   sync.Once
}

func newBlockingServerStream() *blockingServerStream {
	return &blockingServerStream{closed: make(chan struct{})}
}

func (stream *blockingServerStream) Read([]byte) (int, error) {
	<-stream.closed
	return 0, &SessionError{code: SessionStreamReset}
}
func (*blockingServerStream) Write(payload []byte) (int, error) { return len(payload), nil }
func (*blockingServerStream) CloseWrite() error                 { return nil }
func (stream *blockingServerStream) Close() error               { return stream.Reset() }
func (stream *blockingServerStream) Reset() error {
	stream.once.Do(func() { close(stream.closed) })
	return nil
}
func (*blockingServerStream) Kind() string                 { return "blocking" }
func (*blockingServerStream) TerminalError() *SessionError { return nil }

type serverTestStream struct {
	*bytes.Reader
	mu            sync.Mutex
	closed        bool
	writeClosed   bool
	reset         bool
	closeWriteErr error
}

func (stream *serverTestStream) Write(payload []byte) (int, error) { return len(payload), nil }
func (stream *serverTestStream) Close() error {
	stream.mu.Lock()
	stream.closed = true
	stream.mu.Unlock()
	return nil
}
func (*serverTestStream) Kind() string                 { return "files/read" }
func (*serverTestStream) TerminalError() *SessionError { return nil }
func (stream *serverTestStream) CloseWrite() error {
	stream.mu.Lock()
	stream.writeClosed = true
	err := stream.closeWriteErr
	stream.mu.Unlock()
	return err
}
func (stream *serverTestStream) Reset() error {
	stream.mu.Lock()
	stream.reset = true
	stream.mu.Unlock()
	return nil
}
func (stream *serverTestStream) state() (closed, writeClosed, reset bool) {
	stream.mu.Lock()
	defer stream.mu.Unlock()
	return stream.closed, stream.writeClosed, stream.reset
}

func ExampleSessionHandlers() {
	handlers, _ := NewSessionHandlers(SessionHandlerOptions{})
	_ = handlers.HandleRPC(100, func(context.Context, json.RawMessage) (any, *RPCError) {
		return struct {
			Ready bool `json:"ready"`
		}{Ready: true}, nil
	})
	_ = handlers.HandleStream("events", func(context.Context, IncomingStream) error { return nil })
	fmt.Println(handlers)
	// Output: Flowersec.SessionHandlers
}

func ExampleStreamHandlers() {
	handlers, _ := NewStreamHandlers(StreamHandlerOptions{})
	_ = handlers.HandleStream("events", func(context.Context, IncomingStream) error { return nil })
	fmt.Println(handlers)
	// Output: Flowersec.StreamHandlers
}
