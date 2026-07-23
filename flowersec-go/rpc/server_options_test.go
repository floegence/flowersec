package rpc

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/framing/jsonframe"
	rpcv1 "github.com/floegence/flowersec/flowersec-go/v2/gen/flowersec/rpc/v1"
)

func TestNewServerWithOptionsRejectsInvalidLimits(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	tests := []struct {
		name    string
		stream  io.ReadWriteCloser
		router  *Router
		options ServerOptions
	}{
		{name: "nil stream", router: NewRouter()},
		{name: "nil router", stream: a},
		{name: "negative concurrent requests", stream: a, router: NewRouter(), options: ServerOptions{MaxConcurrentRequests: -1}},
		{name: "negative queued requests", stream: a, router: NewRouter(), options: ServerOptions{MaxQueuedRequests: -1}},
		{name: "negative queued notifications", stream: a, router: NewRouter(), options: ServerOptions{MaxQueuedNotifications: -1}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewServerWithOptions(tt.stream, tt.router, tt.options); err == nil {
				t.Fatal("expected invalid options error")
			}
		})
	}
}

func TestServerClosesStreamWhenNotificationQueueIsFull(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	started := make(chan struct{}, 1)
	release := make(chan struct{})
	router := NewRouter()
	router.Register(1, func(_ context.Context, _ json.RawMessage) (json.RawMessage, *rpcv1.RpcError) {
		select {
		case started <- struct{}{}:
		default:
		}
		<-release
		return nil, nil
	})
	server, err := NewServerWithOptions(a, router, ServerOptions{
		MaxConcurrentRequests:  1,
		MaxQueuedRequests:      1,
		MaxQueuedNotifications: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.Serve(context.Background()) }()

	writeNotification := func() error {
		t.Helper()
		return jsonframe.WriteJSONFrame(b, rpcv1.RpcEnvelope{TypeId: 1})
	}
	if err := writeNotification(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("notification worker did not start")
	}
	if err := writeNotification(); err != nil {
		t.Fatal(err)
	}
	closed := false
	for range 8 {
		if err := writeNotification(); err != nil {
			closed = true
			break
		}
	}
	if !closed {
		t.Fatal("expected the RPC stream to close after notification overflow")
	}

	close(release)
	select {
	case err := <-serveErr:
		if err == nil || !strings.Contains(err.Error(), "notification queue exhausted") {
			t.Fatalf("Serve error = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after notification overflow")
	}
}

func TestServerBoundsConcurrentAndQueuedRequests(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	started := make(chan uint64, 2)
	release := make(chan struct{})
	router := NewRouter()
	router.Register(1, func(_ context.Context, payload json.RawMessage) (json.RawMessage, *rpcv1.RpcError) {
		var input struct {
			ID uint64 `json:"id"`
		}
		_ = json.Unmarshal(payload, &input)
		started <- input.ID
		<-release
		return payload, nil
	})
	server, err := NewServerWithOptions(a, router, ServerOptions{
		MaxConcurrentRequests:  1,
		MaxQueuedRequests:      1,
		MaxQueuedNotifications: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = server.Serve(ctx) }()

	writeRequest := func(id uint64) {
		t.Helper()
		if err := jsonframe.WriteJSONFrame(b, rpcv1.RpcEnvelope{
			TypeId: 1, RequestId: id, Payload: json.RawMessage(`{"id":` + strconv.FormatUint(id, 10) + `}`),
		}); err != nil {
			t.Fatal(err)
		}
	}
	writeRequest(1)
	select {
	case id := <-started:
		if id != 1 {
			t.Fatalf("first started request = %d", id)
		}
	case <-time.After(time.Second):
		t.Fatal("handler did not start")
	}
	writeRequest(2)
	writeRequest(3)
	select {
	case id := <-started:
		t.Fatalf("request %d exceeded concurrency limit", id)
	case <-time.After(50 * time.Millisecond):
	}

	var exhausted rpcv1.RpcEnvelope
	for exhausted.ResponseTo != 3 {
		frame, err := jsonframe.ReadJSONFrame(b, jsonframe.DefaultMaxJSONFrameBytes)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(frame, &exhausted); err != nil {
			t.Fatal(err)
		}
	}
	if exhausted.Error == nil || exhausted.Error.Code != 429 {
		t.Fatalf("expected resource exhausted response, got %+v", exhausted.Error)
	}
	if exhausted.Error.Message == nil || *exhausted.Error.Message != "server overloaded" {
		t.Fatalf("unexpected overload message: %+v", exhausted.Error)
	}
	close(release)
}
