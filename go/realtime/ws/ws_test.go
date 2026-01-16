package ws

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func newWSServer(t *testing.T) *httptest.Server {
	t.Helper()
	up := websocket.Upgrader{}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		// Keep the connection open until the client closes.
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				_ = conn.Close()
				return
			}
		}
	}))
}

func TestDialContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := Dial(ctx, "ws://example.invalid", DialOptions{}); err == nil {
		t.Fatalf("expected dial to fail on canceled context")
	}
}

func TestReadMessageHonorsContextDeadline(t *testing.T) {
	srv := newWSServer(t)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	c, _, err := Dial(ctx, "ws"+srv.URL[4:], DialOptions{})
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer c.Close()

	readCtx, readCancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer readCancel()

	_, _, err = c.ReadMessage(readCtx)
	if err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline exceeded, got %v", err)
	}
}

func TestCloseWithStatus(t *testing.T) {
	srv := newWSServer(t)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	c, _, err := Dial(ctx, "ws"+srv.URL[4:], DialOptions{})
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	if err := c.CloseWithStatus(websocket.CloseNormalClosure, "bye"); err != nil {
		t.Fatalf("CloseWithStatus failed: %v", err)
	}
}
