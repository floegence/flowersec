package e2ee

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func newBinaryTransportWSServer(t *testing.T) *httptest.Server {
	t.Helper()
	up := websocket.Upgrader{}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		// Keep the connection open until the client closes.
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}))
}

func TestWebSocketBinaryTransportReadBinaryHonorsContextCancelWithoutDeadline(t *testing.T) {
	srv := newBinaryTransportWSServer(t)
	defer srv.Close()

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer dialCancel()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	c, _, err := websocket.DefaultDialer.DialContext(dialCtx, wsURL, nil)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	transport := NewWebSocketBinaryTransport(c)

	readCtx, readCancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		_, err := transport.ReadBinary(readCtx)
		errCh <- err
	}()

	time.Sleep(10 * time.Millisecond)
	readCancel()

	select {
	case err := <-errCh:
		if err == nil || !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled, got %v", err)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatalf("ReadBinary did not return after context cancellation")
	}
}
