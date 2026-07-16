package ws

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
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

func TestReadMessageHonorsContextCancelWithoutDeadline(t *testing.T) {
	srv := newWSServer(t)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	c, _, err := Dial(ctx, "ws"+srv.URL[4:], DialOptions{})
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer c.Close()

	readCtx, readCancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		_, _, err := c.ReadMessage(readCtx)
		errCh <- err
	}()

	// Ensure the goroutine is blocked inside ReadMessage before canceling.
	time.Sleep(10 * time.Millisecond)
	readCancel()

	select {
	case err := <-errCh:
		if err == nil || !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled, got %v", err)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatalf("ReadMessage did not return after context cancellation")
	}
}

func TestWriteMessageSerializesConcurrentWriters(t *testing.T) {
	srv := newWSServer(t)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	c, _, err := Dial(ctx, "ws"+srv.URL[4:], DialOptions{})
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer c.Close()

	payload := make([]byte, 256*1024)
	const writers = 16
	errCh := make(chan error, writers)
	var wg sync.WaitGroup
	for range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errCh <- c.WriteMessage(ctx, websocket.BinaryMessage, payload)
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatalf("WriteMessage failed: %v", err)
		}
	}
}

func TestWriteMessageCancellationClosesBlockedConnection(t *testing.T) {
	releaseServer := make(chan struct{})
	upgraded := make(chan struct{})
	up := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		close(upgraded)
		<-releaseServer
		_ = conn.Close()
	}))
	defer srv.Close()
	defer close(releaseServer)

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer dialCancel()
	c, _, err := Dial(dialCtx, "ws"+srv.URL[4:], DialOptions{})
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer c.Close()
	<-upgraded

	writeCtx, writeCancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- c.WriteMessage(writeCtx, websocket.BinaryMessage, make([]byte, 16*1024*1024))
	}()
	time.Sleep(20 * time.Millisecond)
	writeCancel()

	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("WriteMessage did not return after context cancellation")
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
