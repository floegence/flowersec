package e2ee

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

type BinaryTransport interface {
	// ReadBinary reads the next binary frame, honoring the context deadline and cancellation.
	ReadBinary(ctx context.Context) ([]byte, error)
	// WriteBinary writes a binary frame, honoring the context deadline and cancellation.
	WriteBinary(ctx context.Context, b []byte) error
	// Close closes the underlying transport.
	Close() error
}

// WebSocketMessageConn is a message-oriented websocket connection that supports context-aware reads/writes.
//
// It matches realtime/ws.Conn and is used to avoid leaking the underlying gorilla/websocket connection
// into higher-level code.
type WebSocketMessageConn interface {
	ReadMessage(ctx context.Context) (messageType int, b []byte, err error)
	WriteMessage(ctx context.Context, messageType int, b []byte) error
	Close() error
}

// WebSocketMessageTransport adapts a context-aware websocket message connection to BinaryTransport.
//
// It accepts only binary messages. Text messages are treated as protocol errors.
type WebSocketMessageTransport struct {
	c WebSocketMessageConn
}

// NewWebSocketMessageTransport wraps a websocket message connection for binary frames only.
func NewWebSocketMessageTransport(c WebSocketMessageConn) *WebSocketMessageTransport {
	return &WebSocketMessageTransport{c: c}
}

// ReadBinary blocks until a binary message is received or the context is done.
func (t *WebSocketMessageTransport) ReadBinary(ctx context.Context) ([]byte, error) {
	for {
		mt, b, err := t.c.ReadMessage(ctx)
		if err != nil {
			return nil, err
		}
		switch mt {
		case websocket.BinaryMessage:
			return b, nil
		case websocket.TextMessage:
			return nil, errors.New("unexpected ws text message")
		default:
			continue
		}
	}
}

// WriteBinary writes a binary message and respects context deadlines.
func (t *WebSocketMessageTransport) WriteBinary(ctx context.Context, b []byte) error {
	return t.c.WriteMessage(ctx, websocket.BinaryMessage, b)
}

// Close closes the underlying websocket connection.
func (t *WebSocketMessageTransport) Close() error {
	return t.c.Close()
}

// WebSocketBinaryTransport adapts a gorilla/websocket Conn to BinaryTransport.
type WebSocketBinaryTransport struct {
	c *websocket.Conn // Underlying websocket connection.
}

// NewWebSocketBinaryTransport wraps a websocket connection for binary frames only.
func NewWebSocketBinaryTransport(c *websocket.Conn) *WebSocketBinaryTransport {
	return &WebSocketBinaryTransport{c: c}
}

// ReadBinary blocks until a binary frame is received or the context is done.
func (t *WebSocketBinaryTransport) ReadBinary(ctx context.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	deadline, hasDeadline := ctx.Deadline()
	if hasDeadline {
		_ = t.c.SetReadDeadline(deadline)
	} else {
		_ = t.c.SetReadDeadline(time.Time{})
	}
	// gorilla/websocket does not unblock ReadMessage on context cancellation unless a read deadline is set.
	// When the context is canceled, force the in-flight read to wake up promptly and map the resulting
	// timeout back to ctx.Err().
	if ctx.Done() != nil {
		var active atomic.Bool
		active.Store(true)
		stop := context.AfterFunc(ctx, func() {
			if !active.Load() {
				return
			}
			_ = t.c.SetReadDeadline(time.Now())
		})
		defer func() {
			active.Store(false)
			stop()
		}()
	}
	for {
		mt, b, err := t.c.ReadMessage()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				// Prefer ctx.Err() when it is already set.
				if cerr := ctx.Err(); cerr != nil {
					return nil, cerr
				}
				// When we set the websocket read deadline from ctx.Deadline(), the I/O timeout
				// can race slightly ahead of the context timer; map it to DeadlineExceeded
				// once the deadline has passed to keep a stable error contract.
				if hasDeadline && !time.Now().Before(deadline) {
					return nil, context.DeadlineExceeded
				}
			}
			return nil, err
		}
		switch mt {
		case websocket.BinaryMessage:
			return b, nil
		case websocket.TextMessage:
			return nil, errors.New("unexpected ws text message")
		default:
			continue
		}
	}
}

// WriteBinary writes a binary frame and respects context deadlines.
func (t *WebSocketBinaryTransport) WriteBinary(ctx context.Context, b []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	deadline, hasDeadline := ctx.Deadline()
	if hasDeadline {
		_ = t.c.SetWriteDeadline(deadline)
	} else {
		_ = t.c.SetWriteDeadline(time.Time{})
	}
	// Like ReadBinary, force a blocked write to wake up on context cancellation.
	if ctx.Done() != nil {
		var active atomic.Bool
		active.Store(true)
		stop := context.AfterFunc(ctx, func() {
			if !active.Load() {
				return
			}
			_ = t.c.SetWriteDeadline(time.Now())
		})
		defer func() {
			active.Store(false)
			stop()
		}()
	}
	err := t.c.WriteMessage(websocket.BinaryMessage, b)
	if err == nil {
		return nil
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		if hasDeadline && !time.Now().Before(deadline) {
			return context.DeadlineExceeded
		}
	}
	return err
}

// Close closes the underlying websocket connection.
func (t *WebSocketBinaryTransport) Close() error {
	return t.c.Close()
}
