package e2ee

import (
	"context"
	"errors"

	fsws "github.com/floegence/flowersec/flowersec-go/v2/realtime/ws"
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
	transport *WebSocketMessageTransport
}

// NewWebSocketBinaryTransport wraps a websocket connection for binary frames only.
func NewWebSocketBinaryTransport(c *websocket.Conn) *WebSocketBinaryTransport {
	return &WebSocketBinaryTransport{
		transport: NewWebSocketMessageTransport(fsws.Wrap(c)),
	}
}

// ReadBinary blocks until a binary frame is received or the context is done.
func (t *WebSocketBinaryTransport) ReadBinary(ctx context.Context) ([]byte, error) {
	return t.transport.ReadBinary(ctx)
}

// WriteBinary writes a binary frame and respects context deadlines.
func (t *WebSocketBinaryTransport) WriteBinary(ctx context.Context, b []byte) error {
	return t.transport.WriteBinary(ctx, b)
}

// Close closes the underlying websocket connection.
func (t *WebSocketBinaryTransport) Close() error {
	return t.transport.Close()
}
