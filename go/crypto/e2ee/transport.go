package e2ee

import (
	"context"
	"errors"

	"github.com/gorilla/websocket"
)

type BinaryTransport interface {
	ReadBinary(ctx context.Context) ([]byte, error)
	WriteBinary(ctx context.Context, b []byte) error
	Close() error
}

type WebSocketBinaryTransport struct {
	c *websocket.Conn
}

func NewWebSocketBinaryTransport(c *websocket.Conn) *WebSocketBinaryTransport {
	return &WebSocketBinaryTransport{c: c}
}

func (t *WebSocketBinaryTransport) ReadBinary(ctx context.Context) ([]byte, error) {
	_ = ctx
	for {
		mt, b, err := t.c.ReadMessage()
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

func (t *WebSocketBinaryTransport) WriteBinary(ctx context.Context, b []byte) error {
	_ = ctx
	return t.c.WriteMessage(websocket.BinaryMessage, b)
}

func (t *WebSocketBinaryTransport) Close() error {
	return t.c.Close()
}
