package e2ee

import (
	"context"
	"errors"
	"net"
	"time"

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
	if deadline, ok := ctx.Deadline(); ok {
		_ = t.c.SetReadDeadline(deadline)
	} else {
		_ = t.c.SetReadDeadline(time.Time{})
	}
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = t.c.SetReadDeadline(time.Now())
		case <-done:
		}
	}()
	defer close(done)
	for {
		mt, b, err := t.c.ReadMessage()
		if err != nil {
			if errors.Is(ctx.Err(), context.Canceled) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					return nil, ctx.Err()
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

func (t *WebSocketBinaryTransport) WriteBinary(ctx context.Context, b []byte) error {
	if deadline, ok := ctx.Deadline(); ok {
		_ = t.c.SetWriteDeadline(deadline)
	} else {
		_ = t.c.SetWriteDeadline(time.Time{})
	}
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = t.c.SetWriteDeadline(time.Now())
		case <-done:
		}
	}()
	defer close(done)
	err := t.c.WriteMessage(websocket.BinaryMessage, b)
	if err == nil {
		return nil
	}
	if errors.Is(ctx.Err(), context.Canceled) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return ctx.Err()
		}
	}
	return err
}

func (t *WebSocketBinaryTransport) Close() error {
	return t.c.Close()
}
