package ws

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
)

type Conn struct {
	c *websocket.Conn // Underlying gorilla/websocket connection.
}

// UpgraderOptions exposes a small set of websocket upgrader controls.
type UpgraderOptions struct {
	ReadBufferSize  int                        // Read buffer size for upgrader.
	WriteBufferSize int                        // Write buffer size for upgrader.
	CheckOrigin     func(r *http.Request) bool // Optional origin check.
}

// Upgrade upgrades an HTTP request to a websocket connection.
func Upgrade(w http.ResponseWriter, r *http.Request, opts UpgraderOptions) (*Conn, error) {
	up := websocket.Upgrader{
		ReadBufferSize:  opts.ReadBufferSize,
		WriteBufferSize: opts.WriteBufferSize,
		CheckOrigin:     opts.CheckOrigin,
	}
	c, err := up.Upgrade(w, r, nil)
	if err != nil {
		return nil, err
	}
	return &Conn{c: c}, nil
}

// DialOptions provides optional headers for websocket dialing.
type DialOptions struct {
	Header http.Header // Optional headers for the handshake request.
}

// Dial opens a websocket connection with deadline-aware handshake.
func Dial(ctx context.Context, urlStr string, opts DialOptions) (*Conn, *http.Response, error) {
	d := websocket.Dialer{}
	if deadline, ok := ctx.Deadline(); ok {
		d.HandshakeTimeout = time.Until(deadline)
	}
	c, resp, err := d.DialContext(ctx, urlStr, opts.Header)
	if err != nil {
		return nil, resp, err
	}
	return &Conn{c: c}, resp, nil
}

// SetReadLimit forwards the read limit to the underlying websocket.
func (c *Conn) SetReadLimit(n int64) {
	c.c.SetReadLimit(n)
}

// ReadMessage reads a websocket frame and respects the context deadline.
func (c *Conn) ReadMessage(ctx context.Context) (int, []byte, error) {
	if deadline, ok := ctx.Deadline(); ok {
		_ = c.c.SetReadDeadline(deadline)
	} else {
		_ = c.c.SetReadDeadline(time.Time{})
	}
	mt, b, err := c.c.ReadMessage()
	if err == nil {
		return mt, b, nil
	}
	if errors.Is(ctx.Err(), context.Canceled) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return 0, nil, ctx.Err()
		}
	}
	return 0, nil, err
}

// WriteMessage writes a websocket frame and respects the context deadline.
func (c *Conn) WriteMessage(ctx context.Context, messageType int, data []byte) error {
	if deadline, ok := ctx.Deadline(); ok {
		_ = c.c.SetWriteDeadline(deadline)
	} else {
		_ = c.c.SetWriteDeadline(time.Time{})
	}
	err := c.c.WriteMessage(messageType, data)
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

// Close closes the websocket connection.
func (c *Conn) Close() error {
	return c.c.Close()
}

// CloseWithStatus sends a close control frame before closing.
func (c *Conn) CloseWithStatus(code int, text string) error {
	_ = c.c.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(code, text), time.Now().Add(2*time.Second))
	return c.c.Close()
}

// Underlying exposes the raw gorilla/websocket connection.
func (c *Conn) Underlying() *websocket.Conn {
	return c.c
}
