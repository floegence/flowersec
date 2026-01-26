package ws

import (
	"context"
	"net"
	"net/http"
	"sync/atomic"
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
	Dialer *websocket.Dialer
}

// Dial opens a websocket connection with deadline-aware handshake.
func Dial(ctx context.Context, urlStr string, opts DialOptions) (*Conn, *http.Response, error) {
	var d websocket.Dialer
	if opts.Dialer != nil {
		d = *opts.Dialer
	} else {
		d = websocket.Dialer{}
	}
	if deadline, ok := ctx.Deadline(); ok {
		// Prefer the tighter of dialer.HandshakeTimeout and the context deadline when both are set.
		dl := time.Until(deadline)
		if d.HandshakeTimeout == 0 || d.HandshakeTimeout > dl {
			d.HandshakeTimeout = dl
		}
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

// ReadMessage reads a websocket frame and respects the context deadline and cancellation.
func (c *Conn) ReadMessage(ctx context.Context) (int, []byte, error) {
	// If the context is already done, fail fast without touching socket deadlines.
	if err := ctx.Err(); err != nil {
		return 0, nil, err
	}
	deadline, hasDeadline := ctx.Deadline()
	if hasDeadline {
		_ = c.c.SetReadDeadline(deadline)
	} else {
		_ = c.c.SetReadDeadline(time.Time{})
	}
	// gorilla/websocket does not natively unblock ReadMessage on context cancellation unless we
	// set a read deadline. When the context is canceled, force the in-flight read to wake up
	// promptly and map the resulting I/O timeout back to ctx.Err().
	if ctx.Done() != nil {
		var active atomic.Bool
		active.Store(true)
		stop := context.AfterFunc(ctx, func() {
			if !active.Load() {
				return
			}
			_ = c.c.SetReadDeadline(time.Now())
		})
		defer func() {
			active.Store(false)
			stop()
		}()
	}
	mt, b, err := c.c.ReadMessage()
	if err == nil {
		return mt, b, nil
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		// Prefer ctx.Err() when it is already set.
		if cerr := ctx.Err(); cerr != nil {
			return 0, nil, cerr
		}
		// When we set the websocket read deadline from ctx.Deadline(), the I/O timeout
		// can race slightly ahead of the context timer; map it to DeadlineExceeded
		// once the deadline has passed to keep a stable error contract.
		if hasDeadline && !time.Now().Before(deadline) {
			return 0, nil, context.DeadlineExceeded
		}
	}
	return 0, nil, err
}

// WriteMessage writes a websocket frame and respects the context deadline and cancellation.
func (c *Conn) WriteMessage(ctx context.Context, messageType int, data []byte) error {
	// If the context is already done, fail fast without touching socket deadlines.
	if err := ctx.Err(); err != nil {
		return err
	}
	deadline, hasDeadline := ctx.Deadline()
	if hasDeadline {
		_ = c.c.SetWriteDeadline(deadline)
	} else {
		_ = c.c.SetWriteDeadline(time.Time{})
	}
	// Like ReadMessage, force a blocked WriteMessage to wake up on context cancellation.
	if ctx.Done() != nil {
		var active atomic.Bool
		active.Store(true)
		stop := context.AfterFunc(ctx, func() {
			if !active.Load() {
				return
			}
			_ = c.c.SetWriteDeadline(time.Now())
		})
		defer func() {
			active.Store(false)
			stop()
		}()
	}
	err := c.c.WriteMessage(messageType, data)
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
