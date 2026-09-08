package flowersec

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

// HTTPStreamOptions bounds HTTP admission without limiting response or upgraded-stream duration.
type HTTPStreamOptions struct {
	ReadHeaderTimeout time.Duration
	IdleTimeout       time.Duration
	MaxHeaderBytes    int
}

// ServeHTTPStream owns a single authorized application stream until its HTTP connection
// closes. It supports keep-alive and Hijacker, and closes even hijacked connections on
// cancellation. A deadline expiry terminates this stream; callers open a new stream
// for subsequent requests. Authorization and stream-kind dispatch belong to the caller.
func ServeHTTPStream(ctx context.Context, stream ByteStream, handler http.Handler, options HTTPStreamOptions) error {
	if ctx == nil || stream == nil || handler == nil {
		return errors.New("invalid HTTP stream arguments")
	}
	if options.ReadHeaderTimeout < 0 || options.IdleTimeout < 0 || options.MaxHeaderBytes < 0 {
		return errors.New("invalid HTTP stream limits")
	}
	if options.ReadHeaderTimeout == 0 {
		options.ReadHeaderTimeout = 15 * time.Second
	}
	if options.IdleTimeout == 0 {
		options.IdleTimeout = 60 * time.Second
	}
	if options.MaxHeaderBytes == 0 {
		options.MaxHeaderBytes = 64 * 1024
	}
	conn := &httpByteStreamConn{stream: stream, done: make(chan struct{}), reads: make(chan httpStreamRead), readChanged: make(chan struct{})}
	go conn.readLoop()
	listener := &httpByteStreamListener{conn: conn}
	server := &http.Server{
		Handler: handler, ReadHeaderTimeout: options.ReadHeaderTimeout,
		IdleTimeout: options.IdleTimeout, MaxHeaderBytes: options.MaxHeaderBytes,
		BaseContext: func(net.Listener) context.Context { return ctx },
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close(); _ = server.Close() })
	defer stop()
	defer conn.Close()
	defer server.Close()
	err := server.Serve(listener)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, net.ErrClosed) || errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

type httpStreamRead struct {
	data []byte
	err  error
}

// Reads have one bounded producer and reversible deadlines: net/http interrupts its
// background read before writing a response. That interruption must not reset the stream.
type httpByteStreamConn struct {
	stream          ByteStream
	done            chan struct{}
	reads           chan httpStreamRead
	readMu          sync.Mutex
	pending         httpStreamRead
	mu              sync.Mutex
	closed          bool
	readDeadline    time.Time
	readChanged     chan struct{}
	writeTimer      *time.Timer
	writeExpired    bool
	writeGeneration uint64
}

func (c *httpByteStreamConn) readLoop() {
	for {
		buffer := make([]byte, 64*1024)
		n, err := c.stream.Read(buffer)
		if n == 0 && err == nil {
			continue
		}
		select {
		case c.reads <- httpStreamRead{buffer[:n], err}:
		case <-c.done:
			return
		}
		if err != nil {
			return
		}
	}
}
func (c *httpByteStreamConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	for {
		c.mu.Lock()
		deadline, changed, closed := c.readDeadline, c.readChanged, c.closed
		c.mu.Unlock()
		if closed {
			return 0, net.ErrClosed
		}
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			return 0, os.ErrDeadlineExceeded
		}
		if len(c.pending.data) > 0 {
			n := copy(p, c.pending.data)
			c.pending.data = c.pending.data[n:]
			return n, nil
		}
		if c.pending.err != nil {
			return 0, c.pending.err
		}
		var timer *time.Timer
		var expired <-chan time.Time
		if !deadline.IsZero() {
			timer = time.NewTimer(time.Until(deadline))
			expired = timer.C
		}
		select {
		case c.pending = <-c.reads:
		case <-changed:
		case <-expired:
		case <-c.done:
		}
		if timer != nil {
			timer.Stop()
		}
	}
}
func (c *httpByteStreamConn) Write(p []byte) (int, error) {
	n := 0
	var err error
	for n < len(p) {
		end := n + 64*1024
		if end > len(p) {
			end = len(p)
		}
		var count int
		count, err = c.stream.Write(p[n:end])
		if count < 0 || count > end-n {
			err = io.ErrShortWrite
			break
		}
		n += count
		if err != nil {
			break
		}
		if count == 0 {
			err = io.ErrShortWrite
			break
		}
	}

	c.mu.Lock()
	expired := c.writeExpired
	c.mu.Unlock()
	if expired {
		return n, os.ErrDeadlineExceeded
	}
	return n, err
}
func (c *httpByteStreamConn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	if c.writeTimer != nil {
		c.writeTimer.Stop()
	}
	close(c.done)
	c.mu.Unlock()
	return c.stream.Close()
}
func (c *httpByteStreamConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return net.ErrClosed
	}
	c.readDeadline = t
	close(c.readChanged)
	c.readChanged = make(chan struct{})
	return nil
}
func (c *httpByteStreamConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return net.ErrClosed
	}
	c.writeGeneration++
	generation := c.writeGeneration
	if c.writeTimer != nil {
		c.writeTimer.Stop()
		c.writeTimer = nil
	}
	if !t.IsZero() {
		c.writeTimer = time.AfterFunc(time.Until(t), func() {
			c.mu.Lock()
			if c.closed || c.writeGeneration != generation {
				c.mu.Unlock()
				return
			}
			c.writeExpired = true
			c.mu.Unlock()
			_ = c.stream.Reset()
			_ = c.Close()
		})
	}
	return nil
}
func (c *httpByteStreamConn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}
func (c *httpByteStreamConn) CloseWrite() error { return c.stream.CloseWrite() }

var _ io.ReadWriteCloser = (*httpByteStreamConn)(nil)

type httpStreamAddress struct{}

func (httpStreamAddress) Network() string          { return "flowersec" }
func (httpStreamAddress) String() string           { return "application-stream" }
func (c *httpByteStreamConn) LocalAddr() net.Addr  { return httpStreamAddress{} }
func (c *httpByteStreamConn) RemoteAddr() net.Addr { return httpStreamAddress{} }

type httpByteStreamListener struct {
	conn     *httpByteStreamConn
	accepted bool
}

func (l *httpByteStreamListener) Accept() (net.Conn, error) {
	if !l.accepted {
		l.accepted = true
		select {
		case <-l.conn.done:
			return nil, net.ErrClosed
		default:
			return l.conn, nil
		}
	}
	<-l.conn.done
	return nil, net.ErrClosed
}
func (l *httpByteStreamListener) Close() error   { return l.conn.Close() }
func (l *httpByteStreamListener) Addr() net.Addr { return httpStreamAddress{} }
