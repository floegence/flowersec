package flowersec

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

const byteStreamBufferBytes = 64 * 1024

// ByteStreamConn owns one encrypted stream and adapts it for TLS and net/http.
// It has one bounded reader and writer. Read deadlines are reversible. A write
// deadline during an in-flight write aborts this stream, because encrypted
// record delivery cannot safely resume after a partial carrier write.
// Addresses are logical, never network destinations or peer authentication.
type ByteStreamConn struct {
	stream        ByteStream
	done          chan struct{}
	stop          func() bool
	closeOnce     sync.Once
	workers       sync.WaitGroup
	closed        chan struct{}
	reads         chan streamReadResult
	writes        chan streamWriteRequest
	readMu        sync.Mutex
	writeMu       sync.Mutex
	pending       streamReadResult
	mu            sync.Mutex
	readDeadline  time.Time
	writeDeadline time.Time
	readChanged   chan struct{}
	writeChanged  chan struct{}
	writeClosed   bool
}

// String and GoString keep buffered application data out of diagnostic output.
func (*ByteStreamConn) String() string   { return "Flowersec.ByteStreamConn" }
func (*ByteStreamConn) GoString() string { return "flowersec.ByteStreamConn" }

type streamReadResult struct {
	data []byte
	err  error
}
type streamWriteRequest struct {
	data   []byte
	finish bool
	result chan streamWriteResult
}
type streamWriteResult struct {
	n   int
	err error
}

// NewByteStreamConn transfers stream ownership to the connection. Canceling ctx
// closes it, including a connection hijacked by an HTTP or WebSocket handler.
func NewByteStreamConn(ctx context.Context, stream ByteStream) (*ByteStreamConn, error) {
	if ctx == nil || stream == nil {
		return nil, errors.New("invalid byte stream connection")
	}
	c := &ByteStreamConn{stream: stream, done: make(chan struct{}), closed: make(chan struct{}), reads: make(chan streamReadResult), writes: make(chan streamWriteRequest), readChanged: make(chan struct{}), writeChanged: make(chan struct{})}
	c.workers.Add(2)
	// Hold mu until stop is installed; an already canceled context may run it immediately.
	c.mu.Lock()
	c.stop = context.AfterFunc(ctx, func() { _ = c.Close() })
	c.mu.Unlock()
	go c.readLoop()
	go c.writeLoop()
	return c, nil
}

func (c *ByteStreamConn) readLoop() {
	defer c.workers.Done()
	for {
		buffer := make([]byte, byteStreamBufferBytes)
		n, err := c.stream.Read(buffer)
		if n < 0 || n > len(buffer) {
			n, err = 0, io.ErrUnexpectedEOF
		}
		if n == 0 && err == nil {
			err = io.ErrNoProgress
		}
		select {
		case c.reads <- streamReadResult{buffer[:n], err}:
		case <-c.done:
			return
		}
		if err != nil {
			return
		}
	}
}

func (c *ByteStreamConn) writeLoop() {
	defer c.workers.Done()
	for {
		select {
		case <-c.done:
			return
		case request := <-c.writes:
			var result streamWriteResult
			select {
			case <-c.done:
				result.err = net.ErrClosed
			default:
				if request.finish {
					result.err = c.stream.CloseWrite()
				} else {
					result.n, result.err = c.stream.Write(request.data)
				}
			}
			request.result <- result
		}
	}
}

func (c *ByteStreamConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	for {
		deadline, changed := c.deadline(false)
		if err := c.operationError(deadline); err != nil {
			return 0, err
		}
		if len(c.pending.data) > 0 {
			n := copy(p, c.pending.data)
			c.pending.data = c.pending.data[n:]
			return n, nil
		}
		if c.pending.err != nil {
			return 0, c.pending.err
		}
		timer, expired := streamDeadlineTimer(deadline)
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

func (c *ByteStreamConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeClosed {
		return 0, net.ErrClosed
	}
	n := 0
	for n < len(p) {
		end := min(n+byteStreamBufferBytes, len(p))
		result := c.write(streamWriteRequest{data: append([]byte(nil), p[n:end]...), result: make(chan streamWriteResult, 1)})
		if result.n < 0 || result.n > end-n {
			return n, io.ErrShortWrite
		}
		n += result.n
		if result.err != nil {
			return n, result.err
		}
		if result.n == 0 {
			return n, io.ErrShortWrite
		}
	}
	return n, nil
}

func (c *ByteStreamConn) write(request streamWriteRequest) streamWriteResult {
	var result <-chan streamWriteResult
	send := c.writes
	for {
		deadline, changed := c.deadline(true)
		if err := c.operationError(deadline); err != nil {
			if result != nil {
				c.beginClose()
			}
			return streamWriteResult{err: err}
		}
		timer, expired := streamDeadlineTimer(deadline)
		var received *streamWriteResult
		select {
		case send <- request:
			send = nil
			result = request.result
		case r := <-result:
			received = &r
		case <-changed:
		case <-expired:
		case <-c.done:
		}
		if timer != nil {
			timer.Stop()
		}
		if received != nil {
			return *received
		}
	}
}

// CloseWrite sends an authenticated FIN without interrupting reads. It shares
// write serialization and deadlines with Write.
func (c *ByteStreamConn) CloseWrite() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeClosed {
		return nil
	}
	err := c.write(streamWriteRequest{finish: true, result: make(chan streamWriteResult, 1)}).err
	if err == nil {
		c.writeClosed = true
	}
	return err
}

// Close interrupts local I/O and joins both adapter workers. The stream owns
// bounded protocol reset completion; pending reads and writes return immediately
// even while Close waits for that cleanup.
func (c *ByteStreamConn) Close() error {
	c.beginClose()
	<-c.closed
	return nil
}

func (c *ByteStreamConn) beginClose() {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		close(c.done)
		c.stop()
		c.mu.Unlock()
		go func() {
			_ = c.stream.Close()
			c.workers.Wait()
			close(c.closed)
		}()
	})
}

func (c *ByteStreamConn) operationError(deadline time.Time) error {
	select {
	case <-c.done:
		return net.ErrClosed
	default:
	}
	if !deadline.IsZero() && !time.Now().Before(deadline) {
		return os.ErrDeadlineExceeded
	}
	return nil
}

func (c *ByteStreamConn) deadline(write bool) (time.Time, <-chan struct{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if write {
		return c.writeDeadline, c.writeChanged
	}
	return c.readDeadline, c.readChanged
}

func streamDeadlineTimer(deadline time.Time) (*time.Timer, <-chan time.Time) {
	if deadline.IsZero() {
		return nil, nil
	}
	timer := time.NewTimer(time.Until(deadline))
	return timer, timer.C
}

func (c *ByteStreamConn) setDeadline(t time.Time, read, write bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.done:
		return net.ErrClosed
	default:
	}
	if read {
		c.readDeadline = t
		close(c.readChanged)
		c.readChanged = make(chan struct{})
	}
	if write {
		c.writeDeadline = t
		close(c.writeChanged)
		c.writeChanged = make(chan struct{})
	}
	return nil
}
func (c *ByteStreamConn) SetDeadline(t time.Time) error      { return c.setDeadline(t, true, true) }
func (c *ByteStreamConn) SetReadDeadline(t time.Time) error  { return c.setDeadline(t, true, false) }
func (c *ByteStreamConn) SetWriteDeadline(t time.Time) error { return c.setDeadline(t, false, true) }

type byteStreamAddress struct{}

func (byteStreamAddress) Network() string    { return "flowersec" }
func (byteStreamAddress) String() string     { return "application-stream" }
func (*ByteStreamConn) LocalAddr() net.Addr  { return byteStreamAddress{} }
func (*ByteStreamConn) RemoteAddr() net.Addr { return byteStreamAddress{} }

var _ net.Conn = (*ByteStreamConn)(nil)

// ByteStreamListener admits exactly one owned connection. Closing the listener
// also closes that connection, including after Accept or an HTTP hijack.
type ByteStreamListener struct {
	conn     *ByteStreamConn
	mu       sync.Mutex
	accepted bool
}

func NewByteStreamListener(ctx context.Context, stream ByteStream) (*ByteStreamListener, error) {
	conn, err := NewByteStreamConn(ctx, stream)
	if err != nil {
		return nil, err
	}
	return &ByteStreamListener{conn: conn}, nil
}

func (l *ByteStreamListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	first := !l.accepted
	l.accepted = true
	l.mu.Unlock()
	if first {
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
func (l *ByteStreamListener) Close() error { return l.conn.Close() }
func (*ByteStreamListener) Addr() net.Addr { return byteStreamAddress{} }

var _ net.Listener = (*ByteStreamListener)(nil)
