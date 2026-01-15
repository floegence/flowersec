package e2ee

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync"
	"time"
)

type SecureConn struct {
	t              BinaryTransport
	maxRecordBytes int

	mu      sync.Mutex
	cond    *sync.Cond
	buf     bytes.Buffer
	readErr error
	closed  bool

	sendMu     sync.Mutex
	sendCh     chan sendReq
	sendClosed bool
	sendErr    error
	sendOnce   sync.Once

	keys RecordKeyState
}

type sendReq struct {
	frame []byte
	done  chan error
}

func NewSecureConn(t BinaryTransport, keys RecordKeyState, maxRecordBytes int) *SecureConn {
	c := &SecureConn{
		t:              t,
		maxRecordBytes: maxRecordBytes,
		keys:           keys,
		sendCh:         make(chan sendReq, 16),
	}
	c.cond = sync.NewCond(&c.mu)
	go c.writeLoop()
	go c.readLoop()
	return c
}

func (c *SecureConn) writeLoop() {
	for req := range c.sendCh {
		// Snapshot send-side state under sendMu to avoid races with Close/RekeyNow/Write.
		c.sendMu.Lock()
		closed := c.sendClosed
		err := c.sendErr
		c.sendMu.Unlock()

		if err == nil && closed {
			err = io.ErrClosedPipe
		}
		if err == nil {
			err = c.t.WriteBinary(context.Background(), req.frame)
			if err != nil {
				c.setSendErr(err)
				_ = c.Close()
			}
		}
		req.done <- err
	}
}

func (c *SecureConn) readLoop() {
	for {
		frame, err := c.t.ReadBinary(context.Background())
		if err != nil {
			c.failRead(err)
			return
		}
		flags, seq, plain, err := DecryptRecord(c.keys.RecvKey, c.keys.RecvNoncePre, frame, c.keys.RecvSeq, c.maxRecordBytes)
		if err != nil {
			c.failRead(err)
			return
		}
		c.keys.RecvSeq = seq + 1
		switch flags {
		case RecordFlagApp:
			c.mu.Lock()
			_, _ = c.buf.Write(plain)
			c.cond.Broadcast()
			c.mu.Unlock()
		case RecordFlagPing:
			// Ignore.
		case RecordFlagRekey:
			newKey, err := DeriveRekeyKey(c.keys.RekeyBase, c.keys.Transcript, seq, c.keys.RecvDir)
			if err != nil {
				c.failRead(err)
				return
			}
			c.keys.RecvKey = newKey
		default:
			c.failRead(ErrRecordBadFlag)
			return
		}
	}
}

func (c *SecureConn) failRead(err error) {
	c.mu.Lock()
	if c.readErr == nil {
		c.readErr = err
	}
	c.cond.Broadcast()
	c.mu.Unlock()
	_ = c.Close()
}

func (c *SecureConn) setSendErr(err error) {
	c.sendMu.Lock()
	if c.sendErr == nil {
		c.sendErr = err
	}
	c.sendMu.Unlock()
}

func (c *SecureConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for {
		if c.buf.Len() > 0 {
			return c.buf.Read(p)
		}
		if c.readErr != nil {
			return 0, c.readErr
		}
		if c.closed {
			return 0, io.EOF
		}
		c.cond.Wait()
	}
}

func (c *SecureConn) Write(p []byte) (int, error) {
	maxPlain := MaxPlaintext(c.maxRecordBytes)
	if maxPlain <= 0 {
		maxPlain = len(p)
	}
	total := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > maxPlain {
			chunk = p[:maxPlain]
		}

		// Allocate seq + build + enqueue under sendMu to guarantee that
		// send order matches seq order (otherwise receiver seq checks can fail).
		req := sendReq{done: make(chan error, 1)}
		c.sendMu.Lock()
		if c.sendClosed {
			c.sendMu.Unlock()
			return total, io.ErrClosedPipe
		}
		if c.sendErr != nil {
			err := c.sendErr
			c.sendMu.Unlock()
			return total, err
		}
		key := c.keys.SendKey
		noncePre := c.keys.SendNoncePre
		seq := c.keys.SendSeq
		c.keys.SendSeq++
		frame, err := EncryptRecord(key, noncePre, RecordFlagApp, seq, chunk, c.maxRecordBytes)
		if err != nil {
			c.sendMu.Unlock()
			return total, err
		}
		req.frame = frame
		c.sendCh <- req
		c.sendMu.Unlock()
		if err := <-req.done; err != nil {
			return total, err
		}

		total += len(chunk)
		p = p[len(chunk):]
	}
	return total, nil
}

func (c *SecureConn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.cond.Broadcast()
	c.mu.Unlock()
	c.sendOnce.Do(func() {
		c.sendMu.Lock()
		c.sendClosed = true
		close(c.sendCh)
		c.sendMu.Unlock()
	})
	return c.t.Close()
}

func (c *SecureConn) LocalAddr() net.Addr  { return dummyAddr("flowersec-local") }
func (c *SecureConn) RemoteAddr() net.Addr { return dummyAddr("flowersec-remote") }

func (c *SecureConn) SetDeadline(_ time.Time) error      { return nil }
func (c *SecureConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *SecureConn) SetWriteDeadline(_ time.Time) error { return nil }

func (c *SecureConn) SendPing() error {
	req := sendReq{done: make(chan error, 1)}
	c.sendMu.Lock()
	if c.sendClosed {
		c.sendMu.Unlock()
		return io.ErrClosedPipe
	}
	if c.sendErr != nil {
		err := c.sendErr
		c.sendMu.Unlock()
		return err
	}
	key := c.keys.SendKey
	noncePre := c.keys.SendNoncePre
	seq := c.keys.SendSeq
	c.keys.SendSeq++
	frame, err := EncryptRecord(key, noncePre, RecordFlagPing, seq, nil, c.maxRecordBytes)
	if err != nil {
		c.sendMu.Unlock()
		return err
	}
	req.frame = frame
	c.sendCh <- req
	c.sendMu.Unlock()
	return <-req.done
}

func (c *SecureConn) RekeyNow() error {
	req := sendReq{done: make(chan error, 1)}
	c.sendMu.Lock()
	if c.sendClosed {
		c.sendMu.Unlock()
		return io.ErrClosedPipe
	}
	if c.sendErr != nil {
		err := c.sendErr
		c.sendMu.Unlock()
		return err
	}
	key := c.keys.SendKey
	noncePre := c.keys.SendNoncePre
	rekeyBase := c.keys.RekeyBase
	transcript := c.keys.Transcript
	sendDir := c.keys.SendDir
	seq := c.keys.SendSeq
	c.keys.SendSeq++

	frame, err := EncryptRecord(key, noncePre, RecordFlagRekey, seq, nil, c.maxRecordBytes)
	if err != nil {
		c.sendMu.Unlock()
		return err
	}
	req.frame = frame
	c.sendCh <- req

	// Update the send key while still holding sendMu so that any later enqueued app records
	// are guaranteed to be encrypted under the new key and ordered after the rekey frame.
	newKey, err := DeriveRekeyKey(rekeyBase, transcript, seq, sendDir)
	if err != nil {
		c.sendMu.Unlock()
		return err
	}
	c.keys.SendKey = newKey
	c.sendMu.Unlock()
	return <-req.done
}

type dummyAddr string

func (d dummyAddr) Network() string { return string(d) }
func (d dummyAddr) String() string  { return string(d) }
