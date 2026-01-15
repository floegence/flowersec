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

	keys RecordKeyState
}

func NewSecureConn(t BinaryTransport, keys RecordKeyState, maxRecordBytes int) *SecureConn {
	c := &SecureConn{
		t:              t,
		maxRecordBytes: maxRecordBytes,
		keys:           keys,
	}
	c.cond = sync.NewCond(&c.mu)
	go c.readLoop()
	return c
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
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, io.ErrClosedPipe
	}
	c.mu.Unlock()

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
		seq := c.nextSendSeq()
		frame, err := EncryptRecord(c.keys.SendKey, c.keys.SendNoncePre, RecordFlagApp, seq, chunk, c.maxRecordBytes)
		if err != nil {
			return total, err
		}
		if err := c.t.WriteBinary(context.Background(), frame); err != nil {
			return total, err
		}
		total += len(chunk)
		p = p[len(chunk):]
	}
	return total, nil
}

func (c *SecureConn) nextSendSeq() uint64 {
	c.mu.Lock()
	seq := c.keys.SendSeq
	c.keys.SendSeq++
	c.mu.Unlock()
	return seq
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
	return c.t.Close()
}

func (c *SecureConn) LocalAddr() net.Addr  { return dummyAddr("flowersec-local") }
func (c *SecureConn) RemoteAddr() net.Addr { return dummyAddr("flowersec-remote") }

func (c *SecureConn) SetDeadline(_ time.Time) error      { return nil }
func (c *SecureConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *SecureConn) SetWriteDeadline(_ time.Time) error { return nil }

func (c *SecureConn) SendPing() error {
	seq := c.nextSendSeq()
	frame, err := EncryptRecord(c.keys.SendKey, c.keys.SendNoncePre, RecordFlagPing, seq, nil, c.maxRecordBytes)
	if err != nil {
		return err
	}
	return c.t.WriteBinary(context.Background(), frame)
}

func (c *SecureConn) RekeyNow() error {
	seq := c.nextSendSeq()
	frame, err := EncryptRecord(c.keys.SendKey, c.keys.SendNoncePre, RecordFlagRekey, seq, nil, c.maxRecordBytes)
	if err != nil {
		return err
	}
	if err := c.t.WriteBinary(context.Background(), frame); err != nil {
		return err
	}
	newKey, err := DeriveRekeyKey(c.keys.RekeyBase, c.keys.Transcript, seq, c.keys.SendDir)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.keys.SendKey = newKey
	c.mu.Unlock()
	return nil
}

type dummyAddr string

func (d dummyAddr) Network() string { return string(d) }
func (d dummyAddr) String() string  { return string(d) }
