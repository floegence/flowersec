package e2ee

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

type SecureConn struct {
	t                BinaryTransport // Underlying transport for encrypted frames.
	maxRecordBytes   int             // Max encoded record size in bytes.
	maxBufferedBytes int             // Max buffered plaintext bytes before failing.

	mu      sync.Mutex   // Guards read buffer and read state.
	buf     bytes.Buffer // Buffered plaintext awaiting Read.
	readErr error        // Sticky read error from readLoop.
	closed  bool         // Close state for Read/Write.

	readNotify   chan struct{} // Closed+replaced to wake Read waiters (data, errors, close, deadline changes).
	readDeadline time.Time     // Read deadline for net.Conn Read; zero means no deadline.

	sendMu     sync.Mutex // Guards send queue and send state.
	sendCond   *sync.Cond // Signals sender when frames are queued.
	sendQueue  []sendReq  // Pending frames to send.
	sendClosed bool       // Indicates no more sends are allowed.
	sendErr    error      // Sticky send error from writeLoop.
	sendOnce   sync.Once  // Ensures send shutdown happens once.

	writeNotify   chan struct{} // Closed+replaced to wake Write waiters (deadline changes, close).
	writeDeadline time.Time     // Write deadline for net.Conn Write; zero means no deadline.

	keys RecordKeyState // Current key material and sequence state.
}

// ErrRecvBufferExceeded indicates buffered plaintext exceeded the configured cap.
var ErrRecvBufferExceeded = errors.New("recv buffer exceeded")

type sendReq struct {
	frame []byte     // Encrypted record frame to write.
	done  chan error // Completion signal for the send.
}

// NewSecureConn wraps a BinaryTransport with record encryption and buffering.
func NewSecureConn(t BinaryTransport, keys RecordKeyState, maxRecordBytes int, maxBufferedBytes int) *SecureConn {
	c := &SecureConn{
		t:                t,
		maxRecordBytes:   maxRecordBytes,
		maxBufferedBytes: maxBufferedBytes,
		readNotify:       make(chan struct{}),
		writeNotify:      make(chan struct{}),
		keys:             keys,
	}
	c.sendCond = sync.NewCond(&c.sendMu)
	go c.writeLoop()
	go c.readLoop()
	return c
}

func (c *SecureConn) signalReadLocked() {
	close(c.readNotify)
	c.readNotify = make(chan struct{})
}

func (c *SecureConn) signalWriteLocked() {
	close(c.writeNotify)
	c.writeNotify = make(chan struct{})
}

func (c *SecureConn) writeLoop() {
	for {
		c.sendMu.Lock()
		for len(c.sendQueue) == 0 && !c.sendClosed {
			c.sendCond.Wait()
		}
		if len(c.sendQueue) == 0 && c.sendClosed {
			c.sendMu.Unlock()
			return
		}
		req := c.sendQueue[0]
		c.sendQueue = c.sendQueue[1:]
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
			if c.maxBufferedBytes > 0 && c.buf.Len()+len(plain) > c.maxBufferedBytes {
				c.mu.Unlock()
				c.failRead(ErrRecvBufferExceeded)
				return
			}
			_, _ = c.buf.Write(plain)
			c.signalReadLocked()
			c.mu.Unlock()
		case RecordFlagPing:
			// Ignore.
		case RecordFlagRekey:
			// Rekey updates only the receive key, bound to the record seq and direction.
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
	c.signalReadLocked()
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
	for {
		c.mu.Lock()
		if c.buf.Len() > 0 {
			n, err := c.buf.Read(p)
			c.mu.Unlock()
			return n, err
		}
		if c.readErr != nil {
			err := c.readErr
			c.mu.Unlock()
			return 0, err
		}
		if c.closed {
			c.mu.Unlock()
			return 0, io.EOF
		}

		ch := c.readNotify
		deadline := c.readDeadline
		c.mu.Unlock()

		if !deadline.IsZero() {
			d := time.Until(deadline)
			if d <= 0 {
				return 0, os.ErrDeadlineExceeded
			}
			timer := time.NewTimer(d)
			select {
			case <-ch:
				timer.Stop()
				continue
			case <-timer.C:
				return 0, os.ErrDeadlineExceeded
			}
		}
		<-ch
	}
}

// Write splits payloads into record-sized chunks and enqueues them for sending.
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
		c.sendQueue = append(c.sendQueue, req)
		c.sendCond.Signal()
		c.sendMu.Unlock()
		if err := c.waitSend(req.done); err != nil {
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
	c.signalReadLocked()
	c.mu.Unlock()
	c.sendOnce.Do(func() {
		c.sendMu.Lock()
		c.sendClosed = true
		c.signalWriteLocked()
		c.sendCond.Broadcast()
		c.sendMu.Unlock()
	})
	return c.t.Close()
}

func (c *SecureConn) LocalAddr() net.Addr  { return dummyAddr("flowersec-local") }
func (c *SecureConn) RemoteAddr() net.Addr { return dummyAddr("flowersec-remote") }

func (c *SecureConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	c.signalReadLocked()
	c.mu.Unlock()
	return nil
}

func (c *SecureConn) SetWriteDeadline(t time.Time) error {
	c.sendMu.Lock()
	c.writeDeadline = t
	c.signalWriteLocked()
	c.sendMu.Unlock()
	return nil
}

func (c *SecureConn) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	_ = c.SetWriteDeadline(t)
	return nil
}

// SendPing writes a keepalive record with an empty payload.
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
	c.sendQueue = append(c.sendQueue, req)
	c.sendCond.Signal()
	c.sendMu.Unlock()
	return c.waitSend(req.done)
}

// RekeyNow injects a rekey record and advances the send key.
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
	c.sendQueue = append(c.sendQueue, req)
	c.sendCond.Signal()

	// Update the send key while still holding sendMu so that any later enqueued app records
	// are guaranteed to be encrypted under the new key and ordered after the rekey frame.
	newKey, err := DeriveRekeyKey(rekeyBase, transcript, seq, sendDir)
	if err != nil {
		c.sendMu.Unlock()
		return err
	}
	c.keys.SendKey = newKey
	c.sendMu.Unlock()
	return c.waitSend(req.done)
}

func (c *SecureConn) waitSend(done <-chan error) error {
	for {
		c.sendMu.Lock()
		ch := c.writeNotify
		deadline := c.writeDeadline
		c.sendMu.Unlock()

		if deadline.IsZero() {
			select {
			case err := <-done:
				return err
			case <-ch:
				continue
			}
		}
		d := time.Until(deadline)
		if d <= 0 {
			return os.ErrDeadlineExceeded
		}
		timer := time.NewTimer(d)
		select {
		case err := <-done:
			timer.Stop()
			return err
		case <-timer.C:
			return os.ErrDeadlineExceeded
		case <-ch:
			timer.Stop()
			continue
		}
	}
}

// dummyAddr provides a stable net.Addr for in-memory transports.
type dummyAddr string

func (d dummyAddr) Network() string { return string(d) }
func (d dummyAddr) String() string  { return string(d) }
