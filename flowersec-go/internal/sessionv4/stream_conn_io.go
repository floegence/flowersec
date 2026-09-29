package sessionv4

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

func (c *StreamConn) beginIO(direction int) (*StreamOwnership, context.Context, resourcev4.Reference, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, nil, resourcev4.Reference{}, net.ErrClosed
	}
	if direction == 1 && c.sendClosed {
		return nil, nil, resourcev4.Reference{}, io.ErrClosedPipe
	}
	if c.active[direction] {
		return nil, nil, resourcev4.Reference{}, ErrStreamOwnershipBusy
	}
	if err := c.parent.Err(); err != nil {
		c.closeLocked(err)
		return nil, nil, resourcev4.Reference{}, err
	}
	if d := c.ioDeadline[direction]; !d.IsZero() && !time.Now().Before(d) {
		if direction == 1 {
			c.closeLocked(os.ErrDeadlineExceeded)
		}
		return nil, nil, resourcev4.Reference{}, os.ErrDeadlineExceeded
	}
	o := c.owner
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.conn != c || o.admission == nil || o.revoked.Load() || o.sealed.Load() {
		return nil, nil, resourcev4.Reference{}, net.ErrClosed
	}
	if err := o.checkLifetime(); err != nil {
		return nil, nil, resourcev4.Reference{}, err
	}
	if o.users == o.cap {
		return nil, nil, resourcev4.Reference{}, ErrStreamOwnershipBusy
	}
	tail, err := c.reservation.Borrow()
	if err != nil {
		return nil, nil, resourcev4.Reference{}, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	c.active[direction], c.ioCancel[direction], c.ioTimedOut[direction] = true, cancel, false
	o.users++
	connNotify(c.wake)
	return o, ctx, tail, nil
}

func (c *StreamConn) endIO(direction int, o *StreamOwnership, tail resourcev4.Reference, n int, err error) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ioCancel[direction]()
	c.ioCancel[direction] = nil
	c.active[direction] = false
	o.end()
	// Committed progress/EOF is never erased by a later wait cancellation.
	if errors.Is(err, context.Canceled) || errors.Is(err, ErrStreamOwned) {
		if c.ioTimedOut[direction] {
			err = os.ErrDeadlineExceeded
		} else if c.closed {
			err = net.ErrClosed
		}
	}
	if direction == 1 && c.sendClosed && errors.Is(err, ErrFlowClosed) {
		err = io.ErrClosedPipe
	}
	if direction == 1 && err != nil && !c.closed && !(c.sendClosed && errors.Is(err, io.ErrClosedPipe)) {
		c.closeLocked(err)
	} else if direction == 0 && err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, os.ErrDeadlineExceeded) && !c.closed {
		c.closeLocked(err)
	}
	tail.Release()
	connNotify(c.workerWake)
	return n, err
}

func (c *StreamConn) Read(p []byte) (int, error) {
	o, ctx, tail, err := c.beginIO(0)
	if err != nil {
		return 0, err
	}
	if len(p) == 0 {
		return c.endIO(0, o, tail, 0, nil)
	}
	r, err := o.flow.receive.readIntoOwned(ctx, p, o)
	if err == nil && r.ReadTerminal == protocolv4.V4ReadTerminalEof {
		err = io.EOF
	}
	return c.endIO(0, o, tail, int(r.Progress.Filled), err)
}

func (c *StreamConn) Write(p []byte) (int, error) {
	o, ctx, tail, err := c.beginIO(1)
	if err != nil {
		return 0, err
	}
	n, err := o.queue.writeAllOwned(ctx, p, o)
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	return c.endIO(1, o, tail, n, err)
}

func (c *StreamConn) SetDeadline(t time.Time) error      { return c.setDeadline(t, true, true) }
func (c *StreamConn) SetReadDeadline(t time.Time) error  { return c.setDeadline(t, true, false) }
func (c *StreamConn) SetWriteDeadline(t time.Time) error { return c.setDeadline(t, false, true) }

func (c *StreamConn) setDeadline(t time.Time, read, write bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return net.ErrClosed
	}
	for i, selected := range [2]bool{read, write} {
		if !selected {
			continue
		}
		c.ioDeadline[i] = t
		if c.active[i] && !t.IsZero() && !time.Now().Before(t) {
			c.ioTimedOut[i] = true
			c.ioCancel[i]()
		}
	}
	connNotify(c.wake)
	return nil
}

// CloseWrite preserves the reverse reader. Finish observes the same FIN and
// only succeeds with authenticated DRAINED(drained). Canceling either wait
// never opens the send gate or changes the original publication operation.
func (c *StreamConn) CloseWrite() error                { return c.waitSend(context.Background(), false) }
func (c *StreamConn) Finish(ctx context.Context) error { return c.waitSend(ctx, true) }

func (c *StreamConn) waitSend(ctx context.Context, drain bool) error {
	if ctx == nil {
		return cryptov4.ErrConfiguration
	}
	c.mu.Lock()
	completion := c.completion
	if settled, err := completion.result(drain); settled {
		c.mu.Unlock()
		return err
	}
	if c.complete {
		c.mu.Unlock()
		return net.ErrClosed
	}
	if c.active[2] {
		c.mu.Unlock()
		return ErrStreamOwnershipBusy
	}
	tail, err := c.reservation.Borrow()
	if err != nil {
		c.mu.Unlock()
		return err
	}
	o := c.owner
	o.mu.Lock()
	q := o.queue
	q.mu.Lock()
	err = q.finishOwnershipLocked(o)
	if err == nil && c.finish == nil {
		c.finish, err = timev4.NewWindow(c.clock, c.options.FinishTimeoutMS)
	}
	if err == nil {
		q.sealLocked()
		c.sendClosed = true
		connNotify(c.wake)
	}
	q.mu.Unlock()
	o.mu.Unlock()
	if err != nil {
		tail.Release()
		c.mu.Unlock()
		return err
	}
	c.active[2] = true
	done := completion.finDone
	if drain {
		done = completion.drainDone
	}
	c.mu.Unlock()
	defer func() { c.mu.Lock(); c.active[2] = false; tail.Release(); connNotify(c.workerWake); c.mu.Unlock() }()
	select {
	case <-done:
	case <-ctx.Done():
	}
	if settled, err := completion.result(drain); settled {
		return err
	}
	return ctx.Err()
}
