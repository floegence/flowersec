package sessionv4

import (
	"context"
	"errors"
	"io"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/rpcv4"
)

// RPCChannel attaches the sole ordinary RPC engine to an accepted original
// Stream. Its reader and publisher are protected SDK services, independent of
// user handlers. The real SendService remains the only record/provider sender.
// The caller transfers StreamOwnership and all four reservations on success.
type RPCChannel struct {
	mu                                          sync.Mutex
	owner                                       *StreamOwnership
	writer                                      *RPCBatchWriter
	publisher                                   *rpcv4.Publisher
	receiver                                    *rpcv4.Receiver
	identity                                    [16]byte
	reservation                                 resourcev4.Reference
	buffer                                      [16384]byte
	cancel                                      context.CancelFunc
	done                                        chan struct{}
	closeDone                                   chan struct{}
	writerDone                                  chan error
	started, running, closed, cleaned, cleaning bool
}

func RPCChannelCharge(runtimeBytes uint64) (resourcev4.Vector, error) {
	if runtimeBytes == 0 {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	return (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(RPCChannel{})), resourcev4.Items: 1, resourcev4.Tasks: 2, resourcev4.WorkSlots: 2}).Add(resourcev4.Vector{resourcev4.SDKBytes: runtimeBytes})
}

// Channel resources, continuous receive promise and SendQueue capacity must
// already be included in SessionPlan before positive OPEN/accepted. This method
// installs them without dialing, running application code or starting workers.
func NewRPCChannel(owner *StreamOwnership, network *rpcv4.Network, channel [16]byte, admission rpcv4.IncomingAdmission, metadata, batch, publish, receive resourcev4.Reference, runtimeBytes uint64) (_ *RPCChannel, err error) {
	if owner == nil || network == nil || admission == nil {
		return nil, cryptov4.ErrConfiguration
	}
	charge, err := RPCChannelCharge(runtimeBytes)
	if err != nil {
		return nil, err
	}
	for _, ref := range []resourcev4.Reference{batch, publish, receive} {
		if err := metadata.CheckSameEnvironment(ref); err != nil {
			return nil, err
		}
	}
	owned, err := metadata.Take(charge)
	if err != nil {
		return nil, err
	}
	c := &RPCChannel{owner: owner, identity: channel, reservation: owned, done: make(chan struct{}), closeDone: make(chan struct{}), writerDone: make(chan error, 1)}
	defer func() {
		if err != nil {
			if c.receiver != nil {
				c.receiver.Close()
			}
			if c.publisher != nil {
				c.publisher.Close()
				_ = c.publisher.Retire()
			}
			if c.writer != nil {
				c.writer.Close()
				_ = c.writer.Retire()
			}
			owned.Release()
		}
	}()
	c.writer, err = NewRPCBatchWriter(owner, batch, runtimeBytes)
	if err != nil {
		return nil, err
	}
	c.publisher, err = network.NewPublisher(channel, c.writer, publish, runtimeBytes)
	if err != nil {
		return nil, err
	}
	c.receiver, err = network.NewReceiver(c.publisher, admission, receive, runtimeBytes)
	if err != nil {
		return nil, err
	}
	if err = owner.protectReceiveCredit(16384); err != nil {
		return nil, err
	}
	return c, nil
}
func (c *RPCChannel) Publisher() *rpcv4.Publisher {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.publisher
}
func (c *RPCChannel) Receiver() *rpcv4.Receiver { c.mu.Lock(); defer c.mu.Unlock(); return c.receiver }

func (c *RPCChannel) Association() rpcv4.Association { return rpcv4.Association{Channel: c.identity} }

func (c *RPCChannel) availablePublisher() *rpcv4.Publisher {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	return c.publisher
}

func (c *RPCChannel) Run(ctx context.Context) (err error) {
	if c == nil || ctx == nil {
		return cryptov4.ErrConfiguration
	}
	c.mu.Lock()
	if c.started || c.closed {
		c.mu.Unlock()
		return cryptov4.ErrTransition
	}
	if err := c.reservation.Check(); err != nil {
		c.mu.Unlock()
		return err
	}
	runCtx, cancel := context.WithCancel(ctx)
	c.cancel = cancel
	c.started = true
	c.running = true
	owner, receiver, publisher, writer := c.owner, c.receiver, c.publisher, c.writer
	c.mu.Unlock()
	go func() {
		failure := ErrCompletionCallbackExit
		defer func() {
			if recover() != nil {
				failure = ErrCompletionCallbackExit
			}
			c.writerDone <- failure
			cancel()
		}()
		failure = c.publish(runCtx, publisher, writer)
	}()
	defer func() {
		cancel()
		publishErr := <-c.writerDone
		if err == nil || errors.Is(err, context.Canceled) {
			err = publishErr
		}
		c.Close()
		c.mu.Lock()
		c.running = false
		c.cancel = nil
		close(c.done)
		c.mu.Unlock()
	}()
	for {
		result, readErr := owner.ReadInto(runCtx, c.buffer[:])
		if result.Progress.Filled > 0 {
			if _, err := receiver.Feed(c.buffer[:result.Progress.Filled]); err != nil {
				return err
			}
			clear(c.buffer[:result.Progress.Filled])
		}
		if readErr != nil {
			return readErr
		}
		if result.ReadTerminal != protocolv4.V4ReadTerminalOpen {
			if err := receiver.End(); err != nil {
				return err
			}
			return io.EOF
		}
	}
}
func (c *RPCChannel) publish(ctx context.Context, p *rpcv4.Publisher, w *RPCBatchWriter) error {
	for {
		progressed, err := p.Step(ctx)
		if err != nil && !errors.Is(err, cryptov4.ErrCapacity) {
			return err
		}
		if progressed {
			continue
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-p.Wake():
		case <-w.Wake():
		}
	}
}
func (c *RPCChannel) Close() {
	if c == nil {
		return
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	cancel, owner, publisher, receiver, writer := c.cancel, c.owner, c.publisher, c.receiver, c.writer
	if !c.started {
		close(c.done)
	}
	c.mu.Unlock()
	defer close(c.closeDone)
	if cancel != nil {
		cancel()
	}
	publisher.Close()
	receiver.Close()
	writer.Close()
	_ = owner.Cancel()
}

// WaitCleanup joins actual publisher/reader exit and the last queue/provider
// borrow before removing the Stream attachment. A canceled wait keeps every
// remaining charge; a later wait continues the same cleanup, without a worker.
func (c *RPCChannel) WaitCleanup(ctx context.Context) error {
	if c == nil {
		return nil
	}
	if ctx == nil {
		return cryptov4.ErrConfiguration
	}
	c.mu.Lock()
	if c.cleaned {
		c.mu.Unlock()
		return nil
	}
	if !c.closed || c.cleaning {
		c.mu.Unlock()
		return cryptov4.ErrCapacity
	}
	c.cleaning = true
	c.mu.Unlock()
	defer func() { c.mu.Lock(); c.cleaning = false; c.mu.Unlock() }()
	select {
	case <-c.closeDone:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case <-c.done:
	case <-ctx.Done():
		return ctx.Err()
	}
	for {
		err := c.publisher.Retire()
		if err == nil {
			break
		}
		if !errors.Is(err, rpcv4.ErrCapacity) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-c.writer.Wake():
		}
	}
	for {
		err := c.writer.Retire()
		if err == nil {
			break
		}
		if !errors.Is(err, cryptov4.ErrCapacity) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-c.writer.Wake():
		}
	}
	if err := c.owner.Cleanup(ctx); err != nil {
		return err
	}
	if err := c.owner.Release(); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	clear(c.buffer[:])
	c.owner = nil
	c.publisher = nil
	c.receiver = nil
	c.writer = nil
	c.reservation.Release()
	c.reservation = resourcev4.Reference{}
	c.cleaned = true
	return nil
}
