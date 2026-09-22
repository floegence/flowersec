package sessionv4

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

type managementCall struct {
	serial                    uint64
	done                      chan struct{}
	response                  rpcv4.ManagementResponse
	err                       error
	used, complete, abandoned bool
}

// ManagementChannel owns the actual M Stream: one reader, two finite SDK
// service workers, and two original outbound wait/result positions. It never
// borrows an application executor slot or starts a per-request goroutine.
type ManagementChannel struct {
	mu                                 sync.Mutex
	owner                              *StreamOwnership
	writer                             *RPCBatchWriter
	engine                             *rpcv4.ExecutionManagementWire
	parser                             *protocolv4.ManagementParser
	clock                              *timev4.Clock
	resolver                           rpcv4.ExecutionManagementResolver
	reservation, parserReservation     resourcev4.Reference
	buffer                             [16384]byte
	jobs                               chan rpcv4.ManagementJob
	workers                            sync.WaitGroup
	calls                              [2]managementCall
	waiters                            int
	waitersDone                        chan struct{}
	done, closeDone                    chan struct{}
	cancel                             context.CancelFunc
	started, closed, cleaned, cleaning bool
}

func ManagementChannelCharge(runtimeBytes uint64) (resourcev4.Vector, error) {
	if runtimeBytes == 0 {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	return (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(ManagementChannel{})) + 2*uint64(unsafe.Sizeof(rpcv4.ManagementJob{})) + 3*uint64(unsafe.Sizeof(timev4.Deadline{})), resourcev4.Items: 5, resourcev4.Tasks: 3, resourcev4.WorkSlots: 3, resourcev4.Timers: 3}).Add(resourcev4.Vector{resourcev4.SDKBytes: runtimeBytes})
}
func ManagementParserCharge(runtimeBytes uint64) (resourcev4.Vector, error) {
	if runtimeBytes == 0 {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	n, err := protocolv4.ManagementParserBackingBytes()
	if err != nil {
		return resourcev4.Vector{}, err
	}
	return (resourcev4.Vector{resourcev4.SDKBytes: n, resourcev4.Items: 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: runtimeBytes})
}
func NewManagementChannel(owner *StreamOwnership, clock *timev4.Clock, resolver rpcv4.ExecutionManagementResolver, refs [4]resourcev4.Reference, runtimeBytes uint64) (_ *ManagementChannel, err error) {
	if owner == nil || clock == nil {
		return nil, cryptov4.ErrConfiguration
	}
	for _, ref := range refs[1:] {
		if err := refs[0].CheckSameEnvironment(ref); err != nil {
			return nil, err
		}
	}
	charge, err := ManagementChannelCharge(runtimeBytes)
	if err != nil {
		return nil, err
	}
	owned, err := refs[0].Take(charge)
	if err != nil {
		return nil, err
	}
	c := &ManagementChannel{owner: owner, clock: clock, resolver: resolver, reservation: owned, jobs: make(chan rpcv4.ManagementJob, 2), done: make(chan struct{}), closeDone: make(chan struct{}), waitersDone: make(chan struct{})}
	if c.resolver == nil {
		c.resolver = rpcv4.ExecutionManagementResolverFunc(nil)
	}
	defer func() {
		if err != nil {
			if c.engine != nil {
				c.engine.Close()
			}
			if c.writer != nil {
				c.writer.Close()
				_ = c.writer.Retire()
			}
			c.parserReservation.Release()
			owned.Release()
		}
	}()
	c.writer, err = newManagementBatchWriter(owner, refs[1], runtimeBytes)
	if err != nil {
		return nil, err
	}
	c.engine, err = rpcv4.NewExecutionManagementWire(rpcv4.ExecutionManagementWireConfig{Clock: clock, Sink: c.writer, RuntimeBytes: runtimeBytes}, refs[2])
	if err != nil {
		return nil, err
	}
	charge, err = ManagementParserCharge(runtimeBytes)
	if err != nil {
		return nil, err
	}
	c.parserReservation, err = refs[3].Take(charge)
	if err != nil {
		return nil, err
	}
	c.parser, err = protocolv4.NewManagementParser()
	if err != nil {
		return nil, err
	}
	if err = owner.protectReceiveCredit(16384); err != nil {
		return nil, err
	}
	return c, nil
}

// Request keeps the original deadline, target and authorization until the
// complete response or generation cleanup. Local cancellation only abandons
// the wait; an unresolved late response still occupies its original cell.
func (c *ManagementChannel) Request(ctx context.Context, cancel bool, target rpcv4.ExecutionTarget, deadline *timev4.Deadline, access rpcv4.ExecutionAccess) (rpcv4.ManagementResponse, error) {
	if c == nil || ctx == nil || deadline == nil || access == nil {
		return rpcv4.ManagementResponse{}, cryptov4.ErrConfiguration
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return rpcv4.ManagementResponse{}, rpcv4.ErrManagementClosed
	}
	index := -1
	for i := range c.calls {
		if !c.calls[i].used {
			index = i
			break
		}
	}
	if index < 0 {
		c.mu.Unlock()
		return rpcv4.ManagementResponse{}, rpcv4.ErrCapacity
	}
	if err := deadline.Check(); err != nil {
		c.mu.Unlock()
		return rpcv4.ManagementResponse{}, err
	}
	// Claim one original wait/result position before waiting for the original
	// sending ring. No request serial is consumed while publication is pending.
	cell := &c.calls[index]
	*cell = managementCall{used: true, done: make(chan struct{})}
	c.waiters++
	done := cell.done
	c.mu.Unlock()
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	defer timer.Stop()
	for {
		remaining, err := deadline.RemainingMS()
		if err == nil {
			err = ctx.Err()
		}
		wake := c.writer.ManagementWake()
		c.mu.Lock()
		if c.closed {
			err = rpcv4.ErrManagementClosed
		}
		var serial uint64
		if err == nil {
			serial, err = c.engine.TryRequestDeadline(ctx, cancel, target, deadline, access)
		}
		if err == nil {
			cell.serial = serial
			c.mu.Unlock()
			break
		}
		if !errors.Is(err, cryptov4.ErrCapacity) {
			*cell = managementCall{}
			c.leaveWaiterLocked()
			c.mu.Unlock()
			return rpcv4.ManagementResponse{}, err
		}
		c.mu.Unlock()
		timer.Reset(time.Duration(min(remaining, uint64((1<<63-1)/time.Millisecond))) * time.Millisecond)
		select {
		case <-ctx.Done():
		case <-done:
		case <-wake:
		case <-timer.C:
		}
		timer.Stop()
	}
	var waitErr error
	for waitErr == nil {
		remaining, err := deadline.RemainingMS()
		if err != nil {
			waitErr = err
			break
		}
		timer.Reset(time.Duration(min(remaining, uint64((1<<63-1)/time.Millisecond))) * time.Millisecond)
		select {
		case <-done:
			c.mu.Lock()
			response, err := cell.response, cell.err
			if err == nil {
				err = ctx.Err()
			}
			if err == nil {
				err = access.WithExecutionAccess(target, func(authority resourcev4.Reference) error {
					if err := c.reservation.CheckSameEnvironment(authority); err != nil {
						return err
					}
					return deadline.Check()
				})
			}
			if err != nil {
				response = rpcv4.ManagementResponse{}
			}
			*cell = managementCall{}
			c.leaveWaiterLocked()
			c.mu.Unlock()
			return response, err
		case <-ctx.Done():
			waitErr = ctx.Err()
		case <-timer.C:
		}
		timer.Stop()
	}
	c.mu.Lock()
	// Even an already completed result must pass this caller's original wait
	// deadline. A simultaneous response is retired once, without redelivery.
	if cell.complete || c.closed {
		*cell = managementCall{}
	} else {
		cell.abandoned = true
		_ = c.engine.Abandon(cell.serial)
	}
	c.leaveWaiterLocked()
	c.mu.Unlock()
	return rpcv4.ManagementResponse{}, waitErr
}
func (c *ManagementChannel) leaveWaiterLocked() {
	c.waiters--
	if c.closed && c.waiters == 0 {
		close(c.waitersDone)
	}
}
func (c *ManagementChannel) acceptResponse(wire []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return rpcv4.ErrManagementClosed
	}
	response, serial, disposition, err := c.engine.AcceptResponse(wire)
	if err != nil && disposition != rpcv4.ManagementResponseRejected {
		return err
	}
	for i := range c.calls {
		cell := &c.calls[i]
		if cell.serial != serial || cell.complete {
			continue
		}
		if cell.abandoned {
			*cell = managementCall{}
			return nil
		}
		if disposition == rpcv4.ManagementResponseDiscarded {
			return nil
		}
		cell.response, cell.err, cell.complete = response, err, true
		close(cell.done)
		return nil
	}
	return nil
}
func (c *ManagementChannel) Run(ctx context.Context) (err error) {
	if c == nil || ctx == nil {
		return cryptov4.ErrConfiguration
	}
	c.mu.Lock()
	if c.started || c.closed {
		c.mu.Unlock()
		return cryptov4.ErrTransition
	}
	runCtx, cancel := context.WithCancel(ctx)
	c.cancel, c.started = cancel, true
	c.workers.Add(2)
	c.mu.Unlock()
	for i := 0; i < 2; i++ {
		go c.serve(runCtx)
	}
	defer func() {
		c.Close()
		c.workers.Wait()
		close(c.done)
	}()
	var job rpcv4.ManagementJob
	var response bool
	var partial *timev4.Deadline
	onHeader := func(h protocolv4.ApplicationHeader) error {
		response = h.IsResponse()
		if response {
			return nil
		}
		var err error
		job, err = c.engine.BeginRequestHeader(h)
		return err
	}
	for {
		readCtx := runCtx
		var stopRead context.CancelFunc
		if partial != nil {
			remaining, err := partial.RemainingMS()
			if err != nil {
				return err
			}
			if !response && job != (rpcv4.ManagementJob{}) {
				original, err := job.RemainingMS()
				if err != nil {
					return err
				}
				remaining = min(remaining, original)
			}
			readCtx, stopRead = context.WithTimeout(runCtx, time.Duration(remaining)*time.Millisecond)
		}
		read, readErr := c.owner.ReadInto(readCtx, c.buffer[:])
		if stopRead != nil {
			stopRead()
		}
		input := c.buffer[:read.Progress.Filled]
		for len(input) > 0 {
			if partial == nil {
				partial, err = timev4.NewAge(c.clock, 30000, ^uint64(0))
				if err != nil {
					return err
				}
			}
			if err := partial.Check(); err != nil {
				return err
			}
			n, wire, err := c.parser.NextWithHeader(input, onHeader)
			if err != nil {
				return err
			}
			input = input[n:]
			if wire == nil {
				continue
			}
			partial = nil
			if response {
				err = c.acceptResponse(wire)
			} else {
				if err = job.Admit(wire); err == nil {
					select {
					case c.jobs <- job:
					default:
						err = rpcv4.ErrCapacity
					}
				}
			}
			if err != nil {
				return err
			}
			job = rpcv4.ManagementJob{}
			response = false
		}
		clear(c.buffer[:read.Progress.Filled])
		if readErr != nil {
			return readErr
		}
		if read.ReadTerminal != protocolv4.V4ReadTerminalOpen {
			if err := c.parser.End(); err != nil {
				return err
			}
			return io.EOF
		}
	}
}
func (c *ManagementChannel) serve(ctx context.Context) {
	defer c.workers.Done()
	defer func() { _ = recover(); c.Close() }()
	for {
		var job rpcv4.ManagementJob
		select {
		case <-ctx.Done():
			return
		case job = <-c.jobs:
		}
		reply, err := job.Run(ctx, c.resolver)
		if err != nil {
			return
		}
		for {
			wake := c.writer.ManagementWake()
			err = reply.Publish(ctx)
			if err == nil {
				break
			}
			if !errors.Is(err, cryptov4.ErrCapacity) {
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-wake:
			}
		}
	}
}
func (c *ManagementChannel) Close() {
	if c == nil {
		return
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	cancel := c.cancel
	if !c.started {
		close(c.done)
	}
	for i := range c.calls {
		p := &c.calls[i]
		if !p.used {
			continue
		}
		if p.abandoned {
			*p = managementCall{}
		} else if !p.complete {
			p.complete, p.err = true, rpcv4.ErrManagementClosed
			close(p.done)
		}
	}
	if c.waiters == 0 {
		close(c.waitersDone)
	}
	c.mu.Unlock()
	defer close(c.closeDone)
	if cancel != nil {
		cancel()
	}
	c.engine.Close()
	c.writer.Close()
	_ = c.owner.Cancel()
}
func (c *ManagementChannel) WaitCleanup(ctx context.Context) error {
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
	for _, done := range []<-chan struct{}{c.closeDone, c.done, c.waitersDone} {
		select {
		case <-done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if !c.engine.CleanupComplete() {
		return cryptov4.ErrCapacity
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
		case <-c.writer.Wake():
		case <-ctx.Done():
			return ctx.Err()
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
	// All reader, service, waiter and provider aliases have physically exited.
	c.parser, c.engine, c.writer, c.owner, c.resolver, c.jobs = nil, nil, nil, nil, nil, nil
	c.clock = nil
	c.parserReservation.Release()
	c.parserReservation = resourcev4.Reference{}
	c.reservation.Release()
	c.reservation = resourcev4.Reference{}
	c.cleaned = true
	return nil
}
