package sessionv4

import (
	"context"
	"errors"
	"math"
	"net"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

var ErrConnCleanupIncomplete = errors.New("sessionv4: connection cleanup incomplete")

// StreamConnOptions fixes lifetime, normal sending and cleanup bounds before
// handing the connection to net/http or another native consumer. RuntimeBytes
// covers channels, cancellation contexts, stacks and allocator overhead; the
// caller must qualify those costs for its runtime. No listener is opened.
// TimeoutMS zero adds no lifetime cap to the original trusted hard deadline.
type StreamConnOptions struct {
	TimeoutMS, FinishTimeoutMS, CleanupTimeoutMS, RuntimeBytes uint64
	HardDeadline                                               *timev4.Deadline
}

func StreamConnCharge(o StreamConnOptions) (resourcev4.Vector, error) {
	fixed := uint64(unsafe.Sizeof(StreamConn{})) + uint64(unsafe.Sizeof(timev4.Deadline{})) + 2*uint64(unsafe.Sizeof(timev4.Window{}))
	if o.FinishTimeoutMS == 0 || o.FinishTimeoutMS > 60000 || o.CleanupTimeoutMS == 0 || o.CleanupTimeoutMS > 5000 || o.RuntimeBytes == 0 || o.RuntimeBytes > math.MaxUint64-fixed {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	// Two original workers, read/write/Finish positions and one cleanup waiter.
	// One supervisor timer also services both reversible native deadlines.
	return resourcev4.Vector{resourcev4.SDKBytes: fixed + o.RuntimeBytes, resourcev4.Items: 1, resourcev4.Tasks: 6, resourcev4.WorkSlots: 6, resourcev4.Timers: 1}, nil
}

// StreamConn owns the original two Stream I/O directions. Close seals external
// I/O synchronously and preserves accepted output through authenticated Finish.
// Abort is the explicit Reset path. Neither Close nor net/http returning proves
// business success; Result and WaitCleanup report the actual direction facts.
// One concurrent read, write, Finish and cleanup wait are admitted. Additional
// simultaneous calls fail locally instead of creating an unbounded waiter list.
type streamConnSignal struct{ wake chan struct{} }

type connExternalCleanup struct {
	backing, dependencies resourcev4.Reference
	done                  chan struct{}
	callbacks             atomic.Uint32
}

type StreamConn struct {
	external           *connExternalCleanup
	aborting           chan struct{}
	signal             streamConnSignal
	mu                 sync.Mutex
	owner              *StreamOwnership
	reservation        resourcev4.Reference
	deadline           *timev4.Deadline
	clock              *timev4.Clock
	parent             context.Context
	options            StreamConnOptions
	completion         *sendCompletion
	active             [3]bool
	ioCancel           [2]context.CancelFunc
	ioDeadline         [2]time.Time
	ioTimedOut         [2]bool
	closed, aborted    bool
	sendClosed         bool
	cleaning, complete bool
	incomplete, waiter bool
	retired, published bool
	first              error
	finish, cleanup    *timev4.Window
	result             protocolv4.V4CloseResult
	accepted           uint64
	wake, workerWake   chan struct{}
	closeStart         chan struct{}
	workerDone, done   chan struct{}
	ready              chan struct{}
}

var _ net.Conn = (*StreamConn)(nil)

// AsConn atomically claims this exact accepted Stream after all metadata is
// admitted. Construction failure never starts I/O or resets the Stream.
func (o *StreamOwnership) AsConn(ctx context.Context, options StreamConnOptions, reservation resourcev4.Reference) (*StreamConn, error) {
	return o.asConn(ctx, options, reservation, nil)
}

func (o *StreamOwnership) asConn(ctx context.Context, options StreamConnOptions, reservation resourcev4.Reference, external *connExternalCleanup) (*StreamConn, error) {
	if o == nil || ctx == nil {
		return nil, cryptov4.ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	charge, err := StreamConnCharge(options)
	if err != nil {
		return nil, err
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.admission == nil || o.conn != nil || o.messages != nil || o.typed != nil || o.resume != nil || o.users != 0 || o.cleaning || o.rawUsed || o.revoked.Load() || o.sealed.Load() {
		return nil, ErrStreamOwned
	}
	a, q, f := o.admission, o.queue, o.flow.receive
	clock := a.engine.Clock()
	if !options.HardDeadline.BelongsTo(clock) {
		return nil, timev4.ErrOwner
	}
	if err := reservation.CheckSameEnvironment(o.reservation); err != nil {
		return nil, err
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		return nil, err
	}
	transferred := false
	defer func() {
		if !transferred {
			owned.Release()
		}
	}()
	start, err := clock.Sample()
	if err != nil {
		return nil, err
	}
	var deadline *timev4.Deadline
	if options.TimeoutMS == 0 {
		deadline, err = options.HardDeadline.Fork(options.HardDeadline.Cap())
	} else {
		deadline, err = options.HardDeadline.ForkAgeAt(start, options.TimeoutMS)
	}
	if err == nil && o.deadline != nil {
		err = deadline.TightenFrom(o.deadline)
	}
	if err != nil {
		return nil, err
	}
	c := &StreamConn{external: external, aborting: make(chan struct{}), owner: o, reservation: owned, deadline: deadline, clock: clock, parent: ctx, options: options,
		completion: q.completion, wake: make(chan struct{}, 1), workerWake: make(chan struct{}, 1), closeStart: make(chan struct{}), workerDone: make(chan struct{}), done: make(chan struct{}), ready: make(chan struct{})}
	a.mu.Lock()
	defer a.mu.Unlock()
	q.mu.Lock()
	defer q.mu.Unlock()
	f.pool.mu.Lock()
	defer f.pool.mu.Unlock()
	s, err := a.slot(o.handle)
	if err != nil {
		return nil, err
	}
	if a.closed || s.owner != o || s.cancelled || !s.accepted || q.writeOwner != o || f.readOwner != o || q.waiters != 0 || q.observers != 0 || q.methodTails != 0 || f.readPending || f.readTails != 0 || q.rawUsed || f.rawUsed || f.cleaned || q.closed || q.sealed {
		return nil, ErrStreamOwnershipBusy
	}
	if err := o.checkLifetime(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	minimum := f.minimumPromise
	if minimum == 0 && f.termination.service != nil {
		minimum = f.limit - f.released
	}
	if f.pool.closed || minimum > f.limit-f.released || minimum > uint64(len(f.storage)) || minimum != 0 && f.protection != nil && (f.protection.closed || f.protection.promise < minimum) {
		return nil, ErrCredit
	}
	if err := selectConnTermination(&o.flow.send.termination, &f.termination, options.FinishTimeoutMS); err != nil {
		return nil, err
	}
	if f.minimumPromise == 0 && minimum != 0 {
		f.minimumPromise = minimum
		f.creditAck, f.creditLimit = f.released, f.limit
	}
	if minimum != 0 {
		_ = f.protectCurrentCreditLocked()
	} // Preflight above used this same pool gate.
	c.signal.wake = c.wake
	o.conn = c
	o.connAbort = c.aborting
	o.connSignal.Store(&c.signal)
	o.notify()
	transferred = true
	go c.lifecycle(o)
	go c.supervise(a.engine.Done())
	return c, nil
}

func connNotify(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

type streamConnAddress struct{}

func (streamConnAddress) Network() string { return "flowersec" }
func (streamConnAddress) String() string  { return "application-stream" }
func (*StreamConn) LocalAddr() net.Addr   { return streamConnAddress{} }
func (*StreamConn) RemoteAddr() net.Addr  { return streamConnAddress{} }

// Close returns after local fencing. The original two workers retain every
// tail and report the real Finish/cleanup outcome independently of this return.
func (c *StreamConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closeLocked(nil)
	return nil
}

func (c *StreamConn) Abort() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closeLocked(ErrAbandoned)
}

func (c *StreamConn) closeLocked(cause error) {
	if c.complete || c.retired && c.external == nil {
		return
	}
	if c.retired && c.external != nil {
		select {
		case <-c.external.done:
			// Physical compound completion wins over a later cancellation,
			// independently of when the supervisor publishes that completion.
			return
		default:
		}
	}
	if cause != nil && c.first == nil {
		c.first = cause
	}
	if cause != nil && !c.aborted {
		c.aborted = true
		close(c.aborting)
		if !c.retired {
			_ = c.owner.Cancel()
		}
	}
	if !c.closed {
		// Both original I/O gates are held during sealing. A later read cannot
		// write to caller memory, and a later write cannot accept another byte.
		c.owner.sealApplication()
		f := c.owner.flow.receive
		f.pool.mu.Lock()
		f.closeCreditSealed = true
		f.pool.mu.Unlock()
		c.closed = true
		var err error
		if c.finish == nil {
			c.finish, err = timev4.NewWindow(c.clock, c.options.FinishTimeoutMS)
		}
		if err != nil && c.first == nil {
			c.first = err
		}
		if err != nil && !c.aborted {
			c.aborted = true
			close(c.aborting)
			_ = c.owner.Cancel()
		}
		for _, cancel := range c.ioCancel {
			if cancel != nil {
				cancel()
			}
		}
		close(c.closeStart)
	}
	connNotify(c.wake)
	connNotify(c.workerWake)
}

func (c *StreamConn) Result() (protocolv4.V4CloseResult, uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.resultLocked()
}

func (c *StreamConn) resultLocked() (protocolv4.V4CloseResult, uint64, error) {
	r, n := c.result, c.accepted
	if !c.complete && !c.retired {
		r, _ = c.owner.CloseResult()
		n = c.owner.AcceptedBytes()
		r.CleanupStatus.Status = protocolv4.V4CleanupStatePending
		if c.incomplete {
			r.CleanupStatus.Status = protocolv4.V4CleanupStateCleanupIncomplete
		}
	}
	if !c.complete {
		r.CleanupStatus.Status = protocolv4.V4CleanupStatePending
		if c.incomplete {
			r.CleanupStatus.Status = protocolv4.V4CleanupStateCleanupIncomplete
		}
	}
	if c.external != nil {
		r.CleanupStatus.PendingCallbacks = uint64(c.external.callbacks.Load())
	}
	return r, n, c.first
}

func (c *StreamConn) WaitCleanup(ctx context.Context) (protocolv4.V4CloseResult, error) {
	if ctx == nil {
		return protocolv4.V4CloseResult{}, cryptov4.ErrConfiguration
	}
	c.mu.Lock()
	if c.complete {
		r, _, err := c.resultLocked()
		c.mu.Unlock()
		return r, err
	}
	if c.waiter {
		c.mu.Unlock()
		return protocolv4.V4CloseResult{}, ErrStreamOwnershipBusy
	}
	tail, err := c.reservation.Borrow()
	if err != nil {
		c.mu.Unlock()
		return protocolv4.V4CloseResult{}, err
	}
	c.waiter = true
	c.mu.Unlock()
	defer func() { c.mu.Lock(); c.waiter = false; tail.Release(); c.mu.Unlock() }()
	select {
	case <-c.ready:
		r, _, err := c.Result()
		if r.CleanupStatus.Status != protocolv4.V4CleanupStateComplete && err == nil {
			err = ErrConnCleanupIncomplete
		}
		return r, err
	case <-ctx.Done():
		r, _, _ := c.Result()
		return r, ctx.Err()
	}
}

// CleanupStatus observes cleanup without closing or starting new work.
func (c *StreamConn) CleanupStatus() protocolv4.V4CleanupStatus {
	r, _, _ := c.Result()
	return r.CleanupStatus
}

// SendStatus remains usable after transport retirement and retains no owner.
func (c *StreamConn) SendStatus() SendStatus { return c.completion.snapshot() }
