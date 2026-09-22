package sessionv4

import (
	"context"
	"errors"
	"math"
	"net"
	"net/netip"
	"sync"
	"time"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

var ErrNativeTCPDial = errors.New("sessionv4: native TCP connection failed")
var ErrNativeTCPDialCanceled = errors.New("sessionv4: native TCP connection canceled")

type NativeTCPDialOptions struct {
	TimeoutMS, CleanupTimeoutMS, RuntimeBytes uint64
	HardDeadline                              *timev4.Deadline
	Endpoint                                  NativeTCPOptions
}

// NativeTCPDialCharge covers the supervisor, one real provider invocation and
// one bounded waiter. Endpoint native/socket charges are separately admitted.
// The pinned stdlib may make up to three sequential physical socket attempts
// inside that one invocation; no SDK retry or parallel fallback is performed.
func NativeTCPDialCharge(options NativeTCPDialOptions) (resourcev4.Vector, error) {
	fixed := uint64(unsafe.Sizeof(NativeTCPDial{})) + uint64(unsafe.Sizeof(timev4.Deadline{})) + uint64(unsafe.Sizeof(timev4.Window{}))
	if options.TimeoutMS == 0 || options.CleanupTimeoutMS == 0 || options.RuntimeBytes == 0 || options.RuntimeBytes > math.MaxUint64-fixed {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	if _, err := NativeTCPCharge(options.Endpoint); err != nil {
		return resourcev4.Vector{}, err
	}
	return resourcev4.Vector{resourcev4.SDKBytes: fixed + options.RuntimeBytes, resourcev4.Items: 1, resourcev4.Tasks: 3, resourcev4.WorkSlots: 3, resourcev4.Timers: 1}, nil
}

// NativeTCPDial separates logical cancellation from real provider exit. A
// pending Background dial cannot promise prompt physical cancellation. Its
// entire worker/socket allowance remains charged; a late connection is closed
// before it can be delivered. The handle creates no ordinary application task.
type NativeTCPDial struct {
	mu                         sync.Mutex
	reservation, socket        resourcev4.Reference
	deadline                   *timev4.Deadline
	clock                      *timev4.Clock
	cleanup                    *timev4.Window
	cleanupMS                  uint64
	operationContext           context.Context
	connection                 *NativeTCP
	first                      error
	delivered, available       bool
	waiting, signaled          bool
	complete, incomplete       bool
	faultClosed, doneClosed    bool
	ready, fault, handed, done chan struct{}
	providerDone               chan struct{}
}

// StartNativeTCPDial accepts only fixed numeric addresses. Name resolution and
// target authorization belong to the original caller's admitted factory stage.
// No user Dialer, callback, resolver, context hook or socket can be substituted.
func StartNativeTCPDial(ctx context.Context, clock *timev4.Clock, address netip.AddrPort, options NativeTCPDialOptions, reservation, socket resourcev4.Reference) (*NativeTCPDial, error) {
	d, worker, nativeTail, supervisor, err := prepareNativeTCPDial(ctx, clock, address, options, reservation, socket)
	if err != nil {
		return nil, err
	}
	go func() {
		defer func() { nativeTail.Release(); worker.Release(); close(d.providerDone) }()
		if err := d.admitProvider(); err != nil {
			d.settle(nil, err)
			return
		}
		network := "tcp6"
		if address.Addr().Is4() {
			network = "tcp4"
		}
		var dialer net.Dialer
		dialer.SetMultipathTCP(false)
		// Background skips Go's connect AfterFunc. That callback is not joined
		// by DialTCP on cancellation and cannot be refunded with its caller.
		conn, err := dialer.DialTCP(context.Background(), network, netip.AddrPort{}, address)
		if err == nil && !validNativeTCPAddresses(conn) {
			err = ErrNativeTCPDial
		}
		d.settle(conn, err)
	}()
	go d.supervise(supervisor)
	return d, nil
}

// The pinned net package can exhaust its self-connect retries with missing
// endpoint addresses. Never turn that provider edge into a process panic.
func validNativeTCPAddresses(conn *net.TCPConn) bool {
	if conn == nil {
		return false
	}
	local, localOK := conn.LocalAddr().(*net.TCPAddr)
	remote, remoteOK := conn.RemoteAddr().(*net.TCPAddr)
	return localOK && remoteOK && local != nil && remote != nil && local.AddrPort().IsValid() && remote.AddrPort().IsValid() && local.AddrPort() != remote.AddrPort()
}

// Preparation is separate from starting the two fixed tasks so original
// ownership and failure gates can be exercised without injectable dial code.
func prepareNativeTCPDial(ctx context.Context, clock *timev4.Clock, address netip.AddrPort, options NativeTCPDialOptions, reservation, socket resourcev4.Reference) (_ *NativeTCPDial, worker, nativeTail, supervisor resourcev4.Reference, err error) {
	charge, err := NativeTCPDialCharge(options)
	if err != nil || ctx == nil || !address.IsValid() || address.Port() == 0 || address.Addr().IsUnspecified() || address.Addr().IsMulticast() || address.Addr().Is4In6() || address.Addr().Zone() != "" {
		return nil, worker, nativeTail, supervisor, cryptov4.ErrConfiguration
	}
	if err = ctx.Err(); err != nil {
		return nil, worker, nativeTail, supervisor, err
	}
	if !options.HardDeadline.BelongsTo(clock) {
		return nil, worker, nativeTail, supervisor, timev4.ErrOwner
	}
	if reservation == socket {
		return nil, worker, nativeTail, supervisor, resourcev4.ErrOwner
	}
	if err = reservation.CheckSameEnvironment(socket); err != nil {
		return nil, worker, nativeTail, supervisor, err
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		return nil, worker, nativeTail, supervisor, err
	}
	d := &NativeTCPDial{reservation: owned, clock: clock, cleanupMS: options.CleanupTimeoutMS, operationContext: ctx, ready: make(chan struct{}), fault: make(chan struct{}), handed: make(chan struct{}), done: make(chan struct{}), providerDone: make(chan struct{})}
	defer func() {
		if err != nil {
			worker.Release()
			nativeTail.Release()
			supervisor.Release()
			d.socket.Release()
			owned.Release()
		}
	}()
	socketCharge, _ := NativeTCPCharge(options.Endpoint)
	d.socket, err = socket.Take(socketCharge)
	if err != nil {
		return nil, worker, nativeTail, supervisor, err
	}
	start, err := clock.Sample()
	if err == nil {
		d.deadline, err = options.HardDeadline.ForkAgeAt(start, options.TimeoutMS)
	}
	if err != nil {
		return nil, worker, nativeTail, supervisor, err
	}
	worker, err = owned.Borrow()
	if err == nil {
		nativeTail, err = d.socket.Borrow()
	}
	if err == nil {
		supervisor, err = owned.Borrow()
	}
	if err != nil {
		return nil, worker, nativeTail, supervisor, err
	}
	return d, worker, nativeTail, supervisor, nil
}

func (d *NativeTCPDial) failLocked(err error) {
	if err == nil || d.delivered || d.complete {
		return
	}
	if d.first == nil {
		if err != ErrNativeTCPDial && err != ErrNativeTCPDialCanceled {
			err = boundedReadCause(err)
		}
		d.first = err
		d.cleanup, _ = timev4.NewWindow(d.clock, d.cleanupMS)
	}
	if !d.faultClosed {
		d.faultClosed = true
		close(d.fault)
	}
}

func (d *NativeTCPDial) checkLocked() error {
	if d.first != nil {
		return d.first
	}
	if err := d.operationContext.Err(); err != nil {
		return err
	}
	if err := d.reservation.Check(); err != nil {
		return err
	}
	if d.connection != nil {
		d.connection.mu.Lock()
		err := d.connection.reservation.Check()
		d.connection.mu.Unlock()
		if err != nil {
			return err
		}
	} else if err := d.socket.Check(); err != nil {
		return err
	}
	return d.deadline.Check()
}

func (d *NativeTCPDial) signalLocked() {
	if !d.signaled {
		d.signaled = true
		close(d.ready)
	}
}

// admitProvider is the last original operation gate before entering the one
// physical provider invocation. Cancellation after this point seals delivery
// but cannot claim that an already admitted OS connect has stopped.
func (d *NativeTCPDial) admitProvider() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.failLocked(d.checkLocked())
	return d.first
}

// settle runs on the already admitted provider worker. It retains that worker
// and socket charge until either the exact endpoint is handed off or its real
// close returns. The deadline supervisor never blocks on native cleanup.
func (d *NativeTCPDial) settle(conn *net.TCPConn, err error) {
	d.mu.Lock()
	d.failLocked(d.checkLocked())
	if err != nil || conn == nil {
		d.failLocked(ErrNativeTCPDial)
	}
	if d.first == nil {
		// No primary alias escapes preparation. Rotate it again at the actual
		// owner transition; the provider's separate borrow pins the same backing.
		owned, takeErr := d.socket.Take(resourcev4.Vector{})
		if takeErr != nil {
			d.failLocked(takeErr)
		} else {
			d.connection = &NativeTCP{nativeTCPCore: &nativeTCPCore{conn: conn, clock: d.clock, reservation: owned, done: make(chan struct{})}}
			d.socket = resourcev4.Reference{}
			d.available = true
			d.signalLocked()
		}
	}
	candidate := d.connection
	d.mu.Unlock()
	if candidate != nil {
		select {
		case <-d.handed:
		case <-d.fault:
		}
		d.mu.Lock()
		delivered := d.delivered
		if !delivered {
			d.connection = nil
			d.available = false
		}
		d.mu.Unlock()
		if !delivered {
			_ = candidate.Close()
		}
	} else {
		if conn != nil {
			_ = conn.Close()
		}
		d.mu.Lock()
		d.socket.Release()
		d.socket = resourcev4.Reference{}
		d.mu.Unlock()
	}
}

// Cancel closes delivery immediately. It does not claim the native connect
// syscall or a late socket close has returned.
func (d *NativeTCPDial) Cancel() {
	d.mu.Lock()
	d.failLocked(ErrNativeTCPDialCanceled)
	d.mu.Unlock()
}

func (d *NativeTCPDial) supervise(reference resourcev4.Reference) {
	defer func() {
		d.mu.Lock()
		reference.Release()
		d.complete = true
		d.closeDoneLocked()
		d.mu.Unlock()
	}()
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	defer timer.Stop()
	ctx := d.operationContext
	providerDone := (<-chan struct{})(d.providerDone)
	fault := (<-chan struct{})(d.fault)
	exited := false
	for {
		d.mu.Lock()
		if d.delivered {
			d.mu.Unlock()
			<-d.providerDone
			d.finish()
			return
		}
		remaining, err := d.deadline.RemainingMS()
		if err == nil {
			err = d.checkLocked()
		}
		d.failLocked(err)
		failed := d.first != nil
		cleanup := d.cleanup
		d.mu.Unlock()
		if failed {
			if exited {
				d.finish()
				return
			}
			var cleanupErr error
			if cleanup == nil {
				cleanupErr = timev4.ErrUnavailable
			} else {
				remaining, cleanupErr = cleanup.RemainingMS()
			}
			if cleanupErr != nil {
				d.mu.Lock()
				d.incomplete = true
				d.signalLocked()
				d.mu.Unlock()
				<-d.providerDone
				d.finish()
				return
			}
		}
		timer.Reset(idleTimerChunk(remaining))
		select {
		case <-ctx.Done():
			d.mu.Lock()
			d.failLocked(ctx.Err())
			d.mu.Unlock()
			ctx = context.Background()
		case <-fault:
			fault = nil
		case <-d.handed:
		case <-providerDone:
			providerDone = nil
			exited = true
		case <-timer.C:
		}
		timer.Stop()
	}
}

func (d *NativeTCPDial) finish() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.signalLocked()
	d.deadline, d.operationContext, d.clock = nil, nil, nil
	d.reservation.Release()
	d.reservation = resourcev4.Reference{}
}

func (d *NativeTCPDial) takeLocked() (*NativeTCP, error) {
	if d.delivered {
		return d.connection, nil
	}
	if d.first != nil {
		return nil, d.first
	}
	if err := d.checkLocked(); err != nil {
		d.failLocked(err)
		return nil, d.first
	}
	if !d.available {
		return nil, ErrOpenPending
	}
	d.delivered = true
	close(d.handed)
	return d.connection, nil
}

// Wait only observes or hands off the original connection. Wait cancellation
// does not cancel the operation. The factory's context/deadline and Cancel own
// that separate authority. Repeated successful Wait returns the same endpoint.
func (d *NativeTCPDial) Wait(ctx context.Context) (*NativeTCP, error) {
	if ctx == nil {
		return nil, cryptov4.ErrConfiguration
	}
	d.mu.Lock()
	if err := ctx.Err(); err != nil {
		d.mu.Unlock()
		return nil, err
	}
	if d.signaled {
		n, err := d.takeLocked()
		d.mu.Unlock()
		return n, err
	}
	if d.waiting {
		d.mu.Unlock()
		return nil, ErrStreamOwnershipBusy
	}
	tail, err := d.reservation.Borrow()
	if err != nil {
		d.mu.Unlock()
		return nil, err
	}
	d.waiting = true
	d.mu.Unlock()
	defer func() {
		d.mu.Lock()
		d.waiting = false
		tail.Release()
		d.closeDoneLocked()
		d.mu.Unlock()
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-d.ready:
		d.mu.Lock()
		defer d.mu.Unlock()
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return d.takeLocked()
	}
}

func (d *NativeTCPDial) CleanupStatus() protocolv4.V4CleanupStatus {
	d.mu.Lock()
	defer d.mu.Unlock()
	c := protocolv4.V4CleanupStatus{Status: protocolv4.V4CleanupStatePending, CoreCleanup: protocolv4.V4CoreCleanupPending}
	if d.incomplete || d.cleanup != nil && d.cleanup.Check() != nil {
		c.Status = protocolv4.V4CleanupStateCleanupIncomplete
	}
	if d.complete && !d.waiting {
		c.Status, c.CoreCleanup = protocolv4.V4CleanupStateComplete, protocolv4.V4CoreCleanupComplete
	}
	return c
}

// The published operation outcome is independent of actual supervisor and
// admitted observer exit. Their references are released before Done closes.
func (d *NativeTCPDial) closeDoneLocked() {
	if d.complete && !d.waiting && !d.doneClosed {
		d.doneClosed = true
		d.cleanup = nil
		close(d.done)
	}
}

func (d *NativeTCPDial) Done() <-chan struct{} { return d.done }
