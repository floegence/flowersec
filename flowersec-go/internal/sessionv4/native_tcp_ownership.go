package sessionv4

import (
	"context"
	"net"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

// nativeTCPOwnership is the canonical full-endpoint claim. Only sealed SDK
// connections can create one, and the original socket stores its sole owner.
// Two existing bridge pumps share it; no additional task or I/O queue exists.
type nativeTCPOwnership struct {
	endpoint                      NativeTCP
	reservation, socketTail       resourcev4.Reference
	deadline                      *timev4.Deadline
	operationContext              context.Context
	revoked                       atomic.Bool
	users                         uint8 // guarded by endpoint.mu; includes real native method tails
	eof, sendFinished, readFailed bool
	changed                       chan struct{}
}

func NativeTCPOwnershipCharge() resourcev4.Vector {
	return resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(nativeTCPOwnership{})), resourcev4.Items: 1}
}

func (n *NativeTCP) own(reservation resourcev4.Reference, deadline *timev4.Deadline, ctx context.Context) (*nativeTCPOwnership, error) {
	if n == nil || n.nativeTCPCore == nil {
		return nil, ErrNativeTCPClosed
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return nil, ErrNativeTCPClosed
	}
	if n.owner != nil {
		return nil, ErrStreamOwned
	}
	if !deadline.BelongsTo(n.clock) {
		return nil, timev4.ErrOwner
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := deadline.Check(); err != nil {
		return nil, err
	}
	if err := reservation.CheckSameEnvironment(n.reservation); err != nil {
		return nil, err
	}
	owned, err := reservation.Take(NativeTCPOwnershipCharge())
	if err != nil {
		return nil, err
	}
	tail, err := n.reservation.Borrow()
	if err != nil {
		owned.Release()
		return nil, err
	}
	o := &nativeTCPOwnership{endpoint: *n, reservation: owned, socketTail: tail, deadline: deadline, operationContext: ctx, changed: make(chan struct{}, 1)}
	n.owner = o
	return o, nil
}

func (o *nativeTCPOwnership) notify() {
	select {
	case o.changed <- struct{}{}:
	default:
	}
}

// The original claim stays attached until all admitted pumps and native calls
// exit. Thus their lifetime checks need no mutable socket fields or lock order
// spanning a Flowersec receive/acceptance gate and a native I/O gate.
func (o *nativeTCPOwnership) checkLifetime() error {
	if o.revoked.Load() {
		return ErrStreamOwned
	}
	if err := o.operationContext.Err(); err != nil {
		return err
	}
	if err := o.deadline.Check(); err != nil {
		return err
	}
	if err := o.reservation.Check(); err != nil {
		return err
	}
	return o.socketTail.Check()
}

func (o *nativeTCPOwnership) begin() (*net.TCPConn, error) {
	n := o.endpoint
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.owner != o || n.closed {
		return nil, ErrNativeTCPClosed
	}
	if err := o.checkLifetime(); err != nil {
		return nil, err
	}
	if o.users == 4 {
		return nil, ErrStreamOwnershipBusy
	}
	o.users++
	return n.conn, nil
}

func (o *nativeTCPOwnership) end() {
	n := o.endpoint
	n.mu.Lock()
	o.users--
	n.closeDoneLocked()
	o.notify()
	n.mu.Unlock()
}

func (o *nativeTCPOwnership) enter() error {
	_, err := o.begin()
	if err == nil {
		o.end()
	}
	return err
}

func (o *nativeTCPOwnership) closeWrite() error {
	conn, err := o.begin()
	if err != nil {
		return err
	}
	defer o.end()
	n := o.endpoint
	n.mu.Lock()
	finished := o.sendFinished
	n.mu.Unlock()
	if finished {
		return nil
	}
	// The bridge has exactly one sequential send worker for this endpoint.
	// Successful return means local TCP shutdown after actual writes returned.
	if err := conn.CloseWrite(); err != nil {
		return ErrNativeTCPFailure
	}
	n.mu.Lock()
	o.sendFinished = true
	n.mu.Unlock()
	return nil
}

func (o *nativeTCPOwnership) finish() error {
	if _, err := o.begin(); err != nil {
		return err
	}
	defer o.end()
	n := o.endpoint
	n.mu.Lock()
	defer n.mu.Unlock()
	if !o.sendFinished {
		return ErrNativeTCPFailure
	}
	return nil
}

func (o *nativeTCPOwnership) revoke() { o.revoked.Store(true); o.notify() }

// Setting an already elapsed deadline wakes both netpoll directions without
// waiting for a worker or installing a future timer. The pinned private socket
// is never switched into blocking mode. The existing lifecycle worker performs
// Close; the supervisor does not wait for its native reference join.
func (o *nativeTCPOwnership) interrupt() {
	n := o.endpoint
	n.mu.Lock()
	if n.closed || n.owner != o {
		n.mu.Unlock()
		return
	}
	conn := n.conn
	o.users++
	n.mu.Unlock()
	_ = conn.SetDeadline(time.Unix(1, 0))
	o.end()
}

func (o *nativeTCPOwnership) closeResult() (protocolv4.V4CloseResult, bool) {
	n := o.endpoint
	n.mu.Lock()
	defer n.mu.Unlock()
	terminal := protocolv4.V4ReadTerminalOpen
	if o.eof {
		terminal = protocolv4.V4ReadTerminalEof
	} else if o.readFailed {
		terminal = protocolv4.V4ReadTerminalUnknown
	} else if n.closed {
		terminal = protocolv4.V4ReadTerminalAbandoned
	}
	cleanup := protocolv4.V4CleanupStatus{Status: protocolv4.V4CleanupStatePending, CoreCleanup: protocolv4.V4CoreCleanupPending}
	if n.complete && o.users == 0 {
		cleanup.Status, cleanup.CoreCleanup = protocolv4.V4CleanupStateComplete, protocolv4.V4CoreCleanupComplete
	}
	return protocolv4.V4CloseResult{ReadTerminal: terminal, CleanupStatus: cleanup}, o.sendFinished
}

func (o *nativeTCPOwnership) release() error {
	n := o.endpoint

	n.mu.Lock()
	defer n.mu.Unlock()
	if o.users != 0 || n.closed && !n.complete {
		return ErrStreamOwnershipBusy
	}
	o.revoked.Store(true)
	n.owner = nil
	o.socketTail.Release()
	o.reservation.Release()
	o.socketTail, o.reservation = resourcev4.Reference{}, resourcev4.Reference{}
	o.deadline, o.operationContext = nil, nil
	return nil
}
