package sessionv4

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"math"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

type serviceDurableRead struct {
	history                 *rpcv4.DurableExecutions
	publisher               *rpcv4.Publisher
	ticket                  rpcv4.Ticket
	target                  rpcv4.ExecutionTarget
	access                  rpcv4.ExecutionAccess
	metadata                resourcev4.Reference
	busy, complete, retired bool
}

func (d *ServiceDispatch) admitDurableRead(publisher *rpcv4.Publisher, ticket rpcv4.Ticket, target rpcv4.ExecutionTarget, access rpcv4.ExecutionAccess, history *rpcv4.DurableExecutions, deadline *timev4.Deadline) error {
	refuse := func(err error) error { _ = publisher.QueueRefusal(ticket, serviceRefusal(err)); return err }
	if d.durableWake == nil {
		return refuse(rpcv4.ErrExecutionUnsupported)
	}
	invocation, err := serviceInvocationCharge(d.runtimeBytes)
	if err == nil {
		invocation, err = invocation.Add(resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(serviceDurableRead{})) + 4*128, resourcev4.Items: 1})
	}
	if err != nil {
		return refuse(err)
	}
	read, err := rpcv4.DurableExecutionResultReadCharge(1048576, d.runtimeBytes)
	if err != nil {
		return refuse(err)
	}
	d.mu.Lock()
	if d.closed || d.serial == math.MaxUint64 {
		d.mu.Unlock()
		return refuse(cryptov4.ErrClosed)
	}
	index := -1
	for n, slot := range d.slots {
		if slot == nil {
			index = n
			break
		}
	}
	if index < 0 {
		d.mu.Unlock()
		return refuse(cryptov4.ErrCapacity)
	}
	d.serial++
	serial := d.serial
	ctx, cancel := context.WithCancelCause(context.Background())
	i := &serviceInvocation{dispatcher: d, plan: d.plan, ctx: ctx, cancel: cancel, deadline: deadline, durableRead: &serviceDurableRead{history: history, publisher: publisher, ticket: ticket, target: target, access: access}}
	d.slots[index] = i
	d.active++
	d.mu.Unlock()
	var refs [2]resourcev4.Reference
	var requests [2]resourcev4.Request
	for n, charge := range [2]resourcev4.Vector{invocation, read} {
		owner := d.owner
		var seed [56]byte
		copy(seed[:16], owner.Instance[:])
		copy(seed[16:32], owner.Backing[:])
		copy(seed[32:40], "dur-read")
		binary.BigEndian.PutUint64(seed[40:48], serial)
		binary.BigEndian.PutUint64(seed[48:], uint64(n))
		digest := sha256.Sum256(seed[:])
		copy(owner.Instance[:], digest[:16])
		copy(owner.Backing[:], digest[16:])
		requests[n] = resourcev4.Request{Owner: owner, Charge: charge, Accounts: d.accounts[:d.accountCount]}
	}
	err = d.root.ReserveBatch(requests[:], refs[:])
	if err != nil {
		cancel(err)
		d.rollback(index, i)
		return refuse(err)
	}
	// Each vector already belongs to this exact request. The provider capture
	// consumes the complete result reservation before allocating its bytes.
	i.mu.Lock()
	i.reservation, i.durableRead.metadata = refs[0], refs[1]
	i.started = true
	i.mu.Unlock()
	d.signalDurable()
	return nil
}

func (d *ServiceDispatch) stepDurableRead(i *serviceInvocation, r *serviceDurableRead) {
	var failure error
	defer func() {
		if recover() != nil {
			failure = ErrCompletionCallbackExit
		}
		if failure != nil {
			_ = r.publisher.QueueRefusal(r.ticket, serviceRefusal(failure))
		}
		r.metadata.Release()
		i.mu.Lock()
		r.metadata = resourcev4.Reference{}
		r.busy = false
		r.complete = true
		i.mu.Unlock()
	}()
	if failure = i.ctx.Err(); failure != nil {
		return
	}
	if failure = i.deadline.Check(); failure != nil {
		return
	}
	read, err := r.history.CaptureResult(i.ctx, r.target, r.access, r.metadata, 1048576, d.runtimeBytes)
	if err != nil {
		failure = err
		return
	}
	defer read.Close()
	if failure = i.ctx.Err(); failure != nil {
		return
	}
	_, failure = r.publisher.QueueResultRead(r.ticket, read, i.deadline)
}

func (d *ServiceDispatch) advanceDurableRead(index int, i *serviceInvocation, closed bool) {
	i.mu.Lock()
	r := i.durableRead
	i.mu.Unlock()
	if closed {
		i.stop(cryptov4.ErrClosed)
	} else {
		err := r.access.WithExecutionAccess(r.target, func(resourcev4.Reference) error { return i.deadline.Check() })
		if err != nil {
			i.stop(err)
		}
	}
	d.signalDurable()
	i.mu.Lock()
	if r.busy || !r.complete {
		i.mu.Unlock()
		return
	}
	r.retired = true
	i.closed = true
	i.cancel(cryptov4.ErrClosed)
	i.reservation.Release()
	i.reservation = resourcev4.Reference{}
	i.dispatcher, i.plan = nil, nil
	i.mu.Unlock()
	d.mu.Lock()
	d.slots[index] = nil
	d.active--
	d.mu.Unlock()
	d.signalDurable()
}
