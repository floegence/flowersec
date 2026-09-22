package sessionv4

import (
	"context"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/rpcv4"
)

func (d *NotificationDispatch) admitDurableNotification(message *rpcv4.NotifyMessage, history *rpcv4.DurableExecutions, access *notificationExecutionAccess, registration NotificationMethod) (bool, error) {
	deadline, err := message.MessageDeadline(d.clock)
	if err != nil {
		return false, err
	}
	if err = deadline.Check(); err != nil {
		return false, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed || d.durableProvider == nil {
		return false, rpcv4.ErrClosed
	}
	index := -1
	for n, current := range d.executions {
		if current == nil {
			index = n
			break
		}
	}
	if index < 0 {
		return false, rpcv4.ErrCapacity
	}
	charge, err := (resourcev4.Vector{resourcev4.SDKBytes: applicationContextBytes() + uint64(unsafe.Sizeof(notificationExecution{})) + uint64(unsafe.Sizeof(notificationExecutionAccess{})) + 3*128, resourcev4.Items: 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: d.deliveryRuntimeBytes})
	if err != nil {
		return false, err
	}
	var refs [1]resourcev4.Reference
	if err = d.reserveLocked([]resourcev4.Vector{charge}, refs[:]); err != nil {
		return false, err
	}
	ctx, cancel := context.WithCancelCause(context.Background())
	i := &notificationExecution{dispatch: d, method: registration, access: access, deadline: deadline, ctx: ctx, cancel: cancel, reservation: refs[0], subscriberBoundary: d.serial, started: true, durableHistory: history, message: message}
	d.executions[index] = i
	d.durableProvider.signalDurable()
	return true, nil
}

// The one existing Session provider task visits the original notification
// execution slots. An observation never enters this provider path or waits on
// its database; observers remain on their original bounded dispatch queues.
func (d *NotificationDispatch) stepDurableNotifications() {
	d.mu.Lock()
	turns := min(8, len(d.executions))
	d.mu.Unlock()
	for range turns {
		d.mu.Lock()
		if len(d.executions) == 0 {
			d.mu.Unlock()
			return
		}
		i := d.executions[d.durableCursor]
		d.durableCursor = (d.durableCursor + 1) % len(d.executions)
		if i == nil || i.durableHistory == nil || i.providerBusy || i.providerDone {
			d.mu.Unlock()
			continue
		}
		i.providerBusy = true
		d.mu.Unlock()
		d.stepDurableNotification(i)
	}
}
func (d *NotificationDispatch) stepDurableNotification(i *notificationExecution) {
	defer func() {
		if recover() != nil {
			d.mu.Lock()
			i.stopLocked(ErrCompletionCallbackExit)
			d.lastExecutionRejection = "service_failed"
			d.mu.Unlock()
		}
		d.mu.Lock()
		i.providerBusy = false
		d.mu.Unlock()
	}()
	d.mu.Lock()
	admitted, canceled := i.providerAdmitted, i.canceled
	d.mu.Unlock()
	if !admitted {
		var work *rpcv4.DurableExecutionWork
		var err error
		if canceled {
			err = rpcv4.ErrClosed
		} else {
			_, work, err = i.message.AdmitDurableExecution(i.ctx, i.durableHistory, i.access.caller, i.access, func(task, backing resourcev4.Reference) error {
				// The original access callback holds this dispatcher gate.
				if i.canceled || d.closed {
					return rpcv4.ErrClosed
				}
				var err error
				i.queued, err = d.plan.executor.prepareApplication(d.plan.applicationGroup, i.method.WorkClass, task, backing)
				return err
			})
		}
		i.message.Close()
		d.mu.Lock()
		i.message = nil
		i.durableWork = work
		i.providerAdmitted = true
		d.mu.Unlock()
		if err == nil && work != nil {
			err = work.SubmitTask(func() (<-chan struct{}, error) {
				d.mu.Lock()
				defer d.mu.Unlock()
				if d.closed || i.canceled {
					return nil, rpcv4.ErrClosed
				}
				if err := i.queued.startPrepared(i.runDurable); err != nil {
					return nil, err
				}
				return i.queued.Done(), nil
			})
		}
		if work == nil || err != nil {
			d.mu.Lock()
			if i.queued != nil {
				i.queued.Cancel()
			}
			if err != nil {
				i.stopLocked(err)
				d.lastExecutionRejection = serviceRefusal(err)
			}
			d.mu.Unlock()
		}
	}
	d.mu.Lock()
	done := true
	if i.queued != nil {
		select {
		case <-i.queued.Done():
		default:
			done = false
		}
	}
	d.mu.Unlock()
	if !done {
		return
	}
	if i.durableWork != nil {
		if err := i.durableWork.Exit(context.Background()); err != nil {
			return
		}
	}
	d.mu.Lock()
	i.providerDone = true
	d.mu.Unlock()
}

func (i *notificationExecution) runDurable() {
	defer func() { _ = recover() }()
	ctx, err := i.durableWork.Context(i.ctx)
	if err != nil {
		return
	}
	input, err := i.durableWork.Enter(ctx)
	if err != nil {
		return
	}
	payload, _, err := input.Bytes()
	if err != nil {
		return
	}
	d := i.dispatch
	var request NotificationRequest
	err = d.withAuthority(i.method.Method, func(notificationMethod) error {
		if i.ctx.Err() != nil {
			return rpcv4.ErrClosed
		}
		if err := i.deadline.Check(); err != nil {
			return err
		}
		for _, token := range d.tokens {
			if token != nil && !token.closed && token.method.method.Method == i.method.Method && token.subscription.identity <= i.subscriberBoundary {
				if err := token.enqueueLocked(i.deadline, payload); err != nil {
					token.gapLocked("dropped_budget")
				}
			}
		}
		request = NotificationRequest{Binding: d.plan.lease.binding, ApplicationContext: d.plan.lease.context, Input: input}
		return nil
	})
	if err != nil || i.durableWork.CheckContinuation(ctx) != nil {
		return
	}
	callCtx, exit, err := enterApplicationContext(ctx, d.plan.executor, ordinaryApplicationLane, i.method.WorkClass, i.reservation, nil)
	if err != nil {
		return
	}
	defer exit()
	if i.method.ExecutionHandler(callCtx, request) == nil {
		_ = i.durableWork.Finish(context.Background(), 0, nil)
	}
}

func (d *NotificationDispatch) advanceDurableNotification(index int, i *notificationExecution) {
	err := i.access.WithExecutionAccess(rpcv4.ExecutionTarget{Service: i.access.service, Caller: i.access.caller}, func(resourcev4.Reference) error { return i.deadline.Check() })
	d.mu.Lock()
	defer d.mu.Unlock()
	if err != nil {
		i.stopLocked(err)
	}
	if d.durableProvider != nil {
		d.durableProvider.signalDurable()
	}
	if !i.providerDone || i.providerBusy {
		return
	}
	i.durableWork = nil
	i.durableHistory = nil
	i.retireLocked()
	d.executions[index] = nil
}
