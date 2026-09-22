package sessionv4

import (
	"context"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

// NotificationRequest carries the original authenticated context and one
// invocation-scoped input. NOTIFY never exposes a response or output interest.
type NotificationRequest struct {
	Binding            ApplicationBinding
	ApplicationContext any
	Input              rpcv4.InputBorrow
}

type notificationExecutionAccess struct {
	dispatcher *NotificationDispatch
	method     uint32
	service    rpcv4.ExecutionService
	caller     rpcv4.ExecutionPrincipal
}

func (a *notificationExecutionAccess) WithExecutionAccess(target rpcv4.ExecutionTarget, action func(resourcev4.Reference) error) error {
	if a == nil || a.dispatcher == nil || action == nil || target.Service != a.service || target.Caller != a.caller {
		return ErrApplicationAuthorization
	}
	d := a.dispatcher
	return d.withAuthority(a.method, func(m notificationMethod) error {
		// withAuthority holds the original lease and dispatcher gates throughout
		// this finite action; revocation and close cannot overtake registration.
		identity, err := d.plan.lease.executionIdentityLocked()
		if err != nil || identity.Tenant != a.service.Tenant || identity.Audience != a.service.Audience || identity.Caller != a.caller || m.policy.Namespace != a.service.Namespace || m.method.ExecutionHandler == nil {
			return ErrApplicationAuthorization
		}
		return action(d.reservation)
	})
}

// Fields are immutable after publication except started/canceled, which share
// the dispatcher gate. The coordinator retires this owner only after real Done.
type notificationExecution struct {
	durableHistory                               *rpcv4.DurableExecutions
	durableWork                                  *rpcv4.DurableExecutionWork
	message                                      *rpcv4.NotifyMessage
	providerBusy, providerAdmitted, providerDone bool
	dispatch                                     *NotificationDispatch
	method                                       NotificationMethod
	access                                       *notificationExecutionAccess
	work                                         *rpcv4.ExecutionWork
	queued                                       *QueuedApplicationTask
	deadline                                     *timev4.Deadline
	ctx                                          context.Context
	cancel                                       context.CancelCauseFunc
	reservation                                  resourcev4.Reference
	subscriberBoundary                           uint64
	started, canceled                            bool
}

func (d *NotificationDispatch) admitExecution(message *rpcv4.NotifyMessage, method uint32, policy protocolv4.ServiceContractPolicy) (bool, error) {
	if policy.Shape != 2 || policy.ExecutionMode > 1 || policy.RetainedContent {
		return false, rpcv4.ErrExecutionUnsupported
	}
	var access *notificationExecutionAccess
	var registry *rpcv4.ServiceRegistry
	var registration NotificationMethod
	err := d.withAuthority(method, func(m notificationMethod) error {
		if m.policy.Namespace != policy.Namespace || m.policy.Type != policy.Type || m.policy.Semantics != 1 || m.method.ExecutionHandler == nil || d.executionRegistry == nil {
			return rpcv4.ErrMethod
		}
		identity, err := d.plan.lease.executionIdentityLocked()
		if err != nil {
			return err
		}
		access = &notificationExecutionAccess{dispatcher: d, method: method, service: rpcv4.ExecutionService{Tenant: identity.Tenant, Audience: identity.Audience, Namespace: policy.Namespace}, caller: identity.Caller}
		registry, registration = d.executionRegistry, m.method
		return nil
	})
	if err != nil {
		return false, err
	}
	binding, err := registry.Lookup(rpcv4.ServiceAuthority{Tenant: access.service.Tenant, Audience: access.service.Audience, Namespace: access.service.Namespace})
	if err == nil && policy.Checkpoint && (policy.ExecutionMode != 1 || binding.Recovery == nil) {
		err = rpcv4.ErrExecutionUnsupported
	}
	if err != nil {
		return false, err
	}
	if policy.ExecutionMode == 1 {
		if binding.DurableHistory == nil {
			return false, rpcv4.ErrExecutionUnsupported
		}
		return d.admitDurableNotification(message, binding.DurableHistory, access, registration)
	}
	if binding.History == nil {
		return false, rpcv4.ErrExecutionUnsupported
	}
	var invocation *notificationExecution
	index := -1
	_, work, err := message.AdmitExecution(context.Background(), binding.History, access.caller, access, func(task, backing resourcev4.Reference, deadline *timev4.Deadline) error {
		// History calls this only for a first registration, with the original
		// authorization/dispatcher gates held. Existing records need no slot.
		for i, current := range d.executions {
			if current == nil {
				index = i
				break
			}
		}
		if index < 0 {
			return rpcv4.ErrCapacity
		}
		charge, err := (resourcev4.Vector{resourcev4.SDKBytes: applicationContextBytes() + uint64(unsafe.Sizeof(notificationExecution{})) + uint64(unsafe.Sizeof(notificationExecutionAccess{})) + 3*128, resourcev4.Items: 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: d.deliveryRuntimeBytes})
		if err != nil {
			return err
		}
		var refs [1]resourcev4.Reference
		if err = d.reserveLocked([]resourcev4.Vector{charge}, refs[:]); err != nil {
			return err
		}
		queued, err := d.plan.executor.prepareApplication(d.plan.applicationGroup, registration.WorkClass, task, backing)
		if err != nil {
			refs[0].Release()
			return err
		}
		ctx, cancel := context.WithCancelCause(context.Background())
		invocation = &notificationExecution{dispatch: d, method: registration, access: access, queued: queued, deadline: deadline, ctx: ctx, cancel: cancel, reservation: refs[0], subscriberBoundary: d.serial}
		d.executions[index] = invocation
		return nil
	})
	if err != nil || work == nil {
		return false, err
	}
	invocation.work = work
	err = work.SubmitTask(func(_, _ resourcev4.Reference) (<-chan struct{}, error) {
		d.mu.Lock()
		defer d.mu.Unlock()
		if d.closed {
			return nil, rpcv4.ErrClosed
		}
		if err := invocation.queued.startPrepared(invocation.run); err != nil {
			return nil, err
		}
		return invocation.queued.Done(), nil
	})
	if err != nil {
		// Submission failed without starting a task. The admitted fact remains
		// in history while this original prepared task is canceled and retired.
		invocation.queued.Cancel()
		_ = work.Exit()
		_ = work.Release()
		d.mu.Lock()
		invocation.retireLocked()
		d.executions[index] = nil
		d.mu.Unlock()
		return false, err
	}
	d.mu.Lock()
	invocation.started = true
	if d.closed {
		invocation.stopLocked(rpcv4.ErrClosed)
	}
	d.mu.Unlock()
	return false, nil
}

func (i *notificationExecution) run() {
	// A panic or Goexit leaves an unreported dispatch. Exit records unknown
	// only after the executor confirms actual callback exit, without a response.
	defer func() { _ = recover() }()
	ctx, err := i.work.Context(i.ctx)
	if err != nil {
		return
	}
	input, err := i.work.Enter()
	if err != nil {
		return
	}
	payload, _, err := input.Bytes()
	if err != nil {
		return
	}
	var request NotificationRequest
	d := i.dispatch
	err = d.withAuthority(i.method.Method, func(notificationMethod) error {
		if i.ctx.Err() != nil {
			return rpcv4.ErrClosed
		}
		if err := i.deadline.Check(); err != nil {
			return err
		}
		// Capture each eligible observer's isolated bytes before the business
		// handler can mutate its input. A later subscription gets no old event.
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
	if err != nil || i.work.CheckContinuation() != nil {
		return
	}
	callCtx, exit, err := enterApplicationContext(ctx, d.plan.executor, ordinaryApplicationLane, i.method.WorkClass, i.reservation, nil)
	if err != nil {
		return
	}
	defer exit()
	if i.method.ExecutionHandler(callCtx, request) == nil {
		_ = i.work.Finish(0, nil)
	}
}

func (i *notificationExecution) stopLocked(reason error) {
	if !i.canceled {
		i.canceled = true
		i.cancel(reason)
		if i.queued != nil {
			i.queued.Cancel()
		}
	}
}

func (i *notificationExecution) retireLocked() {
	i.cancel(rpcv4.ErrClosed)
	i.reservation.Release()
	i.reservation = resourcev4.Reference{}
	i.dispatch, i.access, i.work, i.queued, i.deadline = nil, nil, nil, nil, nil
	i.ctx, i.cancel = nil, nil
	i.method = NotificationMethod{}
}

func (d *NotificationDispatch) advanceExecutions() {
	for index := range d.executions {
		d.mu.Lock()
		i := d.executions[index]
		ready := i != nil && i.started
		d.mu.Unlock()
		if !ready {
			continue
		}
		if i.durableHistory != nil {
			d.advanceDurableNotification(index, i)
			continue
		}
		err := i.access.WithExecutionAccess(rpcv4.ExecutionTarget{Service: i.access.service, Caller: i.access.caller}, func(resourcev4.Reference) error { return nil })
		if err == nil {
			err = i.deadline.Check()
		}
		select {
		case <-i.work.Cancellation():
			err = rpcv4.ErrClosed
		default:
		}
		d.mu.Lock()
		if err != nil {
			i.stopLocked(err)
		}
		done := false
		select {
		case <-i.queued.Done():
			done = true
		default:
		}
		d.mu.Unlock()
		if !done || i.work.Exit() != nil {
			continue
		}
		_ = i.work.Release()
		d.mu.Lock()
		i.retireLocked()
		d.executions[index] = nil
		d.mu.Unlock()
	}
}
