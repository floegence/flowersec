package sessionv4

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/rpcv4"
)

type serviceExecution struct {
	durableAdmission                                       *rpcv4.DurableExecutionAdmission
	durableHistory                                         *rpcv4.DurableExecutions
	durableWork                                            *rpcv4.DurableExecutionWork
	durableJoin                                            *rpcv4.DurableExecutionJoin
	joinReservation                                        resourcev4.Reference
	providerBusy, providerRetired, admissionDone, exitDone bool
	work                                                   *rpcv4.ExecutionWork
	join                                                   *rpcv4.ExecutionJoin
	access                                                 *serviceExecutionAccess
	offset                                                 uint32
	outputFinished                                         bool
	permit                                                 *ApplicationPermit
	scratch                                                [4096]byte
}

// Execution output/response/join backing is acquired before history admission
// or application entry. The history transfers its own single task reservation;
// a duplicate never reserves another application task or decodes the payload.
func executionCallCharges(runtimeBytes uint64, limit uint32) (v [5]resourcev4.Vector, err error) {
	v[0], err = serviceInvocationCharge(runtimeBytes)
	if err == nil {
		v[0], err = v[0].Add(resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(serviceExecution{})) + uint64(unsafe.Sizeof(serviceExecutionAccess{})) + 3*128, resourcev4.Items: 1})
	}
	if err != nil {
		return
	}
	v[1], err = rpcv4.AcceptedResultCharge(runtimeBytes)
	if err != nil {
		return
	}
	v[2], err = rpcv4.AcceptedResultSourceCharge(limit, runtimeBytes)
	if err != nil {
		return
	}
	v[3], err = rpcv4.OutputObservationCharge(runtimeBytes)
	if err != nil {
		return
	}
	v[4], err = rpcv4.ExecutionJoinCharge(runtimeBytes)
	return
}
func (d *ServiceDispatch) admitExecution(publisher *rpcv4.Publisher, ticket rpcv4.Ticket, input *rpcv4.VerifiedInput, method uint32, policy protocolv4.ServiceContractPolicy, header protocolv4.ApplicationHeader) (adopted bool, err error) {
	refuse := func(reason string, cause error) (bool, error) {
		_ = publisher.QueueRefusal(ticket, reason)
		return false, cause
	}
	if policy.ExecutionMode > 1 || policy.RetainedContent {
		return refuse("method_unavailable", rpcv4.ErrExecutionUnsupported)
	}
	binding, access, err := d.executionBindingAuthority(method, policy.Namespace)
	if err != nil {
		return refuse("permission_denied", err)
	}
	if policy.Checkpoint && (policy.ExecutionMode != 1 || binding.Recovery == nil) {
		return refuse("method_unavailable", rpcv4.ErrExecutionUnsupported)
	}
	history := binding.History
	if policy.ExecutionMode == 0 && history == nil || policy.ExecutionMode == 1 && (binding.DurableHistory == nil || d.durableWake == nil) {
		return refuse("method_unavailable", rpcv4.ErrExecutionUnsupported)
	}
	d.mu.Lock()
	if d.closed || d.serial == math.MaxUint64 {
		d.mu.Unlock()
		return refuse("service_unavailable", cryptov4.ErrClosed)
	}
	index := -1
	for j, x := range d.slots {
		if x == nil {
			index = j
			break
		}
	}
	var registration UnaryRegistration
	allowed := false
	for _, m := range d.methods {
		if m.registration.Method == method && m.registration.Namespace == policy.Namespace && m.registration.Type == policy.Type {
			registration = m.registration
			allowed = m.allowed
			break
		}
	}
	if !allowed {
		d.mu.Unlock()
		return refuse("permission_denied", ErrApplicationAuthorization)
	}
	if registration.Resume {
		d.mu.Unlock()
		return refuse("method_unavailable", rpcv4.ErrExecutionUnsupported)
	}
	if index < 0 || registration.WorkClass == ApplicationResident && d.resident == d.residentLimit {
		d.mu.Unlock()
		return refuse("resource_exhausted", cryptov4.ErrCapacity)
	}
	ctx, cancel := context.WithCancelCause(context.Background())
	i := &serviceInvocation{dispatcher: d, plan: d.plan, method: registration, header: header, input: input, ctx: ctx, cancel: cancel, execution: &serviceExecution{access: access, durableHistory: binding.DurableHistory}}
	i.response.invocation = i
	d.slots[index] = i
	d.active++
	d.serial++
	if registration.WorkClass == ApplicationResident {
		d.resident++
	}
	serial := d.serial
	var admission *rpcv4.ExecutionAdmission
	if registration.WorkClass == ApplicationShort && header.Fields().ResponseLimitBytes <= d.shortResponseBytes {
		for _, floor := range d.executionFloors {
			if history != nil && floor.history == history {
				admission = floor.admission
				break
			}
			if binding.DurableHistory != nil && floor.durableHistory == binding.DurableHistory {
				i.execution.durableAdmission = floor.durableAdmission
				break
			}
		}
	}
	d.mu.Unlock()
	success := false
	defer func() {
		if !success {
			cancel(cryptov4.ErrClosed)
			if i.execution.permit != nil {
				i.execution.permit.Close()
			}
			if i.queued != nil {
				i.queued.Cancel()
			}
			if i.execution.work != nil {
				_ = i.execution.work.Exit()
				_ = i.execution.work.Release()
			}
			if i.execution.join != nil {
				i.execution.join.Close()
			}
			d.rollback(index, i)
		}
	}()
	i.deadline, err = input.MessageDeadline(d.clock)
	if err != nil {
		return refuse(serviceRefusal(err), err)
	}
	charges, err := executionCallCharges(d.runtimeBytes, header.Fields().ResponseLimitBytes)
	if err == nil && binding.DurableHistory != nil {
		charges[4], err = rpcv4.DurableExecutionJoinCharge(header.Fields().ResponseLimitBytes, d.runtimeBytes)
	}
	if err != nil {
		return refuse("resource_exhausted", err)
	}
	var requests [5]resourcev4.Request
	var refs [5]resourcev4.Reference
	for j, charge := range charges {
		owner := d.owner
		var seed [56]byte
		copy(seed[:16], owner.Instance[:])
		copy(seed[16:32], owner.Backing[:])
		copy(seed[32:40], "exec-rpc")
		binary.BigEndian.PutUint64(seed[40:48], serial)
		binary.BigEndian.PutUint64(seed[48:], uint64(j))
		hash := sha256.Sum256(seed[:])
		copy(owner.Instance[:], hash[:16])
		copy(owner.Backing[:], hash[16:])
		requests[j] = resourcev4.Request{Owner: owner, Charge: charge, Accounts: d.accounts[:d.accountCount]}
	}
	ready := admission != nil && admission.CheckReady() == nil || i.execution.durableAdmission != nil && i.execution.durableAdmission.CheckReady() == nil
	protected := ready && resourcev4.CheckoutProtectedBatch(d.shortExecution[:], refs[:]) == nil
	if !protected {
		admission = nil
		i.execution.durableAdmission = nil
		if err = d.root.ReserveBatch(requests[:], refs[:]); err != nil {
			return refuse("resource_exhausted", err)
		}
	}
	defer func() {
		for _, ref := range refs {
			ref.Release()
		}
	}()
	i.reservation, err = refs[0].Take(charges[0])
	if err != nil {
		return refuse("resource_exhausted", err)
	}
	i.result, err = publisher.NewAcceptedResult(ticket, input, refs[1], refs[2], d.runtimeBytes)
	if err != nil {
		return refuse(serviceRefusal(err), err)
	}
	i.writer, err = i.result.Writer()
	if err != nil {
		return refuse(serviceRefusal(err), err)
	}
	i.observation, err = d.network.NewOutputObservation(ticket, ctx, refs[3], d.runtimeBytes)
	if err != nil {
		return refuse(serviceRefusal(err), err)
	}
	if binding.DurableHistory != nil {
		i.execution.joinReservation, err = refs[4].Take(charges[4])
		if err != nil {
			return refuse(serviceRefusal(err), err)
		}
		i.mu.Lock()
		i.started = true
		i.mu.Unlock()
		success, adopted = true, true
		d.signalDurable()
		return true, nil
	}
	reserve := func(task, backing resourcev4.Reference) error {
		// No callback or dispatch right exists during the history admission gate.
		if header.Fields().AdmissionMode == 1 {
			i.execution.permit, err = d.plan.executor.TryAcquire(registration.WorkClass, task, backing)
		} else {
			i.queued, err = d.plan.executor.prepareApplication(d.plan.applicationGroup, registration.WorkClass, task, backing)
		}
		return err
	}
	var work *rpcv4.ExecutionWork
	var join *rpcv4.ExecutionJoin
	if admission != nil {
		_, work, join, err = d.consumer.AdmitReservedExecution(ctx, history, input, access.caller, access, refs[4], d.runtimeBytes, admission, reserve)
	} else {
		_, work, join, err = d.consumer.AdmitExecution(ctx, history, input, access.caller, access, refs[4], d.runtimeBytes, reserve)
	}
	if err != nil {
		return refuse(serviceRefusal(err), err)
	}
	i.execution.work, i.execution.join = work, join
	if work != nil {
		err = work.SubmitTask(func(_, _ resourcev4.Reference) (<-chan struct{}, error) {
			i.mu.Lock()
			defer i.mu.Unlock()
			if i.closed {
				return nil, cryptov4.ErrClosed
			}
			if header.Fields().AdmissionMode == 1 {
				i.task, err = i.execution.permit.Start(i.runExecution)
				if err != nil {
					return nil, err
				}
				return i.task.Done(), nil
			}
			err = i.queued.startPrepared(i.runExecution)
			if err != nil {
				return nil, err
			}
			return i.queued.Done(), nil
		})
		if err != nil {
			return refuse(serviceRefusal(err), err)
		}
	}
	i.mu.Lock()
	i.started = true
	i.mu.Unlock()
	success, adopted = true, true
	return true, nil
}
func (i *serviceInvocation) runExecution() {
	work := i.execution.work
	returned := false
	failure := error(ErrCompletionCallbackExit)
	defer func() {
		if recover() != nil || !returned {
			failure = ErrCompletionCallbackExit
		}
		i.mu.Lock()
		i.returned = true
		if failure != nil && !i.execution.outputFinished {
			reason := serviceRefusal(failure)
			if errors.Is(failure, ErrCompletionCallbackExit) {
				reason = "service_failed"
			}
			_ = i.result.Refuse(reason)
			i.result.Close()
			i.execution.outputFinished = true
		}
		i.observation.EndInvocation()
		i.mu.Unlock()
	}()
	ctx, err := work.Context(i.ctx)
	if err != nil {
		failure = err
		returned = true
		return
	}
	input, err := work.Enter()
	if err != nil {
		failure = err
		returned = true
		return
	}
	i.plan.lease.mu.Lock()
	request := UnaryRequest{Binding: i.plan.lease.binding, ApplicationContext: i.plan.lease.context, Input: input, OutputInterest: i.observation.View()}
	i.plan.lease.mu.Unlock()
	callCtx, exit, err := enterApplicationContext(ctx, i.plan.executor, ordinaryApplicationLane, i.method.WorkClass, i.reservation, nil)
	if err != nil {
		failure, returned = err, true
		return
	}
	defer exit()
	code, err := i.method.Handler(callCtx, request, &i.response)
	returned = true
	failure = err
	if failure == nil {
		failure = work.FinishWritten(code)
	}
}

// The existing Session coordinator joins task exit and copies at most one
// bounded result chunk per turn. Reply cancellation never discards a live
// task, history fact or another request's join.
func (d *ServiceDispatch) advanceExecution(index int, i *serviceInvocation, closed bool) {
	x := i.execution
	if closed {
		i.stop(cryptov4.ErrClosed)
	} else if err := i.withAuthority(func() error { return nil }); err != nil {
		i.stop(err)
	}
	i.mu.Lock()
	done := x.work == nil
	if i.queued != nil {
		select {
		case <-i.queued.Done():
			done = true
		default:
		}
	} else if i.task != nil {
		select {
		case <-i.task.Done():
			done = true
		default:
		}
	}
	stopped, outputDone := i.closed, x.outputFinished
	i.mu.Unlock()
	if done && x.work != nil {
		if err := x.work.Exit(); err != nil {
			return
		}
	}
	if !stopped && !outputDone {
		observation, ready, err := x.join.Observe()
		if err != nil {
			i.stop(err)
		} else if ready {
			n, err := x.join.CopyResult(x.scratch[:], x.offset)
			if err == nil {
				err = i.withAuthority(func() error {
					i.mu.Lock()
					defer i.mu.Unlock()
					if i.closed {
						return rpcv4.ErrClosed
					}
					count, err := i.writer.Write(x.scratch[:n])
					x.offset += uint32(count)
					if err == nil && x.offset == observation.ResultBytes {
						_, err = i.writer.Finalize(observation.ApplicationErrorCode)
						if err == nil {
							x.outputFinished = true
						}
					}
					return err
				})
			}
			if err == nil {
				i.mu.Lock()
				if x.outputFinished {
					i.result.Close()
				}
				i.mu.Unlock()
			}
			clear(x.scratch[:])
			if err != nil {
				i.stop(err)
			}
		} else if !observation.WorkActive {
			i.stop(rpcv4.ErrExecutionUnsupported)
		}
	}
	i.mu.Lock()
	if i.closed {
		x.outputFinished = true
	}
	outputFinished := x.outputFinished
	i.mu.Unlock()
	if !done || !outputFinished {
		return
	}
	d.finishExecution(index, i)
}

func (d *ServiceDispatch) finishExecution(index int, i *serviceInvocation) {
	x := i.execution
	// The real task has returned. Close preserves publisher-owned tail backing.
	if x.work != nil {
		_ = x.work.Release()
	}
	if x.join != nil {
		x.join.Close()
	}
	if x.durableJoin != nil {
		x.durableJoin.Close()
		if !x.durableJoin.CleanupComplete() {
			return
		}
	}
	x.joinReservation.Release()
	i.mu.Lock()
	i.closed = true
	i.cancel(cryptov4.ErrClosed)
	i.observation.EndInvocation()
	i.input.Close()
	i.result.Close()
	if !i.result.CleanupComplete() || !i.observation.CleanupComplete() {
		i.mu.Unlock()
		return
	}
	i.reservation.Release()
	i.reservation = resourcev4.Reference{}
	class := i.method.WorkClass
	i.dispatcher = nil
	i.plan = nil
	i.method = UnaryRegistration{}
	i.input = nil
	i.result = nil
	i.writer = nil
	i.observation = nil
	i.deadline = nil
	i.ctx = nil
	i.cancel = nil
	i.queued = nil
	i.task = nil
	i.execution = nil
	i.mu.Unlock()
	d.mu.Lock()
	d.slots[index] = nil
	d.active--
	if class == ApplicationResident {
		d.resident--
	}
	d.mu.Unlock()
}
