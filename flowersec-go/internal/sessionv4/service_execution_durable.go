package sessionv4

import (
	"context"
	"errors"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

func (d *ServiceDispatch) signalDurable() {
	if d.durableWake != nil {
		select {
		case d.durableWake <- struct{}{}:
		default:
		}
	}
}

// One original, separately charged Session task owns provider calls. The
// existing invocation slots are its only pending index; a wake carries no job
// or payload. The Environment coordinator remains finite during blocked I/O.
func (d *ServiceDispatch) runDurableProvider() {
	defer func() { d.mu.Lock(); d.durableExited = true; d.cleanupLocked(); d.mu.Unlock() }()
	for range d.durableWake {
		d.mu.Lock()
		notifications := d.durableNotifications
		stop := d.closed && d.active == 0 && notifications == nil
		turns := min(8, len(d.slots))
		d.mu.Unlock()
		if stop {
			return
		}
		if notifications != nil {
			notifications.stepDurableNotifications()
		}
		for range turns {
			d.mu.Lock()
			if len(d.slots) == 0 {
				d.mu.Unlock()
				return
			}
			i := d.slots[d.durableCursor]
			d.durableCursor = (d.durableCursor + 1) % len(d.slots)
			d.mu.Unlock()
			if i == nil {
				continue
			}
			i.mu.Lock()
			if read := i.durableRead; read != nil {
				if !i.started || read.busy || read.complete || read.retired {
					i.mu.Unlock()
					continue
				}
				read.busy = true
				i.mu.Unlock()
				d.stepDurableRead(i, read)
				continue
			}
			x := i.execution
			if !i.started || x == nil || x.durableHistory == nil || x.providerBusy || x.providerRetired {
				i.mu.Unlock()
				continue
			}
			x.providerBusy = true
			i.mu.Unlock()
			d.stepDurableProvider(i, x)
		}
	}
}

func (d *ServiceDispatch) stepDurableProvider(i *serviceInvocation, x *serviceExecution) {
	defer func() {
		if recover() != nil {
			i.stop(ErrCompletionCallbackExit)
		}
		i.mu.Lock()
		x.providerBusy = false
		i.mu.Unlock()
	}()
	i.mu.Lock()
	admitted, stopped := x.admissionDone, i.closed
	i.mu.Unlock()
	if !admitted {
		var work *rpcv4.DurableExecutionWork
		var join *rpcv4.DurableExecutionJoin
		var err error
		if stopped {
			err = cryptov4.ErrClosed
		} else {
			reserve := func(task, backing resourcev4.Reference) error {
				i.mu.Lock()
				defer i.mu.Unlock()
				if i.closed {
					return cryptov4.ErrClosed
				}
				var err error
				if i.header.Fields().AdmissionMode == 1 {
					x.permit, err = i.plan.executor.TryAcquire(i.method.WorkClass, task, backing)
				} else {
					i.queued, err = i.plan.executor.prepareApplication(i.plan.applicationGroup, i.method.WorkClass, task, backing)
				}
				return err
			}
			if x.durableAdmission != nil {
				_, work, join, err = d.consumer.AdmitReservedDurableExecution(i.ctx, x.durableHistory, i.input, x.access.caller, x.access, x.joinReservation, d.runtimeBytes, x.durableAdmission, reserve)
			} else {
				_, work, join, err = d.consumer.AdmitDurableExecution(i.ctx, x.durableHistory, i.input, x.access.caller, x.access, x.joinReservation, d.runtimeBytes, reserve)
			}
		}
		x.joinReservation.Release()
		x.joinReservation = resourcev4.Reference{}
		i.mu.Lock()
		x.durableWork, x.durableJoin, x.admissionDone = work, join, true
		i.mu.Unlock()
		if err == nil && work != nil {
			err = work.SubmitTask(func() (<-chan struct{}, error) {
				i.mu.Lock()
				defer i.mu.Unlock()
				if i.closed {
					return nil, cryptov4.ErrClosed
				}
				if i.header.Fields().AdmissionMode == 1 {
					var err error
					i.task, err = x.permit.Start(i.runDurableExecution)
					if err != nil {
						return nil, err
					}
					return i.task.Done(), nil
				}
				if err := i.queued.startPrepared(i.runDurableExecution); err != nil {
					return nil, err
				}
				return i.queued.Done(), nil
			})
		}
		if work == nil || err != nil {
			if x.permit != nil {
				x.permit.Close()
			}
			i.mu.Lock()
			if i.queued != nil {
				i.queued.Cancel()
			}
			i.mu.Unlock()
		}
		if err != nil {
			i.stop(err)
		}
	}
	i.mu.Lock()
	done := true
	if i.task != nil {
		select {
		case <-i.task.Done():
		default:
			done = false
		}
	} else if i.queued != nil {
		select {
		case <-i.queued.Done():
		default:
			done = false
		}
	}
	stopped = i.closed
	i.mu.Unlock()
	if done && x.durableWork != nil && !x.exitDone {
		if err := x.durableWork.Exit(context.Background()); err != nil {
			return
		}
	}
	if done {
		i.mu.Lock()
		x.exitDone = true
		i.mu.Unlock()
	}
	if !stopped && x.durableJoin != nil {
		err := x.durableJoin.Refresh(i.ctx)
		if err != nil && !errors.Is(err, rpcv4.ErrCapacity) && !errors.Is(err, ledgerv4.ErrCapacity) && !errors.Is(err, timev4.ErrPending) && !errors.Is(err, timev4.ErrUnavailable) {
			i.stop(err)
		}
	}
}

func (i *serviceInvocation) runDurableExecution() {
	work := i.execution.durableWork
	returned := false
	failure := error(ErrCompletionCallbackExit)
	defer func() {
		if recover() != nil || !returned {
			failure = ErrCompletionCallbackExit
		}
		// A result already committed by the explicit issuance API remains the
		// original outcome even if application cleanup subsequently fails.
		if work.ResultCommitted() {
			failure = nil
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
		failure, returned = err, true
		return
	}
	input, err := work.Enter(ctx)
	if err != nil {
		failure, returned = err, true
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
	returned, failure = true, err
	if failure == nil && !work.ResultCommitted() {
		failure = work.FinishWritten(context.Background(), code)
	}
}

func (d *ServiceDispatch) advanceDurableExecution(index int, i *serviceInvocation, closed bool) {
	x := i.execution
	if closed {
		i.stop(cryptov4.ErrClosed)
	} else if err := i.withAuthority(func() error { return nil }); err != nil {
		i.stop(err)
	}
	d.signalDurable()
	i.mu.Lock()
	busy, admitted, done, stopped, outputDone := x.providerBusy, x.admissionDone, x.exitDone, i.closed, x.outputFinished
	join := x.durableJoin
	i.mu.Unlock()
	if busy || !admitted {
		return
	}
	if !stopped && !outputDone && join != nil {
		o, ready, err := join.Observe()
		if errors.Is(err, rpcv4.ErrCapacity) {
			return
		}
		if err != nil {
			i.stop(err)
		} else if ready {
			n, err := join.CopyResult(x.scratch[:], x.offset)
			if errors.Is(err, rpcv4.ErrCapacity) {
				return
			}
			if err == nil {
				err = i.withAuthority(func() error {
					i.mu.Lock()
					defer i.mu.Unlock()
					if i.closed {
						return rpcv4.ErrClosed
					}
					count, err := i.writer.Write(x.scratch[:n])
					x.offset += uint32(count)
					if err == nil && x.offset == o.ResultBytes {
						_, err = i.writer.Finalize(o.ApplicationErrorCode)
						if err == nil {
							x.outputFinished = true
							i.result.Close()
						}
					}
					return err
				})
			}
			clear(x.scratch[:])
			if err != nil {
				i.stop(err)
			}
		} else if o.Found && !o.WorkActive {
			i.stop(rpcv4.ErrExecutionUnsupported)
		}
	}
	i.mu.Lock()
	if i.closed {
		x.outputFinished = true
	}
	finished := done && x.outputFinished && !x.providerBusy
	// Retire the slot from future provider selection before dropping its owners.
	if finished {
		x.providerRetired = true
	}
	i.mu.Unlock()
	if finished {
		d.finishExecution(index, i)
		d.signalDurable()
	}
}
