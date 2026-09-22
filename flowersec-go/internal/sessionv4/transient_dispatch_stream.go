package sessionv4

import (
	"context"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/rpcv4"
)

// TransientStreamDispatch uses the same bounded stream and ordinary callback
// owner without creating business history, a replay right or another request.
// TaskReservation must be part of the enclosing service's original admission.
type TransientStreamDispatch struct {
	group           *applicationGroup
	Executor        *ApplicationExecutor
	Class           ApplicationWorkClass
	TaskReservation resourcev4.Reference
}

func (d TransientStreamDispatch) Dispatch(ctx context.Context, stream *StreamMessages, handler StreamExecutionHandler) (err error) {
	if ctx == nil || stream == nil || handler == nil || d.Executor == nil || d.Class != ApplicationResident {
		return cryptov4.ErrConfiguration
	}
	i, err := stream.claimInvocation(ctx, ExecutionDispatch{Executor: d.Executor, Class: d.Class}, handler)
	if err != nil {
		return err
	}
	started := false
	var permit *ApplicationPermit
	defer func() {
		if permit != nil {
			permit.Close()
		}
		if !started {
			if i.queued.Load() != nil {
				i.queued.Load().Cancel()
			}
			stream.Close()
			i.release()
		}
	}()
	i.dependencies, err = captureApplicationDependencies(ctx)
	if err != nil {
		return err
	}
	if stream.original.Fields().AdmissionMode == 0 && d.group != nil {
		var queued *QueuedApplicationTask
		queued, err = d.Executor.prepareApplication(d.group, d.Class, d.TaskReservation, stream.reservation)
		i.queued.Store(queued)
	} else {
		permit, err = d.Executor.TryAcquire(d.Class, d.TaskReservation, stream.reservation)
	}
	if err != nil {
		return err
	}
	i.input, err = stream.TakeInitialInput(ctx)
	if err != nil {
		return err
	}
	_, err = i.startInitial(ctx, permit)
	started = err == nil
	return err
}

// The finite registration and delivery gates lend the already captured bytes;
// neither gate contains a decoder, encoder, user handler or provider operation.
func (i *streamInvocation) enterTransient() (borrow rpcv4.InputBorrow, err error) {
	m := i.stream
	err = m.withCurrentAuthorization(func() error {
		return m.route.WithRegistered(func() error {
			var err error
			borrow, err = i.input.Borrow()
			if err == nil {
				i.transientInput = borrow
			}
			return err
		})
	})
	return borrow, err
}
