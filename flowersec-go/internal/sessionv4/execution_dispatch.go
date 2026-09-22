package sessionv4

import (
	"context"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/rpcv4"
)

// ExecutionHandler is the only application callback entry supplied by the
// execution dispatcher. All request verification, key admission, executor
// capacity and deadline gates have already won before this function runs.
type ExecutionHandler func(context.Context, rpcv4.InputBorrow) (errorCode uint32, payload []byte, err error)

type ExecutionDispatch struct {
	group          *applicationGroup
	History        *rpcv4.VolatileExecutions
	DurableHistory *rpcv4.DurableExecutions
	Routes         *rpcv4.ContractRoutes
	Executor       *ApplicationExecutor
	Caller         rpcv4.ExecutionPrincipal
	Access         rpcv4.ExecutionAccess
	Class          ApplicationWorkClass
}

// Dispatch connects volatile history to the real root ApplicationExecutor.
// The executor owns the actual callback task and its borrowed input backing;
// ExecutionWork.Exit runs only after that task returns. A duplicate operation
// joins its original record and does not enter the handler again.
func (d ExecutionDispatch) Dispatch(ctx context.Context, input *rpcv4.VerifiedInput, handler ExecutionHandler) (rpcv4.ExecutionObservation, error) {
	return d.DispatchWithResult(ctx, input, handler, nil)
}

// DispatchWithResult is the execution pipeline used by the Session service
// dispatcher. History is completed before the response callback is invoked, so
// a lost response cannot erase the actual business outcome. The callback runs
// on the same original executor task and owns only publication, not dispatch.
func (d ExecutionDispatch) DispatchWithResult(ctx context.Context, input *rpcv4.VerifiedInput, handler ExecutionHandler, publish func(uint32, []byte) error) (rpcv4.ExecutionObservation, error) {
	return d.DispatchWithOutcome(ctx, input, handler, func(code uint32, payload []byte, err error) error {
		if err == nil && publish != nil {
			return publish(code, payload)
		}
		return nil
	})
}

// DispatchWithOutcome additionally reports a callback/entry/finish failure to
// the result owner. This keeps response ownership physically bounded when the
// executor refuses entry or the application returns an error after execution
// history has been admitted.
func (d ExecutionDispatch) DispatchWithOutcome(ctx context.Context, input *rpcv4.VerifiedInput, handler ExecutionHandler, publish func(uint32, []byte, error) error) (rpcv4.ExecutionObservation, error) {
	if d.DurableHistory != nil {
		if d.History != nil {
			return rpcv4.ExecutionObservation{}, rpcv4.ErrConfiguration
		}
		return d.dispatchDurable(ctx, input, handler, publish)
	}
	if ctx == nil || d.History == nil || d.Routes == nil || d.Executor == nil || d.Access == nil || input == nil || handler == nil {
		return rpcv4.ExecutionObservation{}, rpcv4.ErrConfiguration
	}
	obs, work, err := d.History.Admit(ctx, d.Routes, input, d.Caller, d.Access)
	if err != nil || work == nil {
		return obs, err
	}
	// SubmitTask transfers the exact task and invocation reservation into the
	// root executor in one finite admission. No fallback goroutine or second
	// worker is created when this gate refuses.
	err = work.SubmitTask(func(task, backing resourcev4.Reference) (<-chan struct{}, error) {
		return d.Executor.trySubmitJoined(d.Class, task, backing, func() {
			failure := error(ErrCompletionCallbackExit)
			var code uint32
			var payload []byte
			returned := false
			defer func() {
				if recover() != nil || !returned {
					failure = ErrCompletionCallbackExit
				}
				if publish != nil {
					_ = publish(code, payload, failure)
				}
			}()
			appCtx, contextErr := work.Context(ctx)
			if contextErr != nil {
				failure = contextErr
				returned = true
				return
			}
			inputBorrow, enterErr := work.Enter()
			if enterErr != nil {
				failure = enterErr
				returned = true
				return
			}
			code, payload, failure = handler(appCtx, inputBorrow)
			returned = true
			if failure == nil {
				failure = work.Finish(code, payload)
			}
		}, func() {
			// callbackExited is closed before this finite SDK tail, while the
			// original executor still holds the task slot and backing borrow.
			if work.Exit() == nil {
				_ = work.Release()
			}
		})
	})
	if err != nil {
		// The history record remains retained as an admission fact. Since the
		// executor never started a task, this is a failed dispatch with no app
		// input delivery; Exit performs the precise cleanup transition.
		_ = work.Exit()
		_ = work.Release()
		return work.Status(), err
	}
	return work.Status(), nil
}
