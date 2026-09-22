package sessionv4

import (
	"context"
	"errors"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/rpcv4"
)

// The real executor permit precedes registration. The only asynchronous task
// belongs to that permit; storage never starts a handler or a fallback worker.
func (d ExecutionDispatch) dispatchDurable(ctx context.Context, input *rpcv4.VerifiedInput, handler ExecutionHandler, publish func(uint32, []byte, error) error) (rpcv4.ExecutionObservation, error) {
	return d.dispatchDurableRequest(ctx, input, handler, nil, publish)
}

type recoveryDispatch struct {
	verifier *rpcv4.RecoveryVerifier
	target   rpcv4.RecoveryTarget
	guard    func() error
}

// DispatchRecovery shares the same original durable admission, executor and
// publication owner. The verifier sees only the actual registered input; the
// token CAS and recovery result are committed together before publication.
func (d ExecutionDispatch) DispatchRecovery(ctx context.Context, input *rpcv4.VerifiedInput, verifier *rpcv4.RecoveryVerifier, target rpcv4.RecoveryTarget, targetGuard func() error, publish func(uint32, []byte, error) error) (rpcv4.ExecutionObservation, error) {
	if d.History != nil || verifier == nil || targetGuard == nil || publish == nil {
		return rpcv4.ExecutionObservation{}, rpcv4.ErrConfiguration
	}
	return d.dispatchDurableRequest(ctx, input, nil, &recoveryDispatch{verifier: verifier, target: target, guard: targetGuard}, publish)
}

func (d ExecutionDispatch) dispatchDurableRequest(ctx context.Context, input *rpcv4.VerifiedInput, handler ExecutionHandler, recovery *recoveryDispatch, publish func(uint32, []byte, error) error) (rpcv4.ExecutionObservation, error) {
	if ctx == nil || d.DurableHistory == nil || d.Routes == nil || d.Executor == nil || d.Access == nil || input == nil || handler == nil && recovery == nil {
		return rpcv4.ExecutionObservation{}, rpcv4.ErrConfiguration
	}
	var permit *ApplicationPermit
	var recoveryPin resourcev4.Reference
	transferred := false
	defer func() {
		if permit != nil {
			permit.Close()
		}
		if !transferred {
			recoveryPin.Release()
		}
	}()
	o, work, err := d.DurableHistory.Admit(ctx, d.Routes, input, d.Caller, d.Access, func(task, backing resourcev4.Reference) error {
		var err error
		permit, err = d.Executor.TryAcquire(d.Class, task, backing)
		if err == nil && recovery != nil {
			recoveryPin, err = recovery.verifier.Borrow(backing)
		}
		return err
	})
	if err != nil || work == nil {
		if work != nil {
			err = errors.Join(err, work.Exit(context.Background()))
		}
		return o, err
	}
	err = work.SubmitTask(func() (<-chan struct{}, error) {
		return permit.startJoined(func() {
			failure := error(ErrCompletionCallbackExit)
			returned := false
			defer func() {
				if recover() != nil || !returned {
					failure = ErrCompletionCallbackExit
				}
				if publish == nil {
					return
				}
				if failure == nil {
					_ = work.PublishResult(func(code uint32, body []byte) error { return publish(code, body, nil) })
				} else {
					_ = publish(0, nil, failure)
				}
			}()
			appCtx, contextErr := work.Context(ctx)
			if contextErr != nil {
				failure = contextErr
				returned = true
				return
			}
			borrow, enterErr := work.Enter(appCtx)
			if enterErr != nil {
				failure = enterErr
				returned = true
				return
			}
			if recovery != nil {
				returned = true
				failure = work.ResolveRecovery(appCtx, recovery.verifier, recovery.target, recovery.guard)
				return
			}
			code, body, handlerErr := handler(appCtx, borrow)
			returned = true
			failure = handlerErr
			if handlerErr == nil {
				// A cancelled response cannot erase a real completed business
				// result. This write still belongs to the original charged task.
				failure = work.Finish(context.Background(), code, body)
			}
		}, func() {
			// The actual callback and all its defers have returned. Failed
			// durable cleanup stays in the finite service table for Collect.
			_ = work.Exit(context.Background())
			recoveryPin.Release()
		})
	})
	transferred = err == nil
	if err != nil {
		err = errors.Join(err, work.Exit(context.Background()))
	}
	return o, err
}
