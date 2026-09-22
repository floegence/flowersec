package sessionv4

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/rpcv4"
)

// StreamExecutionHandler runs once on the operation's original ordinary task.
// Its input is the complete verified initial request. Items are encoded and
// published through the dedicated stream; returning records execution metadata
// only. A nonzero code must name the application terminal sent on this stream.
type StreamExecutionHandler func(context.Context, rpcv4.InputBorrow, *StreamMessages) (applicationErrorCode uint32, err error)

// The enclosing stream admits this fixed invocation and application context
// before OPEN. The execution store separately owns its record, input, executor
// task and physical provider tails. No item creates another invocation.
type streamInvocation struct {
	source           *streamEventOperation
	initialDone      <-chan struct{}
	queued           atomic.Pointer[QueuedApplicationTask]
	releaseMu        sync.Mutex
	releaseRequested atomic.Bool
	released         atomic.Bool
	stream           *StreamMessages
	dispatch         ExecutionDispatch
	dependencies     applicationDependencies
	input            *rpcv4.VerifiedInput
	work             *rpcv4.ExecutionWork
	durable          *rpcv4.DurableExecutionWork
	transientInput   rpcv4.InputBorrow
	transientCancel  context.CancelFunc
	appContext       context.Context // published under stream.mu
	handler          StreamExecutionHandler
}

// DispatchStream consumes the original captured request. The executor permit
// precedes business registration. A duplicate returns its existing observation
// and closes this output stream without entering or replaying a generator.
func (d ExecutionDispatch) DispatchStream(ctx context.Context, stream *StreamMessages, handler StreamExecutionHandler) (observation rpcv4.ExecutionObservation, err error) {
	return d.dispatchApplicationStream(ctx, stream, handler, nil, nil)
}

func (d ExecutionDispatch) dispatchVerifiedResume(ctx context.Context, stream *StreamMessages, input *rpcv4.VerifiedInput, handler StreamExecutionHandler) (rpcv4.ExecutionObservation, bool, error) {
	started := false
	observation, err := d.dispatchApplicationStream(ctx, stream, handler, input, &started)
	return observation, started, err
}

func (d ExecutionDispatch) dispatchApplicationStream(ctx context.Context, stream *StreamMessages, handler StreamExecutionHandler, verified *rpcv4.VerifiedInput, startedResult *bool) (observation rpcv4.ExecutionObservation, err error) {
	defer func() {
		if verified != nil {
			verified.Close()
		}
	}()
	if ctx == nil || stream == nil || handler == nil || d.Routes == nil || d.Executor == nil || d.Access == nil || !stream.resumeExchange && d.Class != ApplicationResident || stream.resumeExchange && (d.Class != ApplicationShort || d.DurableHistory == nil) || (d.History == nil) == (d.DurableHistory == nil) {
		return observation, rpcv4.ErrConfiguration
	}
	i, err := stream.claimInvocation(ctx, d, handler)
	if err != nil {
		return observation, err
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
			if !stream.resumeExchange || err != nil {
				stream.Close()
			}
			i.release()
		}
	}()
	i.dependencies, err = captureApplicationDependencies(ctx)
	if err != nil {
		return observation, err
	}
	if verified != nil {
		stream.mu.Lock()
		i.input, verified = verified, nil
		stream.initialInput.Close()
		stream.initialInput = nil
		stream.ready, stream.inputBytes = false, 0
		stream.candidate = protocolv4.ApplicationHeader{}
		stream.mu.Unlock()
	} else {
		i.input, err = stream.TakeInitialInput(ctx)
	}
	if err != nil {
		return observation, err
	}
	reserve := func(task, backing resourcev4.Reference) error {
		if err := backing.CheckSameEnvironment(stream.reservation); err != nil {
			return err
		}
		if stream.original.Fields().AdmissionMode == 0 && d.group != nil {
			queued, err := d.Executor.prepareApplication(d.group, d.Class, task, backing)
			i.queued.Store(queued)
			return err
		}
		var err error
		permit, err = d.Executor.TryAcquire(d.Class, task, backing)
		return err
	}
	if d.DurableHistory != nil {
		observation, i.durable, err = d.DurableHistory.Admit(ctx, d.Routes, i.input, d.Caller, d.Access, reserve)
	} else {
		observation, i.work, err = d.History.AdmitForDispatch(ctx, d.Routes, i.input, d.Caller, d.Access, reserve)
	}
	if err != nil || i.work == nil && i.durable == nil {
		return observation, err
	}
	start := func() (<-chan struct{}, error) { return i.startInitial(ctx, permit) }
	if i.durable != nil {
		err = i.durable.SubmitTask(start)
	} else {
		err = i.work.SubmitTask(func(_, _ resourcev4.Reference) (<-chan struct{}, error) { return start() })
	}
	started = err == nil
	if startedResult != nil {
		*startedResult = started
	}
	return observation, err
}

func (m *StreamMessages) claimInvocation(ctx context.Context, dispatch ExecutionDispatch, handler StreamExecutionHandler) (*streamInvocation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.checkLocked(ctx); err != nil {
		return nil, err
	}
	if !m.server || !m.inputEOF || !m.ready || m.initialInput == nil {
		return nil, ErrStreamMessagePending
	}
	if m.applicationBusy || m.dispatchUsed || m.applicationStarted {
		return nil, ErrStreamMessageBusy
	}
	execution := dispatch.History != nil || dispatch.DurableHistory != nil
	if (m.policy.Semantics == 1) != execution || execution && (m.policy.ExecutionMode == 1) != (dispatch.DurableHistory != nil) {
		return nil, rpcv4.ErrExecutionUnsupported
	}
	i := &streamInvocation{stream: m, dispatch: dispatch, handler: handler, source: m.eventSource}
	m.applicationBusy, m.dispatchUsed, m.invocation = true, true, i
	return i, nil
}

func (i *streamInvocation) run(parent context.Context) {
	m := i.stream
	failure := error(ErrCompletionCallbackExit)
	returned := false
	defer func() {
		if recover() != nil || !returned {
			failure = ErrCompletionCallbackExit
		}
		if i.source != nil {
			i.source.recordSetupOutcome(failure)
			return
		}
		if failure != nil {
			// A failed write keeps its existing offsets. It cannot be replaced
			// with another header; Close ends that original physical stream.
			name := serviceRefusal(failure)
			if errors.Is(failure, ErrCompletionCallbackExit) {
				name = "service_failed"
			}
			if err := m.SendSDKError(parent, name); err != nil {
				m.Close()
			}
		}
	}()
	failure = nil
	var appCtx context.Context
	var borrow rpcv4.InputBorrow
	if i.durable != nil {
		appCtx, failure = i.durable.Context(parent)
	} else if i.work != nil {
		appCtx, failure = i.work.Context(parent)
	} else {
		var cancel context.CancelFunc
		appCtx, cancel = context.WithCancel(parent)
		m.mu.Lock()
		i.transientCancel = cancel
		if m.closed || m.ioEnded {
			cancel()
		}
		m.mu.Unlock()
	}
	if failure != nil {
		returned = true
		return
	}
	m.mu.Lock()
	i.appContext = appCtx
	m.mu.Unlock()
	if i.durable != nil {
		borrow, failure = i.durable.Enter(appCtx)
		if failure == nil {
			failure = i.durable.ConstrainStreamDeadline(m.deadline)
		}
	} else if i.work != nil {
		borrow, failure = i.work.Enter()
		if failure == nil {
			failure = i.work.ConstrainStreamDeadline(m.deadline)
		}
	} else {
		failure = m.BeginApplication(appCtx)
		if failure == nil {
			borrow, failure = i.enterTransient()
		}
	}
	if failure != nil {
		returned = true
		return
	}
	// Execution already fixed the exact first-entry sample. Publish that same
	// narrowed deadline, without sampling a second run origin at transport.
	m.mu.Lock()
	failure = m.checkLocked(appCtx)
	if failure == nil {
		m.applicationStarted = true
		m.owner.notify()
		m.signalLocked()
	}
	m.mu.Unlock()
	if failure != nil {
		returned = true
		return
	}
	callCtx, exit, contextErr := enterApplicationContext(appCtx, i.dispatch.Executor, ordinaryApplicationLane, i.dispatch.Class, m.reservation, &i.dependencies)
	if contextErr != nil {
		failure, returned = contextErr, true
		return
	}
	defer exit()
	code, handlerErr := i.handler(callCtx, borrow, m)
	returned, failure = true, handlerErr
	if i.source != nil {
		return
	}
	if failure == nil {
		failure = m.checkApplicationEnd(code)
	}
	if m.resumeExchange {
		return
	}
	if failure == nil {
		if i.durable != nil {
			failure = i.durable.FinishStream(context.Background(), code)
		} else if i.work != nil {
			failure = i.work.FinishStream(code)
		}
	}
	if failure == nil {
		failure = m.CompleteOutput(appCtx)
	}
}

// This gate inspects only already-owned output facts. It neither invokes user
// code nor turns a partially accepted terminal into a complete execution.
func (m *StreamMessages) checkApplicationEnd(code uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.encoding || m.pending || m.closing || m.writeBusy || m.outputApplicationCode != code {
		return ErrStreamMessagePending
	}
	if code != 0 && !m.outputClosed {
		return ErrStreamMessagePending
	}
	return nil
}

// release is called only after the real callback and all application defers
// return, or when submission never started. Provider cleanup retains its own
// durable work if it cannot yet complete; it cannot refund or restart a task.
// release records that the original callback/factory has returned and then
// settles the same owner. Exit may legitimately fail while a provider tail or
// durable store is still unavailable; keeping this request lets the stream
// supervisor retry without dropping the invocation slot or its charges.
func (i *streamInvocation) release() {
	if i == nil {
		return
	}
	i.releaseRequested.Store(true)
	if err := i.tryRelease(); err != nil {
		m := i.stream
		if m != nil {
			m.mu.Lock()
			if m.invocation == i {
				m.signalLocked()
			}
			m.mu.Unlock()
		}
	}
}

func (i *streamInvocation) tryRelease() error {
	if i == nil {
		return nil
	}
	i.releaseMu.Lock()
	defer i.releaseMu.Unlock()
	if i.released.Load() || !i.releaseRequested.Load() {
		return nil
	}
	err := i.releaseOwners()
	if err == nil {
		i.released.Store(true)
	}
	return err
}

func (i *streamInvocation) releasePending() bool {
	if i == nil {
		return false
	}
	return i.releaseRequested.Load() && !i.released.Load()
}

func (i *streamInvocation) releaseOwners() error {
	if i.durable != nil {
		if err := i.durable.Exit(context.Background()); err != nil {
			return err
		}
	} else if i.work != nil {
		if err := i.work.Exit(); err != nil {
			return err
		}
		if err := i.work.Release(); err != nil {
			return err
		}
	}
	i.transientInput.Release()
	i.transientInput = rpcv4.InputBorrow{}
	if i.input != nil {
		i.input.Close()
		i.input = nil
	}
	i.dependencies.release()
	i.handler = nil
	m := i.stream
	m.mu.Lock()
	if i.transientCancel != nil {
		i.transientCancel()
		i.transientCancel = nil
	}
	i.appContext = nil
	i.work, i.durable = nil, nil
	i.dispatch = ExecutionDispatch{}
	m.invocation = nil
	m.applicationBusy = false
	m.signalLocked()
	m.cleanupLocked()
	m.mu.Unlock()
	i.stream = nil
	return nil
}

// Before another synchronous encoder enters, it checks the original execution
// continuation outside every stream and application mutex. A provider wait is
// owned by the same real callback task and cannot create a new dispatch.
func (m *StreamMessages) checkApplicationContinuation(ctx context.Context) error {
	m.mu.Lock()
	i := m.invocation
	if i == nil || !m.applicationBusy {
		m.mu.Unlock()
		return cryptov4.ErrClosed
	}
	work, durable := i.work, i.durable
	m.mu.Unlock()
	if durable != nil {
		return durable.CheckContinuation(ctx)
	}
	if work != nil {
		return work.CheckContinuation()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return m.route.WithRegistered(func() error { return nil })
}

// The source's original SDK pump keeps the business lifetime after setup
// returns. Ordinary generators finish at their actual one callback exit.
func (i *streamInvocation) startInitial(ctx context.Context, permit *ApplicationPermit) (<-chan struct{}, error) {
	var done <-chan struct{}
	var err error
	if queued := i.queued.Load(); queued != nil {
		err = queued.startPrepared(func() { i.run(ctx) })
		done = queued.Done()
	} else {
		done, err = permit.startJoined(func() { i.run(ctx) }, func() {
			if i.source == nil {
				i.release()
			}
		})
	}
	if err != nil {
		return nil, err
	}
	i.initialDone = done
	if i.source != nil {
		i.source.markStarted()
		return i.source.done, nil
	}
	return done, nil
}
