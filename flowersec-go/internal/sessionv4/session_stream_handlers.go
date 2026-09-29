package sessionv4

import (
	"context"
	"errors"
	"math"
	"sync"
	"time"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// SessionStreamHandlerConfig installs a frozen role-neutral raw Stream plan
// before READY. Concurrency includes authorizing, running and actual late tails.
// Runtime allowances cover qualified host contexts, notifications and stacks;
// application execution retains its own original executor task reservations.
type SessionStreamHandlerConfig struct {
	internal                                           bool
	Plan                                               *StreamHandlerPlan
	Concurrency                                        uint32
	ServiceTarget                                      uint32
	TimeoutMS, RuntimeBytes, RuntimeBytesPerInvocation uint64
}

type sessionStreamDispatcher struct {
	mu                                sync.Mutex
	config                            SessionStreamHandlerConfig
	core                              *SessionCore
	executor                          *ApplicationExecutor
	reservation                       resourcev4.Reference
	context                           context.Context
	cancel                            context.CancelFunc
	active, services                  uint32
	started, running, closed, cleaned bool
	stop, done                        chan struct{}
	publication                       <-chan struct{}
}

type streamHandlerContext struct {
	context.Context
	deadline time.Time
}

func (c *streamHandlerContext) Deadline() (time.Time, bool) {
	if c.deadline.IsZero() {
		return time.Time{}, false
	}
	return c.deadline, true
}

type streamHandlerInvocation struct {
	watchMu         sync.Mutex
	service         *preparedStreamService
	dispatcher      *sessionStreamDispatcher
	allocation      *sessionStreamAllocation
	handle          OpenHandle
	preparation     OpenPreparation
	capture         StreamHandlerCapture
	metadata        []byte
	deadline        *timev4.Deadline
	context         streamHandlerContext
	cancel          context.CancelFunc
	done, watchDone chan struct{}
	owner           *StreamOwnership
	messages        *TypedMessageStream
	recovery        *resumeStreamServer
	ownerReady      chan struct{}
	stopWatch       sync.Once
}

func sessionStreamDispatcherCharge(c SessionStreamHandlerConfig) (resourcev4.Vector, error) {
	if c.ServiceTarget > 128 || c.Plan == nil && c.ServiceTarget != 0 {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	if c.RuntimeBytes == 0 || c.Plan == nil && !c.internal {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	if c.Plan != nil {
		if c.Concurrency == 0 || c.TimeoutMS == 0 || c.TimeoutMS > uint64(math.MaxInt64/time.Millisecond) {
			return resourcev4.Vector{}, cryptov4.ErrConfiguration
		}
		if _, err := streamHandlerInvocationCharge(c); err != nil {
			return resourcev4.Vector{}, err
		}
	} else if c.Concurrency != 0 || c.TimeoutMS != 0 || c.RuntimeBytesPerInvocation != 0 {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	return (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(sessionStreamDispatcher{})), resourcev4.Items: 1, resourcev4.Tasks: 1, resourcev4.WorkSlots: 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: c.RuntimeBytes})
}

func streamHandlerInvocationCharge(c SessionStreamHandlerConfig) (resourcev4.Vector, error) {
	if c.RuntimeBytesPerInvocation == 0 {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	// The Stream factory's original task owns the SDK lifecycle. This extra
	// worker supervises the fixed deadline while network or callbacks block.
	return (resourcev4.Vector{resourcev4.SDKBytes: applicationContextBytes() + uint64(unsafe.Sizeof(streamHandlerInvocation{})) + uint64(unsafe.Sizeof(timev4.Deadline{})), resourcev4.Items: 2, resourcev4.Tasks: 1, resourcev4.WorkSlots: 1, resourcev4.Timers: 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: c.RuntimeBytesPerInvocation})
}

func newSessionStreamDispatcher(core *SessionCore, config SessionStreamHandlerConfig, reservation resourcev4.Reference) (*sessionStreamDispatcher, error) {
	charge, err := sessionStreamDispatcherCharge(config)
	if err != nil {
		return nil, err
	}
	var executor *ApplicationExecutor
	if config.Plan != nil {
		if err := config.Plan.CheckEnvironment(reservation); err != nil {
			return nil, err
		}
		executor = config.Plan.Executor()
		if executor == nil {
			return nil, cryptov4.ErrConfiguration
		}
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	if config.ServiceTarget == 0 {
		config.ServiceTarget = 64
	}
	return &sessionStreamDispatcher{config: config, core: core, executor: executor, reservation: owned, context: ctx, cancel: cancel, stop: make(chan struct{}), done: make(chan struct{})}, nil
}

func (d *sessionStreamDispatcher) Run(ctx context.Context) error {
	d.mu.Lock()
	if d.started || d.closed {
		d.mu.Unlock()
		return cryptov4.ErrClosed
	}
	d.started, d.running = true, true
	d.mu.Unlock()
	defer func() {
		d.Close()
		d.mu.Lock()
		d.running = false
		d.cleanupLocked()
		d.mu.Unlock()
	}()
	if d.publication != nil {
		select {
		case <-d.publication:
		case <-ctx.Done():
			return ctx.Err()
		case <-d.stop:
			return cryptov4.ErrClosed
		}
	}
	a := d.core.plan.admission
	kindCap, err := protocolv4.FieldByteLimit("OPEN_STREAM", "kind")
	if err != nil {
		return err
	}
	metadataCap, err := protocolv4.FieldByteLimit("OPEN_STREAM", "metadata")
	if err != nil {
		return err
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		h, err := a.NextPending(d.context)
		if err != nil {
			return err
		}
		if r := d.core.plan.rpc; r != nil {
			handled, dispatchErr := r.dispatchRPCOpen(h, d.core.plan.writer)
			if handled {
				if dispatchErr != nil {
					reason := "resource_exhausted"
					if errors.Is(dispatchErr, cryptov4.ErrConfiguration) {
						reason = "application_rejected"
					}
					if err := d.rejectClass(h, InternalStream, reason); err != nil {
						return err
					}
				}
				continue
			}
			if dispatchErr != nil {
				return dispatchErr
			}
		}
		if r := d.core.plan.rpc; r != nil && r.plan != nil && r.plan.services != nil {
			handled, dispatchErr := r.plan.services.dispatchStreamOpen(d, h)
			if handled {
				if dispatchErr != nil {
					if err := d.reject(h, "resource_exhausted"); err != nil {
						return err
					}
				}
				continue
			}
			if dispatchErr != nil {
				return dispatchErr
			}
		}
		if d.config.Plan == nil {
			if err := d.reject(h, "kind_unavailable"); err != nil {
				return err
			}
			continue
		}
		d.mu.Lock()
		available := !d.closed && d.active < d.config.Concurrency
		if available {
			d.active++
		}
		d.mu.Unlock()
		if !available {
			if err := d.reject(h, "resource_exhausted"); err != nil {
				return err
			}
			continue
		}
		service, err := a.pendingDelegatedKind(h, d.config.Plan)
		if err != nil {
			d.finishInvocation()
			return err
		}
		allocation, _, err := d.core.plan.prepareStreamInvocation(d.context, kindCap+metadataCap, d, service)
		if err != nil {
			d.finishInvocation()
			reason := "resource_exhausted"
			if errors.Is(err, ErrSessionDraining) {
				reason = "draining"
			}
			if err := d.reject(h, reason); err != nil {
				return err
			}
			continue
		}
		job := &streamHandlerInvocation{dispatcher: d, allocation: allocation, handle: h, done: make(chan struct{}), watchDone: make(chan struct{}), ownerReady: make(chan struct{})}
		job.deadline, err = timev4.NewAge(a.engine.Clock(), d.config.TimeoutMS, a.engine.SessionParameters().SessionNotAfterMS)
		if err != nil {
			d.core.plan.finishStream(allocation)
			d.finishInvocation()
			return err
		}
		job.context.Context, job.cancel = context.WithCancel(context.Background())
		remaining, err := job.deadline.RemainingMS()
		if err != nil {
			job.cancel()
			d.core.plan.finishStream(allocation)
			d.finishInvocation()
			return err
		}
		job.context.deadline = time.Now().Add(idleTimerChunk(remaining))
		go job.watch()
		go job.run()
	}
}

func (d *sessionStreamDispatcher) reject(h OpenHandle, reason string) error {
	return d.rejectClass(h, BusinessStream, reason)
}

func (d *sessionStreamDispatcher) rejectClass(h OpenHandle, class StreamClass, reason string) error {
	a := d.core.plan.admission
	for {
		_, err := a.Decide(d.context, h, class, reason, StreamReservation{}, d.core.plan.writer)
		if !errors.Is(err, ErrOpenPending) && !errors.Is(err, errRecordWriterBusy) {
			return err
		}
		if err := a.WaitDecisionOpportunity(d.context, h); err != nil {
			return err
		}
	}
}

func (job *streamHandlerInvocation) watch() {
	defer close(job.watchDone)
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	defer timer.Stop()
	ownerReady := job.ownerReady
	var ownerChange <-chan struct{}
	var connAbort <-chan struct{}
	for {
		remaining, err := job.deadline.RemainingMS()
		if err != nil {
			job.cancelInvocation()
			return
		}
		timer.Reset(idleTimerChunk(remaining))
		select {
		case <-job.done:
			return
		case <-job.dispatcher.stop:
			job.cancelInvocation()
			return
		case <-job.handle.owner.engine.Done():
			job.cancelInvocation()
			return
		case <-ownerReady:
			ownerReady = nil
			ownerChange = job.owner.changed
			connAbort, err = job.owner.handlerSupervision()
			if err != nil {
				job.cancelInvocation()
				return
			}
		case <-ownerChange:
			connAbort, err = job.owner.handlerSupervision()
			if err != nil {
				job.cancelInvocation()
				return
			}
		case <-connAbort:
			job.cancelInvocation()
			return
		case <-timer.C:
		}
	}
}

func (job *streamHandlerInvocation) run() {
	d, a := job.dispatcher, job.handle.owner
	defer func() {
		job.finishWatch()
		job.recovery.close()
		if job.messages != nil && !job.messages.bound {
			job.messages.disposeCandidate()
		}
		job.capture.Release()
		job.preparation.Release()
		job.metadata = nil
		d.core.plan.finishStream(job.allocation)
		if job.service == nil || !job.service.transferred {
			d.finishInvocation()
		}
		job.service.release()
	}()
	var err error
	for {
		job.preparation, err = a.PreparePeerOpen(job.handle)
		if !errors.Is(err, ErrOpenPending) {
			break
		}
		if err = a.WaitDecisionOpportunity(&job.context, job.handle); err != nil {
			return
		}
	}
	if err != nil {
		if errors.Is(err, ErrSessionDraining) {
			_ = d.reject(job.handle, "draining")
		}
		return
	}
	kind, metadata, _, err := job.preparation.CopyRequest(job.allocation.reservation.OpenStorage)
	if err != nil {
		if errors.Is(err, ErrSessionDraining) {
			_ = d.reject(job.handle, "draining")
		}
		return
	}
	job.metadata = metadata
	job.capture, err = d.config.Plan.Capture(string(kind))
	if err != nil {
		reason := "resource_exhausted"
		if errors.Is(err, ErrStreamHandlerKind) {
			reason = "kind_unavailable"
		}
		_ = d.reject(job.handle, reason)
		return
	}
	registration, _ := job.capture.projection()
	job.allocation.reservation.NormalTerminationMS = registration.NormalTerminationMS
	if registration.HTTP != nil || registration.Delegated != nil || registration.ControlledHTTP != nil {
		if err := job.prepareStreamService(registration); err != nil {
			_ = d.reject(job.handle, "resource_exhausted")
			return
		}
	}
	if registration.Resume != nil {
		job.recovery, err = job.prepareResumeServer(*registration.Resume)
		if err != nil {
			_ = d.reject(job.handle, "application_rejected")
			return
		}
	}
	if registration.Messages != nil {
		job.messages, err = prepareTypedMessages(job.allocation.candidate, registration.Messages.Messages)
		if err == nil {
			err = job.messages.match(string(kind), metadata, false)
		}
		if err != nil {
			_ = d.reject(job.handle, "application_rejected")
			return
		}
		// Authorize and Handle see only the independent ordinary metadata.
		job.messages.authorizeMetadata = append([]byte(nil), job.messages.metadata[:job.messages.metadataBytes]...)
		job.messages.handlerMetadata = append([]byte(nil), job.messages.metadata[:job.messages.metadataBytes]...)
		metadata = job.messages.authorizeMetadata
		job.metadata = metadata
		job.allocation.candidate.typed = job.messages
	}
	permit, err := d.executor.TryAcquire(job.capture.WorkClass(), job.allocation.refs[streamFactoryAuthorizeTask], job.allocation.refs[streamFactoryInvocation])
	if err != nil {
		_ = d.reject(job.handle, "resource_exhausted")
		return
	}
	defer permit.Close()
	authorizeErr := ErrStreamHandlerCallbackExit
	task, err := permit.Start(func() {
		if err := job.preparation.Check(); err != nil {
			authorizeErr = err
			return
		}
		if err := job.deadline.Check(); err != nil {
			authorizeErr = err
			return
		}
		callCtx, exit, e := enterApplicationContext(&job.context, d.executor, ordinaryApplicationLane, job.capture.WorkClass(), job.allocation.refs[streamFactoryInvocation], nil)
		if e != nil {
			authorizeErr = e
			return
		}
		defer exit()
		authorizeErr = job.capture.Authorize(callCtx, metadata)
		if authorizeErr == nil && job.service != nil {
			authorizeErr = ErrStreamHandlerCallbackExit
			authorizeErr = job.service.setup(callCtx, job.capture, metadata)
		}
	})
	if err != nil {
		_ = d.reject(job.handle, "resource_exhausted")
		return
	}
	select {
	case <-task.Done():
	case <-job.context.Done():
		_ = d.reject(job.handle, "application_rejected")
		<-task.Done() // Actual callback tails retain the original snapshot.
		return
	}
	if authorizeErr != nil {
		reason := "application_rejected"
		if errors.Is(authorizeErr, ErrSessionDraining) {
			reason = "draining"
		}
		_ = d.reject(job.handle, reason)
		return
	}
	var handlerReady *QueuedApplicationTask
	if job.recovery != nil {
		handlerReady, err = d.executor.prepareApplication(job.capture.plan.group, job.capture.WorkClass(), job.allocation.refs[streamFactoryHandlerTask], job.allocation.refs[streamFactoryInvocation])
	} else if job.service == nil {
		permit, err = d.executor.TryAcquire(job.capture.WorkClass(), job.allocation.refs[streamFactoryHandlerTask], job.allocation.refs[streamFactoryInvocation])
	}
	if err != nil {
		_ = d.reject(job.handle, "resource_exhausted")
		return
	}
	defer func() {
		if handlerReady != nil {
			handlerReady.Cancel()
		} else {
			permit.Close()
		}
	}()
	var outcome RecordWriteResult
	for {
		outcome, err = a.decideWithGate(&job.context, job.handle, BusinessStream, "", job.allocation.reservation, d.core.plan.writer, func() error {
			if err := job.context.Err(); err != nil {
				return err
			}
			if err := job.deadline.Check(); err != nil {
				return err
			}
			var permitErr error
			if handlerReady != nil {
				permitErr = handlerReady.checkPrepared()
			} else if job.service != nil {
				permitErr = job.service.check()
			} else {
				permitErr = permit.commitAcceptance()
			}
			if err := permitErr; err != nil {
				return err
			}
			return job.capture.Accept()
		})
		if !errors.Is(err, ErrOpenPending) && !errors.Is(err, errRecordWriterBusy) {
			break
		}
		if err = a.WaitDecisionOpportunity(&job.context, job.handle); err != nil {
			return
		}
	}
	if err != nil {
		if !outcome.Submitted {
			_ = d.reject(job.handle, "resource_exhausted")
		}
		return
	}
	if err = a.WaitOutcome(&job.context, job.handle); err != nil {
		_ = a.Cancel(job.handle)
		return
	}
	o := job.allocation.candidate
	deadline, ownerContext := job.deadline, context.Context(&job.context)
	if job.service != nil {
		deadline, ownerContext = job.service.deadline, job.service.context
	}
	owner, err := a.bindStreamOwnership(job.handle, o.reservation, deadline, ownerContext, o)
	if err != nil {
		_ = a.Cancel(job.handle)
		return
	}
	job.allocation.candidate = nil
	job.owner = owner
	if job.service != nil {
		job.runStreamService(owner)
		return
	}
	if job.messages != nil {
		if err := job.messages.bindTypedMessages(owner); err != nil {
			owner.mu.Lock()
			owner.typed = nil
			owner.mu.Unlock()
			owner.Revoke()
			_ = owner.Cancel()
			_ = owner.Release()
			return
		}
		job.messages.handlerPending = true
		metadata = job.messages.handlerMetadata
		go job.messages.superviseTypedMessages()
		go job.messages.publishTypedMessages()
	}
	close(job.ownerReady)
	defer func() {
		job.finishWatch()
		if job.messages != nil {
			job.messages.mu.Lock()
			job.messages.handlerPending = false
			job.messages.signal()
			job.messages.mu.Unlock()
			job.messages.Close()
			_ = job.messages.WaitCleanup(context.Background())
			return
		}
		owner.Revoke()
		_ = owner.Cancel()
		for errors.Is(owner.Release(), ErrStreamOwnershipBusy) {
			<-owner.changed
		}
	}()
	if job.recovery != nil {
		if err := job.recovery.run(owner); err != nil {
			return
		}
		job.recovery.close()
		job.recovery = nil
	}
	handle := func() {
		callCtx, exit, e := enterApplicationContext(&job.context, d.executor, ordinaryApplicationLane, job.capture.WorkClass(), job.allocation.refs[streamFactoryInvocation], nil)
		if e != nil {
			return
		}
		defer exit()
		_ = job.capture.Handle(callCtx, metadata, owner)
	}
	var handlerDone <-chan struct{}
	if handlerReady != nil {
		err = handlerReady.startPrepared(handle)
		handlerDone = handlerReady.Done()
	} else {
		task, err = permit.Start(handle)
		if err == nil {
			handlerDone = task.Done()
		}
	}
	if err != nil {
		return
	}
	select {
	case <-handlerDone:
	case <-job.context.Done():
		if handlerReady != nil {
			handlerReady.Cancel()
		}
		owner.Revoke()
		_ = owner.Cancel()
		<-handlerDone
	}
}

func (job *streamHandlerInvocation) finishWatch() {
	job.stopWatch.Do(func() { job.cancel(); close(job.done) })
	<-job.watchDone
}

func (job *streamHandlerInvocation) cancelInvocation() {
	job.watchMu.Lock()
	defer job.watchMu.Unlock()
	job.cancel()
	if job.service != nil && !job.service.transferred {
		job.service.cancel()
	}
}

func (d *sessionStreamDispatcher) finishInvocation() {
	d.mu.Lock()
	d.active--
	d.cleanupLocked()
	d.mu.Unlock()
}

func (d *sessionStreamDispatcher) cleanupLocked() {
	if d.closed && !d.running && d.active == 0 && d.services == 0 && !d.cleaned {
		d.cleaned = true
		close(d.done)
	}
}

func (d *sessionStreamDispatcher) Close() {
	if d == nil {
		return
	}
	d.mu.Lock()
	if !d.closed {
		d.closed = true
		close(d.stop)
		d.cancel()
		if d.config.Plan != nil {
			d.config.Plan.Close()
		}
	}
	d.cleanupLocked()
	d.mu.Unlock()
}

func (d *sessionStreamDispatcher) WaitCleanup(ctx context.Context) error {
	select {
	case <-d.done:
		if d.config.Plan != nil {
			return d.config.Plan.WaitCleanup(ctx)
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (d *sessionStreamDispatcher) Retire() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.cleaned {
		return cryptov4.ErrCapacity
	}
	if d.config.Plan != nil {
		if err := d.config.Plan.Retire(); err != nil {
			return err
		}
	}
	d.core, d.executor, d.context, d.cancel = nil, nil, nil, nil
	d.reservation.Release()
	d.reservation = resourcev4.Reference{}
	return nil
}
