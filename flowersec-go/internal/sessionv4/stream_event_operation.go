package sessionv4

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

var ErrSourceEvent = errors.New("sessionv4: event source conversion failed")

type streamEventOperation struct {
	activeTask                 atomic.Pointer[QueuedApplicationTask]
	mu                         sync.Mutex
	source                     *streamEventSource
	cleanup                    *streamSourceCleanup
	reservation                resourcev4.Reference
	done                       chan struct{}
	setupFailure               error
	encodingFailure            error
	started, running, finished bool
}

func streamEventOperationCharge(runtimeBytes uint64) (resourcev4.Vector, error) {
	if runtimeBytes == 0 {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	return (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(streamEventOperation{})), resourcev4.Items: 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: runtimeBytes})
}

func prepareStreamEventOperation(job *serviceStreamCall, queue, metadata, cleanupMetadata, cleanupTask resourcev4.Reference) (*streamEventOperation, error) {
	definition, d := job.registration.EventSource, job.dispatcher
	charge, err := streamEventOperationCharge(d.runtimeBytes)
	if err != nil {
		return nil, err
	}
	owned, err := metadata.Take(charge)
	if err != nil {
		return nil, err
	}
	source, err := prepareStreamEventSource(job.messages, definition.config(job), queue)
	if err != nil {
		owned.Release()
		return nil, err
	}
	cleanup, err := prepareStreamSourceCleanup(d.plan.executor, d.plan.applicationGroup, ApplicationResident, source.publisher, d.runtimeBytes, definition.CleanupMS, cleanupMetadata, cleanupTask)
	if err != nil {
		source.setupExited(err)
		source.close()
		source.cleanup()
		owned.Release()
		return nil, err
	}
	source.cleanupOwner = cleanup
	return &streamEventOperation{source: source, cleanup: cleanup, reservation: owned, done: make(chan struct{}), setupFailure: ErrSourceSetup}, nil
}

func (o *streamEventOperation) recordSetupOutcome(failure error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if failure == nil {
		o.setupFailure = nil
	} else {
		o.setupFailure = ErrSourceSetup
	}
}

func (o *streamEventOperation) markStarted() {
	o.mu.Lock()
	o.started = true
	o.mu.Unlock()
}

func (o *streamEventOperation) close() {
	if o == nil {
		return
	}
	o.source.close()
	o.cleanup.request()
}

func (o *streamEventOperation) cleanupComplete() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.finished
}

// A constructor or duplicate that never submitted setup owns no subscription.
// It still cancels the original future cleanup descriptor before refunding.
func (o *streamEventOperation) abortBeforeStart() {
	if o == nil {
		return
	}
	o.mu.Lock()
	if o.started || o.running || o.finished {
		o.mu.Unlock()
		return
	}
	o.mu.Unlock()
	o.close()
	o.source.setupExited(ErrSourceSetup)
	o.cleanup.setupExited()
	if o.cleanup.complete() {
		o.finish()
	}
}

func (o *streamEventOperation) finish() {
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.finished {
		o.finished = true
		close(o.done)
	}
}

func (o *streamEventOperation) releaseOwned() {
	if o == nil || !o.cleanupComplete() {
		return
	}
	if !o.source.cleanup() {
		return
	}
	o.reservation.Release()
	o.reservation = resourcev4.Reference{}
}

// run reuses the original accepted Stream factory task. SDK queue/credit waits
// happen here; each real application stage separately enters ordinary service.
// The single business execution remains live until this whole source exits.
func (o *streamEventOperation) run(job *serviceStreamCall) {
	m := job.messages
	m.mu.Lock()
	invocation := m.invocation
	m.mu.Unlock()
	if invocation == nil {
		o.abortBeforeStart()
		return
	}
	o.mu.Lock()
	o.running = true
	o.mu.Unlock()
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	defer timer.Stop()
	o.activeTask.Store(invocation.queued.Load())
	o.waitTask(job, invocation.initialDone, invocation.queued.Load(), timer, false)
	o.activeTask.Store(nil)
	o.mu.Lock()
	failure := o.setupFailure
	o.mu.Unlock()
	o.cleanup.setupExited()
	o.cleanup.allowStart()
	o.source.setupExited(failure)
	if failure == nil {
		failure = o.pump(job, invocation, timer)
	}
	closed, sourceFailure := o.source.state()
	if sourceFailure != nil {
		failure = sourceFailure
	}
	if !closed && failure == nil {
		failure = m.checkApplicationEnd(0)
		if failure == nil {
			if invocation.durable != nil {
				failure = invocation.durable.FinishStream(context.Background(), 0)
			} else if invocation.work != nil {
				failure = invocation.work.FinishStream(0)
			}
		}
		if failure == nil {
			failure = m.CompleteOutput(job.context)
		}
	}
	if !closed && failure != nil {
		name := serviceRefusal(failure)
		if errors.Is(failure, ErrSourceOverflow) {
			name = "source_overflow"
		}
		if err := m.SendSDKError(job.context, name); err != nil {
			m.Close()
		}
	}
	o.close()
	o.cleanup.allowStart()
	o.waitCleanup(job, timer)
	// All actual setup/mapper/disposer invocations have exited. Only now may
	// the original execution task settle; no per-event business registration.
	o.finish()
	invocation.release()
}

func (o *streamEventOperation) pump(job *serviceStreamCall, invocation *streamInvocation, timer *time.Timer) error {
	for {
		if err := job.context.Err(); err != nil {
			job.messages.Close()
			return err
		}
		input, done, err := o.source.next()
		if err != nil {
			return err
		}
		if done {
			return nil
		}
		if input == nil {
			m := job.messages
			m.mu.Lock()
			changed := m.stateChanged
			closed := m.closed || m.ioEnded
			m.mu.Unlock()
			if closed {
				o.close()
				return cryptov4.ErrClosed
			}
			select {
			case <-o.source.changed:
			case <-changed:
			case <-job.context.Done():
			}
			continue
		}
		err = o.runEvent(job, invocation, input, timer)
		o.source.finishCurrent(input)
		if err != nil {
			o.source.fail(err)
			return err
		}
		// Encoding has actually exited. The original item alone now owns all
		// pending bytes and offsets through backpressure or cancellation.
		if err := job.messages.ContinueOutput(job.context); err != nil {
			return err
		}
	}
}

func (o *streamEventOperation) runEvent(job *serviceStreamCall, invocation *streamInvocation, input *OwnedEventInput, timer *time.Timer) error {
	executor := invocation.dispatch.Executor
	for {
		if err := o.source.checkCurrent(input); err != nil {
			return err
		}
		if err := job.context.Err(); err != nil {
			return err
		}
		available := executor.availabilitySnapshot()
		queued, err := executor.prepareApplicationWithBorrow(job.dispatcher.plan.applicationGroup, invocation.dispatch.Class, input.processing[1], input.processing[0], input.processingBorrow)
		if errors.Is(err, cryptov4.ErrCapacity) {
			select {
			case <-available:
			case <-o.source.changed:
			case <-job.context.Done():
			}
			continue
		}
		if err != nil {
			return err
		}
		o.mu.Lock()
		o.encodingFailure = ErrSourceEvent
		o.mu.Unlock()
		o.activeTask.Store(queued)
		err = queued.startPrepared(func() { o.encodeOnce(input, invocation, job.registration.EventSource) })
		if err != nil {
			queued.Cancel()
			o.activeTask.Store(nil)
			return err
		}
		o.waitTask(job, queued.Done(), queued, timer, true)
		o.activeTask.Store(nil)
		o.mu.Lock()
		failure := o.encodingFailure
		o.mu.Unlock()
		return failure
	}
}

// This waits only on real original work and finite source/stream notifications.
// Logical cancellation cannot free the input or an uncooperative callback.
func (o *streamEventOperation) waitTask(job *serviceStreamCall, done <-chan struct{}, queued *QueuedApplicationTask, timer *time.Timer, event bool) {
	for {
		select {
		case <-done:
			return
		default:
		}
		m := job.messages
		m.mu.Lock()
		changed := m.stateChanged
		closed := m.closed || m.ioEnded
		m.mu.Unlock()
		_, failure := o.source.state()
		if job.context.Err() != nil && !closed {
			m.Close()
			closed = true
		}
		if closed || job.context.Err() != nil || event && failure != nil {
			if closed || job.context.Err() != nil {
				o.close()
			}
			if queued != nil {
				queued.Cancel()
			}
		}
		remaining, cleanupErr := o.cleanup.advance()
		if cleanupErr != nil {
			o.reportCleanupFailure(m)
		}
		var timerC <-chan time.Time
		if remaining > 0 {
			timer.Reset(remaining)
			timerC = timer.C
		} else {
			timer.Stop()
		}
		var cancelled <-chan struct{}
		if !closed && job.context.Err() == nil {
			cancelled = job.context.Done()
		}
		select {
		case <-done:
			return
		case <-changed:
		case <-o.source.changed:
		case <-cancelled:
		case <-timerC:
		}
		timer.Stop()
	}
}

func (o *streamEventOperation) waitCleanup(job *serviceStreamCall, timer *time.Timer) {
	done := o.cleanup.future.Done()
	for {
		remaining, err := o.cleanup.advance()
		if err != nil {
			o.reportCleanupFailure(job.messages)
		}
		if o.cleanup.complete() {
			return
		}
		var timerC <-chan time.Time
		if remaining > 0 {
			timer.Reset(remaining)
			timerC = timer.C
		} else {
			timer.Stop()
		}
		select {
		case <-done:
			done = nil
		case <-timerC:
		}
		timer.Stop()
	}
}

func (o *streamEventOperation) reportCleanupFailure(m *StreamMessages) {
	m.mu.Lock()
	if !m.sourceCleanupReported {
		m.sourceCleanupReported = true
		m.signalLocked()
	}
	m.mu.Unlock()
}
