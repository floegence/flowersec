package sessionv4

import (
	"context"
	"errors"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

var (
	ErrUnaryResultDelivered    = errors.New("sessionv4: result already delivered")
	ErrUnaryInputDelivered     = errors.New("sessionv4: application input already delivered")
	ErrUnaryPayloadUnavailable = errors.New("sessionv4: result payload unavailable")
	ErrUnaryDecodeFailed       = errors.New("sessionv4: result decode failed")
)

// UnaryResultDecoder receives owned input exactly once, on the original root
// Completion service. It may retain that input; arbitrary application objects
// and error formatting never run on the protocol/coordinator goroutines.
type UnaryResultDecoder func(context.Context, []byte) (any, error)

type unaryResultPlan struct {
	environment *Environment
	decode      UnaryResultDecoder
}

// All fields are guarded by UnaryCall.mu. This is the original local result
// owner, not another request, public handle, manager or result budget.
type unaryResultWaiter struct {
	occupied, typed, dependent bool
	done                       <-chan struct{}
}

type unaryResultState struct {
	observers                                            [4]unaryResultWaiter
	metadata                                             resourcev4.Reference
	authorization                                        *protocolv4.DeliveryAuthorization
	environment                                          *Environment
	environmentIndex                                     int
	executor                                             *ApplicationExecutor
	clock                                                *timev4.Clock
	future                                               *CompletionReservation
	input                                                *rpcv4.VerifiedInput
	decode                                               UnaryResultDecoder
	context                                              context.Context
	cancel                                               context.CancelFunc
	inputCancel                                          context.CancelFunc
	dependencies                                         applicationDependencies
	dependency                                           *completionDependency
	task                                                 *CompletionTask
	decodedDone, closing, changed                        chan struct{}
	value                                                any
	failure                                              error
	waiters, typedWaiters                                uint8
	visits                                               uint32
	preparing, networkSettled, attached, closed, cleaned bool
	paused, inputDelivered, decoded, consumed, abandoned bool
}

type UnaryResultStatus struct {
	Request                                                         protocolv4.ApplicationHeader
	Submission                                                      rpcv4.PublicationProgress
	Abandoned, CleanupComplete                                      bool
	Outcome                                                         UnaryCallOutcome
	Complete, Available, DecoderRunning, Decoded, Delivered, Closed bool
}

func unaryResultCharge(runtimeBytes uint64) (resourcev4.Vector, error) {
	if runtimeBytes == 0 {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	return (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(UnaryCall{})) + uint64(unsafe.Sizeof(unaryResultState{})) + applicationContextBytes() + completionDependencyBytes(), resourcev4.Items: 3}).Add(resourcev4.Vector{resourcev4.SDKBytes: runtimeBytes})
}

func (c *UnaryCall) ResultStatus() UnaryResultStatus {
	if c == nil {
		return UnaryResultStatus{Closed: true}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.resultStatusLocked()
}

func (c *UnaryCall) resultStatusLocked() UnaryResultStatus {
	s := UnaryResultStatus{Outcome: c.outcome, Complete: c.finished, Request: c.request}
	if c.publication != nil {
		s.Submission = c.publication.Progress()
	}
	if d := c.deferred; d != nil {
		s.Closed, s.Delivered, s.Decoded, s.CleanupComplete = d.closed, d.consumed, d.decoded, d.cleaned
		s.DecoderRunning = d.inputDelivered && !d.decoded
		s.Available = !d.closed && !d.consumed && d.failure == nil && (d.input != nil || d.decoded)
		s.Outcome.ApplicationInputDelivered = d.inputDelivered
		if d.failure != nil {
			s.Outcome.Error = d.failure
		}
		if d.abandoned {
			s.Abandoned = true
			s.Outcome.Reason, s.Outcome.Error = "result_abandoned", ErrUnaryResultAbandoned
		}
	}
	return s
}

// WaitStatus observes complete authenticated input or a terminal local outcome.
// It neither requests decoding nor claims future Completion service.
func (c *UnaryCall) WaitStatus(ctx context.Context) (UnaryResultStatus, error) {
	if c == nil || ctx == nil {
		return UnaryResultStatus{}, cryptov4.ErrConfiguration
	}
	c.mu.Lock()
	if c.finished || c.deferred != nil && c.deferred.closed {
		status := c.resultStatusLocked()
		c.mu.Unlock()
		return status, nil
	}
	c.mu.Unlock()
	index, err := c.enterResultWait(ctx, false)
	if err != nil {
		return UnaryResultStatus{}, err
	}
	defer c.leaveResultWait(index)
	return c.waitResultStatus(ctx, nil)
}

func (c *UnaryCall) waitResultStatus(ctx context.Context, dependencyFailure <-chan struct{}) (UnaryResultStatus, error) {
	c.mu.Lock()
	if c.finished || c.deferred != nil && c.deferred.closed {
		status := c.resultStatusLocked()
		c.mu.Unlock()
		return status, nil
	}
	var closing <-chan struct{}
	if c.deferred != nil {
		closing = c.deferred.closing
	}
	c.mu.Unlock()
	select {
	case <-dependencyFailure:
		return c.ResultStatus(), ErrCompletionDependency
	case <-c.done:
		return c.ResultStatus(), nil
	case <-closing:
		return c.ResultStatus(), nil
	case <-ctx.Done():
		return UnaryResultStatus{}, ctx.Err()
	}
}

func (c *UnaryCall) enterResultWait(ctx context.Context, typed bool) (int, error) {
	c.mu.Lock()
	if d := c.deferred; d != nil && d.abandoned {
		c.mu.Unlock()
		return 0, ErrUnaryResultAbandoned
	}
	c.mu.Unlock()
	if err := c.checkResultDependency(ctx); err != nil {
		return 0, err
	}
	dependencies, err := captureApplicationDependencies(ctx)
	if err != nil {
		return 0, err
	}
	defer dependencies.release()
	c.mu.Lock()
	defer c.mu.Unlock()
	d := c.deferred
	if d == nil {
		return 0, cryptov4.ErrConfiguration
	}
	if d.closed {
		return 0, d.closedErrorLocked()
	}
	if d.consumed {
		return 0, ErrUnaryResultDelivered
	}
	if d.waiters == uint8(len(d.observers)) {
		return 0, cryptov4.ErrCapacity
	}
	dependent := typed && dependencies.hasCompletion(d.executor)
	if typed && !d.inputDelivered && !d.decoded && d.failure == nil {
		if err := dependencies.merge(&d.dependencies); err != nil {
			return 0, err
		}
		dependency, err := d.future.claimDependency(&dependencies, d.clock)
		if err != nil {
			return 0, err
		}
		if dependency != nil {
			dependency.limitDeadline(ctx)
			d.dependency = dependency
		}
		d.dependencies.release()
		d.dependencies, dependencies = dependencies, applicationDependencies{}
	}
	index := 0
	for d.observers[index].occupied {
		index++
	}
	d.observers[index] = unaryResultWaiter{occupied: true, typed: typed, dependent: dependent, done: ctx.Done()}
	d.waiters++
	if typed {
		d.typedWaiters++
	}
	return index, nil
}

func (c *UnaryCall) leaveResultWait(index int) {
	c.mu.Lock()
	d := c.deferred
	d.waiters--
	if d.observers[index].typed {
		d.typedWaiters--
	}
	d.observers[index] = unaryResultWaiter{}
	if d.typedWaiters == 0 {
		d.future.releaseDependencyClaim()
	}
	environment := d.environment
	c.mu.Unlock()
	if environment != nil {
		environment.signalMaterials()
	}
}

func (d *unaryResultState) eligibleDecoderLocked() bool {
	for _, waiter := range d.observers {
		if !waiter.occupied || !waiter.typed {
			continue
		}
		select {
		case <-waiter.done:
			continue
		default:
		}
		if waiter.dependent && d.dependency != nil {
			select {
			case <-d.dependency.expired:
				continue
			default:
			}
		}
		return true
	}
	return false
}

// TakeResult requests the one original decoder. Cancellation detaches this
// waiter. Once input has entered application code, all later callers join the
// same computation and only one may claim its value (or normalized failure).
func (c *UnaryCall) TakeResult(ctx context.Context) (any, UnaryResultStatus, error) {
	if c == nil || ctx == nil {
		return nil, UnaryResultStatus{}, cryptov4.ErrConfiguration
	}
	index, err := c.enterResultWait(ctx, true)
	if err != nil {
		return nil, c.ResultStatus(), err
	}
	defer c.leaveResultWait(index)
	c.mu.Lock()
	var dependencyFailure <-chan struct{}
	if d := c.deferred; d.dependency != nil && completionContext(ctx, d.executor) {
		dependencyFailure = d.dependency.expired
	}
	c.mu.Unlock()
	if _, err := c.waitResultStatus(ctx, dependencyFailure); err != nil {
		return nil, c.ResultStatus(), err
	}
	for {
		if err := ctx.Err(); err != nil {
			return nil, c.ResultStatus(), err
		}
		select {
		case <-dependencyFailure:
			return nil, c.ResultStatus(), ErrCompletionDependency
		default:
		}
		c.mu.Lock()
		d := c.deferred
		if d.closed || d.consumed || d.failure != nil && !d.decoded {
			err := d.failure
			if d.closed {
				err = d.closedErrorLocked()
			} else if d.consumed {
				err = ErrUnaryResultDelivered
			}
			status := c.resultStatusLocked()
			c.mu.Unlock()
			return nil, status, err
		}
		if d.decoded {
			if err := ctx.Err(); err != nil {
				status := c.resultStatusLocked()
				c.mu.Unlock()
				return nil, status, err
			}
			d.consumed = true
			value, err := d.value, d.failure
			d.value = nil
			status := c.resultStatusLocked()
			c.mu.Unlock()
			return value, status, err
		}
		if d.task == nil {
			if d.input == nil {
				status := c.resultStatusLocked()
				c.mu.Unlock()
				return nil, status, ErrUnaryPayloadUnavailable
			}
			task, err := d.future.offer(c.decodeResult)
			if err != nil {
				status := c.resultStatusLocked()
				c.mu.Unlock()
				return nil, status, err
			}
			d.task = task
		}
		task, closing, decoded := d.task, d.closing, d.decodedDone
		authorization := d.authorization
		c.mu.Unlock()
		var wake <-chan struct{}
		if authorization != nil {
			wake = authorization.Wake()
		}
		select {
		case <-dependencyFailure:
			return nil, c.ResultStatus(), ErrCompletionDependency
		case <-task.Done():
			c.advanceResult()
			if errors.Is(task.Wait(context.Background()), errCompletionNotEligible) {
				c.mu.Lock()
				changed, paused := d.changed, d.paused
				c.mu.Unlock()
				if !paused {
					continue
				}
				select {
				case <-dependencyFailure:
					return nil, c.ResultStatus(), ErrCompletionDependency
				case <-wake:
				case <-changed:
				case <-decoded:
				case <-closing:
				case <-ctx.Done():
					return nil, c.ResultStatus(), ctx.Err()
				}
			}
		case <-decoded:
		case <-closing:
		case <-ctx.Done():
			return nil, c.ResultStatus(), ctx.Err()
		}
	}
}

// TakeEncodedResult and typed delivery share the original single consumption
// gate. Encoded delivery wins only before application input has been disclosed.
func (c *UnaryCall) TakeEncodedResult(ctx context.Context) ([]byte, UnaryResultStatus, error) {
	if c == nil || ctx == nil {
		return nil, UnaryResultStatus{}, cryptov4.ErrConfiguration
	}
	index, err := c.enterResultWait(ctx, false)
	if err != nil {
		return nil, c.ResultStatus(), err
	}
	defer c.leaveResultWait(index)
	if _, err := c.waitResultStatus(ctx, nil); err != nil {
		return nil, c.ResultStatus(), err
	}
	c.mu.Lock()
	d := c.deferred
	if err := d.encodedConflictLocked(); err != nil {
		status := c.resultStatusLocked()
		c.mu.Unlock()
		return nil, status, err
	}
	environment, authorization := d.environment, d.authorization
	c.mu.Unlock()
	var owned rpcv4.ApplicationInput
	err = environment.withResultDelivery(func() error {
		return authorization.WithCurrentAuthorization(func() error {
			c.mu.Lock()
			defer c.mu.Unlock()
			if err := ctx.Err(); err != nil {
				return err
			}
			if d.closed {
				return d.closedErrorLocked()
			}
			if d.consumed {
				return ErrUnaryResultDelivered
			}
			if d.inputDelivered {
				return ErrUnaryInputDelivered
			}
			if d.input == nil || d.failure != nil {
				return ErrUnaryPayloadUnavailable
			}
			var err error
			owned, err = d.input.Deliver()
			if err != nil {
				return err
			}
			d.input, d.authorization, d.decode = nil, nil, nil
			d.consumed = true
			return nil
		})
	})
	if err != nil {
		// Another actual handoff may have closed the shared authorization
		// after this waiter took its snapshot. Preserve that winner's facts.
		c.mu.Lock()
		if conflict := d.encodedConflictLocked(); conflict != nil {
			err = conflict
		}
		status := c.resultStatusLocked()
		c.mu.Unlock()
		return nil, status, err
	}
	authorization.Close(nil)
	d.future.Close()
	payload := owned.Bytes()
	owned.Close()
	return payload, c.ResultStatus(), nil
}

func (c *UnaryCall) decodeResult() (err error) {
	c.mu.Lock()
	d := c.deferred
	environment, authorization, executor := d.environment, d.authorization, d.executor
	callback := d.decode
	parent, metadata, dependency := d.context, d.metadata, d.dependency
	c.mu.Unlock()
	dependency.advance()
	var callCtx context.Context
	var exit func()
	defer func() {
		if exit != nil {
			exit()
		}
	}()
	var owned rpcv4.ApplicationInput
	err = environment.withResultDelivery(func() error {
		return authorization.WithCurrentAuthorization(func() error {
			c.mu.Lock()
			defer c.mu.Unlock()
			if d.closed || d.consumed || d.failure != nil {
				return ErrUnaryPayloadUnavailable
			}
			if !d.eligibleDecoderLocked() {
				return errCompletionNotEligible
			}
			if d.input == nil || d.inputDelivered || callback == nil {
				return ErrUnaryPayloadUnavailable
			}
			var e error
			callCtx, exit, e = enterApplicationContext(parent, executor, completionApplicationLane, ApplicationShort, metadata, &d.dependencies)
			if e != nil {
				return e
			}
			invocation := callCtx.(*applicationContext).state
			invocation.result = c
			owned, e = d.input.Deliver()
			if e != nil {
				return e
			}
			d.input, d.authorization, d.decode = nil, nil, nil
			d.inputDelivered = true
			return nil
		})
	})
	if err != nil {
		if errors.Is(err, timev4.ErrPending) || errors.Is(err, timev4.ErrUnavailable) || errors.Is(err, errCompletionNotEligible) {
			c.mu.Lock()
			d.paused = !errors.Is(err, errCompletionNotEligible)
			c.mu.Unlock()
			return errCompletionNotEligible
		}
		return c.failResultDecode(err)
	}
	authorization.Close(nil)
	defer owned.Close()
	returned := false
	defer func() {
		if recover() != nil || !returned {
			err = c.failResultDecode(ErrUnaryDecodeFailed)
		}
	}()
	value, failure := callback(callCtx, owned.Bytes())
	returned = true
	if failure != nil {
		return c.failResultDecode(ErrUnaryDecodeFailed)
	}
	c.mu.Lock()
	if !d.closed {
		d.value = value
	}
	d.decoded = true
	close(d.decodedDone)
	c.mu.Unlock()
	return nil
}

func (c *UnaryCall) failResultDecode(cause error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	d := c.deferred
	if !d.inputDelivered {
		if d.closed {
			return cryptov4.ErrClosed
		}
		if d.consumed {
			return ErrUnaryResultDelivered
		}
		d.failure = ErrUnaryPayloadUnavailable
		return cause
	}
	if !d.decoded {
		d.failure, d.decoded = ErrUnaryDecodeFailed, true
		close(d.decodedDone)
	}
	return d.failure
}

func (c *UnaryCall) Close() {
	if c == nil {
		return
	}
	c.mu.Lock()
	release := c.discardResultLocked(false)
	c.mu.Unlock()
	release.finish()
}

// advanceResult is SDK-only work on the existing Environment coordinator.
// Namespace expiry closes private input, without changing authenticated wire
// completion facts or canceling application code that already owns its input.
func (c *UnaryCall) advanceResult() bool {
	c.mu.Lock()
	d := c.deferred
	if d == nil || d.cleaned {
		c.mu.Unlock()
		return true
	}
	if d.preparing {
		c.mu.Unlock()
		return false
	}
	// A coordinator visit pins real metadata while clocks and authorization
	// run outside the result gate. Cleanup cannot refund an in-flight check.
	d.visits++
	authorization, dependency := d.authorization, d.dependency
	c.mu.Unlock()
	var authorityError error
	if authorization != nil {
		authorityError = authorization.Check()
	}
	dependency.advance()
	c.mu.Lock()
	d.visits--
	if d.task != nil {
		select {
		case <-d.task.Done():
			err := d.task.Wait(context.Background())
			d.task = nil
			if err != nil && !errors.Is(err, errCompletionNotEligible) && !d.decoded && !d.consumed && !d.closed {
				d.failure = err
				if d.inputDelivered {
					d.failure, d.decoded = ErrUnaryDecodeFailed, true
					close(d.decodedDone)
				}
			}
		default:
		}
	}
	// The clock can recover from temporary unavailability. No TTL replaces
	// the permanently disarmed wire-completion timer of complete input.
	terminal := authorityError != nil && !errors.Is(authorityError, timev4.ErrPending) && !errors.Is(authorityError, timev4.ErrUnavailable)
	var closeAuthorization *protocolv4.DeliveryAuthorization
	var closeFuture *CompletionReservation
	if terminal && d.authorization == authorization && !d.inputDelivered && !d.consumed {
		d.failure = ErrUnaryPayloadUnavailable
		if d.input != nil {
			d.input.Close()
			d.input = nil
		}
		closeAuthorization, d.authorization = d.authorization, nil
		closeFuture, d.decode = d.future, nil
	}
	if d.task == nil {
		if d.inputDelivered {
			d.dependencies.release()
		} else {
			d.dependencies.pruneExited()
		}
	}
	if d.paused && (authorityError == nil || terminal) {
		d.paused = false
		close(d.changed)
		d.changed = make(chan struct{})
	}
	cleaned := d.closed && d.networkSettled && d.waiters == 0 && d.visits == 0 && d.task == nil
	if cleaned {
		d.dependencies.release()
		d.metadata.Release()
		d.metadata = resourcev4.Reference{}
		d.future, d.context, d.cancel, d.inputCancel, d.executor = nil, nil, nil, nil, nil
		d.environment, d.clock, d.dependency = nil, nil, nil
		d.cleaned = true
	}
	c.mu.Unlock()
	if closeAuthorization != nil {
		closeAuthorization.Close(authorityError)
	}
	closeFuture.Close()
	return cleaned
}

func (d *unaryResultState) encodedConflictLocked() error {
	if d.consumed {
		return ErrUnaryResultDelivered
	}
	if d.closed {
		return d.closedErrorLocked()
	}
	if d.inputDelivered {
		return ErrUnaryInputDelivered
	}
	return d.failure
}
