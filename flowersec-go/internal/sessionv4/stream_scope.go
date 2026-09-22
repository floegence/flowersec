package sessionv4

import (
	"context"
	"errors"
	"math"
	"sync"
	"time"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

var (
	ErrScopeExchangeIncomplete = errors.New("sessionv4: scope callback did not finish its owned exchange")
	ErrScopeCallbackExit       = errors.New("sessionv4: scope callback exited without returning")
	ErrScopeCleanupIncomplete  = errors.New("sessionv4: scope cleanup incomplete")
)

// StreamScopeOptions fixes the original lifetime before callback entry.
// RuntimeBytes includes both SDK tasks, the sole waiter and channel/allocator
// overhead. The application task has its separate executor reservation.
type StreamScopeOptions struct {
	TimeoutMS, CleanupTimeoutMS, RuntimeBytes uint64
	HardDeadline                              *timev4.Deadline
}

func StreamScopeCharge(options StreamScopeOptions) (resourcev4.Vector, error) {
	fixed := applicationContextBytes() + uint64(unsafe.Sizeof(StreamScope{})) + uint64(unsafe.Sizeof(ScopeStream{})) + uint64(unsafe.Sizeof(timev4.Deadline{})) + uint64(unsafe.Sizeof(timev4.Window{}))
	if options.TimeoutMS == 0 || options.CleanupTimeoutMS == 0 || options.RuntimeBytes == 0 || options.RuntimeBytes > math.MaxUint64-fixed {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	return resourcev4.Vector{resourcev4.SDKBytes: fixed + options.RuntimeBytes, resourcev4.Items: 1, resourcev4.Tasks: 3, resourcev4.WorkSlots: 3, resourcev4.Timers: 1}, nil
}

// ScopeResult preserves local acceptance independently of authenticated drain
// and physical cleanup. Normal requires actual callback EOF, authenticated
// Finish and complete cleanup. Errors retain the original application cause.
type ScopeResult struct {
	AcceptedBytes uint64
	Close         protocolv4.V4CloseResult
	Normal        bool
}

// StreamScope owns one full Stream, one ordinary application invocation and
// two precharged SDK tasks: deadline supervision and lifecycle waiting. Neither
// task invokes application code or borrows protocol maintenance workers. The
// lifecycle task survives a returned incomplete result until real tails exit.
type StreamScope struct {
	dependencies           applicationDependencies
	mu                     sync.Mutex
	owner                  *StreamOwnership
	view                   *ScopeStream
	reservation            resourcev4.Reference
	deadline               *timev4.Deadline
	task                   *ApplicationTask
	cancel                 context.CancelFunc
	first                  error
	result                 ScopeResult
	coreComplete, complete bool
	incomplete, published  bool
	waiting                bool
	finishStart            chan struct{}
	cleanupStart           chan struct{}
	finishResult           chan error
	workerDone             chan struct{}
	ready, done            chan struct{}
}

// StartStreamScope is an internal factory entry. Registration supplies class;
// each distinct reservation has already passed original full-vector admission.
// No callback starts unless canonical ownership and ordinary execution both
// succeed. Failure before callback entry leaves the Stream unreset and usable.
func (a *OpenAdmission) StartStreamScope(ctx context.Context, h OpenHandle, options StreamScopeOptions, executor *ApplicationExecutor, class ApplicationWorkClass, scopeReservation, ownershipReservation, taskReservation resourcev4.Reference, callback func(context.Context, *ScopeStream) error) (*StreamScope, error) {
	if ctx == nil || executor == nil || callback == nil || scopeReservation == ownershipReservation || scopeReservation == taskReservation || ownershipReservation == taskReservation {
		return nil, cryptov4.ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	charge, err := StreamScopeCharge(options)
	if err != nil {
		return nil, err
	}
	clock := a.engine.Clock()
	if !options.HardDeadline.BelongsTo(clock) {
		return nil, timev4.ErrOwner
	}
	if err := scopeReservation.CheckSameEnvironment(ownershipReservation); err != nil {
		return nil, err
	}
	owned, err := scopeReservation.Take(charge)
	if err != nil {
		return nil, err
	}
	start, err := clock.Sample()
	var deadline *timev4.Deadline
	if err == nil {
		deadline, err = options.HardDeadline.ForkAgeAt(start, options.TimeoutMS)
	}
	if err != nil {
		owned.Release()
		return nil, err
	}
	o, err := a.ownStreamContext(h, ownershipReservation, deadline, ctx)
	if err != nil {
		owned.Release()
		return nil, err
	}
	dependencies, err := captureApplicationDependencies(ctx)
	if err != nil {
		_ = o.Release()
		owned.Release()
		return nil, err
	}
	callCtx, cancel := context.WithCancel(ctx)
	s := &StreamScope{dependencies: dependencies, owner: o, reservation: owned, deadline: deadline, cancel: cancel, finishStart: make(chan struct{}), cleanupStart: make(chan struct{}), finishResult: make(chan error, 1), workerDone: make(chan struct{}), ready: make(chan struct{}), done: make(chan struct{})}
	s.view = &ScopeStream{owner: o, cap: o.cap, idle: make(chan struct{})}
	s.result.Close.CleanupStatus = protocolv4.V4CleanupStatus{Status: protocolv4.V4CleanupStatePending, CoreCleanup: protocolv4.V4CoreCleanupPending, PendingCallbacks: 1}
	task, err := executor.TrySubmit(class, taskReservation, owned, func() {
		cause := ErrScopeCallbackExit
		defer s.dependencies.release()
		defer func() {
			// Preserve handler panic isolation. Never format or retain an
			// arbitrary application panic value in the transport owner.
			if recover() != nil {
				cause = ErrScopeCallbackExit
			}
			s.recordFailure(cause)
			normal := s.view.seal()
			if cause == nil && !normal {
				cause = ErrScopeExchangeIncomplete
			}
			s.recordFailure(cause)
		}()
		if cause = ctx.Err(); cause != nil {
			return
		}
		if cause = o.enterCallback(); cause != nil {
			return
		}
		// Goexit executes the defer above without a successful callback result.
		cause = ErrScopeCallbackExit
		invocationCtx, exit, e := enterApplicationContext(callCtx, executor, ordinaryApplicationLane, class, s.reservation, &s.dependencies)
		if e != nil {
			cause = e
			return
		}
		defer exit()
		cause = callback(invocationCtx, s.view)
	})
	if err != nil {
		s.dependencies.release()
		cancel()
		_ = o.Release() // No callback or I/O alias was admitted.
		owned.Release()
		return nil, err
	}
	s.task = task
	go s.lifecycle(callCtx)
	go s.supervise(ctx, clock, options.CleanupTimeoutMS)
	return s, nil
}

func (s *StreamScope) recordFailure(err error) {
	if err == nil {
		return
	}
	s.mu.Lock()
	if s.first == nil {
		s.first = err
	}
	s.mu.Unlock()
}

func (s *StreamScope) failure() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.first
}

func (s *StreamScope) fail(err error) {
	s.recordFailure(err)
	s.view.seal()
	s.owner.Revoke()
	s.cancel()
	_ = s.owner.Cancel()
}

func (s *StreamScope) supervise(ctx context.Context, clock *timev4.Clock, cleanupMS uint64) {
	operationCtx := ctx
	engine := s.owner.admission.engine
	sessionDone := engine.Done()
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	defer timer.Stop()
	callbackDone := s.task.Done()
	var cleanup *timev4.Window
	closing := false
	startCleanup := func() {
		if !closing {
			closing = true
			var err error
			cleanup, err = timev4.NewWindow(clock, cleanupMS)
			if err != nil {
				s.recordFailure(err)
			}
			close(s.cleanupStart)
		}
	}
	for {
		remaining, err := s.deadline.RemainingMS()
		if s.failure() != nil {
			s.fail(s.failure())
			startCleanup()
		} else if err != nil {
			s.fail(err)
			startCleanup()
		}
		if closing {
			var cleanupErr error
			if cleanup == nil {
				cleanupErr = ErrScopeCleanupIncomplete
			} else {
				var left uint64
				left, cleanupErr = cleanup.RemainingMS()
				if s.failure() != nil || err != nil {
					remaining = left
				} else {
					remaining = min(remaining, left)
				}
			}
			if cleanupErr != nil {
				s.fail(ErrScopeCleanupIncomplete)
				s.publishIncomplete()
				<-s.workerDone
				s.completeScope()
				return
			}
		}
		timer.Reset(idleTimerChunk(remaining))
		select {
		case <-callbackDone:
			callbackDone = nil
			if s.failure() == nil && !closing {
				close(s.finishStart)
			}
		case err := <-s.finishResult:
			if err != nil {
				s.fail(err)
			}
			startCleanup()
		case <-ctx.Done():
			s.fail(ctx.Err())
			startCleanup()
			// Cancellation is permanent; do not spin on a closed channel.
			ctx = context.Background()
		case <-sessionDone:
			s.fail(cryptov4.ErrClosed)
			startCleanup()
			sessionDone = nil
		case <-timer.C:
		case <-s.workerDone:
			if s.failure() == nil {
				err := operationCtx.Err()
				if err == nil {
					err = engine.CheckApplicationAuthorization()
				}
				if err == nil {
					err = s.deadline.Check()
				}
				if err == nil && cleanup != nil {
					if cleanup.Check() != nil {
						err = ErrScopeCleanupIncomplete
					}
				}
				if err != nil {
					s.fail(err)
				}
			}
			s.completeScope()
			return
		}
		timer.Stop()
	}
}

func (s *StreamScope) lifecycle(ctx context.Context) {
	defer close(s.workerDone)
	select {
	case <-s.finishStart:
		s.finishResult <- s.owner.Finish(ctx)
		<-s.cleanupStart
	case <-s.cleanupStart:
	}
	o := s.owner
	for {
		// Consume old merged edges before observing current original facts.
		select {
		case <-o.changed:
		default:
		}
		if err := o.Cleanup(context.Background()); err == nil {
			break
		}
		<-o.changed
	}
	s.mu.Lock()
	s.coreComplete = true
	s.mu.Unlock()
	<-s.task.Done()
	<-s.view.idle
	if s.failure() == nil {
		if err := s.deadline.Check(); err != nil {
			s.fail(err)
		}
	}
	result, _ := o.CloseResult()
	accepted := o.AcceptedBytes()
	s.mu.Lock()
	s.result.AcceptedBytes, s.result.Close = accepted, result
	s.mu.Unlock()
	for {
		select {
		case <-o.changed:
		default:
		}
		if err := o.Release(); err == nil {
			break
		}
		<-o.changed
	}
	s.view.detach()
}

func (s *StreamScope) publishIncomplete() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.incomplete = true
	if !s.published {
		s.published = true
		close(s.ready)
	}
}

func (s *StreamScope) completeScope() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.complete = true
	s.result.Normal = s.first == nil && s.result.Close.SendDrained && s.result.Close.ReadTerminal == protocolv4.V4ReadTerminalEof
	s.result.Close.CleanupStatus = protocolv4.V4CleanupStatus{Status: protocolv4.V4CleanupStateComplete, CoreCleanup: protocolv4.V4CoreCleanupComplete}
	s.cancel()
	s.cancel = nil
	s.owner, s.view, s.task, s.deadline = nil, nil, nil, nil
	s.reservation.Release()
	s.reservation = resourcev4.Reference{}
	if !s.published {
		s.published = true
		close(s.ready)
	}
	close(s.done)
}

// Wait cancellation ends only this wait. The factory's operation context and
// fixed overall deadline own cancellation of the complete exchange.
func (s *StreamScope) Wait(ctx context.Context) (ScopeResult, error) {
	if ctx == nil {
		return ScopeResult{}, cryptov4.ErrConfiguration
	}
	s.mu.Lock()
	if s.published {
		s.mu.Unlock()
		return s.Result()
	}
	if s.waiting {
		s.mu.Unlock()
		return ScopeResult{}, ErrStreamOwnershipBusy
	}
	// The single observer owns a real alias of the original complete charge.
	// Core/callback completion may detach the transport graph, but cannot
	// refund this observer's task/stack while a host wait is still returning.
	tail, err := s.reservation.Borrow()
	if err != nil {
		s.mu.Unlock()
		return ScopeResult{}, err
	}
	s.waiting = true
	s.mu.Unlock()
	defer func() { s.mu.Lock(); s.waiting = false; tail.Release(); s.mu.Unlock() }()
	select {
	case <-s.ready:
		return s.Result()
	case <-ctx.Done():
		result, _ := s.Result()
		return result, ctx.Err()
	}
}

func (s *StreamScope) Result() (ScopeResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.result
	if !s.complete {
		r.AcceptedBytes = s.owner.AcceptedBytes()
		if result, err := s.owner.CloseResult(); err == nil {
			r.Close = result
		}
		r.Close.CleanupStatus = protocolv4.V4CleanupStatus{Status: protocolv4.V4CleanupStatePending, CoreCleanup: protocolv4.V4CoreCleanupPending, PendingCallbacks: 1}
		if s.incomplete {
			r.Close.CleanupStatus.Status = protocolv4.V4CleanupStateCleanupIncomplete
		}
		if s.coreComplete {
			r.Close.CleanupStatus.CoreCleanup = protocolv4.V4CoreCleanupComplete
		}
		select {
		case <-s.task.Done():
			r.Close.CleanupStatus.PendingCallbacks = 0
		default:
		}
	}
	return r, s.first
}

func (s *StreamScope) Done() <-chan struct{} { return s.done }

// ScopeStream exposes data and half-close only. The scope privately retains
// Reset, Finish and cleanup authority. Escaped methods cannot reopen the view.
type ScopeStream struct {
	mu          sync.Mutex
	owner       *StreamOwnership
	users, cap  uint64
	eof, sealed bool
	cursor      *ScopeReaderCursor
	idle        chan struct{}
}

func (v *ScopeStream) begin() (*StreamOwnership, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.sealed || v.owner == nil {
		return nil, ErrStreamOwned
	}
	if v.users == v.cap {
		return nil, ErrStreamOwnershipBusy
	}
	v.users++
	return v.owner, nil
}

func (v *ScopeStream) end(eof bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.eof = v.eof || eof
	v.users--
	v.owner.notify()
	if v.sealed && v.users == 0 {
		close(v.idle)
	}
}

func (v *ScopeStream) seal() bool {
	v.mu.Lock()
	normal := v.eof && v.users == 0 && v.cursor == nil
	if v.sealed {
		v.mu.Unlock()
		return normal
	}
	v.sealed = true
	if v.users == 0 {
		close(v.idle)
	}
	cursor, owner := v.cursor, v.owner
	v.cursor = nil
	v.mu.Unlock()
	// Cursor Close may acquire cursor -> receive gates. It must never run
	// under the full-Stream admission/queue/pool claim or callback view gate.
	if cursor != nil {
		cursor.cursor.Close()
	}
	settled := owner.sealApplication()
	return normal && settled
}

func (v *ScopeStream) detach() { v.mu.Lock(); v.owner = nil; v.mu.Unlock() }

func (v *ScopeStream) ReadInto(ctx context.Context, dst []byte) (ReadTransfer, error) {
	o, err := v.begin()
	if err != nil {
		return ReadTransfer{}, err
	}
	r, err := o.ReadInto(ctx, dst)
	v.end(err == nil && r.ReadTerminal == protocolv4.V4ReadTerminalEof)
	return r, err
}

func (v *ScopeStream) TryRead(dst []byte) (int, protocolv4.V4ReadTerminal, error) {
	o, err := v.begin()
	if err != nil {
		return 0, protocolv4.V4ReadTerminalUnknown, err
	}
	n, terminal, err := o.TryRead(dst)
	v.end(err == nil && terminal == protocolv4.V4ReadTerminalEof)
	return n, terminal, err
}

func (v *ScopeStream) Write(ctx context.Context, input []byte) (int, error) {
	o, err := v.begin()
	if err != nil {
		return 0, err
	}
	defer v.end(false)
	return o.Write(ctx, input)
}

func (v *ScopeStream) WriteAll(ctx context.Context, input []byte) (int, error) {
	o, err := v.begin()
	if err != nil {
		return 0, err
	}
	defer v.end(false)
	return o.WriteAll(ctx, input)
}

func (v *ScopeStream) CloseWrite(ctx context.Context) error {
	o, err := v.begin()
	if err != nil {
		return err
	}
	defer v.end(false)
	return o.CloseWrite(ctx)
}

func (v *ScopeStream) PrepareWrite(input []byte, options WriteOptions) (*WriteOperation, error) {
	o, err := v.begin()
	if err != nil {
		return nil, err
	}
	defer v.end(false)
	return o.PrepareWrite(input, options)
}

func (v *ScopeStream) CopyTo(ctx context.Context, destination *ScopeStream, chunkBytes uint64, reservation resourcev4.Reference) (CopyResult, error) {
	if destination == nil || destination == v {
		return CopyResult{}, cryptov4.ErrConfiguration
	}
	source, err := v.begin()
	if err != nil {
		return CopyResult{}, err
	}
	target, err := destination.begin()
	if err != nil {
		v.end(false)
		return CopyResult{}, err
	}
	result, err := source.CopyTo(ctx, target, chunkBytes, reservation)
	destination.end(false)
	v.end(err == nil && result.SourceTerminal == protocolv4.V4ReadTerminalEof)
	return result, err
}
