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

var (
	ErrControllerBusy           = errors.New("sessionv4: controller attempt still owns work")
	ErrControllerInitialization = errors.New("sessionv4: controller initialization requires explicit replacement")
	ErrRetirementCapacity       = errors.New("sessionv4: retirement_capacity")
)

// ControllerSource is a trusted SDK assembly provider, like the material and
// carrier providers. It returns a fresh, once-owned plan on every invocation.
// A nonnil result transfers its unused preparation ownership even on error.
// Cancellation does not imply that this method or its provider tails exited.
// This method prepares local inputs; lease acquisition belongs to Connect.
type ControllerSource interface {
	PrepareConnection(context.Context, ControllerRequest) (*ControllerPreparation, error)
}

type ControllerRequest struct {
	Attempt           uint64
	SourceIncarnation [16]byte
	Deadline          *timev4.Deadline
}

type ControllerPreparation struct {
	Config     SourceConnectConfig
	Pool       *PoolSessionInput
	Live       *LiveSessionInput
	PoolSource *PreauthorizedPoolSource
}

type ControllerConfig struct {
	InitializeDependencies []ServiceDependency
	Clock                  *timev4.Clock
	Source                 ControllerSource
	SourceIncarnation      [16]byte
	Executor               *ApplicationExecutor
	InitializeSession      func(context.Context, *EnvironmentSession) error
	InitializeClass        ApplicationWorkClass
	// RequiredContracts is the fixed union of required unary contracts. The
	// original Session routes and a live RPC publisher must qualify together.
	RequiredContracts                              [][32]byte
	AttemptTimeoutMS, DrainTimeoutMS, RuntimeBytes uint64
	// MaximumAttempts bounds consecutive connection attempts; zero preserves
	// the long-lived intent. Each successful current starts a new cycle.
	MaximumAttempts uint64
}

type ControllerRetirement uint8

const (
	ControllerDrain ControllerRetirement = iota
	ControllerRetain
)

type ControllerReplaceOptions struct {
	Retirement    ControllerRetirement
	RetainUntilMS uint64
}

type ControllerReplaceResult struct {
	CurrentSwitched   bool
	Current, Previous *EnvironmentSession
	Retirement        ControllerRetirement
	RetainUntilMS     uint64
	// PreviousRetained is the actual installation fact. A previous path that
	// stopped accepting during replacement cannot be reopened by retain.
	PreviousRetained bool
	RetirementError  error
}

type ControllerSnapshot struct {
	Started, Closed, Initializing, InitializationBlocked bool
	Current, Retired, Pending                            bool
	CleanupComplete                                      bool
	WaitingRetry                                         bool
	WaitingVerification                                  bool
	Attempts, RetryNotBeforeMS                           uint64
	LastError                                            error
}

type controllerAttempt struct {
	serial                       uint64
	ctx                          context.Context
	cancel                       context.CancelCauseFunc
	deadline                     *timev4.Deadline
	retention                    *timev4.Deadline
	options                      ControllerReplaceOptions
	previous, candidate          *EnvironmentSession
	result                       ControllerReplaceResult
	err                          error
	done                         chan struct{}
	finished, exited, entered    bool
	initialized, callbackRunning bool
	verificationPending          bool
	cleanupError                 error
	unused                       *ControllerPreparation
	sourceFailure                *ControllerSourceError
	transportFailure             bool
	automatic                    bool
	initializer                  *ApplicationPermit
	completion                   *CompletionReservation
	initialization               *controllerInitializerPlan
	workloads                    controllerWorkloadPlan
}

// ConnectionController owns only acquisition, publication and retirement.
// All protocol, admission, authorization and cleanup remain on the original
// EnvironmentSession. Three fixed links cover current, candidate and retirement;
// the Environment and root still charge every actual Session exactly once.
type ConnectionController struct {
	dependencyMu                            sync.Mutex
	dependencyRevision                      uint64
	initializeServices                      *invocationServices
	operations                              [256]*UnaryOperation
	workloadPositions                       [256]*controllerWorkloadPosition
	mu                                      sync.Mutex
	config                                  ControllerConfig
	identity                                *controllerIdentity
	environment                             *Environment
	position                                int
	reservation, shared                     resourcev4.Reference
	task                                    *resourcev4.ProtectedReservation
	completion                              *CompletionFloor
	lifetime                                context.Context
	current, retired                        *EnvironmentSession
	retention                               *timev4.Deadline
	retirement                              ControllerRetirement
	retirementStarted                       bool
	attempt                                 *controllerAttempt
	serial                                  uint64
	cycleAttempts                           uint64
	automatic, retryRequested, retryPending bool
	retryContext                            context.Context
	retryWindow                             *timev4.Window
	retryNotBefore                          uint64
	dispatches                              uint32
	started, closed, blocked, cleaned       bool
	lastError                               error
	closingAt                               time.Time
	wake, changed, done                     chan struct{}
}

func ControllerCharge(c ControllerConfig) (resourcev4.Vector, error) {
	if c.InitializeSession == nil && len(c.InitializeDependencies) != 0 {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	dependencies, err := serviceDependenciesChargeFor(c.InitializeDependencies, false)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	if c.Clock == nil || c.Source == nil || c.SourceIncarnation == ([16]byte{}) || c.RuntimeBytes == 0 ||
		c.AttemptTimeoutMS == 0 || c.AttemptTimeoutMS > 90000 || c.DrainTimeoutMS == 0 || c.DrainTimeoutMS > 90000 ||
		len(c.RequiredContracts) > 128 || c.InitializeClass > ApplicationResident || c.InitializeSession != nil && c.Executor == nil || c.MaximumAttempts > 9_007_199_254_740_991 {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	for i, digest := range c.RequiredContracts {
		if digest == ([32]byte{}) {
			return resourcev4.Vector{}, cryptov4.ErrConfiguration
		}
		for _, earlier := range c.RequiredContracts[:i] {
			if earlier == digest {
				return resourcev4.Vector{}, cryptov4.ErrConfiguration
			}
		}
	}
	n := uint64(unsafe.Sizeof(ConnectionController{})) + uint64(unsafe.Sizeof(controllerAttempt{})) +
		uint64(unsafe.Sizeof([8]*boundUnaryMethod{})) + uint64(unsafe.Sizeof([8]ServiceContractTarget{})) + uint64(unsafe.Sizeof([8]UnaryContractSnapshot{})) +
		uint64(unsafe.Sizeof(ControllerPreparation{})) + 2*uint64(unsafe.Sizeof(timev4.Deadline{})) +
		uint64(unsafe.Sizeof(time.Timer{})) + uint64(unsafe.Sizeof(timev4.Window{})) + applicationContextBytes() + uint64(len(c.RequiredContracts))*32
	n += uint64(unsafe.Sizeof(controllerInitializerContext{}))
	if c.RuntimeBytes > math.MaxUint64/2 {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	charge, err := (resourcev4.Vector{resourcev4.SDKBytes: n + uint64(unsafe.Sizeof(controllerIdentity{})), resourcev4.Items: 12, resourcev4.Tasks: 2, resourcev4.WorkSlots: 2, resourcev4.Timers: 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: 2 * c.RuntimeBytes})
	if err != nil {
		return resourcev4.Vector{}, err
	}
	charge, err = charge.Add(dependencies)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	return charge.Add(initializerPlanCharge(c.InitializeDependencies))
}

// NewConnectionController transfers three original reservations. Task and
// completion inputs are required only when the initializer is configured.
func (e *Environment) NewConnectionController(ctx context.Context, c ControllerConfig, reservation, task, completion resourcev4.Reference) (*ConnectionController, error) {
	if e == nil || ctx == nil {
		return nil, cryptov4.ErrConfiguration
	}
	charge, err := ControllerCharge(c)
	if err != nil {
		return nil, err
	}
	if c.InitializeSession == nil && (task != (resourcev4.Reference{}) || completion != (resourcev4.Reference{})) {
		return nil, cryptov4.ErrConfiguration
	}
	if _, err = timev4.NewAge(c.Clock, c.AttemptTimeoutMS, math.MaxUint64); err != nil {
		return nil, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return nil, cryptov4.ErrClosed
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if err = reservation.CheckSameEnvironment(e.reservation); err != nil {
		return nil, err
	}
	position := -1
	for i, controller := range e.controllers {
		if controller == nil {
			position = i
			break
		}
	}
	if position < 0 {
		return nil, cryptov4.ErrCapacity
	}
	shared, err := e.reservation.Borrow()
	if err != nil {
		return nil, err
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		shared.Release()
		return nil, err
	}
	controller := &ConnectionController{config: c, identity: &controllerIdentity{}, environment: e, position: position, reservation: owned, shared: shared,
		lifetime: ctx, wake: make(chan struct{}, 1), changed: make(chan struct{}), done: make(chan struct{})}
	if c.InitializeSession != nil {
		if err = task.CheckSameEnvironment(owned); err == nil {
			err = completion.CheckSameEnvironment(owned)
		}
		if err == nil {
			controller.task, err = resourcev4.NewProtectedReservation(task, c.Executor.TaskCharge())
		}
		if err == nil {
			controller.completion, err = c.Executor.NewCompletionFloor(completion, owned)
		}
		if err != nil {
			if controller.task != nil {
				controller.task.Close()
			}
			owned.Release()
			shared.Release()
			return nil, err
		}
	}
	controller.config.RequiredContracts = append([][32]byte(nil), c.RequiredContracts...)
	// Reserve the original finite position before leaving the Environment
	// gate. Close can seal it, but construction owns cleanup until publication.
	e.controllers[position] = controller
	e.controllersActive++
	e.mu.Unlock()
	controller.initializeServices, err = newInvocationServicesFor(c.InitializeDependencies, owned, false)
	e.mu.Lock()
	controller.mu.Lock()
	if err == nil && (e.closed || controller.closed || ctx.Err() != nil) {
		err = cryptov4.ErrClosed
	}
	controller.mu.Unlock()
	if err != nil {
		controller.initializeServices.close()
		if controller.task != nil {
			controller.task.Close()
		}
		if controller.completion != nil {
			controller.completion.Close()
		}
		owned.Release()
		shared.Release()
		e.controllers[position] = nil
		e.controllersActive--
		e.completeLocked()
		return nil, err
	}
	controller.config.InitializeDependencies = nil
	go controller.run()
	return controller, nil
}

func (c *ConnectionController) signalLocked() {
	c.changedLocked()
	notifyOpenWait(c.wake)
}

func (c *ConnectionController) changedLocked() {
	close(c.changed)
	c.changed = make(chan struct{})
}

func (*ConnectionController) String() string               { return "Flowersec.ConnectionController" }
func (*ConnectionController) GoString() string             { return "Flowersec.ConnectionController" }
func (*ConnectionController) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

func (c *ConnectionController) Close() {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.closeLocked()
	c.mu.Unlock()
}

// This gate never invokes provider, Session, source or application code.
func (c *ConnectionController) closeLocked() {
	if c.closed {
		return
	}
	c.closed = true
	c.retryWindow = nil
	c.closingAt = time.Now()
	if a := c.attempt; a != nil {
		a.cancel(cryptov4.ErrClosed)
		c.finishLocked(a, cryptov4.ErrClosed)
	}
	c.signalLocked()
}

func (c *ConnectionController) Snapshot() ControllerSnapshot {
	if c == nil {
		return ControllerSnapshot{Closed: true}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	// Creating the original retry window samples the clock outside this gate.
	// Keep that real transition pending until the window or its failure is
	// published; observers must not mistake the gap for a terminal failure.
	s := ControllerSnapshot{Started: c.started, Closed: c.closed, InitializationBlocked: c.blocked, Current: c.current != nil, Retired: c.retired != nil, Pending: c.attempt != nil || c.retryPending, CleanupComplete: c.cleaned, LastError: c.lastError}
	s.Initializing = c.attempt != nil && c.attempt.entered && !c.attempt.finished
	s.WaitingRetry, s.Attempts, s.RetryNotBeforeMS = c.retryWindow != nil, c.cycleAttempts, c.retryNotBefore
	s.WaitingVerification = c.attempt != nil && c.attempt.verificationPending
	return s
}

func (c *ConnectionController) WaitCleanup(ctx context.Context) error {
	if c == nil || ctx == nil {
		return cryptov4.ErrConfiguration
	}
	if ctx.Value(controllerInitializerKey{}) == c.identity {
		return ErrApplicationDependency
	}
	for {
		c.mu.Lock()
		cleaned, closed, start, changed := c.cleaned, c.closed, c.closingAt, c.changed
		c.mu.Unlock()
		if cleaned {
			return nil
		}
		if !closed {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-changed:
			}
			continue
		}
		remaining := time.Until(start.Add(sessionCleanupTimeout))
		if remaining <= 0 {
			return ErrSessionCleanupIncomplete
		}
		timer := time.NewTimer(remaining)
		select {
		case <-c.done:
			timer.Stop()
			return nil
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
			return ErrSessionCleanupIncomplete
		}
	}
}

// CleanupStatus observes the fixed owner set. Logical failure and observer
// timeout never remove a provider, initializer or accepted publication tail.
func (c *ConnectionController) CleanupStatus() protocolv4.V4CleanupStatus {
	status := protocolv4.V4CleanupStatus{Status: protocolv4.V4CleanupStatePending, CoreCleanup: protocolv4.V4CoreCleanupPending}
	if c == nil {
		return status
	}
	c.mu.Lock()
	if c.cleaned {
		c.mu.Unlock()
		status.Status, status.CoreCleanup = protocolv4.V4CleanupStateComplete, protocolv4.V4CoreCleanupComplete
		return status
	}
	current, retired := c.current, c.retired
	var candidate *EnvironmentSession
	pending := c.attempt != nil || c.retryPending
	if a := c.attempt; a != nil {
		candidate = a.candidate
		if a.callbackRunning {
			status.PendingCallbacks++
		}
		if a.cleanupError != nil {
			status.Status = protocolv4.V4CleanupStateCleanupIncomplete
		}
	}
	if c.closed && !time.Now().Before(c.closingAt.Add(sessionCleanupTimeout)) {
		status.Status = protocolv4.V4CleanupStateCleanupIncomplete
	}
	coreDone := !pending && c.dispatches == 0
	c.mu.Unlock()
	for i, s := range [3]*EnvironmentSession{current, retired, candidate} {
		if s == nil || i == 1 && s == current || i == 2 && (s == current || s == retired) {
			continue
		}
		child := s.CleanupStatus()
		coreDone = coreDone && child.CoreCleanup == protocolv4.V4CoreCleanupComplete
		status.PendingCallbacks += child.PendingCallbacks
		if child.Status == protocolv4.V4CleanupStateCleanupIncomplete {
			status.Status = child.Status
		}
	}
	if coreDone {
		status.CoreCleanup = protocolv4.V4CoreCleanupComplete
	}
	return status
}
