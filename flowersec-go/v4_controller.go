package flowersec

import (
	"context"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// V4ControllerSource supplies a fresh, exclusively owned local recipe for
// each attempt. It must not acquire material or dial during preparation.
// Returning a nonnil preparation transfers its unused inputs even on error.
// The Controller retains that ownership until physical cleanup completes.
type V4ControllerSource interface {
	PrepareConnection(context.Context, V4ControllerRequest) (*V4ControllerPreparation, error)
}

type V4ControllerRequest = sessionv4.ControllerRequest

// V4ControllerPreparation selects one spend authority and either the original
// installed pool source or Config's live material provider. As for Connect,
// all six workspace references must be empty: the SDK reserves them together
// before acquisition. PoolSource is borrowed and never replenished or closed
// by the Controller; each attempt owns its application plan and spend inputs.
type V4ControllerPreparation struct {
	Config     V4SourceConnectConfig
	Pool       *V4PoolSessionInput
	Live       *V4LiveSessionInput
	PoolSource *V4PreauthorizedPoolSource
}

type v4ControllerSource struct{ source V4ControllerSource }

func (s v4ControllerSource) PrepareConnection(ctx context.Context, request sessionv4.ControllerRequest) (*sessionv4.ControllerPreparation, error) {
	if ctx == nil || s.source == nil || isNilV4Interface(s.source) {
		return nil, cryptov4.ErrConfiguration
	}
	p, err := s.source.PrepareConnection(ctx, request)
	if p == nil {
		return nil, err
	}
	prepared := &sessionv4.ControllerPreparation{Config: p.Config, Pool: p.Pool, Live: p.Live}
	if p.PoolSource != nil {
		prepared.PoolSource = p.PoolSource.inner
	}
	// Preserve every transferred cleanup responsibility, including when the
	// source failed after creating only part of its local recipe.
	if err != nil {
		return prepared, err
	}
	if err = ctx.Err(); err != nil {
		return prepared, err
	}
	if (p.Pool == nil) == (p.Live == nil) {
		return prepared, cryptov4.ErrConfiguration
	}
	if p.PoolSource != nil && (prepared.PoolSource == nil || p.Pool == nil || p.Live != nil || p.Config.Identity != nil ||
		p.Config.Provider != nil || p.Config.MaterialRuntimeBytes != 0 || p.Config.Generation != (V4MaterialGeneration{})) {
		return prepared, cryptov4.ErrConfiguration
	}
	prepared.Config, err = reserveV4ConnectionWorkspace(prepared.Config, p.PoolSource == nil)
	return prepared, err
}

type V4ControllerRetirement = sessionv4.ControllerRetirement
type V4ControllerReplaceOptions = sessionv4.ControllerReplaceOptions
type V4ControllerSourceError = sessionv4.ControllerSourceError

func NewV4ControllerSourceError(cause error, notBeforeMS uint64) (*V4ControllerSourceError, error) {
	return sessionv4.NewControllerSourceError(cause, notBeforeMS)
}

const (
	V4ControllerDrain  = sessionv4.ControllerDrain
	V4ControllerRetain = sessionv4.ControllerRetain
)

var (
	ErrV4ControllerBusy           = sessionv4.ErrControllerBusy
	ErrV4ControllerInitialization = sessionv4.ErrControllerInitialization
	ErrV4RetirementCapacity       = sessionv4.ErrRetirementCapacity
)

type V4ControllerOptions struct {
	Clock                                             *V4Clock
	Source                                            V4ControllerSource
	SourceIncarnation                                 [16]byte
	Executor                                          *V4ApplicationExecutor
	InitializeSession                                 func(context.Context, *V4Session) error
	InitializeClass                                   V4WorkClass
	InitializeDependencies                            []V4ServiceDependency
	RequiredContracts                                 [][32]byte
	AttemptTimeoutMS, DrainTimeoutMS, RuntimeBytes    uint64
	MaximumAttempts                                   uint64
	Reservation, InitializeTask, InitializeCompletion V4ResourceReference
}

func (o V4ControllerOptions) config() sessionv4.ControllerConfig {
	c := sessionv4.ControllerConfig{Clock: o.Clock, SourceIncarnation: o.SourceIncarnation, Executor: o.Executor,
		InitializeClass: o.InitializeClass, InitializeDependencies: o.InitializeDependencies, RequiredContracts: o.RequiredContracts, AttemptTimeoutMS: o.AttemptTimeoutMS,
		DrainTimeoutMS: o.DrainTimeoutMS, RuntimeBytes: o.RuntimeBytes, MaximumAttempts: o.MaximumAttempts}
	if o.Source != nil && !isNilV4Interface(o.Source) {
		c.Source = v4ControllerSource{source: o.Source}
	}
	if o.InitializeSession != nil {
		c.InitializeSession = func(context.Context, *sessionv4.EnvironmentSession) error { return cryptov4.ErrConfiguration }
	}
	return c
}

// V4ControllerCharges gives the three separate original allocations. The
// task floor includes protected-reservation metadata; Completion includes the
// original executor's future descriptor. Zero vectors need no reservation.
func V4ControllerCharges(o V4ControllerOptions) (metadata, task, completion V4ResourceVector, err error) {
	metadata, err = sessionv4.ControllerCharge(o.config())
	if err != nil {
		return
	}
	metadata, err = metadata.Add(resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(V4ConnectionController{})) + uint64(unsafe.Sizeof(v4ControllerSource{})) + uint64(unsafe.Sizeof(V4ControllerPreparation{})), resourcev4.Items: 3})
	if err != nil {
		return
	}
	if o.InitializeSession != nil {
		task, err = resourcev4.ProtectedCharge(o.Executor.TaskCharge())
		if err != nil {
			return
		}
		completion = o.Executor.CompletionFloorCharge()
	}
	return
}

type V4ControllerReplaceResult struct {
	CurrentSwitched   bool
	Current, Previous *V4Session
	Retirement        V4ControllerRetirement
	RetainUntilMS     uint64
	PreviousRetained  bool
	RetirementError   *SessionError
}

type V4ControllerSnapshot struct {
	Started, Closed, Initializing, InitializationBlocked bool
	Current, Retired, Pending, CleanupComplete           bool
	LastError                                            *SessionError
	WaitingRetry                                         bool
	WaitingVerification                                  bool
	Attempts, RetryNotBeforeMS                           uint64
}

// V4ConnectionController projects the Environment's original lifecycle owner.
// The Session memoizes its own facade, preserving the same public object from
// initializer to publication without a Controller cache of historical Sessions.
type V4ConnectionController struct {
	inner *sessionv4.ConnectionController
}

func (e *V4Environment) NewConnectionController(ctx context.Context, o V4ControllerOptions) (*V4ConnectionController, error) {
	if e == nil || e.inner == nil {
		return nil, ErrTransportUnavailable
	}
	metadata, _, _, err := V4ControllerCharges(o)
	if err != nil {
		return nil, err
	}
	reservation, err := o.Reservation.Take(metadata)
	if err != nil {
		return nil, err
	}
	defer reservation.Release()
	c := &V4ConnectionController{}
	config := o.config()
	if o.InitializeSession != nil {
		initialize := o.InitializeSession
		config.InitializeSession = func(ctx context.Context, s *sessionv4.EnvironmentSession) error { return initialize(ctx, c.view(s)) }
	}
	inner, err := e.inner.NewConnectionController(ctx, config, reservation, o.InitializeTask, o.InitializeCompletion)
	if err != nil {
		return nil, err
	}
	c.inner = inner
	return c, nil
}

func (c *V4ConnectionController) view(s *sessionv4.EnvironmentSession) *V4Session {
	if s == nil {
		return nil
	}
	return newV4SessionFromEnvironment(s)
}

func (c *V4ConnectionController) Start(ctx context.Context) error {
	if c == nil || c.inner == nil {
		return ErrTransportUnavailable
	}
	return v4ControllerError(c.inner.Start(ctx))
}
func (c *V4ConnectionController) RetryNow(ctx context.Context) error {
	if c == nil || c.inner == nil {
		return ErrTransportUnavailable
	}
	return v4ControllerError(c.inner.RetryNow(ctx))
}

func (c *V4ConnectionController) PrepareUnary(ctx context.Context, method V4UnaryMethod, input []byte, options V4OperationOptions) (*OperationHandle, error) {
	if c == nil || c.inner == nil {
		return nil, ErrTransportUnavailable
	}
	o, err := c.inner.PrepareUnary(ctx, method, input, options.internal())
	if err != nil {
		return nil, v4ControllerError(err)
	}
	return &OperationHandle{inner: o}, nil
}

func (c *V4ConnectionController) Dispatch(ctx context.Context, operation *OperationHandle) OperationStartResult {
	if c == nil || c.inner == nil || operation == nil {
		return OperationStartResult{Err: ErrTransportUnavailable}
	}
	r := c.inner.Dispatch(ctx, operation.inner)
	return OperationStartResult{NotAdmitted: r.NotAdmitted, Err: v4ControllerError(r.Error)}
}
func (c *V4ConnectionController) CaptureSession() (*V4Session, error) {
	if c == nil || c.inner == nil {
		return nil, ErrTransportUnavailable
	}
	s, err := c.inner.CaptureSession()
	return c.view(s), v4ControllerError(err)
}
func (c *V4ConnectionController) WaitForSession(ctx context.Context) (*V4Session, error) {
	if c == nil || c.inner == nil {
		return nil, ErrTransportUnavailable
	}
	s, err := c.inner.WaitForSession(ctx)
	return c.view(s), v4ControllerError(err)
}
func (c *V4ConnectionController) ReplaceSession(ctx context.Context, o V4ControllerReplaceOptions) (V4ControllerReplaceResult, error) {
	if c == nil || c.inner == nil {
		return V4ControllerReplaceResult{}, ErrTransportUnavailable
	}
	r, err := c.inner.ReplaceSession(ctx, o)
	return V4ControllerReplaceResult{CurrentSwitched: r.CurrentSwitched, Current: c.view(r.Current), Previous: c.view(r.Previous), Retirement: r.Retirement, RetainUntilMS: r.RetainUntilMS, PreviousRetained: r.PreviousRetained, RetirementError: v4ControllerSessionError(r.RetirementError)}, v4ControllerError(err)
}
func (c *V4ConnectionController) Snapshot() V4ControllerSnapshot {
	if c == nil || c.inner == nil {
		return V4ControllerSnapshot{Closed: true}
	}
	s := c.inner.Snapshot()
	return V4ControllerSnapshot{Started: s.Started, Closed: s.Closed, Initializing: s.Initializing, InitializationBlocked: s.InitializationBlocked,
		Current: s.Current, Retired: s.Retired, Pending: s.Pending, CleanupComplete: s.CleanupComplete, LastError: v4ControllerSessionError(s.LastError),
		WaitingRetry: s.WaitingRetry, WaitingVerification: s.WaitingVerification, Attempts: s.Attempts, RetryNotBeforeMS: s.RetryNotBeforeMS}
}
func (c *V4ConnectionController) Close() {
	if c != nil && c.inner != nil {
		c.inner.Close()
	}
}
func (c *V4ConnectionController) WaitCleanup(ctx context.Context) error {
	if c == nil || c.inner == nil {
		return ErrTransportUnavailable
	}
	return v4ControllerError(c.inner.WaitCleanup(ctx))
}

// Projection never invokes a source/application error's Error, Is, As or
// Unwrap methods. The public failure contains no retained application graph.
func v4ControllerSessionError(err error) *SessionError {
	if err == nil {
		return nil
	}
	code := SessionOperationFailed
	switch err {
	case context.Canceled, sessionv4.ErrRekeyCancelled:
		code = SessionCanceled
	case context.DeadlineExceeded, timev4.ErrExpired, cryptov4.ErrExpired, sessionv4.ErrDrainDeadline:
		code = SessionTimeout
	case cryptov4.ErrClosed, resourcev4.ErrClosed, sessionv4.ErrPeerClosed:
		code = SessionClosed
	case sessionv4.ErrSessionDraining:
		code = SessionGoingAway
	case cryptov4.ErrCapacity, resourcev4.ErrCapacity, sessionv4.ErrRetirementCapacity:
		code = SessionResourceExhausted
	case timev4.ErrUnavailable, timev4.ErrContinuity:
		code = V4SessionTimeUnavailable
	}
	return &SessionError{code: code}
}

func v4ControllerError(err error) error {
	switch err {
	case nil, ErrV4ControllerBusy, ErrV4ControllerInitialization, ErrV4RetirementCapacity:
		return err
	default:
		return v4ControllerSessionError(err)
	}
}

func (c *V4ConnectionController) CleanupStatus() CleanupStatus {
	if c == nil || c.inner == nil {
		return CleanupStatus{}
	}
	return publicCleanupStatus(c.inner.CleanupStatus())
}
func (*V4ConnectionController) String() string               { return "Flowersec.ConnectionController" }
func (*V4ConnectionController) GoString() string             { return "Flowersec.ConnectionController" }
func (*V4ConnectionController) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }
