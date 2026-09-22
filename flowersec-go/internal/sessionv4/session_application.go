package sessionv4

import (
	"context"
	"errors"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

var (
	ErrApplicationAuthorization = errors.New("sessionv4: application authorization unavailable")
	ErrApplicationRelease       = errors.New("sessionv4: application lease release unconfirmed")
)

// ApplicationBinding identifies the exact authenticated material, selected
// route and original attempt. It contains no keys, proof bytes or credentials.
// Trusted adapters compare this complete value with their original local
// authorization lookup; principal equality alone is not sufficient.
type ApplicationBinding struct {
	Artifact, ClientIdentity, ServerIdentity, Route [32]byte
	Attempt, Candidate                              [16]byte
	CandidateIndex                                  uint64
	Role                                            protocolv4.Direction
	Source, ApplicationProfile                      string
}

// AuthenticatedRequestContext is borrowed only during AuthorizeApplication.
// Retaining it cannot retain or recover a Session or an execution permit.
// Binding is a detached inspection value, not a durable admission receipt.
type AuthenticatedRequestContext struct {
	invocation *applicationInvocation
	binding    ApplicationBinding
}

func (c AuthenticatedRequestContext) Binding() ApplicationBinding { return c.binding }
func (AuthenticatedRequestContext) String() string                { return "Flowersec.AuthenticatedRequestContext" }
func (AuthenticatedRequestContext) GoString() string              { return "Flowersec.AuthenticatedRequestContext" }
func (AuthenticatedRequestContext) MarshalJSON() ([]byte, error)  { return []byte("{}"), nil }

// ReserveLease records the trusted adapter's original cleanup responsibility
// before it returns its result. This must be called immediately when the
// application reserve succeeds, including a late or uncertain success. Even a
// subsequent panic, Goexit or error cannot lose this registered responsibility.
// The exact binding must come from the adapter's authenticated local lookup.
// The application context is immutable and its backing belongs to the declared
// dependency owner; arbitrary application allocations are not cloned by the SDK.
func (c AuthenticatedRequestContext) ReserveLease(binding ApplicationBinding, applicationContext any, release func(context.Context) error) (*ApplicationLease, error) {
	if c.invocation == nil || binding != c.binding || release == nil {
		return nil, ErrApplicationAuthorization
	}
	i := c.invocation
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.lease == nil {
		return nil, ErrApplicationAuthorization
	}
	l := i.lease
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.reserved {
		return nil, cryptov4.ErrTransition
	}
	l.reserved, l.binding, l.context, l.release = true, binding, applicationContext, release
	return l, i.ctx.Err()
}

type applicationInvocation struct {
	mu    sync.Mutex
	lease *ApplicationLease
	ctx   context.Context
}

// ApplicationLease is one local authorization owner. Revocation is terminal
// and uses the existing credential watchdog wake; it starts no new worker and
// invokes no application code under protocol/crypto gates. Retained handles
// are detached from dependencies and credentials after actual cleanup.
type ApplicationLease struct {
	execution                     executionSessionIdentity
	executionHistory              []executionHistoryAccess
	notifications                 *NotificationDispatch
	services                      *ServiceDispatch
	mu                            sync.Mutex
	binding                       ApplicationBinding
	context                       any
	release                       func(context.Context) error
	authorization                 *protocolv4.EndpointAuthorization
	reserved, authorized, revoked bool
	queryMethods                  []queryMethodAccess
	queryEpoch                    uint64
}

func (*ApplicationLease) String() string               { return "Flowersec.ApplicationLease" }
func (*ApplicationLease) GoString() string             { return "Flowersec.ApplicationLease" }
func (*ApplicationLease) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }
func (l *ApplicationLease) Revoke() {
	if l == nil {
		return
	}
	l.mu.Lock()
	l.revoked = true
	a := l.authorization
	l.mu.Unlock()
	if a != nil {
		a.Notify()
	}
}
func (l *ApplicationLease) Check() error {
	if l == nil {
		return ErrApplicationAuthorization
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.reserved || !l.authorized || l.revoked {
		return ErrApplicationAuthorization
	}
	return nil
}
func (l *ApplicationLease) bindAuthorization(a *protocolv4.EndpointAuthorization) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.authorized || l.revoked || a == nil || l.authorization != nil && l.authorization != a {
		return ErrApplicationAuthorization
	}
	l.authorization = a
	return nil
}

type AuthorizeApplicationResult struct {
	Handlers *StreamHandlerPlan
	Lease    *ApplicationLease
}

// SessionPlan freezes the declared transport handler set and authorization
// callback for either signed role. Its resource and future cleanup owners exist
// before consumer spend or accepted admission. Services/execution declarations
// are validated by their own profile assembly; this component grants none.
type SessionPlanConfig struct {
	Services                   bool
	Handlers                   *StreamHandlerPlan
	AuthorizeApplication       func(context.Context, AuthenticatedRequestContext) (AuthorizeApplicationResult, error)
	RuntimeBytes               uint64
	ContractQueries            bool
	ContractQueryMethods       []ContractQueryMethod
	ExecutionHistoryNamespaces []string
}
type SessionPlan struct {
	resumePolicy                                           protocolv4.ResumePolicy
	notifications                                          *NotificationDispatch
	rpc                                                    *RPCServices
	rpcPreparing                                           bool
	services                                               *ServiceDispatch
	queries                                                *sessionContractQueries
	applicationGroup                                       *applicationGroup
	host                                                   *EnvironmentSession
	mu                                                     sync.Mutex
	config                                                 SessionPlanConfig
	executor                                               *ApplicationExecutor
	reservation, taskReservation, dependencies             resourcev4.Reference
	completion                                             *CompletionReservation
	releaseTask                                            *CompletionTask
	invocation                                             *applicationInvocation
	lease                                                  *ApplicationLease
	cancel                                                 context.CancelFunc
	claimed, started, running, authorized, closed, retired bool
	callbackDone                                           chan struct{}
}

func SessionPlanCharge(c SessionPlanConfig) (resourcev4.Vector, error) {
	if c.AuthorizeApplication == nil || c.RuntimeBytes == 0 {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	query, err := sessionContractQueriesCharge(c)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	history, err := sessionExecutionHistoryCharge(c)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	query, err = query.Add(history)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	charge, err := (resourcev4.Vector{resourcev4.SDKBytes: applicationContextBytes() + uint64(unsafe.Sizeof(SessionPlan{})) + uint64(unsafe.Sizeof(applicationGroup{})) + uint64(unsafe.Sizeof(applicationInvocation{})) + uint64(unsafe.Sizeof(ApplicationLease{})), resourcev4.Items: 5}).Add(resourcev4.Vector{resourcev4.SDKBytes: c.RuntimeBytes})
	if err != nil {
		return resourcev4.Vector{}, err
	}
	return charge.Add(query)
}

// NewSessionPlan consumes metadata and the original future ordinary task
// reservation and reserves protected Completion capacity before accepting any
// application lease responsibility. Dependencies is an already admitted borrow.
func NewSessionPlan(c SessionPlanConfig, executor *ApplicationExecutor, metadata, task, completion, dependenciesBorrow resourcev4.Reference) (_ *SessionPlan, err error) {
	charge, err := SessionPlanCharge(c)
	if err != nil || executor == nil {
		return nil, cryptov4.ErrConfiguration
	}
	for _, ref := range []resourcev4.Reference{task, completion, dependenciesBorrow} {
		if err := metadata.CheckSameEnvironment(ref); err != nil {
			return nil, err
		}
	}
	if c.Handlers != nil && c.Handlers.Executor() != executor {
		return nil, cryptov4.ErrConfiguration
	}
	if c.ContractQueries && executor.config.QueryOwners < 2 {
		return nil, cryptov4.ErrConfiguration
	}
	group, err := executor.newApplicationGroup()
	if err != nil {
		return nil, err
	}
	dependencies, err := dependenciesBorrow.TakeBorrow()
	if err != nil {
		return nil, err
	}
	owned, err := metadata.Take(charge)
	if err != nil {
		dependencies.Release()
		return nil, err
	}
	p := &SessionPlan{config: c, executor: executor, applicationGroup: group, reservation: owned, dependencies: dependencies, lease: &ApplicationLease{}, invocation: &applicationInvocation{}, callbackDone: make(chan struct{})}
	p.initializeContractQueryMethods(c.ContractQueryMethods)
	p.initializeExecutionHistory(c.ExecutionHistoryNamespaces)
	defer func() {
		if err != nil {
			executor.cancelApplicationGroup(group)
			if p.completion != nil {
				p.completion.Close()
			}
			p.taskReservation.Release()
			p.reservation.Release()
			p.dependencies.Release()
		}
	}()
	p.taskReservation, err = task.Take(executor.TaskCharge())
	if err != nil {
		return nil, err
	}
	p.completion, err = executor.ReserveCompletion(completion, p.reservation)
	if err != nil {
		return nil, err
	}
	if c.Handlers != nil {
		if err = c.Handlers.requireApplication(p); err != nil {
			return nil, err
		}
	}
	return p, nil
}

// adoptApplicationCore commits both plans under their original construction
// gates. A failed/competing adoption leaves the application plan unclaimed.
func (a *SessionAdmissionReservation) adoptApplicationCore(batch *sessionCoreBatch, refs []resourcev4.Reference) error {
	p := a.config.Application
	if p != nil {
		p.mu.Lock()
		defer p.mu.Unlock()
		if p.closed || p.claimed || p.rpcPreparing || p.config.Handlers != a.config.Core.Handlers.Plan || p.host != a.config.applicationHost {
			return cryptov4.ErrTransition
		}
		if p.config.Services && p.services == nil {
			return cryptov4.ErrConfiguration
		}
		if err := p.checkContractQueriesLocked(); err != nil {
			return err
		}
		if err := p.reservation.CheckSameEnvironment(a.environment); err != nil {
			return err
		}
	}
	core, err := batch.adopt(refs)
	if err != nil {
		return err
	}
	a.core = core
	if p != nil {
		p.claimed = true
		a.application = p
	}
	return nil
}

// authorize joins actual callback exit on the original establishment worker.
// Its original Environment watcher still reports cancellation promptly; no
// canceled waiter can refund a blocked callback or manufacture a second call.
func (p *SessionPlan) authorize(ctx context.Context, binding ApplicationBinding, guard func() error) error {
	dependencies, dependencyErr := captureApplicationDependencies(ctx)
	if dependencyErr != nil {
		return dependencyErr
	}
	defer dependencies.release()
	p.mu.Lock()
	if p.closed || p.started || !p.claimed {
		p.mu.Unlock()
		return ErrApplicationAuthorization
	}
	if err := p.dependencies.Check(); err != nil {
		p.mu.Unlock()
		return err
	}
	p.started, p.running = true, true
	callCtx, cancel := context.WithCancel(ctx)
	p.cancel = cancel
	p.invocation.mu.Lock()
	p.invocation.lease, p.invocation.ctx = p.lease, callCtx
	p.invocation.mu.Unlock()
	callback := p.config.AuthorizeApplication
	request := AuthenticatedRequestContext{p.invocation, binding}
	p.mu.Unlock()
	var result AuthorizeApplicationResult
	callbackErr := ErrApplicationAuthorization
	work := func() {
		defer func() {
			if recover() != nil {
				callbackErr = ErrApplicationAuthorization
			}
			p.invocation.mu.Lock()
			p.invocation.lease, p.invocation.ctx = nil, nil
			p.invocation.mu.Unlock()
		}()
		if callCtx.Err() != nil || guard() != nil {
			return
		}
		invocationCtx, exit, e := enterApplicationContext(callCtx, p.executor, ordinaryApplicationLane, ApplicationShort, p.reservation, &dependencies)
		if e != nil {
			callbackErr = e
			return
		}
		defer exit()
		result, callbackErr = callback(invocationCtx, request)
	}
	var done <-chan struct{}
	var queued *QueuedApplicationTask
	var err error
	if p.executor.config.Ready != 0 && dependencies.count == 0 {
		// This explicitly enabled queue is the first admission attempt. It
		// never retries a failed try-now invocation or creates another worker.
		queued, err = p.executor.queueApplication(p.applicationGroup, ApplicationShort, p.taskReservation, p.reservation, work)
		if err == nil {
			done = queued.Done()
		}
	} else {
		var task *ApplicationTask
		task, err = p.executor.TrySubmit(ApplicationShort, p.taskReservation, p.reservation, work)
		if err == nil {
			done = task.Done()
		}
	}
	if err == nil {
		if queued != nil {
			select {
			case <-done:
			case <-callCtx.Done():
				queued.Cancel()
			}
		}
		<-done
		if queued != nil && queued.Canceled() {
			err = cryptov4.ErrClosed
		}
	}
	// A canceled ready task never enters work or its defers. The original
	// caller also detaches the borrowed callback capability on that path.
	p.invocation.mu.Lock()
	p.invocation.lease, p.invocation.ctx = nil, nil
	p.invocation.mu.Unlock()
	cancel()
	// Do not hold the plan lock while reentering original admission gates.
	if err == nil {
		err = guard()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.running, p.cancel = false, nil
	close(p.callbackDone)
	if err != nil {
		return err
	}
	if p.closed || ctx.Err() != nil || callbackErr != nil || result.Lease != p.lease || result.Handlers != p.config.Handlers {
		return ErrApplicationAuthorization
	}
	p.lease.mu.Lock()
	defer p.lease.mu.Unlock()
	if !p.lease.reserved || p.lease.revoked || p.lease.binding != binding {
		return ErrApplicationAuthorization
	}
	if p.config.Handlers != nil {
		if err := p.config.Handlers.bindApplication(p, p.lease.context); err != nil {
			return err
		}
	}
	p.lease.authorized, p.authorized = true, true
	return nil
}
func (p *SessionPlan) checkPreparation() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return cryptov4.ErrClosed
	}
	if p.rpcPreparing {
		return cryptov4.ErrTransition
	}
	if p.config.Services && p.services == nil {
		return cryptov4.ErrConfiguration
	}
	if err := p.checkContractQueriesLocked(); err != nil {
		return err
	}
	if err := p.reservation.Check(); err != nil {
		return err
	}
	if err := p.dependencies.Check(); err != nil {
		return err
	}
	if p.authorized {
		return p.lease.Check()
	}
	return nil
}
func (p *SessionPlan) checkAuthorized() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || !p.authorized {
		return ErrApplicationAuthorization
	}
	return p.lease.Check()
}
func (p *SessionPlan) Close() {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.closed = true
	cancel := p.cancel
	queries := p.queries
	services := p.services
	notifications := p.notifications
	rpc := p.rpc
	executor, group := p.executor, p.applicationGroup
	p.lease.mu.Lock()
	p.lease.revoked = true
	authorization := p.lease.authorization
	p.lease.mu.Unlock()
	p.mu.Unlock()
	if rpc != nil {
		rpc.Close()
	}
	if executor != nil {
		executor.cancelApplicationGroup(group)
	}
	if services != nil {
		services.Close()
	}
	if notifications != nil {
		notifications.Close()
	}
	if queries != nil {
		queries.close()
	}
	if authorization != nil {
		authorization.Notify()
	}
	if cancel != nil {
		cancel()
	}
}

// releaseAfterCleanup is called only by the original admission aggregate after
// all handler/core/provider methods have actually exited. An unclaimed plan may
// also be disposed through Retire without ever entering application code.
func (p *SessionPlan) releaseAfterCleanup(ctx context.Context) error {
	p.mu.Lock()
	if !p.closed {
		p.mu.Unlock()
		return cryptov4.ErrTransition
	}
	running := p.running
	group := p.applicationGroup
	queries := p.queries
	services := p.services
	notifications := p.notifications
	rpc := p.rpc
	preparing := p.rpcPreparing
	p.mu.Unlock()
	if preparing {
		return cryptov4.ErrCapacity
	}
	if rpc != nil {
		rpc.Close()
		if err := rpc.waitChannel(ctx); err != nil {
			return err
		}
	}
	if services != nil {
		services.Close()
		if err := services.WaitCleanup(ctx); err != nil {
			return err
		}
	}
	if notifications != nil {
		notifications.Close()
		select {
		case <-notifications.done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if queries != nil {
		queries.close()
		if err := queries.wait(ctx); err != nil {
			return err
		}
	}
	if group != nil {
		select {
		case <-group.done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if running {
		select {
		case <-p.callbackDone:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	p.mu.Lock()
	if p.releaseTask == nil && p.completion != nil {
		task, err := p.completion.Submit(func() error {
			p.lease.mu.Lock()
			release := p.lease.release
			p.lease.mu.Unlock()
			if release != nil {
				releaseCtx, exit, err := enterCleanupApplicationContext(p.executor, p.reservation)
				if err != nil {
					return err
				}
				defer exit()
				if err := release(releaseCtx); err != nil {
					return ErrApplicationRelease
				}
			}
			return nil
		})
		if err != nil {
			p.mu.Unlock()
			return err
		}
		p.releaseTask, p.completion = task, nil
	}
	task := p.releaseTask
	p.mu.Unlock()
	if task == nil {
		return nil
	}
	if err := task.Wait(ctx); err != nil {
		return err
	}
	return nil
}
func (p *SessionPlan) Retire() error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.retired {
		return nil
	}
	if !p.closed || p.running || p.rpcPreparing {
		return cryptov4.ErrCapacity
	}
	if p.applicationGroup != nil {
		select {
		case <-p.applicationGroup.done:
		default:
			return cryptov4.ErrCapacity
		}
	}
	if p.services != nil {
		select {
		case <-p.services.done:
		default:
			return cryptov4.ErrCapacity
		}
		p.services = nil
	}
	if p.notifications != nil {
		select {
		case <-p.notifications.done:
		default:
			return cryptov4.ErrCapacity
		}
		p.notifications = nil
	}
	if p.queries != nil {
		if !p.queries.complete() {
			return cryptov4.ErrCapacity
		}
		p.queries = nil
	}
	if p.rpc != nil {
		if err := p.rpc.retire(); err != nil {
			return err
		}
		p.rpc = nil
	}
	if p.started {
		if p.releaseTask == nil {
			return cryptov4.ErrCapacity
		}
		select {
		case <-p.releaseTask.Done():
		default:
			return cryptov4.ErrCapacity
		}
		if err := p.releaseTask.Wait(context.Background()); err != nil {
			return err
		}
	} else if p.completion != nil {
		p.completion.Close()
		p.completion = nil
	}
	p.lease.mu.Lock()
	p.lease.authorization, p.lease.context, p.lease.release = nil, nil, nil
	p.lease.execution = executionSessionIdentity{}
	p.lease.executionHistory = nil
	p.lease.queryMethods = nil
	p.lease.services = nil
	p.lease.notifications = nil
	p.lease.mu.Unlock()
	if p.config.Handlers != nil {
		p.config.Handlers.detachApplication(p)
	}
	p.config, p.executor, p.host = SessionPlanConfig{}, nil, nil
	p.applicationGroup = nil
	p.reservation.Release()
	p.taskReservation.Release()
	p.dependencies.Release()
	p.reservation, p.taskReservation, p.dependencies = resourcev4.Reference{}, resourcev4.Reference{}, resourcev4.Reference{}
	p.retired = true
	return nil
}

// applicationAuthorization composes only bounded SDK gates. Credential and
// application revocation share the same original watch channel and deadline.
type applicationAuthorization struct {
	endpoint *protocolv4.EndpointAuthorization
	lease    *ApplicationLease
}

func (g *applicationAuthorization) Check() error {
	if err := g.lease.Check(); err != nil {
		return err
	}
	return g.endpoint.Check()
}
func (g *applicationAuthorization) RemainingMS() (uint64, error) {
	if err := g.lease.Check(); err != nil {
		return 0, err
	}
	return g.endpoint.RemainingMS()
}
func (g *applicationAuthorization) Wake() <-chan struct{} { return g.endpoint.Wake() }
func (g *applicationAuthorization) Notify()               { g.endpoint.Notify() }
func (g *applicationAuthorization) Close(cause error)     { g.lease.Revoke(); g.endpoint.Close(cause) }

func (g *applicationAuthorization) ForkDelivery(reservation resourcev4.Reference) (*protocolv4.DeliveryAuthorization, error) {
	if err := g.lease.Check(); err != nil {
		return nil, err
	}
	return g.endpoint.ForkDelivery(reservation)
}

func (p *SessionEstablishment) authorizeApplication(a *SessionAdmissionReservation) error {
	if a.application == nil {
		return nil
	}
	if err := p.guard(); err != nil {
		return err
	}
	binding := ApplicationBinding{Artifact: p.session.ArtifactDigest, Attempt: p.material.Hello.Attempt, Candidate: p.expected.CandidateID, Route: p.expected.RouteDigest, CandidateIndex: p.expected.Index, Role: p.material.Role, Source: p.material.Source, ApplicationProfile: p.session.Contract.Limits().ApplicationProfile}
	var err error
	binding.ClientIdentity, err = p.material.ClientCertificate.Digest("certificate_digest")
	if err != nil {
		return err
	}
	binding.ServerIdentity, err = p.material.ServerCertificate.Digest("certificate_digest")
	if err != nil {
		return err
	}
	if a.accepted != nil {
		// These values come from this entrance's complete verified FSB binding,
		// not client metadata, a callback claim or a restored admission row.
		facts, err := a.acceptedFacts.Fields()
		if err != nil {
			return err
		}
		if facts.Artifact != binding.Artifact || facts.Attempt != binding.Attempt || facts.Candidate != binding.Candidate || facts.Route != binding.Route || facts.ClientIdentity != binding.ClientIdentity || facts.ServerIdentity != binding.ServerIdentity || facts.Source != binding.Source || facts.CandidateIndex != binding.CandidateIndex {
			return ErrApplicationAuthorization
		}
	}
	if err := a.application.authorize(a.ctx, binding, p.guard); err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.checkLocked(); err != nil {
		return err
	}
	if a.authorization != nil {
		if err := a.application.lease.bindAuthorization(a.authorization); err != nil {
			return err
		}
	}
	if a.accepted != nil {
		g := &a.accepted.guard
		g.mu.Lock()
		defer g.mu.Unlock()
		if err := g.checkLocked(); err != nil {
			return err
		}
		g.application = a.application.lease
	}
	return nil
}

// claimPreparation fixes the same original Environment position before any
// source/listener provider work. Reusing it along that position's intake stages
// is allowed; another position cannot acquire the plan or its cleanup promise.
func (p *SessionPlan) claimPreparation(s *EnvironmentSession) error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.config.Services && (!s.environment.services || p.services == nil || p.services.clock != s.environment.materialClock || p.services.executionRegistry != nil && p.services.executionRegistry != s.environment.serviceRegistry) {
		return cryptov4.ErrConfiguration
	}
	if p.notifications != nil && p.notifications.executionRegistry != nil && p.notifications.executionRegistry != s.environment.serviceRegistry {
		return cryptov4.ErrConfiguration
	}
	if p.closed || p.claimed || p.rpcPreparing || p.host != nil && p.host != s {
		return cryptov4.ErrTransition
	}
	if err := p.reservation.CheckSameEnvironment(s.environment.reservation); err != nil {
		return err
	}
	if err := p.dependencies.Check(); err != nil {
		return err
	}
	p.host = s
	return nil
}
func (p *SessionPlan) undoPreparation(s *EnvironmentSession) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.claimed && p.host == s {
		p.host = nil
	}
}

// retireUnclaimed belongs to the Environment position that acquired the plan,
// after its actual provider tails exit. The core owns a claimed handler plan;
// this branch owns declarations that never reached core adoption.
func (p *SessionPlan) retireUnclaimed() error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	claimed, handlers := p.claimed, p.config.Handlers
	p.mu.Unlock()
	if claimed {
		return nil
	}
	p.Close()
	if handlers != nil {
		handlers.Close()
		if err := handlers.WaitCleanup(context.Background()); err != nil {
			return err
		}
		if err := handlers.Retire(); err != nil {
			return err
		}
	}
	return p.Retire()
}
