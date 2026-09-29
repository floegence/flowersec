package sessionv4

import (
	"context"
	"errors"
	"math"
	"strings"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
)

// DispatchRequirement is trusted local policy, never a wire capability.
// Its zero value requires readiness before the first application entry.
type DispatchRequirement uint8

const (
	RequiredForDispatch DispatchRequirement = iota
	OnUse
)

type ServiceDependencyMethod struct {
	Method              UnaryMethodSelector
	DispatchRequirement DispatchRequirement
}

// ServiceDependency borrows exact methods of an existing service binding.
// Registration copies only these bounded selectors, not clients or contracts.
type ServiceDependency struct {
	Alias   string
	Client  *UnaryServiceClient
	Methods []ServiceDependencyMethod
}

type invocationServiceBinding struct {
	alias           string
	client          *UnaryServiceClient
	methods         []ServiceDependencyMethod
	requiredMethods []*boundUnaryMethod
	borrow          resourcev4.Reference
	required        bool
}

// This is part of the original registration, not an independently owned root.
type invocationServices struct {
	admissionNext  *invocationServices
	admissionKind  uint8
	admissionIndex int
	sealed         atomic.Bool
	mu             sync.Mutex
	bindings       []invocationServiceBinding
	backing        resourcev4.Reference
	primary        resourcev4.Reference
	viewReferences *resourcev4.BorrowPool
	closed         bool
	visits         uint32
}

type dependencyStreamTarget struct {
	workload   *unaryWorkload
	services   *RPCServices
	controller *ConnectionController
	namespace  string
	typeID     uint32
	shape      [32]byte
}

func serviceDependenciesCharge(declarations []ServiceDependency) (resourcev4.Vector, error) {
	return serviceDependenciesChargeFor(declarations, true)
}

func serviceDependenciesChargeFor(declarations []ServiceDependency, ordinary bool) (resourcev4.Vector, error) {
	if len(declarations) == 0 {
		return resourcev4.Vector{}, nil
	}
	if len(declarations) > 64 {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	charge := resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(invocationServices{})), resourcev4.Items: 1}
	count := 0
	for i, d := range declarations {
		if d.Client == nil || len(d.Alias) == 0 || len(d.Alias) > 64 || len(d.Methods) == 0 || len(d.Methods) > 256 {
			return resourcev4.Vector{}, cryptov4.ErrConfiguration
		}
		for j, ch := range []byte(d.Alias) {
			if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch == '_' || j > 0 && ch >= '0' && ch <= '9') {
				return resourcev4.Vector{}, cryptov4.ErrConfiguration
			}
		}
		for _, previous := range declarations[:i] {
			if previous.Alias == d.Alias {
				return resourcev4.Vector{}, cryptov4.ErrConfiguration
			}
		}
		count += len(d.Methods)
		if count > 256 {
			return resourcev4.Vector{}, cryptov4.ErrConfiguration
		}
		for j, method := range d.Methods {
			if method.DispatchRequirement > OnUse || method.Method.Type == 0 || len(method.Method.Namespace) == 0 || len(method.Method.Namespace) > 128 {
				return resourcev4.Vector{}, cryptov4.ErrConfiguration
			}
			for _, previous := range d.Methods[:j] {
				if previous.Method == method.Method {
					return resourcev4.Vector{}, cryptov4.ErrConfiguration
				}
			}
			charge[resourcev4.SDKBytes] += uint64(unsafe.Sizeof(ServiceDependencyMethod{})) + uint64(unsafe.Sizeof((*boundUnaryMethod)(nil))) + uint64(len(method.Method.Namespace))
			charge[resourcev4.Items]++
		}
		charge[resourcev4.SDKBytes] += uint64(unsafe.Sizeof(invocationServiceBinding{})) + uint64(len(d.Alias))
		charge[resourcev4.Items]++
	}
	if ordinary {
		capacity, err := invocationViewReferenceCapacity(declarations)
		if err != nil {
			return resourcev4.Vector{}, err
		}
		aliases, err := resourcev4.BorrowPoolCharge(capacity)
		if err != nil {
			return resourcev4.Vector{}, err
		}
		return charge.Add(aliases)
	}
	return charge, nil
}

func newInvocationServices(declarations []ServiceDependency, backing resourcev4.Reference) (_ *invocationServices, err error) {
	return newInvocationServicesFor(declarations, backing, true)
}

func newInvocationServicesFor(declarations []ServiceDependency, backing resourcev4.Reference, ordinary bool) (_ *invocationServices, err error) {
	charge, err := serviceDependenciesChargeFor(declarations, ordinary)
	if err != nil || len(declarations) == 0 {
		return nil, err
	}
	if err = backing.CheckMinimum(charge); err != nil {
		return nil, err
	}
	owned, err := backing.Borrow()
	if err != nil {
		return nil, err
	}
	s := &invocationServices{backing: owned, primary: backing, bindings: make([]invocationServiceBinding, len(declarations))}
	adopted := false
	defer func() {
		if !adopted {
			s.close()
		}
	}()
	for i, declaration := range declarations {
		c := declaration.Client
		c.mu.Lock()
		if c.closed || c.cleaned {
			err = cryptov4.ErrClosed
		} else {
			for _, method := range declaration.Methods {
				if method.Method.Namespace != c.namespace {
					err = rpcv4.ErrMethod
					break
				}
				if _, err = c.methodLocked(method.Method.Type); err != nil {
					break
				}
			}
		}
		var borrow resourcev4.Reference
		if err == nil {
			borrow, err = c.metadata.Borrow()
		}
		c.mu.Unlock()
		if err != nil {
			return nil, err
		}
		b := &s.bindings[i]
		b.alias, b.client, b.borrow = strings.Clone(declaration.Alias), c, borrow
		b.methods = make([]ServiceDependencyMethod, len(declaration.Methods))
		b.requiredMethods = make([]*boundUnaryMethod, len(declaration.Methods))
		for j, method := range declaration.Methods {
			method.Method.Namespace = strings.Clone(method.Method.Namespace)
			b.methods[j] = method
		}
	}
	for i := range s.bindings {
		binding := &s.bindings[i]
		if err = binding.adjustRequired(true); err != nil {
			return nil, err
		}
		binding.required = true
	}
	if ordinary {
		capacity, e := invocationViewReferenceCapacity(declarations)
		if e != nil {
			return nil, e
		}
		s.viewReferences, err = resourcev4.NewBorrowPoolInBacking(backing, capacity)
		if err != nil {
			return nil, err
		}
	}
	adopted = true
	return s, nil
}

// Every registration in the same Environment shares this bounded qualification.
// The caller serializes additions with dependencyMu; removals only relax demand.
// Original method slots supply all facts, without a second dependency registry.
func (e *Environment) checkRequiredStreamCapacity(addition *invocationServiceBinding) error {
	return e.checkRequiredStreamCapacityUpdate(addition, nil, nil, [32]byte{}, nil, nil, nil)
}

func (e *Environment) checkRequiredStreamCapacityUpdate(addition *invocationServiceBinding, replacement *UnaryServiceClient, method *boundUnaryMethod, digest [32]byte, projected *ConnectionController, candidate *RPCServices, extra *dependencyStreamTarget) error {
	targets := e.dependencyTargets
	defer clear(targets)
	count := 0
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || e.retired {
		return cryptov4.ErrClosed
	}
	for _, c := range e.serviceClients {
		if c == nil {
			continue
		}
		c.mu.Lock()
		if c.closed || c.cleaned {
			c.mu.Unlock()
			continue
		}
		for i := range c.methods {
			m := &c.methods[i]
			required := m.requiredDeclarations.Load() != 0
			if addition != nil && c == addition.client && !required {
				for _, selection := range addition.methods {
					if selection.Method.Type == m.definition.Type && selection.DispatchRequirement == RequiredForDispatch {
						required = true
						break
					}
				}
			}
			if !required || m.definition.Shape != 1 {
				continue
			}
			contract := m.definition.Method.Contract
			if c == replacement && m == method {
				contract = digest
			}
			x := dependencyStreamTarget{controller: c.source.controller, namespace: c.namespace, typeID: m.definition.Type,
				shape: preacceptedBinding(m.definition.StreamKind, m.definition.StreamMetadata, contract)}
			x.services = c.services
			if x.controller != nil {
				if x.controller == projected {
					x.services = candidate
				} else {
					x.services = x.controller.currentDependencyServices()
				}
			}
			x.workload = c.methodWorkloadLocked(m, x.services)
			duplicate, service, session := false, 1, 1
			for _, previous := range targets[:count] {
				if previous == x {
					duplicate = true
					break
				}
				if previous.services == x.services && previous.controller == x.controller {
					session++
					if previous.namespace == x.namespace {
						service++
					}
				}
			}
			if duplicate {
				continue
			}
			if service > maxPreacceptedStreamsPerService || session > maxPreacceptedStreams || count == len(targets) {
				c.mu.Unlock()
				return cryptov4.ErrCapacity
			}
			targets[count], count = x, count+1
			if err := checkPhysicalDependencyTargets(targets[:count], x); err != nil {
				c.mu.Unlock()
				return err
			}
		}
		c.mu.Unlock()
	}
	for i, target := range targets[:count] {
		if target.services == nil {
			continue
		}
		seen := false
		for _, previous := range targets[:i] {
			seen = seen || previous.services == target.services
		}
		if !seen {
			if err := checkExistingDependencyPool(targets[:count], target.services, extra); err != nil {
				return err
			}
		}
	}
	if extra != nil {
		seen := false
		for _, target := range targets[:count] {
			seen = seen || target.services == extra.services
		}
		if !seen {
			return checkExistingDependencyPool(targets[:count], extra.services, extra)
		}
	}
	return nil
}

func (s *invocationServices) close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	s.sealed.Store(true)
	for i := range s.bindings {
		if s.bindings[i].required {
			_ = s.bindings[i].adjustRequired(false)
			s.bindings[i].required = false
		}
	}
	s.cleanupLocked()
}

func (s *invocationServices) cleanupLocked() {
	if !s.closed || s.visits != 0 {
		return
	}
	for i := range s.bindings {
		s.bindings[i].borrow.Release()
		s.bindings[i] = invocationServiceBinding{}
	}
	s.bindings = nil
	s.viewReferences.Close()
	s.viewReferences = nil
	s.backing.Release()
	s.backing = resourcev4.Reference{}
	s.primary = resourcev4.Reference{}
}

func (s *invocationServices) requiredReady(ctx context.Context) error {
	if s == nil {
		return nil
	}
	if p := initializerPlanFromContext(ctx); p != nil && p.declaration == s {
		return p.requiredReady(ctx)
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ErrApplicationDependency
	}
	if err := s.backing.Check(); err != nil {
		s.mu.Unlock()
		return err
	}
	if s.visits == math.MaxUint32 {
		s.mu.Unlock()
		return cryptov4.ErrCapacity
	}
	s.visits++
	bindings := s.bindings
	s.mu.Unlock()
	defer func() { s.mu.Lock(); s.visits--; s.cleanupLocked(); s.mu.Unlock() }()
	for i := range bindings {
		binding := &bindings[i]
		for _, method := range binding.methods {
			if method.DispatchRequirement == RequiredForDispatch {
				if err := binding.client.dependencyReady(ctx, method.Method.Type); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// dependencyReady observes one original source and current snapshot. It never
// allocates an operation, runs a codec, queries, opens, retries or replenishes.
func (c *UnaryServiceClient) dependencyReady(ctx context.Context, methodType uint32) error {
	return c.dependencyReadyOn(ctx, methodType, nil, nil)
}

func (c *UnaryServiceClient) dependencyReadyOn(ctx context.Context, methodType uint32, target *ConnectionController, candidate *EnvironmentSession) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	if c.closed || c.cleaned {
		c.mu.Unlock()
		return cryptov4.ErrClosed
	}
	c.visits++
	controller, services, clock := c.source.controller, c.services, c.clock
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		c.visits--
		e := c.environment
		c.mu.Unlock()
		if e != nil {
			e.signalMaterials()
		}
	}()
	if controller != nil {
		var selected *RPCServices
		var err error
		if controller == target && candidate != nil {
			selected, err = c.checkControllerSourceIdentity(candidate, false)
		} else {
			_, selected, err = c.captureControllerSource(controller)
		}
		if err != nil {
			return err
		}
		services = selected
	}
	now, err := clock.Sample()
	if err != nil {
		return err
	}
	c.mu.Lock()
	m, err := c.methodLocked(methodType)
	if err != nil {
		c.mu.Unlock()
		return err
	}
	if controller == target && candidate != nil && c.remoteContracts && !m.candidateContract.matches(services, m.generation) {
		c.mu.Unlock()
		return cryptov4.ErrNotReady
	}
	snapshot := c.contractLocked(m, services, now, nil)
	method := m.definition
	method.Method.workload = c.methodWorkloadLocked(m, services)
	if m.workload.Calls != 0 && method.Method.workload == nil {
		c.mu.Unlock()
		return cryptov4.ErrNotReady
	}
	c.mu.Unlock()
	if snapshot.Error != nil {
		if errors.Is(snapshot.Error, rpcv4.ErrMethod) || errors.Is(snapshot.Error, rpcv4.ErrAdmissionOfferUnavailable) {
			return cryptov4.ErrNotReady
		}
		return snapshot.Error
	}
	_, policy, err := services.routes.RegisteredContractPolicy(snapshot.Digest)
	if err != nil {
		return err
	}
	if policy.Semantics == 1 && !snapshot.OfferReady {
		return cryptov4.ErrNotReady
	}
	var stream *streamPreparationPlan
	if method.Shape == 2 {
		stream = &streamPreparationPlan{notify: true}
	} else if method.Shape == 1 {
		var core *SessionCore
		var err error
		if controller == target && candidate != nil {
			core, err = candidate.Core()
		} else {
			core, err = services.bindingCore()
		}
		if err != nil {
			return err
		}
		stream = &streamPreparationPlan{workload: method.Method.workload, core: core, kind: method.StreamKind, metadata: method.StreamMetadata}
	}
	if err := services.checkDependencyPath(ctx, snapshot.Digest, stream); err != nil {
		return err
	}
	if candidate == nil {
		c.mu.Lock()
		if m.dependencyPath.services == services {
			m.dependencyPath = dependencyPathPreparation{}
		}
		c.mu.Unlock()
	}
	return nil
}

// InvocationService is a method-restricted view of an existing client. It has
// no binding, refresh, update, source, lifecycle or generation controls.
type InvocationService struct {
	origin *applicationContext
	index  int
}

func InvocationServiceFromContext(ctx context.Context, alias string) (InvocationService, error) {
	if ctx == nil {
		return InvocationService{}, ErrApplicationDependency
	}
	if _, err := checkApplicationContext(ctx); err != nil {
		return InvocationService{}, err
	}
	origin, _ := ctx.Value(applicationContextKey{}).(*applicationContext)
	if origin == nil {
		return InvocationService{}, ErrApplicationDependency
	}
	origin.state.mu.Lock()
	live, services := origin.state.live, origin.state.services
	origin.state.mu.Unlock()
	if !live || services == nil || ctx.Err() != nil {
		return InvocationService{}, ErrApplicationDependency
	}
	services.mu.Lock()
	defer services.mu.Unlock()
	if !services.closed {
		for i, binding := range services.bindings {
			if binding.alias == alias {
				return InvocationService{origin: origin, index: i}, nil
			}
		}
	}
	return InvocationService{}, ErrApplicationDependency
}

// A selected view retains both the application origin and the registration
// that owns its client borrows. These are usually different responsibilities;
// an initializer may share one primary and therefore needs only one alias.
// Keeping the registration visit prevents Close from clearing its borrowed
// clients while a selected method is still entering or awaiting its operation.
type invocationServiceUse struct {
	services     *invocationServices
	origin       resourcev4.Reference
	registration resourcev4.Reference
}

func (u *invocationServiceUse) Release() {
	if u.services == nil {
		return
	}
	s := u.services
	s.mu.Lock()
	u.origin.Release()
	u.registration.Release()
	s.visits--
	s.cleanupLocked()
	s.mu.Unlock()
	*u = invocationServiceUse{}
}

func (v InvocationService) selectMethod(ctx context.Context, selector UnaryMethodSelector) (*UnaryServiceClient, invocationServiceUse, error) {
	if ctx == nil || v.origin == nil {
		return nil, invocationServiceUse{}, ErrApplicationDependency
	}
	current, _ := ctx.Value(applicationContextKey{}).(*applicationContext)
	if current == nil || current.state != v.origin.state {
		return nil, invocationServiceUse{}, ErrApplicationDependency
	}
	if _, err := checkApplicationContext(ctx); err != nil {
		return nil, invocationServiceUse{}, err
	}
	v.origin.state.mu.Lock()
	s := v.origin.state.services
	v.origin.state.mu.Unlock()
	if s == nil {
		return nil, invocationServiceUse{}, ErrApplicationDependency
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || v.index < 0 || v.index >= len(s.bindings) {
		return nil, invocationServiceUse{}, ErrApplicationDependency
	}
	if s.visits == math.MaxUint32 {
		return nil, invocationServiceUse{}, cryptov4.ErrCapacity
	}
	binding := &s.bindings[v.index]
	for _, method := range binding.methods {
		if method.Method == selector {
			v.origin.state.mu.Lock()
			defer v.origin.state.mu.Unlock()
			origin := v.origin.state
			if !origin.live || !origin.currentSerialLocked(current.serial) || origin.services != s {
				return nil, invocationServiceUse{}, ErrApplicationDependency
			}
			var hold resourcev4.Reference
			var err error
			if origin.dependencyFloor != nil {
				// Initializers retain their exact pre-Acquire Controller floor.
				hold, err = origin.borrowDependencyLocked()
			} else {
				hold, err = s.viewReferences.Borrow(origin.backing)
			}
			if err != nil {
				return nil, invocationServiceUse{}, err
			}
			use := invocationServiceUse{services: s, origin: hold}
			if origin.backing != s.primary {
				use.registration, err = s.viewReferences.Borrow(s.primary)
				if err != nil {
					hold.Release()
					return nil, invocationServiceUse{}, err
				}
			}
			s.visits++
			return binding.client, use, nil
		}
	}
	return nil, invocationServiceUse{}, rpcv4.ErrMethod
}

func (v InvocationService) Prepare(ctx context.Context, method UnaryMethodSelector, input []byte, options rpcv4.UnaryPreparation) (*UnaryOperation, error) {
	c, hold, err := v.selectMethod(ctx, method)
	if err != nil {
		return nil, err
	}
	defer hold.Release()
	return c.PrepareMethod(ctx, method.Type, input, options)
}

func (v InvocationService) Call(ctx context.Context, method UnaryMethodSelector, input []byte, options rpcv4.UnaryPreparation) (any, UnaryResultStatus, error) {
	c, hold, err := v.selectMethod(ctx, method)
	if err != nil {
		return nil, UnaryResultStatus{}, err
	}
	defer hold.Release()
	return c.CallMethod(ctx, method.Type, input, options)
}

func (v InvocationService) Stream(ctx context.Context, method UnaryMethodSelector, input []byte, options rpcv4.UnaryPreparation) (*StreamOperation, error) {
	c, hold, err := v.selectMethod(ctx, method)
	if err != nil {
		return nil, err
	}
	defer hold.Release()
	return c.StreamMethod(ctx, method.Type, input, options)
}

func (v InvocationService) PrepareStream(ctx context.Context, method UnaryMethodSelector, input []byte, options rpcv4.UnaryPreparation) (*StreamOperation, error) {
	c, hold, err := v.selectMethod(ctx, method)
	if err != nil {
		return nil, err
	}
	defer hold.Release()
	return c.PrepareStreamingMethod(ctx, method.Type, input, options)
}

func (v InvocationService) PrepareNotify(ctx context.Context, method UnaryMethodSelector, input []byte, options rpcv4.UnaryPreparation) (*NotifyOperation, error) {
	c, hold, err := v.selectMethod(ctx, method)
	if err != nil {
		return nil, err
	}
	defer hold.Release()
	return c.PrepareNotifyMethod(ctx, method.Type, input, options)
}

func (v InvocationService) Notify(ctx context.Context, method UnaryMethodSelector, input []byte, options rpcv4.UnaryPreparation) (NotificationResult, error) {
	c, hold, err := v.selectMethod(ctx, method)
	if err != nil {
		return NotificationResult{}, err
	}
	defer hold.Release()
	return c.NotifyMethod(ctx, method.Type, input, options)
}

func attachInvocationServices(ctx context.Context, services *invocationServices) error {
	if err := services.requiredReady(ctx); err != nil {
		return err
	}
	origin, _ := ctx.Value(applicationContextKey{}).(*applicationContext)
	if origin == nil {
		return ErrApplicationDependency
	}
	origin.state.mu.Lock()
	defer origin.state.mu.Unlock()
	if !origin.state.live {
		return ErrApplicationDependency
	}
	origin.state.services = services
	return nil
}
