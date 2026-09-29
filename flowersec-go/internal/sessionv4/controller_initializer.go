package sessionv4

import (
	"context"
	"crypto/sha256"
	"math"
	"sync/atomic"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
)

type controllerInitializerMethod struct {
	client          *UnaryServiceClient
	method          *boundUnaryMethod
	generation      uint64
	required        bool
	defaultWorkload bool
	workload        *unaryWorkload
	routing         controllerRoutingIdentity
}

// The original attempt owns this finite projection. It borrows declarations,
// fixes their generation before Acquire and binds only its authenticated
// candidate. Neither selection nor cleanup consults Controller.current.
type controllerInitializerPlan struct {
	declaration *invocationServices
	controller  *ConnectionController
	attempt     *controllerAttempt
	methods     []controllerInitializerMethod
	targets     []SessionMethodWorkload
	token       *controllerInitializerToken
	services    *RPCServices
	references  *resourcev4.BorrowPool
}

type controllerInitializerPlanKey struct{}

// Escaped invocation contexts keep only this revocable token. Once the attempt
// leaves, they cannot retain its Session, Controller, clients or workload graph.
type controllerInitializerToken struct {
	plan atomic.Pointer[controllerInitializerPlan]
}

func (p *controllerInitializerPlan) contextToken() *controllerInitializerToken {
	if p == nil {
		return nil
	}
	return p.token
}

func initializerPlanFromContext(ctx context.Context) *controllerInitializerPlan {
	p, _ := ctx.Value(controllerInitializerPlanKey{}).(*controllerInitializerPlan)
	return p
}

func initializerPlanForApplication(ctx context.Context) *controllerInitializerPlan {
	p := initializerPlanFromContext(ctx)
	if p == nil {
		return nil
	}
	origin, _ := ctx.Value(applicationContextKey{}).(*applicationContext)
	if origin == nil {
		return nil
	}
	origin.state.mu.Lock()
	belongs := origin.state.services == p.declaration
	origin.state.mu.Unlock()
	if !belongs {
		return nil
	}
	return p
}

func initializerPlanCharge(declarations []ServiceDependency) resourcev4.Vector {
	if len(declarations) == 0 {
		return resourcev4.Vector{}
	}
	count := 0
	for _, declaration := range declarations {
		count += len(declaration.Methods)
	}
	return resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(controllerInitializerPlan{})) + uint64(unsafe.Sizeof(controllerInitializerToken{})) + uint64(count)*(uint64(unsafe.Sizeof(controllerInitializerMethod{}))+uint64(unsafe.Sizeof(SessionMethodWorkload{}))), resourcev4.Items: 2}
}

func (c *ConnectionController) prepareInitializerPlan(a *controllerAttempt, config SourceConnectConfig) (err error) {
	s := c.initializeServices
	if s == nil {
		return nil
	}
	if config.Admission.RPC == nil || config.Admission.Application == nil {
		return cryptov4.ErrConfiguration
	}
	s.mu.Lock()
	if s.closed || s.sealed.Load() {
		s.mu.Unlock()
		return ErrApplicationDependency
	}
	s.visits++
	s.mu.Unlock()
	defer func() { s.mu.Lock(); s.visits--; s.cleanupLocked(); s.mu.Unlock() }()
	count := 0
	for _, binding := range s.bindings {
		count += len(binding.methods)
	}
	p := &controllerInitializerPlan{declaration: s, controller: c, attempt: a,
		methods: make([]controllerInitializerMethod, 0, count), targets: make([]SessionMethodWorkload, 0, count)}
	p.token = &controllerInitializerToken{}
	p.token.plan.Store(p)
	// Publish the owner before taking any client pin. Every failed attempt,
	// including an abnormal provider exit, unwinds through this same owner.
	a.initialization = p
	for _, binding := range s.bindings {
		client := binding.client
		for _, selection := range binding.methods {
			duplicate := false
			for i := range p.methods {
				m := &p.methods[i]
				if m.client == client && p.targets[i].Method.Type == selection.Method.Type {
					m.required = m.required || selection.DispatchRequirement == RequiredForDispatch
					duplicate = true
					break
				}
			}
			if duplicate {
				continue
			}
			client.mu.Lock()
			m, e := client.methodLocked(selection.Method.Type)
			if e == nil && (client.closed || client.cleaned || client.environment != c.environment || client.clock != c.config.Clock || client.visits == math.MaxUint32) {
				e = ErrApplicationDependency
			}
			if e != nil {
				client.mu.Unlock()
				return e
			}
			definition, recipe := m.definition, m.workload
			definition.Method.workload = nil
			definition.Method.bindingOffer = protocolv4.AdmissionOfferBounds{}
			client.visits++
			p.methods = append(p.methods, controllerInitializerMethod{client: client, method: m, generation: m.generation, required: selection.DispatchRequirement == RequiredForDispatch})
			p.targets = append(p.targets, SessionMethodWorkload{Namespace: client.namespace, Method: definition, Workload: recipe, initializer: true})
			client.mu.Unlock()
			p.methods[len(p.methods)-1].routing, e = client.initializerRouting()
			if e != nil {
				return e
			}
		}
	}
	// An undeclared overlap has one complete call position. The original
	// contract supplies its maximum request size; explicit method recipes keep
	// their finite concurrency, input and response limits.
	rpc := *config.Admission.RPC
	rpc.Workloads = p.targets
	for i := range p.targets {
		target := &p.targets[i]
		if target.Workload.Calls == 0 {
			p.methods[i].defaultWorkload = true
			target.Workload = ServiceMethodWorkload{Type: target.Method.Type, Calls: 1}
		}
	}
	return visitSessionWorkloads(rpc, func(i int, _ SessionMethodWorkload, policy protocolv4.ServiceContractPolicy, _ uint32) error {
		if p.methods[i].defaultWorkload {
			p.targets[i].Workload.RequestBytes = policy.RequestMaxBytes
		}
		return nil
	})
}

func (c *UnaryServiceClient) initializerRouting() (controllerRoutingIdentity, error) {
	c.mu.Lock()
	controller, routing, r := c.source.controller, c.source.routing, c.services
	c.mu.Unlock()
	if controller != nil {
		return routing, nil
	}
	if r == nil {
		return controllerRoutingIdentity{}, cryptov4.ErrNotReady
	}
	r.mu.Lock()
	plan, closed := r.plan, r.closed || r.retired
	r.mu.Unlock()
	if plan == nil || closed {
		return controllerRoutingIdentity{}, cryptov4.ErrClosed
	}
	lease, authorization, err := plan.queryAuthorization()
	if err != nil {
		return controllerRoutingIdentity{}, err
	}
	identity, err := authorization.RoutingIdentity()
	if err != nil {
		return controllerRoutingIdentity{}, err
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if !lease.authorized || lease.revoked || lease.authorization != authorization {
		return controllerRoutingIdentity{}, ErrApplicationAuthorization
	}
	return controllerRoutingIdentity{endpoint: identity, execution: lease.execution}, nil
}

func (p *controllerInitializerPlan) close() {
	if p == nil {
		return
	}
	p.token.plan.Store(nil)
	p.references.Close()
	for i := range p.methods {
		m := &p.methods[i]
		m.workload.seal()
		m.client.mu.Lock()
		m.client.visits--
		m.client.mu.Unlock()
	}
	p.controller.environment.signalMaterials()
}

func (p *controllerInitializerPlan) checkMethod(i int, candidate *EnvironmentSession) error {
	m := &p.methods[i]
	client := m.client
	client.mu.Lock()
	err := client.metadata.Check()
	if client.closed || client.cleaned {
		err = cryptov4.ErrClosed
	} else if m.method.generation != m.generation || m.method.definition.Method.Contract != p.targets[i].Method.Method.Contract {
		err = ErrApplicationDependency
	}
	client.mu.Unlock()
	if err != nil {
		return err
	}
	r, routing, err := candidate.controllerRPCIdentity()
	if err != nil {
		return err
	}
	if routing != m.routing || r.root != client.root || r.clock != client.clock {
		return ErrApplicationAuthorization
	}
	return nil
}

func (h *sessionHeadroom) reserveInitializer(p *controllerInitializerPlan, b *rpcServicesBatch, core SessionCoreConfig, role protocolv4.Direction, environment *Environment) (err error) {
	if p == nil {
		return nil
	}
	if b == nil || !b.prepared || h.initializer != nil || p.services != nil || len(p.targets) == 0 {
		return resourcev4.ErrOwner
	}
	// Include the old current, ordinary candidate targets and these actual
	// additional owners in the same root. No former target is sealed here.
	var calls, notifications uint32
	for _, targets := range [][]SessionMethodWorkload{b.config.Workloads, p.targets} {
		for _, target := range targets {
			calls += uint32(target.Workload.Calls)
			if target.Method.Shape == 2 {
				notifications += uint32(target.Workload.Calls)
			}
		}
	}
	for _, target := range p.targets {
		if target.Method.Shape != 2 && h.deliveryFloor == nil {
			return resourcev4.ErrOwner
		}
	}
	if calls >= uint32(b.config.Session.Limits().RPCMaxGeneralOutstanding) || notifications > b.config.NotifyPublishPending {
		return cryptov4.ErrCapacity
	}
	if _, _, err := sessionStreamWorkloadRequirements(core, b.config, role, p.targets); err != nil {
		return err
	}
	config := b.config
	config.Workloads = p.targets
	extra := sessionHeadroom{source: h.source, network: h.network, receivePool: h.receivePool}
	err = extra.reserveWorkloads(config, core, role, b.plan, environment)
	h.initializer, h.initializerWorkloads = p, extra.workloads
	if err != nil {
		return err
	}
	return p.reserveReferences(config)
}

func (p *controllerInitializerPlan) reserveReferences(config RPCServicesConfig) error {
	if p.references != nil {
		return resourcev4.ErrOwner
	}
	var capacity uint32
	for _, target := range p.targets {
		// Only the live declaration view belongs to the initializer itself.
		// Prepare/Start/results use their original workload's parent positions.
		capacity += uint32(target.Workload.Calls)
	}
	charge, err := resourcev4.BorrowPoolCharge(capacity)
	if err != nil {
		return err
	}
	owner := config.Owner
	var seed [48]byte
	copy(seed[:16], "init-deps/v4")
	copy(seed[16:32], owner.Instance[:])
	copy(seed[32:48], owner.Backing[:])
	digest := sha256.Sum256(seed[:])
	copy(owner.Instance[:], digest[:16])
	copy(owner.Backing[:], digest[16:])
	ref, err := config.Root.Reserve(owner, charge, config.Accounts...)
	if err != nil {
		return err
	}
	defer ref.Release()
	// These aliases belong to the Controller invocation. Accepted result
	// tails may outlive this candidate's transport without retaining Session
	// scope, while the original tenant, Environment and policy scopes remain.
	if err := ref.DetachSessionScope(); err != nil {
		return err
	}
	p.references, err = resourcev4.NewBorrowPool(p.controller.reservation, ref, capacity)
	return err
}

func (p *controllerInitializerPlan) attachReferences(ctx context.Context) error {
	if p == nil {
		return nil
	}
	origin, _ := ctx.Value(applicationContextKey{}).(*applicationContext)
	if origin == nil || p.references == nil {
		return ErrApplicationDependency
	}
	origin.state.mu.Lock()
	defer origin.state.mu.Unlock()
	s := origin.state
	if !s.live || s.services != p.declaration || s.dependencyFloor != nil || s.backing != p.controller.reservation {
		return ErrApplicationDependency
	}
	if err := p.references.CheckSource(s.backing); err != nil {
		return err
	}
	s.dependencyFloor = p.references
	return nil
}

func (h *sessionHeadroom) checkInitializer(b *rpcServicesBatch, core *sessionCoreBatch) error {
	if h.initializer == nil {
		return nil
	}
	if !b.prepared || b.initializer != nil || b.initializerWorkloads != nil {
		return resourcev4.ErrOwner
	}
	if err := h.initializer.references.CheckSource(h.initializer.controller.reservation); err != nil {
		return err
	}
	config := b.config
	config.Workloads = h.initializer.targets
	extra := sessionHeadroom{workloads: h.initializerWorkloads, network: h.network, receivePool: h.receivePool}
	batch := rpcServicesBatch{prepared: true, config: config}
	return extra.checkWorkloads(&batch, core)
}

func (p *controllerInitializerPlan) install(r *RPCServices, subscriptions *protocolv4.CredentialSubscriptions, headroom **unaryWorkload) error {
	if p == nil {
		return nil
	}
	if r == nil || headroom == nil || p.services != nil {
		return resourcev4.ErrOwner
	}
	for i, target := range p.targets {
		link := headroom
		for *link != nil && (*link).initialIndex != i {
			link = &(*link).initialNext
		}
		if *link == nil {
			return resourcev4.ErrOwner
		}
		w := *link
		*link, w.initialNext = w.initialNext, nil
		defer w.closeUnattached()
		policy, err := r.routes.BindingPolicy(target.Method.Method.Contract, target.Method.Acceptance)
		if err != nil {
			return err
		}
		limit, err := target.responseLimit(policy)
		if err != nil {
			return err
		}
		w, err = r.reserveMethodWorkloadAdmission(target.Method.Method, target.Workload.RequestBytes, limit, target.Workload.Calls, subscriptions, target.streamPlan(), w)
		if err != nil {
			return err
		}
		w.initialIndex = -1
		w.installed.Store(true)
		p.methods[i].workload = w
	}
	p.services = r
	return nil
}

// Path preparation stays outside the initializer permit. It opens no business
// request and retains the same attempt deadline through every readiness wake.
func (p *controllerInitializerPlan) prepare(ctx context.Context, candidate *EnvironmentSession) error {
	if p == nil {
		return nil
	}
	if p.services == nil || p.services != candidate.dependencyServices() {
		return resourcev4.ErrOwner
	}
	for i := range p.methods {
		if err := p.checkMethod(i, candidate); err != nil {
			return err
		}
		if !p.methods[i].required {
			continue
		}
		w := p.methods[i].workload
		var err error
		if w.stream != nil {
			err = w.stream.core.preacceptServiceStream(ctx, w.stream.kind, w.stream.metadata, w.admissionContract, p.attempt.deadline, true, w)
		} else {
			err = p.services.prepareDependencyChannel(ctx, w.shape == 2, p.attempt.deadline)
		}
		if err != nil {
			return err
		}
	}
	return p.requiredReady(ctx)
}

func (p *controllerInitializerPlan) requiredReady(ctx context.Context) error {
	if p == nil {
		return nil
	}
	p.controller.mu.Lock()
	candidate, live := p.attempt.candidate, !p.controller.closed && p.controller.attempt == p.attempt
	p.controller.mu.Unlock()
	if !live || candidate == nil || p.services != candidate.dependencyServices() {
		return cryptov4.ErrNotReady
	}
	now, err := p.controller.config.Clock.Sample()
	if err != nil {
		return err
	}
	if err = p.attempt.deadline.CheckAt(now); err != nil {
		return err
	}
	for i := range p.methods {
		if err := p.checkMethod(i, candidate); err != nil {
			return err
		}
		if !p.methods[i].required {
			continue
		}
		w := p.methods[i].workload
		if w == nil {
			return resourcev4.ErrOwner
		}
		_, policy, err := p.services.routes.RegisteredContractPolicy(w.admissionContract)
		if err != nil {
			return err
		}
		if policy.Semantics == 1 {
			offer, err := p.services.routes.CapturePreparationOfferAt(w.admissionContract, protocolv4.AdmissionOfferBounds{}, now)
			if err != nil {
				return err
			}
			if now.LowerMS < offer.NotBeforeMS || now.UpperMS >= offer.NotAfterMS {
				return cryptov4.ErrNotReady
			}
		}
		stream := w.stream
		if w.shape == 2 {
			stream = &streamPreparationPlan{notify: true}
		}
		if err := p.services.checkDependencyPath(ctx, w.admissionContract, stream); err != nil {
			return err
		}
	}
	return nil
}

func (c *UnaryServiceClient) enterInitializer(ctx context.Context, p *controllerInitializerPlan, methodType uint32, shape uint8, input []byte, options rpcv4.UnaryPreparation) (*serviceClientCall, context.Context, *RPCServices, ServiceMethod, error) {
	if application, err := checkApplicationContext(ctx); err != nil || !application {
		if err == nil {
			err = ErrApplicationDependency
		}
		return nil, nil, nil, ServiceMethod{}, err
	}
	for i := range p.methods {
		m := &p.methods[i]
		definition := p.targets[i].Method
		if m.client != c || definition.Type != methodType && !(methodType == 0 && c.methodCount == 1) || definition.Shape != shape {
			continue
		}
		definition.Method.workload = m.workload
		if m.workload == nil {
			return nil, nil, nil, ServiceMethod{}, resourcev4.ErrOwner
		}
		c.mu.Lock()
		if c.closed || m.method.generation != m.generation {
			c.mu.Unlock()
			return nil, nil, nil, ServiceMethod{}, cryptov4.ErrNotReady
		}
		slot, err := c.reserveCallScopeLocked(definition, input, options)
		if err != nil {
			c.mu.Unlock()
			return nil, nil, nil, ServiceMethod{}, err
		}
		slot.running, slot.initializer, slot.session = true, true, p.attempt.candidate
		c.mu.Unlock()
		transferred := false
		defer func() {
			if !transferred {
				c.leave(slot)
			}
		}()
		child, err := c.setupCallContext(slot, ctx)
		if err != nil {
			return nil, nil, nil, ServiceMethod{}, err
		}
		c.mu.Lock()
		closed := c.closed
		c.mu.Unlock()
		if closed {
			return nil, nil, nil, ServiceMethod{}, cryptov4.ErrClosed
		}
		// The actual call position now owns clock/authorization checks and
		// their real tails, even if the initializer returns concurrently.
		if err := p.checkMethod(i, p.attempt.candidate); err != nil {
			return nil, nil, nil, ServiceMethod{}, err
		}
		if _, err := checkApplicationContext(child); err != nil {
			return nil, nil, nil, ServiceMethod{}, err
		}
		transferred = true
		return slot, child, p.services, definition, nil
	}
	return nil, nil, nil, ServiceMethod{}, ErrApplicationDependency
}

// The callback-entry and current-publication gates recheck the original
// generations atomically with their finite SDK state change. TryLock avoids
// introducing an ordering cycle across independently borrowed client sets.
func (p *controllerInitializerPlan) withGenerations(action func() error) error {
	if p == nil {
		return action()
	}
	locked := 0
	duplicate := func(index int) bool {
		for _, previous := range p.methods[:index] {
			if previous.client == p.methods[index].client {
				return true
			}
		}
		return false
	}
	defer func() {
		for i := locked - 1; i >= 0; i-- {
			if !duplicate(i) {
				p.methods[i].client.mu.Unlock()
			}
		}
	}()
	for i := range p.methods {
		m := &p.methods[i]
		if !duplicate(i) && !m.client.mu.TryLock() {
			return cryptov4.ErrNotReady
		}
		locked = i + 1
		if m.client.closed || m.client.cleaned || m.method.generation != m.generation || m.method.definition.Method.Contract != p.targets[i].Method.Method.Contract {
			return cryptov4.ErrNotReady
		}
	}
	return action()
}
