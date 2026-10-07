package sessionv4

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"math"
	"strings"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// ServiceDefinition is a trusted, immutable projection of one service.
// Each Type is a nonzero wire method ID in Namespace. All contract bodies come
// from the Session's admitted static registry; this API does not discover peers.
type ServiceDefinition struct {
	Namespace string
	Methods   []ServiceMethod
}

// UnaryMethodSelector carries its parent service namespace. Equal numeric IDs
// in unrelated services cannot select one another's methods.
type UnaryMethodSelector struct {
	Namespace string
	Type      uint32
}

func (d ServiceDefinition) Selector(methodType uint32) (UnaryMethodSelector, error) {
	if d.Namespace == "" || methodType == 0 {
		return UnaryMethodSelector{}, rpcv4.ErrMethod
	}
	for _, m := range d.Methods {
		if m.Type == methodType {
			return UnaryMethodSelector{Namespace: d.Namespace, Type: methodType}, nil
		}
	}
	return UnaryMethodSelector{}, rpcv4.ErrMethod
}

type ServiceMethod struct {
	Shape          uint8
	StreamKind     string
	StreamMetadata []byte
	Type           uint32
	Method         UnaryMethodDefinition
	Acceptance     protocolv4.ContractAcceptance
}

// Unary names are aliases over the same finite service owner.
type UnaryServiceDefinition = ServiceDefinition
type UnaryServiceMethod = ServiceMethod

type UnaryServiceBindOptions struct {
	// PeerReplicas is an optional finite trusted mapping for Controller bindings.
	// Every selected authenticated peer must occur in this immutable subject set;
	// authority domains, tenant, audience and original caller remain unchanged.
	// Nil requires the exact original peer subject. Fixed Session bindings reject
	// this option because they never select another authenticated peer.
	PeerReplicas []string
	// Workloads reserves additional complete call positions before Bind returns.
	// Matching Session admission targets transfer their original backing;
	// otherwise Bind must obtain the complete increment from the same root.
	// Nil declares no additional target; an explicit empty list is invalid.
	Workloads []ServiceMethodWorkload
	// Nil selects all methods. An explicit empty set is invalid.
	InitialMethods []UnaryMethodSelector
	// ContractSource selects static installation or explicit authenticated
	// queries for the trusted method set. Neither source acquires a connection.
	ContractSource ServiceContractSource
	// Managed renewal needs explicit trusted timing and source guarantees.
	// A transient-only service creates no periodic work or protected capacity.
	OfferRefresh  ServiceOfferRefresh
	RenewalPolicy ContractRenewalPolicy
}

type ServiceContractSource uint8

const (
	ServiceContractsStatic ServiceContractSource = iota
	ServiceContractsRemote
)

type boundUnaryMethod struct {
	notificationSemantics uint8
	workload              ServiceMethodWorkload
	candidateWorkload     candidateMethodWorkload
	requiredDeclarations  atomic.Uint32
	dependencyPath        dependencyPathPreparation
	candidateContract     candidateContractSnapshot
	definition            UnaryServiceMethod
	// The admitted static route also pins the trusted declaration when its
	// snapshot has not been installed. No separate contract body is copied.
	route      rpcv4.ContractRoute
	generation uint64
	installed  bool
	update     serviceContractUpdate
	// Controller bindings retain a complete immutable snapshot independently
	// of any retired Session registry. Future dispatch still requires the new
	// current's exact authorized registration.
	canonical                         []byte
	shapeIdentity, acceptanceIdentity [32]byte
	offer                             protocolv4.AdmissionOfferBounds
	known                             protocolv4.ContractQueryKnown
	renewal                           contractRenewalMethod
}

func (s *EnvironmentSession) BindUnaryMethods(ctx context.Context, definition UnaryServiceDefinition, options UnaryServiceBindOptions) (*UnaryServiceClient, error) {
	for _, method := range definition.Methods {
		if method.Shape != 0 {
			return nil, rpcv4.ErrMethod
		}
	}
	return s.BindMethods(ctx, definition, options)
}

func (s *EnvironmentSession) BindMethods(ctx context.Context, definition UnaryServiceDefinition, options UnaryServiceBindOptions) (*UnaryServiceClient, error) {
	core, err := s.Core()
	if err != nil {
		return nil, err
	}
	core.plan.mu.Lock()
	r, closed := core.plan.rpc, core.plan.closed
	core.plan.mu.Unlock()
	if closed {
		return nil, cryptov4.ErrClosed
	}
	return r.bindMethodsSource(ctx, definition, options, nil, nil, controllerRoutingIdentity{}, true)
}

func (r *RPCServices) bindUnaryService(method UnaryMethodDefinition) (*UnaryServiceClient, error) {
	if r == nil {
		return nil, cryptov4.ErrNotReady
	}
	policy, err := r.routes.BindingPolicy(method.Contract, protocolv4.ContractAcceptance{})
	if err != nil {
		return nil, err
	}
	return r.bindUnaryMethods(context.Background(), UnaryServiceDefinition{Namespace: policy.Namespace, Methods: []UnaryServiceMethod{{Type: policy.Type, Method: method}}}, UnaryServiceBindOptions{})
}

func (r *RPCServices) validateBindingMethod(definition UnaryServiceMethod, registered bool, now timev4.Sample, plannedWorkload ...bool) error {
	m := definition.Method
	if definition.Shape > 2 || (m.Decode == nil) != (definition.Shape == 2) || m.Contract == ([32]byte{}) || m.WorkClass > ApplicationResident {
		return cryptov4.ErrConfiguration
	}
	if m.Codec.Encode == nil && (m.Codec.MaxEncodedBytes != 0 || m.Codec.ScratchBytes != 0) || m.Codec.MaxEncodedBytes > 1048576 || m.Codec.ScratchBytes > 1048576 {
		return cryptov4.ErrConfiguration
	}
	policy, err := r.routes.BindingPolicy(m.Contract, definition.Acceptance)
	if err != nil {
		return err
	}
	if policy.Type != definition.Type || policy.Shape != definition.Shape {
		return rpcv4.ErrMethod
	}
	if err := m.checkExecutionPolicy(policy); err != nil {
		return err
	}
	if definition.Shape == 1 {
		kindLimit, err := protocolv4.FieldByteLimit("OPEN_STREAM", "kind")
		if err != nil {
			return err
		}
		metadataLimit, err := protocolv4.FieldByteLimit("OPEN_STREAM", "metadata")
		if err != nil {
			return err
		}
		if !canonicalStreamHandlerKind(definition.StreamKind) || len(definition.StreamKind) > kindLimit || len(definition.StreamMetadata) > metadataLimit {
			return cryptov4.ErrConfiguration
		}
	} else if definition.StreamKind != "" || len(definition.StreamMetadata) != 0 {
		return cryptov4.ErrConfiguration
	}
	if definition.Shape == 2 {
		if m.DefaultResponseLimitBytes != 0 {
			return rpcv4.ErrResponseLimitUnsupported
		}
	} else {
		limit, err := m.responseLimit(policy, rpcv4.UnaryPreparation{})
		if err != nil {
			return err
		}
		if definition.Shape == 0 && m.WorkClass == ApplicationShort && limit > r.shortResponseBytes && m.workload == nil && !(len(plannedWorkload) == 1 && plannedWorkload[0]) {
			return cryptov4.ErrCapacity
		}
	}
	if !registered {
		return nil
	}
	if _, _, err := r.routes.RegisteredContractPolicy(m.Contract); err != nil {
		return err
	}
	if policy.Semantics == 1 {
		_, err = r.routes.CapturePreparationOfferAt(m.Contract, protocolv4.AdmissionOfferBounds{}, now)
	}
	return err
}

func (r *RPCServices) bindUnaryMethods(ctx context.Context, definition UnaryServiceDefinition, options UnaryServiceBindOptions) (*UnaryServiceClient, error) {
	for _, method := range definition.Methods {
		if method.Shape != 0 {
			return nil, rpcv4.ErrMethod
		}
	}
	return r.bindMethods(ctx, definition, options)
}

func (r *RPCServices) bindMethods(ctx context.Context, definition ServiceDefinition, options UnaryServiceBindOptions) (_ *UnaryServiceClient, err error) {
	return r.bindMethodsSource(ctx, definition, options, nil, nil, controllerRoutingIdentity{}, false)
}

func (r *RPCServices) bindMethodsSource(ctx context.Context, definition ServiceDefinition, options UnaryServiceBindOptions, controller *ConnectionController, session *EnvironmentSession, routing controllerRoutingIdentity, initializeChannels bool) (_ *UnaryServiceClient, err error) {
	if r == nil || ctx == nil || options.ContractSource > ServiceContractsRemote || options.OfferRefresh > ServiceOfferRefreshManaged || len(definition.Methods) == 0 || len(definition.Methods) > 256 || definition.Namespace == "" || len(definition.Namespace) > 128 || options.InitialMethods != nil && len(options.InitialMethods) == 0 || len(options.InitialMethods) > len(definition.Methods) {
		return nil, cryptov4.ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if options.PeerReplicas != nil && controller == nil {
		return nil, cryptov4.ErrConfiguration
	}
	if _, err := checkApplicationContext(ctx); err != nil {
		return nil, err
	}
	workloads, err := selectServiceWorkloads(definition, options.Workloads)
	if err != nil {
		return nil, err
	}
	remote := options.ContractSource == ServiceContractsRemote
	var initialDeadline *timev4.Deadline
	var initial [256]bool
	for j, method := range definition.Methods {
		if method.Type == 0 {
			return nil, cryptov4.ErrConfiguration
		}
		for k := 0; k < j; k++ {
			if definition.Methods[k].Type == method.Type {
				return nil, cryptov4.ErrConfiguration
			}
		}
		initial[j] = options.InitialMethods == nil
	}
	for _, selected := range options.InitialMethods {
		if selected.Namespace != definition.Namespace {
			return nil, cryptov4.ErrConfiguration
		}
		found := false
		for j, method := range definition.Methods {
			if method.Type != selected.Type {
				continue
			}
			if initial[j] {
				return nil, cryptov4.ErrConfiguration
			}
			initial[j], found = true, true
			break
		}
		if !found {
			return nil, cryptov4.ErrConfiguration
		}
	}
	for j, recipe := range workloads[:len(definition.Methods)] {
		if remote && recipe.Calls != 0 && !initial[j] {
			return nil, cryptov4.ErrConfiguration
		}
	}
	e, err := r.bindingEnvironment()
	if err != nil {
		return nil, err
	}
	index, err := e.reserveServiceBinding(uint16(len(definition.Methods)))
	if err != nil {
		return nil, err
	}
	published := false
	defer func() {
		if !published {
			e.releaseServiceBinding(index, uint16(len(definition.Methods)))
		}
	}()
	if remote {
		initialDeadline, err = r.contractAcquisitionDeadline(ctx)
		if err != nil {
			return nil, err
		}
	}
	r.mu.Lock()
	clock, plan := r.clock, r.plan
	closed := r.closed || r.retired
	r.mu.Unlock()
	if closed || clock == nil || plan == nil {
		return nil, cryptov4.ErrClosed
	}
	now, err := clock.Sample()
	if err != nil {
		return nil, err
	}
	lease, authorization, err := plan.queryAuthorization()
	if err != nil {
		return nil, err
	}
	if err = authorization.Check(); err != nil {
		return nil, err
	}
	r.mu.Lock()
	locked := true
	defer func() {
		if locked {
			r.mu.Unlock()
		}
	}()
	if r.closed || r.retired {
		return nil, cryptov4.ErrClosed
	}
	if r.draining.Load() {
		return nil, ErrSessionDraining
	}
	if r.callSerial == math.MaxUint64 {
		return nil, cryptov4.ErrCapacity
	}
	for j, method := range definition.Methods {
		method.Method.workload = nil
		if err := r.validateBindingMethod(method, initial[j] && !remote, now, workloads[j].Calls != 0); err != nil {
			return nil, err
		}
		policy, err := r.routes.BindingPolicy(method.Method.Contract, method.Acceptance)
		if err != nil {
			return nil, err
		}
		if policy.Namespace != definition.Namespace {
			return nil, rpcv4.ErrMethod
		}
	}
	charge, err := serviceClientCharge(r.runtimeBytes, len(definition.Methods))
	if err != nil {
		return nil, err
	}
	if controller != nil || remote {
		charge, err = charge.Add(resourcev4.Vector{resourcev4.SDKBytes: uint64(len(definition.Methods)) * 8192})
		if err != nil {
			return nil, err
		}
	}
	if remote {
		// Four synchronous acquisition callers are bounded independently of
		// the Environment's shared actual query jobs. Initial handoff has one
		// complete finite selector/status workspace, with no per-method task.
		charge, err = charge.Add(resourcev4.Vector{resourcev4.Timers: 4, resourcev4.SDKBytes: 4*(uint64(unsafe.Sizeof(time.Timer{}))+uint64(unsafe.Sizeof(timev4.Deadline{}))) + uint64(len(definition.Methods))*protocolv4.ContractQueryKnownBackingBytes() + 256*(4+uint64(unsafe.Sizeof(UnaryContractSnapshot{}))+32+uint64(unsafe.Sizeof(protocolv4.AdmissionOfferBounds{})))})
		if err != nil {
			return nil, err
		}
	}
	for _, method := range definition.Methods {
		charge, err = charge.Add(resourcev4.Vector{resourcev4.SDKBytes: uint64(len(method.StreamKind) + len(method.StreamMetadata))})
		if err != nil {
			return nil, err
		}
	}
	routeCharge, err := rpcv4.ContractRouteCharge(r.runtimeBytes)
	if err != nil {
		return nil, err
	}
	r.callSerial++
	var seed [56]byte
	copy(seed[:16], "service-client4/")
	copy(seed[16:32], r.owner.Instance[:])
	copy(seed[32:48], r.owner.Backing[:])
	binary.BigEndian.PutUint64(seed[48:], r.callSerial)
	hash := sha256.Sum256(seed[:])
	var requests [257]resourcev4.Request
	var refs [257]resourcev4.Reference
	n := len(definition.Methods) + 1
	for j := 0; j < n; j++ {
		owner := r.owner
		copy(owner.Instance[:], hash[:16])
		copy(owner.Backing[:], hash[16:])
		owner.Backing[0] ^= byte(j)
		owner.Backing[1] ^= byte(j >> 8)
		value := routeCharge
		if j == 0 {
			value = charge
		}
		requests[j] = resourcev4.Request{Owner: owner, Charge: value, Accounts: r.accounts[:r.accountCount]}
	}
	if err = r.root.ReserveBatch(requests[:n], refs[:n]); err != nil {
		return nil, err
	}
	defer func() {
		for _, ref := range refs[:n] {
			ref.Release()
		}
	}()
	c := &UnaryServiceClient{services: r, clock: r.clock, root: r.root, namespace: strings.Clone(definition.Namespace), methods: make([]boundUnaryMethod, len(definition.Methods)), methodCount: uint16(len(definition.Methods)), done: make(chan struct{}), remoteContracts: remote, managedRenewal: remote && options.OfferRefresh == ServiceOfferRefreshManaged, renewalPolicy: options.RenewalPolicy}
	defer func() {
		if err != nil && !published {
			c.releaseUnpublishedWorkloads()
			for j := range c.methods {
				c.methods[j].route.Release()
			}
			if c.dependencyFloor != nil {
				c.dependencyFloor.Close()
				c.dependencyFloor = nil
			}
			c.metadata.Release()
			c.shared.Release()
			c.source.close()
		}
	}()
	c.metadata, err = refs[0].Take(charge)
	if err != nil {
		return nil, err
	}
	for j, method := range definition.Methods {
		method.Method.workload = nil
		route, err := r.routes.Capture(method.Method.Contract, refs[j+1], r.runtimeBytes)
		if err != nil {
			return nil, err
		}
		for k := range method.Acceptance.Ranges {
			// Retain canonical constant names, never a tiny substring alias
			// that pins an arbitrarily large caller-owned string allocation.
			switch method.Acceptance.Ranges[k].Field {
			case "history_retention_ms":
				method.Acceptance.Ranges[k].Field = "history_retention_ms"
			case "result_retention_ms":
				method.Acceptance.Ranges[k].Field = "result_retention_ms"
			case "min_response_limit_bytes":
				method.Acceptance.Ranges[k].Field = "min_response_limit_bytes"
			case "max_response_bytes":
				method.Acceptance.Ranges[k].Field = "max_response_bytes"
			}
		}
		method.StreamKind = strings.Clone(method.StreamKind)
		method.StreamMetadata = append([]byte(nil), method.StreamMetadata...)
		c.methods[j] = boundUnaryMethod{workload: workloads[j], definition: method, route: route, generation: 1, installed: initial[j] && !remote}
		if method.Shape == 2 {
			_, policy, policyErr := route.Policy()
			if policyErr != nil {
				return nil, policyErr
			}
			c.methods[j].notificationSemantics = policy.Semantics
		}
		if remote {
			c.methods[j].generation = 0
		}
		if controller != nil || remote {
			m := &c.methods[j]
			m.shapeIdentity, m.acceptanceIdentity, err = route.BindingIdentity(method.Acceptance)
			if err != nil {
				return nil, err
			}
			m.canonical = make([]byte, 8192)
			n, copyErr := route.CopyCanonical(m.canonical)
			if copyErr != nil {
				return nil, copyErr
			}
			m.canonical = m.canonical[:n]
		}
	}
	if controller != nil {
		// The immutable binding owns its future dependency positions across
		// Session changes. Detach before those idle aliases copy its scopes;
		// actual source registry references keep their original Session charge.
		if err = c.metadata.DetachSessionScope(); err != nil {
			return nil, err
		}
	}
	c.dependencyFloor, err = resourcev4.NewBorrowPoolForSources(c.metadata, dependencyFloorCapacity)
	if err != nil {
		return nil, err
	}
	c.metadata = c.dependencyFloor.Metadata()
	// Do not acquire Environment below RPCServices: shutdown owns the opposite
	// direction. The unpublished client already pins all its actual resources.
	r.mu.Unlock()
	locked = false
	if controller != nil {
		// This original shared executor is independent of any Session route.
		// A later local subscription can wait unattached through a reconnect.
		plan.mu.Lock()
		c.notificationExecutor = plan.executor
		plan.mu.Unlock()
	}
	if !remote {
		if err = c.reserveInitialWorkloads(ctx, r, controller); err != nil {
			return nil, err
		}
	}
	for j, method := range definition.Methods {
		if initializeChannels && initial[j] && method.Shape == 2 {
			if initialDeadline == nil {
				initialDeadline, err = r.contractAcquisitionDeadline(ctx)
				if err != nil {
					return nil, err
				}
			}
			if err = r.prepareBindingNotifyChannel(ctx, initialDeadline); err != nil {
				return nil, err
			}
			break
		}
	}
	e.mu.Lock()
	environmentLocked := true
	defer func() {
		if environmentLocked {
			e.mu.Unlock()
		}
	}()
	if e.closed || e.retired || !e.services {
		return nil, cryptov4.ErrClosed
	}
	if !e.serviceClientBinding[index] || e.serviceClients[index] != nil {
		return nil, cryptov4.ErrConfiguration
	}
	if err = e.reservation.CheckSameEnvironment(c.metadata); err != nil {
		return nil, err
	}
	// Endpoint authorization precedes services publication. Channel
	// construction retains its charged owner outside r.mu, so one-shot Bind
	// waits for ordinary mutex contention without exposing a retry error.
	err = authorization.WithCurrentAuthorization(func() error {
		r.mu.Lock()
		defer r.mu.Unlock()
		if r.closed || r.retired {
			return cryptov4.ErrClosed
		}
		if r.draining.Load() {
			return ErrSessionDraining
		}
		lease.mu.Lock()
		defer lease.mu.Unlock()
		if lease.revoked || !lease.authorized || lease.authorization != authorization {
			return ErrApplicationAuthorization
		}
		for j := range c.methods {
			if c.methods[j].installed {
				if err := c.methods[j].route.WithRegistered(func() error { return nil }); err != nil {
					return err
				}
			}
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if controller != nil {
			if len(options.Workloads) != 0 {
				if !controller.dependencyMu.TryLock() {
					return cryptov4.ErrNotReady
				}
				defer controller.dependencyMu.Unlock()
				if controller.dependencyRevision == math.MaxUint64 {
					return cryptov4.ErrCapacity
				}
				controller.dependencyRevision++
			}
			for j := range c.methods {
				c.methods[j].route.Release()
				c.methods[j].route = rpcv4.ContractRoute{}
			}
			controller.mu.Lock()
			defer controller.mu.Unlock()
			if controller.closed || controller.blocked || controller.current != session || controller.environment != e {
				return cryptov4.ErrNotReady
			}
			if controller.dispatches == 1024 {
				return cryptov4.ErrCapacity
			}
			if err := c.metadata.CheckSameEnvironment(controller.reservation); err != nil {
				return err
			}
			borrow, err := controller.reservation.Borrow()
			if err != nil {
				return err
			}
			controller.dispatches++
			c.source = controllerDispatch{controller: controller, identity: controller.identity, borrow: borrow, routing: routing}
			c.services = nil
		}
		var err error
		c.shared, err = e.reservation.Borrow()
		if err != nil {
			return err
		}
		return withApplicationHandoff(ctx, func() error {
			// Initialization and publication share this Bind's original
			// deadline, including local static notification bindings.
			if initialDeadline != nil {
				if err := initialDeadline.Check(); err != nil {
					return err
				}
			}
			for j := range c.methods {
				if w := c.methods[j].definition.Method.workload; w != nil {
					w.installed.Store(true)
				}
			}
			c.environment = e
			if remote {
				// The private Bind remains indexed through queries and cleanup.
				// No public reference exists until its complete initial set passes.
				c.visits++
			}
			e.serviceClients[index] = c
			e.serviceClientBinding[index] = false
			published = true
			e.signalMaterials()
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	e.mu.Unlock()
	environmentLocked = false
	if remote {
		err = c.initializeRemote(ctx, initial[:len(c.methods)], initialDeadline)
		c.mu.Lock()
		if err != nil {
			c.closeLocked()
		}
		c.mu.Unlock()
		if err != nil {
			c.releaseUnpublishedWorkloads()
		}
		c.mu.Lock()
		c.visits--
		c.mu.Unlock()
		e.signalMaterials()
		if err != nil {
			return nil, err
		}
	}
	return c, nil
}

func (c *UnaryServiceClient) methodLocked(methodType uint32) (*boundUnaryMethod, error) {
	if c.closed || c.cleaned {
		return nil, cryptov4.ErrClosed
	}
	// The original no-selector convenience API is unambiguous only for a
	// single-method service. Multi-method callers must select explicitly.
	if methodType == 0 && len(c.methods) == 1 {
		return &c.methods[0], nil
	}
	for j := range c.methods {
		if c.methods[j].definition.Type == methodType {
			return &c.methods[j], nil
		}
	}
	return nil, rpcv4.ErrMethod
}

func (c *UnaryServiceClient) SelectMethod(selector UnaryMethodSelector) error {
	if c == nil {
		return cryptov4.ErrClosed
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.cleaned {
		return cryptov4.ErrClosed
	}
	if selector.Namespace != c.namespace || selector.Type == 0 {
		return rpcv4.ErrMethod
	}
	_, err := c.methodLocked(selector.Type)
	return err
}

func (c *UnaryServiceClient) PrepareMethod(ctx context.Context, methodType uint32, input []byte, options rpcv4.UnaryPreparation) (*UnaryOperation, error) {
	op, _, _, err := c.prepare(ctx, methodType, input, options, false)
	return op, err
}
