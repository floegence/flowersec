package sessionv4

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math"
	"strings"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

// UnaryRegistration is trusted local application code and scheduling policy.
// Method is the index in the original immutable ContractRoutes table. Neither
// a peer header nor a caller-supplied work class can replace this registration.
// Handler decodes, executes and encodes under one original ordinary permit.
// Its returned nonzero code must belong to the exact contract's error catalog.
type UnaryRegistration struct {
	// Resume selects the SDK's target-bound recovery exchange. It has no
	// ordinary RPC callback and requires a matching raw kind registration.
	Resume    bool
	Method    uint32
	Namespace string
	Type      uint32
	WorkClass ApplicationWorkClass
	Handler   func(context.Context, UnaryRequest, *UnaryResponse) (uint32, error)
}

type UnaryRequest struct {
	Binding            ApplicationBinding
	ApplicationContext any
	Input              rpcv4.InputBorrow
	OutputInterest     rpcv4.OutputInterest
}

// UnaryResponse exposes bounded writes only. The SDK finalizes after the real
// callback returns and rechecks current authority and the original deadline.
type UnaryResponse struct{ invocation *serviceInvocation }

func (w *UnaryResponse) Write(data []byte) (count int, err error) {
	if w == nil || w.invocation == nil {
		return 0, rpcv4.ErrOwner
	}
	i := w.invocation
	i.mu.Lock()
	execution := i.execution
	closed := i.closed || i.returned
	i.mu.Unlock()
	if execution != nil {
		if closed {
			return 0, rpcv4.ErrClosed
		}
		if execution.durableWork != nil {
			return execution.durableWork.Write(i.ctx, data)
		}
		if execution.work == nil {
			return 0, rpcv4.ErrClosed
		}
		return execution.work.Write(data)
	}
	err = i.withAuthority(func() error {
		i.mu.Lock()
		defer i.mu.Unlock()
		if i.closed || i.returned {
			return rpcv4.ErrClosed
		}
		var e error
		count, e = i.writer.Write(data)
		return e
	})
	return count, err
}
func (*UnaryResponse) String() string               { return "Flowersec.UnaryResponse" }
func (*UnaryResponse) GoString() string             { return "Flowersec.UnaryResponse" }
func (*UnaryResponse) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

type ServiceDispatchConfig struct {
	Streams     []StreamRegistration
	StreamSlots uint32
	// Zero disables durable provider work. Nonzero charges one original
	// Session worker stack; callbacks still use the root application executor.
	DurableProviderRuntimeBytes          uint64
	ExecutionRegistry                    *rpcv4.ServiceRegistry
	ExecutionServices                    []rpcv4.ServiceBinding
	ShortExecutionReservations           [5]resourcev4.Reference
	ShortExecutionAdmissions             [][4]resourcev4.Reference
	ShortResponseBytes                   uint32
	ShortReservations                    [5]resourcev4.Reference
	ShortExecutionBorrow                 resourcev4.Reference
	Root                                 *resourcev4.Root
	Owner                                resourcev4.OwnerKey
	Accounts                             []resourcev4.Account
	Clock                                *timev4.Clock
	Slots, ResidentSlots                 uint32
	Methods                              []UnaryRegistration
	RuntimeBytes, InvocationRuntimeBytes uint64
}

type serviceMethod struct {
	registration UnaryRegistration
	allowed      bool
}

// ServiceDispatch is the finite original Session method dispatcher. Advance is
// driven by the Environment's existing coordinator; it creates no timer or
// waiter per invocation. Both canceled callbacks and final provider tails keep
// their slots occupied. Every application entry uses the shared root executor.
type serviceChannel struct {
	receiver  *rpcv4.Receiver
	publisher *rpcv4.Publisher
}

type ServiceDispatch struct {
	streamMethods                         []serviceStreamMethod
	streamSlots                           []*serviceStreamCall
	durableNotifications                  *NotificationDispatch
	durableWake                           chan struct{}
	durableStarted, durableExited         bool
	durableCursor                         int
	executionRegistry                     *rpcv4.ServiceRegistry
	registryBorrow                        resourcev4.Reference
	shortResponseBytes                    uint32
	short                                 [5]*resourcev4.ProtectedReservation
	shortExecution                        [5]*resourcev4.ProtectedReservation
	executionFloors                       []serviceExecutionFloor
	closingResources                      bool
	consumer                              *rpcv4.ServiceConsumer
	channels                              [8]serviceChannel
	activated                             bool
	mu                                    sync.Mutex
	plan                                  *SessionPlan
	network                               *rpcv4.Network
	root                                  *resourcev4.Root
	owner                                 resourcev4.OwnerKey
	clock                                 *timev4.Clock
	accounts                              [resourcev4.MaxAccountsPerCharge]resourcev4.Account
	accountCount                          int
	methods                               []serviceMethod
	readCodec                             *protocolv4.ManagementCodec
	slots                                 []*serviceInvocation
	resident, active                      uint32
	residentLimit                         uint32
	serial                                uint64
	runtimeBytes                          uint64
	reservation, planBorrow               resourcev4.Reference
	closed, advancing, admitting, cleaned bool
	done                                  chan struct{}
}

type serviceInvocation struct {
	durableRead               *serviceDurableRead
	execution                 *serviceExecution
	mu                        sync.Mutex
	dispatcher                *ServiceDispatch
	plan                      *SessionPlan
	method                    UnaryRegistration
	header                    protocolv4.ApplicationHeader
	input                     *rpcv4.VerifiedInput
	borrow                    rpcv4.InputBorrow
	result                    *rpcv4.AcceptedResult
	writer                    *rpcv4.ResponseWriter
	observation               *rpcv4.OutputObservation
	deadline, runDeadline     *timev4.Deadline
	ctx                       context.Context
	cancel                    context.CancelCauseFunc
	queued                    *QueuedApplicationTask
	task                      *ApplicationTask
	reservation               resourcev4.Reference
	response                  UnaryResponse
	started, returned, closed bool
}

func ServiceDispatchCharge(c ServiceDispatchConfig) (resourcev4.Vector, error) {
	if c.Root == nil || c.Clock == nil || c.Slots == 0 || c.Slots > 1024 || c.ResidentSlots >= c.Slots || len(c.Methods) > 128 || len(c.Accounts) > resourcev4.MaxAccountsPerCharge || c.RuntimeBytes == 0 || c.InvocationRuntimeBytes == 0 || c.ShortResponseBytes > 1048576 {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	streamCharge, err := streamRegistrationsCharge(c)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	n := uint64(unsafe.Sizeof(ServiceDispatch{})) + uint64(c.Slots)*uint64(unsafe.Sizeof((*serviceInvocation)(nil)))
	if err := validateExecutionServices(c.ExecutionRegistry, c.ExecutionServices, c.Methods); err != nil {
		return resourcev4.Vector{}, err
	}
	n += uint64(len(c.ExecutionServices)) * uint64(unsafe.Sizeof(serviceExecutionFloor{}))
	if c.ExecutionRegistry != nil {
		codecBytes, err := protocolv4.ManagementCodecBackingBytes()
		if err != nil {
			return resourcev4.Vector{}, err
		}
		n += codecBytes
	}
	for index, m := range c.Methods {
		if (m.Handler == nil) != m.Resume || m.Resume && m.WorkClass != ApplicationShort || m.Type == 0 || m.WorkClass > ApplicationResident || m.WorkClass == ApplicationResident && c.ResidentSlots == 0 {
			return resourcev4.Vector{}, cryptov4.ErrConfiguration
		}
		var wire [512]byte
		if _, err := protocolv4.EncodeMap(wire[:], "ContractTarget", []protocolv4.Field{{Name: "service_namespace", Kind: protocolv4.TextString, Text: m.Namespace}, {Name: "method_type_id", Number: uint64(m.Type)}}); err != nil {
			return resourcev4.Vector{}, cryptov4.ErrConfiguration
		}
		for _, other := range c.Methods[:index] {
			if other.Method == m.Method || other.Namespace == m.Namespace && other.Type == m.Type {
				return resourcev4.Vector{}, cryptov4.ErrConfiguration
			}
		}
		n += uint64(unsafe.Sizeof(serviceMethod{})) + uint64(len(m.Namespace))
	}
	charge, err := (resourcev4.Vector{resourcev4.SDKBytes: n, resourcev4.Items: uint64(1+c.Slots) + uint64(len(c.Methods))}).Add(resourcev4.Vector{resourcev4.SDKBytes: c.RuntimeBytes})
	if err != nil {
		return resourcev4.Vector{}, err
	}
	charge, err = charge.Add(streamCharge)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	if c.DurableProviderRuntimeBytes != 0 {
		if c.ExecutionRegistry == nil {
			return resourcev4.Vector{}, cryptov4.ErrConfiguration
		}
		return charge.Add(resourcev4.Vector{resourcev4.SDKBytes: c.DurableProviderRuntimeBytes, resourcev4.Tasks: 1, resourcev4.WorkSlots: 1, resourcev4.Items: 1})
	}
	return charge, nil
}
func serviceInvocationCharge(runtimeBytes uint64) (resourcev4.Vector, error) {
	n := uint64(unsafe.Sizeof(serviceInvocation{})) + 2*uint64(unsafe.Sizeof(timev4.Deadline{})) + applicationContextBytes()
	return (resourcev4.Vector{resourcev4.SDKBytes: n, resourcev4.Items: 3}).Add(resourcev4.Vector{resourcev4.SDKBytes: runtimeBytes})
}

// InstallServices is once-only and precedes Session adoption. This component
// admits transient unary callbacks; execution methods require their original
// execution registration owner before they can use the same dispatch service.
func (p *SessionPlan) InstallServices(c ServiceDispatchConfig, n *rpcv4.Network, metadata resourcev4.Reference) (*ServiceDispatch, error) {
	if p == nil || n == nil {
		return nil, cryptov4.ErrConfiguration
	}
	charge, err := ServiceDispatchCharge(c)
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.claimed || p.services != nil || !p.config.Services {
		return nil, cryptov4.ErrTransition
	}
	if err := metadata.CheckSameEnvironment(p.reservation); err != nil {
		return nil, err
	}
	if err := metadata.CheckAllocationScope(c.Root, c.Owner, c.Accounts); err != nil {
		return nil, err
	}
	if err := n.CheckServiceClock(c.Clock); err != nil {
		return nil, err
	}
	if err := n.CheckEnvironment(metadata); err != nil {
		return nil, err
	}
	for _, m := range c.Methods {
		if err := n.CheckUnaryBinding(m.Method, m.Namespace, m.Type); err != nil {
			return nil, err
		}
	}
	if err := validateResumeRegistrations(p.config.Handlers, n, c); err != nil {
		return nil, err
	}
	for _, m := range c.Streams {
		_, policy, err := n.StreamBinding(m.Method, m.Namespace, m.Type, m.ContractDigest)
		if err != nil {
			return nil, err
		}
		if policy.Semantics == 1 && c.ExecutionRegistry == nil {
			return nil, rpcv4.ErrExecutionUnsupported
		}
		if p.config.Handlers != nil {
			p.config.Handlers.mu.Lock()
			collision := false
			for _, raw := range p.config.Handlers.registrations {
				collision = collision || raw.config.Kind == m.Kind
			}
			p.config.Handlers.mu.Unlock()
			if collision {
				return nil, cryptov4.ErrConfiguration
			}
		}
	}
	for _, binding := range c.ExecutionServices {
		found := false
		for _, m := range c.Methods {
			check := n.CheckShortExecutionBinding
			if binding.DurableHistory != nil {
				check = n.CheckShortDurableExecutionBinding
			}
			if m.Namespace == binding.Authority.Namespace && m.WorkClass == ApplicationShort && check(m.Method, m.Namespace, m.Type) == nil {
				found = true
				break
			}
		}
		if !found {
			return nil, cryptov4.ErrConfiguration
		}
	}
	if p.queries != nil {
		if err := n.CheckQueryService(p.queries.service); err != nil {
			return nil, err
		}
	}
	borrow, err := p.reservation.Borrow()
	if err != nil {
		return nil, err
	}
	owned, err := metadata.Take(charge)
	if err != nil {
		borrow.Release()
		return nil, err
	}
	d := &ServiceDispatch{executionRegistry: c.ExecutionRegistry, plan: p, network: n, root: c.Root, owner: c.Owner, clock: c.Clock, accountCount: len(c.Accounts), methods: make([]serviceMethod, len(c.Methods)), slots: make([]*serviceInvocation, c.Slots), residentLimit: c.ResidentSlots, runtimeBytes: c.InvocationRuntimeBytes, reservation: owned, planBorrow: borrow, done: make(chan struct{})}
	if c.ExecutionRegistry != nil {
		d.readCodec, err = protocolv4.NewManagementCodec()
		if err != nil {
			owned.Release()
			borrow.Release()
			return nil, err
		}
	}
	if c.ShortResponseBytes != 0 {
		charges, e := serviceCallCharges(c.InvocationRuntimeBytes, c.ShortResponseBytes, p.executor.TaskCharge())
		if e == nil {
			for index, ref := range c.ShortReservations {
				if e = ref.CheckAllocationScope(c.Root, c.Owner, c.Accounts); e != nil {
					break
				}
				if index == 0 {
					d.short[index], e = resourcev4.NewProtectedReservation(ref, charges[index], c.ShortExecutionBorrow)
				} else {
					d.short[index], e = resourcev4.NewProtectedReservation(ref, charges[index])
				}
				if e != nil {
					break
				}
			}
		}
		if e != nil {
			for _, r := range d.short {
				r.Close()
			}
			owned.Release()
			borrow.Release()
			return nil, e
		}
		d.shortResponseBytes = c.ShortResponseBytes
	} else if c.ShortReservations != ([5]resourcev4.Reference{}) || c.ShortExecutionBorrow != (resourcev4.Reference{}) {
		owned.Release()
		borrow.Release()
		return nil, cryptov4.ErrConfiguration
	}
	d.streamMethods = make([]serviceStreamMethod, len(c.Streams))
	d.streamSlots = make([]*serviceStreamCall, c.StreamSlots)
	for index, m := range c.Streams {
		m.Kind, m.Namespace = strings.Clone(m.Kind), strings.Clone(m.Namespace)
		m.Metadata = append([]byte(nil), m.Metadata...)
		if m.EventSource != nil {
			copy := *m.EventSource
			m.EventSource = &copy
		}
		d.streamMethods[index].registration = m
	}
	copy(d.accounts[:], c.Accounts)
	for index, m := range c.Methods {
		m.Namespace = strings.Clone(m.Namespace)
		d.methods[index].registration = m
	}
	consumer, err := n.ClaimServiceConsumer(owned)
	if err != nil {
		for _, r := range d.short {
			r.Close()
		}
		owned.Release()
		borrow.Release()
		return nil, err
	}
	d.consumer = consumer
	if c.ExecutionRegistry != nil {
		d.registryBorrow, err = c.ExecutionRegistry.Borrow(owned)
		if err != nil {
			consumer.Stop()
			for _, r := range d.short {
				r.Close()
			}
			owned.Release()
			borrow.Release()
			return nil, err
		}
	}
	if err = d.installExecutionFloors(c); err != nil {
		d.closeExecutionFloors()
		d.registryBorrow.Release()
		consumer.Stop()
		for _, r := range d.short {
			r.Close()
		}
		owned.Release()
		borrow.Release()
		return nil, err
	}
	if c.DurableProviderRuntimeBytes != 0 {
		d.durableWake = make(chan struct{}, 1)
	}
	p.services = d
	p.lease.mu.Lock()
	p.lease.services = d
	p.lease.mu.Unlock()
	return d, nil
}

// SetServiceAccess changes only an already registered original method. Current
// authorization is fail-closed; acquiring a query permission does not grant
// execution. The lease gate orders revocation with callback and output entry.
func (l *ApplicationLease) SetServiceAccess(namespace string, typeID uint32, allowed bool) error {
	if l == nil {
		return ErrApplicationAuthorization
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.reserved || l.revoked || l.services == nil {
		return ErrApplicationAuthorization
	}
	d := l.services
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return ErrApplicationAuthorization
	}
	for index := range d.methods {
		m := &d.methods[index]
		if m.registration.Namespace == namespace && m.registration.Type == typeID {
			m.allowed = allowed
			return nil
		}
	}
	for index := range d.streamMethods {
		m := &d.streamMethods[index]
		if m.registration.Namespace == namespace && m.registration.Type == typeID {
			m.allowed = allowed
			return nil
		}
	}
	return ErrApplicationAuthorization
}

func (i *serviceInvocation) withAuthority(action func() error) error {
	i.mu.Lock()
	p, d, deadline, runDeadline, ctx := i.plan, i.dispatcher, i.deadline, i.runDeadline, i.ctx
	closed := i.closed
	method := i.method.Method
	i.mu.Unlock()
	if closed || p == nil || d == nil {
		return rpcv4.ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := deadline.Check(); err != nil {
		return err
	}
	if runDeadline != nil {
		if err := runDeadline.Check(); err != nil {
			return err
		}
	}
	l, a, err := p.queryAuthorization()
	if err != nil {
		return err
	}
	return a.WithCurrentAuthorization(func() error {
		l.mu.Lock()
		defer l.mu.Unlock()
		if l.revoked || l.authorization != a {
			return ErrApplicationAuthorization
		}
		d.mu.Lock()
		defer d.mu.Unlock()
		if d.closed {
			return ErrApplicationAuthorization
		}
		for _, m := range d.methods {
			if m.registration.Method == method && m.allowed {
				if err := ctx.Err(); err != nil {
					return err
				}
				if err := deadline.Check(); err != nil {
					return err
				}
				if runDeadline != nil {
					if err := runDeadline.Check(); err != nil {
						return err
					}
				}
				return action()
			}
		}
		return ErrApplicationAuthorization
	})
}

// Admit takes one actual complete request off the channel's finite ready set.
// It never waits for application work. Refusal consumes only the original
// ReplySlot and leaves the channel reader free to process unrelated messages.
func (d *ServiceDispatch) Admit(receiver *rpcv4.Receiver, publisher *rpcv4.Publisher) error {
	if d == nil || receiver == nil || publisher == nil {
		return cryptov4.ErrConfiguration
	}
	d.mu.Lock()
	if d.closed || d.cleaned || !d.activated {
		d.mu.Unlock()
		return cryptov4.ErrClosed
	}
	if d.admitting {
		d.mu.Unlock()
		return cryptov4.ErrCapacity
	}
	d.admitting = true
	d.mu.Unlock()
	defer func() { d.mu.Lock(); d.admitting = false; d.cleanupLocked(); d.mu.Unlock() }()
	if err := receiver.CheckAssociation(d.network, publisher); err != nil {
		return err
	}
	ticket, input, err := d.consumer.NextRequest(receiver, publisher)
	if err != nil {
		return err
	}
	defer input.Close()
	verified, err := input.Take()
	if err != nil {
		_ = publisher.QueueRefusal(ticket, "service_unavailable")
		return err
	}
	adopted := false
	defer func() {
		if !adopted {
			verified.Close()
		}
	}()
	refuse := func(code string, err error) error { _ = publisher.QueueRefusal(ticket, code); return err }
	// read_result_request is a fixed SDK route. It never enters the ordinary
	// method table or application executor; the complete target and current
	// authorization are checked before the original result bytes are copied.
	_, requestHeader, headerErr := func() ([]byte, protocolv4.ApplicationHeader, error) {
		borrow, e := verified.Borrow()
		if e != nil {
			return nil, protocolv4.ApplicationHeader{}, e
		}
		defer borrow.Release()
		payload, h, e := borrow.Bytes()
		return payload, h, e
	}()
	if headerErr != nil {
		verified.Close()
		return refuse("service_unavailable", headerErr)
	}
	if requestHeader.Kind() == "read_result_request" {
		return d.admitReadResult(publisher, ticket, verified)
	}
	method, policy, err := verified.OriginalMethod()
	if err != nil {
		return refuse("service_contract_mismatch", err)
	}
	borrow, err := verified.Borrow()
	if err != nil {
		return refuse("service_unavailable", err)
	}
	defer func() {
		if !adopted {
			borrow.Release()
		}
	}()
	_, header, err := borrow.Bytes()
	if err != nil {
		return refuse("service_unavailable", err)
	}
	if header.Kind() == "execution_unary_request" && policy.Shape == 0 && policy.Semantics == 1 {
		borrow.Release()
		adopted, err = d.admitExecution(publisher, ticket, verified, method, policy, header)
		return err
	}
	// This exact variant has no execution history or operation registration.
	if header.Kind() != "transient_unary_request" || policy.Shape != 0 || policy.Semantics != 0 {
		return refuse("method_unavailable", rpcv4.ErrMethod)
	}
	d.mu.Lock()
	if d.closed || d.serial == math.MaxUint64 {
		d.mu.Unlock()
		return refuse("service_unavailable", cryptov4.ErrClosed)
	}
	index := -1
	for j, x := range d.slots {
		if x == nil {
			index = j
			break
		}
	}
	var registration UnaryRegistration
	found, allowed := false, false
	for _, m := range d.methods {
		if m.registration.Method == method && m.registration.Namespace == policy.Namespace && m.registration.Type == policy.Type {
			registration = m.registration
			found = true
			allowed = m.allowed
			break
		}
	}
	if !found || !allowed {
		d.mu.Unlock()
		return refuse("permission_denied", ErrApplicationAuthorization)
	}
	if registration.Resume {
		d.mu.Unlock()
		return refuse("method_unavailable", rpcv4.ErrExecutionUnsupported)
	}
	if index < 0 || registration.WorkClass == ApplicationResident && d.resident == d.residentLimit {
		d.mu.Unlock()
		return refuse("resource_exhausted", cryptov4.ErrCapacity)
	}
	if err := d.reservation.Check(); err != nil {
		d.mu.Unlock()
		return refuse("service_unavailable", err)
	}
	// Reserve the finite index before leaving the gate for clock/authority checks.
	ctx, cancel := context.WithCancelCause(context.Background())
	i := &serviceInvocation{dispatcher: d, plan: d.plan, method: registration, header: header, input: verified, borrow: borrow, ctx: ctx, cancel: cancel}
	i.response.invocation = i
	d.slots[index] = i
	d.active++
	if registration.WorkClass == ApplicationResident {
		d.resident++
	}
	d.serial++
	serial := d.serial
	d.mu.Unlock()
	// Unpublished construction is still an actual in-flight owner. Advance skips
	// it until the complete references and its once-only dispatch outcome exist.
	success := false
	defer func() {
		if !success {
			cancel(cryptov4.ErrClosed)
			d.rollback(index, i)
		}
	}()
	deadline, err := verified.MessageDeadline(d.clock)
	if err != nil {
		return refuse(serviceRefusal(err), err)
	}
	now, err := deadline.Sample()
	if err != nil {
		return refuse(serviceRefusal(err), err)
	}
	if policy.MessageLifetimeMS == 0 || header.Fields().DeadlineAtMS-now.LowerMS > policy.MessageLifetimeMS {
		return refuse("deadline_exceeded", timev4.ErrExpired)
	}
	i.deadline = deadline
	charges, err := serviceCallCharges(d.runtimeBytes, header.Fields().ResponseLimitBytes, d.plan.executor.TaskCharge())
	if err != nil {
		return refuse("resource_exhausted", err)
	}
	var requests [5]resourcev4.Request
	var refs [5]resourcev4.Reference
	for j, c := range charges {
		owner := d.owner
		var key [48]byte
		copy(key[:16], owner.Instance[:])
		copy(key[16:32], owner.Backing[:])
		binary.BigEndian.PutUint64(key[32:40], serial)
		binary.BigEndian.PutUint64(key[40:], uint64(j))
		digest := sha256.Sum256(key[:])
		copy(owner.Instance[:], digest[:16])
		copy(owner.Backing[:], digest[16:])
		requests[j] = resourcev4.Request{Owner: owner, Charge: c, Accounts: d.accounts[:d.accountCount]}
	}
	protected := false
	if registration.WorkClass == ApplicationShort && d.shortResponseBytes != 0 && header.Fields().ResponseLimitBytes <= d.shortResponseBytes {
		protected = resourcev4.CheckoutProtectedBatch(d.short[:], refs[:]) == nil
	}
	if !protected {
		if err := d.root.ReserveBatch(requests[:], refs[:]); err != nil {
			return refuse("resource_exhausted", err)
		}
	}
	defer func() {
		for _, ref := range refs {
			ref.Release()
		}
	}()
	if err := refs[0].CheckSameEnvironment(d.reservation); err != nil {
		return refuse("service_unavailable", err)
	}
	i.reservation, err = refs[0].Take(charges[0])
	if err != nil {
		return refuse("resource_exhausted", err)
	}
	i.result, err = publisher.NewAcceptedResult(ticket, verified, refs[2], refs[3], d.runtimeBytes)
	if err != nil {
		return refuse("resource_exhausted", err)
	}
	i.writer, err = i.result.Writer()
	if err != nil {
		return refuse("service_unavailable", err)
	}
	i.observation, err = d.network.NewOutputObservation(ticket, ctx, refs[4], d.runtimeBytes)
	if err != nil {
		return refuse("service_unavailable", err)
	}
	err = i.withAuthority(func() error {
		i.mu.Lock()
		defer i.mu.Unlock()
		if i.closed {
			return cryptov4.ErrClosed
		}
		work := func() { i.run(policy.TransientRunMS) }
		if header.Fields().AdmissionMode == 1 {
			i.task, err = d.plan.executor.TrySubmit(registration.WorkClass, refs[1], i.reservation, work)
		} else {
			i.queued, err = d.plan.executor.queueApplication(d.plan.applicationGroup, registration.WorkClass, refs[1], i.reservation, work)
		}
		return err
	})
	if err != nil {
		return refuse(serviceRefusal(err), err)
	}
	i.mu.Lock()
	i.started = true
	i.mu.Unlock()
	adopted, success = true, true
	return nil
}

// admitReadResult services the fixed read_result_request after its complete
// target payload has been authenticated and captured. The target is only a
// lookup selector: resolveReadHistory supplies the current Session identity
// and history permission, and CaptureResult repeats that gate before every
// retained result read. The response uses the same ReplySlot and publisher
// tail as every other ordinary RPC.
func (d *ServiceDispatch) admitReadResult(publisher *rpcv4.Publisher, ticket rpcv4.Ticket, input *rpcv4.VerifiedInput) error {
	if d == nil || publisher == nil || input == nil || d.readCodec == nil || d.plan == nil || d.executionRegistry == nil {
		return rpcv4.ErrOwner
	}
	refuse := func(code string, cause error) error {
		_ = publisher.QueueRefusal(ticket, code)
		return cause
	}
	borrow, err := input.Borrow()
	if err != nil {
		return refuse("service_unavailable", err)
	}
	payload, _, err := borrow.Bytes()
	if err != nil {
		borrow.Release()
		return refuse("service_unavailable", err)
	}
	targetWire := append([]byte(nil), payload...)
	borrow.Release()
	mt, err := d.readCodec.DecodeTarget(targetWire)
	clear(targetWire)
	if err != nil {
		return refuse("service_contract_mismatch", err)
	}
	target := rpcv4.ExecutionTarget{Service: rpcv4.ExecutionService{Tenant: mt.Tenant, Audience: mt.Audience, Namespace: mt.Namespace}, Caller: rpcv4.ExecutionPrincipal{Authority: mt.Authority, Subject: mt.Subject}, Operation: mt.Operation, RequestDigest: mt.RequestDigest, ContractDigest: mt.ContractDigest}
	deadline, err := input.MessageDeadline(d.clock)
	if err != nil {
		return refuse(serviceRefusal(err), err)
	}
	if err := deadline.Check(); err != nil {
		return refuse(serviceRefusal(err), err)
	}
	binding, access, err := d.resolveReadBinding(target)
	if err != nil {
		return refuse(serviceRefusal(err), err)
	}
	if binding.DurableHistory != nil {
		return d.admitDurableRead(publisher, ticket, target, access, binding.DurableHistory, deadline)
	}
	history := binding.History
	readCharge, err := rpcv4.ExecutionResultReadCharge(d.runtimeBytes)
	if err != nil {
		return refuse("resource_exhausted", err)
	}
	d.mu.Lock()
	if d.serial == math.MaxUint64 {
		d.mu.Unlock()
		return refuse("service_unavailable", rpcv4.ErrCapacity)
	}
	d.serial++
	metadataSerial := d.serial
	d.mu.Unlock()
	metadataOwner := d.owner
	var metadataSeed [48]byte
	copy(metadataSeed[:16], metadataOwner.Instance[:])
	copy(metadataSeed[16:32], metadataOwner.Backing[:])
	copy(metadataSeed[32:40], "readmeta")
	binary.BigEndian.PutUint64(metadataSeed[40:], metadataSerial)
	metadataDigest := sha256.Sum256(metadataSeed[:])
	copy(metadataOwner.Instance[:], metadataDigest[:16])
	copy(metadataOwner.Backing[:], metadataDigest[16:])
	metadata, err := d.root.Reserve(metadataOwner, readCharge, d.accounts[:d.accountCount]...)
	if err != nil {
		return refuse("resource_exhausted", err)
	}
	defer metadata.Release()
	if err := metadata.CheckSameEnvironment(d.reservation); err != nil {
		return refuse("service_unavailable", err)
	}
	read, err := history.CaptureResult(target, access, metadata, d.runtimeBytes)
	if err != nil {
		return refuse(serviceRefusal(err), err)
	}
	queuedRead := false
	defer func() {
		if !queuedRead {
			read.Close()
		}
	}()
	length, err := read.Length()
	if err != nil || length > 1048576 {
		if err == nil {
			err = rpcv4.ErrResponseLimit
		}
		return refuse(serviceRefusal(err), err)
	}
	if _, err = publisher.QueueResultRead(ticket, read, deadline); err != nil {
		return refuse(serviceRefusal(err), err)
	}
	queuedRead = true
	return nil
}

// resolveReadHistory binds the wire target to this Session's original
// authorization and execution registry. It mirrors the management adapter
// without requiring the management channel to exist: ordinary result reads
// use an accepting RPC channel and their own full ReplySlot/result owner.
func (d *ServiceDispatch) resolveReadHistory(target rpcv4.ExecutionTarget) (*rpcv4.VolatileExecutions, rpcv4.ExecutionAccess, error) {
	binding, access, err := d.resolveReadBinding(target)
	if err == nil && binding.DurableHistory != nil {
		return nil, nil, rpcv4.ErrExecutionUnsupported
	}
	return binding.History, access, err
}

func (d *ServiceDispatch) resolveReadBinding(target rpcv4.ExecutionTarget) (rpcv4.ServiceBinding, rpcv4.ExecutionAccess, error) {
	if d == nil || d.plan == nil || d.executionRegistry == nil {
		return rpcv4.ServiceBinding{}, nil, rpcv4.ErrExecutionUnsupported
	}
	lease, endpoint, err := d.plan.queryAuthorization()
	if err != nil {
		return rpcv4.ServiceBinding{}, nil, err
	}
	access := &managementHistoryAuthority{lease: lease, endpoint: endpoint, backing: d.reservation, target: target}
	var binding rpcv4.ServiceBinding
	err = access.WithExecutionAccess(target, func(authority resourcev4.Reference) error {
		if err := d.executionRegistry.CheckSameEnvironment(authority); err != nil {
			return err
		}
		found, err := d.executionRegistry.Lookup(rpcv4.ServiceAuthority{Tenant: target.Service.Tenant, Audience: target.Service.Audience, Namespace: target.Service.Namespace})
		if err != nil {
			return err
		}
		binding = found
		return nil
	})
	if err != nil {
		return rpcv4.ServiceBinding{}, nil, err
	}
	return binding, access, nil
}

func serviceRefusal(err error) string {
	switch {
	case errors.Is(err, timev4.ErrExpired), errors.Is(err, context.DeadlineExceeded), errors.Is(err, rpcv4.ErrExecutionExpired):
		return "deadline_exceeded"
	case errors.Is(err, rpcv4.ErrExecutionConflict):
		return "operation_conflict"
	case errors.Is(err, rpcv4.ErrResultExpired):
		return "result_expired"
	case errors.Is(err, ErrApplicationAuthorization), errors.Is(err, rpcv4.ErrExecutionUnauthorized):
		return "permission_denied"
	case errors.Is(err, cryptov4.ErrCapacity), errors.Is(err, resourcev4.ErrCapacity), errors.Is(err, rpcv4.ErrCapacity), errors.Is(err, rpcv4.ErrResponseLimit):
		return "resource_exhausted"
	default:
		return "service_unavailable"
	}
}

func (i *serviceInvocation) run(duration uint64) {
	failure := error(ErrCompletionCallbackExit)
	var code uint32
	returned := false
	defer func() {
		if recover() != nil || !returned {
			failure = ErrCompletionCallbackExit
		}
		if failure == nil {
			failure = i.withAuthority(func() error {
				i.mu.Lock()
				defer i.mu.Unlock()
				if i.closed {
					return rpcv4.ErrClosed
				}
				_, err := i.writer.Finalize(code)
				return err
			})
		}
		i.mu.Lock()
		i.returned = true
		i.cancel(cryptov4.ErrClosed)
		if failure != nil && !i.closed {
			reason := serviceRefusal(failure)
			if errors.Is(failure, ErrCompletionCallbackExit) {
				reason = "service_failed"
			}
			_ = i.result.Refuse(reason)
		}
		i.observation.EndInvocation()
		i.borrow.Release()
		i.borrow = rpcv4.InputBorrow{}
		i.input.Close()
		i.result.Close()
		i.mu.Unlock()
	}()
	failure = i.withAuthority(func() error {
		sample, err := i.deadline.Sample()
		if err != nil {
			return err
		}
		run, err := i.deadline.ForkAgeAt(sample, duration)
		if err != nil {
			return err
		}
		i.mu.Lock()
		defer i.mu.Unlock()
		if i.closed {
			return cryptov4.ErrClosed
		}
		i.runDeadline = run
		return nil
	})
	if failure != nil {
		returned = true
		return
	}
	i.plan.lease.mu.Lock()
	request := UnaryRequest{Binding: i.plan.lease.binding, ApplicationContext: i.plan.lease.context, Input: i.borrow, OutputInterest: i.observation.View()}
	i.plan.lease.mu.Unlock()
	callCtx, exit, err := enterApplicationContext(i.ctx, i.plan.executor, ordinaryApplicationLane, i.method.WorkClass, i.reservation, nil)
	if err != nil {
		failure, returned = err, true
		return
	}
	defer exit()
	code, failure = i.method.Handler(callCtx, request, &i.response)
	returned = true
}

func (d *ServiceDispatch) rollback(index int, i *serviceInvocation) {
	// No callback was dispatched when construction failed.
	if i.observation != nil {
		i.observation.EndInvocation()
	}
	if i.result != nil {
		i.result.Close()
	}
	i.reservation.Release()
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.slots[index] == i {
		d.slots[index] = nil
		d.active--
		if i.method.WorkClass == ApplicationResident {
			d.resident--
		}
	}
	d.cleanupLocked()
}
func (i *serviceInvocation) stop(cause error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.closed {
		return
	}
	i.closed = true
	i.cancel(cause)
	if i.queued != nil {
		i.queued.Cancel()
	}
	if i.result != nil {
		_ = i.result.Refuse(serviceRefusal(cause))
		i.result.Close()
	}
}

// Advance performs only finite SDK observation, cancellation and cleanup. It
// never executes a user handler and never substitutes a worker for a late one.
func (d *ServiceDispatch) Advance() {
	if d == nil {
		return
	}
	d.mu.Lock()
	if d.advancing || d.cleaned {
		d.mu.Unlock()
		return
	}
	d.advancing = true
	channels := d.channels
	accepting := d.activated && !d.closed
	d.mu.Unlock()
	defer func() { d.mu.Lock(); d.advancing = false; d.cleanupLocked(); d.mu.Unlock() }()
	if accepting {
		for _, channel := range channels {
			if channel.receiver != nil {
				for range 4 {
					if err := d.Admit(channel.receiver, channel.publisher); err != nil {
						break
					}
				}
			}
		}
	}
	for index := range d.slots {
		d.mu.Lock()
		i := d.slots[index]
		closed := d.closed
		d.mu.Unlock()
		if i == nil {
			continue
		}
		i.mu.Lock()
		started := i.started
		i.mu.Unlock()
		if !started {
			continue
		}
		if i.durableRead != nil {
			d.advanceDurableRead(index, i, closed)
			continue
		}
		if i.execution != nil {
			if i.execution.durableHistory != nil {
				d.advanceDurableExecution(index, i, closed)
				continue
			}
			d.advanceExecution(index, i, closed)
			continue
		}
		if closed {
			i.stop(cryptov4.ErrClosed)
		} else if err := i.withAuthority(func() error { return nil }); err != nil {
			i.stop(err)
		}
		i.mu.Lock()
		var done <-chan struct{}
		if i.queued != nil {
			done = i.queued.Done()
		} else if i.task != nil {
			done = i.task.Done()
		}
		finished := false
		select {
		case <-done:
			finished = true
		default:
		}
		if !finished {
			i.mu.Unlock()
			continue
		}
		i.closed = true
		i.cancel(cryptov4.ErrClosed)
		i.observation.EndInvocation()
		i.borrow.Release()
		i.borrow = rpcv4.InputBorrow{}
		i.input.Close()
		i.result.Close()
		if !i.result.CleanupComplete() || !i.observation.CleanupComplete() {
			i.mu.Unlock()
			continue
		}
		i.reservation.Release()
		i.reservation = resourcev4.Reference{}
		class := i.method.WorkClass
		i.dispatcher = nil
		i.plan = nil
		i.method = UnaryRegistration{}
		i.input = nil
		i.result = nil
		i.writer = nil
		i.observation = nil
		i.deadline = nil
		i.runDeadline = nil
		i.ctx = nil
		i.cancel = nil
		i.queued = nil
		i.task = nil
		i.mu.Unlock()
		d.mu.Lock()
		// Work class is recorded by the slot before the retained response detaches.
		d.slots[index] = nil
		d.active--
		if class == ApplicationResident {
			d.resident--
		}
		d.mu.Unlock()
	}
}
func (d *ServiceDispatch) Close() {
	if d == nil {
		return
	}
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		d.Advance()
		return
	}
	d.closed = true
	for _, job := range d.streamSlots {
		if job != nil {
			job.cancel()
		}
	}
	d.signalDurable()
	d.closingResources = true
	short := d.short
	for _, r := range short {
		r.Close()
	}
	d.mu.Unlock()
	d.closeExecutionFloors()
	d.mu.Lock()
	d.closingResources = false
	d.mu.Unlock()
	d.Advance()
}
func (d *ServiceDispatch) cleanupLocked() {
	if !d.closed || d.cleaned || d.active != 0 || d.advancing || d.admitting || d.closingResources || d.durableStarted && !d.durableExited || d.durableNotifications != nil {
		return
	}
	d.cleaned = true
	clear(d.short[:])
	clear(d.shortExecution[:])
	d.executionFloors = nil
	d.consumer.Stop()
	d.consumer = nil
	d.plan = nil
	d.network = nil
	d.root = nil
	d.clock = nil
	clear(d.methods)
	d.methods = nil
	clear(d.streamMethods)
	d.streamMethods, d.streamSlots = nil, nil
	d.slots = nil
	d.channels = [8]serviceChannel{}
	clear(d.accounts[:])
	d.reservation.Release()
	d.planBorrow.Release()
	d.registryBorrow.Release()
	d.registryBorrow = resourcev4.Reference{}
	d.executionRegistry = nil
	d.reservation = resourcev4.Reference{}
	d.planBorrow = resourcev4.Reference{}
	close(d.done)
}
func (d *ServiceDispatch) WaitCleanup(ctx context.Context) error {
	if d == nil {
		return nil
	}
	if ctx == nil {
		return cryptov4.ErrConfiguration
	}
	select {
	case <-d.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// AttachChannel binds an actually constructed channel from this exact Network.
// The finite attachment remains until channel cleanup; it grants no OPEN or
// application publication permission by itself.
func (d *ServiceDispatch) AttachChannel(receiver *rpcv4.Receiver, publisher *rpcv4.Publisher) error {
	if d == nil {
		return cryptov4.ErrConfiguration
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed || d.cleaned {
		return cryptov4.ErrClosed
	}
	if err := receiver.CheckAssociation(d.network, publisher); err != nil {
		return err
	}
	for _, c := range d.channels {
		if c.receiver == receiver {
			return cryptov4.ErrTransition
		}
	}
	for index, c := range d.channels {
		if c.receiver == nil {
			d.channels[index] = serviceChannel{receiver, publisher}
			return nil
		}
	}
	return cryptov4.ErrCapacity
}
func (d *ServiceDispatch) activate() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.closed {
		d.activated = true
		if d.durableWake != nil && !d.durableStarted {
			d.durableStarted = true
			go d.runDurableProvider()
		}
	}
}

// detachChannel removes only the exact retired reader. In-flight invocations
// already retain their own input/output owners; a stale Advance snapshot meets
// the closed receiver gate and cannot consume a replacement channel's work.
func (d *ServiceDispatch) detachChannel(receiver *rpcv4.Receiver) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for index, channel := range d.channels {
		if channel.receiver == receiver {
			d.channels[index] = serviceChannel{}
			return
		}
	}
}

// serviceCallCharges is shared by dynamic admission and the already admitted
// short responsibility. Changing a writer/task's geometry changes both paths.
func serviceCallCharges(runtimeBytes uint64, responseLimit uint32, task resourcev4.Vector) (v [5]resourcev4.Vector, err error) {
	v[0], err = serviceInvocationCharge(runtimeBytes)
	if err != nil {
		return
	}
	v[1] = task
	v[2], err = rpcv4.AcceptedResultCharge(runtimeBytes)
	if err != nil {
		return
	}
	v[3], err = rpcv4.AcceptedResultSourceCharge(responseLimit, runtimeBytes)
	if err != nil {
		return
	}
	v[4], err = rpcv4.OutputObservationCharge(runtimeBytes)
	return
}
