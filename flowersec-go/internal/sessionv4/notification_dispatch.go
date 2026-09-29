package sessionv4

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

var ErrNotificationCleanupIncomplete = errors.New("sessionv4: notification cleanup incomplete")

type NotificationPendingPolicy uint8

const (
	NotificationDropNewest NotificationPendingPolicy = iota
	NotificationLatestPending
)

// NotificationMethod is trusted local scheduling policy for one exact method
// definition. Alternate contracts of that method share one subscriber count.
type NotificationMethod struct {
	Dependencies []ServiceDependency
	services     *invocationServices
	Method       uint32
	WorkClass    ApplicationWorkClass
	// ExecutionHandler is the unique business handler for execution semantics.
	// Observation methods have only independent local subscription callbacks.
	ExecutionHandler func(context.Context, NotificationRequest) error
}
type NotificationDispatchConfig struct {
	dependencyPreparation              *rpcDependencyPreparation
	Root                               *resourcev4.Root
	Owner                              resourcev4.OwnerKey
	Accounts                           []resourcev4.Account
	Clock                              *timev4.Clock
	Methods                            []NotificationMethod
	RuntimeBytes, DeliveryRuntimeBytes uint64
	WaitMS, CleanupMS                  uint64
	ExecutionRegistry                  *rpcv4.ServiceRegistry
	ExecutionSlots                     uint32
}

type notificationMethod struct {
	method  NotificationMethod
	policy  protocolv4.ServiceContractPolicy
	allowed bool
}

// NotificationDispatch uses the original SessionPlan group and root executor.
// Advance is driven by the existing Environment coordinator, never a polling
// goroutine or timer for each subscription. Readers only enqueue SDK work.
type NotificationDispatch struct {
	closingSamples                                        uint32
	durableProvider                                       *ServiceDispatch
	durableCursor                                         int
	lastExecutionRejection                                string
	mu                                                    sync.Mutex
	plan                                                  *SessionPlan
	root                                                  *resourcev4.Root
	owner                                                 resourcev4.OwnerKey
	accounts                                              [resourcev4.MaxAccountsPerCharge]resourcev4.Account
	accountCount                                          int
	clock                                                 *timev4.Clock
	routes                                                *rpcv4.ContractRoutes
	methods                                               []notificationMethod
	tokens                                                [128]*notificationToken
	channels                                              [2]*rpcv4.NotifyReceiver
	executions                                            []*notificationExecution
	executionRegistry                                     *rpcv4.ServiceRegistry
	registryBorrow                                        resourcev4.Reference
	serial                                                uint64
	runtimeBytes, deliveryRuntimeBytes, waitMS, cleanupMS uint64
	reservation, planBorrow                               resourcev4.Reference
	closed, activated, advancing, admitting, cleaned      bool
	draining                                              atomic.Bool
	done                                                  chan struct{}
}

// Decoder receives one isolated, bounded borrowed byte slice. It may mutate
// that slice during this invocation but cannot retain it after return. Its
// returned application object graph and arbitrary allocations are application
// owned; wire length never claims to bound that graph. Both callbacks execute
// serially under the same original ordinary executor task.
type NotificationObserver struct {
	Dependencies []ServiceDependency
	Decode       func(context.Context, []byte) (any, error)
	Handle       func(context.Context, any) error
}

type NotificationStatus struct {
	Closed, CleanupComplete bool
	Pending, Running        uint32
	KnownDropped            uint64
	LastGap                 string
}

// NotificationSubscription is an internal handle. Close seals dispatch without
// waiting. Release is used by the language binding when the caller relinquishes
// this compact handle; retaining status continues to retain its real charge.
type NotificationSubscription struct {
	mu                                 sync.Mutex
	token                              *notificationToken
	status                             NotificationStatus
	reservation                        resourcev4.Reference
	root                               *resourcev4.Root
	owner                              resourcev4.OwnerKey
	accounts                           [resourcev4.MaxAccountsPerCharge]resourcev4.Account
	accountCount                       int
	clock                              *timev4.Clock
	waitMS                             uint64
	runtimeBytes, identity, waitSerial uint64
	cleanup                            *timev4.Window
	cleanupError                       error
	waiters                            uint32
	done, closing                      chan struct{}
}

type notificationToken struct {
	closingSamples uint32
	services       *invocationServices
	dispatch       *NotificationDispatch
	subscription   *NotificationSubscription
	method         notificationMethod
	observer       NotificationObserver
	policy         NotificationPendingPolicy
	jobs           [17]*notificationDelivery
	active         *notificationDelivery
	serial         uint64
	closed         bool
	preparing      bool
	reservation    resourcev4.Reference
	dependencies   resourcev4.Reference
}
type notificationDelivery struct {
	token                        *notificationToken
	serial                       uint64
	payload                      []byte
	deadline                     *timev4.Deadline
	ctx                          context.Context
	cancel                       context.CancelCauseFunc
	queued                       *QueuedApplicationTask
	reservation, taskReservation resourcev4.Reference
	entered, returned, canceled  bool
}
type notificationInvocationKey struct{}
type notificationInvocation struct {
	token  *notificationToken
	parent *notificationInvocation
}

func NotificationDispatchCharge(c NotificationDispatchConfig) (resourcev4.Vector, error) {
	if c.Root == nil || c.Clock == nil || c.RuntimeBytes == 0 || c.DeliveryRuntimeBytes == 0 || c.WaitMS == 0 || c.WaitMS > 120000 || c.CleanupMS == 0 || c.CleanupMS > 120000 || len(c.Methods) > 128 || len(c.Accounts) > resourcev4.MaxAccountsPerCharge {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	if _, err := protocolv4.Notify(); err != nil {
		return resourcev4.Vector{}, err
	}
	hasExecution := false
	var dependencies resourcev4.Vector
	for i, m := range c.Methods {
		if m.ExecutionHandler == nil && len(m.Dependencies) != 0 {
			return resourcev4.Vector{}, cryptov4.ErrConfiguration
		}
		charge, err := serviceDependenciesCharge(m.Dependencies)
		if err != nil {
			return resourcev4.Vector{}, err
		}
		dependencies, err = dependencies.Add(charge)
		if err != nil {
			return resourcev4.Vector{}, err
		}
		hasExecution = hasExecution || m.ExecutionHandler != nil
		if m.WorkClass > ApplicationResident {
			return resourcev4.Vector{}, cryptov4.ErrConfiguration
		}
		for _, earlier := range c.Methods[:i] {
			if earlier.Method == m.Method {
				return resourcev4.Vector{}, cryptov4.ErrConfiguration
			}
		}
	}
	if c.ExecutionSlots > 128 || hasExecution && (c.ExecutionRegistry == nil || c.ExecutionSlots == 0) || !hasExecution && c.ExecutionSlots != 0 {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	n := uint64(unsafe.Sizeof(NotificationDispatch{})) + uint64(len(c.Methods))*(uint64(unsafe.Sizeof(notificationMethod{}))+128)
	n += uint64(c.ExecutionSlots) * uint64(unsafe.Sizeof((*notificationExecution)(nil)))
	charge, err := (resourcev4.Vector{resourcev4.SDKBytes: n, resourcev4.Items: uint64(1 + len(c.Methods))}).Add(resourcev4.Vector{resourcev4.SDKBytes: c.RuntimeBytes})
	if err != nil {
		return resourcev4.Vector{}, err
	}
	return charge.Add(dependencies)
}

func (p *SessionPlan) InstallNotifications(c NotificationDispatchConfig, routes *rpcv4.ContractRoutes, metadata resourcev4.Reference) (*NotificationDispatch, error) {
	return p.installNotifications(c, routes, metadata, resourcev4.Reference{}, resourcev4.Reference{})
}

func (p *SessionPlan) installNotifications(c NotificationDispatchConfig, routes *rpcv4.ContractRoutes, metadata, planBorrow, registryBorrow resourcev4.Reference) (*NotificationDispatch, error) {
	if p == nil || routes == nil {
		return nil, cryptov4.ErrConfiguration
	}
	charge, err := NotificationDispatchCharge(c)
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.claimed || p.registrationPreparing || p.notifications != nil || !p.config.Services {
		return nil, cryptov4.ErrTransition
	}
	if err := metadata.CheckAllocationScope(c.Root, c.Owner, c.Accounts); err != nil {
		return nil, err
	}
	if err := metadata.CheckSameEnvironment(p.reservation); err != nil {
		return nil, err
	}
	owned, err := metadata.Take(charge)
	if err != nil {
		return nil, err
	}
	var borrow resourcev4.Reference
	if planBorrow == (resourcev4.Reference{}) {
		borrow, err = p.reservation.Borrow()
	} else {
		borrow, err = planBorrow.TakeBorrow()
	}
	if err != nil {
		owned.Release()
		return nil, err
	}
	d := &NotificationDispatch{plan: p, routes: routes, root: c.Root, owner: c.Owner, clock: c.Clock, accountCount: len(c.Accounts), methods: make([]notificationMethod, len(c.Methods)), runtimeBytes: c.RuntimeBytes, deliveryRuntimeBytes: c.DeliveryRuntimeBytes, waitMS: c.WaitMS, cleanupMS: c.CleanupMS, reservation: owned, planBorrow: borrow, done: make(chan struct{})}
	copy(d.accounts[:], c.Accounts)
	for i, m := range c.Methods {
		policy, err := routes.RegisteredMethodPolicy(m.Method)
		if err != nil || policy.Shape != 2 || (policy.Semantics == 1) != (m.ExecutionHandler != nil) || m.WorkClass == ApplicationResident && p.executor.config.ResidentRunning == 0 {
			borrow.Release()
			owned.Release()
			return nil, cryptov4.ErrConfiguration
		}
		policy.Namespace = strings.Clone(policy.Namespace)
		d.methods[i] = notificationMethod{method: m, policy: policy}
	}
	if c.ExecutionSlots != 0 {
		if registryBorrow == (resourcev4.Reference{}) {
			d.registryBorrow, err = c.ExecutionRegistry.Borrow(owned)
		} else {
			d.registryBorrow, err = registryBorrow.TakeBorrow()
		}
		if err != nil {
			borrow.Release()
			owned.Release()
			return nil, err
		}
		d.executionRegistry = c.ExecutionRegistry
		d.executions = make([]*notificationExecution, c.ExecutionSlots)
	}
	p.registrationPreparing = true
	p.mu.Unlock()
	for i, method := range c.Methods {
		d.methods[i].method.services, err = c.dependencyPreparation.take(notificationDependencyAdmission, i, method.Dependencies, owned)
		d.methods[i].method.Dependencies = nil
		if err != nil {
			break
		}
	}
	p.mu.Lock()
	p.registrationPreparing = false
	if err == nil && (p.closed || p.claimed || p.notifications != nil) {
		err = cryptov4.ErrTransition
	}
	if err != nil {
		for _, installed := range d.methods {
			installed.method.services.close()
		}
		d.registryBorrow.Release()
		borrow.Release()
		owned.Release()
		return nil, err
	}
	installed := false
	defer func() {
		if !installed {
			for _, method := range d.methods {
				method.method.services.close()
			}
		}
	}()
	for _, method := range d.methods {
		if method.policy.Semantics != 1 || method.policy.ExecutionMode != 1 {
			continue
		}
		provider := p.services
		if provider == nil || provider.durableWake == nil {
			d.registryBorrow.Release()
			borrow.Release()
			owned.Release()
			return nil, cryptov4.ErrConfiguration
		}
		provider.mu.Lock()
		if provider.closed || provider.durableNotifications != nil {
			provider.mu.Unlock()
			d.registryBorrow.Release()
			borrow.Release()
			owned.Release()
			return nil, cryptov4.ErrConfiguration
		}
		provider.durableNotifications = d
		d.durableProvider = provider
		provider.mu.Unlock()
		break
	}
	p.notifications = d
	p.lease.mu.Lock()
	p.lease.notifications = d
	p.lease.mu.Unlock()
	installed = true
	return d, nil
}

func (l *ApplicationLease) SetNotificationAccess(namespace string, typeID uint32, allowed bool) error {
	if l == nil {
		return ErrApplicationAuthorization
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.reserved || l.revoked || l.notifications == nil {
		return ErrApplicationAuthorization
	}
	d := l.notifications
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return ErrApplicationAuthorization
	}
	for i := range d.methods {
		m := &d.methods[i]
		if m.policy.Namespace == namespace && m.policy.Type == typeID {
			m.allowed = allowed
			return nil
		}
	}
	return ErrApplicationAuthorization
}

// Lock order is original endpoint -> lease -> notification gate. No application
// callback executes in the action; Close and revocation share these gates.
func (d *NotificationDispatch) withAuthority(method uint32, action func(notificationMethod) error) error {
	return d.withAuthoritySample(method, func(m notificationMethod, _ timev4.Sample) error { return action(m) })
}

func (d *NotificationDispatch) withAuthoritySample(method uint32, action func(notificationMethod, timev4.Sample) error) error {
	d.mu.Lock()
	p := d.plan
	d.mu.Unlock()
	if p == nil {
		return rpcv4.ErrClosed
	}
	l, a, err := p.queryAuthorization()
	if err != nil {
		return err
	}
	return a.WithCurrentAuthorizationSample(func(sample timev4.Sample) error {
		l.mu.Lock()
		defer l.mu.Unlock()
		if l.revoked || l.authorization != a {
			return ErrApplicationAuthorization
		}
		d.mu.Lock()
		defer d.mu.Unlock()
		if d.closed || !d.activated {
			return rpcv4.ErrClosed
		}
		for _, m := range d.methods {
			if m.method.Method == method && m.allowed {
				return action(m, sample)
			}
		}
		return ErrApplicationAuthorization
	})
}

func (d *NotificationDispatch) reserveLocked(charges []resourcev4.Vector, refs []resourcev4.Reference) error {
	if len(charges) != len(refs) || len(charges) > 3 || d.serial == math.MaxUint64 {
		return rpcv4.ErrCapacity
	}
	d.serial++
	var requests [3]resourcev4.Request
	var identity [73]byte
	copy(identity[:32], "flowersec.notification.dispatch")
	copy(identity[32:48], d.owner.Instance[:])
	copy(identity[48:64], d.owner.Backing[:])
	binary.BigEndian.PutUint64(identity[64:72], d.serial)
	for i, c := range charges {
		identity[72] = byte(i)
		h := sha256.Sum256(identity[:])
		owner := d.owner
		copy(owner.Instance[:], h[:16])
		copy(owner.Backing[:], h[16:])
		requests[i] = resourcev4.Request{Owner: owner, Charge: c, Accounts: d.accounts[:d.accountCount]}
	}
	return d.root.ReserveBatch(requests[:len(charges)], refs)
}

func (d *NotificationDispatch) Subscribe(method uint32, policy NotificationPendingPolicy, observer NotificationObserver) (*NotificationSubscription, error) {
	if d == nil || policy > NotificationLatestPending || observer.Decode == nil || observer.Handle == nil {
		return nil, cryptov4.ErrConfiguration
	}
	// Validate the bounded declaration shape without joining a client gate.
	// Capacity qualification follows the reserved construction token, so Close
	// and authorization can still observe and retire an in-progress binding.
	_, err := serviceDependenciesChargeFor(observer.Dependencies, false)
	if err != nil {
		return nil, err
	}
	var subscription *NotificationSubscription
	var token *notificationToken
	err = d.withAuthority(method, func(m notificationMethod) error {
		if policy == NotificationLatestPending && m.policy.Semantics != 0 {
			return cryptov4.ErrConfiguration
		}
		count, index := 0, -1
		for i, t := range d.tokens {
			if t == nil {
				if index < 0 {
					index = i
				}
				continue
			}
			if t.method.method.Method == method {
				count++
			}
		}
		if index < 0 || count >= 32 {
			return rpcv4.ErrCapacity
		}
		var charges [2]resourcev4.Vector
		var err error
		charges[0], err = (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(notificationToken{})), resourcev4.Items: 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: d.runtimeBytes})
		if err != nil {
			return err
		}
		charges[1], err = (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(NotificationSubscription{})) + uint64(unsafe.Sizeof(timev4.Window{})), resourcev4.Items: 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: d.runtimeBytes})
		if err != nil {
			return err
		}
		var refs [2]resourcev4.Reference
		if err = d.reserveLocked(charges[:], refs[:]); err != nil {
			return err
		}
		s := &NotificationSubscription{reservation: refs[1], root: d.root, owner: d.owner, accountCount: d.accountCount, clock: d.clock, waitMS: d.waitMS, runtimeBytes: d.runtimeBytes, identity: d.serial, done: make(chan struct{}), closing: make(chan struct{})}
		copy(s.accounts[:], d.accounts[:])
		t := &notificationToken{dispatch: d, subscription: s, method: m, policy: policy, reservation: refs[0], preparing: true}
		s.token = t
		d.tokens[index] = t
		subscription, token = s, t
		return nil
	})
	if err != nil {
		return nil, err
	}
	// The reserved token pins its original slot and dispatcher during local
	// dependency construction. No input or callback can enter it yet.
	dependencyCharge, err := serviceDependenciesCharge(observer.Dependencies)
	var dependencyBacking resourcev4.Reference
	if err == nil && dependencyCharge != (resourcev4.Vector{}) {
		err = d.withAuthority(method, func(notificationMethod) error {
			if token.closed || !token.preparing {
				return rpcv4.ErrClosed
			}
			var refs [1]resourcev4.Reference
			if err := d.reserveLocked([]resourcev4.Vector{dependencyCharge}, refs[:]); err != nil {
				return err
			}
			dependencyBacking = refs[0]
			return nil
		})
	}
	defer func() { dependencyBacking.Release() }()
	var services *invocationServices
	if err == nil {
		services, err = newInvocationServices(observer.Dependencies, dependencyBacking)
	}
	if err == nil {
		err = d.withAuthority(method, func(notificationMethod) error {
			if token.closed || !token.preparing {
				return rpcv4.ErrClosed
			}
			observer.Dependencies = nil
			token.services, token.observer, token.preparing = services, observer, false
			token.dependencies, dependencyBacking = dependencyBacking, resourcev4.Reference{}
			return nil
		})
	}
	if err != nil {
		services.close()
		d.mu.Lock()
		token.preparing = false
		if token.closed {
			token.advanceLocked(timev4.Sample{})
		} else {
			// This token never published a successful subscription or admitted
			// a callback. Retire it without a caller-visible cleanup window.
			token.closeLocked(timev4.Mark{}, timev4.ErrUnavailable)
		}
		d.cleanupLocked()
		d.mu.Unlock()
		_ = subscription.Release()
		return nil, err
	}
	return subscription, nil
}

func (t *notificationToken) gapLocked(reason string) {
	s := t.subscription
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.status.KnownDropped < math.MaxUint64 {
		s.status.KnownDropped++
	}
	s.status.LastGap = reason
}

func (t *notificationToken) enqueueLocked(deadline *timev4.Deadline, payload []byte, sample timev4.Sample) error {
	d := t.dispatch
	if t.closed || t.serial == math.MaxUint64 {
		return rpcv4.ErrClosed
	}
	pending, index := 0, -1
	for i, j := range t.jobs {
		if j == nil {
			if index < 0 {
				index = i
			}
			continue
		}
		if !j.entered {
			pending++
		}
	}
	if pending >= 16 || index < 0 {
		return rpcv4.ErrCapacity
	}
	metadata, err := (resourcev4.Vector{resourcev4.SDKBytes: applicationContextBytes() + uint64(unsafe.Sizeof(notificationDelivery{})) + uint64(unsafe.Sizeof(notificationInvocation{})) + uint64(unsafe.Sizeof(timev4.Deadline{})) + uint64(len(payload)), resourcev4.Items: 2}).Add(resourcev4.Vector{resourcev4.SDKBytes: d.deliveryRuntimeBytes})
	if err != nil {
		return err
	}
	var refs [2]resourcev4.Reference
	if err = d.reserveLocked([]resourcev4.Vector{metadata, d.plan.executor.TaskCharge()}, refs[:]); err != nil {
		return err
	}
	deadline, err = deadline.ForkAt(deadline.Cap(), sample)
	if err != nil {
		for _, ref := range refs {
			ref.Release()
		}
		return err
	}
	// The new input/task vector and physical copy exist before any replacement
	// revokes an old pending item. Old started trampolines retain their own charge.
	copyBytes := append([]byte(nil), payload...)
	t.serial++
	ctx, cancel := context.WithCancelCause(context.Background())
	ctx = context.WithValue(ctx, notificationInvocationKey{}, &notificationInvocation{token: t})
	j := &notificationDelivery{token: t, serial: t.serial, payload: copyBytes, deadline: deadline, ctx: ctx, cancel: cancel, reservation: refs[0], taskReservation: refs[1]}
	if t.policy == NotificationLatestPending {
		for _, old := range t.jobs {
			if old != nil && !old.entered && !old.canceled {
				old.canceled = true
				old.cancel(rpcv4.ErrClosed)
				if old.queued != nil {
					old.queued.Cancel()
				}
				t.gapLocked("coalesced_pending")
			}
		}
	}
	t.jobs[index] = j
	t.advanceLocked(sample)
	return nil
}

func (d *NotificationDispatch) Admit(receiver *rpcv4.NotifyReceiver) (err error) {
	if d == nil || receiver == nil {
		return rpcv4.ErrOwner
	}
	d.mu.Lock()
	attached := !d.closed && !d.draining.Load() && (d.channels[0] == receiver || d.channels[1] == receiver)
	busy := d.admitting
	if attached && !busy {
		d.admitting = true
	}
	d.mu.Unlock()
	if !attached {
		return rpcv4.ErrAssociation
	}
	if busy {
		return rpcv4.ErrCapacity
	}
	// The one admission gate preserves each reader's FIFO even if another SDK
	// coordinator calls Admit concurrently. It never holds application work.
	defer func() { d.mu.Lock(); d.admitting = false; d.cleanupLocked(); d.mu.Unlock() }()
	m, err := receiver.Take()
	if err != nil {
		return err
	}
	adopted := false
	defer func() {
		if !adopted {
			m.Close()
		}
	}()
	defer func() {
		if err == nil {
			return
		}
		reason := serviceRefusal(err)
		switch {
		case errors.Is(err, rpcv4.ErrExecutionConflict):
			reason = "operation_conflict"
		case errors.Is(err, rpcv4.ErrExecutionExpired):
			reason = "operation_admission_expired"
		case errors.Is(err, rpcv4.ErrMethod), errors.Is(err, rpcv4.ErrExecutionUnsupported):
			reason = "method_unavailable"
		}
		receiver.RecordAdmissionRejection(reason)
	}()
	method, policy, err := m.OriginalMethod()
	if err != nil {
		return err
	}
	if policy.Semantics == 1 {
		adopted, err = d.admitExecution(m, method, policy)
		return err
	}
	return d.withAuthoritySample(method, func(local notificationMethod, sample timev4.Sample) error {
		return m.FanoutObservationAt(sample, func(method uint32, policy protocolv4.ServiceContractPolicy, deadline *timev4.Deadline, payload []byte) error {
			if local.policy.Namespace != policy.Namespace || local.policy.Type != policy.Type || local.policy.Semantics != 0 {
				return rpcv4.ErrMethod
			}
			if err := deadline.CheckAt(sample); err != nil {
				return err
			}
			for _, t := range d.tokens {
				if t != nil && !t.closed && !t.preparing && t.method.method.Method == method {
					if err := t.enqueueLocked(deadline, payload, sample); err != nil {
						t.gapLocked("dropped_budget")
					}
				}
			}
			return nil
		})
	})
}

func (t *notificationToken) advanceLocked(sample timev4.Sample) {
	if t.preparing {
		return
	}
	d := t.dispatch
	for index, j := range t.jobs {
		if j == nil {
			continue
		}
		if !j.canceled && (t.closed || j.deadline.CheckAt(sample) != nil) {
			j.canceled = true
			j.cancel(rpcv4.ErrClosed)
			if j.queued != nil {
				j.queued.Cancel()
			}
			if !j.entered {
				t.gapLocked("delivery_expired")
			}
		}
		done := j.canceled && j.queued == nil
		if j.queued != nil {
			select {
			case <-j.queued.Done():
				done = true
			default:
			}
		}
		if !done {
			continue
		}
		if t.active == j {
			t.active = nil
		}
		j.cancel(rpcv4.ErrClosed)
		clear(j.payload)
		j.payload = nil
		j.reservation.Release()
		j.taskReservation.Release()
		j.reservation, j.taskReservation = resourcev4.Reference{}, resourcev4.Reference{}
		j.ctx, j.cancel, j.deadline, j.queued, j.token = nil, nil, nil, nil, nil
		t.jobs[index] = nil
	}
	if !t.closed && t.active == nil && t.services == nil {
		t.queueNextLocked()
	}
	s := t.subscription
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status.Pending, s.status.Running = 0, 0
	for _, j := range t.jobs {
		if j != nil {
			if j.entered {
				s.status.Running++
			} else {
				s.status.Pending++
			}
		}
	}
	if t.closed && t.closingSamples == 0 && s.status.Pending == 0 && s.status.Running == 0 {
		s.status.CleanupComplete = true
		s.token = nil
		for i, current := range d.tokens {
			if current == t {
				d.tokens[i] = nil
				break
			}
		}
		t.services.close()
		t.services = nil
		t.dependencies.Release()
		t.dependencies = resourcev4.Reference{}
		t.reservation.Release()
		t.reservation = resourcev4.Reference{}
		t.observer = NotificationObserver{}
		t.method = notificationMethod{}
		t.dispatch = nil
		t.subscription = nil
		close(s.done)
	}
}

func (t *notificationToken) queueNextLocked() {
	d := t.dispatch
	if !t.closed && !t.preparing && t.active == nil {
		var next *notificationDelivery
		for _, j := range t.jobs {
			if j != nil && !j.canceled && (next == nil || j.serial < next.serial) {
				next = j
			}
		}
		if next != nil {
			q, err := d.plan.executor.queueApplication(d.plan.applicationGroup, t.method.method.WorkClass, next.taskReservation, next.reservation, next.run)
			if err != nil {
				next.canceled = true
				next.cancel(err)
				t.gapLocked("dropped_budget")
			} else {
				next.queued = q
				t.active = next
			}
		}
	}
}

func (j *notificationDelivery) run() {
	t := j.token
	d := t.dispatch
	reason := "handler_error"
	returned := false
	defer func() {
		if recover() != nil || !returned {
			reason = "handler_error"
		}
		d.mu.Lock()
		defer d.mu.Unlock()
		j.returned = true
		if reason != "" {
			t.gapLocked(reason)
		}
	}()
	err := d.withAuthoritySample(t.method.method.Method, func(_ notificationMethod, sample timev4.Sample) error {
		if t.closed || j.canceled || j.ctx.Err() != nil {
			return rpcv4.ErrClosed
		}
		if err := j.deadline.CheckAt(sample); err != nil {
			return err
		}
		j.entered = true
		t.subscription.mu.Lock()
		t.subscription.status.Running++
		if t.subscription.status.Pending != 0 {
			t.subscription.status.Pending--
		}
		t.subscription.mu.Unlock()
		return nil
	})
	if err != nil {
		reason = "delivery_unavailable"
		returned = true
		return
	}
	callCtx, exit, err := enterApplicationContext(j.ctx, d.plan.executor, ordinaryApplicationLane, t.method.method.WorkClass, j.reservation, nil)
	if err != nil {
		reason, returned = "delivery_unavailable", true
		return
	}
	defer exit()
	if err := attachInvocationServices(callCtx, t.services); err != nil {
		reason, returned = "dependency_unavailable", true
		return
	}
	value, err := t.observer.Decode(callCtx, j.payload)
	if err != nil {
		reason = "decode_error"
		returned = true
		return
	}
	if err = d.withAuthoritySample(t.method.method.Method, func(_ notificationMethod, sample timev4.Sample) error {
		if t.closed || j.canceled || j.ctx.Err() != nil {
			return rpcv4.ErrClosed
		}
		return j.deadline.CheckAt(sample)
	}); err != nil {
		reason = "delivery_unavailable"
		returned = true
		return
	}
	if err = t.observer.Handle(callCtx, value); err != nil {
		reason = "handler_error"
	} else {
		reason = ""
	}
	returned = true
}

func (d *NotificationDispatch) AttachChannel(receiver *rpcv4.NotifyReceiver) error {
	if d == nil || receiver == nil {
		return rpcv4.ErrOwner
	}
	d.mu.Lock()
	routes := d.routes
	d.mu.Unlock()
	if !receiver.UsesRoutes(routes) {
		return rpcv4.ErrAssociation
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return rpcv4.ErrClosed
	}
	for _, r := range d.channels {
		if r == receiver {
			return rpcv4.ErrAssociation
		}
	}
	for i, r := range d.channels {
		if r == nil {
			d.channels[i] = receiver
			return nil
		}
	}
	return rpcv4.ErrCapacity
}

func (d *NotificationDispatch) DetachChannel(receiver *rpcv4.NotifyReceiver) {
	if d == nil || receiver == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	for i, r := range d.channels {
		if r == receiver {
			d.channels[i] = nil
		}
	}
}
func (d *NotificationDispatch) activate() {
	d.mu.Lock()
	if !d.closed {
		d.activated = true
	}
	d.mu.Unlock()
}

func (d *NotificationDispatch) Advance() {
	if d == nil {
		return
	}
	d.mu.Lock()
	if d.cleaned || d.advancing {
		d.mu.Unlock()
		return
	}
	d.advancing = true
	channels, accepting := d.channels, d.activated && !d.closed
	d.mu.Unlock()
	if accepting {
		for _, r := range channels {
			if r != nil {
				for range 4 {
					if d.Admit(r) != nil {
						break
					}
				}
			}
		}
	}
	d.advanceExecutions()
	// Each current permission check precedes its token's finite cancellation gate.
	for index := range d.tokens {
		d.mu.Lock()
		t := d.tokens[index]
		var method uint32
		if t != nil {
			method = t.method.method.Method
		}
		d.mu.Unlock()
		if t == nil {
			continue
		}
		var sample timev4.Sample
		err := d.withAuthoritySample(method, func(_ notificationMethod, now timev4.Sample) error { sample = now; return nil })
		var dependencyErr error
		d.mu.Lock()
		var services *invocationServices
		if d.tokens[index] == t {
			services = t.services
		}
		d.mu.Unlock()
		if services != nil && err == nil {
			dependencyErr = services.requiredReady(context.Background())
		}
		d.mu.Lock()
		if d.tokens[index] == t {
			if err != nil {
				for _, j := range t.jobs {
					if j != nil {
						j.canceled = true
						j.cancel(err)
						if j.queued != nil {
							j.queued.Cancel()
						}
					}
				}
			}
			t.advanceLocked(sample)
			if d.tokens[index] == t && dependencyErr == nil {
				t.queueNextLocked()
			}
		}
		d.mu.Unlock()
	}
	d.mu.Lock()
	d.advancing = false
	d.cleanupLocked()
	d.mu.Unlock()
}

// The original close sample precedes this finite gate. It may conservatively
// precede the winning close, but is never replaced by a later wait or Close.
func (t *notificationToken) closeLocked(mark timev4.Mark, sampleErr error) {
	if !t.closed {
		t.closed = true
		t.services.close()
		s := t.subscription
		s.mu.Lock()
		s.status.Closed = true
		s.cleanupError = sampleErr
		if sampleErr == nil {
			s.cleanup, s.cleanupError = timev4.NewWindowAt(s.clock, mark, t.dispatch.cleanupMS)
		}
		close(s.closing)
		s.mu.Unlock()
	}
	t.advanceLocked(timev4.Sample{})
}

func (s *NotificationSubscription) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	t := s.token
	var d *NotificationDispatch
	if t != nil {
		d = t.dispatch
	}
	s.mu.Unlock()
	if d != nil {
		d.closeSelected(t)
	}
}

func (d *NotificationDispatch) Close() {
	if d != nil {
		d.closeSelected(nil)
	}
}

// A nil token closes the original dispatch. A token closes only that exact
// subscription. The adapter is a bounded local read and runs outside all owner
// gates; no application callback, waiter or replacement task is started here.
func (d *NotificationDispatch) closeSelected(token *notificationToken) {
	d.mu.Lock()
	if d.cleaned {
		d.mu.Unlock()
		return
	}
	if token == nil {
		if d.closed {
			d.mu.Unlock()
			return
		}
	} else {
		found := false
		for _, current := range d.tokens {
			found = found || current == token
		}
		if !found || token.closed {
			d.mu.Unlock()
			return
		}
	}
	if d.closingSamples == math.MaxUint32 || token != nil && token.closingSamples == math.MaxUint32 {
		d.closeSelectedLocked(token, timev4.Mark{}, timev4.ErrUnavailable)
		d.cleanupLocked()
		d.mu.Unlock()
		return
	}
	d.closingSamples++
	if token != nil {
		token.closingSamples++
	}
	clock := d.clock
	d.mu.Unlock()
	var mark timev4.Mark
	var sampleErr error = timev4.ErrUnavailable
	defer func() {
		d.mu.Lock()
		defer d.mu.Unlock()
		d.closingSamples--
		if token != nil {
			token.closingSamples--
		}
		// The real sampling tail has exited, even on panic or Goexit. A
		// second Close may already have won; its original deadline survives.
		d.closeSelectedLocked(token, mark, sampleErr)
		d.cleanupLocked()
	}()
	mark, sampleErr = clock.Monotonic()
}

func (d *NotificationDispatch) closeSelectedLocked(token *notificationToken, mark timev4.Mark, sampleErr error) {
	if token != nil {
		token.closeLocked(mark, sampleErr)
		return
	}
	d.closed = true
	for _, method := range d.methods {
		method.method.services.close()
	}
	for _, execution := range d.executions {
		if execution != nil && execution.started {
			execution.stopLocked(rpcv4.ErrClosed)
		}
	}
	for _, current := range d.tokens {
		if current != nil {
			current.closeLocked(mark, sampleErr)
		}
	}
}
func (d *NotificationDispatch) cleanupLocked() {
	if !d.closed || d.cleaned || d.advancing || d.admitting || d.closingSamples != 0 {
		return
	}
	for _, t := range d.tokens {
		if t != nil {
			return
		}
	}
	for _, execution := range d.executions {
		if execution != nil {
			return
		}
	}
	if provider := d.durableProvider; provider != nil {
		provider.mu.Lock()
		provider.durableNotifications = nil
		provider.signalDurable()
		provider.mu.Unlock()
		d.durableProvider = nil
	}
	d.executions = nil
	d.executionRegistry = nil
	d.registryBorrow.Release()
	d.registryBorrow = resourcev4.Reference{}
	for _, method := range d.methods {
		method.method.services.close()
	}
	d.methods = nil
	clear(d.channels[:])
	d.plan = nil
	d.routes = nil
	d.root = nil
	d.clock = nil
	clear(d.accounts[:])
	d.reservation.Release()
	d.planBorrow.Release()
	d.reservation, d.planBorrow = resourcev4.Reference{}, resourcev4.Reference{}
	d.cleaned = true
	close(d.done)
}

func (s *NotificationSubscription) Status() NotificationStatus {
	if s == nil {
		return NotificationStatus{Closed: true, CleanupComplete: true}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.status
}

// WaitClosed is passive: a timeout never closes the token or changes its final
// cleanup outcome. The original callback context rejects self/ancestor waits
// immediately; returning cleanup_incomplete does not release the callback.
func (s *NotificationSubscription) WaitClosed(ctx context.Context) error {
	if s == nil || ctx == nil {
		return cryptov4.ErrConfiguration
	}
	s.mu.Lock()
	if s.status.CleanupComplete {
		s.mu.Unlock()
		return nil
	}
	if s.waiters >= 4 || s.root == nil || s.waitSerial == math.MaxUint64 {
		s.mu.Unlock()
		return rpcv4.ErrCapacity
	}
	charge, err := (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(time.Timer{})) + uint64(unsafe.Sizeof(timev4.Window{})), resourcev4.Items: 1, resourcev4.Timers: 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: s.runtimeBytes})
	if err != nil {
		s.mu.Unlock()
		return err
	}
	s.waitSerial++
	var identity [80]byte
	copy(identity[:32], "flowersec.notification.wait")
	copy(identity[32:48], s.owner.Instance[:])
	copy(identity[48:64], s.owner.Backing[:])
	binary.BigEndian.PutUint64(identity[64:72], s.identity)
	binary.BigEndian.PutUint64(identity[72:], s.waitSerial)
	hash := sha256.Sum256(identity[:])
	owner := s.owner
	copy(owner.Instance[:], hash[:16])
	copy(owner.Backing[:], hash[16:])
	ref, err := s.root.Reserve(owner, charge, s.accounts[:s.accountCount]...)
	if err != nil {
		s.mu.Unlock()
		return err
	}
	s.waiters++
	clock, duration := s.clock, s.waitMS
	done, closing := s.done, s.closing
	s.mu.Unlock()
	defer func() { ref.Release(); s.mu.Lock(); s.waiters--; s.mu.Unlock() }()
	// The admitted waiter pins its original handle before any opaque context
	// or clock call. Release cannot clear its clock or refund its backing.
	window, err := timev4.NewWindow(clock, duration)
	if err != nil {
		return err
	}
	invocation, _ := ctx.Value(notificationInvocationKey{}).(*notificationInvocation)
	ctxDone := ctx.Done()
	s.mu.Lock()
	if s.status.CleanupComplete {
		s.mu.Unlock()
		return nil
	}
	for current := invocation; current != nil; current = current.parent {
		if current.token == s.token {
			s.mu.Unlock()
			return ErrNotificationCleanupIncomplete
		}
	}
	s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	var timer *time.Timer
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	for {
		s.mu.Lock()
		if s.status.CleanupComplete {
			s.mu.Unlock()
			return nil
		}
		closed, cleanup, cleanupErr := s.status.Closed, s.cleanup, s.cleanupError
		s.mu.Unlock()
		left, err := window.RemainingMS()
		if closed {
			if cleanupErr != nil {
				err = cleanupErr
			} else if remaining, e := cleanup.RemainingMS(); e != nil {
				err = e
			} else {
				left = min(left, remaining)
			}
			closing = nil
		}
		// Sampling may overlap Close or actual callback cleanup. A newly
		// closed token uses its one original cleanup window on the next pass;
		// the passive wait's own window is never replaced or extended.
		s.mu.Lock()
		complete, newlyClosed := s.status.CleanupComplete, !closed && s.status.Closed
		s.mu.Unlock()
		if complete {
			return nil
		}
		if newlyClosed {
			continue
		}
		if err != nil {
			return ErrNotificationCleanupIncomplete
		}
		if timer == nil {
			timer = time.NewTimer(time.Duration(left) * time.Millisecond)
		} else {
			timer.Reset(time.Duration(left) * time.Millisecond)
		}
		select {
		case <-done:
			return nil
		case <-closing:
			timer.Stop()
		case <-ctxDone:
			return ctx.Err()
		case <-timer.C:
		}
	}
}

// Release destroys only a fully detached internal handle. A language binding
// must not use it while the application still retains the compact status.
func (s *NotificationSubscription) Release() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.status.CleanupComplete || s.waiters != 0 {
		return ErrNotificationCleanupIncomplete
	}
	s.reservation.Release()
	s.reservation = resourcev4.Reference{}
	s.root, s.clock, s.cleanup = nil, nil, nil
	clear(s.accounts[:])
	return nil
}
