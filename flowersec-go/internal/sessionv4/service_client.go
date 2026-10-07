package sessionv4

import (
	"context"
	"math"
	"sync"
	"time"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// UnaryServiceClient owns one static service binding's local lifetime over a
// borrowed Session or Controller. Existing Sessions own routes, channels and
// publication. Returned operations are independent of the convenience scopes.
// Explicit contract acquisition uses the original fixed query owner. Ordinary
// preparation and calls never query or acquire a connection.
type UnaryServiceClient struct {
	mu                       sync.Mutex
	environment              *Environment
	services                 *RPCServices
	notificationExecutor     *ApplicationExecutor
	source                   controllerDispatch
	clock                    *timev4.Clock
	root                     *resourcev4.Root
	namespace                string
	methods                  []boundUnaryMethod
	methodCount              uint16
	metadata, shared         resourcev4.Reference
	dependencyFloor          *resourcev4.BorrowPool
	calls                    [32]serviceClientCall
	active                   uint32
	callHead                 *serviceClientCall
	advancing                bool
	waiters                  uint8
	visits                   uint32
	closed, settled, cleaned bool
	done                     chan struct{}
	remoteContracts          bool
	remoteVisits             uint8
	contractVisits           [4]serviceContractVisit
	managedRenewal           bool
	renewalPublished         bool
	renewalPolicy            ContractRenewalPolicy
}

type serviceClientCall struct {
	previous, next *serviceClientCall
	workload       *unaryWorkloadSlot
	operation      *UnaryOperation
	session        *EnvironmentSession
	cancel         context.CancelFunc
	cancellation   *serviceCallCancellation
	active         bool
	running        bool
	visiting       bool
	initializer    bool
}

func serviceClientCharge(runtimeBytes uint64, methods int) (resourcev4.Vector, error) {
	if methods < 1 || methods > 256 || runtimeBytes == 0 || runtimeBytes > math.MaxUint64/(81+5*uint64(methods)) {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	// Every generic call position includes its actual cancellation context,
	// observer task and qualified runtime overhead before Bind can publish.
	charge := resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(UnaryServiceClient{})) + 36*uint64(unsafe.Sizeof(serviceCallCancellation{})) + 4*uint64(unsafe.Sizeof(time.Timer{})) + 128 + uint64(methods)*(uint64(unsafe.Sizeof(boundUnaryMethod{}))+uint64(unsafe.Sizeof(timev4.Deadline{}))+128), resourcev4.Items: 41 + 2*uint64(methods), resourcev4.Tasks: 36, resourcev4.Timers: 4, resourcev4.WorkSlots: 72 + 5*uint64(methods)}
	dependencyCharge, err := resourcev4.BorrowPoolCharge(dependencyFloorCapacity)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	charge, err = charge.Add(dependencyCharge)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	return charge.Add(resourcev4.Vector{resourcev4.SDKBytes: (81 + 5*uint64(methods)) * runtimeBytes})
}

func (s *EnvironmentSession) BindUnaryService(method UnaryMethodDefinition) (*UnaryServiceClient, error) {
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
	return r.bindUnaryService(method)
}

func (c *UnaryServiceClient) enter(ctx context.Context, methodType uint32, shape uint8, input []byte, options rpcv4.UnaryPreparation) (*serviceClientCall, context.Context, *RPCServices, ServiceMethod, error) {
	if c == nil || ctx == nil {
		return nil, nil, nil, ServiceMethod{}, cryptov4.ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, nil, ServiceMethod{}, err
	}
	if p := initializerPlanForApplication(ctx); p != nil {
		return c.enterInitializer(ctx, p, methodType, shape, input, options)
	}
	c.mu.Lock()
	locked := true
	defer func() {
		if locked {
			c.mu.Unlock()
		}
	}()
	if c.closed || c.cleaned {
		return nil, nil, nil, ServiceMethod{}, cryptov4.ErrClosed
	}
	if err := c.metadata.Check(); err != nil {
		return nil, nil, nil, ServiceMethod{}, err
	}
	method, err := c.methodLocked(methodType)
	if err != nil {
		return nil, nil, nil, ServiceMethod{}, err
	}
	if method.definition.Shape != shape {
		return nil, nil, nil, ServiceMethod{}, rpcv4.ErrMethod
	}
	c.promoteCandidateContractLocked(method)
	if !method.installed {
		return nil, nil, nil, ServiceMethod{}, cryptov4.ErrNotReady
	}
	definition, services, controller := method.definition, c.services, c.source.controller
	selectedWorkload := definition.Method.workload
	if controller == nil {
		if err := c.workloadReadyLocked(method, services); err != nil {
			return nil, nil, nil, ServiceMethod{}, err
		}
	}
	slot, err := c.reserveCallScopeLocked(definition, input, options)
	if err != nil {
		return nil, nil, nil, ServiceMethod{}, err
	}
	slot.running = true
	transferred := false
	defer func() {
		if !transferred {
			if locked {
				c.mu.Unlock()
				locked = false
			}
			c.leave(slot)
		}
	}()
	if c.remoteContracts {
		definition.Method.bindingOffer = method.offer
	}
	// The original call slot retains the binding and workload while opaque
	// context setup runs. Close can fence it without waiting for parent code;
	// panic and Goexit return that same slot through the unconditional defer.
	c.mu.Unlock()
	locked = false
	child, err := c.setupCallContext(slot, ctx)
	if err != nil {
		return nil, nil, nil, ServiceMethod{}, err
	}
	c.mu.Lock()
	locked = true
	if err := child.Err(); err != nil {
		return nil, nil, nil, ServiceMethod{}, err
	}
	if c.closed {
		return nil, nil, nil, ServiceMethod{}, cryptov4.ErrClosed
	}
	if controller == nil {
		transferred = true
		return slot, child, services, definition, nil
	}
	c.mu.Unlock()
	locked = false
	session, services, err := c.captureControllerSource(controller)
	if err != nil {
		return nil, nil, nil, ServiceMethod{}, err
	}
	c.mu.Lock()
	locked = true
	if c.closed || child.Err() != nil {
		err = child.Err()
		if err == nil {
			err = cryptov4.ErrClosed
		}
	} else {
		c.promoteCandidateContractLocked(method)
		definition = method.definition
		if c.remoteContracts {
			definition.Method.bindingOffer = method.offer
		}
		err = c.workloadReadyLocked(method, services)
		// A switch during source capture must take the new Session's actual
		// call position. The old position stays charged until this transfer.
		if err == nil && selectedWorkload != definition.Method.workload {
			var next *serviceClientCall
			next, err = c.reserveCallScopeLocked(definition, input, options)
			if err == nil {
				next.cancel, next.cancellation, next.running = slot.cancel, slot.cancellation, true
				slot.cancel, slot.cancellation = nil, nil
				c.releaseCallScopeLocked(slot)
				slot = next
			}
		}
		slot.session = session
	}
	c.mu.Unlock()
	locked = false
	if err != nil {
		return nil, nil, nil, ServiceMethod{}, err
	}
	transferred = true
	return slot, child, services, definition, nil
}

// leave marks actual caller/codec exit. A submitted Call retains its slot until
// the original operation's network, result and decoder cleanup really finishes.
func (c *UnaryServiceClient) leave(slot *serviceClientCall) {
	c.mu.Lock()
	slot.running = false
	if slot.cancel != nil {
		slot.cancel()
	}
	if slot.operation == nil && !slot.visiting && slot.cancellation.complete() {
		c.releaseCallScopeLocked(slot)
	}
	e := c.environment
	c.mu.Unlock()
	if e != nil {
		e.signalMaterials()
	}
}

func (c *UnaryServiceClient) prepare(ctx context.Context, methodType uint32, input []byte, options rpcv4.UnaryPreparation, convenience bool) (*UnaryOperation, *serviceClientCall, context.Context, error) {
	slot, child, r, method, err := c.enter(ctx, methodType, 0, input, options)
	if err != nil {
		return nil, nil, nil, err
	}
	returned := false
	defer func() {
		if !returned {
			c.leave(slot)
		}
	}()
	op, err := c.prepareUnaryAt(slot, child, r, method.Method, input, options)
	if err != nil {
		return nil, nil, nil, err
	}
	c.mu.Lock()
	if c.closed || child.Err() != nil {
		c.mu.Unlock()
		op.Close()
		err := child.Err()
		if err == nil {
			err = cryptov4.ErrClosed
		}
		if convenience {
			return op, nil, nil, err
		}
		return nil, nil, nil, err
	}
	if convenience {
		slot.operation = op
		returned = true
	}
	c.mu.Unlock()
	return op, slot, child, nil
}

func (c *UnaryServiceClient) Prepare(ctx context.Context, input []byte, options rpcv4.UnaryPreparation) (*UnaryOperation, error) {
	op, _, _, err := c.prepare(ctx, 0, input, options, false)
	return op, err
}

func (c *UnaryServiceClient) Call(ctx context.Context, input []byte, options rpcv4.UnaryPreparation) (any, UnaryResultStatus, error) {
	return c.CallMethod(ctx, 0, input, options)
}

func (c *UnaryServiceClient) CallMethod(ctx context.Context, methodType uint32, input []byte, options rpcv4.UnaryPreparation) (value any, status UnaryResultStatus, err error) {
	op, slot, child, err := c.prepare(ctx, methodType, input, options, true)
	if err != nil {
		if op != nil {
			return nil, op.Snapshot().Result, err
		}
		return nil, UnaryResultStatus{}, err
	}
	defer c.leave(slot)
	defer func() {
		op.Close()
		status.CleanupComplete = op.Snapshot().CleanupComplete
		status.Closed = true
	}()
	started := op.Start(child)
	if started.Error != nil {
		return nil, op.Snapshot().Result, started.Error
	}
	value, status, err = op.TakeResult(child)
	// The original result gate already decided a successful value/error
	// handoff. Late cancellation cannot revoke that transferred owned result.
	c.mu.Lock()
	if !status.Delivered && c.closed {
		value, err = nil, cryptov4.ErrClosed
	} else if !status.Delivered && child.Err() != nil {
		value, err = nil, child.Err()
	}
	c.mu.Unlock()
	return value, status, err
}

func (c *UnaryServiceClient) Close() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closeLocked()
}

func (c *UnaryServiceClient) closeLocked() {
	if c.closed {
		return
	}
	c.closed = true
	for slot := c.callHead; slot != nil; slot = slot.next {
		if slot.cancel != nil {
			slot.cancel()
		}
	}
	for j := range c.contractVisits {
		if owner := c.contractVisits[j].cancellation; owner != nil {
			owner.cancel()
		}
	}
	for j := range c.methods {
		c.methods[j].definition.Method.workload.seal()
		c.methods[j].candidateWorkload.workload.seal()
		if c.methods[j].update.renewal {
			// A protected batch may contain methods from other bindings. Its
			// original coordinator closes the shared query only after all
			// participants have relinquished installation rights.
			c.methods[j].update.superseded = true
			continue
		}
		if cancel := c.methods[j].update.cancel; cancel != nil {
			cancel()
		}
		if q := c.methods[j].update.query; q != nil {
			q.Close()
		}
	}
	if c.environment != nil {
		c.environment.signalMaterials()
	}
}

func (c *UnaryServiceClient) advance() bool {
	c.mu.Lock()
	if c.cleaned {
		c.mu.Unlock()
		return true
	}
	if c.advancing {
		c.mu.Unlock()
		return false
	}
	c.advancing = true
	closed := false
	if controller := c.source.controller; controller != nil {
		controller.mu.Lock()
		closed = controller.closed
		controller.mu.Unlock()
	} else if r := c.services; r != nil {
		r.mu.Lock()
		closed = r.closed || r.retired
		r.mu.Unlock()
	}
	if closed {
		c.closeLocked()
	}
	for slot := c.callHead; slot != nil; {
		op := slot.operation
		if op == nil {
			next := slot.next
			if !slot.running && !slot.visiting && slot.cancellation.complete() {
				c.releaseCallScopeLocked(slot)
			}
			slot = next
			continue
		}
		closing := c.closed
		slot.visiting = true
		c.visits++
		c.mu.Unlock()
		// Start may be acquiring the original Environment result position.
		// Never hold the binding/Environment close gate while joining that
		// operation's local lock or advancing its physical cleanup.
		if closing {
			op.Close()
		}
		complete := op.Snapshot().CleanupComplete
		c.mu.Lock()
		c.visits--
		slot.visiting = false
		next := slot.next
		if !slot.running && slot.cancellation.complete() && (slot.operation == nil || slot.operation == op && complete) {
			c.releaseCallScopeLocked(slot)
		}
		slot = next
	}
	c.advancing = false
	defer c.mu.Unlock()
	for j := range c.contractVisits {
		c.settleContractVisitLocked(&c.contractVisits[j])
	}
	queryTail := false
	for j := range c.methods {
		u := &c.methods[j].update
		if u.query != nil {
			select {
			case <-u.query.done:
				u.query = nil
			default:
				queryTail = true
			}
		}
		if u.done != nil && !u.active && u.waiters == 0 && u.query == nil {
			*u = serviceContractUpdate{}
		}
	}
	if !c.closed || c.active != 0 || c.visits != 0 || c.remoteVisits != 0 || queryTail {
		return false
	}
	if !c.settled {
		// Cleanup observers retain only their own metadata borrow. Release
		// completed routes and the borrowed Controller before notifying them;
		// a waiter must not delay the very physical completion it observes.
		for j := range c.methods {
			c.methods[j].route.Release()
			c.methods[j].route = rpcv4.ContractRoute{}
			c.methods[j].canonical, c.methods[j].known = nil, nil
			c.methods[j].dependencyPath = dependencyPathPreparation{}
			c.methods[j].candidateContract = candidateContractSnapshot{}
		}
		c.shared.Release()
		c.shared = resourcev4.Reference{}
		c.source.close()
		c.settled = true
		close(c.done)
	}
	if c.waiters != 0 {
		return false
	}
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
	c.metadata, c.shared = resourcev4.Reference{}, resourcev4.Reference{}
	c.environment, c.services, c.methods = nil, nil, nil
	c.notificationExecutor = nil
	c.clock, c.root = nil, nil
	c.namespace = ""
	c.cleaned = true
	return true
}

func (c *UnaryServiceClient) CleanupStatus() protocolv4.V4CleanupStatus {
	status := protocolv4.V4CleanupStatus{Status: protocolv4.V4CleanupStateComplete, CoreCleanup: protocolv4.V4CoreCleanupComplete}
	if c == nil {
		return status
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.cleaned {
		status.Status, status.CoreCleanup = protocolv4.V4CleanupStatePending, protocolv4.V4CoreCleanupPending
		for slot := c.callHead; slot != nil; slot = slot.next {
			if slot.running {
				status.PendingCallbacks++
			}
		}
	}
	return status
}

func (c *UnaryServiceClient) WaitCleanup(ctx context.Context) error {
	if c == nil || ctx == nil {
		return cryptov4.ErrConfiguration
	}
	c.mu.Lock()
	if c.cleaned || c.settled {
		c.mu.Unlock()
		return nil
	}
	// Waiters observe the precharged channel; they do not create a timer,
	// watcher or cleanup owner, and never hold completion back themselves.
	if c.waiters == 4 {
		c.mu.Unlock()
		return cryptov4.ErrCapacity
	}
	borrow, err := c.metadata.Borrow()
	if err != nil {
		c.mu.Unlock()
		return err
	}
	c.waiters++
	done := c.done
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		c.waiters--
		borrow.Release()
		e := c.environment
		c.mu.Unlock()
		if e != nil {
			e.signalMaterials()
		}
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
