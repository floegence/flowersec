package sessionv4

import (
	"sync"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
)

// sessionHeadroom is the same future admission batch, reserved before Acquire.
// It contains no protocol/spend state. The actual admission consumes these
// references once after comparing its signed geometry with the trusted recipe.
type sessionHeadroom struct {
	dependencies                     rpcDependencyPreparation
	execution                        serviceExecutionPreparation
	source                           sourceReferences
	queries                          *sessionContractQueries
	environmentOrigin, preauthOrigin resourcev4.Reference
	coreBorrows                      [3]resourcev4.Reference
	preauth, sessionSlot             resourcev4.Reference
	rpcReferences                    rpcServicesReferences
	network                          *rpcv4.Network
	serviceFloors                    []streamServiceFloor
	servicePlan                      *StreamHandlerPlan
	serviceGeometry                  streamCallerGeometry
	receivePool                      *ReceivePool
	receiveProtection                [11]*ReceiveProtection
	receiveIndex                     int
	resultPosition                   environmentResultProtection
	completionFloor                  *CompletionFloor
	deliveryFloor                    *protocolv4.DeliverySubscriptionFloor
	workloads                        *unaryWorkload
	initializerWorkloads             *unaryWorkload
	initializer                      *controllerInitializerPlan
	workloadController               *ConnectionController
	workloadRevision                 uint64
	mu                               sync.Mutex
	refs                             [sessionAdmissionOwnerCapacity + 2]resourcev4.Reference
	count                            int
	claimed                          bool
}

func reserveSessionHeadroom(c SourceConnectConfig, environments ...*Environment) (*sessionHeadroom, error) {
	if c.Admission.headroom != nil || len(environments) > 1 || len(environments) == 1 && environments[0] == nil {
		return nil, cryptov4.ErrConfiguration
	}
	if err := c.Preauth.CheckSameEnvironment(c.Environment); err != nil {
		return nil, err
	}
	metadata, initial, err := sessionAdmissionCharges(c.Admission)
	if err != nil {
		return nil, err
	}
	var batch sessionAdmissionBatch
	if err = batch.prepare(c.Admission, c.Root, c.Owner, c.Environment, c.Scope); err != nil {
		return nil, err
	}
	defer batch.release()
	var requests [sessionAdmissionOwnerCapacity + 2]resourcev4.Request
	for i := range batch.count {
		requests[i], err = batch.request(i)
		if err != nil {
			return nil, err
		}
	}
	n := batch.count
	requests[n] = resourcev4.Request{Owner: admissionResourceKey(c.Owner, coreOwnerCapacity), Charge: metadata, Accounts: batch.core.accounts[:batch.core.accountCount]}
	tenant := [1]resourcev4.Account{c.Scope.Tenant}
	requests[n+1] = resourcev4.Request{Owner: admissionResourceKey(c.Owner, coreOwnerCapacity+1), Charge: initial, Accounts: tenant[:]}
	h := &sessionHeadroom{count: n + 2, environmentOrigin: c.Environment, preauthOrigin: c.Preauth}
	if c.controller != nil {
		if c.controllerOwner == nil || !c.controller.workloads.prepared {
			return nil, resourcev4.ErrOwner
		}
		h.workloadController, h.workloadRevision = c.controllerOwner, c.controller.workloads.revision
	}
	if err = c.Root.ReserveBatch(requests[:h.count], h.refs[:h.count]); err != nil {
		return nil, err
	}
	h.coreBorrows, batch.core.borrows = batch.core.borrows, [3]resourcev4.Reference{}
	h.source, err = reserveSourceReferences(c)
	if err == nil {
		err = h.reserveWorkloadSnapshot(c)
	}
	if err == nil {
		h.preauth, err = c.Preauth.Borrow()
	}
	if err == nil {
		h.sessionSlot, err = h.refs[0].Borrow()
	}
	if err != nil {
		h.close()
		return nil, err
	}
	if err = batch.core.prepareReceivePool(h.refs[:batch.core.count]); err != nil {
		h.close()
		return nil, err
	}
	if err = batch.core.prepareStreamServiceFloor(h.refs[:batch.core.count]); err != nil {
		h.close()
		return nil, err
	}
	if batch.core.serviceFloors != nil {
		h.serviceFloors, batch.core.serviceFloors = batch.core.serviceFloors, nil
		h.servicePlan, h.serviceGeometry = batch.core.config.Handlers.Plan, callerStreamGeometry(batch.core.config)
	}
	if batch.core.receivePool != nil {
		h.receivePool, batch.core.receivePool = batch.core.receivePool, nil
		for i, position := range batch.core.positions[:batch.core.count] {
			if position == coreReceivePoolOwner {
				h.receiveIndex = i
				break
			}
		}
	}
	if batch.rpc.prepared && len(environments) == 1 {
		h.resultPosition, err = environments[0].protectResult(h.refs[batch.core.count+rpcServicesCallerOwner])
		if err != nil {
			h.close()
			return nil, err
		}
	}
	if batch.rpc.prepared {
		h.deliveryFloor, err = h.source.subscriptions.ReserveSourceDeliveryFloor(h.refs[batch.core.count+rpcServicesDeliveryFloor])
		if err != nil {
			h.close()
			return nil, err
		}
		h.network, err = rpcv4.NewNetwork(batch.rpc.config.networkConfig(), h.refs[batch.core.count+rpcServicesNetwork])
		if err != nil {
			h.close()
			return nil, err
		}
		if err = batch.rpc.reserveReferences(h.refs[batch.core.count:batch.count]); err != nil {
			h.close()
			return nil, err
		}
		h.rpcReferences, batch.rpc.references = batch.rpc.references, rpcServicesReferences{}
		if err = batch.rpc.reserveQueries(); err != nil {
			h.close()
			return nil, err
		}
		h.queries, batch.rpc.queries = batch.rpc.queries, nil
		if err = batch.rpc.reserveExecution(h.refs[batch.core.count:batch.count]); err != nil {
			h.close()
			return nil, err
		}
		h.execution, batch.rpc.execution = batch.rpc.execution, serviceExecutionPreparation{}
		if err = batch.rpc.reserveDependencies(h.refs[batch.core.count:batch.count]); err != nil {
			h.close()
			return nil, err
		}
		h.dependencies, batch.rpc.dependencies = batch.rpc.dependencies, rpcDependencyPreparation{}
		h.receiveProtection, err = reserveInternalChannelReceive(h.receivePool, batch.rpc.config)
		if err != nil {
			h.close()
			return nil, err
		}
		h.completionFloor, err = batch.rpc.plan.executor.NewCompletionFloor(h.refs[batch.core.count+rpcServicesCompletionFloor], h.refs[batch.core.count+rpcServicesMetadata])
		if err != nil {
			h.close()
			return nil, err
		}
	}
	if batch.rpc.prepared && len(batch.rpc.config.Workloads) != 0 {
		if len(environments) != 1 {
			h.close()
			return nil, cryptov4.ErrConfiguration
		}
		if err = h.reserveWorkloads(batch.rpc.config, batch.core.config, c.Admission.Initial.Role, batch.rpc.plan, environments[0]); err != nil {
			h.close()
			return nil, err
		}
	}
	if c.controller != nil && c.controller.initialization != nil {
		if len(environments) != 1 {
			h.close()
			return nil, cryptov4.ErrConfiguration
		}
		if err = h.reserveInitializer(c.controller.initialization, &batch.rpc, batch.core.config, c.Admission.Initial.Role, environments[0]); err != nil {
			h.close()
			return nil, err
		}
	}
	return h, nil
}

func (h *sessionHeadroom) claim(requests []resourcev4.Request, refs []resourcev4.Reference, batch *sessionAdmissionBatch, preauth resourcev4.Reference) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if batch == nil || h.claimed || h.count != len(requests) || len(refs) != h.count {
		return cryptov4.ErrConfiguration
	}
	rpc, core := &batch.rpc, &batch.core
	if h.dependencies.prepared {
		if !rpc.prepared || rpc.dependencies.prepared {
			return resourcev4.ErrOwner
		}
		if err := h.dependencies.check(rpc.config); err != nil {
			return err
		}
	}
	if h.execution.floors != nil {
		start := core.count + rpc.executionStart
		end := start + h.execution.count()
		if !rpc.prepared || rpc.execution.floors != nil || start < core.count || end > core.count+rpc.count || end > len(requests) {
			return resourcev4.ErrOwner
		}
		if err := h.execution.checkRequests(rpc.config.dispatchConfig(), requests[start:end]); err != nil {
			return err
		}
	}
	if h.environmentOrigin != (resourcev4.Reference{}) {
		if core.environment != h.environmentOrigin || h.preauthOrigin != preauth || !core.prepared || core.used || core.borrows != ([3]resourcev4.Reference{}) || batch.preauth != (resourcev4.Reference{}) || batch.sessionSlot != (resourcev4.Reference{}) {
			return resourcev4.ErrOwner
		}
		for i, ref := range h.coreBorrows {
			if i == 2 && !core.config.MessageCarrier {
				if ref != (resourcev4.Reference{}) {
					return resourcev4.ErrOwner
				}
				continue
			}
			if err := ref.Check(); err != nil {
				return err
			}
		}
		if err := h.preauth.Check(); err != nil {
			return err
		}
		if err := h.sessionSlot.Check(); err != nil {
			return err
		}
	}
	if h.receivePool != nil {
		if core == nil || !core.prepared || core.used || core.receivePool != nil || h.receiveIndex >= core.count || core.positions[h.receiveIndex] != coreReceivePoolOwner || core.config.Streams.ReceivePoolBytes != h.receivePool.capacity || core.config.Open.Active != h.receivePool.maxFlows || min(core.config.Session.Contract.Limits().MaxCredit, core.config.Streams.ReceivePoolBytes) != h.receivePool.limit {
			return cryptov4.ErrConfiguration
		}
	}
	if h.serviceFloors != nil {
		count, _, err := streamServiceFloorCharges(core.config)
		if err != nil {
			return err
		}
		if core.serviceFloors != nil || len(h.serviceFloors) != int(count) || core.config.Handlers.Plan != h.servicePlan || callerStreamGeometry(core.config) != h.serviceGeometry {
			return cryptov4.ErrConfiguration
		}
	}
	if h.resultPosition != (environmentResultProtection{}) && (rpc == nil || !rpc.prepared || rpc.resultPosition != (environmentResultProtection{})) {
		return cryptov4.ErrConfiguration
	}
	if err := h.checkWorkloads(rpc, core); err != nil {
		return err
	}
	if err := h.checkInitializer(rpc, core); err != nil {
		return err
	}
	if h.completionFloor != nil && (rpc == nil || !rpc.prepared || rpc.completionFloor != nil || h.completionFloor.executor.Load() != rpc.plan.executor) {
		return cryptov4.ErrConfiguration
	}
	if h.receiveProtection[0] != nil {
		if !rpc.prepared || rpc.receivePool != nil || rpc.receiveProtection != ([11]*ReceiveProtection{}) {
			return cryptov4.ErrConfiguration
		}
		if err := checkInternalChannelReceive(h.receivePool, rpc.config, h.receiveProtection); err != nil {
			return err
		}
	}
	if h.rpcReferences.plan != nil {
		if rpc.references.plan != nil {
			return resourcev4.ErrOwner
		}
		if err := h.rpcReferences.check(rpc); err != nil {
			return err
		}
	}
	if h.queries != nil {
		if !rpc.prepared || rpc.queries != nil {
			return resourcev4.ErrOwner
		}
		if err := h.queries.checkPreparation(rpc.plan); err != nil {
			return err
		}
	}
	for i, request := range requests {
		if refs[i] != (resourcev4.Reference{}) {
			return resourcev4.ErrOwner
		}
		if h.deliveryFloor != nil && i == core.count+rpcServicesDeliveryFloor {
			if !rpc.prepared || rpc.deliveryFloor != nil {
				return resourcev4.ErrOwner
			}
			if err := h.deliveryFloor.CheckAdmissionRequest(request); err != nil {
				return err
			}
			continue
		}
		if h.execution.floors != nil && i >= core.count+rpc.executionStart && i < core.count+rpc.executionStart+h.execution.count() {
			continue
		}
		if h.network != nil && i == core.count+rpcServicesNetwork {
			if !rpc.prepared || rpc.network != nil {
				return resourcev4.ErrOwner
			}
			if err := h.network.CheckAdmission(rpc.config.networkConfig(), request); err != nil {
				return err
			}
			continue
		}
		if i < core.count && core.positions[i] >= coreStreamServiceStart && h.serviceFloors != nil {
			position := core.positions[i] - coreStreamServiceStart
			if err := h.serviceFloors[position/streamServiceOwners].owners[position%streamServiceOwners].CheckAdmissionRequest(request); err != nil {
				return err
			}
			continue
		}
		if h.receivePool != nil && i == h.receiveIndex {
			if err := h.receivePool.reservation.CheckRequest(request); err != nil {
				return err
			}
			continue
		}
		if h.completionFloor != nil && i == h.count-2-rpc.count+rpcServicesCompletionFloor {
			if err := h.completionFloor.checkAdmissionRequest(request); err != nil {
				return err
			}
			continue
		}
		if err := h.refs[i].CheckRequest(request); err != nil {
			return err
		}
	}
	// Advance each original alias before publishing the batch. If a move
	// fails, this unpublished headroom still owns every surviving reference.
	for i, ref := range h.coreBorrows {
		if ref == (resourcev4.Reference{}) {
			continue
		}
		moved, err := ref.TakeBorrow()
		if err != nil {
			return err
		}
		h.coreBorrows[i] = moved
	}
	for _, ref := range []*resourcev4.Reference{&h.preauth, &h.sessionSlot} {
		if *ref == (resourcev4.Reference{}) {
			continue
		}
		moved, err := ref.TakeBorrow()
		if err != nil {
			return err
		}
		*ref = moved
	}
	if err := h.rpcReferences.move(); err != nil {
		return err
	}
	rpc.references, h.rpcReferences = h.rpcReferences, rpcServicesReferences{}
	rpc.network, h.network = h.network, nil
	rpc.queries, h.queries = h.queries, nil
	rpc.execution, h.execution = h.execution, serviceExecutionPreparation{}
	rpc.dependencies, h.dependencies = h.dependencies, rpcDependencyPreparation{}
	rpc.deliveryFloor, h.deliveryFloor = h.deliveryFloor, nil
	rpc.initializer, h.initializer = h.initializer, nil
	rpc.initializerWorkloads, h.initializerWorkloads = h.initializerWorkloads, nil
	core.borrows, h.coreBorrows = h.coreBorrows, [3]resourcev4.Reference{}
	core.serviceFloors, h.serviceFloors = h.serviceFloors, nil
	batch.preauth, h.preauth = h.preauth, resourcev4.Reference{}
	batch.sessionSlot, h.sessionSlot = h.sessionSlot, resourcev4.Reference{}
	copy(refs, h.refs[:h.count])
	clear(h.refs[:h.count])
	if h.receiveProtection[0] != nil {
		rpc.receivePool = h.receivePool
		rpc.receiveProtection, h.receiveProtection = h.receiveProtection, [11]*ReceiveProtection{}
	}
	if h.receivePool != nil {
		core.receivePool, h.receivePool = h.receivePool, nil
	}
	if h.resultPosition != (environmentResultProtection{}) {
		rpc.resultPosition = h.resultPosition
		h.resultPosition = environmentResultProtection{}
	}
	if h.workloads != nil {
		rpc.workloadHeadroom, h.workloads = h.workloads, nil
	}
	if h.completionFloor != nil {
		rpc.completionFloor, h.completionFloor = h.completionFloor, nil
	}
	h.claimed = true
	return nil
}

func (h *sessionHeadroom) close() {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.source.close()
	h.execution.close()
	h.dependencies.close()
	for w := h.workloads; w != nil; {
		next := w.initialNext
		w.initialNext = nil
		w.closeUnattached()
		w = next
	}
	h.workloads = nil
	for w := h.initializerWorkloads; w != nil; {
		next := w.initialNext
		w.initialNext = nil
		w.closeUnattached()
		w = next
	}
	h.initializerWorkloads, h.initializer = nil, nil
	h.network.Close()
	h.network = nil
	for _, guard := range h.receiveProtection {
		guard.Close()
	}
	clear(h.receiveProtection[:])
	h.rpcReferences.close()
	h.queries.releasePreparation()
	h.queries = nil
	for i := range h.serviceFloors {
		h.serviceFloors[i].close()
	}
	h.serviceFloors = nil
	if h.receivePool != nil {
		h.receivePool.Close()
		h.receivePool = nil
	}
	for _, ref := range h.coreBorrows {
		ref.Release()
	}
	clear(h.coreBorrows[:])
	h.preauth.Release()
	h.sessionSlot.Release()
	h.preauth, h.sessionSlot = resourcev4.Reference{}, resourcev4.Reference{}
	h.completionFloor.Close()
	h.completionFloor = nil
	h.deliveryFloor.Close()
	h.deliveryFloor = nil
	for _, ref := range h.refs[:h.count] {
		ref.Release()
	}
	clear(h.refs[:h.count])
	h.resultPosition.close()
	h.resultPosition = environmentResultProtection{}
	h.claimed = true
}
