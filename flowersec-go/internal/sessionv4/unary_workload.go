package sessionv4

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"math"
	"sync/atomic"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
)

const (
	workloadRoute = iota
	workloadPreparation
	workloadCall         = workloadPreparation + 5
	workloadCompletion   = workloadCall + 6
	workloadAuthority    = workloadCompletion + 1
	workloadDependencies = workloadAuthority + 1
	workloadOwners       = workloadDependencies + 1
)

// A workload occupies positions in the original operation, call, Network,
// Environment and Completion tables. Its protected references are the actual
// references consumed by Prepare/Start, not an additional capacity estimate.
// Fields other than activeCall are guarded by the original RPCServices gate.
type unaryWorkload struct {
	stream                      *streamPreparationPlan
	initialIndex                int
	initialNext                 *unaryWorkload
	admissionContract           [32]byte
	origin, lineage             [32]byte
	installed                   atomic.Bool
	initializer                 bool
	replacement                 bool
	namespace                   [32]byte
	methodType                  uint32
	shape                       uint8
	encoded                     bool
	class                       ApplicationWorkClass
	codecBytes, scratchBytes    uint32
	services                    *RPCServices
	environment                 *Environment
	metadata                    resourcev4.Reference
	slots                       []unaryWorkloadSlot
	requestBytes, responseBytes uint32
	closed, cleaned             bool
}

type unaryWorkloadSlot struct {
	references                                *resourcev4.BorrowPool
	transport                                 *streamCallerFloor
	workload                                  *unaryWorkload
	operation                                 *UnaryOperation
	callScope                                 serviceClientCall
	callScopeUsed                             atomic.Bool
	controller                                *controllerWorkloadPosition
	index                                     int
	owners                                    [workloadCompletion]*resourcev4.ProtectedReservation
	completion                                *CompletionFloor
	authority                                 *protocolv4.DeliverySubscriptionFloor
	authorityBacking                          resourcev4.Reference
	result                                    environmentResultProtection
	network                                   rpcv4.OutgoingProtection
	notify                                    [2]rpcv4.NotifyProtection
	activeCall                                atomic.Pointer[unaryInvocation]
	building, claiming, used, closed, closing bool
}

func unaryWorkloadCharges(r *RPCServices, method UnaryMethodDefinition, requestBytes, responseBytes uint32) (charges [workloadOwners]resourcev4.Vector, err error) {
	return unaryWorkloadChargesWithTask(r.runtimeBytes, method, requestBytes, responseBytes, r.plan.executor.TaskCharge(), r.plan.executor.CompletionFloorCharge())
}

func unaryWorkloadChargesWithTask(runtimeBytes uint64, method UnaryMethodDefinition, requestBytes, responseBytes uint32, task, completion resourcev4.Vector) (charges [workloadOwners]resourcev4.Vector, err error) {
	return methodWorkloadChargesWithTask(runtimeBytes, method, 0, requestBytes, responseBytes, task, completion)
}

func methodWorkloadChargesWithTask(runtimeBytes uint64, method UnaryMethodDefinition, shape uint8, requestBytes, responseBytes uint32, task, completion resourcev4.Vector) (charges [workloadOwners]resourcev4.Vector, err error) {
	if shape != 0 && shape != 2 {
		return charges, cryptov4.ErrConfiguration
	}
	var codec *SynchronousUnaryCodec
	var preparation *streamPreparationPlan
	if shape == 2 {
		preparation = &streamPreparationPlan{notify: true}
	}
	encoded := requestBytes
	if method.Codec.Encode != nil {
		codec, encoded = &method.Codec, method.Codec.MaxEncodedBytes
	}
	charges[workloadRoute], err = rpcv4.ContractRouteCharge(runtimeBytes)
	if err != nil {
		return
	}
	prepared, count, err := preparedOperationChargesWithTask(runtimeBytes, encoded, requestBytes, codec, preparation, task, true)
	if err != nil {
		return charges, err
	}
	copy(charges[workloadPreparation:workloadCall], prepared[:count])
	charges[workloadDependencies], err = resourcev4.BorrowPoolCharge(workloadDependencyPositions(shape))
	if err != nil {
		return charges, err
	}
	if shape == 2 {
		charges[workloadCall], err = rpcv4.NotifySourceCharge(encoded, runtimeBytes)
		if err == nil {
			charges[workloadCall+1], err = rpcv4.NotifySubmissionCharge(runtimeBytes)
		}
		return charges, err
	}
	caller, err := shortCallerCharges(runtimeBytes, encoded, responseBytes)
	if err != nil {
		return charges, err
	}
	// The independent result owner already includes the one UnaryCall.
	caller[0][resourcev4.SDKBytes] -= uint64(unsafe.Sizeof(UnaryCall{}))
	copy(charges[workloadCall:workloadCompletion], caller[:])
	charges[workloadCompletion] = completion
	charges[workloadAuthority], err = protocolv4.DeliverySubscriptionFloorCharge().Add(resourcev4.Vector{resourcev4.SDKBytes: runtimeBytes})
	return
}

// Every position is an actual root reference. The bound follows the existing
// eight-parent representation and the responsibilities that can coexist in
// one original call; it is independent of ordinary/Completion worker counts.
func workloadDependencyPositions(shape uint8) uint32 {
	sets := 1 // Original preparation, including notifications.
	if shape == 0 {
		sets += 2 + len(unaryResultState{}.observers) // Start, result, waiters.
	} else if shape == 1 {
		sets += 2 // Start/result and the single item reader.
	}
	return uint32(sets * maxApplicationAncestors)
}

// reserveUnaryWorkload is the internal unary admission composition. No caller can supply a new root, peer work class or worker pool.
// All failures unwind the unpublished target; no partial target is delivered.
func (r *RPCServices) reserveUnaryWorkload(method UnaryMethodDefinition, requestBytes, responseBytes uint32, calls uint16) (*unaryWorkload, error) {
	return r.reserveUnaryWorkloadAdmission(method, requestBytes, responseBytes, calls, nil)
}

// Original admission supplies the verified subscription owner before activation.
// Runtime Bind uses its existing authorized endpoint; neither path creates one.
func (r *RPCServices) reserveUnaryWorkloadAdmission(method UnaryMethodDefinition, requestBytes, responseBytes uint32, calls uint16, subscriptions *protocolv4.CredentialSubscriptions, admitted ...*unaryWorkload) (*unaryWorkload, error) {
	return r.reserveMethodWorkloadAdmission(method, requestBytes, responseBytes, calls, subscriptions, nil, admitted...)
}

func (r *RPCServices) reserveMethodWorkloadAdmission(method UnaryMethodDefinition, requestBytes, responseBytes uint32, calls uint16, subscriptions *protocolv4.CredentialSubscriptions, stream *streamPreparationPlan, admitted ...*unaryWorkload) (_ *unaryWorkload, err error) {
	if len(admitted) > 1 || r == nil || calls == 0 || calls > 1024 || requestBytes > 1048576 || method.Contract == ([32]byte{}) || method.WorkClass > ApplicationResident || method.Codec.MaxEncodedBytes > 1048576 || method.Codec.ScratchBytes > 1048576 || method.Codec.Encode == nil && (method.Codec.MaxEncodedBytes != 0 || method.Codec.ScratchBytes != 0) {
		return nil, cryptov4.ErrConfiguration
	}
	e, err := r.bindingEnvironment()
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	if r.closed || r.retired || r.plan == nil || r.plan.executor == nil || r.routes == nil || r.network == nil || r.callSerial == math.MaxUint64 {
		r.mu.Unlock()
		return nil, cryptov4.ErrClosed
	}
	if r.draining.Load() {
		r.mu.Unlock()
		return nil, ErrSessionDraining
	}
	policy, err := r.routes.BindingPolicy(method.Contract, protocolv4.ContractAcceptance{})
	if err == nil {
		err = method.checkExecutionPolicy(policy)
	}
	if err == nil {
		_, err = workloadResponseLimit(method, policy, ServiceMethodWorkload{ResponseLimitBytes: responseBytes, ExplicitResponseLimit: policy.Shape != 2})
	}
	encoded := requestBytes
	if method.Codec.Encode != nil {
		encoded = method.Codec.MaxEncodedBytes
	}
	if err == nil && (policy.Shape > 2 || (policy.Shape == 1) != (stream != nil) || encoded > policy.RequestMaxBytes) {
		err = cryptov4.ErrConfiguration
	}
	if err == nil && policy.Shape == 2 && subscriptions == nil && r.notifications == nil {
		err = cryptov4.ErrNotReady
	}
	var charges [workloadOwners]resourcev4.Vector
	if err == nil {
		if stream != nil {
			charges, err = streamWorkloadCharges(r, method, policy, requestBytes, responseBytes, stream)
		} else {
			charges, err = methodWorkloadChargesWithTask(r.runtimeBytes, method, policy.Shape, requestBytes, responseBytes, r.plan.executor.TaskCharge(), r.plan.executor.CompletionFloorCharge())
		}
	}
	if err != nil {
		r.mu.Unlock()
		return nil, err
	}
	if len(r.workloadSlots) != len(r.operations) || len(r.generalCalls) != len(r.operations) {
		r.mu.Unlock()
		return nil, cryptov4.ErrConfiguration
	}
	available := 0
	for i, operation := range r.operations {
		if operation == nil && i < len(r.generalCalls) && r.generalCalls[i] == nil && r.workloadSlots[i] == nil {
			available++
		}
	}
	if available < int(calls) {
		r.mu.Unlock()
		return nil, cryptov4.ErrCapacity
	}
	r.callSerial++
	var seed [56]byte
	copy(seed[:16], "rpc-workload/v4")
	copy(seed[16:32], r.owner.Instance[:])
	copy(seed[32:48], r.owner.Backing[:])
	binary.BigEndian.PutUint64(seed[48:], r.callSerial)
	hash := sha256.Sum256(seed[:])
	owner, root, executor, plan, network := r.owner, r.root, r.plan.executor, r.plan, r.network
	accounts, accountCount, runtimeBytes := r.accounts, r.accountCount, r.runtimeBytes
	copy(owner.Instance[:], hash[:16])
	copy(owner.Backing[:], hash[16:])
	r.mu.Unlock()
	var w *unaryWorkload
	if len(admitted) == 1 {
		w = admitted[0]
		if w == nil || w.services != nil || w.cleaned || w.closed || w.environment != e || w.admissionContract != method.Contract || len(w.slots) != int(calls) || w.requestBytes != requestBytes || w.responseBytes != responseBytes || !w.matchesMethod(method, policy) {
			return nil, cryptov4.ErrConfiguration
		}
		if err := w.metadata.CheckAllocationScope(root, r.owner, accounts[:accountCount]); err != nil {
			return nil, err
		}
		for i := range w.slots {
			if w.slots[i].references == nil || w.slots[i].references.CheckAvailable() != nil {
				return nil, cryptov4.ErrConfiguration
			}
			if policy.Shape != 2 && (w.slots[i].completion == nil || w.slots[i].completion.executor.Load() != executor) {
				return nil, cryptov4.ErrConfiguration
			}
		}
	} else {
		w, err = reserveUnaryWorkloadBacking(root, owner, accounts[:accountCount], runtimeBytes, executor, e, method, policy, requestBytes, responseBytes, calls, charges, stream)
		if err != nil {
			return nil, err
		}
	}
	defer func() {
		if err != nil {
			w.closeUnattached()
		}
	}()
	if stream != nil && len(admitted) == 1 {
		if !w.matchesStreamTarget(ServiceMethod{Shape: 1, StreamKind: stream.kind, StreamMetadata: stream.metadata}) {
			return nil, cryptov4.ErrConfiguration
		}
		for i := range w.slots {
			if w.slots[i].transport == nil || w.slots[i].transport.plan != nil || w.stream.core != nil || stream.core != nil {
				return nil, cryptov4.ErrConfiguration
			}
		}
	} else if stream != nil {
		if stream.core == nil || stream.core.plan == nil {
			return nil, cryptov4.ErrConfiguration
		}
		for i := range w.slots {
			w.slots[i].transport, err = stream.core.plan.reserveStreamCallerFloor(len(stream.kind) + len(stream.metadata))
			if err != nil {
				return nil, err
			}
			w.slots[i].transport.workload = w
		}
	}
	if policy.Shape != 2 {
		if err = w.reserveNetwork(network); err != nil {
			return nil, err
		}
		var authorization *protocolv4.EndpointAuthorization
		if subscriptions == nil {
			_, authorization, err = plan.queryAuthorization()
			if err != nil {
				return nil, err
			}
		}
		for i := range w.slots {
			s := &w.slots[i]
			if s.authority != nil {
				err = s.authority.BindSubscriptions(subscriptions)
			} else if subscriptions != nil {
				s.authority, err = subscriptions.ReserveDeliveryFloor(s.authorityBacking)
			} else {
				s.authority, err = authorization.ReserveDeliveryFloor(s.authorityBacking)
			}
			if err != nil {
				return nil, err
			}
			s.authorityBacking = resourcev4.Reference{}
		}
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.retired {
		return nil, cryptov4.ErrClosed
	}
	if r.draining.Load() {
		return nil, ErrSessionDraining
	}
	available = 0
	for i, operation := range r.operations {
		if operation == nil && r.generalCalls[i] == nil && r.workloadSlots[i] == nil {
			available++
		}
	}
	if available < int(calls) {
		return nil, cryptov4.ErrCapacity
	}
	if policy.Shape == 2 {
		if err = r.protectNotifyWorkloadLocked(w); err != nil {
			return nil, err
		}
	}
	w.services = r
	index := 0
	for i := range w.slots {
		for r.operations[index] != nil || r.generalCalls[index] != nil || r.workloadSlots[index] != nil {
			index++
		}
		s := &w.slots[i]
		s.index = index
		r.workloadSlots[index] = s
		index++
	}
	return w, nil
}

func (s *unaryWorkloadSlot) protect(component int, ref resourcev4.Reference, minimum resourcev4.Vector) (err error) {
	var anchor resourcev4.Reference
	var borrows [5]resourcev4.Reference
	count := 0
	if component == workloadPreparation+3 {
		count = 1 // Original synchronous encoder permit backing.
	}
	if component == workloadPreparation+2 || component == workloadCall+2 || component == workloadCall+4 || component == workloadCall+5 {
		anchor, err = ref.Borrow()
		if err != nil {
			return err
		}
		defer anchor.Release()
		if component == workloadCall+4 {
			count = 2
		}
	}
	if s.workload.shape == 1 && component == workloadCall {
		anchor, err = ref.Borrow()
		if err != nil {
			return err
		}
		defer anchor.Release()
		count = 3 // Environment result pin, Completion use and actual decoder.
	}
	if s.workload.shape == 2 && component == workloadPreparation+2 {
		// The source publication guard and all four pending waits retain
		// the same original operation metadata, even at a full root slab.
		count = 5
	}
	for i := range count {
		borrows[i], err = ref.Borrow()
		if err != nil {
			for _, borrow := range borrows {
				borrow.Release()
			}
			return err
		}
	}
	if anchor != (resourcev4.Reference{}) {
		s.owners[component], err = resourcev4.NewProtectedResultReservation(ref, minimum, anchor, borrows[:count]...)
	} else {
		s.owners[component], err = resourcev4.NewProtectedReservation(ref, minimum, borrows[:count]...)
	}
	for _, borrow := range borrows {
		borrow.Release()
	}
	return err
}

func (s *unaryWorkloadSlot) closeOwners() {
	s.transport.close()
	s.transport.cleanupComplete()
	if s.controller != nil {
		s.controller.backing.CloseAfterUse()
	}
	s.network.Close()
	for _, protection := range s.notify {
		protection.Close()
	}
	s.notify = [2]rpcv4.NotifyProtection{}
	s.result.close()
	s.authority.Close()
	s.authorityBacking.Release()
	s.authorityBacking = resourcev4.Reference{}
	s.completion.Close()
	for _, owner := range s.owners {
		owner.CloseAfterUse()
	}
}

// Binding Close only seals future claims. A returned prepared operation keeps
// its full future call vector until that original operation actually exits.
func (w *unaryWorkload) seal() {
	if w == nil {
		return
	}
	w.services.mu.Lock()
	w.closed = true
	w.services.mu.Unlock()
	w.environment.signalMaterials()
}

// prepare selects the normal limit before choosing protected capacity. A legal
// larger call, or overlap beyond the declared target, uses ordinary admission.
func (w *unaryWorkload) prepare(ctx context.Context, r *RPCServices, method UnaryMethodDefinition, input []byte, options rpcv4.UnaryPreparation) (*UnaryOperation, error) {
	if w == nil || r == nil || r != w.services || ctx == nil {
		return nil, cryptov4.ErrConfiguration
	}
	r.advanceWorkloads()
	r.mu.Lock()
	stream := w.stream
	r.mu.Unlock()
	var transport *SessionCorePlan
	if stream != nil && stream.core != nil {
		transport = stream.core.plan
		transport.mu.Lock()
	}
	r.mu.Lock()
	if w.closed || w.cleaned || r.closed || r.retired {
		r.mu.Unlock()
		if transport != nil {
			transport.mu.Unlock()
		}
		return nil, cryptov4.ErrClosed
	}
	policy, err := r.routes.BindingPolicy(method.Contract, protocolv4.ContractAcceptance{})
	if err == nil && !w.matchesMethod(method, policy) {
		err = cryptov4.ErrConfiguration
	}
	var limit uint32
	if err == nil {
		limit, err = workloadResponseLimit(method, policy, ServiceMethodWorkload{ResponseLimitBytes: options.ResponseLimitBytes, ExplicitResponseLimit: options.ExplicitResponseLimit})
	}
	var slot *unaryWorkloadSlot
	var routeRef resourcev4.Reference
	if err == nil && uint64(len(input)) <= uint64(w.requestBytes) && limit <= w.responseBytes {
		// Prefer a slot whose original preaccepted Stream is already ready.
		// This keeps a multi-call recipe from selecting an unrelated dormant
		// floor while another one owns its available try-now transport.
		for pass := 0; pass < 2 && slot == nil && err == nil; pass++ {
			for i := range w.slots {
				s := &w.slots[i]
				if s.used || s.building || s.closed || s.closing {
					continue
				}
				ready := false
				if transport != nil && s.transport != nil && s.transport.preaccepted != nil {
					e := s.transport.preaccepted
					e.mu.Lock()
					ready = !e.closed && !e.claimed && !e.transferred && e.owner != nil
					e.mu.Unlock()
				}
				if pass == 0 && !ready || pass == 1 && ready {
					continue
				}
				routeRef, err = s.owners[workloadRoute].Checkout()
				if err == nil {
					s.used, s.claiming, slot = true, true, s
				}
				break
			}
		}
	}
	r.mu.Unlock()
	if transport != nil {
		transport.mu.Unlock()
	}
	if err != nil {
		return nil, err
	}
	if slot == nil {
		if w.initializer {
			return nil, cryptov4.ErrCapacity
		}
		method.workload = nil
		if w.shape == 2 {
			operation, err := r.prepareNotifyMethod(ctx, method, input, options)
			if err != nil {
				return nil, err
			}
			return operation.owner, nil
		}
		if w.shape == 1 {
			operation, err := r.prepareStreamingMethod(ctx, stream.core, method, stream.kind, stream.metadata, input, options)
			if err != nil {
				return nil, err
			}
			return operation.owner, nil
		}
		return r.PrepareMethod(ctx, method, input, options)
	}
	defer func() {
		routeRef.Release()
		r.mu.Lock()
		slot.claiming = false
		r.mu.Unlock()
		w.environment.signalMaterials()
	}()
	route, _, options, err := r.prepareMethodRouteReserved(ctx, method, options, w.shape, routeRef)
	if err != nil {
		return nil, err
	}
	defer route.Release()
	var codec *SynchronousUnaryCodec
	if method.Codec.Encode != nil {
		codec = &method.Codec
	}
	if w.shape == 2 {
		return r.prepareUnaryEncodingWithWorkload(ctx, route, input, options, method.WorkClass, false, nil, nil, codec, slot, &streamPreparationPlan{notify: true})
	}
	plan, err := r.resultPlan(method.Decode)
	if err != nil {
		return nil, err
	}
	if w.shape == 1 {
		return r.prepareUnaryEncodingWithWorkload(ctx, route, input, options, method.WorkClass, false, nil, plan, codec, slot, stream)
	}
	return r.prepareUnaryEncodingWithWorkload(ctx, route, input, options, method.WorkClass, false, nil, plan, codec, slot)
}

// Only the original call vector decides when a failed unsubmitted Start may
// reuse its Network position. Prepared request ownership is still live then.
func (s *unaryWorkloadSlot) releaseCallUseLocked() error {
	for _, owner := range s.owners[workloadCall:workloadCompletion] {
		if owner != nil {
			if err := owner.CheckAvailable(); err != nil {
				return err
			}
		}
	}
	if s.workload.shape == 2 {
		for _, protection := range s.notify {
			if err := protection.ReleaseUse(); err != nil {
				return err
			}
		}
		return nil
	}
	if err := s.completion.checkAvailable(); err != nil {
		return err
	}
	if call := s.activeCall.Load(); call != nil {
		if err := s.network.ReleaseUse(call.ticket); err != nil {
			return err
		}
		s.activeCall.Store(nil)
	}
	return nil
}

func (s *unaryWorkloadSlot) availableLocked() bool {
	if s.references == nil || s.references.CheckAvailable() != nil {
		return false
	}
	if s.controller != nil && s.controller.backing.CheckAvailable() != nil {
		return false
	}
	for _, owner := range s.owners {
		if owner != nil && owner.CheckAvailable() != nil {
			return false
		}
	}
	return s.releaseCallUseLocked() == nil
}

// The Environment's existing coordinator visits original RPC positions. No
// workload adds a timer, waiting task, worker or second cleanup registry.
func (r *RPCServices) advanceWorkloads() {
	if r == nil {
		return
	}
	r.mu.Lock()
	count := len(r.workloadSlots)
	r.mu.Unlock()
	for index := 0; index < count; index++ {
		r.mu.Lock()
		if index >= len(r.workloadSlots) {
			r.mu.Unlock()
			return
		}
		s := r.workloadSlots[index]
		if s == nil || s.building || s.claiming || s.closing {
			r.mu.Unlock()
			continue
		}
		transportReady, transportCleaned := true, true
		if s.transport != nil && (s.workload.stream.core != nil || s.closed) {
			s.closing = true
			r.mu.Unlock()
			transportReady = s.transport.checkWorkloadAvailable() == nil
			transportCleaned = s.transport.cleanupComplete()
			r.mu.Lock()
			s.closing = false
		}
		w := s.workload
		idle := s.operation == nil && r.operations[index] == nil && r.generalCalls[index] == nil
		if !s.closed && s.used && idle && transportReady && s.availableLocked() {
			s.used = false
		}
		closeNow := !s.closed && (r.closed || w.closed && !s.used)
		if closeNow {
			s.closing = true
			r.mu.Unlock()
			// Environment ordering requires its gate outside the RPC gate.
			s.closeOwners()
			r.mu.Lock()
			s.closed, s.closing = true, false
		}
		if !s.closed || !idle || s.callScopeUsed.Load() || !s.completion.CleanupComplete() {
			r.mu.Unlock()
			continue
		}
		complete := true
		for _, owner := range s.owners {
			complete = complete && owner.CleanupComplete()
		}
		if complete {
			// Accepted results keep their preadmitted parent positions usable
			// after transport Close, until their real owner and decoder exit.
			s.references.Close()
			complete = s.references.CleanupComplete()
		}
		if complete && transportCleaned && s.controller.cleanupComplete() {
			s.activeCall.Store(nil)
			r.workloadSlots[index] = nil
			for i := range w.slots {
				if r.workloadSlots[w.slots[i].index] == &w.slots[i] {
					complete = false
					break
				}
			}
			if complete && !w.cleaned {
				if w.initialIndex >= 0 && w.initialIndex < len(r.initialWorkloads) && r.initialWorkloads[w.initialIndex] == w {
					r.initialWorkloads[w.initialIndex] = nil
				}
				w.cleaned = true
				w.stream = nil
				w.metadata.Release()
				w.metadata = resourcev4.Reference{}
			}
		}
		r.mu.Unlock()
	}
}

func unaryWorkloadMetadataCharge(runtimeBytes uint64, calls uint16) (resourcev4.Vector, error) {
	if calls == 0 || calls > 1024 || runtimeBytes == 0 {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	metadata := resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(unaryWorkload{})) + uint64(calls)*(uint64(unsafe.Sizeof(unaryWorkloadSlot{}))+uint64(unsafe.Sizeof(serviceCallCancellation{}))+workloadOwners*(uint64(unsafe.Sizeof(resourcev4.Request{}))+uint64(unsafe.Sizeof(resourcev4.Reference{})))) + uint64(unsafe.Sizeof(resourcev4.Request{})) + uint64(unsafe.Sizeof(resourcev4.Reference{})) + uint64(calls)*(uint64(unsafe.Sizeof(environmentResultProtection{}))+uint64(unsafe.Sizeof(rpcv4.OutgoingProtection{}))), resourcev4.Items: 2*uint64(calls) + 1, resourcev4.WorkSlots: 2 * uint64(calls), resourcev4.Tasks: uint64(calls)}
	if runtimeBytes > (math.MaxUint64/uint64(calls)-128)/2 {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	metadata, err := metadata.Add(resourcev4.Vector{resourcev4.SDKBytes: uint64(calls) * (2*runtimeBytes + 128)})
	return metadata, err
}
