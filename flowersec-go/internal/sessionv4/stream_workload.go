package sessionv4

import (
	"context"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// This internal composition admits streaming on one fixed Session. Explicit
// preacceptance and queued OPEN consume the same original transport floor;
// both retain the call's own result, Completion and delivery responsibility.
func (r *RPCServices) reserveStreamingWorkload(core *SessionCore, method UnaryMethodDefinition, kind string, metadata []byte, requestBytes, itemBytes uint32, calls uint16) (*unaryWorkload, error) {
	if r == nil || core == nil || core.plan == nil || checkStreamWorkloadTarget(kind, metadata) != nil {
		return nil, cryptov4.ErrConfiguration
	}
	p := core.plan
	p.mu.Lock()
	valid := !p.closed && p.rpc == r && serviceStreamGeometry(p.config.Streams)
	p.mu.Unlock()
	if !valid {
		return nil, cryptov4.ErrConfiguration
	}
	return r.reserveMethodWorkloadAdmission(method, requestBytes, itemBytes, calls, nil, &streamPreparationPlan{core: core, kind: kind, metadata: metadata})
}

func streamWorkloadCharges(r *RPCServices, method UnaryMethodDefinition, policy protocolv4.ServiceContractPolicy, requestBytes, itemBytes uint32, stream *streamPreparationPlan) (charges [workloadOwners]resourcev4.Vector, err error) {
	return streamWorkloadChargesWithTask(r.runtimeBytes, r.hashRuntimeBytes, method, policy, requestBytes, itemBytes, stream, r.plan.executor.TaskCharge(), r.plan.executor.CompletionFloorCharge())
}

func streamWorkloadChargesWithTask(runtimeBytes, hashRuntimeBytes uint64, method UnaryMethodDefinition, policy protocolv4.ServiceContractPolicy, requestBytes, itemBytes uint32, stream *streamPreparationPlan, task, completion resourcev4.Vector) (charges [workloadOwners]resourcev4.Vector, err error) {
	if policy.Shape != 1 || stream == nil || method.Decode == nil || policy.MaxItemCount == 0 || policy.MaxStreamPayloadBytes == 0 || policy.StreamDurationMS == 0 || itemBytes < policy.MinResponseBytes || itemBytes > policy.MaxResponseBytes || policy.Semantics == 1 && hashRuntimeBytes == 0 {
		return charges, cryptov4.ErrConfiguration
	}
	encoded := requestBytes
	var codec *SynchronousUnaryCodec
	if method.Codec.Encode != nil {
		codec, encoded = &method.Codec, method.Codec.MaxEncodedBytes
	}
	if encoded > policy.RequestMaxBytes {
		return charges, cryptov4.ErrConfiguration
	}
	charges[workloadRoute], err = rpcv4.ContractRouteCharge(runtimeBytes)
	if err != nil {
		return
	}
	prepared, count, err := preparedOperationChargesWithTask(runtimeBytes, encoded, requestBytes, codec, stream, task, true)
	if err != nil {
		return charges, err
	}
	copy(charges[workloadPreparation:workloadCall], prepared[:count])
	config := StreamMessagesConfig{HashRuntimeBytes: hashRuntimeBytes, RuntimeBytes: runtimeBytes}
	charges[workloadCall], err = streamMessagesBackingCharge(config, max(itemBytes, 256), encoded, true)
	if err == nil {
		charges[workloadCall+1], err = rpcv4.ContractRouteCharge(runtimeBytes)
	}
	if err == nil {
		charges[workloadCall+2], err = protocolv4.CredentialSubscriptionsCharge().Add(resourcev4.Vector{resourcev4.SDKBytes: runtimeBytes})
	}
	charges[workloadCompletion] = completion
	if err == nil {
		charges[workloadAuthority], err = protocolv4.DeliverySubscriptionFloorCharge().Add(resourcev4.Vector{resourcev4.SDKBytes: runtimeBytes})
	}
	if err == nil {
		charges[workloadDependencies], err = resourcev4.BorrowPoolCharge(workloadDependencyPositions(policy.Shape))
	}
	return
}

// Preparation has already selected this target. Start moves its original
// result/route/delivery vector and borrows the original Completion descriptor;
// the same transport factory consumes its receive, OPEN and provider floors.
func (r *RPCServices) beginWorkloadStream(ctx context.Context, binding *streamOperationState, route rpcv4.ContractRoute, h protocolv4.ApplicationHeader, payload []byte, deadline *timev4.Deadline, result *unaryResultPlan, dependencies *applicationDependencies) (*StreamMessages, error) {
	s := binding.workload
	if s == nil || binding.resume != nil || h.Fields().AdmissionMode > 1 || result == nil {
		return nil, cryptov4.ErrConfiguration
	}
	contract, err := route.StreamContract()
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	if r.closed || r.retired || r.plan == nil || s.workload.services != r || !s.used || s.closed || s.index >= len(r.workloadSlots) || r.workloadSlots[s.index] != s {
		r.mu.Unlock()
		return nil, cryptov4.ErrClosed
	}
	plan := r.plan
	config := StreamMessagesConfig{environment: result.environment, resultPosition: s.result, networkPosition: s.network, transportFloor: s.transport,
		dependencies: dependencies, HardDeadline: deadline, Request: h, HashRuntimeBytes: r.hashRuntimeBytes, RuntimeBytes: r.runtimeBytes, RouteRuntimeBytes: r.runtimeBytes,
		Result: &StreamResultConfig{Executor: plan.executor, Decode: result.decode, completionFloor: s.completion, dependencyFloor: s.references}}
	var refs [3]resourcev4.Reference
	err = resourcev4.CheckoutProtectedBatch(s.owners[workloadCall:workloadCall+len(refs)], refs[:])
	r.mu.Unlock()
	if err != nil {
		return nil, err
	}
	defer func() {
		for _, ref := range refs {
			ref.Release()
		}
	}()
	_, authority, err := plan.queryAuthorization()
	if err != nil {
		return nil, err
	}
	delivery, err := authority.ForkDeliveryWithFloor(refs[2], s.authority)
	if err != nil {
		return nil, err
	}
	config.RouteReservation = refs[1]
	stream, err := binding.core.BeginStreamMessages(ctx, binding.kind, binding.metadata, payload, contract, config, refs[0], delivery)
	if err != nil {
		delivery.Close(err)
	}
	return stream, err
}

func checkStreamWorkloadTarget(kind string, metadata []byte) error {
	kindLimit, err := protocolv4.FieldByteLimit("OPEN_STREAM", "kind")
	if err != nil || !canonicalStreamHandlerKind(kind) || len(kind) > kindLimit || len(metadata) > 4096 {
		return cryptov4.ErrConfiguration
	}
	return nil
}
