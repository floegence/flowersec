package sessionv4

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"math"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
)

// Every public call shape captures the same charged exact route before codec
// entry. Neither lookup nor preparation creates a channel or queries a peer.
func (r *RPCServices) prepareMethodRoute(ctx context.Context, method UnaryMethodDefinition, options rpcv4.UnaryPreparation, shape uint8) (rpcv4.ContractRoute, protocolv4.ServiceContractPolicy, rpcv4.UnaryPreparation, error) {
	return r.prepareMethodRouteReserved(ctx, method, options, shape, resourcev4.Reference{})
}

func (r *RPCServices) prepareMethodRouteReserved(ctx context.Context, method UnaryMethodDefinition, options rpcv4.UnaryPreparation, shape uint8, reservation resourcev4.Reference) (rpcv4.ContractRoute, protocolv4.ServiceContractPolicy, rpcv4.UnaryPreparation, error) {
	if r == nil || ctx == nil || shape > 2 || method.Contract == ([32]byte{}) || method.WorkClass > ApplicationResident || method.Codec.MaxEncodedBytes > 1048576 || method.Codec.ScratchBytes > 1048576 || method.Codec.Encode == nil && (method.Codec.MaxEncodedBytes != 0 || method.Codec.ScratchBytes != 0) {
		return rpcv4.ContractRoute{}, protocolv4.ServiceContractPolicy{}, options, cryptov4.ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return rpcv4.ContractRoute{}, protocolv4.ServiceContractPolicy{}, options, err
	}
	if p := initializerPlanForApplication(ctx); p != nil {
		if p.services != r || method.workload == nil || !method.workload.initializer {
			return rpcv4.ContractRoute{}, protocolv4.ServiceContractPolicy{}, options, ErrApplicationDependency
		}
		if err := p.attempt.deadline.Check(); err != nil {
			return rpcv4.ContractRoute{}, protocolv4.ServiceContractPolicy{}, options, err
		}
		options.ParentDeadline = p.attempt.deadline
	}
	r.mu.Lock()
	if r.closed || r.retired {
		r.mu.Unlock()
		return rpcv4.ContractRoute{}, protocolv4.ServiceContractPolicy{}, options, cryptov4.ErrClosed
	}
	if r.draining.Load() {
		r.mu.Unlock()
		return rpcv4.ContractRoute{}, protocolv4.ServiceContractPolicy{}, options, ErrSessionDraining
	}
	if r.routes == nil {
		r.mu.Unlock()
		return rpcv4.ContractRoute{}, protocolv4.ServiceContractPolicy{}, options, cryptov4.ErrNotReady
	}
	if reservation == (resourcev4.Reference{}) && r.callSerial == math.MaxUint64 {
		r.mu.Unlock()
		return rpcv4.ContractRoute{}, protocolv4.ServiceContractPolicy{}, options, cryptov4.ErrCapacity
	}
	charge, err := rpcv4.ContractRouteCharge(r.runtimeBytes)
	if err != nil {
		r.mu.Unlock()
		return rpcv4.ContractRoute{}, protocolv4.ServiceContractPolicy{}, options, err
	}
	if reservation == (resourcev4.Reference{}) {
		r.callSerial++
		var seed [56]byte
		copy(seed[:16], "public-route/v4")
		copy(seed[16:32], r.owner.Instance[:])
		copy(seed[32:48], r.owner.Backing[:])
		binary.BigEndian.PutUint64(seed[48:], r.callSerial)
		hash := sha256.Sum256(seed[:])
		owner := r.owner
		copy(owner.Instance[:], hash[:16])
		copy(owner.Backing[:], hash[16:])
		reservation, err = r.root.Reserve(owner, charge, r.accounts[:r.accountCount]...)
	}
	routes, runtimeBytes := r.routes, r.runtimeBytes
	r.mu.Unlock()
	if err != nil {
		return rpcv4.ContractRoute{}, protocolv4.ServiceContractPolicy{}, options, err
	}
	defer reservation.Release()
	route, err := routes.Capture(method.Contract, reservation, runtimeBytes)
	if err != nil {
		return rpcv4.ContractRoute{}, protocolv4.ServiceContractPolicy{}, options, err
	}

	_, policy, err := route.Policy()
	if err == nil {
		err = method.checkExecutionPolicy(policy)
	}
	if err == nil && policy.Shape != shape {
		err = rpcv4.ErrMethod
	}
	if err == nil {
		if shape == 2 {
			if method.Decode != nil || method.DefaultResponseLimitBytes != 0 || options.ResponseLimitBytes != 0 {
				err = rpcv4.ErrResponseLimitUnsupported
			}
		} else {
			options.ResponseLimitBytes, err = method.responseLimit(policy, options)
		}
	}
	options.ExplicitResponseLimit = true
	options.RequireExecution = options.RequireExecution || method.RequireExecution
	options.RequireDurable = options.RequireDurable || method.RequireDurable
	if err == nil && policy.Semantics == 1 {
		if method.bindingOffer != (protocolv4.AdmissionOfferBounds{}) {
			if options.Offer != (protocolv4.AdmissionOfferBounds{}) && options.Offer != method.bindingOffer {
				route.Release()
				return rpcv4.ContractRoute{}, policy, options, rpcv4.ErrAdmissionOfferUnavailable
			}
			options.Offer = method.bindingOffer
		}
		options.Offer, err = routes.CapturePreparationOffer(policy.Digest, options.Offer)
	}
	if err != nil {
		route.Release()
		return rpcv4.ContractRoute{}, policy, options, err
	}
	return route, policy, options, nil
}

// PrepareStreaming and PrepareNotify project the original prepared-operation
// engine. Shape-specific views cannot send unary requests or consume results
// that their contract does not declare.
func (s *EnvironmentSession) PrepareStreaming(ctx context.Context, method UnaryMethodDefinition, kind string, metadata, input []byte, options rpcv4.UnaryPreparation) (*StreamOperation, error) {
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
	return r.prepareStreamingMethod(ctx, core, method, kind, metadata, input, options)
}
func (s *EnvironmentSession) PrepareNotify(ctx context.Context, method UnaryMethodDefinition, input []byte, options rpcv4.UnaryPreparation) (*NotifyOperation, error) {
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
	return r.prepareNotifyMethod(ctx, method, input, options)
}
func (r *RPCServices) prepareStreamingMethod(ctx context.Context, core *SessionCore, method UnaryMethodDefinition, kind string, metadata, input []byte, options rpcv4.UnaryPreparation) (*StreamOperation, error) {
	if method.Decode == nil {
		return nil, cryptov4.ErrConfiguration
	}
	if method.workload != nil {
		w := method.workload
		if r == nil || w.services != r {
			return nil, cryptov4.ErrConfiguration
		}
		r.mu.Lock()
		stream := w.stream
		r.mu.Unlock()
		if w.shape != 1 || stream == nil || stream.core != core || stream.kind != kind || !bytes.Equal(stream.metadata, metadata) {
			return nil, cryptov4.ErrConfiguration
		}
		owner, err := w.prepare(ctx, r, method, input, options)
		if err != nil {
			return nil, err
		}
		return &StreamOperation{owner: owner}, nil
	}
	route, _, options, err := r.prepareMethodRoute(ctx, method, options, 1)
	if err != nil {
		return nil, err
	}
	defer route.Release()
	stream := rpcv4.StreamPreparation{ParentDeadline: options.ParentDeadline, DeadlineAtMS: options.DeadlineAtMS, DefaultLifetimeMS: options.DefaultLifetimeMS, AdmissionNotAfterMS: options.AdmissionNotAfterMS,
		MaxItemBytes: options.ResponseLimitBytes, AdmissionMode: options.AdmissionMode, ExplicitAdmissionMode: options.ExplicitAdmissionMode,
		RequireExecution: options.RequireExecution, RequireDurable: options.RequireDurable, Offer: options.Offer}
	var codec *SynchronousUnaryCodec
	if method.Codec.Encode != nil {
		codec = &method.Codec
	}
	return r.prepareStreamOperation(ctx, core, route, kind, metadata, input, stream, method.WorkClass, codec, method.Decode)
}
func (r *RPCServices) prepareNotifyMethod(ctx context.Context, method UnaryMethodDefinition, input []byte, options rpcv4.UnaryPreparation) (*NotifyOperation, error) {
	if method.workload != nil {
		if method.workload.shape != 2 {
			return nil, cryptov4.ErrConfiguration
		}
		owner, err := method.workload.prepare(ctx, r, method, input, options)
		if err != nil {
			return nil, err
		}
		return &NotifyOperation{owner: owner}, nil
	}
	route, _, options, err := r.prepareMethodRoute(ctx, method, options, 2)
	if err != nil {
		return nil, err
	}
	defer route.Release()
	var codec *SynchronousUnaryCodec
	if method.Codec.Encode != nil {
		codec = &method.Codec
	}
	owner, err := r.prepareUnaryEncoding(ctx, route, input, options, method.WorkClass, false, nil, nil, codec, &streamPreparationPlan{notify: true})
	if err != nil {
		return nil, err
	}
	return &NotifyOperation{owner: owner}, nil
}
