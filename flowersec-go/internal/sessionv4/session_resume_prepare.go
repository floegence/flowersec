package sessionv4

import (
	"context"
	"math"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/rpcv4"
)

type resumePreparationPlan struct {
	target  *StreamOwnership
	binding ResumeStreamBinding
	token   protocolv4.ResumeToken
}

func resumePreparationCharge(runtimeBytes uint64) (resourcev4.Vector, error) {
	n, err := protocolv4.ResumeCodecBackingBytes()
	if err != nil {
		return resourcev4.Vector{}, err
	}
	n += 9345 + uint64(unsafe.Sizeof(resumePreparationPlan{})) + 2*uint64(unsafe.Sizeof(protocolv4.ResumeRequest{}))
	return (resourcev4.Vector{resourcev4.SDKBytes: n, resourcev4.Items: 2, resourcev4.WorkSlots: 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: runtimeBytes})
}

// PrepareResume uses the same operation table, original request/digest engine
// and result decoder as all prepared operations. It captures a qualification
// before generating the recovery id and performs no I/O or stream creation.
func (r *RPCServices) PrepareResume(ctx context.Context, core *SessionCore, target *StreamOwnership, binding ResumeStreamBinding, route rpcv4.ContractRoute, checkpoint protocolv4.ResumeToken, options rpcv4.UnaryPreparation, decode UnaryResultDecoder) (*StreamOperation, error) {
	if r == nil || core == nil || core.plan == nil || decode == nil || target == nil {
		return nil, cryptov4.ErrConfiguration
	}
	core.plan.mu.Lock()
	valid := !core.plan.closed && core.plan.rpc == r
	core.plan.mu.Unlock()
	if !valid {
		return nil, cryptov4.ErrConfiguration
	}
	method, _, err := route.Policy()
	if err != nil {
		return nil, err
	}
	if method != binding.Method {
		return nil, rpcv4.ErrMethod
	}
	plan, err := r.resultPlan(decode)
	if err != nil {
		return nil, err
	}
	x := &resumePreparationPlan{target: target, binding: binding, token: checkpoint}
	o, err := r.prepareUnaryEncoding(ctx, route, nil, options, ApplicationShort, false, nil, plan, nil, &streamPreparationPlan{core: core, kind: binding.Kind, resume: x})
	if err != nil {
		return nil, err
	}
	return &StreamOperation{owner: o}, nil
}

func prepareResumeRequest(route rpcv4.ContractRoute, options rpcv4.UnaryPreparation, token protocolv4.ResumeToken, target *resumeTarget, request, routeBacking resourcev4.Reference) (_ *rpcv4.PreparedRequest, err error) {
	codec, err := protocolv4.NewResumeCodec()
	if err != nil {
		return nil, err
	}
	var payload [9345]byte
	defer clear(payload[:])
	claims := token.Claims()
	if claims.Generation == math.MaxUint64 {
		return nil, rpcv4.ErrConfiguration
	}
	n, err := codec.EncodeResult(payload[:], protocolv4.ResumeResult{Status: 0, HasProgress: true, Checkpoint: claims.Checkpoint, Generation: claims.Generation + 1})
	if err != nil {
		return nil, err
	}
	if uint64(n) > uint64(options.ResponseLimitBytes) {
		return nil, rpcv4.ErrCapacity
	}
	target.checkpoint, target.generation = claims.Checkpoint, claims.Generation
	n, err = codec.EncodeRequest(payload[:], protocolv4.ResumeRequest{Token: token, TransportContext: target.target.TransportContext, StreamID: target.target.StreamID})
	if err != nil {
		return nil, err
	}
	p, err := rpcv4.BeginResumePreparation(route, uint32(n), options, request, routeBacking)
	if err != nil {
		return nil, err
	}
	if err = p.FinalizePayload(payload[:n]); err != nil {
		p.Close()
		return nil, err
	}
	return p, nil
}
