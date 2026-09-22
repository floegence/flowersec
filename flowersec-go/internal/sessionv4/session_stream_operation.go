package sessionv4

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

// StreamOperation shares the original bounded prepared-operation table with
// unary calls. Preparation performs no OPEN or initial publication. Every
// successful Start returns this operation's same dedicated StreamMessages.
type StreamOperation struct{ owner *UnaryOperation }

type streamPreparationPlan struct {
	notify   bool
	resume   *resumePreparationPlan
	core     *SessionCore
	kind     string
	metadata []byte
}

type streamOperationState struct {
	resume   *resumeTarget
	core     *SessionCore
	kind     string
	metadata []byte
	messages *StreamMessages
}

type StreamStartResult struct {
	Stream      *StreamMessages
	NotAdmitted bool
	Error       error
}

// PrepareStreamOperation snapshots a trusted local stream binding and complete
// initial encoding. A peer cannot select an implementation by inventing kind,
// metadata or contract fields; the caller supplies its registered local route.
func (r *RPCServices) PrepareStreamOperation(ctx context.Context, core *SessionCore, route rpcv4.ContractRoute, kind string, metadata, payload []byte, options rpcv4.StreamPreparation, decode UnaryResultDecoder) (*StreamOperation, error) {
	return r.prepareStreamOperation(ctx, core, route, kind, metadata, payload, options, ApplicationShort, nil, decode)
}

// PrepareEncodedStreamOperation runs one original synchronous request encoder
// before returning a prepared operation. It opens no Stream and uses the same
// immutable request, deadline, Start gate and result engine as encoded input.
func (r *RPCServices) PrepareEncodedStreamOperation(ctx context.Context, core *SessionCore, route rpcv4.ContractRoute, kind string, metadata, input []byte, options rpcv4.StreamPreparation, class ApplicationWorkClass, codec SynchronousUnaryCodec, decode UnaryResultDecoder) (*StreamOperation, error) {
	return r.prepareStreamOperation(ctx, core, route, kind, metadata, input, options, class, &codec, decode)
}

func (r *RPCServices) prepareStreamOperation(ctx context.Context, core *SessionCore, route rpcv4.ContractRoute, kind string, metadata, payload []byte, options rpcv4.StreamPreparation, class ApplicationWorkClass, codec *SynchronousUnaryCodec, decode UnaryResultDecoder) (*StreamOperation, error) {
	if r == nil || core == nil || core.plan == nil || decode == nil {
		return nil, cryptov4.ErrConfiguration
	}
	kindLimit, err := protocolv4.FieldByteLimit("OPEN_STREAM", "kind")
	if err != nil {
		return nil, err
	}
	metadataLimit, err := protocolv4.FieldByteLimit("OPEN_STREAM", "metadata")
	if err != nil {
		return nil, err
	}
	if len(kind) == 0 || len(kind) > kindLimit || len(metadata) > metadataLimit {
		return nil, cryptov4.ErrConfiguration
	}
	core.plan.mu.Lock()
	valid := !core.plan.closed && core.plan.rpc == r
	core.plan.mu.Unlock()
	if !valid {
		return nil, cryptov4.ErrConfiguration
	}
	plan, err := r.resultPlan(decode)
	if err != nil {
		return nil, err
	}
	o, err := r.prepareUnaryEncoding(ctx, route, payload, options.RequestOptions(), class, false, nil, plan, codec, &streamPreparationPlan{core: core, kind: kind, metadata: metadata})
	if err != nil {
		return nil, err
	}
	return &StreamOperation{owner: o}, nil
}

func (s *StreamOperation) Start(ctx context.Context, sessions ...*SessionCore) StreamStartResult {
	if s == nil || s.owner == nil || ctx == nil {
		return StreamStartResult{Error: cryptov4.ErrConfiguration}
	}
	application, contextErr := checkApplicationContext(ctx)
	o := s.owner
	o.mu.Lock()
	defer o.mu.Unlock()
	x := o.stream
	if x == nil {
		return StreamStartResult{Error: cryptov4.ErrConfiguration}
	}
	if len(sessions) > 1 || len(sessions) == 1 && (x.resume == nil || !x.resume.sameSession(sessions[0])) {
		return StreamStartResult{NotAdmitted: true, Error: ErrOpenAssociation}
	}
	if o.started {
		return StreamStartResult{Stream: x.messages, Error: o.failure}
	}
	if contextErr != nil {
		return StreamStartResult{NotAdmitted: true, Error: contextErr}
	}
	if o.preparing {
		return StreamStartResult{NotAdmitted: true, Error: rpcv4.ErrPreparationIncomplete}
	}
	if o.closed || o.detached || x == nil {
		return StreamStartResult{Error: cryptov4.ErrClosed}
	}
	if application && o.header.Fields().AdmissionMode == 0 {
		return StreamStartResult{NotAdmitted: true, Error: ErrApplicationDependency}
	}
	if err := o.dependencies.checkOrigin(); err != nil {
		return StreamStartResult{NotAdmitted: true, Error: err}
	}
	var stream *StreamMessages
	err := o.request.WithStart(ctx, func(route rpcv4.ContractRoute, h protocolv4.ApplicationHeader, _, payload []byte) error {
		if x.resume != nil {
			if err := x.resume.check(x.core); err != nil {
				return err
			}
		}
		deadline, err := o.request.StartDeadline()
		if err != nil {
			return err
		}
		stream, err = o.services.beginPreparedStream(ctx, x, route, h, payload, deadline, o.resultPlan.decode, &o.dependencies)
		return err
	})
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrApplicationDependency) || errors.Is(err, ErrCompletionDependency) || o.header.Fields().AdmissionMode == 1 && (preacceptedStartMiss(err) || errors.Is(err, cryptov4.ErrCapacity) || errors.Is(err, resourcev4.ErrCapacity) || errors.Is(err, rpcv4.ErrCapacity)) {
			return StreamStartResult{NotAdmitted: true, Error: err}
		}
		if errors.Is(err, timev4.ErrPending) {
			return StreamStartResult{Error: err}
		}
		o.started, o.failure = true, err
		o.request.Close()
		o.request, o.resultPlan = nil, nil
		x.core, x.kind, x.metadata = nil, "", nil
		o.detachLocked()
		return StreamStartResult{Error: err}
	}
	o.started, x.messages = true, stream
	o.request.Close()
	o.request, o.resultPlan = nil, nil
	o.dependencies.release()
	x.core, x.kind, x.metadata = nil, "", nil
	return StreamStartResult{Stream: stream}
}

// beginPreparedStream reserves only the exact original general stream vector.
// The shared root performs one atomic batch before any native/OPEN side effect.
func (r *RPCServices) beginPreparedStream(ctx context.Context, binding *streamOperationState, route rpcv4.ContractRoute, h protocolv4.ApplicationHeader, payload []byte, deadline *timev4.Deadline, decode UnaryResultDecoder, dependencies *applicationDependencies) (*StreamMessages, error) {
	var contract *protocolv4.ServiceContract
	var err error
	if binding.resume != nil {
		contract, err = route.ResumeContract()
	} else {
		contract, err = route.StreamContract()
	}
	if err != nil {
		return nil, err
	}
	_, policy, err := route.Policy()
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	if r.closed || r.retired || r.plan == nil || r.plan.executor == nil || r.callSerial == math.MaxUint64 {
		r.mu.Unlock()
		return nil, cryptov4.ErrClosed
	}
	plan := r.plan
	config := StreamMessagesConfig{dependencies: dependencies, HardDeadline: deadline, Request: h, HashRuntimeBytes: r.hashRuntimeBytes, RuntimeBytes: r.runtimeBytes, RouteRuntimeBytes: r.runtimeBytes, Result: &StreamResultConfig{Executor: plan.executor, Decode: decode}}
	config.resume = binding.resume != nil
	var charges [4]resourcev4.Vector
	charges[0], err = StreamMessagesCharge(policy, config)
	if err == nil {
		charges[1], err = rpcv4.ContractRouteCharge(r.runtimeBytes)
	}
	if err == nil {
		charges[2], err = protocolv4.CredentialSubscriptionsCharge().Add(resourcev4.Vector{resourcev4.SDKBytes: r.runtimeBytes})
	}
	charges[3] = plan.executor.CompletionFloorCharge()
	if err != nil {
		r.mu.Unlock()
		return nil, err
	}
	r.callSerial++
	var seed [56]byte
	copy(seed[:16], "rpc-stream/v4/")
	copy(seed[16:32], r.owner.Instance[:])
	copy(seed[32:48], r.owner.Backing[:])
	binary.BigEndian.PutUint64(seed[48:], r.callSerial)
	digest := sha256.Sum256(seed[:])
	var requests [4]resourcev4.Request
	var refs [4]resourcev4.Reference
	for j, charge := range charges {
		owner := r.owner
		copy(owner.Instance[:], digest[:16])
		copy(owner.Backing[:], digest[16:])
		owner.Backing[0] ^= byte(j)
		requests[j] = resourcev4.Request{Owner: owner, Charge: charge, Accounts: r.accounts[:r.accountCount], ResultOwner: j == 0}
	}
	err = r.root.ReserveBatch(requests[:], refs[:])
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
	delivery, err := authority.ForkDelivery(refs[2])
	if err != nil {
		return nil, err
	}
	config.RouteReservation, config.Result.CompletionReservation = refs[1], refs[3]
	var stream *StreamMessages
	if binding.resume != nil {
		stream, err = binding.core.beginResumeMessages(ctx, binding.resume, payload, contract, config, refs[0], delivery)
	} else {
		stream, err = binding.core.BeginStreamMessages(ctx, binding.kind, binding.metadata, payload, contract, config, refs[0], delivery)
	}
	if err != nil {
		delivery.Close(err)
	}
	return stream, err
}

func (s *StreamOperation) Close() {
	if s != nil && s.owner != nil {
		s.owner.Close()
	}
}
