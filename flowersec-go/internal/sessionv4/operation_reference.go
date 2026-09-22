package sessionv4

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"math"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

// ReadOperationResult starts one new ordinary result-read request against the
// configured accepting Session. Its result shares UnaryCall's existing single
// typed/encoded consumption gate. It never joins a management position, creates
// an execution, replays a request or recovers the old operation handle.
func (r *RPCServices) ReadOperationResult(ctx context.Context, ref protocolv4.OperationReference, deadlineMS uint64, decode UnaryResultDecoder) (*UnaryCall, error) {
	if ctx == nil {
		return nil, rpcv4.ErrConfiguration
	}
	if _, err := r.referenceTarget(ref); err != nil {
		return nil, err
	}
	if ref.CallShape() != 0 {
		return nil, rpcv4.ErrExecutionUnsupported
	}
	plan, err := r.resultPlan(decode)
	if err != nil {
		return nil, err
	}
	if _, err = checkApplicationContext(ctx); err != nil {
		return nil, err
	}
	r.mu.Lock()
	if r.closed || r.retired || r.referenceCodec == nil || r.resultReadBinding.Type == 0 || r.callSerial == math.MaxUint64 {
		r.mu.Unlock()
		return nil, rpcv4.ErrClosed
	}
	// The bounded encoding scratch belongs to this call before construction;
	// the codec's original shared backing is retained through its actual use.
	r.callSerial++
	var seed [56]byte
	copy(seed[:16], "reference-read4/")
	copy(seed[16:32], r.owner.Instance[:])
	copy(seed[32:48], r.owner.Backing[:])
	binary.BigEndian.PutUint64(seed[48:], r.callSerial)
	digest := sha256.Sum256(seed[:])
	owner := r.owner
	copy(owner.Instance[:], digest[:16])
	copy(owner.Backing[:], digest[16:])
	charge := resourcev4.Vector{resourcev4.SDKBytes: 2048 + r.runtimeBytes, resourcev4.Items: 1}
	reservation, err := r.root.Reserve(owner, charge, r.accounts[:r.accountCount]...)
	if err != nil {
		r.mu.Unlock()
		return nil, err
	}
	shared, err := r.refs[rpcServicesMetadata].Borrow()
	codec, binding := r.referenceCodec, r.resultReadBinding
	r.mu.Unlock()
	defer reservation.Release()
	if err != nil {
		return nil, err
	}
	defer shared.Release()
	var header [512]byte
	var payload [1024]byte
	defer clear(header[:])
	defer clear(payload[:])
	h, hn, pn, err := codec.EncodeResultRead(header[:], payload[:], ref, binding.Type, binding.Contract, deadlineMS)
	if err != nil {
		return nil, err
	}
	return r.beginUnary(ctx, rpcv4.ContractRoute{}, h, header[:hn], payload[:pn], ApplicationResident, false, false, nil, plan, nil, true)
}

// Reference returns the immutable query locator captured before the prepared
// operation was delivered. It survives local Close and Session termination and
// cannot reconstruct Start, payload delivery or the old operation's ownership.
func (o *UnaryOperation) Reference() (protocolv4.OperationReference, error) {
	if o == nil {
		return protocolv4.OperationReference{}, rpcv4.ErrOwner
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.reference.Valid() {
		return protocolv4.OperationReference{}, rpcv4.ErrExecutionUnsupported
	}
	return o.reference, nil
}

func (o *StreamOperation) Reference() (protocolv4.OperationReference, error) {
	if o == nil || o.owner == nil {
		return protocolv4.OperationReference{}, rpcv4.ErrOwner
	}
	return o.owner.Reference()
}

// referenceTarget only resolves the configured local domain. A saved locator
// supplies no trust root, endpoint, credentials or authority. Imported claims
// (including mode/cancellation) remain untrusted and the remote owner checks
// the actual original contract on every independently authorized request.
func (r *RPCServices) referenceTarget(ref protocolv4.OperationReference) (rpcv4.ExecutionTarget, error) {
	if r == nil || !ref.Valid() {
		return rpcv4.ExecutionTarget{}, rpcv4.ErrOwner
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.retired {
		return rpcv4.ExecutionTarget{}, rpcv4.ErrClosed
	}
	if r.referenceDomain == "" || ref.TargetDomain() != r.referenceDomain {
		return rpcv4.ExecutionTarget{}, rpcv4.ErrAssociation
	}
	t := ref.Target()
	return rpcv4.ExecutionTarget{Service: rpcv4.ExecutionService{Tenant: t.Tenant, Audience: t.Audience, Namespace: t.Namespace}, Caller: rpcv4.ExecutionPrincipal{Authority: t.Authority, Subject: t.Subject}, Operation: t.Operation, RequestDigest: t.RequestDigest, ContractDigest: t.ContractDigest}, nil
}

// QueryReference uses one existing management request. Its cancellation owns
// only this wait; it cannot locate, close, retry or resurrect a local handle.
// Access comes from the current trusted Session/application grant, including
// explicit delegation where configured; the original caller key is preserved.
func (r *RPCServices) QueryReference(ctx context.Context, ref protocolv4.OperationReference, deadline *timev4.Deadline, access rpcv4.ExecutionAccess) (rpcv4.ManagementResponse, error) {
	target, err := r.referenceTarget(ref)
	if err != nil {
		return rpcv4.ManagementResponse{}, err
	}
	return r.ManagementRequest(ctx, false, target, deadline, access)
}

func (r *RPCServices) RequestReferenceCancel(ctx context.Context, ref protocolv4.OperationReference, deadline *timev4.Deadline, access rpcv4.ExecutionAccess) (rpcv4.ManagementResponse, error) {
	target, err := r.referenceTarget(ref)
	if err != nil {
		return rpcv4.ManagementResponse{}, err
	}
	if ref.CancelMode() != 1 {
		return rpcv4.ManagementResponse{}, rpcv4.ErrExecutionUnsupported
	}
	return r.ManagementRequest(ctx, true, target, deadline, access)
}
