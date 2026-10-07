package sessionv4

import (
	"context"
	"math"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// UnaryMethodDefinition is trusted local codec/scheduling policy. Its digest
// selects exactly one already installed contract; it cannot install a route or
// extend the Session's admitted application profile.
type UnaryMethodDefinition struct {
	workload     *unaryWorkload
	bindingOffer protocolv4.AdmissionOfferBounds
	Contract     [32]byte
	WorkClass    ApplicationWorkClass
	Codec        SynchronousUnaryCodec
	Decode       UnaryResultDecoder
	// Nonzero defaults are explicit; the flag also permits an explicit zero.
	// These local binding options never enter the stable contract digest.
	DefaultResponseLimitBytes    uint32
	ExplicitDefaultResponseLimit bool
	// These immutable local guarantees are checked at Bind and before codec
	// entry. Per-call options may strengthen them but never weaken them.
	RequireExecution, RequireDurable bool
}

func (m UnaryMethodDefinition) responseLimit(policy protocolv4.ServiceContractPolicy, options rpcv4.UnaryPreparation) (uint32, error) {
	return rpcv4.SelectResponseLimit(policy, options.ResponseLimitBytes, options.ExplicitResponseLimit || options.ResponseLimitBytes != 0,
		m.DefaultResponseLimitBytes, m.ExplicitDefaultResponseLimit || m.DefaultResponseLimitBytes != 0)
}

func (m UnaryMethodDefinition) checkExecutionPolicy(policy protocolv4.ServiceContractPolicy) error {
	if (m.RequireExecution || m.RequireDurable) && policy.Semantics != 1 || m.RequireDurable && policy.ExecutionMode != 1 {
		return protocolv4.ErrRequiredGuaranteeUnavailable
	}
	return nil
}

// ValidateUnaryMethod checks the current exact registration and immutable local
// default without encoding, reserving a result, opening a channel or querying.
func (s *EnvironmentSession) ValidateUnaryMethod(method UnaryMethodDefinition) error {
	core, err := s.Core()
	if err != nil {
		return err
	}
	core.plan.mu.Lock()
	r, closed := core.plan.rpc, core.plan.closed
	core.plan.mu.Unlock()
	if closed {
		return cryptov4.ErrClosed
	}
	return r.ValidateUnaryMethod(method)
}

func (r *RPCServices) ValidateUnaryMethod(method UnaryMethodDefinition) error {
	if r == nil || method.Decode == nil || method.Contract == ([32]byte{}) || method.WorkClass > ApplicationResident {
		return cryptov4.ErrConfiguration
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.retired {
		return cryptov4.ErrClosed
	}
	if r.draining.Load() {
		return ErrSessionDraining
	}
	if r.routes == nil {
		return cryptov4.ErrNotReady
	}
	_, policy, err := r.routes.RegisteredContractPolicy(method.Contract)
	if err != nil {
		return err
	}
	if policy.Shape != 0 {
		return rpcv4.ErrMethod
	}
	if err := method.checkExecutionPolicy(policy); err != nil {
		return err
	}
	_, err = method.responseLimit(policy, rpcv4.UnaryPreparation{})
	return err
}

func (s *EnvironmentSession) PrepareUnary(ctx context.Context, method UnaryMethodDefinition, input []byte, options rpcv4.UnaryPreparation) (*UnaryOperation, error) {
	core, err := s.Core()
	if err != nil {
		return nil, err
	}
	return core.PrepareUnary(ctx, method, input, options)
}

func (c *SessionCore) PrepareUnary(ctx context.Context, method UnaryMethodDefinition, input []byte, options rpcv4.UnaryPreparation) (*UnaryOperation, error) {
	if c == nil || c.plan == nil || ctx == nil {
		return nil, cryptov4.ErrConfiguration
	}
	c.plan.mu.Lock()
	r, closed := c.plan.rpc, c.plan.closed
	c.plan.mu.Unlock()
	if closed {
		return nil, cryptov4.ErrClosed
	}
	if r == nil {
		return nil, cryptov4.ErrNotReady
	}
	return r.PrepareMethod(ctx, method, input, options)
}

// PrepareMethod captures and charges the original exact route before codec
// entry. Preparation and Start keep the same request and result owners.
func (r *RPCServices) PrepareMethod(ctx context.Context, method UnaryMethodDefinition, input []byte, options rpcv4.UnaryPreparation) (*UnaryOperation, error) {
	if method.Decode == nil {
		return nil, cryptov4.ErrConfiguration
	}
	if method.workload != nil {
		return method.workload.prepare(ctx, r, method, input, options)
	}
	route, _, options, err := r.prepareMethodRoute(ctx, method, options, 0)
	if err != nil {
		return nil, err
	}
	defer route.Release()
	if method.Codec.Encode != nil {
		if method.WorkClass == ApplicationShort {
			return r.PrepareEncodedShortUnaryResult(ctx, route, input, options, method.Codec, method.Decode)
		}
		return r.PrepareEncodedUnaryResult(ctx, route, input, options, method.WorkClass, method.Codec, method.Decode)
	}
	if method.WorkClass == ApplicationShort {
		return r.PrepareShortUnaryResult(ctx, route, input, options, method.Decode)
	}
	return r.PrepareUnaryResult(ctx, route, input, options, method.WorkClass, method.Decode)
}

// Snapshot contains only facts held by the original operation and result.
// Accepted is local SDK admission, never proof of remote execution.
type UnaryOperationSnapshot struct {
	Started, Closed, CleanupComplete bool
	Result                           UnaryResultStatus
	Failure                          error
}

func (o *UnaryOperation) Snapshot() UnaryOperationSnapshot {
	if o == nil {
		return UnaryOperationSnapshot{Closed: true, Failure: cryptov4.ErrClosed}
	}
	o.mu.Lock()
	s := UnaryOperationSnapshot{Started: o.started, Closed: o.closed, Failure: o.failure, Result: UnaryResultStatus{Request: o.header, Reference: o.reference}}
	reference := o.reference
	call, preparing, detached := o.call, o.preparing, o.detached
	var stream *StreamMessages
	var submission *rpcv4.NotifySubmission
	if o.stream != nil {
		stream = o.stream.messages
	}
	if o.notify != nil {
		submission = o.notify.submission
	}
	o.mu.Unlock()
	s.CleanupComplete = !preparing && detached && call == nil
	if call != nil {
		s.Result = call.ResultStatus()
		s.Result.Reference = reference
		s.CleanupComplete = !preparing && detached && call.routesCleaned()
	}
	if stream != nil {
		if stream.resumeExchange {
			s.Result = stream.resumeResultStatus()
			s.Result.Reference = reference
			s.CleanupComplete = !preparing && detached && s.Result.CleanupComplete
		} else {
			s.CleanupComplete = !preparing && detached && stream.Status().CleanupComplete
		}
	}
	if submission != nil {
		select {
		case <-submission.Done():
			s.CleanupComplete = !preparing && detached
		default:
			s.CleanupComplete = false
		}
	}
	return s
}

func (o *UnaryOperation) resultCall() (*UnaryCall, error) {
	if o == nil {
		return nil, cryptov4.ErrClosed
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.call != nil {
		return o.call, nil
	}
	if o.failure != nil {
		return nil, o.failure
	}
	if o.closed {
		return nil, cryptov4.ErrClosed
	}
	return nil, ErrUnaryNotStarted
}

func (o *UnaryOperation) WaitResultStatus(ctx context.Context) (UnaryResultStatus, error) {
	if m := o.resumeMessages(); m != nil {
		_, err := m.WaitStatus(ctx)
		return o.resumeStatus(m), err
	}
	call, err := o.resultCall()
	if err != nil {
		return o.Snapshot().Result, err
	}
	s, err := call.WaitStatus(ctx)
	if err != nil {
		s = call.ResultStatus()
	}
	s.Reference, _ = o.Reference()
	return s, err
}

func (o *UnaryOperation) TakeResult(ctx context.Context) (any, UnaryResultStatus, error) {
	if m := o.resumeMessages(); m != nil {
		value, _, err := m.ReadNext(ctx)
		return value, o.resumeStatus(m), resumeResultError(err)
	}
	call, err := o.resultCall()
	if err != nil {
		return nil, o.Snapshot().Result, err
	}
	value, status, err := call.TakeResult(ctx)
	status.Reference, _ = o.Reference()
	return value, status, err
}

func (o *UnaryOperation) TakeEncodedResult(ctx context.Context) ([]byte, UnaryResultStatus, error) {
	if m := o.resumeMessages(); m != nil {
		value, _, err := m.ReadNextEncoded(ctx)
		return value, o.resumeStatus(m), resumeResultError(err)
	}
	call, err := o.resultCall()
	if err != nil {
		return nil, o.Snapshot().Result, err
	}
	value, status, err := call.TakeEncodedResult(ctx)
	status.Reference, _ = o.Reference()
	return value, status, err
}

// Cancel stops local input/output interest using the original call context.
// It is separate from a business RequestCancel on an execution reference.
func (o *UnaryOperation) Cancel() {
	if o == nil {
		return
	}
	if m := o.resumeMessages(); m != nil {
		m.Close()
		return
	}
	o.mu.Lock()
	cancel := o.cancel
	o.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (o *UnaryOperation) CleanupSnapshot() protocolv4.V4CleanupStatus {
	s := o.Snapshot()
	status := protocolv4.V4CleanupStatus{Status: protocolv4.V4CleanupStatePending, CoreCleanup: protocolv4.V4CoreCleanupPending}
	if s.Result.DecoderRunning {
		status.PendingCallbacks = 1
	}
	if s.CleanupComplete {
		status.Status, status.CoreCleanup = protocolv4.V4CleanupStateComplete, protocolv4.V4CoreCleanupComplete
	}
	return status
}

// ReferenceManagement uses current authenticated Session authority. A saved
// reference supplies only the target, never access or a replacement owner.
func (s *EnvironmentSession) ReferenceManagement(ctx context.Context, ref protocolv4.OperationReference, cancel bool, timeoutMS uint64) (rpcv4.ManagementResponse, error) {
	core, err := s.Core()
	if err != nil {
		return rpcv4.ManagementResponse{}, err
	}
	core.plan.mu.Lock()
	r := core.plan.rpc
	core.plan.mu.Unlock()
	return r.referenceManagement(ctx, ref, cancel, timeoutMS)
}

func (r *RPCServices) referenceManagement(ctx context.Context, ref protocolv4.OperationReference, cancel bool, timeoutMS uint64) (response rpcv4.ManagementResponse, err error) {
	diagnosticOperation := diagnosticOperationFromContext(ctx)
	ownedDiagnostic := diagnosticOperationOwnedFromContext(ctx)
	if !ownedDiagnostic {
		diagnosticOperation = nil
	}
	if diagnosticOperation == nil && r != nil && r.plan != nil {
		diagnosticOperation = r.plan.beginApplicationDiagnostic()
		ownedDiagnostic = true
	}
	defer func() {
		if ownedDiagnostic {
			finishApplicationDiagnosticError(diagnosticOperation, err)
		}
	}()
	if ctx == nil || timeoutMS == 0 || timeoutMS > 30000 {
		return rpcv4.ManagementResponse{}, cryptov4.ErrConfiguration
	}
	target, err := r.referenceTarget(ref)
	if err != nil {
		return rpcv4.ManagementResponse{}, err
	}
	if cancel && ref.CancelMode() != 1 {
		return rpcv4.ManagementResponse{}, rpcv4.ErrExecutionUnsupported
	}
	r.mu.Lock()
	backing := r.refs[rpcServicesMetadata]
	retained, err := backing.Borrow()
	plan, clock := r.plan, r.clock
	r.mu.Unlock()
	if err != nil {
		return rpcv4.ManagementResponse{}, err
	}
	defer retained.Release()
	if plan == nil {
		return rpcv4.ManagementResponse{}, cryptov4.ErrClosed
	}
	lease, endpoint, err := plan.queryAuthorization()
	if err != nil {
		return rpcv4.ManagementResponse{}, err
	}
	// The call retains an alias, but the wire owner must borrow from the
	// original primary for a response association that can outlive this wait.
	access := &managementHistoryAuthority{lease: lease, endpoint: endpoint, backing: backing, target: target, cancel: cancel}
	deadline, err := timev4.NewAge(clock, timeoutMS, math.MaxUint64)
	if err != nil {
		return rpcv4.ManagementResponse{}, err
	}
	ownedDiagnostic = false
	return r.managementRequestWithDiagnostic(ctx, cancel, target, deadline, access, diagnosticOperation)
}

func (o *UnaryOperation) RequestCancel(ctx context.Context, timeoutMS uint64) (rpcv4.ManagementResponse, error) {
	if ctx == nil {
		return rpcv4.ManagementResponse{}, cryptov4.ErrConfiguration
	}
	ref, err := o.Reference()
	if err != nil {
		return rpcv4.ManagementResponse{}, err
	}
	o.mu.Lock()
	r, operation := o.services, o.diagnosticOperation
	retained := r != nil && retainApplicationDiagnostic(operation)
	o.mu.Unlock()
	if r == nil {
		return rpcv4.ManagementResponse{}, cryptov4.ErrClosed
	}
	if !retained {
		operation = nil
	}
	return r.referenceManagement(withOwnedDiagnosticOperation(ctx, operation), ref, true, timeoutMS)
}
