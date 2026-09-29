package flowersec

import (
	"context"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

// V4UnaryMethod fixes the exact contract and local codec definition. Prepare
// reserves its input before Encode and TakeResult decodes on Completion.
type V4UnaryMethod = sessionv4.UnaryMethodDefinition

// V4UnaryServiceDefinition freezes one namespace and its finite typed methods.
// Binding copies these local options; later caller mutations have no effect.
type V4UnaryServiceDefinition = sessionv4.UnaryServiceDefinition
type V4UnaryServiceMethod = sessionv4.UnaryServiceMethod
type V4MethodSelector = sessionv4.UnaryMethodSelector
type V4ServiceBindOptions = sessionv4.UnaryServiceBindOptions
type V4ContractSnapshot = sessionv4.UnaryContractSnapshot
type V4ContractAcceptance = protocolv4.ContractAcceptance
type V4ContractRange = protocolv4.ContractRange

const (
	V4ContractExact   = protocolv4.ContractExact
	V4ContractBounded = protocolv4.ContractBounded
)

func V4BoundedContractAcceptance(ranges ...V4ContractRange) (V4ContractAcceptance, error) {
	return protocolv4.BoundedContractAcceptance(ranges...)
}

type V4UnaryCodec = sessionv4.SynchronousUnaryCodec
type V4UnaryResultDecoder = sessionv4.UnaryResultDecoder
type V4WorkClass = sessionv4.ApplicationWorkClass

const (
	V4WorkShort    = sessionv4.ApplicationShort
	V4WorkResident = sessionv4.ApplicationResident
)

type V4OperationOptions struct {
	DeadlineAtMS, DefaultLifetimeMS, AdmissionNotAfterMS uint64
	ResponseLimitBytes                                   uint32
	// Set ExplicitResponseLimit when selecting zero. A nonzero value is explicit.
	// Omission selects the method's local default, then its exact contract maximum.
	ExplicitResponseLimit            bool
	AdmissionMode                    uint8
	ExplicitAdmissionMode            bool
	RequireExecution, RequireDurable bool
	Offer                            V4AdmissionOffer
}
type V4AdmissionOffer = protocolv4.AdmissionOfferBounds

func (o V4OperationOptions) internal() rpcv4.UnaryPreparation {
	return rpcv4.UnaryPreparation{DeadlineAtMS: o.DeadlineAtMS, DefaultLifetimeMS: o.DefaultLifetimeMS, AdmissionNotAfterMS: o.AdmissionNotAfterMS, ResponseLimitBytes: o.ResponseLimitBytes, ExplicitResponseLimit: o.ExplicitResponseLimit, AdmissionMode: o.AdmissionMode, ExplicitAdmissionMode: o.ExplicitAdmissionMode, RequireExecution: o.RequireExecution, RequireDurable: o.RequireDurable, Offer: o.Offer}
}

// OperationReference is an immutable query locator without Start authority.
type OperationReference struct{ inner protocolv4.OperationReference }

func (r OperationReference) Valid() bool                { return r.inner.Valid() }
func (OperationReference) String() string               { return "Flowersec.OperationReference" }
func (OperationReference) GoString() string             { return "Flowersec.OperationReference" }
func (OperationReference) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

type OperationStatus string

const (
	OperationPending   OperationStatus = "pending"
	OperationAccepted  OperationStatus = "accepted"
	OperationExecuting OperationStatus = "executing"
	OperationCompleted OperationStatus = "completed"
	OperationFailed    OperationStatus = "failed"
	OperationUnknown   OperationStatus = "unknown"
)

// OperationProgress reports local admission, original request publication and
// result delivery independently. Status never infers remote execution from a
// locally flushed request or an observer's cancellation.
type OperationProgress struct {
	Status                                                            OperationStatus
	Started, Closed, ResultAvailable, ResultDelivered, DecoderRunning bool
	HeaderAccepted, MessageAccepted, Flushed, SubmissionComplete      bool
	ResultComplete, ResultAbandoned                                   bool
	ApplicationErrorCode                                              uint32
	SDKErrorCode                                                      uint64
	Err                                                               error
	Cleanup                                                           CleanupStatus
}
type Result struct {
	// Reference is valid only for an already prepared execution operation.
	// Submission and Cleanup report local facts even on cancellation/error.
	Reference            OperationReference
	Submission           NotificationSubmission
	CleanupComplete      bool
	Status               OperationStatus
	Payload              []byte
	Value                any
	ApplicationErrorCode uint32
	SDKErrorCode         uint64
	Err                  error
}
type OperationStartResult struct {
	NotAdmitted bool
	Err         error
}

// OperationHandle projects one original prepared operation. Repeated Start
// joins it; canceled waits retain its result and physical cleanup owner.
type OperationHandle struct{ inner *sessionv4.UnaryOperation }

func PrepareOperation(ctx context.Context, session *V4Session, method V4UnaryMethod, input []byte, options V4OperationOptions) (*OperationHandle, error) {
	return session.PrepareUnary(ctx, method, input, options)
}
func (s *V4Session) PrepareUnary(ctx context.Context, method V4UnaryMethod, input []byte, options V4OperationOptions) (*OperationHandle, error) {
	if s == nil || s.prepareUnary == nil || ctx == nil {
		return nil, ErrTransportUnavailable
	}
	s.mu.Lock()
	closed := s.closed
	prepare := s.prepareUnary
	s.mu.Unlock()
	if closed {
		return nil, ErrOperationClosed
	}
	inner, err := prepare(ctx, method, input, options.internal())
	if err != nil {
		return nil, err
	}
	if err := s.handoffOperation(ctx, inner.Close); err != nil {
		return nil, err
	}
	return &OperationHandle{inner: inner}, nil
}

// A Session close or canceled preparation competes with this one public
// handoff. A late encoder cannot publish an unmanageable prepared operation.
func (s *V4Session) handoffOperation(ctx context.Context, close func()) error {
	s.mu.Lock()
	err := ctx.Err()
	if s.closed {
		err = ErrOperationClosed
	}
	s.mu.Unlock()
	if err != nil {
		close()
	}
	return err
}

// V4ServiceClient captures a fixed Session and method table. It does not follow a
// controller replacement, refresh a contract implicitly, or retry a request.
type V4ServiceClient struct {
	inner *sessionv4.UnaryServiceClient
}

func (s *V4Session) BindUnaryService(ctx context.Context, definition V4UnaryServiceDefinition, options V4ServiceBindOptions) (*V4ServiceClient, error) {
	if s == nil || s.bindUnaryMethods == nil {
		return nil, ErrTransportUnavailable
	}
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if closed {
		return nil, ErrOperationClosed
	}
	client, err := s.bindUnaryMethods(ctx, definition, options)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		client.Close()
		return nil, ErrOperationClosed
	}
	return &V4ServiceClient{inner: client}, nil
}

func (c *V4ServiceClient) Contract(method V4MethodSelector) V4ContractSnapshot {
	if c == nil || c.inner == nil {
		return V4ContractSnapshot{Type: method.Type, Error: ErrOperationClosed}
	}
	if err := c.inner.SelectMethod(method); err != nil {
		return V4ContractSnapshot{Type: method.Type, Error: err}
	}
	return c.inner.Contract(method.Type)
}

// Refresh fills caller-owned output with independent method outcomes. A top
// level error means selection or aggregate work admission failed before work.
func (c *V4ServiceClient) Refresh(ctx context.Context, methods []V4MethodSelector, output []V4ContractSnapshot) error {
	if c == nil || c.inner == nil {
		return ErrOperationClosed
	}
	if len(methods) == 0 || len(methods) > 256 || len(output) != len(methods) {
		return cryptov4.ErrConfiguration
	}
	var selected [256]uint32
	for j, method := range methods {
		if err := c.inner.SelectMethod(method); err != nil {
			return err
		}
		selected[j] = method.Type
	}
	return c.inner.Refresh(ctx, selected[:len(methods)], output)
}

func (c *V4ServiceClient) UpdateContract(ctx context.Context, method V4MethodSelector, digest [32]byte) (V4ContractSnapshot, error) {
	if c == nil || c.inner == nil {
		return V4ContractSnapshot{}, ErrOperationClosed
	}
	if err := c.inner.SelectMethod(method); err != nil {
		return V4ContractSnapshot{Type: method.Type, Error: err}, err
	}
	return c.inner.UpdateContract(ctx, method.Type, digest)
}

func (c *V4ServiceClient) PrepareMethod(ctx context.Context, method V4MethodSelector, input []byte, options V4OperationOptions) (*OperationHandle, error) {
	if c == nil || c.inner == nil {
		return nil, ErrOperationClosed
	}
	if err := c.inner.SelectMethod(method); err != nil {
		return nil, err
	}
	op, err := c.inner.PrepareMethod(ctx, method.Type, input, options.internal())
	if err != nil {
		return nil, err
	}
	return &OperationHandle{inner: op}, nil
}

func (c *V4ServiceClient) DispatchMethod(ctx context.Context, method V4MethodSelector, input []byte, options V4OperationOptions) (*OperationHandle, OperationStartResult, error) {
	o, err := c.PrepareMethod(ctx, method, input, options)
	if err != nil {
		return nil, OperationStartResult{}, err
	}
	return o, o.StartContext(ctx), nil
}

func (c *V4ServiceClient) CallMethod(ctx context.Context, method V4MethodSelector, input []byte, options V4OperationOptions) (Result, error) {
	if c == nil || c.inner == nil {
		return Result{}, ErrOperationClosed
	}
	if err := c.inner.SelectMethod(method); err != nil {
		return Result{}, err
	}
	value, status, err := c.inner.CallMethod(ctx, method.Type, input, options.internal())
	payload, _ := value.([]byte)
	result := operationResult(value, payload, status, err)
	if err != nil && !status.Complete {
		result.Status = OperationFailed
	}
	return result, err
}

func (s *V4Session) BindService(method V4UnaryMethod) (*V4ServiceClient, error) {
	if s == nil || s.bindUnaryService == nil || method.Decode == nil || method.Contract == [32]byte{} || method.WorkClass > V4WorkResident {
		return nil, ErrTransportUnavailable
	}
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if closed {
		return nil, ErrOperationClosed
	}
	client, err := s.bindUnaryService(method)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		client.Close()
		return nil, ErrOperationClosed
	}
	return &V4ServiceClient{inner: client}, nil
}
func (c *V4ServiceClient) Prepare(ctx context.Context, input []byte, options V4OperationOptions) (*OperationHandle, error) {
	if c == nil || c.inner == nil {
		return nil, ErrOperationClosed
	}
	op, err := c.inner.Prepare(ctx, input, options.internal())
	if err != nil {
		return nil, err
	}
	return &OperationHandle{inner: op}, nil
}
func (c *V4ServiceClient) Dispatch(ctx context.Context, input []byte, options V4OperationOptions) (*OperationHandle, OperationStartResult, error) {
	o, err := c.Prepare(ctx, input, options)
	if err != nil {
		return nil, OperationStartResult{}, err
	}
	started := o.StartContext(ctx)
	return o, started, nil
}
func (c *V4ServiceClient) Call(ctx context.Context, input []byte, options V4OperationOptions) (Result, error) {
	if c == nil || c.inner == nil {
		return Result{}, ErrOperationClosed
	}
	value, status, err := c.inner.Call(ctx, input, options.internal())
	var payload []byte
	if encoded, ok := value.([]byte); ok {
		payload = encoded
	}
	result := operationResult(value, payload, status, err)
	if err != nil && !status.Complete {
		result.Status = OperationFailed
	}
	return result, err
}

func (c *V4ServiceClient) Close() {
	if c != nil && c.inner != nil {
		c.inner.Close()
	}
}
func (c *V4ServiceClient) CleanupStatus() CleanupStatus {
	if c == nil || c.inner == nil {
		return CleanupStatus{Complete: true, Status: protocolv4.V4CleanupStateComplete, CoreCleanup: protocolv4.V4CoreCleanupComplete}
	}
	return publicCleanupStatus(c.inner.CleanupStatus())
}
func (c *V4ServiceClient) WaitCleanup(ctx context.Context) error {
	if c == nil || c.inner == nil {
		return ErrOperationClosed
	}
	return c.inner.WaitCleanup(ctx)
}
func (o *OperationHandle) Start() error { return o.StartContext(context.Background()).Err }
func (o *OperationHandle) StartContext(ctx context.Context) OperationStartResult {
	if o == nil || o.inner == nil {
		return OperationStartResult{Err: ErrOperationClosed}
	}
	r := o.inner.Start(ctx)
	return OperationStartResult{NotAdmitted: r.NotAdmitted, Err: r.Error}
}
func operationStatus(s sessionv4.UnaryOperationSnapshot) OperationStatus {
	if s.Failure != nil {
		return OperationFailed
	}
	if s.Result.Complete {
		if s.Result.Outcome.Error != nil || s.Result.Outcome.SDKErrorCode != 0 {
			return OperationFailed
		}
		return OperationCompleted
	}
	if s.Started {
		return OperationAccepted
	}
	if s.Closed {
		return OperationFailed
	}
	return OperationPending
}
func (o *OperationHandle) Progress() OperationProgress {
	if o == nil || o.inner == nil {
		return OperationProgress{Status: OperationUnknown, Err: ErrOperationClosed}
	}
	s := o.inner.Snapshot()
	r := s.Result
	err := s.Failure
	if err == nil {
		err = r.Outcome.Error
	}
	return OperationProgress{Status: operationStatus(s), Started: s.Started, Closed: s.Closed, ResultAvailable: r.Available, ResultDelivered: r.Delivered, DecoderRunning: r.DecoderRunning, HeaderAccepted: r.Submission.HeaderAccepted, MessageAccepted: r.Submission.MessageAccepted, Flushed: r.Submission.Flushed, SubmissionComplete: r.Submission.Terminal, ResultComplete: r.Complete, ResultAbandoned: r.Abandoned, ApplicationErrorCode: r.Outcome.Header.Fields().ApplicationErrorCode, SDKErrorCode: r.Outcome.SDKErrorCode, Err: err, Cleanup: publicCleanupStatus(o.inner.CleanupSnapshot())}
}
func (o *OperationHandle) Status() OperationStatus { return o.Progress().Status }
func (o *OperationHandle) WaitStatus(ctx context.Context) (OperationStatus, error) {
	if o == nil || o.inner == nil {
		return OperationUnknown, ErrOperationClosed
	}
	_, err := o.inner.WaitResultStatus(ctx)
	return o.Status(), err
}
func operationResult(value any, payload []byte, s sessionv4.UnaryResultStatus, err error) Result {
	status := OperationAccepted
	if s.Complete {
		status = OperationCompleted
	}
	if s.Outcome.Error != nil || s.Outcome.SDKErrorCode != 0 {
		status = OperationFailed
	}
	if err == nil {
		err = s.Outcome.Error
	}
	return Result{Status: status, Payload: payload, Value: value, Reference: OperationReference{inner: s.Reference}, Submission: s.Submission, CleanupComplete: s.CleanupComplete, ApplicationErrorCode: s.Outcome.Header.Fields().ApplicationErrorCode, SDKErrorCode: s.Outcome.SDKErrorCode, Err: err}
}
func (o *OperationHandle) TakeResult() (Result, error) {
	return o.TakeResultContext(context.Background())
}
func (o *OperationHandle) TakeResultContext(ctx context.Context) (Result, error) {
	if o == nil || o.inner == nil {
		return Result{}, ErrOperationClosed
	}
	value, s, err := o.inner.TakeResult(ctx)
	var payload []byte
	if bytes, ok := value.([]byte); ok {
		payload = bytes
	}
	result := operationResult(value, payload, s, err)
	result.Status = o.Status()
	return result, err
}
func (o *OperationHandle) TakeEncodedResult(ctx context.Context) (Result, error) {
	if o == nil || o.inner == nil {
		return Result{}, ErrOperationClosed
	}
	payload, s, err := o.inner.TakeEncodedResult(ctx)
	result := operationResult(nil, payload, s, err)
	result.Status = o.Status()
	return result, err
}
func (o *OperationHandle) AbandonResult() error {
	if o == nil || o.inner == nil {
		return ErrOperationClosed
	}
	_, err := o.inner.AbandonResult()
	return err
}
func (o *OperationHandle) Reference() (OperationReference, error) {
	if o == nil || o.inner == nil {
		return OperationReference{}, ErrOperationClosed
	}
	r, err := o.inner.Reference()
	return OperationReference{inner: r}, err
}
func (o *OperationHandle) Close() {
	if o != nil && o.inner != nil {
		o.inner.Close()
	}
}
func (o *OperationHandle) Cancel() {
	if o != nil && o.inner != nil {
		o.inner.Cancel()
	}
}
func (o *OperationHandle) CleanupStatus() CleanupStatus {
	if o == nil || o.inner == nil {
		return CleanupStatus{}
	}
	return publicCleanupStatus(o.inner.CleanupSnapshot())
}
func (o *OperationHandle) WaitCleanup(ctx context.Context) error {
	if o == nil || o.inner == nil {
		return ErrOperationClosed
	}
	return o.inner.WaitCleanup(ctx)
}

type OperationObservation = rpcv4.ExecutionObservation
type OperationManagementResult = rpcv4.ManagementResponse

func (s *V4Session) QueryOperation(ctx context.Context, ref OperationReference, timeoutMS uint64) (OperationManagementResult, error) {
	if s == nil || s.referenceManagement == nil {
		return OperationManagementResult{}, ErrTransportUnavailable
	}
	return s.referenceManagement(ctx, ref.inner, false, timeoutMS)
}
func (s *V4Session) RequestOperationCancel(ctx context.Context, ref OperationReference, timeoutMS uint64) (OperationManagementResult, error) {
	if s == nil || s.referenceManagement == nil {
		return OperationManagementResult{}, ErrTransportUnavailable
	}
	return s.referenceManagement(ctx, ref.inner, true, timeoutMS)
}
func (o *OperationHandle) RequestCancel(ctx context.Context, timeoutMS uint64) (OperationManagementResult, error) {
	if o == nil || o.inner == nil {
		return OperationManagementResult{}, ErrOperationClosed
	}
	return o.inner.RequestCancel(ctx, timeoutMS)
}

var ErrOperationNotStarted = sessionv4.ErrUnaryNotStarted

var ErrResponseLimitUnsupported = rpcv4.ErrResponseLimitUnsupported

var ErrContractPolicyRejected = protocolv4.ErrContractPolicyRejected
var ErrContractUpdateInProgress = sessionv4.ErrContractUpdateInProgress
var ErrResultAlreadyDelivered = sessionv4.ErrUnaryResultDelivered
var ErrResultAbandoned = sessionv4.ErrUnaryResultAbandoned
