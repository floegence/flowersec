package flowersec

import (
	"context"
	"errors"
	"iter"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

// V4ServiceDefinition freezes one namespace with unary, streaming and notify
// descriptors. All methods share the same ServiceClient and Close scope.
type V4ServiceDefinition = sessionv4.ServiceDefinition
type V4ServiceMethod = sessionv4.ServiceMethod
type V4ServiceMethodWorkload = sessionv4.ServiceMethodWorkload
type V4SessionMethodWorkload = sessionv4.SessionMethodWorkload
type V4ServiceContractSource = sessionv4.ServiceContractSource
type V4ServiceOfferRefresh = sessionv4.ServiceOfferRefresh
type V4ContractRenewalPolicy = sessionv4.ContractRenewalPolicy

const (
	V4ServiceContractsStatic      = sessionv4.ServiceContractsStatic
	V4ServiceContractsRemote      = sessionv4.ServiceContractsRemote
	V4ServiceOfferRefreshExplicit = sessionv4.ServiceOfferRefreshExplicit
	V4ServiceOfferRefreshManaged  = sessionv4.ServiceOfferRefreshManaged
)

var (
	ErrV4ContractDenied               = sessionv4.ErrContractDenied
	ErrV4ContractUnavailable          = sessionv4.ErrContractUnavailable
	ErrV4ContractRenewalQualification = sessionv4.ErrContractRenewalQualification
)

const (
	V4CallUnary uint8 = iota
	V4CallServerStreaming
	V4CallNotify
)

// V4StreamingMethod selects the trusted local stream entrance and item codec.
// Metadata is encoded once through the standard bounded StreamMetadata codec.
type V4StreamingMethod struct {
	Method   V4UnaryMethod
	Kind     string
	Metadata StreamMetadata
}

// V4NotifyMethod has no response decoder or response-limit configuration.
type V4NotifyMethod struct {
	Contract                         [32]byte
	WorkClass                        V4WorkClass
	Codec                            V4UnaryCodec
	RequireExecution, RequireDurable bool
}

type NotificationSubmission = rpcv4.PublicationProgress

// NotificationResult reports local publication and cleanup, with a query-only
// reference for execution notifications. It never implies remote execution.
type NotificationResult struct {
	NotificationSubmission
	Reference       OperationReference
	CleanupComplete bool
}

// StreamingStartError reports failure before a convenience StreamMethod
// transferred its handle. Reference remains query-only and may be invalid.
type StreamingStartError struct {
	Err             error
	Reference       OperationReference
	CleanupComplete bool
}

func (e *StreamingStartError) Error() string { return e.Err.Error() }
func (e *StreamingStartError) Unwrap() error { return e.Err }

func (s *V4Session) BindMethods(ctx context.Context, definition V4ServiceDefinition, options V4ServiceBindOptions) (*V4ServiceClient, error) {
	if s == nil || s.bindMethods == nil || ctx == nil {
		return nil, ErrTransportUnavailable
	}
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if closed {
		return nil, ErrOperationClosed
	}
	c, err := s.bindMethods(ctx, definition, options)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		c.Close()
		return nil, ErrOperationClosed
	}
	return &V4ServiceClient{inner: c}, nil
}

// BindMethods borrows the Controller and follows only its existing authorized
// current for new work. Closing the service never closes the Controller.
func (c *V4ConnectionController) BindMethods(ctx context.Context, definition V4ServiceDefinition, options V4ServiceBindOptions) (*V4ServiceClient, error) {
	if c == nil || c.inner == nil {
		return nil, ErrTransportUnavailable
	}
	service, err := c.inner.BindMethods(ctx, definition, options)
	if err != nil {
		return nil, err
	}
	return &V4ServiceClient{inner: service}, nil
}

func (c *V4ConnectionController) BindUnaryMethods(ctx context.Context, definition V4ServiceDefinition, options V4ServiceBindOptions) (*V4ServiceClient, error) {
	if c == nil || c.inner == nil {
		return nil, ErrTransportUnavailable
	}
	service, err := c.inner.BindUnaryMethods(ctx, definition, options)
	if err != nil {
		return nil, err
	}
	return &V4ServiceClient{inner: service}, nil
}

func (s *V4Session) PrepareStreaming(ctx context.Context, method V4StreamingMethod, input []byte, options V4OperationOptions) (*StreamingOperationHandle, error) {
	if s == nil || s.prepareStreaming == nil || ctx == nil {
		return nil, ErrTransportUnavailable
	}
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if closed {
		return nil, ErrOperationClosed
	}
	metadata := method.Metadata.Bytes()
	op, err := s.prepareStreaming(ctx, method.Method, method.Kind, metadata, input, options.internal())
	if err != nil {
		return nil, err
	}
	if err := s.handoffOperation(ctx, op.Close); err != nil {
		return nil, err
	}
	return &StreamingOperationHandle{inner: op}, nil
}

func (s *V4Session) PrepareNotify(ctx context.Context, method V4NotifyMethod, input []byte, options V4OperationOptions) (*NotifyOperationHandle, error) {
	if s == nil || s.prepareNotify == nil || ctx == nil {
		return nil, ErrTransportUnavailable
	}
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if closed {
		return nil, ErrOperationClosed
	}
	op, err := s.prepareNotify(ctx, V4UnaryMethod{Contract: method.Contract, WorkClass: method.WorkClass, Codec: method.Codec, RequireExecution: method.RequireExecution, RequireDurable: method.RequireDurable}, input, options.internal())
	if err != nil {
		return nil, err
	}
	if err := s.handoffOperation(ctx, op.Close); err != nil {
		return nil, err
	}
	return &NotifyOperationHandle{inner: op}, nil
}

func (c *V4ServiceClient) PrepareStreamingMethod(ctx context.Context, method V4MethodSelector, input []byte, options V4OperationOptions) (*StreamingOperationHandle, error) {
	if c == nil || c.inner == nil {
		return nil, ErrOperationClosed
	}
	if err := c.inner.SelectMethod(method); err != nil {
		return nil, err
	}
	op, err := c.inner.PrepareStreamingMethod(ctx, method.Type, input, options.internal())
	if err != nil {
		return nil, err
	}
	return &StreamingOperationHandle{inner: op}, nil
}

func (c *V4ServiceClient) StreamMethod(ctx context.Context, method V4MethodSelector, input []byte, options V4OperationOptions) (*StreamingOperationHandle, error) {
	if c == nil || c.inner == nil {
		return nil, ErrOperationClosed
	}
	if err := c.inner.SelectMethod(method); err != nil {
		return nil, err
	}
	op, err := c.inner.StreamMethod(ctx, method.Type, input, options.internal())
	if err != nil {
		var failure *sessionv4.StreamingStartFailure
		if errors.As(err, &failure) {
			return nil, &StreamingStartError{Err: failure.Cause, Reference: OperationReference{inner: failure.Reference}, CleanupComplete: failure.CleanupComplete}
		}
		return nil, err
	}
	return &StreamingOperationHandle{inner: op}, nil
}

func (c *V4ServiceClient) PrepareNotifyMethod(ctx context.Context, method V4MethodSelector, input []byte, options V4OperationOptions) (*NotifyOperationHandle, error) {
	if c == nil || c.inner == nil {
		return nil, ErrOperationClosed
	}
	if err := c.inner.SelectMethod(method); err != nil {
		return nil, err
	}
	op, err := c.inner.PrepareNotifyMethod(ctx, method.Type, input, options.internal())
	if err != nil {
		return nil, err
	}
	return &NotifyOperationHandle{inner: op}, nil
}

func (c *V4ServiceClient) NotifyMethod(ctx context.Context, method V4MethodSelector, input []byte, options V4OperationOptions) (NotificationResult, error) {
	if c == nil || c.inner == nil {
		return NotificationResult{}, ErrOperationClosed
	}
	if err := c.inner.SelectMethod(method); err != nil {
		return NotificationResult{}, err
	}
	r, err := c.inner.NotifyMethod(ctx, method.Type, input, options.internal())
	return NotificationResult{NotificationSubmission: r.PublicationProgress, Reference: OperationReference{inner: r.Reference}, CleanupComplete: r.CleanupComplete}, err
}

// StreamingOperationHandle exposes one original dedicated response stream.
// Canceled direct reads retain progress; Items owns a closing iteration scope.
type StreamingOperationHandle struct{ inner *sessionv4.StreamOperation }
type StreamingProgress struct {
	Ready, EOF, Terminal, Closed, CleanupComplete, TerminalDelivered, Abandoned bool
	ReceivedItems, DeliveredItems                                               uint32
	ReceivedBytes, DeliveredBytes                                               uint64
	ApplicationErrorCode                                                        uint32
	SDKErrorCode                                                                uint64
	Err                                                                         error
}
type StreamingItem struct {
	Value    any
	Progress StreamingProgress
}

func streamingProgress(s sessionv4.StreamMessageStatus) StreamingProgress {
	code := s.Header.Fields().ApplicationErrorCode
	if s.TerminalHeader.Fields().ApplicationErrorCode != 0 {
		code = s.TerminalHeader.Fields().ApplicationErrorCode
	}
	return StreamingProgress{Ready: s.Ready, EOF: s.EOF, Terminal: s.Terminal, Closed: s.Closed, CleanupComplete: s.CleanupComplete,
		TerminalDelivered: s.TerminalDelivered, Abandoned: s.Abandoned, ReceivedItems: s.ReceivedItems, DeliveredItems: s.DeliveredItems,
		ReceivedBytes: s.ReceivedBytes, DeliveredBytes: s.DeliveredBytes, ApplicationErrorCode: code, SDKErrorCode: s.SDKErrorCode, Err: s.Error}
}
func (h *StreamingOperationHandle) Start(ctx context.Context) OperationStartResult {
	if h == nil || h.inner == nil {
		return OperationStartResult{Err: ErrOperationClosed}
	}
	r := h.inner.Start(ctx)
	return OperationStartResult{NotAdmitted: r.NotAdmitted, Err: r.Error}
}
func (h *StreamingOperationHandle) Status() StreamingProgress {
	if h == nil || h.inner == nil {
		return StreamingProgress{Closed: true, Err: ErrOperationClosed}
	}
	return streamingProgress(h.inner.Status())
}
func (h *StreamingOperationHandle) ReadNext(ctx context.Context) (any, StreamingProgress, error) {
	if h == nil || h.inner == nil {
		return nil, StreamingProgress{}, ErrOperationClosed
	}
	v, s, err := h.inner.ReadNext(ctx)
	return v, streamingProgress(s), err
}
func (h *StreamingOperationHandle) ReadNextEncoded(ctx context.Context) ([]byte, StreamingProgress, error) {
	if h == nil || h.inner == nil {
		return nil, StreamingProgress{}, ErrOperationClosed
	}
	v, s, err := h.inner.ReadNextEncoded(ctx)
	return v, streamingProgress(s), err
}
func (h *StreamingOperationHandle) WaitStatus(ctx context.Context) (StreamingProgress, error) {
	if h == nil || h.inner == nil {
		return StreamingProgress{}, ErrOperationClosed
	}
	s, err := h.inner.WaitStatus(ctx)
	return streamingProgress(s), err
}
func (h *StreamingOperationHandle) AbandonResult() (StreamingProgress, error) {
	if h == nil || h.inner == nil {
		return StreamingProgress{}, ErrOperationClosed
	}
	s, err := h.inner.AbandonResult()
	return streamingProgress(s), err
}
func (h *StreamingOperationHandle) Items(ctx context.Context) iter.Seq2[StreamingItem, error] {
	return func(yield func(StreamingItem, error) bool) {
		if h == nil || h.inner == nil {
			yield(StreamingItem{}, ErrOperationClosed)
			return
		}
		for item, err := range h.inner.Items(ctx) {
			if !yield(StreamingItem{Value: item.Value, Progress: streamingProgress(item.Status)}, err) {
				return
			}
		}
	}
}
func (h *StreamingOperationHandle) Reference() (OperationReference, error) {
	if h == nil || h.inner == nil {
		return OperationReference{}, ErrOperationClosed
	}
	r, err := h.inner.Reference()
	return OperationReference{inner: r}, err
}
func (h *StreamingOperationHandle) Close() {
	if h != nil && h.inner != nil {
		h.inner.Close()
	}
}
func (h *StreamingOperationHandle) WaitCleanup(ctx context.Context) error {
	if h == nil || h.inner == nil {
		return ErrOperationClosed
	}
	return h.inner.WaitCleanup(ctx)
}

// NotifyOperationHandle reports local publication only; it owns no result.
type NotifyOperationHandle struct{ inner *sessionv4.NotifyOperation }

func (h *NotifyOperationHandle) Start(ctx context.Context) OperationStartResult {
	if h == nil || h.inner == nil {
		return OperationStartResult{Err: ErrOperationClosed}
	}
	r := h.inner.Start(ctx)
	return OperationStartResult{NotAdmitted: r.NotAdmitted, Err: r.Error}
}
func (h *NotifyOperationHandle) SubmissionStatus() NotificationSubmission {
	if h == nil || h.inner == nil {
		return NotificationSubmission{Terminal: true, Reason: "owner_unavailable"}
	}
	return h.inner.SubmissionStatus()
}
func (h *NotifyOperationHandle) WaitSubmission(ctx context.Context) (NotificationSubmission, error) {
	if h == nil || h.inner == nil {
		return NotificationSubmission{}, ErrOperationClosed
	}
	return h.inner.WaitSubmission(ctx)
}
func (h *NotifyOperationHandle) Reference() (OperationReference, error) {
	if h == nil || h.inner == nil {
		return OperationReference{}, ErrOperationClosed
	}
	r, err := h.inner.Reference()
	return OperationReference{inner: r}, err
}
func (h *NotifyOperationHandle) Close() {
	if h != nil && h.inner != nil {
		h.inner.Close()
	}
}
func (h *NotifyOperationHandle) WaitCleanup(ctx context.Context) error {
	if h == nil || h.inner == nil {
		return ErrOperationClosed
	}
	return h.inner.WaitCleanup(ctx)
}
