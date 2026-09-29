package flowersec

import (
	"context"
	"errors"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

type V4DispatchRequirement = sessionv4.DispatchRequirement
type V4ServiceDependencyMethod = sessionv4.ServiceDependencyMethod
type V4ServiceDependency = sessionv4.ServiceDependency

const (
	V4RequiredForDispatch = sessionv4.RequiredForDispatch
	V4OnUse               = sessionv4.OnUse
)

// NewV4ServiceDependency selects an exact method subset of a borrowed client.
// The owning handler registration validates and copies the bounded declaration.
func NewV4ServiceDependency(alias string, client *V4ServiceClient, methods []V4ServiceDependencyMethod) V4ServiceDependency {
	dependency := V4ServiceDependency{Alias: alias, Methods: methods}
	if client != nil {
		dependency.Client = client.inner
	}
	return dependency
}

// V4InvocationService grants only the methods declared by the current handler.
// Copies lose new-work rights when that invocation exits or its declaration closes.
type V4InvocationService struct{ inner sessionv4.InvocationService }

func V4InvocationServiceFromContext(ctx context.Context, alias string) (V4InvocationService, error) {
	view, err := sessionv4.InvocationServiceFromContext(ctx, alias)
	return V4InvocationService{inner: view}, err
}

func (v V4InvocationService) PrepareMethod(ctx context.Context, method V4MethodSelector, input []byte, options V4OperationOptions) (*OperationHandle, error) {
	op, err := v.inner.Prepare(ctx, method, input, options.internal())
	if err != nil {
		return nil, err
	}
	return &OperationHandle{inner: op}, nil
}

func (v V4InvocationService) CallMethod(ctx context.Context, method V4MethodSelector, input []byte, options V4OperationOptions) (Result, error) {
	value, status, err := v.inner.Call(ctx, method, input, options.internal())
	payload, _ := value.([]byte)
	result := operationResult(value, payload, status, err)
	if err != nil && !status.Complete {
		result.Status = OperationFailed
	}
	return result, err
}

func (v V4InvocationService) StreamMethod(ctx context.Context, method V4MethodSelector, input []byte, options V4OperationOptions) (*StreamingOperationHandle, error) {
	op, err := v.inner.Stream(ctx, method, input, options.internal())
	if err != nil {
		var failure *sessionv4.StreamingStartFailure
		if errors.As(err, &failure) {
			return nil, &StreamingStartError{Err: failure.Cause, Reference: OperationReference{inner: failure.Reference}, CleanupComplete: failure.CleanupComplete}
		}
		return nil, err
	}
	return &StreamingOperationHandle{inner: op}, nil
}

func (v V4InvocationService) PrepareStreamingMethod(ctx context.Context, method V4MethodSelector, input []byte, options V4OperationOptions) (*StreamingOperationHandle, error) {
	op, err := v.inner.PrepareStream(ctx, method, input, options.internal())
	if err != nil {
		return nil, err
	}
	return &StreamingOperationHandle{inner: op}, nil
}

func (v V4InvocationService) PrepareNotifyMethod(ctx context.Context, method V4MethodSelector, input []byte, options V4OperationOptions) (*NotifyOperationHandle, error) {
	op, err := v.inner.PrepareNotify(ctx, method, input, options.internal())
	if err != nil {
		return nil, err
	}
	return &NotifyOperationHandle{inner: op}, nil
}

func (v V4InvocationService) NotifyMethod(ctx context.Context, method V4MethodSelector, input []byte, options V4OperationOptions) (NotificationResult, error) {
	r, err := v.inner.Notify(ctx, method, input, options.internal())
	return NotificationResult{NotificationSubmission: r.PublicationProgress, Reference: OperationReference{inner: r.Reference}, CleanupComplete: r.CleanupComplete}, err
}
