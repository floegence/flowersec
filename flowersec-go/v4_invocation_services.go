package flowersec

import (
	"context"
	"errors"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

type DispatchRequirement = sessionv4.DispatchRequirement
type ServiceDependencyMethod = sessionv4.ServiceDependencyMethod
type ServiceDependency = sessionv4.ServiceDependency

const (
	RequiredForDispatch = sessionv4.RequiredForDispatch
	OnUse               = sessionv4.OnUse
)

// NewServiceDependency selects an exact method subset of a borrowed client.
// The owning handler registration validates and copies the bounded declaration.
func NewServiceDependency(alias string, client *ServiceClient, methods []ServiceDependencyMethod) ServiceDependency {
	dependency := ServiceDependency{Alias: alias, Methods: methods}
	if client != nil {
		dependency.Client = client.inner
	}
	return dependency
}

// InvocationService grants only the methods declared by the current handler.
// Copies lose new-work rights when that invocation exits or its declaration closes.
type InvocationService struct{ inner sessionv4.InvocationService }

func InvocationServiceFromContext(ctx context.Context, alias string) (InvocationService, error) {
	view, err := sessionv4.InvocationServiceFromContext(ctx, alias)
	return InvocationService{inner: view}, err
}

func (v InvocationService) PrepareMethod(ctx context.Context, method MethodSelector, input []byte, options OperationOptions) (*OperationHandle, error) {
	op, err := v.inner.Prepare(ctx, method, input, options.internal())
	if err != nil {
		return nil, err
	}
	return &OperationHandle{inner: op}, nil
}

func (v InvocationService) CallMethod(ctx context.Context, method MethodSelector, input []byte, options OperationOptions) (Result, error) {
	value, status, err := v.inner.Call(ctx, method, input, options.internal())
	payload, _ := value.([]byte)
	result := operationResult(value, payload, status, err)
	if err != nil && !status.Complete {
		result.Status = OperationFailed
	}
	return result, err
}

func (v InvocationService) StreamMethod(ctx context.Context, method MethodSelector, input []byte, options OperationOptions) (*StreamingOperationHandle, error) {
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

func (v InvocationService) PrepareStreamingMethod(ctx context.Context, method MethodSelector, input []byte, options OperationOptions) (*StreamingOperationHandle, error) {
	op, err := v.inner.PrepareStream(ctx, method, input, options.internal())
	if err != nil {
		return nil, err
	}
	return &StreamingOperationHandle{inner: op}, nil
}

func (v InvocationService) PrepareNotifyMethod(ctx context.Context, method MethodSelector, input []byte, options OperationOptions) (*NotifyOperationHandle, error) {
	op, err := v.inner.PrepareNotify(ctx, method, input, options.internal())
	if err != nil {
		return nil, err
	}
	return &NotifyOperationHandle{inner: op}, nil
}

func (v InvocationService) NotifyMethod(ctx context.Context, method MethodSelector, input []byte, options OperationOptions) (NotificationResult, error) {
	r, err := v.inner.Notify(ctx, method, input, options.internal())
	return NotificationResult{NotificationSubmission: r.PublicationProgress, Reference: OperationReference{inner: r.Reference}, CleanupComplete: r.CleanupComplete}, err
}
