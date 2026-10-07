package flowersec

import (
	"context"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

type UnaryRegistration = sessionv4.UnaryRegistration
type UnaryResponse = sessionv4.UnaryResponse
type RPCServicesConfig = sessionv4.RPCServicesConfig
type NotificationMethod = sessionv4.NotificationMethod
type StreamRegistration = sessionv4.StreamRegistration
type StreamingRequest = sessionv4.StreamRequest

// ReplaceServiceDependencies atomically replaces the declaration for one
// existing unary, streaming or notification execution handler. New required dependencies gate future
// dispatch; already admitted invocations retain their original declaration.
func (s *Session) ReplaceServiceDependencies(ctx context.Context, method MethodSelector, dependencies []ServiceDependency) error {
	if s == nil || s.replaceServiceDependencies == nil || !s.available() {
		return ErrTransportUnavailable
	}
	return s.replaceServiceDependencies(ctx, method, dependencies)
}

// StreamingResponse borrows the original current-item output owner. Every
// SendItemEncoded observes the request's exact item limit and backpressure.
// Returning from the handler lets the original dispatcher publish its terminal.
type StreamingResponse struct{ inner *sessionv4.StreamMessages }

// SaveContent explicitly retains selected bytes at an application-defined
// position under the original method's content policy. Sending an item does
// not save it. Repeated saves compare the original bytes without renewal.
func (s *StreamingResponse) SaveContent(ctx context.Context, position, payload []byte) (ContentObservation, error) {
	if s == nil || s.inner == nil {
		return ContentObservation{}, ErrOperationClosed
	}
	return s.inner.SaveContent(ctx, position, payload)
}

func (s *StreamingResponse) SendItemEncoded(ctx context.Context, payload []byte, applicationErrorCode uint32) error {
	if s == nil || s.inner == nil {
		return ErrOperationClosed
	}
	return s.inner.SendItemEncoded(ctx, payload, applicationErrorCode)
}

// NewStreamRegistration freezes the trusted OPEN and contract selection on
// the existing RPCServicesConfig.StreamMethods table before Session adoption.
// Input, authorization, execution permits and terminal output stay on its
// original dispatcher; the adapter starts no goroutine or queue.
func NewStreamRegistration(method uint32, namespace string, typeID uint32, digest [32]byte, kind string, metadata StreamMetadata, handler func(context.Context, StreamingRequest, *StreamingResponse) (uint32, error)) StreamRegistration {
	registration := sessionv4.StreamRegistration{Method: method, Namespace: namespace, Type: typeID, ContractDigest: digest, Kind: kind, Metadata: metadata.Bytes()}
	if handler != nil {
		registration.Handler = func(ctx context.Context, request sessionv4.StreamRequest, stream *sessionv4.StreamMessages) (uint32, error) {
			return handler(ctx, request, &StreamingResponse{inner: stream})
		}
	}
	return registration
}

// UnaryRequest retains the original authenticated handler context and its
// bounded input/output capabilities. No wrapper independently dispatches work.
type UnaryRequest struct {
	sessionv4.UnaryRequest
	publication *ResponsePublication
}

var noResponsePublication = &ResponsePublication{}

func (r UnaryRequest) ResponsePublication() *ResponsePublication {
	if r.publication == nil {
		if original := r.UnaryRequest.ResponsePublication(); original != nil {
			return &ResponsePublication{owner: original}
		}
		return noResponsePublication
	}
	return r.publication
}
func (r UnaryRequest) MaintenanceOwner() (*MaintenanceOwner, error) {
	return r.UnaryRequest.MaintenanceOwner()
}

type MaintenanceOwner = sessionv4.MaintenanceOwner

func MaintenanceOwnerCharge(maxObservations uint32, runtimeBytes uint64) (ResourceVector, error) {
	return sessionv4.MaintenanceOwnerCharge(maxObservations, runtimeBytes)
}
func NewMaintenanceOwner(maxObservations uint32, runtimeBytes uint64, metadata ResourceReference) (*MaintenanceOwner, error) {
	return sessionv4.NewMaintenanceOwner(maxObservations, runtimeBytes, metadata)
}

// NewUnaryRegistration supplies trusted local code to the existing immutable
// RPCServicesConfig.Methods registry. Codecs and the handler execute under that
// registry's original ordinary permit and authenticated application context.
func NewUnaryRegistration(method uint32, namespace string, typeID uint32, workClass WorkClass, handler func(context.Context, UnaryRequest, *UnaryResponse) (uint32, error)) UnaryRegistration {
	registration := sessionv4.UnaryRegistration{Method: method, Namespace: namespace, Type: typeID, WorkClass: workClass}
	if handler != nil {
		registration.Handler = func(ctx context.Context, request sessionv4.UnaryRequest, response *sessionv4.UnaryResponse) (uint32, error) {
			return handler(ctx, UnaryRequest{UnaryRequest: request, publication: &ResponsePublication{owner: request.ResponsePublication()}}, response)
		}
	}
	return registration
}

var ErrPublicationAlreadyTransferred = sessionv4.ErrPublicationAlreadyTransferred
var ErrPublicationOwnerUnavailable = sessionv4.ErrPublicationOwnerUnavailable
var ErrPublicationExpired = sessionv4.ErrPublicationExpired
var ErrPublicationInvalid = sessionv4.ErrPublicationInvalid
