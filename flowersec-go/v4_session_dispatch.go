package flowersec

import (
	"context"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

type V4UnaryRegistration = sessionv4.UnaryRegistration
type V4UnaryResponse = sessionv4.UnaryResponse
type V4RPCServicesConfig = sessionv4.RPCServicesConfig
type V4StreamRegistration = sessionv4.StreamRegistration
type V4StreamingRequest = sessionv4.StreamRequest

// V4StreamingResponse borrows the original current-item output owner. Every
// SendItemEncoded observes the request's exact item limit and backpressure.
// Returning from the handler lets the original dispatcher publish its terminal.
type V4StreamingResponse struct{ inner *sessionv4.StreamMessages }

// SaveContent explicitly retains selected bytes at an application-defined
// position under the original method's content policy. Sending an item does
// not save it. Repeated saves compare the original bytes without renewal.
func (s *V4StreamingResponse) SaveContent(ctx context.Context, position, payload []byte) (V4ContentObservation, error) {
	if s == nil || s.inner == nil {
		return V4ContentObservation{}, ErrOperationClosed
	}
	return s.inner.SaveContent(ctx, position, payload)
}

func (s *V4StreamingResponse) SendItemEncoded(ctx context.Context, payload []byte, applicationErrorCode uint32) error {
	if s == nil || s.inner == nil {
		return ErrOperationClosed
	}
	return s.inner.SendItemEncoded(ctx, payload, applicationErrorCode)
}

// NewV4StreamRegistration freezes the trusted OPEN and contract selection on
// the existing RPCServicesConfig.StreamMethods table before Session adoption.
// Input, authorization, execution permits and terminal output stay on its
// original dispatcher; the adapter starts no goroutine or queue.
func NewV4StreamRegistration(method uint32, namespace string, typeID uint32, digest [32]byte, kind string, metadata StreamMetadata, handler func(context.Context, V4StreamingRequest, *V4StreamingResponse) (uint32, error)) V4StreamRegistration {
	registration := sessionv4.StreamRegistration{Method: method, Namespace: namespace, Type: typeID, ContractDigest: digest, Kind: kind, Metadata: metadata.Bytes()}
	if handler != nil {
		registration.Handler = func(ctx context.Context, request sessionv4.StreamRequest, stream *sessionv4.StreamMessages) (uint32, error) {
			return handler(ctx, request, &V4StreamingResponse{inner: stream})
		}
	}
	return registration
}

// V4UnaryRequest retains the original authenticated handler context and its
// bounded input/output capabilities. No wrapper independently dispatches work.
type V4UnaryRequest struct {
	sessionv4.UnaryRequest
	publication *ResponsePublication
}

var noV4ResponsePublication = &ResponsePublication{}

func (r V4UnaryRequest) ResponsePublication() *ResponsePublication {
	if r.publication == nil {
		if original := r.UnaryRequest.ResponsePublication(); original != nil {
			return &ResponsePublication{owner: original}
		}
		return noV4ResponsePublication
	}
	return r.publication
}
func (r V4UnaryRequest) MaintenanceOwner() (*MaintenanceOwner, error) {
	return r.UnaryRequest.MaintenanceOwner()
}

type MaintenanceOwner = sessionv4.MaintenanceOwner

func V4MaintenanceOwnerCharge(maxObservations uint32, runtimeBytes uint64) (V4ResourceVector, error) {
	return sessionv4.MaintenanceOwnerCharge(maxObservations, runtimeBytes)
}
func NewV4MaintenanceOwner(maxObservations uint32, runtimeBytes uint64, metadata V4ResourceReference) (*MaintenanceOwner, error) {
	return sessionv4.NewMaintenanceOwner(maxObservations, runtimeBytes, metadata)
}

// NewV4UnaryRegistration supplies trusted local code to the existing immutable
// RPCServicesConfig.Methods registry. Codecs and the handler execute under that
// registry's original ordinary permit and authenticated application context.
func NewV4UnaryRegistration(method uint32, namespace string, typeID uint32, workClass V4WorkClass, handler func(context.Context, V4UnaryRequest, *V4UnaryResponse) (uint32, error)) V4UnaryRegistration {
	registration := sessionv4.UnaryRegistration{Method: method, Namespace: namespace, Type: typeID, WorkClass: workClass}
	if handler != nil {
		registration.Handler = func(ctx context.Context, request sessionv4.UnaryRequest, response *sessionv4.UnaryResponse) (uint32, error) {
			return handler(ctx, V4UnaryRequest{UnaryRequest: request, publication: &ResponsePublication{owner: request.ResponsePublication()}}, response)
		}
	}
	return registration
}

var ErrPublicationAlreadyTransferred = sessionv4.ErrPublicationAlreadyTransferred
var ErrPublicationOwnerUnavailable = sessionv4.ErrPublicationOwnerUnavailable
var ErrPublicationExpired = sessionv4.ErrPublicationExpired
var ErrPublicationInvalid = sessionv4.ErrPublicationInvalid
