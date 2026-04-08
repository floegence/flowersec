package controlplanehttp

import (
	"context"
	stdhttp "net/http"

	"github.com/floegence/flowersec/flowersec-go/protocolio"
)

const DefaultMaxBodyBytes int64 = 32 * 1024

type ArtifactRequest struct {
	EndpointID  string                    `json:"endpoint_id"`
	Payload     map[string]any            `json:"payload,omitempty"`
	Correlation *ArtifactCorrelationInput `json:"correlation,omitempty"`
}

type ArtifactCorrelationInput struct {
	TraceID string `json:"trace_id,omitempty"`
}

type ArtifactEnvelope struct {
	ConnectArtifact *protocolio.ConnectArtifact `json:"connect_artifact"`
}

type ErrorEnvelope struct {
	Error ErrorBody `json:"error"`
}

type ErrorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type ArtifactRequestMetadata struct {
	RequestID            string
	RemoteAddr           string
	Host                 string
	Origin               string
	UserAgent            string
	AuthenticatedSubject string
	Attributes           map[string]string
}

type ArtifactIssueInput struct {
	EndpointID  string
	Payload     map[string]any
	TraceID     string
	EntryTicket string
	IsEntry     bool
	Metadata    ArtifactRequestMetadata
}

type ArtifactHandlerOptions struct {
	MaxBodyBytes    int64
	ExtractMetadata func(*stdhttp.Request) (ArtifactRequestMetadata, error)
	ValidateRequest func(*stdhttp.Request, *ArtifactRequest) error
	IssueArtifact   func(context.Context, ArtifactIssueInput) (*protocolio.ConnectArtifact, error)
}

type RequestError struct {
	Status  int
	Code    string
	Message string
	Cause   error
}

func (e *RequestError) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Message != "" {
		return e.Message
	}
	return "controlplane request failed"
}

func (e *RequestError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

func NewRequestError(status int, code, message string, cause error) *RequestError {
	return &RequestError{
		Status:  status,
		Code:    code,
		Message: message,
		Cause:   cause,
	}
}
