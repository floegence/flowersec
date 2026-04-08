package controlplanehttp

import (
	"context"
	stdhttp "net/http"
	"strings"

	"github.com/floegence/flowersec/flowersec-go/protocolio"
)

func NewArtifactHandler(opts ArtifactHandlerOptions) stdhttp.Handler {
	return newArtifactHandler(opts, false)
}

func NewEntryArtifactHandler(opts ArtifactHandlerOptions) stdhttp.Handler {
	return newArtifactHandler(opts, true)
}

func newArtifactHandler(opts ArtifactHandlerOptions, isEntry bool) stdhttp.Handler {
	return stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		if r.Method != stdhttp.MethodPost {
			writeRequestError(w, NewRequestError(stdhttp.StatusMethodNotAllowed, "method_not_allowed", "method must be POST", nil))
			return
		}

		req, err := DecodeArtifactRequest(r, opts.MaxBodyBytes)
		if err != nil {
			writeRequestError(w, err)
			return
		}

		metadata, err := extractMetadata(opts, r)
		if err != nil {
			writeRequestError(w, err)
			return
		}

		if opts.ValidateRequest != nil {
			if err := opts.ValidateRequest(r, req); err != nil {
				writeRequestError(w, coerceHookError(err, stdhttp.StatusBadRequest, "invalid_request", "request validation failed"))
				return
			}
		}

		if opts.IssueArtifact == nil {
			writeRequestError(w, NewRequestError(stdhttp.StatusInternalServerError, "internal_error", "artifact issuer is required", nil))
			return
		}

		artifact, err := opts.IssueArtifact(r.Context(), ArtifactIssueInput{
			EndpointID:  req.EndpointID,
			Payload:     clonePayload(req.Payload),
			TraceID:     traceIDFromRequest(req),
			EntryTicket: bearerToken(r.Header.Get("Authorization")),
			IsEntry:     isEntry,
			Metadata:    metadata,
		})
		if err != nil {
			writeRequestError(w, coerceHookError(err, stdhttp.StatusInternalServerError, "issue_failed", "artifact issuance failed"))
			return
		}
		if artifact == nil {
			writeRequestError(w, NewRequestError(stdhttp.StatusInternalServerError, "issue_failed", "artifact issuer returned nil artifact", nil))
			return
		}
		if err := WriteArtifactEnvelope(w, artifact); err != nil {
			writeRequestError(w, NewRequestError(stdhttp.StatusInternalServerError, "write_failed", "failed to write artifact response", err))
			return
		}
	})
}

func extractMetadata(opts ArtifactHandlerOptions, r *stdhttp.Request) (ArtifactRequestMetadata, error) {
	if opts.ExtractMetadata == nil {
		return DefaultRequestMetadata(r), nil
	}
	metadata, err := opts.ExtractMetadata(r)
	if err != nil {
		return ArtifactRequestMetadata{}, coerceHookError(err, stdhttp.StatusInternalServerError, "metadata_extract_failed", "metadata extraction failed")
	}
	if metadata.Attributes == nil {
		metadata.Attributes = map[string]string{}
	}
	return metadata, nil
}

func DefaultRequestMetadata(r *stdhttp.Request) ArtifactRequestMetadata {
	return ArtifactRequestMetadata{
		RequestID:  strings.TrimSpace(r.Header.Get("X-Request-Id")),
		RemoteAddr: strings.TrimSpace(r.RemoteAddr),
		Host:       strings.TrimSpace(r.Host),
		Origin:     strings.TrimSpace(r.Header.Get("Origin")),
		UserAgent:  strings.TrimSpace(r.UserAgent()),
		Attributes: map[string]string{},
	}
}

func traceIDFromRequest(req *ArtifactRequest) string {
	if req == nil || req.Correlation == nil {
		return ""
	}
	return strings.TrimSpace(req.Correlation.TraceID)
}

func bearerToken(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(raw, prefix) {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(raw, prefix))
}

func clonePayload(payload map[string]any) map[string]any {
	if payload == nil {
		return nil
	}
	out := make(map[string]any, len(payload))
	for key, value := range payload {
		out[key] = value
	}
	return out
}

func coerceHookError(err error, status int, code, message string) error {
	if err == nil {
		return nil
	}
	if reqErr, ok := err.(*RequestError); ok {
		return reqErr
	}
	return NewRequestError(status, code, message, err)
}

func IssueArtifact(
	ctx context.Context,
	opts ArtifactHandlerOptions,
	input ArtifactIssueInput,
) (*protocolio.ConnectArtifact, error) {
	if opts.IssueArtifact == nil {
		return nil, NewRequestError(stdhttp.StatusInternalServerError, "internal_error", "artifact issuer is required", nil)
	}
	return opts.IssueArtifact(ctx, input)
}
