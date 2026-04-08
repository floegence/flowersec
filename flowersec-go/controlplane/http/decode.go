package controlplanehttp

import (
	"encoding/json"
	"fmt"
	"io"
	"mime"
	stdhttp "net/http"
	"strings"
)

func DecodeArtifactRequest(r *stdhttp.Request, maxBodyBytes int64) (*ArtifactRequest, error) {
	if r == nil {
		return nil, NewRequestError(stdhttp.StatusBadRequest, "invalid_request", "request is required", nil)
	}
	if err := requireJSONContentType(r.Header.Get("Content-Type")); err != nil {
		return nil, err
	}

	body, err := readBodyLimit(r.Body, normalizeMaxBodyBytes(maxBodyBytes))
	if err != nil {
		return nil, err
	}
	if len(strings.TrimSpace(string(body))) == 0 {
		return nil, NewRequestError(stdhttp.StatusBadRequest, "invalid_json", "request body must be a JSON object", nil)
	}

	var top map[string]json.RawMessage
	if err := json.Unmarshal(body, &top); err != nil {
		return nil, NewRequestError(stdhttp.StatusBadRequest, "invalid_json", "malformed JSON request body", err)
	}

	if err := assertAllowedTopLevelKeys(top); err != nil {
		return nil, err
	}

	endpointID, err := decodeRequiredNonEmptyString(top, "endpoint_id")
	if err != nil {
		return nil, err
	}

	req := &ArtifactRequest{EndpointID: endpointID}
	if raw, ok := top["payload"]; ok {
		payload, err := decodeOpaquePayload(raw)
		if err != nil {
			return nil, err
		}
		req.Payload = payload
	}
	if raw, ok := top["correlation"]; ok {
		correlation, err := decodeCorrelation(raw)
		if err != nil {
			return nil, err
		}
		req.Correlation = correlation
	}
	return req, nil
}

func requireJSONContentType(raw string) error {
	mediaType, _, err := mime.ParseMediaType(strings.TrimSpace(raw))
	if err != nil {
		return NewRequestError(stdhttp.StatusUnsupportedMediaType, "unsupported_media_type", "content type must be application/json", err)
	}
	if mediaType != "application/json" {
		return NewRequestError(stdhttp.StatusUnsupportedMediaType, "unsupported_media_type", "content type must be application/json", nil)
	}
	return nil
}

func normalizeMaxBodyBytes(maxBodyBytes int64) int64 {
	if maxBodyBytes <= 0 {
		return DefaultMaxBodyBytes
	}
	return maxBodyBytes
}

func readBodyLimit(body io.ReadCloser, maxBodyBytes int64) ([]byte, error) {
	defer body.Close()
	limited := io.LimitReader(body, maxBodyBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, NewRequestError(stdhttp.StatusBadRequest, "invalid_body", "failed to read request body", err)
	}
	if int64(len(data)) > maxBodyBytes {
		return nil, NewRequestError(stdhttp.StatusRequestEntityTooLarge, "body_too_large", fmt.Sprintf("request body exceeds %d bytes", maxBodyBytes), nil)
	}
	return data, nil
}

func assertAllowedTopLevelKeys(top map[string]json.RawMessage) error {
	allowed := map[string]struct{}{
		"endpoint_id": {},
		"payload":     {},
		"correlation": {},
	}
	for key := range top {
		if _, ok := allowed[key]; !ok {
			return NewRequestError(stdhttp.StatusBadRequest, "invalid_request", fmt.Sprintf("unknown request field: %s", key), nil)
		}
	}
	return nil
}

func decodeRequiredNonEmptyString(top map[string]json.RawMessage, key string) (string, error) {
	raw, ok := top[key]
	if !ok {
		return "", NewRequestError(stdhttp.StatusBadRequest, "invalid_request", fmt.Sprintf("missing %s", key), nil)
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", NewRequestError(stdhttp.StatusBadRequest, "invalid_request", fmt.Sprintf("bad %s", key), err)
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return "", NewRequestError(stdhttp.StatusBadRequest, "invalid_request", fmt.Sprintf("bad %s", key), nil)
	}
	return value, nil
}

func decodeOpaquePayload(raw json.RawMessage) (map[string]any, error) {
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, NewRequestError(stdhttp.StatusBadRequest, "invalid_request", "bad payload", err)
	}
	if payload == nil {
		return nil, NewRequestError(stdhttp.StatusBadRequest, "invalid_request", "bad payload", nil)
	}
	return payload, nil
}

func decodeCorrelation(raw json.RawMessage) (*ArtifactCorrelationInput, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		return nil, NewRequestError(stdhttp.StatusBadRequest, "invalid_request", "bad correlation", err)
	}
	for key := range top {
		if key != "trace_id" {
			return nil, NewRequestError(stdhttp.StatusBadRequest, "invalid_request", fmt.Sprintf("unknown correlation field: %s", key), nil)
		}
	}
	traceID, err := decodeOptionalString(top["trace_id"])
	if err != nil {
		return nil, NewRequestError(stdhttp.StatusBadRequest, "invalid_request", "bad correlation.trace_id", err)
	}
	if traceID == "" {
		return &ArtifactCorrelationInput{}, nil
	}
	return &ArtifactCorrelationInput{TraceID: traceID}, nil
}

func decodeOptionalString(raw json.RawMessage) (string, error) {
	if len(raw) == 0 {
		return "", nil
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", err
	}
	return strings.TrimSpace(value), nil
}
