package controlplanehttp

import (
	"bytes"
	stdhttp "net/http"
	"testing"
)

func newJSONRequest(t *testing.T, body string) *stdhttp.Request {
	t.Helper()
	req, err := stdhttp.NewRequest(stdhttp.MethodPost, "/v1/connect/artifact", bytes.NewBufferString(body))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	return req
}

func TestDecodeArtifactRequest_StrictlyDecodesStableEnvelope(t *testing.T) {
	req := newJSONRequest(t, `{"endpoint_id":"env_demo","payload":{"app":"demo","unknown":"ok"},"correlation":{"trace_id":"trace-0001"}}`)

	got, err := DecodeArtifactRequest(req, DefaultMaxBodyBytes)
	if err != nil {
		t.Fatalf("DecodeArtifactRequest: %v", err)
	}
	if got.EndpointID != "env_demo" {
		t.Fatalf("unexpected endpoint id: %q", got.EndpointID)
	}
	if got.Payload["app"] != "demo" || got.Payload["unknown"] != "ok" {
		t.Fatalf("unexpected payload: %#v", got.Payload)
	}
	if got.Correlation == nil || got.Correlation.TraceID != "trace-0001" {
		t.Fatalf("unexpected correlation: %#v", got.Correlation)
	}
}

func TestDecodeArtifactRequest_RejectsUnknownTopLevelField(t *testing.T) {
	req := newJSONRequest(t, `{"endpoint_id":"env_demo","extra":true}`)

	_, err := DecodeArtifactRequest(req, DefaultMaxBodyBytes)
	reqErr, ok := err.(*RequestError)
	if !ok {
		t.Fatalf("expected *RequestError, got %T", err)
	}
	if reqErr.Status != stdhttp.StatusBadRequest || reqErr.Code != "invalid_request" {
		t.Fatalf("unexpected request error: %+v", reqErr)
	}
}

func TestDecodeArtifactRequest_RejectsUnknownCorrelationField(t *testing.T) {
	req := newJSONRequest(t, `{"endpoint_id":"env_demo","correlation":{"trace_id":"trace-0001","extra":"bad"}}`)

	_, err := DecodeArtifactRequest(req, DefaultMaxBodyBytes)
	reqErr, ok := err.(*RequestError)
	if !ok {
		t.Fatalf("expected *RequestError, got %T", err)
	}
	if reqErr.Status != stdhttp.StatusBadRequest || reqErr.Code != "invalid_request" {
		t.Fatalf("unexpected request error: %+v", reqErr)
	}
}

func TestDecodeArtifactRequest_RejectsMalformedJSON(t *testing.T) {
	req := newJSONRequest(t, `{"endpoint_id":"env_demo"`)

	_, err := DecodeArtifactRequest(req, DefaultMaxBodyBytes)
	reqErr, ok := err.(*RequestError)
	if !ok {
		t.Fatalf("expected *RequestError, got %T", err)
	}
	if reqErr.Status != stdhttp.StatusBadRequest || reqErr.Code != "invalid_json" {
		t.Fatalf("unexpected request error: %+v", reqErr)
	}
}

func TestDecodeArtifactRequest_RejectsWrongContentType(t *testing.T) {
	req, err := stdhttp.NewRequest(stdhttp.MethodPost, "/v1/connect/artifact", bytes.NewBufferString(`{"endpoint_id":"env_demo"}`))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "text/plain")

	_, err = DecodeArtifactRequest(req, DefaultMaxBodyBytes)
	reqErr, ok := err.(*RequestError)
	if !ok {
		t.Fatalf("expected *RequestError, got %T", err)
	}
	if reqErr.Status != stdhttp.StatusUnsupportedMediaType || reqErr.Code != "unsupported_media_type" {
		t.Fatalf("unexpected request error: %+v", reqErr)
	}
}

func TestDecodeArtifactRequest_RejectsLargeBodies(t *testing.T) {
	req := newJSONRequest(t, `{"endpoint_id":"env_demo","payload":{"blob":"0123456789"}}`)

	_, err := DecodeArtifactRequest(req, 16)
	reqErr, ok := err.(*RequestError)
	if !ok {
		t.Fatalf("expected *RequestError, got %T", err)
	}
	if reqErr.Status != stdhttp.StatusRequestEntityTooLarge || reqErr.Code != "body_too_large" {
		t.Fatalf("unexpected request error: %+v", reqErr)
	}
}
