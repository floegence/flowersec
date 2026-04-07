package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/floegence/flowersec/flowersec-go/protocolio"
)

type ConnectArtifactRequestConfig struct {
	BaseURL    string
	Path       string
	EndpointID string
	Payload    map[string]any
	TraceID    string
	Headers    http.Header
	HTTPClient *http.Client
}

type EntryConnectArtifactRequestConfig struct {
	ConnectArtifactRequestConfig
	EntryTicket string
}

type ConnectArtifactResponse struct {
	ConnectArtifact *protocolio.ConnectArtifact `json:"connect_artifact"`
}

type controlplaneErrorEnvelope struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

type RequestError struct {
	Status       int
	Code         string
	Message      string
	ResponseBody []byte
}

func (e *RequestError) Error() string {
	if e == nil {
		return "<nil>"
	}
	if strings.TrimSpace(e.Message) != "" {
		return e.Message
	}
	return fmt.Sprintf("controlplane request failed: %d", e.Status)
}

func RequestConnectArtifact(ctx context.Context, cfg ConnectArtifactRequestConfig) (*protocolio.ConnectArtifact, error) {
	return requestConnectArtifact(ctx, cfg, "")
}

func RequestEntryConnectArtifact(ctx context.Context, cfg EntryConnectArtifactRequestConfig) (*protocolio.ConnectArtifact, error) {
	entryTicket := strings.TrimSpace(cfg.EntryTicket)
	if entryTicket == "" {
		return nil, fmt.Errorf("entry ticket is required")
	}
	return requestConnectArtifact(ctx, cfg.ConnectArtifactRequestConfig, entryTicket)
}

func requestConnectArtifact(ctx context.Context, cfg ConnectArtifactRequestConfig, entryTicket string) (*protocolio.ConnectArtifact, error) {
	reqBody, err := buildRequestBody(cfg)
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, buildURL(cfg.BaseURL, defaultPath(cfg.Path, entryTicket != "")), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header = cloneHeaders(cfg.Headers)
	if req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if entryTicket != "" {
		req.Header.Set("Authorization", "Bearer "+entryTicket)
	}
	resp, err := httpClient(cfg.HTTPClient).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, protocolio.DefaultMaxJSONBytes))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, decodeRequestError(resp.StatusCode, respBody)
	}

	var envelope struct {
		ConnectArtifact json.RawMessage `json:"connect_artifact"`
	}
	if err := json.Unmarshal(respBody, &envelope); err != nil {
		return nil, err
	}
	if len(envelope.ConnectArtifact) == 0 {
		return nil, fmt.Errorf("invalid controlplane response: missing connect_artifact")
	}
	return protocolio.DecodeConnectArtifactJSON(bytes.NewReader(envelope.ConnectArtifact))
}

func buildRequestBody(cfg ConnectArtifactRequestConfig) (map[string]any, error) {
	endpointID := strings.TrimSpace(cfg.EndpointID)
	if endpointID == "" {
		return nil, fmt.Errorf("endpoint id is required")
	}
	body := map[string]any{
		"endpoint_id": endpointID,
	}
	if cfg.Payload != nil {
		body["payload"] = clonePayload(cfg.Payload)
	}
	if traceID := strings.TrimSpace(cfg.TraceID); traceID != "" {
		body["correlation"] = map[string]any{"trace_id": traceID}
	}
	return body, nil
}

func decodeRequestError(status int, body []byte) error {
	out := &RequestError{Status: status, ResponseBody: append([]byte(nil), body...)}
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		out.Message = fmt.Sprintf("controlplane request failed: %d", status)
		return out
	}
	var envelope controlplaneErrorEnvelope
	if err := json.Unmarshal(body, &envelope); err == nil {
		out.Code = strings.TrimSpace(envelope.Error.Code)
		if msg := strings.TrimSpace(envelope.Error.Message); msg != "" {
			out.Message = msg
			return out
		}
	}
	out.Message = trimmed
	return out
}

func defaultPath(path string, entry bool) string {
	path = strings.TrimSpace(path)
	if path != "" {
		return path
	}
	if entry {
		return "/v1/connect/artifact/entry"
	}
	return "/v1/connect/artifact"
}

func buildURL(baseURL, path string) string {
	baseURL = strings.TrimSpace(baseURL)
	if baseURL == "" {
		return path
	}
	return strings.TrimRight(baseURL, "/") + path
}

func httpClient(client *http.Client) *http.Client {
	if client != nil {
		return client
	}
	return http.DefaultClient
}

func clonePayload(payload map[string]any) map[string]any {
	out := make(map[string]any, len(payload))
	for k, v := range payload {
		out[k] = v
	}
	return out
}

func cloneHeaders(h http.Header) http.Header {
	if h == nil {
		return make(http.Header)
	}
	out := make(http.Header, len(h))
	for k, vv := range h {
		cp := make([]string, len(vv))
		copy(cp, vv)
		out[k] = cp
	}
	return out
}
