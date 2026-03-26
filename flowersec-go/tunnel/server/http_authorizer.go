package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type HTTPAuthorizerConfig struct {
	AttachURL  string
	ObserveURL string
	Headers    http.Header
	HTTPClient *http.Client
}

type HTTPAuthorizer struct {
	attachURL  string
	observeURL string
	headers    http.Header
	client     *http.Client
}

type httpAuthorizerEnvelope struct {
	Success bool            `json:"success"`
	Data    json.RawMessage `json:"data"`
	Error   *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func NewHTTPAuthorizer(cfg HTTPAuthorizerConfig) (Authorizer, error) {
	attachURL := strings.TrimSpace(cfg.AttachURL)
	if attachURL == "" {
		return nil, fmt.Errorf("missing attach authorizer url")
	}
	observeURL := strings.TrimSpace(cfg.ObserveURL)

	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	return &HTTPAuthorizer{
		attachURL:  attachURL,
		observeURL: observeURL,
		headers:    cloneHeader(cfg.Headers),
		client:     client,
	}, nil
}

func (a *HTTPAuthorizer) AuthorizeAttach(ctx context.Context, req AttachAuthorizationRequest) (AttachAuthorizationDecision, error) {
	var out AttachAuthorizationDecision
	if err := a.doJSON(ctx, a.attachURL, req, &out); err != nil {
		return AttachAuthorizationDecision{}, err
	}
	return out, nil
}

func (a *HTTPAuthorizer) ObserveChannels(ctx context.Context, req ObserveChannelsRequest) (ObserveChannelsResponse, error) {
	if strings.TrimSpace(a.observeURL) == "" {
		return ObserveChannelsResponse{}, nil
	}
	var out ObserveChannelsResponse
	if err := a.doJSON(ctx, a.observeURL, req, &out); err != nil {
		return ObserveChannelsResponse{}, err
	}
	return out, nil
}

func (a *HTTPAuthorizer) doJSON(ctx context.Context, rawURL string, reqBody any, out any) error {
	body, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("marshal authorizer request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create authorizer request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	for key, values := range a.headers {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return fmt.Errorf("authorizer request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read authorizer response: %w", err)
	}
	if resp.StatusCode >= http.StatusBadRequest {
		return fmt.Errorf("authorizer http %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	if len(bytes.TrimSpace(respBody)) == 0 {
		return nil
	}

	var envelope httpAuthorizerEnvelope
	if err := json.Unmarshal(respBody, &envelope); err == nil && (envelope.Success || envelope.Error != nil) {
		if !envelope.Success {
			if envelope.Error != nil && strings.TrimSpace(envelope.Error.Message) != "" {
				return fmt.Errorf("authorizer error: %s", envelope.Error.Message)
			}
			return fmt.Errorf("authorizer error")
		}
		if len(envelope.Data) == 0 || bytes.Equal(bytes.TrimSpace(envelope.Data), []byte("null")) {
			return nil
		}
		if err := json.Unmarshal(envelope.Data, out); err != nil {
			return fmt.Errorf("decode authorizer envelope: %w", err)
		}
		return nil
	}

	if err := json.Unmarshal(respBody, out); err != nil {
		return fmt.Errorf("decode authorizer response: %w", err)
	}
	return nil
}

func cloneHeader(in http.Header) http.Header {
	if len(in) == 0 {
		return nil
	}
	out := make(http.Header, len(in))
	for key, values := range in {
		copied := make([]string, 0, len(values))
		for _, value := range values {
			value = strings.TrimSpace(value)
			if value == "" {
				continue
			}
			copied = append(copied, value)
		}
		if len(copied) > 0 {
			out[key] = copied
		}
	}
	return out
}
